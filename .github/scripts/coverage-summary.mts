// Turns the coverage reports of `bun run coverage` into one Markdown summary: the totals per package and the files
// with the least line coverage. Prints it, and appends it to the job summary when GitHub Actions runs it.
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { relative, resolve } from "node:path";

interface Metric { pct: number; covered: number; total: number }
interface Row { name: string; lines: Metric; statements: Metric; functions: Metric | null; branches: Metric | null }

const root = resolve(import.meta.dirname, "../..");
const pct = (m: Metric | null) => (m === null ? "–" : `${m.pct.toFixed(1)}% (${m.covered}/${m.total})`);
const metric = (m: { pct: number; covered: number; total: number }): Metric => ({ pct: m.pct, covered: m.covered, total: m.total });

function vitest(pkg: string): { total: Row; files: Row[] } | null {
  const file = resolve(root, "packages", pkg, "coverage/coverage-summary.json");
  if (!existsSync(file)) return null;
  const summary = JSON.parse(readFileSync(file, "utf8")) as Record<string, Record<"lines" | "statements" | "functions" | "branches", Metric>>;
  const row = (name: string, s: Record<"lines" | "statements" | "functions" | "branches", Metric>): Row =>
    ({ name, lines: metric(s.lines), statements: metric(s.statements), functions: metric(s.functions), branches: metric(s.branches) });
  const files = Object.entries(summary).filter(([k]) => k !== "total").map(([k, s]) => row(relative(root, k), s));
  return { total: row(`@agent-custody/${pkg}`, summary.total), files };
}

function python(): { total: Row; files: Row[] } | null {
  const file = resolve(root, "packages/python/coverage/coverage.json");
  if (!existsSync(file)) return null;
  const report = JSON.parse(readFileSync(file, "utf8")) as { totals: { percent_covered: number; covered_lines: number; num_statements: number }; files: Record<string, { summary: { percent_covered: number; covered_lines: number; num_statements: number } }> };
  const row = (name: string, s: { percent_covered: number; covered_lines: number; num_statements: number }): Row => {
    const m = { pct: s.percent_covered, covered: s.covered_lines, total: s.num_statements };
    return { name, lines: m, statements: m, functions: null, branches: null };
  };
  const files = Object.entries(report.files).map(([k, s]) => row(`packages/python/${k}`, s.summary));
  return { total: row("agent-custody (Python)", report.totals), files };
}

const reports = [vitest("receipts"), vitest("state"), python()].filter((r) => r !== null);
if (reports.length === 0) {
  console.error("no coverage reports found; run `bun run coverage` first");
  process.exit(1);
}

const out: string[] = ["## Test coverage", "", "| Package | Lines | Statements | Functions | Branches |", "| --- | --- | --- | --- | --- |"];
for (const r of reports) out.push(`| ${r.total.name} | ${pct(r.total.lines)} | ${pct(r.total.statements)} | ${pct(r.total.functions)} | ${pct(r.total.branches)} |`);
out.push("", "Least covered files (lines):", "", "| File | Lines | Functions |", "| --- | --- | --- |");
const lowest = reports.flatMap((r) => r.files).filter((f) => f.lines.total > 0).sort((a, b) => a.lines.pct - b.lines.pct).slice(0, 15);
for (const f of lowest) out.push(`| \`${f.name}\` | ${pct(f.lines)} | ${pct(f.functions)} |`);
out.push(
  "",
  "Coverage counts code that runs in the test process. Code that a test reaches by running the CLI as a child process (`cli.ts`, and commands such as `export`) shows as uncovered, and `packages/state/src/verify-web.ts` is exercised by the site's tests against every vector, which this report does not include.",
);

const text = out.join("\n") + "\n";
process.stdout.write(text);
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, text);
