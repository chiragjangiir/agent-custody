// `agent-custody verify --markdown`: verifies every receipt bundle in a directory and prints one table for a pull request.
// The GitHub Action in action.yml posts this table. The module reads files and calls the verifier. It never uses the network.
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join } from "node:path";
import type { ReceiptBundle } from "./receipt.ts";
import { verifyBundle, type VerifyOptions } from "./verify.ts";

/** The action finds its own comment again by this line, so it edits one comment and never adds a second. */
export const SUMMARY_MARKER = "<!-- agent-custody -->";

const AUTHORIZATION = ".authorization.json";
const MAX_ROWS = 200;
const MAX_NAMES = 3;
const KNOWN_STATUS = new Set(["executed", "denied", "failed", "error", "withheld"]);

export interface SummaryRow {
  file: string;
  receiptId: string;
  tool: string;
  /** the execution status in the signed receipt, or "-" when the signature fails and nothing in the receipt is trusted */
  status: string;
  /** "verified", or the names of the checks that failed, joined with "; " */
  result: string;
  ok: boolean;
}

export interface PrSummary {
  ok: boolean;
  rows: SummaryRow[];
  /** set when no receipt was read */
  problem?: string;
}

/** The bundle files of a directory (not the `<id>.authorization.json` files, not the subdirectories, not the symbolic links), or the one file given. A path that does not exist holds no receipts. */
export function receiptFiles(path: string): string[] {
  if (!existsSync(path)) return [];
  if (!statSync(path).isDirectory()) return [path];
  return readdirSync(path, { withFileTypes: true })
    .filter((e) => e.isFile() && e.name.endsWith(".json") && !e.name.endsWith(AUTHORIZATION))
    .map((e) => join(path, e.name))
    .sort();
}

function rowOf(file: string, opts: VerifyOptions): SummaryRow {
  const stem = basename(file).replace(/\.json$/, "");
  const fail = (result: string): SummaryRow => ({ file, receiptId: stem, tool: "-", status: "-", result, ok: false });
  let bundle: ReceiptBundle;
  try {
    bundle = JSON.parse(readFileSync(file, "utf8")) as ReceiptBundle;
  } catch {
    // the comment is public: a parser message can quote the first bytes of the file
    return fail("not a JSON file");
  }
  let result: ReturnType<typeof verifyBundle>;
  try {
    result = verifyBundle(bundle, opts);
  } catch {
    return fail("not a receipt bundle");
  }
  const failed = result.checks.filter((c) => !c.ok).map((c) => c.name);
  const p = result.statement?.predicate;
  if (!p) return fail(failed.length ? failed.join("; ") : "no receipt in the bundle");
  // the gateway names each file by its receipt id, so a valid receipt under another name does not stand in for that one
  if (basename(file) !== `${p.receiptId}.json`) failed.push("file name matches receipt id");
  return { file, receiptId: p.receiptId, tool: p.tool.name, status: p.execution.status, result: failed.length ? failed.join("; ") : "verified", ok: failed.length === 0 };
}

/** Verifies each file. Fails when a receipt does not verify, and when there is no receipt at all. */
export function summarizeReceipts(files: string[], opts: VerifyOptions): PrSummary {
  if (files.length === 0) return { ok: false, rows: [], problem: "No receipt bundles found." };
  const rows = files.map((f) => rowOf(f, opts));
  return { ok: rows.every((r) => r.ok), rows };
}

/** Receipt data is text from the agent. Remove what could break a table cell or inject Markdown or HTML. */
function code(text: string, max = 80): string {
  if (text === "-") return text;
  const clean = text.replace(/[^\x20-\x7e]|[|`<>\\]/g, "?");
  return `\`${clean.length > max ? `${clean.slice(0, max - 3)}...` : clean}\``;
}

function resultCell(r: SummaryRow): string {
  if (r.ok) return "verified";
  const names = r.result.split("; ");
  const shown = names.slice(0, MAX_NAMES).map((n) => code(n)).join("; ");
  return names.length > MAX_NAMES ? `${shown} (+${names.length - MAX_NAMES} more)` : shown;
}

/** The pull request comment and the job summary. It starts with the marker line. */
export function formatSummaryMarkdown(s: PrSummary): string {
  const lines = [SUMMARY_MARKER, "## agent-custody receipts", ""];
  if (s.rows.length === 0) {
    lines.push(`**Not verified.** ${s.problem ?? "No receipt bundles found."}`);
    return lines.join("\n") + "\n";
  }
  const failed = s.rows.filter((r) => !r.ok).length;
  lines.push(failed === 0 ? `**Verified.** All ${s.rows.length} receipts verify.` : `**Not verified.** ${failed} of ${s.rows.length} receipts do not verify.`, "");
  lines.push("| Receipt | Tool | Status | Result |", "| --- | --- | --- | --- |");
  const shown = [...s.rows.filter((r) => !r.ok), ...s.rows.filter((r) => r.ok)].slice(0, MAX_ROWS);
  for (const r of shown) lines.push(`| ${code(r.receiptId)} | ${code(r.tool)} | ${KNOWN_STATUS.has(r.status) ? r.status : code(r.status)} | ${resultCell(r)} |`);
  if (s.rows.length > shown.length) lines.push("", `${s.rows.length - shown.length} more receipts are not shown. Every receipt that does not verify is listed first.`);
  return lines.join("\n") + "\n";
}
