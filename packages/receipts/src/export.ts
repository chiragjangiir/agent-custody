// `agent-custody export`: copies receipt bundles from the receipts directory of a machine into a directory that goes into a pull request.
// The module reads files and calls the verifier. It never rewrites a receipt, because the signature covers it, and it never uses the network.
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { under, type Path } from "./capture.ts";
import type { ReceiptBundle, ReceiptPredicate } from "./receipt.ts";
import { verifyBundle, type VerifyOptions } from "./verify.ts";

const AUTHORIZATION = ".authorization.json";

export interface ReceiptExportOptions {
  receiptsDir: string;
  outDir: string;
  verify: VerifyOptions;
  /** keep the receipts issued at or after this time (ms since the epoch) */
  since?: number;
  /** copy a receipt that holds plain values */
  allowClear?: boolean;
}

export interface ReceiptExportLine {
  file: string;
  outcome: "copied" | "refused" | "skipped";
  /** the reason for a refusal or a skip */
  reason?: string;
  /** the sides of a copied receipt that carry plain values (only with allowClear) */
  clear: string[];
}

export interface ReceiptExportResult {
  lines: ReceiptExportLine[];
  copied: number;
  refused: number;
  skipped: number;
  /** set when no receipt was copied */
  problem?: string;
}

/** The bundle files at the top level of a directory. Subdirectories, symbolic links, `<id>.authorization.json` files, and other files are not read. */
function bundleFiles(dir: string): string[] {
  if (!existsSync(dir) || !statSync(dir).isDirectory()) throw new Error(`${dir} is not a directory`);
  return readdirSync(dir, { withFileTypes: true })
    .filter((e) => e.isFile() && e.name.endsWith(".json") && !e.name.endsWith(AUTHORIZATION))
    .map((e) => e.name)
    .sort();
}

/** True when a value carries something to read. An empty object, an empty list, and null do not. */
function hasData(v: unknown): boolean {
  if (v === undefined || v === null) return false;
  if (Array.isArray(v)) return v.some(hasData);
  if (typeof v === "object") return Object.values(v).some(hasData);
  return true;
}

/**
 * The sides of a call that the signed receipt carries in plain values: "args", "result", or "facts". The signed capture
 * note decides: a side that holds data and has no withheld path under it is in clear. A field that a rule lists in
 * `clear` leaves a commitment for the other fields beside it, so it does not count. A side with only fields in its
 * `clear` list has no commitment, and the check cannot tell it from a side in mode `clear`.
 */
export function clearSides(p: ReceiptPredicate): string[] {
  const withheld: Path[] = p.capture?.withheld ?? [];
  const open = (path: Path, value: unknown) => hasData(value) && !withheld.some((w) => under(w, path));
  const sides: string[] = [];
  if (open(["request", "args"], p.request?.args)) sides.push("args");
  const exec = p.execution as unknown as Record<string, unknown>;
  // the error message and the denial reason follow the result: a private rule withholds them, a clear rule does not
  if (["result", "error", "reason"].some((f) => open(["execution", f], exec[f]))) sides.push("result");
  if (Object.entries(p.facts ?? {}).some(([name, fact]) => open(["facts", name, "value"], fact?.value))) sides.push("facts");
  return sides;
}

/** Verifies each bundle, checks that it keeps its values private, and copies the bytes of those that pass. */
export function exportReceipts(opts: ReceiptExportOptions): ReceiptExportResult {
  if (resolve(opts.receiptsDir) === resolve(opts.outDir)) throw new Error("--out must not be the receipts directory");
  const lines: ReceiptExportLine[] = [];
  for (const name of bundleFiles(opts.receiptsDir)) {
    const refuse = (reason: string): void => void lines.push({ file: name, outcome: "refused", reason, clear: [] });
    // the bytes that were verified are the bytes that are written
    const bytes = readFileSync(join(opts.receiptsDir, name));
    let result: ReturnType<typeof verifyBundle>;
    try {
      result = verifyBundle(JSON.parse(bytes.toString("utf8")) as ReceiptBundle, opts.verify);
    } catch (e) {
      refuse(`not a receipt bundle: ${e instanceof Error ? e.message : String(e)}`);
      continue;
    }
    const p = result.statement?.predicate;
    const failed = result.checks.filter((c) => !c.ok).map((c) => c.name);
    if (p && name !== `${p.receiptId}.json`) failed.push("file name matches receipt id");
    if (!p || failed.length) {
      refuse(failed.length ? failed.join("; ") : "no receipt in the bundle");
      continue;
    }
    if (opts.since !== undefined && !(Date.parse(p.timestamp) >= opts.since)) {
      lines.push({ file: name, outcome: "skipped", reason: `issued ${p.timestamp}, before --since`, clear: [] });
      continue;
    }
    const clear = clearSides(p);
    if (clear.length && !opts.allowClear) {
      refuse(`${clear.join(" and ")} in clear: a capture rule must withhold it (or give --allow-clear)`);
      continue;
    }
    mkdirSync(opts.outDir, { recursive: true });
    writeFileSync(join(opts.outDir, name), bytes);
    lines.push({ file: name, outcome: "copied", clear });
  }
  const count = (o: ReceiptExportLine["outcome"]) => lines.filter((l) => l.outcome === o).length;
  const copied = count("copied");
  return { lines, copied, refused: count("refused"), skipped: count("skipped"), ...(copied === 0 ? { problem: lines.length === 0 ? "The receipts directory holds no receipt bundle." : "No receipt was copied." } : {}) };
}

/** One line for each receipt, then the count. */
export function formatReceiptExport(r: ReceiptExportResult): string[] {
  const out = r.lines.map((l) => (l.outcome === "copied" ? `copied  ${l.file}${l.clear.length ? ` (plain values: ${l.clear.join(", ")})` : ""}` : `${l.outcome.padEnd(7)} ${l.file}: ${l.reason}`));
  out.push(`${r.copied} copied, ${r.refused} refused, ${r.skipped} skipped`);
  return out;
}

export const CLEAR_WARNING = "warning: --allow-clear is on. Each receipt marked with plain values publishes its arguments or its result to everyone who can read the output directory.";
