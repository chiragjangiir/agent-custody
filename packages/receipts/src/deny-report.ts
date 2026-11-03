// `agent-custody report`: the calls that the policy would have denied, read from the receipts of an SDK config.
// Each receipt is verified with the agent's key first. A receipt that does not verify is counted apart and never listed as a denial.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { loadSdkConfig } from "./config.ts";
import { loadPrivateKey, loadPublicKey } from "./crypto.ts";
import { policyDigest, policyReasons, policyRules } from "./policy.ts";
import type { ReceiptBundle } from "./receipt.ts";
import { verifyBundle } from "./verify.ts";

export interface DeniedCall {
  receiptId: string;
  timestamp: string;
  tool: string;
  /** The command, the file path, or the URL of the call. */
  target: string;
  /** The Cedar policy ids that decided, such as `policy3`. */
  policyIds: string[];
  /** The `@reason` of each rule that has one. */
  reasons: string[];
  /** The text of each rule, when the policy file still has the digest that the receipt names. */
  rules: string[];
}

export interface DenyReport {
  configFile: string;
  receiptsDir: string;
  observe: boolean;
  /** Receipts that verified. */
  verified: number;
  /** Denials recorded with `enforced: false`: the call ran. */
  wouldDeny: DeniedCall[];
  /** Denials that the policy enforced: the call was blocked. */
  denied: DeniedCall[];
  unverified: { file: string; reason: string }[];
}

const ANNOTATIONS = /^(?:\s*@\w+\s*\("(?:[^"\\]|\\.)*"\))+\s*/;
const TARGET_ARGS = ["command", "file_path", "notebook_path", "path", "url"];

function targetOf(args: unknown): string {
  if (!args || typeof args !== "object") return "(withheld)";
  const a = args as Record<string, unknown>;
  const name = TARGET_ARGS.find((k) => typeof a[k] === "string");
  const text = name ? (a[name] as string) : JSON.stringify(a);
  return text.replace(/\s+/g, " ").trim();
}

export function denyReport(configFile: string): DenyReport {
  const cfg = loadSdkConfig(configFile);
  const issuer = loadPrivateKey(cfg.identity.keyFile);
  const opts = {
    issuerKeys: [{ publicKey: issuer.publicKey, keyid: issuer.keyid }],
    principalKeys: [],
    logKeys: (cfg.log?.keys ?? []).map(loadPublicKey),
    ...(cfg.logFile ? { logFile: cfg.logFile } : {}),
    ...(cfg.log?.logId ? { logId: cfg.log.logId } : {}),
  };
  const policyText = cfg.policyFile && existsSync(cfg.policyFile) ? readFileSync(cfg.policyFile, "utf8") : null;
  const rules = policyText === null ? [] : policyRules(policyText);
  const reasons = policyText === null ? [] : policyReasons(policyText);
  const currentDigest = policyText === null ? null : policyDigest(policyText);

  const report: DenyReport = { configFile, receiptsDir: cfg.receiptsDir, observe: cfg.mode === "observe", verified: 0, wouldDeny: [], denied: [], unverified: [] };
  const files = existsSync(cfg.receiptsDir)
    ? readdirSync(cfg.receiptsDir, { withFileTypes: true }).filter((e) => (e.isFile() || e.isSymbolicLink()) && e.name.endsWith(".json") && !e.name.endsWith(".authorization.json")).map((e) => e.name).sort()
    : [];
  for (const file of files) {
    try {
      const result = verifyBundle(JSON.parse(readFileSync(join(cfg.receiptsDir, file), "utf8")) as ReceiptBundle, opts);
      if (!result.ok || !result.statement) {
        const failed = result.checks.filter((c) => !c.ok).map((c) => c.name);
        throw new Error(`failed: ${failed.join("; ")}`);
      }
      const p = result.statement.predicate;
      if (`${p.receiptId}.json` !== file) throw new Error("the file name does not match the receipt id");
      report.verified++;
      if (p.policy?.decision !== "deny") continue;
      const policyIds = p.policy.reasons;
      const known = p.policy.policyDigest === currentDigest;
      const call: DeniedCall = {
        receiptId: p.receiptId,
        timestamp: p.timestamp,
        tool: p.tool.name,
        target: targetOf(p.request.args),
        policyIds,
        reasons: known ? policyIds.map((id) => reasons[Number(id.replace(/^policy/, ""))]).filter((r): r is string => typeof r === "string") : [],
        rules: known ? policyIds.map((id) => rules[Number(id.replace(/^policy/, ""))]).filter((r): r is string => typeof r === "string").map((r) => r.replace(/\s+/g, " ").replace(/;$/, "").replace(ANNOTATIONS, "").trim()) : [],
      };
      (p.policy.enforced === false ? report.wouldDeny : report.denied).push(call);
    } catch (e) {
      report.unverified.push({ file, reason: e instanceof Error ? e.message : String(e) });
    }
  }
  const byTime = (a: DeniedCall, b: DeniedCall) => (a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : 0);
  report.wouldDeny.sort(byTime);
  report.denied.sort(byTime);
  return report;
}

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;
const clip = (s: string) => (s.length > 160 ? `${s.slice(0, 157)}...` : s);

export function formatDenyReport(r: DenyReport): string {
  const lines: string[] = [];
  const list = (calls: DeniedCall[]) => {
    for (const c of calls) {
      lines.push("", `  ${c.tool}: ${clip(c.target)}`);
      if (c.reasons.length) lines.push(`    reason:  ${c.reasons.join("; ")}`);
      lines.push(`    rule:    ${c.rules.length ? clip(c.rules.join(" | ")) : c.policyIds.join(", ") || "(none)"}${c.rules.length ? ` [${c.policyIds.join(", ")}]` : ""}`);
      lines.push(`    receipt: ${c.receiptId}  (${c.timestamp})`);
    }
  };
  if (!r.verified && !r.unverified.length) {
    lines.push(`No receipts in ${r.receiptsDir} yet.`, "Start a Claude Code session with the hooks registered, then run this report again.");
    return lines.join("\n");
  }
  lines.push(`would have denied ${plural(r.wouldDeny.length, "call")}${r.wouldDeny.length ? " (the policy recorded each one and blocked nothing)" : ""}`);
  list(r.wouldDeny);
  lines.push("", `Checked ${plural(r.verified + r.unverified.length, "receipt")}: ${r.verified} verified, ${r.unverified.length} did not verify.`);
  if (r.denied.length) {
    lines.push("", `denied ${plural(r.denied.length, "call")} (the policy enforced these, and the call did not run)`);
    list(r.denied);
  }
  if (r.unverified.length) {
    lines.push("", `${plural(r.unverified.length, "receipt")} did not verify. The report does not count them.`);
    for (const u of r.unverified) lines.push(`  ${u.file}: ${u.reason}`);
  }
  lines.push("");
  lines.push(r.observe
    ? `To enforce this policy, remove the "mode": "observe" line from ${r.configFile}. A denied call is then blocked before it runs.`
    : `The config ${r.configFile} has no "mode": "observe" line, so the policy already blocks a denied call.`);
  return lines.join("\n");
}
