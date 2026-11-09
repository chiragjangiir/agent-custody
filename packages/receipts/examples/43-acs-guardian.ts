// Aspect: an OWASP Agent Control Standard (ACS) Guardian whose decisions land in a transparency log. Source: src/acs.ts, src/config.ts
// Run:    node examples/43-acs-guardian.ts
//
// ACS is a wire contract: before it acts, an agent's instrumentation sends a JSON-RPC hook such as steps/toolCallRequest
// to a Guardian, which answers allow or deny. ACS's baseline signature is an HMAC both sides hold, so a decision is not
// attributable to the Guardian (ACS §8.6), and its audit chain is only as trustworthy as the one Guardian that keeps it
// (ACS issue #18). Here agent-custody is the Guardian: the Cedar policy decides, each decision and the session's
// chain_hash go into a receipt signed with the Guardian's key, and the receipt is appended to a log someone else runs.
// An outside party checks it offline with two public keys, and checks that the log was never rewritten.
import { spawn } from "node:child_process";
import { copyFileSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { ACS_RECEIPT_KEY, ACS_STEP_FACT, createAcsGuardian, type AcsResponse } from "../src/acs.ts";
import { loadAcsGuardianConfig } from "../src/config.ts";
import { generateKeyPair, loadPrivateKey, loadPublicKey, writeKeyPair } from "../src/crypto.ts";
import { serveLog } from "../src/log-sink.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { auditExtends } from "../src/verify.ts";
import { out, step } from "./_out.ts";

const acs = resolve(import.meta.dirname, "acs");
const cli = resolve(import.meta.dirname, "..", "src", "cli.ts");
const dir = out("43-acs-guardian");
// asynchronous, so the log served in this process can answer the child
const run = (args: string[], input?: string) => new Promise<{ status: number | null; stdout: string; stderr: string }>((done) => {
  const child = spawn(process.execPath, [cli, ...args]);
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (c) => (stdout += c));
  child.stderr.on("data", (c) => (stderr += c));
  child.on("close", (status) => done({ status, stdout, stderr }));
  child.stdin.end(input ?? "");
});
const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;

step(1, "a log run by someone other than the Guardian, with its own key (in-process here, on a free port)");
const logKey = writeKeyPair(generateKeyPair(), join(dir, "log-keys"), "log");
process.env.ACS_DEMO_LOG_TOKEN = "demo-token";
const log = await serveLog(join(dir, "log-operator.jsonl"), loadPrivateKey(logKey.keyFile), { port: 0, tokens: ["demo-token"] });
console.log(`   log at ${log.url}, keyid ${loadPublicKey(logKey.pubFile).keyid.slice(0, 12)}`);

step(2, "the Guardian: its own key, the policy, and acs.json naming that log, with the log's key pinned");
writeKeyPair(generateKeyPair(), join(dir, "keys"), "guardian");
copyFileSync(join(acs, "policy.cedar"), join(dir, "policy.cedar"));
writeFileSync(join(dir, "acs.json"), JSON.stringify({ identity: { keyFile: "keys/guardian.key" }, policyFile: "policy.cedar", receiptsDir: "receipts", log: { url: log.url, tokenEnv: "ACS_DEMO_LOG_TOKEN", keys: ["log-keys/log.pub"] } }, null, 2));
console.log("   policy:\n" + readFileSync(join(dir, "policy.cedar"), "utf8").split("\n").map((l) => "     " + l).join("\n"));

step(3, "pipe the ACS README's sample toolCallRequest through: agent-custody acs --config acs.json < tool-call-request.json");
const sample = readFileSync(join(acs, "tool-call-request.json"), "utf8");
const piped = await run(["acs", "--config", join(dir, "acs.json")], sample);
if (piped.status !== 0) throw new Error(piped.stderr);
const answer = JSON.parse(piped.stdout) as { result: { decision: string; reasoning: string; chain_hash: string; policy_data: Record<string, { receiptId: string; receipt: ReceiptBundle }> } };
const first = answer.result.policy_data[ACS_RECEIPT_KEY]!.receipt;
const step1 = decode(first).predicate.facts[ACS_STEP_FACT]!.value as { chain_hash: string; request_hash: string };
console.log(`   decision ${answer.result.decision} ("${answer.result.reasoning}")`);
console.log(`   chain_hash ${answer.result.chain_hash.slice(0, 16)}… on the wire, and the same inside the signed receipt: ${step1.chain_hash === answer.result.chain_hash}`);
console.log(`   tree head signed by the log's key ${first.treeHead.signatures[0]!.keyid.slice(0, 12)}, not the Guardian's`);
if (answer.result.decision !== "allow" || step1.chain_hash !== answer.result.chain_hash) throw new Error("unexpected answer");

step(4, "an outside party verifies offline, with two public keys and no trust in the Guardian's own records");
writeFileSync(join(dir, "receipt.json"), JSON.stringify(first, null, 2));
const verified = await run(["verify", join(dir, "receipt.json"), "--issuer-key", join(dir, "keys", "guardian.pub"), "--log-key", logKey.pubFile]);
console.log("   agent-custody verify receipt.json --issuer-key guardian.pub --log-key log.pub");
console.log(verified.stdout.split("\n").filter((l) => /guardian|tree head|inclusion|RESULT|^(agent|tool|args|fact\.acsStep|policy|execution) /.test(l)).map((l) => "   " + l.slice(0, 200)).join("\n"));
if (verified.status !== 0) throw new Error("the receipt did not verify");

step(5, "the same session, in one long-lived Guardian: a read outside /reports is denied; a result passes only for an allowed request");
const guardian = createAcsGuardian(loadAcsGuardianConfig(join(dir, "acs.json")));
const env = JSON.parse(sample) as { params: Record<string, unknown> };
const decide = async (method: string, payload: unknown) => {
  const r = (await guardian.handle({ ...env, id: crypto.randomUUID(), method, params: { ...env.params, request_id: crypto.randomUUID(), payload } })) as AcsResponse;
  if (!("result" in r)) throw new Error(JSON.stringify(r));
  return r.result as { request_id: string; decision: string; reasoning: string; policy_data: Record<string, { receipt: ReceiptBundle }> };
};
const allowed = await decide("steps/toolCallRequest", { tool: { name: "file_read" }, arguments: { path: { value: "/reports/q4.md" } } });
const denied = await decide("steps/toolCallRequest", { tool: { name: "file_read" }, arguments: { path: { value: "/etc/passwd" } } });
const passed = await decide("steps/toolCallResult", { tool: { name: "file_read" }, request_id_ref: allowed.request_id, exit_status: "success", outputs: [{ value: "Q4 draft" }] });
const orphan = await decide("steps/toolCallResult", { tool: { name: "file_read" }, request_id_ref: crypto.randomUUID(), exit_status: "success", outputs: [{ value: "?" }] });
for (const [what, d] of [["read /reports/q4.md", allowed], ["read /etc/passwd", denied], ["its result", passed], ["a result for no known request", orphan]] as const) console.log(`   ${what.padEnd(30)} ${d.decision.padEnd(5)} ${d.reasoning}`);
if ([allowed, denied, passed, orphan].map((d) => d.decision).join() !== "allow,deny,allow,deny") throw new Error("unexpected decisions");

step(6, "the auditor checks that the log after the deny extends the log that held the first decision: nothing was dropped or rewritten");
const last = orphan.policy_data[ACS_RECEIPT_KEY]!.receipt;
const size = (b: ReceiptBundle) => (JSON.parse(Buffer.from(b.treeHead.payload, "base64").toString()) as { treeSize: number }).treeSize;
const proof = (await (await fetch(new URL(`consistency?old=${size(first)}&new=${size(last)}`, log.url), { signal: AbortSignal.timeout(5000) })).json()) as { hashes: string[] };
const audit = auditExtends(first.treeHead, last.treeHead, proof.hashes, [loadPublicKey(logKey.pubFile)]);
console.log(audit.checks.map((c) => `   ${c.ok ? "PASS" : "FAIL"}  ${c.name}${c.detail ? `  (${c.detail})` : ""}`).join("\n"));
await log.close();
if (!audit.ok) throw new Error("the log does not extend");

console.log("\n   ACS issue #18, direction 1 (chain_hash signed under a long-lived key, exported as a checkpoint) and direction 3");
console.log("   (signed heads in an external append-only log). Direction 2, Guardians exchanging chain heads, is not built.");
console.log("   The agent chose to ask and is trusted to honor the answer; the gateway is the enforcement point it cannot skip.");
console.log("\nOK");
