// The ACS Guardian: an OWASP Agent Control Standard decision becomes a receipt a third party can check with the
// Guardian's public key alone. ACS's own HMAC baseline cannot do that (ACS §8.6), which is the point of the adapter.
import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { copyFileSync, existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { ACS_ERROR, ACS_RECEIPT_KEY, ACS_STEP_FACT, createAcsGuardian, type AcsResponse } from "../src/acs.ts";
import type { AcsGuardianConfig } from "../src/config.ts";
import { dsseSign, generateKeyPair, loadPrivateKey, loadPublicKey, writeKeyPair } from "../src/crypto.ts";
import { httpLog, serveLog, type LogSink } from "../src/log-sink.ts";
import { RECEIPT_TYPE, type ReceiptBundle } from "../src/receipt.ts";
import { auditExtends, verifyBundle } from "../src/verify.ts";
import { decode } from "./helpers.ts";

const ACS_DIR = resolve(import.meta.dirname, "..", "examples", "acs");
const SAMPLE = JSON.parse(readFileSync(join(ACS_DIR, "tool-call-request.json"), "utf8")) as { id: string; params: Record<string, unknown> & { metadata: Record<string, string> } };

function fixture(log?: LogSink) {
  const dir = mkdtempSync(join(tmpdir(), "acs-"));
  const kp = generateKeyPair();
  const files = writeKeyPair(kp, join(dir, "keys"), "guardian");
  copyFileSync(join(ACS_DIR, "policy.cedar"), join(dir, "policy.cedar"));
  const cfg: AcsGuardianConfig = { identity: { keyFile: files.keyFile }, policyFile: join(dir, "policy.cedar"), receiptsDir: join(dir, "receipts"), logFile: join(dir, "log.jsonl") };
  const guardian = createAcsGuardian(cfg, log ? { log } : {});
  const verify = (b: ReceiptBundle) => verifyBundle(b, { issuerKeys: [loadPublicKey(files.pubFile)], principalKeys: [], logFile: cfg.logFile! });
  return { dir, cfg, guardian, verify };
}

/** a toolCallRequest in the sample's session, with a fresh request_id */
const request = (args: Record<string, unknown>, tool = "file_read") => ({ ...SAMPLE, id: randomUUID(), params: { ...SAMPLE.params, request_id: randomUUID(), payload: { tool: { name: tool }, arguments: Object.fromEntries(Object.entries(args).map(([k, v]) => [k, { value: v }])) } } });
const result = (ref: string | undefined, outputs: unknown[] = ["Q3 revenue grew 4%"]) => ({ ...SAMPLE, id: randomUUID(), method: "steps/toolCallResult", params: { ...SAMPLE.params, request_id: randomUUID(), payload: { tool: { name: "file_read" }, exit_status: "success", outputs: outputs.map((value) => ({ value })), ...(ref ? { request_id_ref: ref } : {}) } } });
type Result = Record<string, unknown> & { decision: string; chain_hash: string; policy_data: Record<string, { receiptId: string; receipt: ReceiptBundle }> };
const ok = (r: AcsResponse | AcsResponse[]): Result => {
  if (Array.isArray(r) || !("result" in r)) throw new Error(`expected a decision, got ${JSON.stringify(r)}`);
  return r.result as Result;
};
const receiptOf = (r: Result) => r.policy_data[ACS_RECEIPT_KEY]!.receipt;

describe("ACS Guardian", () => {
  it("answers the ACS README's sample toolCallRequest with allow and a receipt that verifies with the Guardian's key alone", async () => {
    const { guardian, verify } = fixture();
    const r = ok(await guardian.handle(SAMPLE));
    expect(r).toMatchObject({ type: "final", acs_version: "0.1.0", request_id: SAMPLE.params.request_id, decision: "allow", reasoning: "reading a published report is allowed" });
    const v = verify(receiptOf(r));
    expect(v.checks.filter((c) => !c.ok)).toEqual([]);
    const p = v.statement!.predicate;
    // Everything the agent sent is its own report; the decision and the step record are the Guardian's.
    expect(p.issuer).toMatchObject({ kind: "guardian", framework: "acs steps/toolCallRequest" });
    expect([p.agent.provenance, p.tool.provenance, p.request.provenance]).toEqual(["claimed", "claimed", "claimed"]);
    expect(p.request.args).toEqual({ path: "/reports/q3-summary.md" });
    expect(p.policy).toMatchObject({ decision: "allow", provenance: "observed" });
    expect(p.execution.status).toBe("withheld");
  });

  it("denies what no rule permits, says why on the wire, and receipts the denial", async () => {
    const { guardian, verify } = fixture();
    const r = ok(await guardian.handle(request({ path: "/etc/passwd" })));
    expect(r).toMatchObject({ decision: "deny", reasoning: "no permit policy matched", reason_codes: ["policy_denied"] });
    const v = verify(receiptOf(r));
    expect(v.ok).toBe(true);
    expect(v.statement!.predicate.execution).toMatchObject({ status: "denied", reason: "no permit policy matched" });
  });

  it("a decision cannot be rewritten or minted by anyone without the Guardian's key, unlike an HMAC that both parties hold", async () => {
    const { guardian, verify } = fixture();
    const denied = receiptOf(ok(await guardian.handle(request({ path: "/etc/passwd" }))));
    const st = decode(denied);
    st.predicate.policy = { ...st.predicate.policy!, decision: "allow" };
    st.predicate.execution = { status: "withheld", reason: "allowed", provenance: "observed" };
    const forged = { ...denied, envelope: dsseSign(RECEIPT_TYPE, st, generateKeyPair()) };
    expect(verify(forged).checks.find((c) => c.name === "receipt signature (issuer key)")?.ok).toBe(false);
    const edited = { ...denied, envelope: { ...denied.envelope, payload: Buffer.from(JSON.stringify(st)).toString("base64") } };
    expect(verify(edited).ok).toBe(false);
  });

  it("publishes the ACS chain head (§8.6) that an auditor can recompute from the receipts by §8.2", async () => {
    const { guardian } = fixture();
    const first = ok(await guardian.handle(SAMPLE));
    const second = ok(await guardian.handle(request({ path: "/reports/q4.md" })));
    let prev: string | null = null;
    for (const [r, params] of [[first, SAMPLE.params], [second, undefined]] as const) {
      const p = decode(receiptOf(r)).predicate;
      const step = p.facts[ACS_STEP_FACT]!.value as { request_hash: string; entry_id: string; request_id: string; method: string; previous_hash: string | null; chain_hash: string };
      if (params) expect(step.request_hash).toBe(createHash("sha256").update(jcs(params)).digest("hex"));
      const entry = { entry_id: step.entry_id, step_id: step.request_id, step_type: step.method, request_hash: step.request_hash, timestamp: p.timestamp };
      const recomputed: string = createHash("sha256").update(jcs(entry)).update(prev ? Buffer.from(prev, "hex") : Buffer.alloc(0)).digest("hex");
      expect(step.previous_hash).toBe(prev);
      expect(step.chain_hash).toBe(recomputed);
      expect(r.chain_hash).toBe(recomputed);
      prev = recomputed;
    }
  });

  it("lets a result through only for a request it allowed, and records a request_id_ref it cannot resolve", async () => {
    const { guardian, verify } = fixture();
    ok(await guardian.handle(SAMPLE));
    const known = ok(await guardian.handle(result(SAMPLE.params.request_id as string)));
    expect(known.decision).toBe("allow");
    const unknownRef = randomUUID();
    const orphan = ok(await guardian.handle(result(unknownRef)));
    expect(orphan.decision).toBe("deny");
    const v = verify(receiptOf(orphan));
    expect(v.ok).toBe(true);
    expect(v.statement!.predicate.issuer.framework).toBe("acs steps/toolCallResult");
    expect((v.statement!.predicate.facts[ACS_STEP_FACT]!.value as { request_ref: unknown }).request_ref).toEqual({ id: unknownRef, resolved: false });
  });

  it("puts each decision in a log someone else runs, so an outside party needs no trust in the Guardian's own records (ACS issue #18)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "acs-remote-"));
    const logKp = writeKeyPair(generateKeyPair(), join(dir, "log-keys"), "log");
    const logPub = loadPublicKey(logKp.pubFile);
    const server = await serveLog(join(dir, "operator.jsonl"), loadPrivateKey(logKp.keyFile), { port: 0 });
    try {
      const gKp = writeKeyPair(generateKeyPair(), join(dir, "keys"), "guardian");
      const guardian = createAcsGuardian({ identity: { keyFile: gKp.keyFile }, policyFile: join(ACS_DIR, "policy.cedar"), receiptsDir: join(dir, "receipts"), log: { url: server.url } }, { log: httpLog(server.url, { keys: [logPub] }) });
      const first = receiptOf(ok(await guardian.handle(SAMPLE)));
      const denial = receiptOf(ok(await guardian.handle(request({ path: "/etc/passwd" }))));
      const issuerKeys = [loadPublicKey(gKp.pubFile)];
      // the tree head is the log operator's, so the Guardian's key alone does not vouch for the log
      expect(verifyBundle(first, { issuerKeys, principalKeys: [] }).checks.find((c) => c.name === "tree head signature")?.ok).toBe(false);
      expect(verifyBundle(first, { issuerKeys, principalKeys: [], logKeys: [logPub] }).ok).toBe(true);
      // the head that holds the denial extends the head that held the first decision: the Guardian could not drop it later
      const size = (b: ReceiptBundle) => (JSON.parse(Buffer.from(b.treeHead.payload, "base64").toString()) as { treeSize: number }).treeSize;
      const proof = (await (await fetch(new URL(`consistency?old=${size(first)}&new=${size(denial)}`, server.url), { signal: AbortSignal.timeout(5000) })).json()) as { hashes: string[] };
      expect(auditExtends(first.treeHead, denial.treeHead, proof.hashes, [logPub]).ok).toBe(true);
    } finally {
      await server.close();
    }
  });

  it("decides two concurrent calls with one request_id once, so a replay cannot slip in while a receipt is being written", async () => {
    const { cfg, guardian } = fixture();
    const answers = await Promise.all([guardian.handle(SAMPLE), guardian.handle(SAMPLE)]);
    const codes = answers.map((a) => (!Array.isArray(a) && "error" in a ? a.error.code : ok(a).decision)).sort();
    expect(codes).toEqual([ACS_ERROR.replay, "allow"].sort());
    expect(readdirSync(cfg.receiptsDir).filter((f) => f.endsWith(".json"))).toHaveLength(1);
  });

  it("keeps one chain per session under concurrent calls: each step links to the one before, never forks", async () => {
    const { guardian } = fixture();
    const answers = await Promise.all([1, 2, 3, 4].map((n) => guardian.handle(request({ path: `/reports/r${n}.md` }))));
    const steps = answers.map((a) => decode(receiptOf(ok(a))).predicate.facts[ACS_STEP_FACT]!.value as { previous_hash: string | null; chain_hash: string });
    const prevs = steps.map((x) => x.previous_hash);
    expect(prevs.filter((x) => x === null)).toHaveLength(1);
    expect(new Set(prevs).size).toBe(4);
    for (const x of steps) if (x.previous_hash) expect(steps.map((y) => y.chain_hash)).toContain(x.previous_hash);
  });

  it("refuses another agent on a session it did not open, so a caller who knows a session id cannot extend its chain", async () => {
    const { guardian } = fixture();
    ok(await guardian.handle(SAMPLE));
    const other = { ...result(SAMPLE.params.request_id as string), params: { ...result(SAMPLE.params.request_id as string).params, metadata: { ...SAMPLE.params.metadata, agent_id: "someone-else" } } };
    expect(await guardian.handle(other)).toMatchObject({ error: { code: ACS_ERROR.sessionRefused, data: { reason: "agent_mismatch" } } });
  });

  it("gives the policy the request's tool and whether a result already went through, so one allowed request lets one result through", async () => {
    const { guardian, verify } = fixture();
    ok(await guardian.handle(SAMPLE));
    const ref = SAMPLE.params.request_id as string;
    expect(ok(await guardian.handle(result(ref))).decision).toBe("allow");
    const again = ok(await guardian.handle(result(ref)));
    expect(again.decision).toBe("deny");
    const step = verify(receiptOf(again)).statement!.predicate.facts[ACS_STEP_FACT]!.value as { request_ref: Record<string, unknown> };
    expect(step.request_ref).toMatchObject({ id: ref, resolved: true, decision: "allow", tool: "file_read", agent: "research-assistant", consumed: true });
  });

  it("the example policy refuses a path that climbs out of /reports", async () => {
    const { guardian } = fixture();
    expect(ok(await guardian.handle(request({ path: "/reports/../etc/passwd" }))).decision).toBe("deny");
  });

  it("re-reads the policy when the file changes, and keeps the one in force when the new file does not parse", async () => {
    const { cfg, guardian } = fixture();
    expect(ok(await guardian.handle(request({ path: "/reports/a.md" }))).decision).toBe("allow");
    writeFileSync(cfg.policyFile, 'forbid (principal, action, resource);\n');
    const tightened = guardian.policyDigest;
    expect(ok(await guardian.handle(request({ path: "/reports/a.md" }))).decision).toBe("deny");
    writeFileSync(cfg.policyFile, "permit (principal, action, resource) when {");
    expect(ok(await guardian.handle(request({ path: "/reports/a.md" }))).decision).toBe("deny");
    expect(guardian.policyDigest).toBe(tightened);
  });

  it("the CLI exits 1 when any answer is an error rather than a decision, so a wrapper reading the exit code is not misled", () => {
    const { dir, cfg } = fixture();
    const configFile = join(dir, "acs.json");
    writeFileSync(configFile, JSON.stringify(cfg));
    const cli = (input: unknown) => spawnSync(process.execPath, [resolve(import.meta.dirname, "..", "src", "cli.ts"), "acs", "--config", configFile], { input: JSON.stringify(input), encoding: "utf8" });
    expect(cli(SAMPLE).status).toBe(0);
    expect(cli(request({ path: "/etc/passwd" })).status).toBe(0);
    expect(cli([request({ path: "/reports/x.md" }), { jsonrpc: "2.0", id: 9, method: "handshake/hello", params: {} }]).status).toBe(1);
  });

  it("refuses a replayed request_id in the session and writes no second receipt", async () => {
    const { cfg, guardian } = fixture();
    ok(await guardian.handle(SAMPLE));
    const again = await guardian.handle(SAMPLE);
    expect(again).toMatchObject({ id: SAMPLE.id, error: { code: ACS_ERROR.replay } });
    expect(readdirSync(cfg.receiptsDir).filter((f) => f.endsWith(".json"))).toHaveLength(1);
  });

  it("gives no decision when the receipt cannot be logged, so no decision goes unrecorded", async () => {
    const refusing: LogSink = { kind: "http", where: "https://log.invalid", append: () => Promise.reject(new Error("log down")) };
    const { cfg, guardian } = fixture(refusing);
    const r = await guardian.handle(SAMPLE);
    expect(r).toMatchObject({ error: { code: ACS_ERROR.internal, data: { reason: "receipt_not_written" } } });
    expect(existsSync(cfg.receiptsDir) ? readdirSync(cfg.receiptsDir).filter((f) => f.endsWith(".json")) : []).toEqual([]);
  });

  it("answers what it does not evaluate with JSON-RPC and ACS errors, and pings without a receipt", async () => {
    const { cfg, guardian } = fixture();
    expect(await guardian.handle({ ...SAMPLE, method: "handshake/hello" })).toMatchObject({ error: { code: ACS_ERROR.methodNotFound } });
    expect(await guardian.handle({ ...SAMPLE, method: "steps/memoryStore" })).toMatchObject({ error: { code: ACS_ERROR.methodNotFound } });
    expect(await guardian.handle({ ...SAMPLE, params: { ...SAMPLE.params, acs_version: "1.0.0" } })).toMatchObject({ error: { code: ACS_ERROR.unsupportedVersion } });
    expect(await guardian.handle({ ...SAMPLE, params: { ...SAMPLE.params, metadata: {} } })).toMatchObject({ error: { code: ACS_ERROR.invalidParams } });
    expect(await guardian.handle({ jsonrpc: "2.0", method: "steps/toolCallRequest" })).toMatchObject({ id: null, error: { code: ACS_ERROR.invalidRequest } });
    expect(await guardian.handle([])).toMatchObject({ id: null, error: { code: ACS_ERROR.invalidRequest } });
    expect(await guardian.handle({ ...SAMPLE, method: "system/ping", params: { ...SAMPLE.params, payload: { echo: "hi" } } })).toMatchObject({ result: { decision: "allow", payload: { status: "ok", echo: "hi" } } });
    expect(existsSync(cfg.receiptsDir) ? readdirSync(cfg.receiptsDir).filter((f) => f.endsWith(".json")) : []).toEqual([]);
  });

  it("evaluates a batch in order, one answer per request", async () => {
    const { guardian } = fixture();
    const answers = await guardian.handle([SAMPLE, request({ path: "/etc/shadow" })]);
    expect(Array.isArray(answers) && answers.map((a) => ("result" in a ? (a.result as Result).decision : a.error.code))).toEqual(["allow", "deny"]);
  });

  it("refuses to start on a policy that does not parse", () => {
    const dir = mkdtempSync(join(tmpdir(), "acs-bad-"));
    const files = writeKeyPair(generateKeyPair(), join(dir, "keys"), "guardian");
    const bad = join(dir, "policy.cedar");
    writeFileSync(bad, "permit (principal, action, resource) when {");
    expect(() => createAcsGuardian({ identity: { keyFile: files.keyFile }, policyFile: bad, receiptsDir: join(dir, "r"), logFile: join(dir, "log.jsonl") })).toThrow(/does not parse/);
  });
});

/** RFC 8785 for the plain JSON these tests use: keys sorted by code unit, no whitespace. Written apart from src on purpose. */
function jcs(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(jcs).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${jcs((v as Record<string, unknown>)[k])}`).join(",")}}`;
  return JSON.stringify(v);
}
