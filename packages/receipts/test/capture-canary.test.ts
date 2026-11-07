// The canary: one secret in the withheld arguments of a call, an upstream that repeats it in every place a result can
// carry a value, and every path a call can take through the gateway and the SDK. Under one private rule, the secret
// must reach nothing the receipt leaves in clear: not the signed statement, not the authorization inside it, not the
// authorization file, not the log, not an exporter. The control runs the same calls with no rule and finds the secret,
// so that the check can fail. Every leak of the four review rounds on #123 would have failed this test.
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { randomBytes, randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { APPROVAL_META_KEY, APPROVAL_TYPE, createApproval } from "../src/approval.ts";
import { isCommitment, pathKey } from "../src/capture.ts";
import { loadConfig, loadSdkConfig } from "../src/config.ts";
import { digestOf, dsseCountersign, dsseSign, generateKeyPair, loadPrivateKey, loadPublicKey, writeKeyPair, type Envelope } from "../src/crypto.ts";
import { createGateway, createGatewayHost, LOG_PENDING_META_KEY, RECEIPT_META_KEY, RETRY_RECEIPT_META_KEY, type Gateway } from "../src/gateway.ts";
import { OPERATION_META_KEY } from "../src/operations.ts";
import { financialFixture } from "../scripts/financial-fixture.ts";
import { fileLog, type LogSink } from "../src/log-sink.ts";
import { spanFor } from "../src/otel.ts";
import type { ReceiptBundle, ReceiptPredicate, ReceiptStatement } from "../src/receipt.ts";
import { createSdkIssuer } from "../src/sdk/index.ts";
import { hecEvent } from "../src/splunk.ts";
import { formatReport, verifyBundle } from "../src/verify.ts";
import { buildFixture, buildSdkFixture } from "../scripts/fixture.ts";
import { buildDoorFixture, startOrigin } from "../scripts/door-fixture.ts";
import { loadDoorConfig } from "../src/config.ts";
import { createDelegation } from "../src/delegation.ts";
import { createDoorHost, RECEIPT_HEADER as DOOR_RECEIPT_HEADER, serveDoor } from "../src/door.ts";
import { grantHeader } from "../src/gateway-http.ts";

const CANARY = `CANARY_${randomBytes(8).toString("hex")}`;
const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;
/** the text with every base64 `payload` field decoded in place, applied until nothing is left encoded: the statement, the authorization and the upstream's envelope inside it, the grant */
const decodeAll = (text: string): string => {
  let out = text;
  for (let i = 0; i < 4; i++) {
    const next = out.replace(/"payload":\s*"([A-Za-z0-9+/=]+)"/g, (_m, b64: string) => `"payload":${JSON.stringify(Buffer.from(b64, "base64").toString())}`);
    if (next === out) break;
    out = next;
  }
  return out;
};
/** everything a receipt file says, decoded, nested payloads included */
const bundleText = (b: ReceiptBundle): string => decodeAll(JSON.stringify(b));
/** every file under the receipts directory (the issuer's salts included) and every log line, decoded */
const onDisk = (receiptsDir: string, logFile: string): string => decodeAll([...readdirSync(receiptsDir, { recursive: true, withFileTypes: true }).filter((e) => e.isFile()).map((e) => readFileSync(join(e.parentPath, e.name), "utf8")), readFileSync(logFile, "utf8")].join("\n"));
/** an exporter that keeps what the issuer hands it, and what the two real exporters would send of it */
const keepExports = () => {
  const seen: string[] = [];
  const spans: unknown[] = [];
  return {
    seen,
    spans,
    exporter: {
      where: "test",
      async exported(p: ReceiptPredicate, b: ReceiptBundle) {
        const span = spanFor(p, b, "agent-custody");
        spans.push(span);
        seen.push(JSON.stringify(p), JSON.stringify(span), JSON.stringify(hecEvent(p, b, { url: "https://splunk.example", tokenEnv: "X" })));
      },
    },
  };
};
/** the OTLP status of a span as exported: `message` is a string there, whatever the receipt holds */
const statusOf = (span: unknown) => (span as { resourceSpans: { scopeSpans: { spans: { status: { code: number; message?: unknown } }[] }[] }[] }).resourceSpans[0]!.scopeSpans[0]!.spans[0]!.status;
const withheldLog = (inner: LogSink): LogSink => ({
  kind: inner.kind,
  where: inner.where,
  async append(leaf) {
    const st = JSON.parse(Buffer.from((JSON.parse(leaf) as { payload: string }).payload, "base64").toString()) as { predicateType: string };
    if (st.predicateType.includes("/authorization/")) throw new Error("log is read-only for this tenant");
    return inner.append(leaf);
  },
});

/** every path through the gateway, each with the canary in a withheld argument */
async function everyGatewayPath(gw: Gateway, gwWithheld: Gateway): Promise<{ name: string; result: { _meta?: Record<string, unknown>; isError?: boolean } }[]> {
  const call = (name: string, args: Record<string, unknown>, through = gw, tool = "stripe.refund") => through.handleCall({ name: tool, arguments: args }).then((result) => ({ name, result }));
  return [
    // executed, with a provider delivery, pre-committed: the authorization is in play
    await call("executed", { customer_id: CANARY, account_ref: CANARY, amount: 2500 }),
    // the upstream answers isError
    await call("failed", { customer_id: CANARY, account_ref: CANARY, amount: 2500, reason: "error" }),
    // the upstream throws
    await call("thrown", { customer_id: CANARY, account_ref: CANARY, amount: 2500, reason: "throw" }),
    // the policy denies: over the limit, after the lookup ran
    await call("denied", { customer_id: CANARY, account_ref: CANARY, amount: 5_000_000 }),
    // the lookup answers isError, and the lookup throws: the answer lands in the policy errors and the denial reason
    await call("lookup isError", { customer_id: CANARY, account_ref: `cust_error_${CANARY}`, amount: 2500 }),
    await call("lookup throws", { customer_id: CANARY, account_ref: `cust_throw_${CANARY}`, amount: 2500 }),
    // out of the grant's scopes
    await call("out of scope", { customer_id: CANARY, amount: 2500 }, gw, "stripe.payout"),
    // the log refuses the authorization: withheld, nothing forwarded
    await call("withheld", { customer_id: CANARY, account_ref: CANARY, amount: 2500 }, gwWithheld),
  ];
}
const TOOLS: Record<string, string> = { "out of scope": "stripe.payout" };

describe("the canary", () => {
  it("human approvals keep private arguments and untrusted envelope data out of statements, precommit files, logs, and exporters", async () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "canary-approvals-")));
    const first = generateKeyPair();
    const second = generateKeyPair();
    const firstFiles = writeKeyPair(first, join(fx.dir, "keys"), "approver");
    const secondFiles = writeKeyPair(second, join(fx.dir, "keys"), "second-approver");
    const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
    cfg.upstream.args[2] = resolve(import.meta.dirname, "..", "scripts", "fake-canary.ts");
    // This upstream copies reason into its returned signature metadata, proving the full private argument reached it.
    cfg.upstream.args.push("--envelope", "note");
    cfg.precommit = ["stripe.refund"];
    cfg.capture = { "*": { args: { mode: "digest" }, result: { mode: "digest" }, facts: { mode: "digest" } } };
    cfg.approvals = {
      trustedKeys: [firstFiles.pubFile, secondFiles.pubFile],
      usedDir: "approvals-used",
      tools: [{ tool: "stripe.refund", minApprovers: 2 }],
    };
    writeFileSync(fx.configFile, JSON.stringify(cfg));
    const exports = keepExports();
    const gw = await createGateway(loadConfig(fx.configFile), { exporter: exports.exporter });
    // The approval signs the action fields and an unsalted digest of the arguments. A secret in the beneficiary must
    // stay out of every statement, so the receipt withholds the whole envelope under a private rule.
    const args = { customer_id: "cust_123", amount: 2500, currency: "GBP", beneficiary: `IBAN-${CANARY}`, reason: CANARY };
    const approve = () => dsseCountersign(createApproval(first, {
      principal: "user_456", agent: "support-agent", tool: "stripe.refund", args,
      expiresAt: new Date(Date.now() + 300_000).toISOString(),
    }), second);
    const original = approve();
    const invalidPayload = JSON.parse(Buffer.from(original.payload, "base64").toString());
    invalidPayload[CANARY] = CANARY;
    const malformed = dsseCountersign(dsseSign(APPROVAL_TYPE, invalidPayload, first), second);
    const injectedSignature = Buffer.from(CANARY.padEnd(64, "x")).toString("base64");
    const untrusted = approve();
    const forgedDuplicate = approve();
    const cases: { name: string; envelope: Envelope; retained?: Envelope }[] = [
      { name: "trusted approval", envelope: original, retained: original },
      { name: "signed invalid schema", envelope: malformed },
      { name: "untrusted signature keyid", envelope: { ...untrusted, signatures: [...untrusted.signatures, { keyid: CANARY, sig: injectedSignature }] }, retained: untrusted },
      { name: "forged duplicate trusted keyid", envelope: { ...forgedDuplicate, signatures: [...forgedDuplicate.signatures, { keyid: first.keyid, sig: injectedSignature }] }, retained: forgedDuplicate },
    ];
    // Controls: these inputs really carry the secret, including inside an encoded signature outside the signed payload.
    expect(decodeAll(JSON.stringify(malformed))).toContain(CANARY);
    expect(Buffer.from(injectedSignature, "base64").toString()).toContain(CANARY);
    const keys = {
      issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)],
      approvalKeys: [loadPublicKey(firstFiles.pubFile), loadPublicKey(secondFiles.pubFile)], logFile: fx.logFile,
    };
    // The signed payload carries this digest, and it is not salted: it would confirm a guess of the arguments.
    const unsaltedDigest = digestOf(args);
    const needles = [CANARY, injectedSignature, unsaltedDigest];
    expect(decodeAll(JSON.stringify(original))).toContain(unsaltedDigest);
    try {
      for (const { name, envelope, retained } of cases) {
        const result = await gw.handleCall({ name: "stripe.refund", arguments: args, _meta: { [APPROVAL_META_KEY]: envelope } });
        const id = String(result._meta![RECEIPT_META_KEY]);
        const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${id}.json`), "utf8")) as ReceiptBundle;
        const p = decode(bundle).predicate;
        const v = verifyBundle(bundle, keys);
        for (const needle of needles) expect(bundleText(bundle), `${name}: a decoded receipt carries private approval data`).not.toContain(needle);
        if (retained) {
          expect(p.execution.status, name).toBe("executed");
          expect(result.isError, name).toBeFalsy();
          expect((result._meta!["agent-custody/upstream-signature"] as { customer_note: string }).customer_note, name).toBe(args.reason);
          // The status, the times, and the signer ids stay in clear. The envelope is one commitment, shared with the precommit.
          expect(p.approval).toMatchObject({ status: "approved", requiredApprovers: 2, approverKeyids: [first.keyid, second.keyid], provenance: "observed" });
          expect(isCommitment(p.approval!.envelope), name).toBe(true);
          const authorization = decode(p.authorization as ReceiptBundle).predicate;
          expect(authorization.approval!.envelope, name).toEqual(p.approval!.envelope);
          expect(readdirSync(fx.receiptsDir)).toContain(`${id}.authorization.json`);
          // Without a disclosure the verifier passes the approval checks as committed.
          expect(v.ok, `${name}: ${formatReport(v)}`).toBe(true);
          expect(v.checks.find((check) => check.name === "approval signatures (human keys)")?.detail, name).toMatch(/committed, not recomputed/);
          const { salts } = JSON.parse(readFileSync(join(fx.receiptsDir, "salts", `${id}.json`), "utf8")) as { salts: Record<string, string> };
          const disclosed = {
            receiptId: id,
            request: { args: { $rest: { $custody: "disclosed", salt: salts[pathKey(["request", "args", "$rest"])], value: args } } },
            approval: { envelope: { $custody: "disclosed", salt: salts[pathKey(["approval", "envelope"])], value: retained } },
          };
          const revealed = verifyBundle(bundle, { ...keys, disclosed });
          expect(revealed.ok, `${name}: ${formatReport(revealed)}`).toBe(true);
          expect(revealed.checks.find((check) => check.name === "approval payload binding")?.detail, name).toMatch(/principal, agent, tool, full arguments/);
        } else {
          expect(p.execution.status).toBe("denied");
          expect(p.approval).not.toHaveProperty("envelope");
          // A refusal reason can quote the statement, so it is withheld too.
          expect(isCommitment(p.approval!.reason), name).toBe(true);
          expect(v.ok, formatReport(v)).toBe(true);
        }
      }
      const disk = onDisk(fx.receiptsDir, fx.logFile);
      const exported = decodeAll(exports.seen.join("\n"));
      for (const needle of needles) {
        expect(disk, "a receipt, authorization, salts file, or log carries private approval data").not.toContain(needle);
        expect(exported, "an exporter carries private approval data").not.toContain(needle);
      }
      expect(exports.seen).toHaveLength(cases.length * 3);
    } finally {
      await gw.close();
    }
  });

  it("financial retries and reconciliation keep withheld payment details out of receipts, authorizations, log, and exporters", async () => {
    const fx = await financialFixture(mkdtempSync(join(tmpdir(), "canary-financial-")));
    fx.config.capture = { "*": { args: { mode: "digest" }, result: { mode: "digest" } } };
    writeFileSync(fx.configFile, JSON.stringify(fx.config));
    const exports = keepExports();
    const host = await createGatewayHost(loadConfig(fx.configFile), { exporter: exports.exporter });
    try {
      const session = host.open(JSON.parse(readFileSync(join(fx.dir, "grant.json"), "utf8")));
      const id = randomUUID();
      const params = { name: "stripe.refund", arguments: { amount: 60, currency: "GBP", note: CANARY }, _meta: { [OPERATION_META_KEY]: id } };
      const first = await session.handleCall(params);
      expect(JSON.stringify(first)).toContain(CANARY);
      // the retry gets the stored answer and a receipt of its own
      const retry = await session.handleCall(params);
      const { [RETRY_RECEIPT_META_KEY]: retryReceipt, ...retryMeta } = retry._meta!;
      expect({ ...retry, _meta: retryMeta }).toEqual(first);
      expect(retryReceipt).toEqual(expect.any(String));
      fx.records.values().next().value!.status = "succeeded";
      const closed = await host.reconcile(id);
      expect(bundleText(closed)).not.toContain(CANARY);
      expect(onDisk(fx.receiptsDir, fx.logFile)).not.toContain(CANARY);
      expect(exports.seen.join("\n")).not.toContain(CANARY);
      // the id is the agent's: a UUID-shaped canary must not reach a statement, a file, the log, or an exporter
      expect(bundleText(closed)).not.toContain(id);
      expect(onDisk(fx.receiptsDir, fx.logFile)).not.toContain(id);
      expect(exports.seen.join("\n")).not.toContain(id);
      // the call, its retry, and the reconciliation
      expect(exports.spans).toHaveLength(3);
      const v = verifyBundle(closed, { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile });
      expect(v.ok, formatReport(v)).toBe(true);
      expect(decode(closed).predicate.operation?.budget).not.toHaveProperty("amount");
    } finally { await host.close(); await fx.close(); }
  });

  it("under one private rule, a secret in the arguments reaches nothing in clear on any path through the gateway: statement, authorization, files, log, exporters", async () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "canary-gateway-")));
    const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
    cfg.upstream.args[2] = resolve(import.meta.dirname, "..", "scripts", "fake-canary.ts");
    cfg.upstream.args.push("--webhook-secret", "whsec_canary");
    // two facts with the same name, one copying a renamed argument: the lookup argument is withheld by its source
    cfg.facts = [
      { name: "customer", tool: "customer.lookup", args: { customer_id: "$args.customer_id" }, forTools: ["stripe.payout"] },
      { name: "customer", tool: "customer.lookup", args: { customer_id: "$args.account_ref" }, forTools: ["stripe.refund"] },
    ];
    cfg.precommit = ["stripe.refund"];
    cfg.capture = { "*": { args: { mode: "digest", clear: ["amount"] } } };
    writeFileSync(fx.configFile, JSON.stringify(cfg));
    const exports = keepExports();
    const gw = await createGateway(loadConfig(fx.configFile), { exporter: exports.exporter });
    // the second gateway's log refuses authorizations; it keeps its own log file and receipts, as two writers of one log would not
    const withheldDir = join(fx.dir, "receipts-withheld");
    const withheldLogFile = join(fx.dir, "log-withheld.jsonl");
    writeFileSync(join(fx.dir, "gateway-withheld.json"), JSON.stringify({ ...cfg, receiptsDir: "receipts-withheld", logFile: "log-withheld.jsonl" }));
    const gwWithheld = await createGateway(loadConfig(join(fx.dir, "gateway-withheld.json")), { exporter: exports.exporter, log: withheldLog(fileLog(withheldLogFile, loadPrivateKey(join(fx.dir, "keys", "gateway.key")))) });
    try {
      const calls = await everyGatewayPath(gw, gwWithheld);
      const statuses: Record<string, string> = {};
      for (const { name, result } of calls) {
        const id = String(result._meta![RECEIPT_META_KEY]);
        const own = name === "withheld" ? { receiptsDir: withheldDir, logFile: withheldLogFile } : { receiptsDir: fx.receiptsDir, logFile: fx.logFile };
        const bundle = JSON.parse(readFileSync(join(own.receiptsDir, `${id}.json`), "utf8")) as ReceiptBundle;
        const p = decode(bundle).predicate;
        statuses[name] = p.execution.status;
        expect(bundleText(bundle), `${name}: the receipt carries the canary`).not.toContain(CANARY);
        const v = verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)], upstreamKeys: [loadPublicKey(fx.upstreamPub)], providerSecrets: { stripe: "whsec_canary" }, logFile: own.logFile });
        expect(v.ok, `${name}: ${formatReport(v)}`).toBe(true);
        // the report a reviewer reads carries no more than the receipt: a refusal's reason is shown as withheld
        expect(formatReport(v), `${name}: the report carries the canary`).not.toContain(CANARY);
        if (p.execution.status === "denied" || p.execution.status === "withheld") expect(formatReport(v)).toMatch(/: \(reason withheld under the capture rule\)/);
        expect(p.tool.name).toBe(TOOLS[name] ?? "stripe.refund");
      }
      expect(statuses).toEqual({ executed: "executed", failed: "failed", thrown: "error", denied: "denied", "lookup isError": "denied", "lookup throws": "denied", "out of scope": "denied", withheld: "withheld" });
      expect(onDisk(fx.receiptsDir, fx.logFile), "a file on disk carries the canary").not.toContain(CANARY);
      expect(onDisk(withheldDir, withheldLogFile), "a file on disk carries the canary").not.toContain(CANARY);
      expect(exports.seen.join("\n"), "an export carries the canary").not.toContain(CANARY);
      expect(exports.seen.length).toBe(calls.length * 3);
      // the OTLP status message is a string, a fixed one where the error is a commitment
      for (const span of exports.spans) expect(["string", "undefined"]).toContain(typeof statusOf(span).message);
      expect(exports.spans.map((s) => statusOf(s).message)).toContain("the upstream reported an error (withheld under the capture rule)");
      // the upstream's signed payload carried the id as an extra claim: the envelope is withheld with the result
      const failed = calls.find((c) => c.name === "failed")!;
      const failedBundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${String(failed.result._meta![RECEIPT_META_KEY])}.json`), "utf8")) as ReceiptBundle;
      expect((decode(failedBundle).predicate.capture?.withheld ?? []).map((w) => w.join("."))).toContain("execution.upstream.envelope");
      // the agent got everything: the real answers, the real errors (a policy denial names the policy, not the arguments)
      expect(calls.filter((c) => (c.result as { content: { text: string }[] }).content[0]!.text.includes(CANARY)).map((c) => c.name)).toEqual(["executed", "failed", "thrown", "lookup isError", "lookup throws"]);
    } finally {
      await gw.close();
      await gwWithheld.close();
    }
  });

  it("beside a result the rule leaves in clear, an upstream envelope that copies a withheld argument into any field of its own is withheld, in either mode; the plain one stays and verifies", async () => {
    const captureKey = randomBytes(32);
    const before = process.env.TEST_CAPTURE_KEY;
    process.env.TEST_CAPTURE_KEY = captureKey.toString("hex");
    try {
    for (const mode of ["digest", "encrypted"] as const) {
      for (const envelope of ["note", "plain"] as const) {
        const fx = buildFixture(mkdtempSync(join(tmpdir(), `canary-envelope-${mode}-${envelope}-`)));
        const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
        cfg.upstream.args[2] = resolve(import.meta.dirname, "..", "scripts", "fake-canary.ts");
        cfg.upstream.args.push("--envelope", envelope);
        cfg.capture = { "*": { args: { mode }, result: { mode: "clear" } } };
        cfg.captureKeyEnv = "TEST_CAPTURE_KEY";
        writeFileSync(fx.configFile, JSON.stringify(cfg));
        const gw = await createGateway(loadConfig(fx.configFile));
        try {
          // the result names the customer and the amount, never the reason: only the envelope could carry it
          const r = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500, reason: CANARY } });
          expect(r.isError, `${mode}/${envelope}`).toBeFalsy();
          const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${String(r._meta![RECEIPT_META_KEY])}.json`), "utf8")) as ReceiptBundle;
          const p = decode(bundle).predicate;
          const withheld = (p.capture?.withheld ?? []).map((w) => w.join("."));
          expect(bundleText(bundle), `${mode}/${envelope}: the receipt carries the canary`).not.toContain(CANARY);
          expect(onDisk(fx.receiptsDir, fx.logFile), `${mode}/${envelope}: a file on disk carries the canary`).not.toContain(CANARY);
          const keys = { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile };
          const upstream = { ...keys, upstreamKeys: [loadPublicKey(fx.upstreamPub)] };
          const check = (v: ReturnType<typeof verifyBundle>) => v.checks.find((c) => c.name.startsWith("upstream signature"));
          if (envelope === "plain") {
            expect(withheld).not.toContain("execution.upstream.envelope");
            const v = verifyBundle(bundle, upstream);
            expect(v.ok, formatReport(v)).toBe(true);
            // run, not skipped: "upstream signature not checked" would pass too
            expect(check(v)?.name).toBe("upstream signature (upstream key)");
            expect(check(v)?.ok).toBe(true);
          } else {
            expect(withheld).toContain("execution.upstream.envelope");
            expect(verifyBundle(bundle, keys).ok).toBe(true);
            // a verifier holding the upstream's key is told the envelope is withheld, not waved past
            const v = verifyBundle(bundle, upstream);
            expect(v.ok, formatReport(v)).toBe(false);
            expect(check(v)?.detail).toMatch(/withheld/);
            // with the capture key the envelope comes back, and the upstream's signature over the clear result verifies
            if (mode === "encrypted") {
              const vk = verifyBundle(bundle, { ...upstream, captureKey });
              expect(vk.ok, formatReport(vk)).toBe(true);
              expect(check(vk)?.name).toBe("upstream signature (upstream key)");
              expect(check(vk)?.ok).toBe(true);
            }
          }
        } finally {
          await gw.close();
        }
      }
    }
    } finally {
      if (before === undefined) delete process.env.TEST_CAPTURE_KEY;
      else process.env.TEST_CAPTURE_KEY = before;
    }
  });

  it("under one private rule, a receipt that waits in the outbox while the log is down carries no secret in the outbox, the log, the exports, or the flushed bundles", async () => {
    // one host per rule: the control has no rule, so the scan of the outbox can fail
    const run = async (rule: object | undefined) => {
      const fx = buildFixture(mkdtempSync(join(tmpdir(), "canary-outbox-")));
      const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
      cfg.upstream.args[2] = resolve(import.meta.dirname, "..", "scripts", "fake-canary.ts");
      cfg.upstream.args.push("--webhook-secret", "whsec_canary");
      cfg.facts = [{ name: "customer", tool: "customer.lookup", args: { customer_id: "$args.account_ref" }, forTools: ["stripe.refund"] }];
      if (rule) cfg.capture = rule;
      writeFileSync(fx.configFile, JSON.stringify(cfg));
      const inner = fileLog(fx.logFile, loadPrivateKey(join(fx.dir, "keys", "gateway.key")));
      let down = true;
      const log: LogSink = { kind: inner.kind, where: inner.where, append: (leaf) => down ? Promise.reject(new Error("log unreachable")) : inner.append(leaf) };
      const exports = keepExports();
      const host = await createGatewayHost(loadConfig(fx.configFile), { exporter: exports.exporter, log });
      const gw = host.open(JSON.parse(readFileSync(loadConfig(fx.configFile).grantFile!, "utf8")) as Envelope);
      try {
        const calls = await everyGatewayPath(gw, gw);
        const outbox = join(fx.receiptsDir, "outbox");
        const waiting = readdirSync(outbox).map((f) => readFileSync(join(outbox, f), "utf8")).join("\n");
        const whileDown = decodeAll(waiting);
        expect(calls.every((c) => c.result._meta![LOG_PENDING_META_KEY] === true), "every receipt waits in the outbox").toBe(true);
        expect(host.pendingReceipts()).toBe(calls.length);
        expect(exports.seen).toEqual([]);
        down = false;
        expect(await host.flushOutbox()).toEqual({ sent: calls.length, pending: 0, setAside: 0, foreign: 0 });
        const bundles = calls.map((c) => JSON.parse(readFileSync(join(fx.receiptsDir, `${String(c.result._meta![RECEIPT_META_KEY])}.json`), "utf8")) as ReceiptBundle);
        return { calls, whileDown, bundles, disk: onDisk(fx.receiptsDir, fx.logFile), exported: exports.seen.join("\n"), exportCount: exports.seen.length, keys: { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)], upstreamKeys: [loadPublicKey(fx.upstreamPub)], providerSecrets: { stripe: "whsec_canary" }, logFile: fx.logFile } };
      } finally {
        await host.close();
      }
    };
    const kept = await run({ "*": { args: { mode: "digest", clear: ["amount"] } } });
    expect(kept.whileDown, "the outbox carries the canary").not.toContain(CANARY);
    for (const b of kept.bundles) {
      expect(bundleText(b), "a flushed receipt carries the canary").not.toContain(CANARY);
      const v = verifyBundle(b, kept.keys);
      expect(v.ok, formatReport(v)).toBe(true);
      expect(formatReport(v), "the report carries the canary").not.toContain(CANARY);
    }
    expect(kept.disk, "a file on disk carries the canary").not.toContain(CANARY);
    expect(kept.exported, "an export carries the canary").not.toContain(CANARY);
    expect(kept.exportCount).toBe(kept.calls.length * 3);
    // the agent still gets the real answers; the pending flag is the only key the outbox adds to what a call returns
    for (const { name, result } of kept.calls) expect(Object.keys(result._meta!).filter((k) => k.startsWith("agent-custody/") && k !== LOG_PENDING_META_KEY).every((k) => ["agent-custody/receipt", "agent-custody/facts", "agent-custody/upstream-signature"].includes(k)), name).toBe(true);
    // the control: with no rule the same outbox carries the canary
    expect((await run(undefined)).whileDown).toContain(CANARY);
  });

  it("the control: the same calls with no rule carry the canary in the statement, the files, the log, and the exports", async () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "canary-control-")));
    const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
    cfg.upstream.args[2] = resolve(import.meta.dirname, "..", "scripts", "fake-canary.ts");
    cfg.upstream.args.push("--webhook-secret", "whsec_canary");
    cfg.facts = [{ name: "customer", tool: "customer.lookup", args: { customer_id: "$args.account_ref" }, forTools: ["stripe.refund"] }];
    cfg.precommit = ["stripe.refund"];
    writeFileSync(fx.configFile, JSON.stringify(cfg));
    const exports = keepExports();
    const gw = await createGateway(loadConfig(fx.configFile), { exporter: exports.exporter });
    try {
      const calls = await everyGatewayPath(gw, gw);
      const carrying = calls.filter(({ result }) => {
        const id = String(result._meta![RECEIPT_META_KEY]);
        return bundleText(JSON.parse(readFileSync(join(fx.receiptsDir, `${id}.json`), "utf8")) as ReceiptBundle).includes(CANARY);
      });
      expect(carrying.map((c) => c.name)).toEqual(calls.map((c) => c.name));
      expect(onDisk(fx.receiptsDir, fx.logFile)).toContain(CANARY);
      expect(exports.seen.join("\n")).toContain(CANARY);
    } finally {
      await gw.close();
    }
  });

  it("under one private rule, a secret reaches nothing in clear through the SDK: record on every outcome, and wrap with a tool that throws, which is the path every adapter takes", async () => {
    const fx = buildSdkFixture(mkdtempSync(join(tmpdir(), "canary-sdk-")));
    const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
    cfg.capture = { "*": { args: { mode: "digest", clear: ["amount"] } } };
    writeFileSync(fx.configFile, JSON.stringify(cfg));
    const sdk = createSdkIssuer(loadSdkConfig(fx.configFile));
    const ev = { tool: "stripe.refund", args: { customer_id: CANARY, amount: 900 } };
    const bundles = [
      await sdk.record(ev, { status: "executed", result: { content: [{ type: "text", text: `refunded ${CANARY}` }], structuredContent: { id: CANARY }, _meta: { trace: CANARY } } }),
      await sdk.record(ev, { status: "failed", result: { content: [{ type: "text", text: `refused ${CANARY}` }], isError: true } }),
      await sdk.record(ev, { status: "error", error: `declined for ${CANARY}` }),
      await sdk.record(ev, { status: "denied", reason: `no permit for ${CANARY}` }, { decision: "deny", reasons: [], errors: [`lookup failed for ${CANARY}`], policyDigest: "d" }),
      await sdk.record({ tool: "stripe.refund", args: { customer_id: CANARY, amount: 900 } }, { status: "executed", result: `plain string with ${CANARY}` }),
    ];
    const wrapped = sdk.wrap("stripe.refund", async (a: { customer_id: string; amount: number }) => {
      throw new Error(`card declined for ${a.customer_id}`);
    });
    await expect(wrapped({ customer_id: CANARY, amount: 900 })).rejects.toThrow(CANARY);
    for (const b of bundles) {
      expect(bundleText(b)).not.toContain(CANARY);
      const v = verifyBundle(b, { issuerKeys: [loadPublicKey(fx.appPub)], principalKeys: [], logFile: fx.logFile });
      expect(v.ok, formatReport(v)).toBe(true);
      const span = spanFor(decode(b).predicate, b, "agent-custody");
      expect(JSON.stringify(span)).not.toContain(CANARY);
      expect(["string", "undefined"]).toContain(typeof statusOf(span).message);
    }
    expect(onDisk(fx.receiptsDir, fx.logFile)).not.toContain(CANARY);
    // and the control
    const clear = createSdkIssuer(loadSdkConfig(buildSdkFixture(mkdtempSync(join(tmpdir(), "canary-sdk-control-"))).configFile));
    expect(bundleText(await clear.record(ev, { status: "error", error: `declined for ${CANARY}` }))).toContain(CANARY);
  });

  // The door is a path a call can take: its arguments are the query and the body an arrival sent. A config with no rule
  // keeps both out of every place a receipt reaches; the control, with a rule that keeps arguments in clear, finds them.
  for (const control of [false, true]) {
    it(control ? "the door control: with arguments kept in clear, the canary is in the statement, the files, the log, and the exports" : "at the door with no capture rule, a secret in the query or the body reaches nothing in clear: relayed, refused, pre-committed, withheld by the log, the origin down", async () => {
      const origin = await startOrigin();
      const dir = mkdtempSync(join(tmpdir(), control ? "canary-door-control-" : "canary-door-"));
      const fx = buildDoorFixture(dir, origin.url, { capture: control ? { "*": { args: { mode: "clear" } } } : undefined });
      const exports = keepExports();
      const host = await createDoorHost(loadDoorConfig(fx.configFile), { exporter: exports.exporter });
      const door = await serveDoor(host, { port: 0, log: () => {} });
      const refusing: LogSink = { kind: "file", where: "refusing", append: async () => { throw new Error("the log is full"); } };
      const outboxHost = await createDoorHost(loadDoorConfig(fx.configFile), { exporter: exports.exporter, log: refusing });
      const outboxDoor = await serveDoor(outboxHost, { port: 0, log: () => {} });
      const deadFx = buildDoorFixture(join(dir, "dead"), "http://127.0.0.1:9", { origin: { url: "http://127.0.0.1:9" }, capture: control ? { "*": { args: { mode: "clear" } } } : undefined });
      const deadHost = await createDoorHost(loadDoorConfig(deadFx.configFile), { exporter: exports.exporter });
      const deadDoor = await serveDoor(deadHost, { port: 0, log: () => {} });
      const grant = createDelegation(fx.principalKey, { version: "0.1", principal: "shop-owner", agent: "shopping-agent", scopes: ["refund"], issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString() });
      const json = { "content-type": "application/json" };
      try {
        const answers = [
          await fetch(`${door.url}/catalogue/shoes?api_key=${CANARY}`),
          await fetch(`${door.url}/refunds`, { method: "POST", headers: json, body: JSON.stringify({ order: CANARY, amount: 100 }) }),
          await fetch(`${door.url}/refunds?note=${CANARY}`, { method: "POST", headers: { ...json, authorization: `Bearer ${grantHeader(grant)}` }, body: JSON.stringify({ order: CANARY, amount: 100 }) }),
          await fetch(`${outboxDoor.url}/refunds`, { method: "POST", headers: { ...json, authorization: `Bearer ${grantHeader(grant)}` }, body: JSON.stringify({ order: CANARY, amount: 100 }) }),
          await fetch(`${deadDoor.url}/catalogue/x?q=${CANARY}`),
        ];
        expect(answers.map((a) => a.status)).toEqual([200, 403, 200, 503, 502]);
        for (const a of answers) expect(a.headers.get(DOOR_RECEIPT_HEADER)).toBeTruthy();
        const text = [onDisk(fx.receiptsDir, fx.logFile), onDisk(deadFx.receiptsDir, deadFx.logFile), exports.seen.join("\n")].join("\n");
        if (control) expect(text).toContain(CANARY);
        else expect(text).not.toContain(CANARY);
      } finally {
        for (const d of [door, outboxDoor, deadDoor]) await d.close();
        for (const h of [host, outboxHost, deadHost]) await h.close();
        await origin.close();
      }
    });
  }
});
