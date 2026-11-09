// Generates the conformance vectors in vectors/. Run with `bun run vectors`; commit the result.
// The vectors are a snapshot: keys, receipts, logs, and expected verdicts produced by this implementation, so that a
// verifier written elsewhere can prove it agrees. Regenerate only when the format changes, never to make a test pass.
import { withhold } from "../src/capture.ts";
import { APPROVAL_META_KEY, APPROVAL_TYPE, createApproval } from "../src/approval.ts";
import { createDelegation, delegateFrom, DELEGATION_TYPE } from "../src/delegation.ts";
import nodeFs, { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalize, digestOf, dsseCountersign, dsseSign, generateKeyPair, loadPrivateKey, loadPublicKey, sha256Hex, type Envelope, type KeyPair, publicKeyToPem, writeKeyPair as writeApprovalKeyPair } from "../src/crypto.ts";
import { createGateway, RECEIPT_META_KEY, createGatewayHost } from "../src/gateway.ts";
import { loadConfig, loadSdkConfig } from "../src/config.ts";
import { consistencyProof, inclusionProof, leafHash, rootOf } from "../src/log.ts";
import { fileLog, serveLog, type LogSink } from "../src/log-sink.ts";
import { RECEIPT_TYPE, type ReceiptBundle, type ReceiptStatement } from "../src/receipt.ts";
import { createSdkIssuer } from "../src/sdk/index.ts";
import { verifyBundle, type VerifyOptions } from "../src/verify.ts";
import { buildFixture, buildSdkFixture } from "./fixture.ts";
import { financialFixture } from "./financial-fixture.ts";
import { OPERATION_META_KEY } from "../src/operations.ts";
import { randomUUID } from "node:crypto";
import { createDoorHost, RECEIPT_HEADER, serveDoor } from "../src/door.ts";
import { grantHeader } from "../src/gateway-http.ts";
import { loadDoorConfig } from "../src/config.ts";
import { buildDoorFixture, startOrigin } from "./door-fixture.ts";
import { createEgressHost, serveEgress } from "../src/egress.ts";
import { loadEgressConfig } from "../src/config.ts";
import { EGRESS_AGENT, EGRESS_SECRET, buildEgressFixture, connectThrough, proxyAuth, startEcho } from "./egress-fixture.ts";
import { ACS_RECEIPT_KEY, createAcsGuardian, type AcsResponse } from "../src/acs.ts";

const out = join(import.meta.dirname, "..", "vectors");
const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;
const bundleFile = (dir: string, id: string) => JSON.parse(readFileSync(join(dir, `${id}.json`), "utf8")) as ReceiptBundle;
const logLines = (file: string) => readFileSync(file, "utf8").trim().split("\n").map((l) => JSON.parse(l) as string);

interface Case {
  name: string;
  description: string;
  bundle: ReceiptBundle;
  issuerKeys: string[];
  principalKeys: string[];
  logKeys: string[];
  upstreamKeys?: string[];
  approvalKeys?: string[];
  /** shared secrets for provider-native deliveries; test values, published on purpose */
  providerSecrets?: { stripe?: string; github?: string };
  /** the log id the verifier is told to expect on the tree head */
  logId?: string;
  /** the verifier is told to require a strict gateway receipt */
  requireStrict?: boolean;
  log: string[] | null;
  expected: { ok: boolean; failing: string[] };
}

const keys: Record<string, { publicKeyPem: string; keyid: string }> = {};
const pems: Record<string, string> = {};
function key(name: string, pubFile: string) {
  const pem = readFileSync(pubFile, "utf8");
  pems[name] = pem;
  keys[name] = { publicKeyPem: pem, keyid: loadPublicKey(pubFile).keyid };
}

/** Re-sign a statement whose predicate was edited, with the issuer's key, keeping the original tree head and proof. */
function resigned(bundle: ReceiptBundle, issuer: KeyPair, edit: (st: ReceiptStatement) => void): ReceiptBundle {
  const st = decode(bundle);
  edit(st);
  return { ...bundle, envelope: dsseSign(RECEIPT_TYPE, st, issuer) };
}

const cases: Case[] = [];
function addCase(c: Omit<Case, "expected">, opts?: Partial<VerifyOptions>) {
  const tmp = mkdtempSync(join(tmpdir(), "vectors-"));
  const logFile = c.log ? join(tmp, "log.jsonl") : undefined;
  if (c.log && logFile) writeFileSync(logFile, c.log.map((l) => JSON.stringify(l)).join("\n") + "\n");
  const r = verifyBundle(c.bundle, {
    issuerKeys: c.issuerKeys.map((k) => keyFrom(k)),
    principalKeys: c.principalKeys.map((k) => keyFrom(k)),
    logKeys: c.logKeys.map((k) => keyFrom(k)),
    ...(c.upstreamKeys ? { upstreamKeys: c.upstreamKeys.map((k) => keyFrom(k)) } : {}),
    ...(c.approvalKeys ? { approvalKeys: c.approvalKeys.map((k) => keyFrom(k)) } : {}),
    ...(c.providerSecrets ? { providerSecrets: c.providerSecrets } : {}),
    ...(c.logId ? { logId: c.logId } : {}),
    ...(c.requireStrict ? { requireStrict: true } : {}),
    ...(logFile ? { logFile } : {}),
    ...opts,
  });
  cases.push({ ...c, expected: { ok: r.ok, failing: r.checks.filter((x) => !x.ok).map((x) => x.name) } });
}
import { publicKeyFromPem } from "../src/crypto.ts";
const keyFrom = (name: string) => publicKeyFromPem(pems[name]!);

// ---- gateway receipts: executed, denied, and edited-then-resigned variants ----
const gfx = buildFixture(mkdtempSync(join(tmpdir(), "vectors-gateway-")));
key("gateway", gfx.gatewayPub);
key("principal", gfx.principalPub);
key("upstream", gfx.upstreamPub);
const gatewayKey = loadPrivateKey(join(gfx.dir, "keys", "gateway.key"));
const gw = await createGateway(loadConfig(gfx.configFile));
const ok = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 50000 }, _meta: { "agent-custody/model": "vector-model" } });
const denied = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 5000000 } });
await gw.close();
const executed = bundleFile(gfx.receiptsDir, String(ok._meta?.[RECEIPT_META_KEY]));
const deniedBundle = bundleFile(gfx.receiptsDir, String(denied._meta?.[RECEIPT_META_KEY]));
const glog = logLines(gfx.logFile);
const G = { issuerKeys: ["gateway"], principalKeys: ["principal"], logKeys: [] as string[] };

addCase({ name: "gateway-executed", description: "An in-policy refund through the gateway: delegation attested, facts observed, executed. Every check passes with the log.", bundle: executed, ...G, log: glog });

// ---- strict mode: every call precommitted to a remote hash-only log, and the receipt says so ----
const strictFx = buildFixture(mkdtempSync(join(tmpdir(), "vectors-strict-")));
key("strict-gateway", strictFx.gatewayPub);
key("strict-principal", strictFx.principalPub);
const strictRaw = JSON.parse(readFileSync(strictFx.configFile, "utf8"));
delete strictRaw.logFile;
writeFileSync(strictFx.configFile, JSON.stringify({ ...strictRaw, strict: true, log: { url: "https://log.invalid", hashOnly: true, keys: [strictFx.gatewayPub] } }));
const strictKey = loadPrivateKey(join(strictFx.dir, "keys", "gateway.key"));
// the log is reached as if over HTTP; behind it is a file, so the case carries its leaves
const strictFile = fileLog(strictFx.logFile, strictKey);
const strictSink: LogSink = { kind: "http", where: "https://log.invalid", append: (leaf) => strictFile.append(leaf) };
const strictCfg = loadConfig(strictFx.configFile);
const strictHost = await createGatewayHost(strictCfg, { log: strictSink });
const strictCall = await strictHost.open(JSON.parse(readFileSync(strictCfg.grantFile!, "utf8")) as Envelope).handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 50000 } });
await strictHost.close();
const strictBundle = bundleFile(strictFx.receiptsDir, String(strictCall._meta?.[RECEIPT_META_KEY]));
const S = { issuerKeys: ["strict-gateway"], principalKeys: ["strict-principal"], logKeys: [] as string[], requireStrict: true };
addCase({ name: "gateway-strict", description: "A refund through a strict gateway, verified with strict required. The issuer says `strict: true`, and the authorization was committed to the log before the call was forwarded.", bundle: strictBundle, ...S, log: logLines(strictFx.logFile) });
addCase({ name: "gateway-executed-strict-required", description: "The ordinary executed refund, verified with strict required. Its issuer does not say strict, and the call went out with no authorization committed first: both strict checks fail.", bundle: executed, ...G, requireStrict: true, log: glog });
addCase({ name: "resigned-strict-authorization-removed", description: "The strict receipt with its authorization removed, re-signed. The issuer still says strict, but the executed call carries no precommit, so `strict: call precommitted before forwarding` fails.", bundle: resigned(strictBundle, strictKey, (st) => { delete st.predicate.authorization; }), ...S, log: logLines(strictFx.logFile) });
addCase({ name: "resigned-strict-claimed-without-precommit", description: "The ordinary executed refund re-signed with `issuer.strict: true` added. Claiming strict does not make a call precommitted: `strict: call precommitted before forwarding` fails.", bundle: resigned(executed, gatewayKey, (st) => { st.predicate.issuer.strict = true; }), ...G, requireStrict: true, log: glog });

// ---- human approvals: exact payload, distinct signers, single use, and expiry ----
const afx = buildFixture(mkdtempSync(join(tmpdir(), "vectors-approvals-")));
const human = generateKeyPair(), secondHuman = generateKeyPair();
const humanFiles = writeApprovalKeyPair(human, join(afx.dir, "keys"), "human");
const secondFiles = writeApprovalKeyPair(secondHuman, join(afx.dir, "keys"), "second-human");
key("approval-gateway", afx.gatewayPub);
key("approval-principal", afx.principalPub);
key("human", humanFiles.pubFile);
key("second-human", secondFiles.pubFile);
const acfg = loadConfig(afx.configFile);
acfg.approvals = { trustedKeys: [humanFiles.pubFile, secondFiles.pubFile], usedDir: join(afx.dir, "used-approvals"), tools: [{ tool: "stripe.refund", minApprovers: 2 }] };
acfg.precommit = ["stripe.refund"];
const agw = await createGateway(acfg);
const aargs = { customer_id: "cust_123", amount: 2500, currency: "GBP", beneficiary: "acct_42" };
const abinding = { principal: "user_456", agent: "support-agent", tool: "stripe.refund", args: aargs };
const ae = dsseCountersign(createApproval(human, { ...abinding, expiresAt: new Date(Date.now() + 3600_000).toISOString() }), secondHuman);
const approved = await agw.handleCall({ name: "stripe.refund", arguments: aargs, _meta: { [APPROVAL_META_KEY]: ae } });
const reused = await agw.handleCall({ name: "stripe.refund", arguments: aargs, _meta: { [APPROVAL_META_KEY]: ae } });
const changed = await agw.handleCall({ name: "stripe.refund", arguments: { ...aargs, amount: 2501 }, _meta: { [APPROVAL_META_KEY]: ae } });
const expiredApproval = dsseCountersign(createApproval(human, { ...abinding, issuedAt: new Date(Date.now() - 120_000).toISOString(), expiresAt: new Date(Date.now() - 60_000).toISOString() }), secondHuman);
const aexpired = await agw.handleCall({ name: "stripe.refund", arguments: aargs, _meta: { [APPROVAL_META_KEY]: expiredApproval } });
await agw.close();
const approvedBundle = bundleFile(afx.receiptsDir, String(approved._meta?.[RECEIPT_META_KEY]));
const approvalIssuer = loadPrivateKey(join(afx.dir, "keys", "gateway.key"));
const alog = logLines(afx.logFile);
const A = { issuerKeys: ["approval-gateway"], principalKeys: ["approval-principal"], logKeys: [] as string[], approvalKeys: ["human", "second-human"] };
addCase({ name: "gateway-approved-two-humans", description: "Two distinct trusted humans signed the exact refund payload; the gateway precommitted the approval, atomically consumed it, and forwarded once.", bundle: approvedBundle, ...A, log: alog });
addCase({ name: "gateway-approval-used", description: "The same approval was presented again. The gateway withheld the call; the refusal is an authentic receipt.", bundle: bundleFile(afx.receiptsDir, String(reused._meta?.[RECEIPT_META_KEY])), ...A, log: alog });
addCase({ name: "gateway-approval-payload-changed", description: "One penny changed after approval. The gateway denied the action with the binding failure in the receipt.", bundle: bundleFile(afx.receiptsDir, String(changed._meta?.[RECEIPT_META_KEY])), ...A, log: alog });
addCase({ name: "gateway-approval-expired", description: "An expired approval was refused; the denied receipt still verifies.", bundle: bundleFile(afx.receiptsDir, String(aexpired._meta?.[RECEIPT_META_KEY])), ...A, log: alog });
addCase({ name: "gateway-approved-without-human-trust", description: "The approved receipt with no human keys trusted. Neither the gateway nor delegation keys substitute for human approval keys.", bundle: approvedBundle, ...A, approvalKeys: [], log: alog });
addCase({ name: "gateway-approved-only-one-human-trusted", description: "A two-person action with only one of the human keys trusted fails approval verification.", bundle: approvedBundle, ...A, approvalKeys: ["human"], log: alog });
for (const field of ["amount", "currency", "beneficiary", "extra"] as const) {
  addCase({ name: `resigned-approved-${field}-changed`, description: `The gateway re-signed a changed ${field} and recomputed the request digest. The humans' unchanged signatures still bind the original full payload, so the approval check fails.`, bundle: resigned(approvedBundle, approvalIssuer, (st) => {
    st.predicate.request.args[field] = field === "amount" ? 2501 : "changed";
    st.predicate.request.argsDigest = digestOf(st.predicate.request.args);
    st.subject[0]!.digest.sha256 = st.predicate.request.argsDigest;
  }), ...A, log: alog });
}
addCase({ name: "resigned-approval-consumed-after-expiry", description: "A consumed time after the signed expiry fails even though the receipt's initial timestamp was within the approval window.", bundle: resigned(approvedBundle, approvalIssuer, (st) => { st.predicate.approval!.consumedAt = new Date(Date.now() + 7200_000).toISOString(); }), ...A, log: alog });
addCase({ name: "resigned-approval-checked-before-issuance", description: "The final consumption time is valid but the recorded check precedes the human's signature window; approval time validation must check both.", bundle: resigned(approvedBundle, approvalIssuer, (st) => { st.predicate.approval!.checkedAt = new Date(Date.now() - 7200_000).toISOString(); }), ...A, log: alog });
addCase({ name: "resigned-approval-not-consumed", description: "An executed call with its consumption record removed is inconsistent with single-use approval enforcement.", bundle: resigned(approvedBundle, approvalIssuer, (st) => { delete st.predicate.approval!.consumedAt; }), ...A, log: alog });
addCase({ name: "resigned-approval-denied-but-forwarded", description: "An executed call whose approval status is denied fails approval/execution consistency.", bundle: resigned(approvedBundle, approvalIssuer, (st) => { st.predicate.approval!.status = "denied"; }), ...A, log: alog });
for (const part of ["execution", "approval"] as const) addCase({ name: `resigned-${part}-array-status`, description: "An array whose string conversion resembles a status is not a status; reject it before the equality-based execution and approval checks.", bundle: resigned(approvedBundle, approvalIssuer, (st) => { (st.predicate[part] as unknown as { status: unknown }).status = [part === "execution" ? "executed" : "approved"]; }), ...A, log: alog });
addCase({ name: "resigned-approval-withheld", description: "An approval hidden behind a capture commitment cannot bypass the approval checks: approval is structural evidence.", bundle: resigned(approvedBundle, approvalIssuer, (st) => { (st.predicate as unknown as { approval: unknown }).approval = withhold(st.predicate.approval).commitment; st.predicate.capture = { mode: "digest", withheld: [["approval"]] }; }), ...A, log: alog });
for (const field of ["status", "checkedAt", "approverKeyids"] as const) addCase({ name: `resigned-precommit-approval-${field}`, description: "The precommit approval record is changed and re-signed while the final receipt keeps a valid approval. The initial authorization must itself record a valid approval.", bundle: resigned(approvedBundle, approvalIssuer, (st) => {
  const authorization = st.predicate.authorization!;
  const original = JSON.parse(Buffer.from(authorization.envelope.payload, "base64").toString()) as { predicate: { approval: NonNullable<ReceiptStatement["predicate"]["approval"]> } };
  if (field === "status") original.predicate.approval.status = "denied";
  if (field === "checkedAt") original.predicate.approval.checkedAt = new Date(Date.now() - 7200_000).toISOString();
  if (field === "approverKeyids") original.predicate.approval.approverKeyids = [human.keyid, human.keyid];
  authorization.envelope = dsseSign(RECEIPT_TYPE, original, approvalIssuer);
}), ...A, log: alog });
for (const malformed of ["fractional-amount", "unknown-field", "bad-date"] as const) addCase({ name: `resigned-human-approval-${malformed}`, description: "Both human keys signed a malformed approval payload. A trusted signature does not exempt it from schema checks.", bundle: resigned(approvedBundle, approvalIssuer, (st) => {
  const value = JSON.parse(Buffer.from(st.predicate.approval!.envelope!.payload, "base64").toString());
  if (malformed === "fractional-amount") value.amount = 25.01;
  if (malformed === "unknown-field") value.unrecognized = "not part of the approval format";
  if (malformed === "bad-date") value.issuedAt = "2026-02-30T12:00:00Z";
  st.predicate.approval!.envelope = dsseCountersign(dsseSign(APPROVAL_TYPE, value, human), secondHuman);
}), ...A, log: alog });

// A refusal that carried a valid approval, and an approved call under a private args rule. The refusal needs no human
// keys. Under the private rule the approval envelope is a commitment, so its checks pass as committed.
for (const variant of ["clear", "private"] as const) {
  const vfx = buildFixture(mkdtempSync(join(tmpdir(), `vectors-approval-${variant}-`)));
  key(`approval-${variant}-gateway`, vfx.gatewayPub);
  key(`approval-${variant}-principal`, vfx.principalPub);
  const vcfg = loadConfig(vfx.configFile);
  vcfg.approvals = { trustedKeys: [humanFiles.pubFile], usedDir: join(vfx.dir, "used-approvals"), tools: [{ tool: "stripe.refund", minApprovers: 1 }] };
  vcfg.precommit = ["stripe.refund"];
  if (variant === "private") vcfg.capture = { "*": { args: { mode: "digest" } } };
  const approval = () => ({ [APPROVAL_META_KEY]: createApproval(human, { ...abinding, expiresAt: new Date(Date.now() + 3600_000).toISOString() }) });
  const permitting = await createGateway(vcfg);
  const forwardedCall = await permitting.handleCall({ name: "stripe.refund", arguments: aargs, _meta: approval() });
  await permitting.close();
  // the policy file is read at start: a second gateway on the same directory, with a policy that forbids the call
  writeFileSync(join(vfx.dir, "policy.cedar"), "forbid(principal, action, resource);");
  const refusing = await createGateway(vcfg);
  const cedarDenied = await refusing.handleCall({ name: "stripe.refund", arguments: aargs, _meta: approval() });
  await refusing.close();
  const V = { issuerKeys: [`approval-${variant}-gateway`], principalKeys: [`approval-${variant}-principal`], logKeys: [] as string[] };
  const vlog = logLines(vfx.logFile);
  addCase({ name: `gateway-approval-cedar-denied${variant === "private" ? "-private-args" : ""}`, description: `A valid single-human approval was presented and the Cedar policy then denied the call${variant === "private" ? ", with the arguments withheld (digest)" : ""}. The gateway records the approval as approved and the call as denied. The call was never forwarded, so the receipt verifies without any human key.`, bundle: bundleFile(vfx.receiptsDir, String(cedarDenied._meta?.[RECEIPT_META_KEY])), ...V, log: vlog });
  if (variant === "private") addCase({ name: "gateway-approved-private-args", description: "A forwarded call with an approval under a private args rule (digest). The receipt withholds the approval envelope, which carries the action fields and an unsalted digest of the arguments. The signature, window, and binding checks pass as committed; the status, the times, and the signer ids stay in clear.", bundle: bundleFile(vfx.receiptsDir, String(forwardedCall._meta?.[RECEIPT_META_KEY])), ...V, approvalKeys: ["human"], log: vlog });
}
// A grant revoked right after the approval was consumed: the call is withheld, the approval stays recorded as approved
// with its consumption time, and the precommit exists. Verifies without human keys. The revocation is written from the
// durable claim's fsync, as the gateway tests do, so that it lands between the claim and the forward.
for (const variant of ["clear", "private"] as const) {
  const rfx = buildFixture(mkdtempSync(join(tmpdir(), `vectors-approval-revoked-${variant}-`)));
  key(`approval-revoked-${variant}-gateway`, rfx.gatewayPub);
  key(`approval-revoked-${variant}-principal`, rfx.principalPub);
  const rcfg = loadConfig(rfx.configFile);
  rcfg.approvals = { trustedKeys: [humanFiles.pubFile], usedDir: join(rfx.dir, "used-approvals"), tools: [{ tool: "stripe.refund", minApprovers: 1 }] };
  rcfg.precommit = ["stripe.refund"];
  rcfg.revokedGrants = join(rfx.dir, "revoked.json");
  if (variant === "private") rcfg.capture = { "*": { args: { mode: "digest" } } };
  const revoking = await createGateway(rcfg);
  const realFsync = nodeFs.fsyncSync;
  nodeFs.fsyncSync = (fd: number) => { realFsync(fd); writeFileSync(rcfg.revokedGrants!, JSON.stringify([revoking.grantDigest])); };
  syncBuiltinESMExports();
  const revoked = await revoking.handleCall({ name: "stripe.refund", arguments: aargs, _meta: { [APPROVAL_META_KEY]: createApproval(human, { ...abinding, expiresAt: new Date(Date.now() + 3600_000).toISOString() }) } });
  nodeFs.fsyncSync = realFsync;
  syncBuiltinESMExports();
  await revoking.close();
  addCase({ name: `gateway-approval-revoked-after-consumption${variant === "private" ? "-private-args" : ""}`, description: `The grant was revoked after the gateway consumed a valid approval and before it forwarded the call${variant === "private" ? ", with the arguments withheld (digest)" : ""}. The call is withheld; the approval is recorded as approved and consumed, and a precommit exists. No call was forwarded, so the receipt verifies without any human key.`, bundle: bundleFile(rfx.receiptsDir, String(revoked._meta?.[RECEIPT_META_KEY])), issuerKeys: [`approval-revoked-${variant}-gateway`], principalKeys: [`approval-revoked-${variant}-principal`], logKeys: [], log: logLines(rfx.logFile) });
}
// The rule keeps the arguments whole in clear and the result private: an approved envelope stays in clear, so the
// binding check runs. A crafted receipt that withholds it beside clear arguments fails instead of passing as committed.
{
  const cfx = buildFixture(mkdtempSync(join(tmpdir(), "vectors-approval-args-clear-")));
  key("approval-args-clear-gateway", cfx.gatewayPub);
  key("approval-args-clear-principal", cfx.principalPub);
  const ccfg = loadConfig(cfx.configFile);
  ccfg.approvals = { trustedKeys: [humanFiles.pubFile], usedDir: join(cfx.dir, "used-approvals"), tools: [{ tool: "stripe.refund", minApprovers: 1 }] };
  ccfg.capture = { "*": { args: { mode: "clear" }, result: { mode: "digest" } } };
  ccfg.precommit = ["stripe.refund"];
  const clearArgs = await createGateway(ccfg);
  const clearCall = await clearArgs.handleCall({ name: "stripe.refund", arguments: aargs, _meta: { [APPROVAL_META_KEY]: createApproval(human, { ...abinding, expiresAt: new Date(Date.now() + 3600_000).toISOString() }) } });
  await clearArgs.close();
  const C = { issuerKeys: ["approval-args-clear-gateway"], principalKeys: ["approval-args-clear-principal"], logKeys: [] as string[], approvalKeys: ["human"], log: logLines(cfx.logFile) };
  const clearBundle = bundleFile(cfx.receiptsDir, String(clearCall._meta?.[RECEIPT_META_KEY]));
  addCase({ name: "gateway-approved-args-clear-result-private", description: "A forwarded call with an approval, under a rule that keeps the arguments whole in clear and the result private. The approved envelope stays in clear beside the clear arguments, so the signature, window, and binding checks all run and pass.", bundle: clearBundle, ...C });
  const clearGatewayKey = loadPrivateKey(join(cfx.dir, "keys", "gateway.key"));
  const hideEnvelope = (st: { predicate: { approval?: { envelope?: unknown }; capture?: { mode: "digest" | "encrypted"; withheld: string[][] } } }, commitment: unknown) => {
    (st.predicate.approval as { envelope?: unknown }).envelope = commitment;
    st.predicate.capture = { mode: "digest", withheld: [...(st.predicate.capture?.withheld ?? []), ["approval", "envelope"]] };
  };
  addCase({ name: "resigned-approval-envelope-withheld-beside-clear-args", description: "The issuer re-signed the receipt with the approval envelope replaced by a commitment and the capture note naming it, while the arguments are in clear. A verifier must not pass the human signatures as committed: with the arguments public the binding could be checked, so the check fails.", bundle: resigned(clearBundle, clearGatewayKey, (st) => hideEnvelope(st, withhold(st.predicate.approval!.envelope).commitment)), ...C });
  // the same, in the precommit too: both statements carry one commitment, so "authorization carries this approval" holds
  // and only the check on the precommit's own approval can fail
  addCase({ name: "resigned-precommit-approval-envelope-withheld-beside-clear-args", description: "The receipt and its precommit both carry one commitment in place of the approval envelope, with the arguments in clear. The precommit's approval must not pass as committed either: `authorization approval was valid` fails beside the receipt's own signature check.", bundle: resigned(clearBundle, clearGatewayKey, (st) => {
    const commitment = withhold(st.predicate.approval!.envelope).commitment;
    const authorization = st.predicate.authorization!;
    const original = JSON.parse(Buffer.from(authorization.envelope.payload, "base64").toString()) as { predicate: Parameters<typeof hideEnvelope>[0]["predicate"] };
    hideEnvelope(original, commitment);
    authorization.envelope = dsseSign(RECEIPT_TYPE, original, clearGatewayKey);
    hideEnvelope(st, commitment);
  }), ...C });
}
// a private args rule whose clear list covers every argument of the call: nothing is withheld under request.args, so the
// approved envelope stays in clear and the binding check runs, as it does under a rule that keeps the arguments whole
{
  const lfx = buildFixture(mkdtempSync(join(tmpdir(), "vectors-approval-args-listed-")));
  key("approval-args-listed-gateway", lfx.gatewayPub);
  key("approval-args-listed-principal", lfx.principalPub);
  const lcfg = loadConfig(lfx.configFile);
  lcfg.approvals = { trustedKeys: [humanFiles.pubFile], usedDir: join(lfx.dir, "used-approvals"), tools: [{ tool: "stripe.refund", minApprovers: 1 }] };
  lcfg.capture = { "*": { args: { mode: "digest", clear: Object.keys(aargs) } } };
  lcfg.precommit = ["stripe.refund"];
  const listed = await createGateway(lcfg);
  const listedCall = await listed.handleCall({ name: "stripe.refund", arguments: aargs, _meta: { [APPROVAL_META_KEY]: createApproval(human, { ...abinding, expiresAt: new Date(Date.now() + 3600_000).toISOString() }) } });
  await listed.close();
  addCase({ name: "gateway-approved-args-all-clear-listed", description: "A forwarded call with an approval under a private args rule whose clear list names every argument of the call. Nothing under request.args is withheld, so the approved envelope stays in clear and the signature, window, and binding checks all run and pass, in the receipt and in the precommit.", bundle: bundleFile(lfx.receiptsDir, String(listedCall._meta?.[RECEIPT_META_KEY])), issuerKeys: ["approval-args-listed-gateway"], principalKeys: ["approval-args-listed-principal"], logKeys: [], approvalKeys: ["human"], log: logLines(lfx.logFile) });
}
addCase({ name: "resigned-approval-checked-at-no-offset", description: "The approval record's checkedAt and consumedAt carry no offset. Date.parse would read them as local time, so the window checks would depend on the verifier's time zone. Both verifiers refuse such a time as a structural fault.", bundle: resigned(approvedBundle, approvalIssuer, (st) => {
  st.predicate.approval!.checkedAt = st.predicate.approval!.checkedAt.replace("Z", "");
  st.predicate.approval!.consumedAt = st.predicate.approval!.consumedAt!.replace("Z", "");
}), ...A, log: alog });

// ---- arguments with special keys: an own property named __proto__ is in the digest, as it was in the call ----
const protoFx = buildFixture(mkdtempSync(join(tmpdir(), "vectors-proto-")));
key("proto-gateway", protoFx.gatewayPub);
key("proto-principal", protoFx.principalPub);
const pgwProto = await createGateway(loadConfig(protoFx.configFile));
const protoCall = await pgwProto.handleCall({ name: "stripe.refund", arguments: JSON.parse('{"customer_id":"cust_123","amount":2500,"__proto__":{"polluted":true}}') as Record<string, unknown> });
await pgwProto.close();
addCase({ name: "gateway-executed-proto-key", description: "The call's arguments carry an own property named __proto__. The receipt records it and the args digest covers it (a canonicaliser that loses the key fails the digest check).", bundle: bundleFile(protoFx.receiptsDir, String(protoCall._meta?.[RECEIPT_META_KEY])), issuerKeys: ["proto-gateway"], principalKeys: ["proto-principal"], logKeys: [], log: logLines(protoFx.logFile) });

// ---- private evidence: the receipt carries commitments where the capture rule withholds; the digests are over the whole call ----
process.env.VECTORS_CAPTURE_KEY = "9f1c2e3d4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff0";
const capFx = buildFixture(mkdtempSync(join(tmpdir(), "vectors-capture-")));
key("capture-gateway", capFx.gatewayPub);
key("capture-principal", capFx.principalPub);
key("capture-upstream", capFx.upstreamPub);
{
  const cfg = JSON.parse(readFileSync(capFx.configFile, "utf8"));
  cfg.capture = { "stripe.refund": { args: { mode: "encrypted", clear: ["customer_id", "amount"] }, result: { mode: "digest" }, facts: { mode: "encrypted" } } };
  cfg.captureKeyEnv = "VECTORS_CAPTURE_KEY";
  writeFileSync(capFx.configFile, JSON.stringify(cfg));
}
const capGw = await createGateway(loadConfig(capFx.configFile));
const privateCall = await capGw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500, reason: "customer called from +44 20 7946 0000" } });
await capGw.close();
const privateBundle = bundleFile(capFx.receiptsDir, String(privateCall._meta?.[RECEIPT_META_KEY]));
const CAP = { issuerKeys: ["capture-gateway"], principalKeys: ["capture-principal"], logKeys: [] as string[] };
// the arguments private and the result in clear: the result's _meta is withheld, the plain attestation stays
const clrFx = buildFixture(mkdtempSync(join(tmpdir(), "vectors-capture-clear-result-")));
key("clear-result-gateway", clrFx.gatewayPub);
key("clear-result-principal", clrFx.principalPub);
key("clear-result-upstream", clrFx.upstreamPub);
{
  const cfg = JSON.parse(readFileSync(clrFx.configFile, "utf8"));
  cfg.capture = { "stripe.refund": { args: { mode: "digest", clear: ["amount"] }, result: { mode: "clear" } } };
  writeFileSync(clrFx.configFile, JSON.stringify(cfg));
}
const clrGw = await createGateway(loadConfig(clrFx.configFile));
const clrCall = await clrGw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500, reason: "customer called from +44 20 7946 0000" } });
await clrGw.close();
addCase({ name: "gateway-private-clear-result-upstream-attested", description: "A refund whose arguments are withheld (digest) and whose result the rule leaves in clear. The result's _meta is withheld, as it always is under a private rule, and the upstream's plain attestation stays in clear beside the result. With the upstream key given, `upstream signature (upstream key)` runs and passes in both verifiers: the signature covers the content and isError, never _meta. The expected outcome alone cannot tell a pass from a skip; the wrong-key case beside it shows the check runs.", bundle: bundleFile(clrFx.receiptsDir, String(clrCall._meta?.[RECEIPT_META_KEY])), issuerKeys: ["clear-result-gateway"], principalKeys: ["clear-result-principal"], logKeys: [], upstreamKeys: ["clear-result-upstream"], log: logLines(clrFx.logFile) });
addCase({ name: "gateway-private-clear-result-upstream-wrong-key", description: "The same receipt with the principal's key offered as the upstream key. The check runs rather than being skipped for the withheld _meta, so `upstream signature (upstream key)` fails in both verifiers; everything else passes.", bundle: bundleFile(clrFx.receiptsDir, String(clrCall._meta?.[RECEIPT_META_KEY])), issuerKeys: ["clear-result-gateway"], principalKeys: ["clear-result-principal"], logKeys: [], upstreamKeys: ["clear-result-principal"], log: logLines(clrFx.logFile) });
addCase({ name: "gateway-executed-private", description: "A refund whose capture rule withholds the note (encrypted), the provider's answer (digest), and the customer record (encrypted): the receipt carries commitments, the digests are over the whole call, and without the key or a disclosure the verifier passes them as committed, not recomputed, and does not check the upstream's signature.", bundle: privateBundle, ...CAP, upstreamKeys: ["capture-upstream"], log: logLines(capFx.logFile) });
// commitment-shaped data without a capture note is ordinary data: the digest covers it and a verifier must not take it for a withheld field
const shapedFx = buildSdkFixture(mkdtempSync(join(tmpdir(), "vectors-shaped-")));
key("shaped-app", shapedFx.appPub);
const shapedSdk = createSdkIssuer(loadSdkConfig(shapedFx.configFile));
const shapedBundle = await shapedSdk.record({ tool: "stripe.refund", args: { customer_id: "cust_123", amount: 100 } }, { status: "executed", result: { content: [{ type: "text", text: "{\"status\":\"succeeded\"}" }], extra: { $custody: "withheld", sha256: "00".repeat(32), salt: "00".repeat(16) } } });
const shapedKey = loadPrivateKey(join(shapedFx.dir, "keys", "app.key"));
addCase({ name: "sdk-malformed-commitment-resigned", description: "An SDK receipt whose request argument is replaced by `{ $custody: \"withheld\" }` with no sha256 and no salt, a capture note naming that path added, the original digest kept, re-signed. A tag without the fields a verifier checks is not a commitment, so the note is not borne out and the args digest check fails in both verifiers.", bundle: resigned(shapedBundle, shapedKey, (st) => { (st.predicate.request.args as Record<string, unknown>).amount = { $custody: "withheld" }; (st.predicate as { capture?: unknown }).capture = { mode: "digest", withheld: [["request", "args", "amount"]] }; }), issuerKeys: ["shaped-app"], principalKeys: [], logKeys: [], log: logLines(shapedFx.logFile) });
addCase({ name: "sdk-array-hash-commitment-resigned", description: "As above, with `sha256` an array holding one well-formed hash instead of a string. A pattern test that coerces its argument would take it for a commitment; both verifiers require a string, and the args digest check fails.", bundle: resigned(shapedBundle, shapedKey, (st) => { (st.predicate.request.args as Record<string, unknown>).amount = { $custody: "withheld", sha256: ["00".repeat(32)] }; (st.predicate as { capture?: unknown }).capture = { mode: "digest", withheld: [["request", "args", "amount"]] }; }), issuerKeys: ["shaped-app"], principalKeys: [], logKeys: [], log: logLines(shapedFx.logFile) });
addCase({ name: "sdk-array-keyid-commitment-resigned", description: "An encrypted-shaped commitment whose `keyid` is an array holding one hex string. Not a commitment in either verifier; the args digest check fails.", bundle: resigned(shapedBundle, shapedKey, (st) => { (st.predicate.request.args as Record<string, unknown>).amount = { $custody: "encrypted", alg: "A256GCM", keyid: ["00".repeat(32)], iv: "AAAA", ciphertext: "AAAA", tag: "AAAA", sha256: "00".repeat(32) }; (st.predicate as { capture?: unknown }).capture = { mode: "encrypted", withheld: [["request", "args", "amount"]] }; }), issuerKeys: ["shaped-app"], principalKeys: [], logKeys: [], log: logLines(shapedFx.logFile) });
addCase({ name: "gateway-undeclared-envelope-commitment-resigned", description: "An executed receipt with a clear result whose upstream envelope is replaced by a well-formed commitment, with no capture note naming it, re-signed. The note, not the shape, says what is withheld: with the upstream key given, the signature check fails instead of being skipped.", bundle: resigned(executed, gatewayKey, (st) => { (st.predicate.execution as { upstream: { envelope: unknown } }).upstream.envelope = { $custody: "withheld", sha256: "00".repeat(32) }; }), ...G, upstreamKeys: ["upstream"], log: glog });
// a crafted issuer withholds a structural part, or writes a note no issuer writes: the verifiers refuse the statement outright
const structural = (name: string, description: string, edit: (st: ReceiptStatement) => void) => addCase({ name, description, bundle: resigned(executed, gatewayKey, edit), ...G, upstreamKeys: ["upstream"], log: glog });
structural("resigned-status-withheld", "The executed receipt's execution.status replaced by a well-formed commitment, named in the note, re-signed. A note may not name what a verifier reads to run its checks: the statement fails `structural parts in clear` in both verifiers.", (st) => { const w = withhold("executed"); (st.predicate.execution as { status: unknown }).status = w.commitment; (st.predicate as { capture?: unknown }).capture = { mode: "digest", withheld: [["execution", "status"]] }; });
structural("resigned-tool-withheld", "The whole `tool` replaced by a commitment and named in the note. Fails `structural parts in clear`.", (st) => { const w = withhold(st.predicate.tool); (st.predicate as { tool: unknown }).tool = w.commitment; (st.predicate as { capture?: unknown }).capture = { mode: "digest", withheld: [["tool"]] }; });
structural("resigned-delegation-withheld", "The grant replaced by a commitment and named in the note. Fails `structural parts in clear` rather than throwing.", (st) => { const w = withhold(st.predicate.delegation); (st.predicate as { delegation: unknown }).delegation = w.commitment; (st.predicate as { capture?: unknown }).capture = { mode: "digest", withheld: [["delegation"]] }; });
structural("resigned-note-malformed", "A capture note that is a number. Fails `structural parts in clear` in both verifiers, the same way.", (st) => { (st.predicate as { capture?: unknown }).capture = 5; });
structural("resigned-note-path-twice", "A capture note naming the same path twice. No issuer writes one; fails `structural parts in clear` in both verifiers.", (st) => { (st.predicate as { capture?: unknown }).capture = { mode: "digest", withheld: [["request", "args", "customer_id"], ["request", "args", "customer_id"]] }; });
structural("resigned-note-path-proto", "A capture note whose path begins with __proto__. A lookup of that head in an ordinary object would throw; both verifiers fail `structural parts in clear` instead.", (st) => { (st.predicate as { capture?: unknown }).capture = { mode: "digest", withheld: [["__proto__", "x"]] }; });
structural("resigned-clear-result-envelope-withheld", "The executed receipt with its result in clear and its upstream envelope replaced by a digest-only commitment named in the note, re-signed. A withheld signature beside a result in clear is not a reason to skip the check: with the upstream key given, `upstream signature (upstream key)` fails in both verifiers.", (st) => { const w = withhold("gone"); (st.predicate.execution as { upstream: { envelope: unknown } }).upstream.envelope = w.commitment; (st.predicate as { capture?: unknown }).capture = { mode: "digest", withheld: [["execution", "upstream", "envelope"]] }; });
structural("resigned-note-path-string", "A capture note whose path is a string rather than segments. Fails `structural parts in clear` in both verifiers, the same way.", (st) => { (st.predicate as { capture?: unknown }).capture = { mode: "digest", withheld: ["request.args.customer_id"] }; });
// a crafted issuer leaves out a part that the spec requires and the verifiers read: both refuse the statement before any check reads it
structural("resigned-policy-no-digest", "The executed receipt's policy without `policyDigest`, re-signed. The spec requires the digest of the policy text; both verifiers fail `structural parts in clear` instead of throwing.", (st) => { delete (st.predicate.policy as { policyDigest?: string }).policyDigest; });
structural("resigned-principal-no-keyid", "The executed receipt's attested principal without `keyid`, re-signed. The spec gives an attested principal a key id; both verifiers fail `structural parts in clear` instead of throwing.", (st) => { delete (st.predicate.principal as { keyid?: string }).keyid; });
addCase({ name: "gateway-private-short-tag-resigned", description: "The private receipt's encrypted commitment over the arguments with its tag cut to 4 bytes, re-signed with the gateway key. A tag shorter than 16 bytes is not a commitment in either verifier, so the note is not borne out and the args digest check fails.", bundle: resigned(privateBundle, loadPrivateKey(join(capFx.dir, "keys", "gateway.key")), (st) => { (st.predicate.request.args as Record<string, { tag: string }>)["$rest"]!.tag = "AAAAAA=="; }), ...CAP, log: logLines(capFx.logFile) });
addCase({ name: "sdk-custody-shaped-data-resigned", description: "An SDK receipt whose result carries data shaped like a commitment but no capture note, with the result edited and re-signed. The data is ordinary, the digest covers it, and the result digest check fails: a verifier must not skip a digest on the shape of the data.", bundle: resigned(shapedBundle, shapedKey, (st) => { (st.predicate.execution as { result: { content: { text: string }[] } }).result.content[0]!.text = "{\"status\":\"refunded twice\"}"; }), issuerKeys: ["shaped-app"], principalKeys: [], logKeys: [], log: logLines(shapedFx.logFile) });


// ---- a call refused because the grant had expired: the denial is a true record, issued outside the window ----
const efx = buildFixture(mkdtempSync(join(tmpdir(), "vectors-expired-")), 1200);
key("expired-gateway", efx.gatewayPub);
key("expired-principal", efx.principalPub);
const egw = await createGateway(loadConfig(efx.configFile));
await new Promise((r) => setTimeout(r, 1400));
const expiredCall = await egw.handleCall({ name: "customer.lookup", arguments: { customer_id: "cust_123" } });
await egw.close();
addCase({ name: "gateway-denied-expired-grant", description: "The session's grant expired before this call; the gateway denied it and issued the receipt after the window. Denied, so the validity check passes with a note; an executed receipt timestamped outside the window would not.", bundle: bundleFile(efx.receiptsDir, String(expiredCall._meta?.[RECEIPT_META_KEY])), issuerKeys: ["expired-gateway"], principalKeys: ["expired-principal"], logKeys: [], log: logLines(efx.logFile) });
addCase({ name: "gateway-denied", description: "An over-limit refund denied by policy. The receipt exists, execution is denied, and every check passes.", bundle: deniedBundle, ...G, log: glog });
addCase({ name: "gateway-executed-upstream-attested", description: "The executed receipt verified with the upstream's key as well: the upstream signed its result for this receipt, so the execution is attested, not only observed.", bundle: executed, ...G, upstreamKeys: ["upstream"], log: glog });
addCase({ name: "gateway-executed-upstream-wrong-key", description: "The same receipt with the principal's key offered as the upstream key. The upstream signature check fails; everything else passes.", bundle: executed, ...G, upstreamKeys: ["principal"], log: glog });
addCase({ name: "gateway-executed-no-log-copy", description: "The same executed receipt verified without a copy of the log: inclusion still proven against the signed tree head, the log-file check simply absent.", bundle: executed, ...G, log: null });
addCase({ name: "wrong-issuer-key", description: "Verified against the principal's key as if it were the issuer's. The signature check fails first and nothing else is decided.", bundle: executed, issuerKeys: ["principal"], principalKeys: ["principal"], logKeys: [], log: glog });
addCase({ name: "tampered-payload", description: "One character of the base64 payload changed. The signature no longer verifies.", bundle: { ...executed, envelope: { ...executed.envelope, payload: executed.envelope.payload.replace(/^(.)/, (c) => (c === "A" ? "B" : "A")) } }, ...G, log: glog });
addCase({ name: "resigned-tool-out-of-scope", description: "Predicate edited to name a tool outside the grant, then re-signed with the real gateway key. The signature passes; the scope check fails; the log no longer contains this leaf.", bundle: resigned(executed, gatewayKey, (st) => { st.predicate.tool.name = "stripe.payout"; st.subject[0]!.name = `tool-call:stripe.payout:${st.predicate.receiptId}`; }), ...G, log: glog });
addCase({ name: "resigned-policy-inconsistent", description: "Predicate edited so the policy says deny while execution says executed, re-signed with the gateway key.", bundle: resigned(executed, gatewayKey, (st) => { st.predicate.policy!.decision = "deny"; }), ...G, log: glog });
addCase({ name: "resigned-args-digest", description: "Request args edited without updating the digest, re-signed with the gateway key.", bundle: resigned(executed, gatewayKey, (st) => { (st.predicate.request.args as Record<string, unknown>).amount = 1; }), ...G, log: glog });
addCase({ name: "resigned-body-note-without-commitment", description: "The executed receipt's capture note says the provider's delivery body is withheld, the evidence is removed, the result edited, re-signed with the gateway key. A note naming a path the receipt carries no commitment for fails that path's check in both verifiers, and the edited result fails its digest.", bundle: resigned(executed, gatewayKey, (st) => { const ex = st.predicate.execution as { upstream?: unknown; result: { content: { text: string }[] } }; delete ex.upstream; (st.predicate as { capture?: unknown }).capture = { mode: "digest", withheld: [["execution", "upstream", "rawBody"]] }; ex.result.content[0]!.text = "edited"; }), ...G, log: glog });
addCase({ name: "resigned-result-digest", description: "Execution result edited without updating the result digest, re-signed with the gateway key. The result digest check fails.", bundle: resigned(executed, gatewayKey, (st) => { (st.predicate.execution as { result: unknown }).result = { content: [{ type: "text", text: "edited" }] }; }), ...G, log: glog });
addCase({ name: "inclusion-proof-wrong-index", description: "The inclusion proof's leaf index changed. The tree head still verifies; the proof does not.", bundle: { ...executed, inclusion: { ...executed.inclusion, leafIndex: executed.inclusion.leafIndex + 1 } }, ...G, log: glog });
addCase({ name: "log-copy-from-another-log", description: "Verified against a copy of a different log. Everything passes except the recomputed root.", bundle: executed, ...G, log: ["not-the-same-leaf"] });

// ---- a sub-agent under a delegation chain: principal -> planner -> refunder ----
const dfx = buildFixture(mkdtempSync(join(tmpdir(), "vectors-chain-")));
key("gateway-chain", dfx.gatewayPub);
key("principal-chain", dfx.principalPub);
const dgatewayKey = loadPrivateKey(join(dfx.dir, "keys", "gateway.key"));
{
  const principalKey = loadPrivateKey(join(dfx.dir, "keys", "principal.key"));
  const planner = generateKeyPair();
  const t0 = Date.now();
  const parent = createDelegation(principalKey, { version: "0.1", principal: "user_456", agent: "planner", scopes: ["stripe.refund", "customer.lookup"], issuedAt: new Date(t0 - 3600_000).toISOString(), expiresAt: new Date(t0 + 7200_000).toISOString(), agentKey: publicKeyToPem(planner.publicKey) });
  const child = delegateFrom(parent, planner, { agent: "refunder", scopes: ["stripe.refund"] });
  const host = await createGatewayHost(loadConfig(dfx.configFile));
  const session = host.open(child);
  const cok = await session.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500 } });
  await host.close();
  const chained = bundleFile(dfx.receiptsDir, String(cok._meta?.[RECEIPT_META_KEY]));
  const dlog = logLines(dfx.logFile);
  const D = { issuerKeys: ["gateway-chain"], principalKeys: ["principal-chain"], logKeys: [] as string[] };
  // the same chain with the child's scope escalated beyond the parent's, signed by the planner's real key
  const escalated = createDelegation(planner, { version: "0.1", principal: "user_456", agent: "refunder", scopes: ["stripe.refund", "stripe.payout"], issuedAt: new Date(t0).toISOString(), expiresAt: new Date(t0 + 3600_000).toISOString(), parent });
  addCase({ name: "gateway-chain-executed", description: "A refund by a sub-agent under a two-link delegation chain: the principal granted the planner, whose key the grant names; the planner delegated the refund to the refunder. The chain verifies to the principal's key, the receipt names the refunder and the principal, and every check passes.", bundle: chained, ...D, log: dlog });
  // #43: a child window that sorts inside the parent's as a string but lies outside it in time. The child's start is
  // written with a +02:00 offset, so its text is "later" than the parent's UTC start while the instant is earlier.
  const childStart = new Date(t0).toISOString().replace("Z", "+02:00"); // = t0 - 2h, written as t0 local
  const offsetWindow = dsseSign(DELEGATION_TYPE, { version: "0.1", principal: "user_456", agent: "refunder", scopes: ["stripe.refund"], issuedAt: childStart, expiresAt: new Date(t0 + 7200_000).toISOString(), parent }, planner);
  addCase({ name: "gateway-chain-offset-window-resigned", description: "The chain's leaf re-issued with a start time written in a +02:00 offset: as text it sorts after the parent's start, as an instant it is an hour before it. Both verifiers must compare instants and refuse the link; the re-signed receipt also loses its inclusion.", bundle: resigned(chained, dgatewayKey, (st) => { st.predicate.delegation = { envelope: offsetWindow, provenance: "attested" }; }), ...D, log: dlog });
  addCase({ name: "gateway-chain-escalated-resigned", description: "The same receipt with the chain's leaf replaced by one giving the refunder a scope the planner never held, signed with the planner's real key, then the receipt re-signed with the gateway key. The chain check fails on that link; the re-signed receipt also loses its inclusion.", bundle: resigned(chained, dgatewayKey, (st) => { st.predicate.delegation = { envelope: escalated, provenance: "attested" }; }), ...D, log: dlog });
}

// ---- observe mode: the decision is recorded, never enforced; the receipt says so and the verifier holds it to that ----
const ofx = buildFixture(mkdtempSync(join(tmpdir(), "vectors-observe-")));
{
  const cfg = JSON.parse(readFileSync(ofx.configFile, "utf8"));
  cfg.mode = "observe";
  writeFileSync(ofx.configFile, JSON.stringify(cfg));
}
key("gateway-observe", ofx.gatewayPub);
key("principal-observe", ofx.principalPub);
const ogatewayKey = loadPrivateKey(join(ofx.dir, "keys", "gateway.key"));
const ogw = await createGateway(loadConfig(ofx.configFile));
const observed = await ogw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 5000000 } });
await ogw.close();
const observedBundle = bundleFile(ofx.receiptsDir, String(observed._meta?.[RECEIPT_META_KEY]));
const olog = logLines(ofx.logFile);
const O = { issuerKeys: ["gateway-observe"], principalKeys: ["principal-observe"], logKeys: [] as string[] };
addCase({ name: "gateway-observe-denied", description: "The over-limit refund through a gateway in observe mode: the policy says deny, the call was forwarded anyway, and the receipt carries enforced: false. Every check passes; the consistency check names the mode.", bundle: observedBundle, ...O, log: olog });
addCase({ name: "resigned-observe-flag-stripped", description: "The same receipt with enforced: false removed and re-signed with the gateway key: a deny now claims to have been enforced beside an executed call, and the consistency check fails.", bundle: resigned(observedBundle, ogatewayKey, (st) => { delete st.predicate.policy!.enforced; }), ...O, log: olog });

// ---- a consequential tool: the authorization is committed to the log before the call is forwarded ----
const cfx = buildFixture(mkdtempSync(join(tmpdir(), "vectors-precommit-")));
{
  const cfg = JSON.parse(readFileSync(cfx.configFile, "utf8"));
  cfg.precommit = ["stripe.refund"];
  writeFileSync(cfx.configFile, JSON.stringify(cfg));
}
key("gateway-3", cfx.gatewayPub);
key("principal-3", cfx.principalPub);
const cgatewayKey = loadPrivateKey(join(cfx.dir, "keys", "gateway.key"));
const cgw = await createGateway(loadConfig(cfx.configFile));
const cok = await cgw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 7500 } });
const cok2 = await cgw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 7600 } });
await cgw.close();
const committed = bundleFile(cfx.receiptsDir, String(cok._meta?.[RECEIPT_META_KEY]));
const committed2 = bundleFile(cfx.receiptsDir, String(cok2._meta?.[RECEIPT_META_KEY]));
const clog = logLines(cfx.logFile);
const C = { issuerKeys: ["gateway-3"], principalKeys: ["principal-3"], logKeys: [] as string[] };
addCase({ name: "gateway-precommit-executed", description: "A consequential refund: the gateway committed a signed authorization to the log before forwarding the call, and the receipt embeds it. The five authorization checks pass, and the authorization leaf precedes the receipt leaf.", bundle: committed, ...C, log: clog });
addCase({ name: "gateway-precommit-spliced", description: "The second refund's receipt carrying the first refund's authorization, re-signed with the gateway key. The authorization verifies as a statement but does not name this call; the re-signed receipt also loses its own inclusion.", bundle: resigned(committed2, cgatewayKey, (st) => { st.predicate.authorization = decode(committed).predicate.authorization; }), ...C, log: clog });
addCase({ name: "gateway-precommit-reordered", description: "The authorization's inclusion proof replaced by the receipt's own, so it claims a leaf after the execution. The proof fails and so does the order check.", bundle: resigned(committed, cgatewayKey, (st) => { st.predicate.authorization = { ...st.predicate.authorization!, inclusion: committed.inclusion, treeHead: committed.treeHead }; }), ...C, log: clog });
addCase({ name: "resigned-authorization-no-inclusion", description: "The committed receipt's authorization without its `inclusion` proof, re-signed. The spec gives an authorization an envelope, a tree head, and a proof; both verifiers fail `structural parts in clear` instead of throwing.", bundle: resigned(committed, cgatewayKey, (st) => { delete (st.predicate.authorization as { inclusion?: unknown }).inclusion; }), ...C, log: clog });
addCase({ name: "resigned-authorization-no-tree-head", description: "The committed receipt's authorization without its `treeHead`, re-signed. Fails `structural parts in clear` in both verifiers.", bundle: resigned(committed, cgatewayKey, (st) => { delete (st.predicate.authorization as { treeHead?: unknown }).treeHead; }), ...C, log: clog });

// ---- a provider-native delivery: the fake Stripe attaches the webhook it would send, signed with the shared secret ----
const pfx = buildFixture(mkdtempSync(join(tmpdir(), "vectors-provider-")));
{
  const cfg = JSON.parse(readFileSync(pfx.configFile, "utf8"));
  cfg.upstream.args = [...cfg.upstream.args.filter((a: string, i: number, all: string[]) => a !== "--key" && all[i - 1] !== "--key"), "--webhook-secret", "whsec_vectors"];
  writeFileSync(pfx.configFile, JSON.stringify(cfg));
}
key("gateway-2", pfx.gatewayPub);
key("principal-2", pfx.principalPub);
const pgw = await createGateway(loadConfig(pfx.configFile));
const pok = await pgw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500 } });
await pgw.close();
const withWebhook = bundleFile(pfx.receiptsDir, String(pok._meta?.[RECEIPT_META_KEY]));
const plog = logLines(pfx.logFile);
const P = { issuerKeys: ["gateway-2"], principalKeys: ["principal-2"], logKeys: [] as string[] };
addCase({ name: "gateway-executed-stripe-webhook", description: "The upstream attached the Stripe webhook for the refund, signed with the shared secret whsec_vectors. With that secret given, the delivery verifies and binds to the refund id in the result: attested by shared secret.", bundle: withWebhook, ...P, providerSecrets: { stripe: "whsec_vectors" }, log: plog });
addCase({ name: "resigned-provider-bound-value-missing", description: "The webhook receipt with the result's content replaced (the refund id gone), the result digest recomputed, the metadata copy of the delivery kept, re-signed. The delivery's bound value must appear in what the agent received, never in the delivery's own copy in the metadata: the provider check fails.", bundle: resigned(withWebhook, loadPrivateKey(join(pfx.dir, "keys", "gateway.key")), (st) => { const ex = st.predicate.execution as { result: { content: { text: string }[] }; resultDigest: string }; ex.result.content = [{ text: "{\"refund_id\":\"re_SOMETHING_ELSE\",\"amount\":999999}" }] as never; ex.resultDigest = digestOf(ex.result); }), ...P, providerSecrets: { stripe: "whsec_vectors" }, log: plog });
addCase({ name: "gateway-executed-stripe-webhook-wrong-secret", description: "The same receipt with the wrong secret. The provider check fails; everything else passes.", bundle: withWebhook, ...P, providerSecrets: { stripe: "whsec_other" }, log: plog });
addCase({ name: "gateway-executed-stripe-webhook-no-secret", description: "The same receipt with no secret given. The delivery is carried, not checked; every other check passes.", bundle: withWebhook, ...P, log: plog });

// ---- SDK receipts: self-reported, no delegation ----
const sfx = buildSdkFixture(mkdtempSync(join(tmpdir(), "vectors-sdk-")), undefined, "vectors");
key("app", sfx.appPub);
const sdk = createSdkIssuer(loadSdkConfig(sfx.configFile));
const sdkBundle = await sdk.record({ tool: "stripe.refund", args: { amount: 500 }, session: { id: "sess-1", toolUseId: "call-1" } }, { status: "executed", result: { refund_id: "re_1" } }, sdk.decide({ tool: "stripe.refund", args: { amount: 500 } }));
const sdkDenied = await sdk.record({ tool: "stripe.refund", args: { amount: 500000 } }, { status: "denied", reason: "over limit" }, sdk.decide({ tool: "stripe.refund", args: { amount: 500000 } }));
const slog = logLines(sfx.logFile);
addCase({ name: "sdk-executed", description: "A receipt from the in-process SDK: issuer kind sdk, principal claimed, no delegation, every field claimed. Passes; the report says what it is worth.", bundle: sdkBundle, issuerKeys: ["app"], principalKeys: [], logKeys: [], log: slog });
addCase({ name: "sdk-denied", description: "An SDK denial receipt: the wrapped function was never called.", bundle: sdkDenied, issuerKeys: ["app"], principalKeys: [], logKeys: [], log: slog });

// ---- remote log: tree heads signed by the log's key ----
const rdir = mkdtempSync(join(tmpdir(), "vectors-remote-"));
const logKp = generateKeyPair();
const { writeKeyPair } = await import("../src/crypto.ts");
const logFiles = writeKeyPair(logKp, join(rdir, "log-keys"), "log");
key("log", logFiles.pubFile);
const remote = await serveLog(join(rdir, "server-log.jsonl"), logKp, { port: 0, logId: "vectors-log" });
// hash-only: the log's file holds leaf hashes, never the receipts; the tree heads name the log
const remoteSdk = createSdkIssuer({ agentId: "remote-bot", identity: { keyFile: join(sfx.dir, "keys", "app.key") }, receiptsDir: join(rdir, "receipts"), log: { url: remote.url, hashOnly: true } });
const remoteBundle = await remoteSdk.record({ tool: "crm.lookup", args: { id: "acct:42" } }, { status: "executed", result: { plan: "pro" } });
await remoteSdk.record({ tool: "crm.lookup", args: { id: "acct:43" } }, { status: "executed", result: { plan: "free" } });
const remoteHeadLater = (await (await fetch(new URL("head", remote.url))).json()) as { treeHead: Envelope };
const remoteProof = (await (await fetch(new URL("consistency?old=1&new=2", remote.url))).json()) as { hashes: string[] };
const rlog = logLines(join(rdir, "server-log.jsonl"));
await remote.close();
addCase({ name: "remote-log-with-log-key", description: "Logged to a log run by someone else: the tree head is signed by the log's key. With that key trusted, everything passes and the report names the log key.", bundle: remoteBundle, issuerKeys: ["app"], principalKeys: [], logKeys: ["log"], log: rlog });
addCase({ name: "remote-log-expected-id", description: "The same receipt with the expected log id given. The tree head names vectors-log, so the check passes; the log file is hash-only and its root still matches.", bundle: remoteBundle, issuerKeys: ["app"], principalKeys: [], logKeys: ["log"], logId: "vectors-log", log: rlog });
addCase({ name: "remote-log-wrong-id", description: "The same receipt with a different expected log id. Only the log-id check fails.", bundle: remoteBundle, issuerKeys: ["app"], principalKeys: [], logKeys: ["log"], logId: "another-log", log: rlog });
addCase({ name: "remote-log-without-log-key", description: "The same receipt with only the issuer key trusted. The tree head signature fails; nothing about inclusion can be decided.", bundle: remoteBundle, issuerKeys: ["app"], principalKeys: [], logKeys: [], log: rlog });

// ---- financial operations: an unknown payment and provider-bound reconciliation ----
const ffx = await financialFixture(mkdtempSync(join(tmpdir(), "vectors-financial-")));
key("financial-gateway", ffx.gatewayPub);
key("financial-principal", ffx.principalPub);
const F = { issuerKeys: ["financial-gateway"], principalKeys: ["financial-principal"], logKeys: [] as string[] };
const fhost = await createGatewayHost(loadConfig(ffx.configFile));
try {
  ffx.api.drop = true;
  const id = randomUUID();
  const session = fhost.open(JSON.parse(readFileSync(join(ffx.dir, "grant.json"), "utf8")));
  const response = await session.handleCall({ name: "stripe.refund", arguments: { amount: 60, currency: "GBP" }, _meta: { [OPERATION_META_KEY]: id } });
  const unknown = bundleFile(ffx.receiptsDir, String(response._meta?.[RECEIPT_META_KEY]));
  addCase({ name: "financial-unknown", description: "Provider accepted a refund but its response was lost. The operation is unknown, its budget stays reserved, and its committed authorization verifies.", bundle: unknown, ...F, log: logLines(ffx.logFile) });
  ffx.records.values().next().value!.status = "succeeded";
  const reconciled = await fhost.reconcile(id);
  addCase({ name: "financial-reconciled", description: "An observed provider read closes the unknown operation as confirmed. Original identity, precommitted lookup mapping, provider idempotency key, result digest and log order all verify.", bundle: reconciled, ...F, log: logLines(ffx.logFile) });
  const fkey = loadPrivateKey(join(ffx.dir, "keys", "gateway.key"));
  for (const [name, description, edit] of [
    ["financial-wrong-operation", "A re-signed reconciliation whose operation id differs from the embedded original.", (st: ReceiptStatement) => { st.predicate.operation!.id = randomUUID(); }],
    ["financial-remapped-provider-state", "A re-signed reconciliation changes the terminal provider mapping after authorization.", (st: ReceiptStatement) => { st.predicate.reconciliation!.lookup.confirmed = ["pending"]; }],
    ["financial-unrelated-provider-record", "The issuer re-signs a provider result carrying another idempotency key, recomputing the result digest. The provider status check still fails.", (st: ReceiptStatement) => { const result = { content: [{ type: "text", text: JSON.stringify({ status: "succeeded", idempotencyKey: "0".repeat(64) }) }] }; st.predicate.execution = { status: "executed", result, resultDigest: digestOf(result), provenance: "observed" }; }],
  ] as const) addCase({ name, description, bundle: resigned(reconciled, fkey, edit), ...F, log: logLines(ffx.logFile) });
} finally { await fhost.close(); await ffx.close(); }

// ---- the door: receipts for arrivals at a business's own HTTP surface, issuer kind "door" ----
{
  const origin = await startOrigin();
  const dfx = buildDoorFixture(mkdtempSync(join(tmpdir(), "vectors-door-")), origin.url);
  key("door", dfx.doorPub);
  key("door-principal", dfx.principalPub);
  const dhost = await createDoorHost(loadDoorConfig(dfx.configFile));
  const door = await serveDoor(dhost, { port: 0, log: () => {} });
  try {
    const arrive = async (method: string, path: string, headers: Record<string, string> = {}, body?: unknown) => {
      const res = await fetch(`${door.url}${path}`, { method, headers: { ...(body !== undefined ? { "content-type": "application/json" } : {}), ...headers }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
      await res.arrayBuffer();
      return bundleFile(dfx.receiptsDir, res.headers.get(RECEIPT_HEADER)!);
    };
    const D = { issuerKeys: ["door"], principalKeys: ["door-principal"], logKeys: [] as string[] };
    const readCatalogue = await arrive("GET", "/catalogue/shoes?colour=red");
    const refusedRefund = await arrive("POST", "/refunds", {}, { order: "o_1", amount: 1000 });
    const grant = createDelegation(dfx.principalKey, { version: "0.1", principal: "shop-owner", agent: "shopping-agent", scopes: ["refund", "api"], issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 3600_000).toISOString() });
    const verifiedRefund = await arrive("POST", "/refunds", { authorization: `Bearer ${grantHeader(grant)}` }, { order: "o_2", amount: 4500 });
    const dlog = logLines(dfx.logFile);
    addCase({ name: "door-unknown-executed", description: "An arrival that presented nothing reads a public route through the door: issuer kind door, principal claimed, agent `unknown` claimed, the arrival fact observed, relayed and executed. Verifies with the door's key alone.", bundle: readCatalogue, ...D, principalKeys: [], log: dlog });
    addCase({ name: "door-unknown-denied", description: "The same unknown arrival asks for a refund and the policy refuses it: a denied door receipt, nothing relayed, verified without any principal key.", bundle: refusedRefund, ...D, principalKeys: [], log: dlog });
    addCase({ name: "door-verified-executed", description: "An agent presents a grant signed by the shop's principal, in scope for the refund route: the arrival is verified, principal and agent attested, the delegation checks run, the request is committed to the log as an authorization before it is relayed, and the refund is relayed. The authorization checks run and pass.", bundle: verifiedRefund, ...D, log: dlog });
    addCase({ name: "door-verified-without-principal-trust", description: "The verified refund checked without the principal's key: the delegation signature fails, as for a gateway receipt.", bundle: verifiedRefund, ...D, principalKeys: [], log: dlog });
    const doorKey = loadPrivateKey(join(dfx.dir, "keys", "door.key"));
    addCase({ name: "resigned-door-no-policy", description: "A door receipt re-signed with its policy decision removed. A door decides every arrival by policy, so `door receipt carries a policy decision` fails.", bundle: resigned(readCatalogue, doorKey, (st) => { st.predicate.policy = null; }), ...D, principalKeys: [], log: dlog });
  } finally { await door.close(); await dhost.close(); await origin.close(); }
}

// ---- the egress witness: receipts for connections that went around the gateway, issuer kind "egress" ----
{
  const echo = await startEcho();
  const efx = buildEgressFixture(mkdtempSync(join(tmpdir(), "vectors-egress-")));
  key("egress", efx.witnessPub);
  const ehost = await createEgressHost(loadEgressConfig(efx.configFile));
  const witness = await serveEgress(ehost, { port: 0, log: () => {} });
  const wport = Number(new URL(witness.url).port);
  try {
    const attempt = async (target: string, auth?: string, send?: string) => {
      const a = await connectThrough(wport, target, auth);
      if (a.status === 200 && send) await new Promise((r) => { a.socket.once("data", r); a.socket.write(send); });
      a.socket.end();
      const file = join(efx.receiptsDir, `${a.headers[RECEIPT_HEADER]}.json`);
      for (let i = 0; i < 200 && !nodeFs.existsSync(file); i++) await new Promise((r) => setTimeout(r, 25));
      return bundleFile(efx.receiptsDir, a.headers[RECEIPT_HEADER]!);
    };
    const auth = proxyAuth(EGRESS_AGENT, EGRESS_SECRET);
    const refusedProvider = await attempt("api.stripe.com:443", auth);
    const tunnel = await attempt(`127.0.0.1:${echo.port}`, auth, "hello");
    const anonymous = await attempt(`127.0.0.1:${echo.port}`);
    const E = { issuerKeys: ["egress"], principalKeys: [] as string[], logKeys: [] as string[] };
    const elog = logLines(efx.logFile);
    addCase({ name: "egress-provider-denied", description: "A locked-down agent, identified by the proxy credential the witness checked, tries a direct call to a payment provider (CONNECT api.stripe.com:443). The policy refuses it: issuer kind egress, agent observed, destination observed, denied, nothing relayed. An observed bypass of the gateway, not a record of what was sent. Verifies with the witness's key alone.", bundle: refusedProvider, ...E, log: elog });
    addCase({ name: "egress-tunnel-executed", description: "An allowed CONNECT tunnel: the result records the address connected to, the open and close times, the bytes each way, and how it ended, never the payload.", bundle: tunnel, ...E, log: elog });
    addCase({ name: "egress-no-credential-denied", description: "A connection with no proxy credential: refused with 407 and receipted. The agent is `unknown`, claimed; the policy saw principal Agent::\"unknown\".", bundle: anonymous, ...E, log: elog });
    const egressKey = loadPrivateKey(join(efx.dir, "keys", "egress.key"));
    addCase({ name: "resigned-egress-no-policy", description: "An egress receipt re-signed with its policy decision removed. The witness decides every connection by policy, so `egress receipt carries a policy decision` fails.", bundle: resigned(refusedProvider, egressKey, (st) => { st.predicate.policy = null; }), ...E, log: elog });
    addCase({ name: "resigned-egress-unchecked-agent-relayed", description: "The executed tunnel re-signed with the agent claimed: the witness relays only for an agent whose credential it checked, so `egress relayed only for a checked agent` fails; the committed authorization still names the checked agent, so `authorization names this call` fails too.", bundle: resigned(tunnel, egressKey, (st) => { st.predicate.agent = { id: "unknown", provenance: "claimed" }; }), ...E, log: elog });
    addCase({ name: "resigned-egress-open-not-committed", description: "The executed tunnel re-signed with its authorization removed: the witness commits every relayed connection to the log before any byte moves, so `egress open committed before relaying` fails.", bundle: resigned(tunnel, egressKey, (st) => { delete st.predicate.authorization; }), ...E, log: elog });
    addCase({ name: "resigned-egress-internal-peer", description: "The executed tunnel re-signed as a connection to the host name registry.npmjs.org:443 whose recorded peer is 169.254.169.254, the cloud metadata address, with every digest recomputed. The witness never dials an internal address for a host name, so `egress peer matches the destination` fails; the authorization still names the original destination, so `authorization names this call` fails too.", bundle: resigned(tunnel, egressKey, (st) => {
      const p = st.predicate;
      const dest = { ...(p.facts.destination!.value as Record<string, unknown>), host: "registry.npmjs.org", port: 443 };
      p.facts.destination = { ...p.facts.destination!, value: dest, resultDigest: digestOf(dest) };
      p.tool = { name: "registry.npmjs.org:443", provenance: "observed" };
      p.request = { ...p.request, args: { ...p.request.args, host: "registry.npmjs.org", port: 443 } };
      p.request.argsDigest = digestOf(p.request.args);
      st.subject[0]!.digest.sha256 = p.request.argsDigest;
      const ex = p.execution as { result: Record<string, unknown>; resultDigest: string };
      ex.result = { ...ex.result, peer: "169.254.169.254" };
      ex.resultDigest = digestOf(ex.result);
    }), ...E, log: elog });
    addCase({ name: "resigned-egress-literal-peer-mismatch", description: "The executed tunnel to the IP literal 127.0.0.1 re-signed with its recorded peer changed to 169.254.169.254, the result digest recomputed. An IP literal is the Cedar action itself, so the peer must be that very address: `egress peer matches the destination` fails.", bundle: resigned(tunnel, egressKey, (st) => {
      const ex = st.predicate.execution as { result: Record<string, unknown>; resultDigest: string };
      ex.result = { ...ex.result, peer: "169.254.169.254" };
      ex.resultDigest = digestOf(ex.result);
    }), ...E, log: elog });
    addCase({ name: "resigned-egress-noncanonical-host", description: "The executed tunnel re-signed as a connection to the host 010.0.0.1 whose peer is 8.0.0.1, every digest recomputed. A part with a leading zero is not an IPv4 address in any of the three verifiers (Python's ipaddress refuses it too), so the host is read as a name and its public peer passes `egress peer matches the destination` everywhere; the verifiers must agree. The authorization still names the original destination, so `authorization names this call` fails.", bundle: resigned(tunnel, egressKey, (st) => {
      const p = st.predicate;
      const port = (p.facts.destination!.value as { port: number }).port;
      const dest = { ...(p.facts.destination!.value as Record<string, unknown>), host: "010.0.0.1" };
      p.facts.destination = { ...p.facts.destination!, value: dest, resultDigest: digestOf(dest) };
      p.tool = { name: `010.0.0.1:${port}`, provenance: "observed" };
      p.request = { ...p.request, args: { ...p.request.args, host: "010.0.0.1" } };
      p.request.argsDigest = digestOf(p.request.args);
      st.subject[0]!.digest.sha256 = p.request.argsDigest;
      const ex = p.execution as { result: Record<string, unknown>; resultDigest: string };
      ex.result = { ...ex.result, peer: "8.0.0.1" };
      ex.resultDigest = digestOf(ex.result);
    }), ...E, log: elog });
    addCase({ name: "resigned-egress-destination-mismatch", description: "The refused provider call re-signed to name another destination than the one the witness observed: `egress destination observed` fails.", bundle: resigned(refusedProvider, egressKey, (st) => { st.predicate.tool = { name: "registry.npmjs.org:443", provenance: "observed" }; }), ...E, log: elog });
  } finally { await ehost.close(); await witness.close(); await echo.close(); }
}

// ---- an OWASP ACS Guardian: decisions on ACS hooks, issuer kind "guardian" ----
{
  const gdir = mkdtempSync(join(tmpdir(), "vectors-acs-"));
  const gkey = generateKeyPair();
  const gfiles = writeApprovalKeyPair(gkey, join(gdir, "keys"), "guardian");
  key("guardian", gfiles.pubFile);
  const acsDir = join(import.meta.dirname, "..", "examples", "acs");
  const guardian = createAcsGuardian({ identity: { keyFile: gfiles.keyFile }, policyFile: join(acsDir, "policy.cedar"), receiptsDir: join(gdir, "receipts"), logFile: join(gdir, "log.jsonl") });
  const receiptOf = (r: AcsResponse | AcsResponse[]) => ((r as unknown as { result: { policy_data: Record<string, { receipt: ReceiptBundle }> } }).result.policy_data[ACS_RECEIPT_KEY]!.receipt);
  const sample = JSON.parse(readFileSync(join(acsDir, "tool-call-request.json"), "utf8")) as { params: Record<string, unknown> };
  const allowed = receiptOf(await guardian.handle(sample));
  const denied = receiptOf(await guardian.handle({ ...sample, id: "2", params: { ...sample.params, request_id: randomUUID(), payload: { tool: { name: "file_read" }, arguments: { path: { value: "/etc/passwd" } } } } }));
  const G = { issuerKeys: ["guardian"], principalKeys: [] as string[], logKeys: [] as string[] };
  const alog = logLines(join(gdir, "log.jsonl"));
  addCase({ name: "guardian-acs-allow", description: "The ACS README's sample steps/toolCallRequest (file_read /reports/q3-summary.md), decided by an ACS Guardian: issuer kind guardian, agent, tool, and arguments claimed (the agent's own report), policy allow, execution withheld (a Guardian forwards nothing). The acsStep fact carries the ACS request_hash and chain_hash. Verifies with the Guardian's key alone.", bundle: allowed, ...G, log: alog });
  addCase({ name: "guardian-acs-deny", description: "The same session asks to read /etc/passwd; no permit matches, so the Guardian denies and receipts the denial.", bundle: denied, ...G, log: alog });
  addCase({ name: "resigned-guardian-allow-as-executed", description: "The allow re-signed as if the Guardian had executed the call. A Guardian carries out nothing, so `guardian decided, executed nothing` fails.", bundle: resigned(allowed, gkey, (st) => { st.predicate.execution = { status: "executed", result: null, resultDigest: digestOf(null), provenance: "claimed" }; }), ...G, log: alog });
  addCase({ name: "resigned-guardian-no-policy", description: "The denial re-signed with its policy decision removed: `guardian receipt carries a policy decision` fails.", bundle: resigned(denied, gkey, (st) => { st.predicate.policy = null; }), ...G, log: alog });
}

writeFileSync(join(out, "receipts.json"), JSON.stringify({ version: "0.2", generated: new Date().toISOString(), note: "Each case: verify `bundle` with the named keys (see `keys`) and, when `log` is not null, a copy of the log whose lines are these leaves. `expected.failing` lists the check names that must fail; `expected.ok` is true only when it is empty.", keys, cases }, null, 2) + "\n");

// ---- audit: consistency between two signed tree heads ----
const audit = {
  version: "0.2",
  note: "auditExtends(older, newer, proof, keys): both tree heads must verify against a listed key; the proof is the log's consistency proof between their sizes.",
  cases: [
    { name: "remote-log-extends", description: "The tree head from the first remote receipt and the log's later head, with the proof the log served.", older: remoteBundle.treeHead, newer: remoteHeadLater.treeHead, proof: remoteProof.hashes, keys: ["log"], expected: { ok: true, failing: [] } },
    { name: "remote-log-wrong-order", description: "The same heads the wrong way round.", older: remoteHeadLater.treeHead, newer: remoteBundle.treeHead, proof: remoteProof.hashes, keys: ["log"], expected: { ok: false, failing: ["older is not larger than newer"] } },
    { name: "remote-log-wrong-key", description: "Tree heads checked against the app key, which did not sign them.", older: remoteBundle.treeHead, newer: remoteHeadLater.treeHead, proof: remoteProof.hashes, keys: ["app"], expected: { ok: false, failing: ["older tree head signature", "newer tree head signature"] } },
    { name: "remote-log-bad-proof", description: "A proof with a hash removed.", older: remoteBundle.treeHead, newer: remoteHeadLater.treeHead, proof: remoteProof.hashes.slice(1), keys: ["log"], expected: { ok: false, failing: ["newer log extends older log"] } },
  ],
};
writeFileSync(join(out, "audit.json"), JSON.stringify(audit, null, 2) + "\n");

// ---- the log itself: RFC 6962 roots, RFC 9162 inclusion and consistency proofs ----
const leaves = Array.from({ length: 7 }, (_, i) => `leaf-${i}`);
const hashes = leaves.map(leafHash);
const merkle = {
  version: "0.2",
  note: "leafHash = sha256(0x00 || leaf); nodeHash = sha256(0x01 || left || right). Proof hashes are hex, leaf-to-root for inclusion; RFC 9162 order for consistency.",
  leaves,
  leafHashes: hashes.map((h) => h.toString("hex")),
  roots: Array.from({ length: 8 }, (_, n) => rootOf(hashes, n)),
  inclusion: [
    ...leaves.map((_, i) => ({ leafIndex: i, treeSize: 7, hashes: inclusionProof(hashes, i, 7).hashes, root: rootOf(hashes, 7), expected: true })),
    // a case may name its leaf hash; otherwise the leaf is leafHashes[leafIndex]
    { leafIndex: 2.5, treeSize: 7, leafHash: hashes[2]!.toString("hex"), hashes: inclusionProof(hashes, 2, 7).hashes, root: rootOf(hashes, 7), expected: false, description: "an index is an integer: leaf 2's own proof walks the same path from index 2.5 when the loop halves with floor" },
    { leafIndex: 0, treeSize: 7, hashes: inclusionProof(hashes, 0, 7).hashes.map((h, i) => (i === 0 ? `${h}\n` : h)), root: rootOf(hashes, 7), expected: false, description: "a proof hash is exactly 64 lowercase hex digits: a trailing newline is refused" },
    { leafIndex: 0, treeSize: 7, hashes: inclusionProof(hashes, 0, 7).hashes, root: rootOf(hashes, 7).toUpperCase(), expected: false, description: "a root is 64 lowercase hex digits, as a signed tree head must carry it" },
  ],
  consistency: [
    ...[[0, 7], [1, 7], [2, 5], [3, 7], [4, 7], [5, 6], [7, 7]].map(([m, n]) => ({ oldSize: m, newSize: n, oldRoot: rootOf(hashes, m!), newRoot: rootOf(hashes, n!), hashes: consistencyProof(hashes, m!, n!), expected: true })),
    { oldSize: 3, newSize: 7, oldRoot: rootOf(hashes, 3), newRoot: rootOf(hashes.map((h, i) => (i === 1 ? leafHash("leaf-1-edited") : h)), 7), hashes: consistencyProof(hashes.map((h, i) => (i === 1 ? leafHash("leaf-1-edited") : h)), 3, 7), expected: false, description: "leaf 1 rewritten after the older head was taken" },
    { oldSize: 0, newSize: 7, oldRoot: rootOf(hashes, 7), newRoot: rootOf(hashes, 7), hashes: [], expected: false, description: "an old head of size 0 whose root is not the empty tree's root, sha256 of nothing" },
    { oldSize: 0, newSize: 7, oldRoot: rootOf(hashes, 0), newRoot: rootOf(hashes, 7), hashes: [hashes[0]!.toString("hex")], expected: false, description: "RFC 9162 has no consistency proof from size 0: a hash beside the empty tree's root is refused" },
    { oldSize: 0, newSize: 7, oldRoot: rootOf(hashes, 0).toUpperCase(), newRoot: rootOf(hashes, 7), hashes: [], expected: false, description: "a root is 64 lowercase hex digits, as a signed tree head must carry it: the empty tree's root in uppercase is refused" },
    { oldSize: 0, newSize: 0, oldRoot: "ab".repeat(32), newRoot: "ab".repeat(32), hashes: [], expected: false, description: "two heads of size 0 with the same root that is not the empty tree's root" },
    { oldSize: 0, newSize: 0, oldRoot: rootOf(hashes, 0), newRoot: rootOf(hashes, 0), hashes: [], expected: true, description: "two heads of size 0, each with the empty tree's root" },
    { oldSize: 1.5, newSize: 7, oldRoot: rootOf(hashes, 1), newRoot: rootOf(hashes, 7), hashes: consistencyProof(hashes, 1, 7), expected: false, description: "a size is an integer: the proof from size 1 also passes from 1.5 when the loop halves with floor" },
    { oldSize: 1, newSize: 6.5, oldRoot: rootOf(hashes, 1), newRoot: rootOf(hashes, 7), hashes: consistencyProof(hashes, 1, 7), expected: false, description: "a size is an integer: the proof to size 7 also passes to 6.5" },
    { oldSize: 1, newSize: 7, oldRoot: rootOf(hashes, 1), newRoot: rootOf(hashes, 7), hashes: consistencyProof(hashes, 1, 7).map((h, i) => (i === 0 ? `${h}\n` : h)), expected: false, description: "a proof hash is exactly 64 lowercase hex digits: a trailing newline is refused" },
  ],
};
writeFileSync(join(out, "merkle.json"), JSON.stringify(merkle, null, 2) + "\n");

// ---- canonical JSON, digests, keyids, and the DSSE pre-authentication encoding ----
const values: unknown[] = [{ b: 1, a: [3, { z: null, y: "ÿ" }], c: undefined }, "plain", 42, [1, 2, 3], { nested: { deep: { deeper: true } } }, {}];
const kp = generateKeyPair();
const env = dsseSign("application/vnd.example+json", { hello: "world" }, kp);
const canonical = {
  version: "0.2",
  note: "canonical JSON: keys sorted, no whitespace, undefined dropped. digest = hex sha256 of the canonical string. keyid = hex sha256 of the SPKI DER public key. DSSE PAE = 'DSSEv1 ' + len(type) + ' ' + type + ' ' + len(payload) + ' ' + payload, signed with Ed25519.",
  values: values.map((v) => ({ value: v ?? null, canonical: canonicalize(v), digest: digestOf(v) })),
  keyid: { publicKeyPem: kp.publicKey.export({ type: "spki", format: "pem" }), keyid: kp.keyid },
  dsse: { publicKeyPem: kp.publicKey.export({ type: "spki", format: "pem" }), envelope: env, payloadJson: canonicalize({ hello: "world" }), paeHex: Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(env.payloadType)} ${env.payloadType} ${Buffer.from(env.payload, "base64").length} `), Buffer.from(env.payload, "base64")]).toString("hex"), paeSha256: sha256Hex(Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(env.payloadType)} ${env.payloadType} ${Buffer.from(env.payload, "base64").length} `), Buffer.from(env.payload, "base64")])), expected: true },
};
writeFileSync(join(out, "canonical.json"), JSON.stringify(canonical, null, 2) + "\n");

console.log(`wrote ${cases.length} receipt cases, ${audit.cases.length} audit cases, merkle and canonical vectors to ${out}`);
