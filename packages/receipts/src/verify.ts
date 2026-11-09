// Independent verification of a receipt bundle. Needs only public keys, and optionally a copy of the log.
import { internalAddress, isAddressLiteral, sameAddress } from "./addresses.ts";
import { canonicalize, digestOf, dsseVerifiers, dsseVerify, type Envelope, type PublicKeyRef } from "./crypto.ts";
import { isApprovalTime, verifyApproval, verifyApprovalStatement } from "./approval.ts";
import { digestSaltFor, getAt, isCommitment, pathKey, pathText, restorePaths, under, type How } from "./capture.ts";
import { delegationHasParent, delegationValidAt, describeChain, verifyDelegation } from "./delegation.ts";
import { leafHash, MerkleLog, verifyConsistency, verifyInclusion } from "./log.ts";
import { checkProvider, checkUpstream, contentDigest, isProviderAttestation, type ProviderSecrets } from "./upstream.ts";
import { AUTHORIZATION_PREDICATE_TYPE, RECEIPT_PREDICATE_TYPE, RECEIPT_TYPE, TREEHEAD_TYPE, type AuthorizationBundle, type AuthorizationPredicate, type AuthorizationStatement, type ReceiptBundle, type ReceiptStatement, type TreeHead } from "./receipt.ts";

export interface Check {
  name: string;
  ok: boolean;
  detail?: string;
}

export interface VerifyOptions {
  /** keys trusted to have issued receipts: gateway keys, SDK application keys */
  issuerKeys: PublicKeyRef[];
  principalKeys: PublicKeyRef[];
  /** Human approval keys, trusted independently of receipt issuers and delegation principals. Required for an approved action. */
  approvalKeys?: PublicKeyRef[];
  /** keys of logs run by someone other than the issuer; tree heads are checked against these and the issuer keys */
  logKeys?: PublicKeyRef[];
  /** keys of upstreams that sign their results; with one given, an execution carrying an upstream signature is checked and becomes attested */
  upstreamKeys?: PublicKeyRef[];
  /** shared secrets for provider-native deliveries; with the matching one given, an execution carrying a Stripe or GitHub delivery is checked */
  providerSecrets?: ProviderSecrets;
  /** If given, the root is recomputed from this log file at the receipt's tree size and compared. */
  logFile?: string;
  /** If given, every tree head in the bundle must name this log, so a head from another tenant's log cannot be presented as this one's. */
  logId?: string;
  /** Require a strict gateway receipt: one whose issuer says it ran in strict mode, and whose call, if forwarded, carries the authorization committed before it. */
  requireStrict?: boolean;
  /**
   * The withheld values, as `agent-custody reveal` writes them or the party that holds them hands them over: a partial
   * predicate with `{ $custody: "disclosed", salt, value }` at each withheld path (`{ receiptId, request: { args: { reason: {...} } }, execution: { result: { content: {...} }, error, upstream: { rawBody } }, policy: { errors }, facts: { <name>: { value, args } } }`).
   * The digests are then recomputed and every disclosed value checked against its commitment under its salt.
   */
  disclosed?: Record<string, unknown> & { receiptId?: string };
  /** the customer's capture key: encrypted fields are revealed and the digests recomputed */
  captureKey?: Buffer;
}

export interface VerifyResult {
  ok: boolean;
  checks: Check[];
  statement: ReceiptStatement | null;
}

const short = (s: string) => s.slice(0, 12);

const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const hex64 = (v: unknown) => typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
function operationProblem(o: unknown): string | null {
  if (!isObject(o) || (o.id !== undefined && (typeof o.id !== "string" || !UUID.test(o.id))) || typeof o.originalReceiptId !== "string" || !UUID.test(o.originalReceiptId)) return "operation ids are not UUIDs";
  if (!hex64(o.idempotencyKey) || !hex64(o.lookupDigest)) return "operation idempotencyKey or lookupDigest is not a sha256";
  if (!["submitted", "pending", "confirmed", "failed", "unknown"].includes(String(o.status)) || o.provenance !== "observed") return "operation status or provenance is invalid";
  if (!isObject(o.budget) || typeof o.budget.id !== "string" || !o.budget.id.length || o.budget.id.length > 128 || typeof o.budget.currency !== "string" || !/^[A-Z]{3}$/.test(o.budget.currency) || typeof o.budget.period !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(o.budget.period)) return "operation budget is invalid";
  return null;
}
/** Provider records are JSON in the first text result, just as the gateway's ordinary fact extraction reads them. */
function providerValue(result: unknown, path: string): unknown {
  let record: unknown;
  if (isObject(result) && Array.isArray(result.content)) {
    const text = result.content.find((c) => isObject(c) && c.type === "text");
    if (isObject(text) && typeof text.text === "string") {
      try { record = JSON.parse(text.text); } catch { return undefined; }
    }
  }
  return path.split(".").reduce<unknown>((v, k) => isObject(v) && Object.hasOwn(v, k) ? v[k] : undefined, record);
}

/** Verify a pre-forward authorization on its own when a crash prevented an outcome receipt being written. */
function verifyOriginalAuthorization(bundle: AuthorizationBundle, opts: VerifyOptions): { ok: boolean; predicate: AuthorizationPredicate | null; checks: Check[] } {
  const checks: Check[] = [];
  const add = (name: string, ok: boolean, detail?: string) => checks.push({ name, ok, ...(detail === undefined ? {} : { detail }) });
  const sig = dsseVerify(bundle.envelope, opts.issuerKeys);
  const st = sig.ok ? sig.payload as AuthorizationStatement : null;
  const typed = !!st && bundle.envelope.payloadType === RECEIPT_TYPE && st.predicateType === AUTHORIZATION_PREDICATE_TYPE;
  add("authorization signature (issuer key)", sig.ok && typed);
  if (!sig.ok || !st || !typed) return { ok: false, predicate: null, checks };
  const p = st.predicate;
  // Authorizations have no session, model, or execution; validate the parts they share with ordinary receipts.
  const problem = structuralProblem({ ...p, session: { id: null, toolUseId: null, provenance: "claimed" }, model: { id: null, provenance: "claimed" }, execution: { status: "withheld", provenance: "observed" } });
  add("structural parts in clear", !problem, problem ?? undefined);
  if (problem) return { ok: false, predicate: null, checks };
  add("authorization issued by the gateway", (p.issuer.kind === "gateway" || p.issuer.kind === "door") && p.issuer.keyid === sig.keyid, p.issuer.kind === "door" ? "a door commits a request before relaying it, as a gateway commits a call" : undefined);
  add("authorization operation is submitted", p.issuer.kind === "door" || p.operation?.status === "submitted", p.issuer.kind === "door" ? "a door has no operations" : undefined);
  add("authorization permits the original call", p.policy?.decision === "allow" ? Array.isArray(p.policy.errors) && p.policy.errors.length === 0 : p.policy?.decision === "deny" && p.policy.enforced === false);
  const del = p.delegation && verifyDelegation(p.delegation.envelope, opts.principalKeys);
  add("delegation signature (principal key)", !!del?.ok);
  if (del?.ok) {
    const d = del.delegation;
    add("delegation binds principal and agent", d.principal === p.principal.id && d.agent === p.agent.id && p.principal.provenance === "attested" && p.principal.keyid === del.keyid);
    add("delegation valid at receipt time", delegationValidAt(d, p.timestamp));
    add("executed tool within delegated scope", d.scopes.includes(p.tool.name));
  }
  const back = restorePaths(p, p.capture, undefined, opts.captureKey);
  add("captured commitments are well formed", back.problems.length === 0, back.problems[0]?.error);
  const missingArgs = back.missing.some((w) => under(w, ["request", "args"]));
  add("request args digest", st.subject[0]?.digest.sha256 === p.request.argsDigest && (missingArgs || digestOf(back.predicate.request.args, digestSaltFor(back, p.capture, ["request", "args"])) === p.request.argsDigest));
  const th = dsseVerify(bundle.treeHead, [...(opts.logKeys ?? []), ...opts.issuerKeys]);
  add("tree head signature", th.ok && bundle.treeHead.payloadType === TREEHEAD_TYPE);
  if (th.ok) {
    const head = th.payload as TreeHead;
    if (opts.logId !== undefined) add("tree head names the expected log", head.log === opts.logId);
    add("log inclusion proof", head.treeSize === bundle.inclusion.treeSize && verifyInclusion(leafHash(canonicalize(bundle.envelope)), bundle.inclusion, head.rootHash));
    if (opts.logFile) {
      try { add("log file root matches tree head", MerkleLog.rootFromFile(opts.logFile, head.treeSize) === head.rootHash); }
      catch { add("log file root matches tree head", false); }
    }
  }
  return { ok: checks.every((c) => c.ok), predicate: p, checks };
}
/** The parts of a statement a capture note may never name: what a verifier reads to run its checks. A note naming one, or a commitment sitting there, is not a private receipt but a broken one. */
const STRUCTURAL_TOP = new Set(["receiptId", "timestamp", "issuer", "principal", "agent", "delegation", "tool", "authorization", "capture"]);
// The approval record's envelope and reason are withheld under a private rule; its status, times, and signer ids are not.
const STRUCTURAL_IN: Record<string, Set<string>> = { approval: new Set(["status", "requiredApprovers", "checkedAt", "consumedAt", "approverKeyids", "fields", "provenance"]), request: new Set(["argsDigest", "provenance"]), execution: new Set(["status", "provenance"]), policy: new Set(["decision", "reasons", "policyDigest", "enforced", "provenance"]), consumed: new Set(["provenance"]), session: new Set(["provenance"]), model: new Set(["provenance"]), operation: new Set(["idempotencyKey", "lookupDigest", "status", "budget", "originalReceiptId", "provenance"]), reconciliation: new Set(["original", "lookup"]) };
/**
 * Why a statement cannot be verified at all, or null: the capture note is malformed, names a structural part, or a
 * structural part is not what every check assumes it to be. Checked once, before anything reads the statement, so that
 * a crafted note cannot hide the status, the tool, the decision, or the digests behind a commitment and still verify.
 */
export function structuralProblem(p: unknown): string | null {
  if (!isObject(p)) return "the predicate is not an object";
  const note = p.capture;
  if (note !== undefined) {
    if (!isObject(note) || (note.mode !== "digest" && note.mode !== "encrypted") || !Array.isArray(note.withheld)) return "the capture note is malformed";
    if (new Set(note.withheld.map((w) => JSON.stringify(w))).size !== note.withheld.length) return "the capture note names a path twice";
    for (const w of note.withheld) {
      if (!Array.isArray(w) || w.length === 0 || !w.every((s) => typeof s === "string")) return "the capture note names a malformed path";
      const path = w as string[];
      const head = path[0]!;
      const named = STRUCTURAL_TOP.has(head) || (path.length === 1 && Object.hasOwn(STRUCTURAL_IN, head)) || (path.length === 2 && Object.hasOwn(STRUCTURAL_IN, head) && STRUCTURAL_IN[head]!.has(path[1]!)) || head === "facts" && (path.length <= 2 || path[2] === "tool" || path[2] === "provenance") || (head === "execution" && path.length === 2 && path[1] === "upstream") || (head === "execution" && path.length === 3 && path[1] === "upstream" && path[2] === "provider") || (head === "execution" && path.length === 3 && path[1] === "result" && path[2] === "isError");
      if (named) return `the capture note names a structural part: ${pathText(path)}`;
    }
  }
  if (typeof p.receiptId !== "string" || typeof p.timestamp !== "string") return "receiptId or timestamp is not a string";
  if (!isObject(p.issuer) || !isObject(p.principal) || !isObject(p.agent) || !isObject(p.session) || !isObject(p.model)) return "issuer, principal, agent, session, or model is not an object";
  if (p.principal.provenance === "attested" && typeof p.principal.keyid !== "string") return "an attested principal has no keyid";
  if (!isObject(p.tool) || typeof p.tool.name !== "string") return "tool.name is not a string";
  if (!isObject(p.request) || typeof p.request.argsDigest !== "string" || !isObject(p.request.args)) return "request.args or request.argsDigest is not what it should be";
  if (!isObject(p.execution) || typeof p.execution.status !== "string" || !["executed", "failed", "denied", "error", "withheld"].includes(p.execution.status)) return "execution.status is not a status";
  if (p.policy !== null && (!isObject(p.policy) || (p.policy.decision !== "allow" && p.policy.decision !== "deny") || !Array.isArray(p.policy.reasons) || typeof p.policy.policyDigest !== "string")) return "policy is neither null nor a decision";
  if (!isObject(p.facts) || Object.values(p.facts).some((f) => !isObject(f) || typeof f.tool !== "string")) return "facts is not a map of facts";
  if (p.consumed !== undefined && !isObject(p.consumed)) return "consumed is not an object";
  if (p.delegation !== undefined && (!isObject(p.delegation) || !isObject(p.delegation.envelope))) return "delegation is not a signed envelope";
  if (p.authorization !== undefined && (!isObject(p.authorization) || !isObject(p.authorization.envelope) || !isObject(p.authorization.treeHead) || !isObject(p.authorization.inclusion))) return "authorization is not a bundle";
  if (p.approval !== undefined) {
    const a = p.approval;
    if (!isObject(a) || typeof a.status !== "string" || !["approved", "denied"].includes(a.status) || (a.requiredApprovers !== 1 && a.requiredApprovers !== 2) || !isApprovalTime(a.checkedAt) || !Array.isArray(a.approverKeyids) || !a.approverKeyids.every((k) => typeof k === "string") || a.provenance !== "observed") return "approval is not an approval record";
    if (a.consumedAt !== undefined && !isApprovalTime(a.consumedAt)) return "approval consumption time is not a timestamp";
    if (a.fields !== undefined && (!isObject(a.fields) || Object.entries(a.fields).some(([k, v]) => !["amount", "currency", "beneficiary"].includes(k) || typeof v !== "string" || !v.length))) return "approval field mapping is malformed";
  }
  if (p.operation !== undefined) {
    const problem = operationProblem(p.operation);
    if (problem) return problem;
  }
  if (p.reconciliation !== undefined) {
    const r = p.reconciliation;
    if (!isObject(r) || !isObject(r.original) || !isObject(r.original.envelope) || !isObject(r.original.treeHead) || !isObject(r.original.inclusion) || !isObject(r.lookup)) return "reconciliation is not a lookup and an original bundle";
    const l = r.lookup;
    const statuses = (v: unknown) => Array.isArray(v) && v.length > 0 && v.every((s) => typeof s === "string" && s.length > 0 && s.length <= 128);
    const path = (v: unknown) => typeof v === "string" && v.length > 0 && v.length <= 512 && v.split(".").every((s) => s.length > 0);
    if (typeof l.tool !== "string" || !l.tool.length || !isObject(l.args) || !path(l.statusPath) || !path(l.identityPath) || !statuses(l.confirmed) || !statuses(l.failed) || (l.confirmed as string[]).some((s) => (l.failed as string[]).includes(s))) return "reconciliation lookup is malformed or its terminal statuses overlap";
  }
  if (isObject(p.execution.upstream) && typeof p.execution.upstream.provider !== "undefined" && typeof p.execution.upstream.provider !== "string") return "execution.upstream.provider is not a string";
  return null;
}

export function verifyBundle(bundle: ReceiptBundle, opts: VerifyOptions): VerifyResult {
  const checks: Check[] = [];
  const add = (name: string, ok: boolean, detail?: string) => {
    checks.push(detail === undefined ? { name, ok } : { name, ok, detail });
    return ok;
  };
  const done = (statement: ReceiptStatement | null): VerifyResult => ({ ok: checks.every((c) => c.ok), checks, statement });

  const sig = dsseVerify(bundle.envelope, opts.issuerKeys);
  if (!sig.ok) {
    add("receipt signature (issuer key)", false, sig.error);
    return done(null);
  }
  add("receipt signature (issuer key)", true, `keyid ${short(sig.keyid)}`);
  const st = sig.payload as ReceiptStatement;
  if (!add("receipt payload type", bundle.envelope.payloadType === RECEIPT_TYPE && st.predicateType === RECEIPT_PREDICATE_TYPE)) return done(null);
  const broken = structuralProblem(st.predicate);
  if (!add("structural parts in clear", !broken, broken ?? undefined)) return done(null);
  const p = st.predicate;

  add("issuer kind is known", p.issuer.kind === "gateway" || p.issuer.kind === "sdk" || p.issuer.kind === "door" || p.issuer.kind === "egress" || p.issuer.kind === "guardian", `${p.issuer.kind}${p.issuer.framework ? ` / ${p.issuer.framework}` : ""}`);
  add("issuer keyid matches signer", p.issuer.keyid === sig.keyid);
  if (opts.requireStrict) {
    add("strict mode in force", p.issuer.kind === "gateway" && p.issuer.strict === true, p.issuer.strict === true ? undefined : "the issuer does not say it ran in strict mode");
    // under strict mode every call is precommitted; a provider read the operator ran is a lookup, not a call
    const forwarded = p.execution.status === "executed" || p.execution.status === "failed" || p.execution.status === "error";
    add("strict: call precommitted before forwarding", !forwarded || !!p.reconciliation || !!p.authorization, forwarded && !p.reconciliation && !p.authorization ? `the call was ${p.execution.status} with no authorization committed first` : undefined);
  }
  if (p.operation) {
    add("operation observed by gateway", p.issuer.kind === "gateway" && p.operation.provenance === "observed");
    if (!p.reconciliation) {
      // A retry of an existing operation has a receipt of its own. It is withheld (never forwarded again) and names the original.
      const retry = p.operation.originalReceiptId !== p.receiptId;
      add("operation names this original receipt", !retry || p.execution.status === "withheld");
      const refused = p.execution.status === "withheld" || p.execution.status === "denied";
      add("operation awaits provider reconciliation", retry || ["submitted", "pending", "unknown"].includes(p.operation.status) || refused && p.operation.status === "failed");
      add("operation carries committed authorization", refused || !!p.authorization);
    }
  }

  if (p.issuer.kind === "gateway") {
    add("gateway receipt carries a delegation", p.delegation !== undefined);
    add("gateway receipt carries a policy decision", p.policy !== null);
  }
  // A door decides every arrival by policy; an arrival carries a grant only when it chose to present one.
  if (p.issuer.kind === "door") add("door receipt carries a policy decision", p.policy !== null);
  // An egress witness saw a connection that went around the gateway: where it went and how much, never what was sent.
  // Its destination is its own observation; its agent is only as good as the proxy credential it checked.
  if (p.issuer.kind === "egress") {
    add("egress receipt carries a policy decision", p.policy !== null);
    const dest = Object.hasOwn(p.facts, "destination") ? p.facts.destination : undefined;
    const seen = dest?.value as { host?: unknown; port?: unknown } | undefined;
    const name = typeof seen?.host === "string" && typeof seen.port === "number" ? `${seen.host.includes(":") ? `[${seen.host}]` : seen.host}:${seen.port}` : undefined;
    add("egress destination observed", p.tool.provenance === "observed" && dest?.provenance === "observed" && name === p.tool.name, name === p.tool.name ? `${p.tool.name}; an observed bypass of the gateway, not a record of what was sent` : `the destination fact names ${name ?? "nothing"}, the receipt ${p.tool.name}`);
    const relayed = p.execution.status === "executed" || p.execution.status === "failed" || p.execution.status === "error";
    add("egress relayed only for a checked agent", !relayed || p.agent.provenance === "observed", p.agent.provenance === "observed" ? `${p.agent.id}, by the proxy credential the witness checked` : relayed ? `the connection was ${p.execution.status} for an agent the witness did not check` : "no agent was checked and nothing was relayed");
    add("egress open committed before relaying", !relayed || !!p.authorization, relayed ? (p.authorization ? "the connection was in the log before any byte moved" : `the connection was ${p.execution.status} with nothing committed first`) : "nothing was relayed");
    // An IP literal is the action itself: the peer must be that very address. A host name must have led to a public address.
    const host = typeof seen?.host === "string" ? seen.host : "";
    const literal = isAddressLiteral(host);
    const reached = p.execution.status === "executed" || p.execution.status === "failed";
    const peer = p.execution.status === "executed" || p.execution.status === "failed" ? (p.execution.result as { peer?: unknown } | null)?.peer : undefined;
    const peerOk = typeof peer === "string" && (literal ? sameAddress(peer, host) : !internalAddress(peer));
    add("egress peer matches the destination", !reached || peerOk, !reached ? "no connection was made" : literal ? `${host}, an address the policy named, reached ${typeof peer === "string" ? peer : "no recorded peer"}` : `${host} reached ${typeof peer === "string" ? peer : "no recorded peer"}${peerOk ? ", a public address" : ""}`);
  }

  // A Guardian decides and carries out nothing: an allow is withheld (nothing forwarded), a deny is denied.
  if (p.issuer.kind === "guardian") {
    add("guardian receipt carries a policy decision", !!p.policy && typeof p.policy === "object" && !Array.isArray(p.policy));
    const decided = p.execution.status === "denied" ? p.policy?.decision === "deny" : p.execution.status === "withheld" && p.policy?.decision === "allow";
    add("guardian decided, executed nothing", decided, decided ? `${p.policy?.decision}; the agent asked, reports the call itself, and is trusted to honor the answer` : `the receipt says ${p.execution.status} with a policy ${p.policy?.decision ?? "absent"}`);
  }

  if (p.delegation) {
    const del = verifyDelegation(p.delegation.envelope, opts.principalKeys);
    add("delegation signature (principal key)", del.ok, del.ok ? `signed by ${short(del.keyid)}` : del.error);
    // A chained grant: every link signed by the key its parent names, scopes and windows nested, one principal
    // throughout. The line appears only when the grant embeds a parent, and fails with the link that broke.
    const chained = delegationHasParent(p.delegation.envelope);
    if (chained) add("delegation chain to the principal", del.ok, del.ok ? `${describeChain(del.chain)} (${del.chain.length - 1} delegation(s))` : del.error);
    if (del.ok) {
      const d = del.delegation;
      const principalKeyid = p.principal.provenance === "attested" ? p.principal.keyid : null;
      add("delegation binds principal and agent", d.principal === p.principal.id && d.agent === p.agent.id && del.keyid === principalKeyid);
      const inScope = d.scopes.includes(p.tool.name);
      const executed = p.execution.status === "executed" || p.execution.status === "failed";
      // a call the gateway refused after the grant ran out is still a true record; only an executed call has to sit inside the window
      const valid = delegationValidAt(d, p.timestamp);
      add("delegation valid at receipt time", valid || !executed || !!p.reconciliation, valid ? `${d.issuedAt} .. ${d.expiresAt}` : p.reconciliation ? "operator reconciliation; the original authorization's grant window is checked separately" : `${d.issuedAt} .. ${d.expiresAt}; the call was ${p.execution.status}, so the grant need not have been in force`);
      add("executed tool within delegated scope", !executed || inScope, inScope ? p.tool.name : `${p.tool.name} not in [${d.scopes.join(", ")}]`);
    }
  } else {
    add("principal is claimed, not attested", p.principal.provenance === "claimed", "no signed delegation in this receipt");
  }

  // Private evidence: the signed capture note names every path whose value is withheld behind a commitment. Each path
  // is put back when the receipt carries the value, when it is disclosed, or when the capture key reveals it; a digest
  // over values that are all back is recomputed (with the salt the statement carries), and otherwise the check passes
  // as a commitment and says so. The note decides, never the shape of the data: a path it names must hold a
  // commitment, and commitment-shaped data it does not name is ordinary data, inside the digest.
  const subjectOk = st.subject[0]?.digest.sha256 === p.request.argsDigest;
  const note = p.capture;
  if (opts.disclosed && typeof opts.disclosed === "object" && "receiptId" in opts.disclosed && opts.disclosed.receiptId !== undefined) {
    add("disclosure names this receipt", opts.disclosed.receiptId === p.receiptId, opts.disclosed.receiptId === p.receiptId ? undefined : `the disclosure is for receipt ${String(opts.disclosed.receiptId)}`);
  }
  const back = restorePaths(p, note, opts.disclosed, opts.captureKey);
  const full = back.predicate;
  const committedNote = (paths: string[][]) => {
    const encrypted = paths.filter((w) => (getAt(p, w) as { $custody?: string } | undefined)?.$custody === "encrypted").length;
    return `committed, not recomputed: ${paths.length} value(s) withheld${encrypted ? ` (${encrypted} encrypted)` : ""}; ${encrypted ? "give the capture key or " : ""}disclose them to recompute`;
  };
  const claimed = new Set<string>();
  /** the state of the withheld paths under a prefix, and the paths it claims for its check line */
  const region = (prefix: string[]) => {
    const paths = (note?.withheld ?? []).filter((w) => under(w, prefix));
    for (const w of paths) claimed.add(pathKey(w));
    const problem = back.problems.find((x) => under(x.path, prefix))?.error ?? null;
    const missing = back.missing.filter((w) => under(w, prefix));
    const hows = [...new Set(paths.map((w) => back.restored.get(pathKey(w))).filter((h): h is How => !!h))];
    const how = hows.length === 2 ? "disclosed and decrypted" : hows[0];
    return { paths, problem, missing, how };
  };
  const args = region(["request", "args"]);
  if (args.problem) add("request args digest", false, args.problem);
  else if (args.missing.length) add("request args digest", subjectOk, committedNote(args.missing));
  else add("request args digest", digestOf(full.request.args, digestSaltFor(back, note, ["request", "args"])) === p.request.argsDigest && subjectOk, args.how ? `recomputed from ${args.how} values` : undefined);
  // An upstream error can follow a side effect too; every attempted forward must have consumed a valid approval.
  const forwarded = ["executed", "failed", "error"].includes(p.execution.status);
  if (p.approval) {
    const a = p.approval;
    const consumed = a.consumedAt !== undefined && Date.parse(a.consumedAt) >= Date.parse(a.checkedAt) && Date.parse(a.checkedAt) >= Date.parse(p.timestamp);
    add("approval consistent with execution", !forwarded || (a.status === "approved" && consumed), a.status === "denied" ? `approval refused: ${typeof a.reason === "string" ? a.reason : "not approved"}` : "single use is enforced by the gateway's persistent store; one receipt cannot prove absence of reuse elsewhere");
    // Only a forwarded call must rest on a valid approval. A refusal is an authentic record whatever its approval was:
    // missing, expired, forged, already used, or valid for a call that the policy or the grant then refused.
    if (forwarded && a.status === "approved") {
      // The envelope is withheld under a private rule: it carries the action fields and a digest of the arguments.
      const sealed = region(["approval", "envelope"]);
      if (sealed.problem) add("approval signatures (human keys)", false, sealed.problem);
      // The issuer withholds the envelope only when it withholds the arguments. With the arguments in clear, a withheld
      // envelope would let an issuer skip the binding check, so it fails rather than passes as committed.
      else if (sealed.missing.length && !args.paths.length) add("approval signatures (human keys)", false, "the approval envelope is withheld but the arguments are in clear; the binding cannot be checked");
      else if (sealed.missing.length) add("approval signatures (human keys)", true, committedNote(sealed.missing));
      else {
        const envelope = (full.approval as { envelope?: unknown }).envelope;
        const signed = verifyApprovalStatement(envelope, opts.approvalKeys ?? [], a.requiredApprovers);
        const reported = signed.ok && new Set(a.approverKeyids).size >= a.requiredApprovers && a.approverKeyids.every((id) => signed.approverKeyids.includes(id));
        add("approval signatures (human keys)", signed.ok && reported, signed.ok ? `${signed.approverKeyids.length} distinct trusted signature(s)` : signed.error);
        if (signed.ok) {
          const at = a.consumedAt ?? a.checkedAt;
          const valid = [a.checkedAt, at].every((time) => Date.parse(time) >= Date.parse(signed.approval.issuedAt) && Date.parse(time) < Date.parse(signed.approval.expiresAt));
          add("approval valid at forward time", valid, `${signed.approval.issuedAt} .. ${signed.approval.expiresAt}; checked at ${at}`);
          if (args.problem) add("approval payload binding", false, args.problem);
          else if (args.missing.length) add("approval payload binding", true, committedNote(args.missing));
          else {
            const binding = verifyApproval(envelope, opts.approvalKeys ?? [], { principal: p.principal.id ?? "", agent: p.agent.id, tool: p.tool.name, args: full.request.args, ...(a.fields ? { fields: a.fields } : {}) }, { at, minApprovers: a.requiredApprovers });
            add("approval payload binding", binding.ok, binding.ok ? "principal, agent, tool, full arguments, amount, currency, and beneficiary match" : binding.error);
          }
        }
      }
    }
  }
  // a captured fact: its commitments are checked against a disclosure or the key; the policy decided on the real value
  for (const name of Object.keys(p.facts)) {
    for (const part of ["value", "args"] as const) {
      const r = region(["facts", name, part]);
      if (!r.paths.length) continue;
      if (r.problem) add(`fact ${name} ${part}`, false, r.problem);
      else add(`fact ${name} ${part}`, true, r.missing.length ? committedNote(r.missing) : `commitments hold against the ${r.how} value`);
    }
  }
  const executedOrFailed = p.execution.status === "executed" || p.execution.status === "failed";
  let result: { content: unknown; isError?: boolean } | null = null;
  if (executedOrFailed) {
    const r = region(["execution", "result"]);
    const ex = full.execution as { result: unknown; resultDigest: string };
    if (r.problem) add("execution result digest", false, r.problem);
    else if (r.missing.length) {
      add("execution result digest", true, committedNote(r.missing));
      // the upstream checks read the content, isError, and structuredContent, never _meta, which carries what the
      // upstream wrote and is withheld beside a result the rule leaves in clear: with only _meta withheld they still run
      if (r.missing.every((w) => pathKey(w) === pathKey(["execution", "result", "_meta"]))) result = ex.result as { content: unknown; isError?: boolean };
    } else {
      add("execution result digest", digestOf(ex.result, digestSaltFor(back, note, ["execution", "result"])) === ex.resultDigest, r.how ? `recomputed from ${r.how} values` : undefined);
      result = ex.result as { content: unknown; isError?: boolean };
    }
  }
  // every other withheld path gets its own line: a message, a denial reason, a provider's delivery body, a part added later
  for (const w of note?.withheld ?? []) {
    if (claimed.has(pathKey(w))) continue;
    const problem = back.problems.find((x) => pathKey(x.path) === pathKey(w))?.error;
    const how = back.restored.get(pathKey(w));
    add(`withheld ${pathText(w)}`, !problem, problem ?? (how ? `holds against the ${how} value` : committedNote([w])));
  }
  const evidence = executedOrFailed && "upstream" in p.execution ? p.execution.upstream : undefined;
  if (executedOrFailed && evidence) {
    // The evidence as restored: the delivery body or the signed envelope may have been withheld with the result. A
    // check is skipped only for a part the signed note declares withheld and the verifier could not restore; a body
    // or an envelope that is simply not there, or commitment-shaped without the note saying so, fails the check.
    const restoredEvidence = (full.execution as { upstream?: { rawBody?: unknown; envelope?: unknown } }).upstream;
    const withheldStill = (path: string[]) => (note?.withheld ?? []).some((w) => pathKey(w) === pathKey(path)) && back.missing.some((w) => pathKey(w) === pathKey(path));
    if (isProviderAttestation(evidence)) {
      if (opts.providerSecrets) {
        const re = restoredEvidence as { rawBody?: unknown; signature?: unknown; bind?: unknown } | undefined;
        const parts = ["rawBody", "signature", "bind"] as const;
        if (!result || parts.some((f) => withheldStill(["execution", "upstream", f]))) add("upstream signature not checked", true, "the result, the delivery body, its signature, or its bind is withheld; disclose them or give the capture key to check the provider's delivery");
        else if (parts.some((f) => typeof re?.[f] !== "string")) add("upstream signature (provider secret)", false, "the receipt carries no delivery body, signature, or bind to check, and the capture note does not say they are withheld");
        else {
          const u = checkProvider({ ...evidence, rawBody: re!.rawBody as string, signature: re!.signature as string, bind: re!.bind as string }, opts.providerSecrets, { timestamp: p.timestamp, result });
          add("upstream signature (provider secret)", u.ok, u.ok ? u.keyid : u.error);
        }
      }
    } else if ((opts.upstreamKeys?.length ?? 0) > 0) {
      const env = restoredEvidence?.envelope as Envelope | undefined;
      const wellFormed = !!env && typeof env === "object" && typeof env.payload === "string" && Array.isArray(env.signatures);
      if (!result) add("upstream signature not checked", true, "the result is withheld; disclose it or give the capture key to check the upstream's signature against it");
      // the issuer withholds the envelope beside a result it leaves in clear only when the envelope is anything but the plain attestation for this call (a field, a claim, or an encoding the upstream added); a verifier given the upstream's key is then told, not waved past
      else if (withheldStill(["execution", "upstream", "envelope"])) add("upstream signature (upstream key)", false, "the result is in clear but the upstream's signature is withheld; disclose it or give the capture key to check it");
      else if (!wellFormed) add("upstream signature (upstream key)", false, "the receipt carries no upstream envelope to check, and the capture note does not say it is withheld");
      else {
        const u = checkUpstream(env, opts.upstreamKeys!, { receiptId: p.receiptId, tool: p.tool.name, contentDigest: contentDigest(result) });
        add("upstream signature (upstream key)", u.ok, u.ok ? `keyid ${short(u.keyid)}` : u.error);
      }
    }
  }
  if (p.policy) {
    // a deny that was not enforced (observe mode, enforced: false on the receipt) may sit beside an executed call; an enforced one never does
    const consistent = p.policy.decision === "allow" ? p.execution.status !== "denied" : p.policy.enforced === false ? p.execution.status !== "denied" : p.execution.status === "denied";
    add("policy decision consistent with execution", consistent, `${p.policy.decision}${p.policy.enforced === false ? " (observe mode, not enforced)" : ""} -> ${p.execution.status}`);
    // a withheld error list is a non-empty one: the issuer leaves an empty list in clear
    const errors = isCommitment(p.policy.errors) || (Array.isArray(p.policy.errors) && p.policy.errors.length > 0);
    add("no policy errors on an allow", !(p.policy.decision === "allow" && errors));
  }

  if (p.reconciliation) {
    const r = p.reconciliation;
    // Refuse nesting before the recursive verifier is called; the original must be the first operation attempt.
    const osig = dsseVerify(r.original.envelope, opts.issuerKeys);
    const ost = osig.ok ? osig.payload as ReceiptStatement | AuthorizationStatement : null;
    const original = ost?.predicate;
    const eligible = isObject(original) && !("reconciliation" in original);
    let originalOk = false;
    if (eligible && ost) {
      try {
        const nested = ost.predicateType === RECEIPT_PREDICATE_TYPE
          ? verifyBundle(r.original, { ...opts, disclosed: undefined })
          : verifyOriginalAuthorization(r.original, opts);
        originalOk = nested.ok;
        for (const c of nested.checks) add(`reconciliation original ${c.name}`, c.ok, c.detail);
      } catch {
        add("reconciliation original bundle is well formed", false);
      }
    }
    add("reconciliation original evidence verifies", eligible && originalOk);
    const o = original?.operation;
    const op = p.operation;
    const linked = !!o && !!op && !operationProblem(o) && ["submitted", "pending", "unknown"].includes(o.status) && o.originalReceiptId === original!.receiptId && op.originalReceiptId === original!.receiptId && p.receiptId !== original!.receiptId && (op.id === undefined || o.id === undefined || op.id === o.id) && op.idempotencyKey === o.idempotencyKey && op.lookupDigest === o.lookupDigest && canonicalize(op.budget) === canonicalize(o.budget) && canonicalize(p.principal) === canonicalize(original!.principal) && canonicalize(p.agent) === canonicalize(original!.agent) && canonicalize(p.tool) === canonicalize(original!.tool) && canonicalize(p.delegation) === canonicalize(original!.delegation) && p.issuer.keyid === original!.issuer.keyid && Date.parse(p.timestamp) >= Date.parse(original!.timestamp);
    add("reconciliation links the original operation", linked);
    add("reconciliation lookup matches authorization", !!o && digestOf(r.lookup) === o.lookupDigest);
    const lookupArgs = region(["request", "args"]);
    add("reconciliation lookup args match request", !lookupArgs.problem && (lookupArgs.missing.length > 0 || canonicalize(full.request.args) === canonicalize(r.lookup.args)), lookupArgs.missing.length > 0 ? "request arguments committed under the capture rule" : undefined);
    const before = r.original.inclusion.leafIndex < bundle.inclusion.leafIndex && r.original.inclusion.treeSize <= bundle.inclusion.treeSize;
    const oth = dsseVerify(r.original.treeHead, [...(opts.logKeys ?? []), ...opts.issuerKeys]);
    const cth = dsseVerify(bundle.treeHead, [...(opts.logKeys ?? []), ...opts.issuerKeys]);
    add("reconciliation logged after original", before && oth.ok && cth.ok && isObject(oth.payload) && isObject(cth.payload) && oth.payload.log === cth.payload.log);
    const terminal = op?.status === "confirmed" || op?.status === "failed";
    add("reconciliation records a terminal provider outcome", terminal && p.execution.status === "executed" && p.execution.provenance === "observed");
    const rr = region(["execution", "result"]);
    if (rr.problem) add("reconciliation provider status", false, rr.problem);
    else if (rr.missing.some((w) => pathKey(w) !== pathKey(["execution", "result", "_meta"]))) add("reconciliation provider status", true, "provider result withheld; disclose it or give the capture key to recompute the gateway-observed status");
    else {
      const ex = full.execution as { result?: unknown };
      const status = providerValue(ex.result, r.lookup.statusPath);
      const mapped = typeof status === "string" ? r.lookup.confirmed.includes(status) ? "confirmed" : r.lookup.failed.includes(status) ? "failed" : null : null;
      const identity = providerValue(ex.result, r.lookup.identityPath);
      add("reconciliation provider status", terminal && mapped === op?.status && identity === op?.idempotencyKey && !(isObject(ex.result) && ex.result.isError === true), "provider read observed by the gateway and bound to its idempotency key; no independent provider signature is implied");
    }
  }

  const logKeys = opts.logKeys ?? [];
  if (p.authorization) {
    // The gateway says it committed this call to the log before forwarding it. Check that the committed statement is
    // the issuer's, describes this very call, sits in the log, and sits there before the receipt does.
    const a = p.authorization;
    const asig = dsseVerify(a.envelope, opts.issuerKeys);
    const ast = asig.ok ? (asig.payload as AuthorizationStatement) : null;
    const typed = !!ast && a.envelope.payloadType === RECEIPT_TYPE && ast.predicateType === AUTHORIZATION_PREDICATE_TYPE;
    add("authorization signature (issuer key)", asig.ok && typed && asig.keyid === sig.keyid, asig.ok ? (typed ? `keyid ${short(asig.keyid)}` : "not an authorization statement") : asig.error);
    if (ast && typed) {
      const ap = ast.predicate;
      const same = ap.receiptId === p.receiptId && ap.tool.name === p.tool.name && ap.request.argsDigest === p.request.argsDigest && ap.agent.id === p.agent.id && ap.principal.id === p.principal.id && (ap.policy?.decision === "allow" || ap.policy?.decision === "deny" && ap.policy.enforced === false);
      add("authorization names this call", same, same ? `${ap.tool.name} for receipt ${short(ap.receiptId)}` : "committed for a different receipt, tool, arguments, agent, or decision");
      if (ap.approval || p.approval) {
        const stable = (approval: typeof p.approval) => approval ? { envelope: approval.envelope, requiredApprovers: approval.requiredApprovers, fields: approval.fields } : null;
        const carries = canonicalize(stable(ap.approval)) === canonicalize(stable(p.approval));
        add("authorization carries this approval", carries, "approval envelope, signer requirement, and argument mapping must match the precommit");
        // A refusal needs no human keys, so the precommit's approval is checked for a forwarded call only.
        if (forwarded) {
          const ac = ap.approval;
          // Under a private rule the precommit carries the receipt's commitment to the envelope: it is checked once restored.
          const envelope = ac && isCommitment(ac.envelope) && carries ? (full.approval as { envelope?: unknown } | undefined)?.envelope : ac?.envelope;
          // an envelope withheld beside arguments in clear is not a private receipt: see "approval signatures (human keys)"
          const sealed = isCommitment(envelope) && args.paths.length > 0;
          const signed = ac && !sealed ? verifyApprovalStatement(envelope, opts.approvalKeys ?? [], ac.requiredApprovers) : null;
          const valid = !!ac && ac.status === "approved" && ac.provenance === "observed" && isApprovalTime(ac.checkedAt) && (sealed || !!signed?.ok) &&
            (!signed?.ok || (Date.parse(ac.checkedAt) >= Date.parse(signed.approval.issuedAt) && Date.parse(ac.checkedAt) < Date.parse(signed.approval.expiresAt))) &&
            Date.parse(ac.checkedAt) >= Date.parse(p.timestamp) && Date.parse(ac.checkedAt) <= Date.parse(p.approval?.checkedAt ?? "") &&
            Array.isArray(ac.approverKeyids) && new Set(ac.approverKeyids).size >= ac.requiredApprovers && (!signed?.ok || ac.approverKeyids.every((id) => signed.approverKeyids.includes(id)));
          add("authorization approval was valid", valid, sealed ? "the envelope is withheld, so only the recorded status, times, and signer count are checked; disclose it or give the capture key to check the signatures" : "the precommit must record an approved statement with trusted signer observations and a check inside its validity window");
        }
      }
      if (p.operation || ap.operation) {
        const o = p.operation;
        const aop = ap.operation;
        add("authorization names this operation", !!o && !!aop && !operationProblem(aop) && aop.status === "submitted" && (aop.id === undefined || o.id === undefined || aop.id === o.id) && aop.idempotencyKey === o.idempotencyKey && aop.lookupDigest === o.lookupDigest && aop.originalReceiptId === o.originalReceiptId && canonicalize(aop.budget) === canonicalize(o.budget));
      }
      const ath = dsseVerify(a.treeHead, [...logKeys, ...opts.issuerKeys]);
      add("authorization tree head signature", ath.ok && a.treeHead.payloadType === TREEHEAD_TYPE, ath.ok ? `keyid ${short(ath.keyid)}` : ath.error);
      if (ath.ok) {
        const ahead = ath.payload as TreeHead;
        const included = ahead.treeSize === a.inclusion.treeSize && verifyInclusion(leafHash(canonicalize(a.envelope)), a.inclusion, ahead.rootHash);
        add("authorization log inclusion proof", included, `leaf ${a.inclusion.leafIndex} of ${a.inclusion.treeSize}`);
        const before = a.inclusion.leafIndex < bundle.inclusion.leafIndex && a.inclusion.treeSize <= bundle.inclusion.treeSize;
        add("authorization logged before execution", before, `authorization leaf ${a.inclusion.leafIndex}, receipt leaf ${bundle.inclusion.leafIndex}`);
      }
    }
  }
  const th = dsseVerify(bundle.treeHead, [...logKeys, ...opts.issuerKeys]);
  const byLog = th.ok && logKeys.some((k) => k.keyid === th.keyid);
  add("tree head signature", th.ok && bundle.treeHead.payloadType === TREEHEAD_TYPE, th.ok ? `${byLog ? "log key" : "issuer key"} ${short(th.keyid)}` : th.error);
  if (th.ok) {
    const head = th.payload as TreeHead;
    if (opts.logId !== undefined) add("tree head names the expected log", head.log === opts.logId, head.log ? `log ${head.log}` : "tree head names no log");
    add("tree head matches inclusion proof size", head.treeSize === bundle.inclusion.treeSize);
    const included = verifyInclusion(leafHash(canonicalize(bundle.envelope)), bundle.inclusion, head.rootHash);
    add("log inclusion proof", included, `leaf ${bundle.inclusion.leafIndex} of ${bundle.inclusion.treeSize}, root ${short(head.rootHash)}`);
    if (opts.logFile) {
      let root = "";
      try {
        root = MerkleLog.rootFromFile(opts.logFile, head.treeSize);
      } catch (e) {
        add("log file root matches tree head", false, String(e instanceof Error ? e.message : e));
      }
      if (root) add("log file root matches tree head", root === head.rootHash, `recomputed ${short(root)}`);
    }
  }
  return done(st);
}

export interface AuditResult {
  ok: boolean;
  checks: Check[];
  older: TreeHead | null;
  newer: TreeHead | null;
}

/**
 * Does the newer tree head extend the older one? Both must be signed by a trusted log or issuer key, and the proof
 * must be the log's consistency proof between the two sizes. A pass means nothing in the older log was rewritten.
 */
export interface AuditOptions {
  /** with these, the newer head must also carry a signature by one of them: a witness that is not the log's operator */
  witnessKeys?: PublicKeyRef[];
}

export function auditExtends(older: Envelope, newer: Envelope, proof: string[], keys: PublicKeyRef[], logId?: string, opts: AuditOptions = {}): AuditResult {
  const checks: Check[] = [];
  const add = (name: string, ok: boolean, detail?: string) => {
    checks.push(detail === undefined ? { name, ok } : { name, ok, detail });
    return ok;
  };
  const decode = (label: string, env: Envelope): TreeHead | null => {
    const v = dsseVerify(env, keys);
    add(`${label} tree head signature`, v.ok && env.payloadType === TREEHEAD_TYPE, v.ok ? `keyid ${short(v.keyid)}` : v.error);
    return v.ok ? (v.payload as TreeHead) : null;
  };
  const a = decode("older", older);
  const b = decode("newer", newer);
  if (!a || !b) return { ok: false, checks, older: a, newer: b };
  if (logId !== undefined) add("both tree heads name the expected log", a.log === logId && b.log === logId, `expected ${logId}, got ${a.log ?? "none"} and ${b.log ?? "none"}`);
  else if (a.log !== b.log) add("both tree heads name the same log", false, `${a.log ?? "none"} and ${b.log ?? "none"}`);
  if (!add("older is not larger than newer", a.treeSize <= b.treeSize, `${a.treeSize} -> ${b.treeSize}`)) return { ok: false, checks, older: a, newer: b };
  const consistent = verifyConsistency(a.treeSize, a.rootHash, b.treeSize, b.rootHash, proof);
  add("newer log extends older log", consistent, consistent ? `${proof.length} proof hashes` : "history was rewritten, or the proof is for other tree heads");
  if (opts.witnessKeys && opts.witnessKeys.length > 0) {
    const by = dsseVerifiers(newer, opts.witnessKeys);
    add("newer tree head countersigned by a witness", by.length > 0, by.length ? `witness ${short(by[0]!)}` : "no witness signature on the newer head");
  }
  return { ok: checks.every((c) => c.ok), checks, older: a, newer: b };
}

const ISSUER_NOTE: Record<string, string> = {
  gateway: "enforced outside the agent's process; the agent could neither skip nor forge this receipt",
  sdk: "self-reported by the agent's own process; tamper-evident after issue, but nothing here was enforced outside the agent",
  guardian: "decided by an ACS Guardian outside the agent's process and signed with its own key, so the decision is attributable to it; the call is the agent's own report, and the agent could skip the Guardian or ignore its answer",
  egress: "observed by a forward proxy in the agent's network path, for a connection that went around the gateway: where it went and how much, never what was sent; the agent is known only by the proxy credential the witness checked, and a connection that skipped the proxy (no lockdown) leaves no receipt at all",
};

/** Human-readable report: checks, then every field with its provenance so the reader knows what was proven vs. claimed. */
export function formatReport(r: VerifyResult): string {
  const lines: string[] = [];
  for (const c of r.checks) lines.push(`${c.ok ? "PASS" : "FAIL"}  ${c.name}${c.detail ? `  (${c.detail})` : ""}`);
  lines.push("");
  lines.push(r.ok ? "RESULT: VERIFIED" : "RESULT: NOT VERIFIED");
  if (!r.statement) return lines.join("\n");
  const p = r.statement.predicate;
  lines.push("");
  lines.push(`ISSUER: ${p.issuer.kind}${p.issuer.framework ? ` (${p.issuer.framework})` : ""}${p.issuer.strict ? ", strict mode" : ""}, ${ISSUER_NOTE[p.issuer.kind] ?? "unknown issuer kind"}`);
  lines.push("");
  lines.push("field           provenance  value");
  const row = (f: string, prov: string, v: unknown) => lines.push(`${f.padEnd(15)} ${prov.padEnd(11)} ${typeof v === "string" ? v : JSON.stringify(v)}`);
  row("principal", p.principal.provenance, p.principal.id ?? "(none)");
  row("agent", p.agent.provenance, p.agent.id);
  const idText = (v: unknown) => (typeof v === "string" ? v : v === null || v === undefined ? "-" : "(withheld under the capture rule)");
  if (p.session.id || p.session.toolUseId) row("session", p.session.provenance, `${idText(p.session.id)} / ${idText(p.session.toolUseId)}`);
  row("model", p.model.provenance, p.model.id === null ? "(none supplied)" : idText(p.model.id));
  row("tool", p.tool.provenance, p.tool.name);
  row("args", p.request.provenance, p.request.args);
  for (const [k, f] of Object.entries(p.facts)) row(`fact.${k}`, f.provenance, f.value);
  if (p.reconciliation) row("policy", "-", "(none evaluated: a provider read, not a call)");
  else if (p.policy) row("policy", p.policy.provenance, `${p.policy.decision}${p.policy.enforced === false ? " (observe mode, not enforced)" : ""} [${p.policy.reasons.join(",")}] policy ${short(p.policy.policyDigest)}`);
  else row("policy", "-", "(none evaluated)");
  if (p.consumed) row("consumed", p.consumed.provenance, !Array.isArray(p.consumed.factIds) ? "(withheld under the capture rule)" : p.consumed.factIds.length === 0 ? "(no facts shown before this call)" : p.consumed.factIds);
  if (p.authorization) {
    const committed = r.checks.filter((c) => c.name.startsWith("authorization ")).every((c) => c.ok);
    row("authorization", "observed", committed ? `committed to the log as leaf ${p.authorization.inclusion.leafIndex}, before the call was forwarded` : "carried, but its checks FAILED");
  } else if (p.execution.status === "withheld" && p.issuer.kind !== "guardian") row("authorization", "observed", "the log would not commit it; the call was not forwarded");
  if (p.approval) row("approval", p.approval.provenance, `${p.approval.status}; ${p.approval.requiredApprovers} approver(s) required${p.approval.consumedAt ? `; consumed ${p.approval.consumedAt}` : ""}${typeof p.approval.reason === "string" ? `; ${p.approval.reason}` : ""}`);
  const upstreamCheck = r.checks.find((c) => c.name === "upstream signature (upstream key)" || c.name === "upstream signature (provider secret)");
  const hasUpstream = (p.execution.status === "executed" || p.execution.status === "failed") && !!p.execution.upstream;
  const byProvider = hasUpstream && isProviderAttestation((p.execution as { upstream?: unknown }).upstream);
  const attestedAs = upstreamCheck?.ok ? (byProvider ? "attested (shared secret)" : "attested") : p.execution.provenance;
  const note = !hasUpstream ? "" : upstreamCheck ? (upstreamCheck.ok ? ` (${byProvider ? upstreamCheck.detail : `signed by upstream ${upstreamCheck.detail}`})` : " (upstream signature FAILED)") : byProvider ? " (carries a provider delivery; pass the provider secret to check it)" : " (carries an upstream signature; pass --upstream-key to check it)";
  // a refusal says why, as the receipt records it; under a capture rule the reason is a commitment, and the report says so rather than printing it
  const reason = "reason" in p.execution ? p.execution.reason : undefined;
  const why = reason === undefined ? "" : typeof reason === "string" ? `: ${reason}` : ": (reason withheld under the capture rule)";
  row("execution", attestedAs, `${p.reconciliation ? "provider read, " : ""}${p.execution.status}${why}${note}`);
  return lines.join("\n");
}
