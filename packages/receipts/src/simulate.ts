// Offline policy replay. The recorded inputs stay fixed; no tool or fact provider is called.
import { randomUUID } from "node:crypto";
import * as cedar from "@cedar-policy/cedar-wasm/nodejs";
import { isCommitment, pathText, restorePaths, under } from "./capture.ts";
import { canonicalize, dsseVerify, type PublicKeyRef } from "./crypto.ts";
import { decodeDelegation, DELEGATION_TYPE, delegationValidAt } from "./delegation.ts";
import { leafHash, verifyInclusion } from "./log.ts";
import { evaluate, policyDigest, type PolicyDecision } from "./policy.ts";
import { compileRego, evaluateRego } from "./policy-rego.ts";
import { AUTHORIZATION_PREDICATE_TYPE, RECEIPT_TYPE, TREEHEAD_TYPE, type AuthorizationBundle, type AuthorizationStatement, type ReceiptPredicate, type TreeHead } from "./receipt.ts";
import { structuralProblem } from "./verify.ts";

export interface SimulationChange {
  receiptId: string;
  tool: string;
  /** The recorded Cedar decision, including observe-mode and provenance information. */
  previous: NonNullable<ReceiptPredicate["policy"]>;
  proposed: PolicyDecision;
}

export interface SimulationSkip {
  receiptId: string;
  tool: string;
  reason: string;
}

export interface SimulationGroup {
  tool: string;
  /** The proposed policy's determining policy ids and evaluation errors. */
  reason: string;
  receiptIds: string[];
}

export interface SimulationReport {
  runId: string;
  timestamp: string;
  policyDigest: string;
  previousPolicyDigests: string[];
  total: number;
  evaluated: number;
  unchanged: number;
  /** Reconciliation receipts. Each is a provider read with no policy decision, so a replay counts it here and not in `evaluated` or `skipped`. */
  reconciliations: number;
  complete: boolean;
  changes: SimulationChange[];
  skipped: SimulationSkip[];
  /** Changed decisions, grouped by tool and the proposed reason. */
  groups: SimulationGroup[];
}

export interface SimulationOptions {
  /** The customer's capture key. It decrypts the withheld values that were encrypted under it. */
  captureKey?: Buffer;
  /** Disclosure files by receipt id, as `agent-custody reveal` writes them. A disclosure applies only to its own receipt. */
  disclosures?: ReadonlyMap<string, unknown>;
  /** Calls that have no receipt to replay. Each counts in `total` and is reported as skipped. */
  unreplayable?: SimulationSkip[];
  /** The proposed policy's language. Rego is compiled once with the opa binary on PATH. Default cedar. */
  language?: "cedar" | "rego";
}

const strings = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string");
const order = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;

/** A gateway can deny before Cedar runs. Such a denial cannot be changed by replacing Cedar text. */
function gateProblem(p: ReceiptPredicate): string | null {
  if (p.issuer.kind !== "gateway") return null;
  // The approval gate runs before Cedar and records its refusal as a deny. The approval record, which stays in clear
  // under a private rule, says so. A later approval refusal beside an allow, or beside an unenforced deny, means that
  // Cedar did run.
  if (p.policy?.decision === "deny" && p.policy.enforced !== false && p.approval?.status === "denied") return "non-policy gate: the approval was refused before Cedar ran";
  // A failed gatherFacts never assigns its partial result to the receipt. With private errors, no facts, and no
  // determining policy ids, an evaluation error and missing lookup inputs are indistinguishable. Observe mode may
  // even have executed this call, so execution status cannot establish whether Cedar ran.
  if (p.policy?.decision === "deny" && isCommitment(p.policy.errors) && Object.keys(p.facts).length === 0 && p.policy.reasons.length === 0) {
    return "original failure details are withheld; cannot establish complete Cedar inputs";
  }
  // The decision is the baseline. A grant revoked after Cedar ran can withhold execution, but does not invalidate
  // the recorded policy inputs or turn that allow into an early gate denial.
  const messages = Array.isArray(p.policy?.errors) ? p.policy.errors : [];
  const gate = messages.find((s) => /^delegation grant /s.test(s)
    || /^tool ".*" is not in the delegation scopes$/s.test(s)
    || /^fact argument ".*" needs call argument ".*", which is missing$/s.test(s)
    || /^fact ".*" lookup via .* failed:/s.test(s));
  return gate ? `non-policy gate: ${gate}` : null;
}

/**
 * Check an authorization bundle that has no receipt, as the verifier does for an embedded one: the issuer signed it, it
 * is an authorization statement, and its leaf is in the log under a signed tree head. Throws when a check fails.
 * Returns the statement's predicate.
 */
export function verifyOrphanAuthorization(bundle: AuthorizationBundle, issuerKeys: PublicKeyRef[], logKeys: PublicKeyRef[]): AuthorizationStatement["predicate"] {
  const signed = dsseVerify(bundle.envelope, issuerKeys);
  if (!signed.ok) throw new Error(`authorization signature (issuer key) (${signed.error})`);
  const statement = signed.payload as AuthorizationStatement;
  if (bundle.envelope.payloadType !== RECEIPT_TYPE || statement.predicateType !== AUTHORIZATION_PREDICATE_TYPE) throw new Error("authorization payload type");
  const head = dsseVerify(bundle.treeHead, [...logKeys, ...issuerKeys]);
  if (!head.ok || bundle.treeHead.payloadType !== TREEHEAD_TYPE) throw new Error(`authorization tree head signature${head.ok ? "" : ` (${head.error})`}`);
  const tree = head.payload as TreeHead;
  if (tree.treeSize !== bundle.inclusion.treeSize || !verifyInclusion(leafHash(canonicalize(bundle.envelope)), bundle.inclusion, tree.rootHash)) throw new Error("authorization log inclusion proof");
  return statement.predicate;
}

/**
 * Compare a proposed Cedar or Rego policy with recorded policy decisions, using each receipt's original arguments, fact
 * values, agent, and (for gateways) grant context. Observe-mode decisions are the baseline even when the call ran.
 * Receipts are not signature-verified here; verify their bundles separately when their authenticity matters. A
 * reconciliation receipt is trusted as a provider read only after `verifyBundle` accepts it: the library checks no more
 * than its shape and its link to an original receipt id.
 * A reconciliation whose original receipt is not among the supplied receipts or `unreplayable` is reported as skipped,
 * because the call it settles cannot be replayed.
 * Missing inputs and non-Cedar gate failures are reported as skipped, never guessed or fetched again.
 * The receipts are read once, one at a time, so a caller can verify and parse a large history lazily.
 */
export function simulatePolicy(policyText: string, receipts: Iterable<ReceiptPredicate>, options: SimulationOptions = {}): SimulationReport {
  const rego = options.language === "rego" ? compileRego(policyText) : undefined;
  if (rego && !rego.policy) throw new Error(`invalid Rego policy: ${rego.errors.join("; ")}`);
  if (!rego) {
    const parsed = cedar.checkParsePolicySet({ staticPolicies: policyText });
    if (parsed.type === "failure") throw new Error(`invalid Cedar policy: ${parsed.errors.map((e) => e.message).join("; ")}`);
  }
  const unreplayable = options.unreplayable ?? [];
  const report: SimulationReport = {
    runId: randomUUID(),
    timestamp: new Date().toISOString(),
    policyDigest: policyDigest(policyText),
    previousPolicyDigests: [],
    total: unreplayable.length,
    evaluated: 0,
    unchanged: 0,
    reconciliations: 0,
    complete: true,
    changes: [],
    skipped: [...unreplayable],
    groups: [],
  };
  const digests = new Set<string>();
  const seen = new Set(unreplayable.map((u) => u.receiptId));
  const reconciled: SimulationSkip[] = [];
  for (const original of receipts) {
    report.total++;
    const receiptId = typeof original?.receiptId === "string" ? original.receiptId : "(unknown receipt)";
    const tool = typeof original?.tool?.name === "string" ? original.tool.name : "(unknown tool)";
    const skip = (reason: string) => { report.skipped.push({ receiptId, tool, reason }); };
    if (original?.reconciliation === undefined) seen.add(receiptId);
    const broken = structuralProblem(original);
    if (broken) { skip(`malformed receipt: ${broken}`); continue; }
    if (original.reconciliation !== undefined) {
      const link = original.operation?.originalReceiptId;
      if (original.issuer.kind !== "gateway" || typeof link !== "string" || link === receiptId) {
        skip("malformed receipt: a reconciliation needs a gateway issuer and an operation that names another receipt"); continue;
      }
      report.reconciliations++;
      reconciled.push({ receiptId: link, tool, reason: `only the reconciliation ${receiptId} survives; the original receipt is missing, so the call cannot be replayed` });
      continue;
    }
    if (original.policy === null) { skip("no recorded policy decision (record-only receipt)"); continue; }
    const previous = original.policy;
    if (typeof previous.policyDigest !== "string" || !previous.policyDigest || !strings(previous.reasons)
      || (!strings(previous.errors) && !(isCommitment(previous.errors) && original.capture?.withheld.some((p) => p.length === 2 && p[0] === "policy" && p[1] === "errors")))
      || (previous.enforced !== undefined && typeof previous.enforced !== "boolean")) {
      skip("malformed receipt: recorded policy metadata is invalid"); continue;
    }
    digests.add(previous.policyDigest);
    if (!receiptId || !tool || typeof original.agent.id !== "string" || !original.agent.id
      || !Number.isFinite(Date.parse(original.timestamp)) || !["sdk", "gateway"].includes(original.issuer.kind)) {
      skip("malformed receipt: receipt id, tool, agent, timestamp, or issuer is invalid"); continue;
    }
    const restored = restorePaths(original, original.capture, options.disclosures?.get(receiptId), options.captureKey);
    if (restored.problems.length) {
      skip(`malformed capture: ${restored.problems.map((p) => p.error).join("; ")}`); continue;
    }
    const missing = restored.missing.filter((p) => under(p, ["request", "args"]) || (p[0] === "facts" && p[2] === "value"));
    if (missing.length) { skip(`required policy inputs are withheld: ${missing.map(pathText).join(", ")}`); continue; }
    const p = restored.predicate;
    if (tool === "(unknown tool)" && p.issuer.kind === "gateway" && p.capture) {
      skip("the original tool name is unavailable under the capture rule"); continue;
    }
    if (Object.values(p.facts).some((f) => !Object.hasOwn(f, "value") || f.value === undefined)) {
      skip("malformed receipt: a recorded fact has no value"); continue;
    }
    const gate = gateProblem(p);
    if (gate) { skip(gate); continue; }
    const context: Record<string, unknown> = {
      args: p.request.args,
      facts: Object.fromEntries(Object.entries(p.facts).map(([name, fact]) => [name, fact.value])),
    };
    if (p.issuer.kind === "gateway") {
      const envelope = p.delegation?.envelope;
      const grant = envelope?.payloadType === DELEGATION_TYPE ? decodeDelegation(envelope) : null;
      if (!grant || grant.agent !== p.agent.id || grant.principal !== p.principal.id) {
        skip("the recorded delegation context is missing, malformed, or does not name this agent and principal"); continue;
      }
      if (!grant.scopes.includes(tool)) { skip("the tool is outside the recorded delegation scopes"); continue; }
      if (!delegationValidAt(grant, p.timestamp)) { skip("the recorded delegation was outside its validity window at receipt time"); continue; }
      context.grant = { principal: grant.principal, scopes: grant.scopes };
    }
    let proposed: PolicyDecision;
    try {
      const request = { agentId: p.agent.id, tool, context };
      proposed = rego?.policy ? evaluateRego(rego.policy, report.policyDigest, request) : evaluate(policyText, request);
    } catch (e) {
      // An evaluator exception is a deny, just as at the gateway; it must never become an allow in a replay.
      proposed = { decision: "deny", reasons: [], errors: [e instanceof Error ? e.message : String(e)], policyDigest: report.policyDigest };
    }
    report.evaluated++;
    if (proposed.decision === previous.decision) report.unchanged++;
    else report.changes.push({ receiptId, tool, previous, proposed });
  }
  for (const lost of reconciled) {
    if (seen.has(lost.receiptId)) continue;
    report.reconciliations--;
    report.skipped.push(lost);
  }
  report.previousPolicyDigests = [...digests].sort(order);
  report.complete = report.skipped.length === 0;
  const groups = new Map<string, SimulationGroup>();
  for (const change of report.changes) {
    const reason = [...new Set([...change.proposed.reasons, ...change.proposed.errors])].sort(order).join("; ") || "no permit policy matched";
    const key = JSON.stringify([change.tool, reason]);
    const group = groups.get(key) ?? { tool: change.tool, reason, receiptIds: [] };
    group.receiptIds.push(change.receiptId);
    groups.set(key, group);
  }
  report.groups = [...groups.values()].sort((a, b) => order(a.tool, b.tool) || order(a.reason, b.reason));
  for (const group of report.groups) group.receiptIds.sort(order);
  return report;
}

export function formatSimulation(report: SimulationReport): string {
  const changes = new Map(report.changes.map((c) => [JSON.stringify([c.tool, c.receiptId]), c]));
  const lines = [
    `Policy simulation ${report.runId}`,
    `Timestamp: ${report.timestamp}`,
    `Proposed policy: ${report.policyDigest}`,
    `Previous policies: ${report.previousPolicyDigests.join(", ") || "none"}`,
    `Receipts: ${report.total}; evaluated: ${report.evaluated}; unchanged: ${report.unchanged}; reconciliations: ${report.reconciliations}; changed: ${report.changes.length}; skipped: ${report.skipped.length}`,
  ];
  for (const group of report.groups) {
    lines.push("", `${group.tool}: ${group.reason}`);
    for (const receiptId of group.receiptIds) {
      const change = changes.get(JSON.stringify([group.tool, receiptId]))!;
      lines.push(`  ${receiptId}: ${change.previous.decision} -> ${change.proposed.decision}`);
    }
  }
  for (const skipped of report.skipped) lines.push(`SKIPPED ${skipped.receiptId} (${skipped.tool}): ${skipped.reason}`);
  lines.push("", report.complete ? "RESULT: COMPLETE" : "RESULT: INCOMPLETE");
  return lines.join("\n");
}
