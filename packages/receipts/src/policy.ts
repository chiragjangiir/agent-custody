// Cedar policy evaluation. Fails closed: any evaluation error is a deny.
import * as cedar from "@cedar-policy/cedar-wasm/nodejs";
import { sha256Hex } from "./crypto.ts";

export interface PolicyDecision {
  decision: "allow" | "deny";
  /** ids of policies that determined the decision */
  reasons: string[];
  /** evaluation errors; non-empty always yields deny */
  errors: string[];
  policyDigest: string;
  /** false when the issuer ran in observe mode: the decision was recorded but a deny was not enforced. Absent means enforced. */
  enforced?: boolean;
}

export interface PolicyRequest {
  agentId: string;
  tool: string;
  /** Cedar context. Numbers must be integers; Cedar has no floats. */
  context: Record<string, unknown>;
}

/** True when the policy set contains a permit rule. Cedar answers, so a `permit(` in a comment does not count. */
export function hasPermitRule(policyText: string): boolean {
  const parts = cedar.policySetTextToParts(policyText);
  if (parts.type !== "success") return false;
  return parts.policies.some((p) => {
    const j = cedar.policyToJson(p);
    return j.type === "success" && j.json.effect === "permit";
  });
}

/** Why Cedar cannot parse the policy set, or an empty list when it can. */
export function policyParseErrors(policyText: string): string[] {
  const parsed = cedar.checkParsePolicySet({ staticPolicies: policyText });
  return parsed.type === "success" ? [] : parsed.errors.map((e) => e.message);
}

/** The text of each static policy, in file order. Cedar names them `policy0`, `policy1`, and so on in this order. */
export function policyRules(policyText: string): string[] {
  const parts = cedar.policySetTextToParts(policyText);
  return parts.type === "success" ? parts.policies : [];
}

/** The `@reason("...")` annotation of each static policy, in file order, or null for a policy without one. */
export function policyReasons(policyText: string): (string | null)[] {
  return policyRules(policyText).map((rule) => {
    const j = cedar.policyToJson(rule);
    const reason = j.type === "success" ? j.json.annotations?.reason : undefined;
    return typeof reason === "string" && reason.trim() ? reason.trim() : null;
  });
}

/** The reason of the policy that a Cedar id such as `policy3` names: its `@reason` text, or the id when it has none. */
export function reasonOfRule(id: string, reasons: readonly (string | null)[]): string {
  return reasons[Number(id.replace(/^policy/, ""))] ?? id;
}

export function policyDigest(policyText: string): string {
  return sha256Hex(policyText);
}

/**
 * Cedar's JSON context reads `{ "__entity": … }` and `{ "__extn": … }` as typed values. Arguments come from the agent,
 * so an argument shaped that way could satisfy a policy comparing it to an entity, an address, or a decimal by its
 * shape rather than by anything the gateway observed. Arguments are data: the first such form found is the path
 * returned, and the evaluation is a deny with that error.
 */
export function reservedCedarForm(value: unknown, path = "args"): string | null {
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const hit = reservedCedarForm(value[i], `${path}[${i}]`);
      if (hit) return hit;
    }
    return null;
  }
  if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (k === "__entity" || k === "__extn") return `${path}.${k}`;
      const hit = reservedCedarForm(v, `${path}.${k}`);
      if (hit) return hit;
    }
  }
  return null;
}

interface ParsedPolicy {
  /** the id the policy set is preparsed under in cedar-wasm; unused when parseErrors is non-empty */
  slot: string;
  digest: string;
  parseErrors: string[];
}

/** Policy sets kept parsed, most recently used last. A reload or a second gateway in the process takes another slot. */
const PARSED_SLOTS = 8;
const parsed = new Map<string, ParsedPolicy>();
/** Slot ids that no live entry holds. At most PARSED_SLOTS + 1 ids are ever made. */
const freeSlots: string[] = [];
let slotsMade = 0;

/**
 * The policy set parsed once per text, so a decision no longer parses the whole file. Keyed by the text itself: an
 * edited file is a new key, a new parse, and a new digest. A new text takes a slot that no live entry holds, and the
 * least recently used entry is evicted, and its slot freed, only once the new entry is in place: a preparse that throws
 * or fails never changes the set a live entry decides with. Reusing a freed id replaces the set held in cedar-wasm, so
 * neither side grows past PARSED_SLOTS + 1. A failed preparse leaves the slot's previous set in place, so an entry with
 * parse errors must never be evaluated.
 */
function parsedPolicy(policyText: string): ParsedPolicy {
  const hit = parsed.get(policyText);
  if (hit) {
    parsed.delete(policyText);
    parsed.set(policyText, hit);
    return hit;
  }
  const digest = policyDigest(policyText);
  const slot = freeSlots.pop() ?? `agent-custody-policy-${slotsMade++}`;
  let answer: ReturnType<typeof cedar.preparsePolicySet>;
  try {
    answer = cedar.preparsePolicySet(slot, { staticPolicies: policyText });
  } catch (e) {
    freeSlots.push(slot);
    throw e;
  }
  const entry = { slot, digest, parseErrors: answer.type === "success" ? [] : answer.errors.map((e) => e.message) };
  parsed.set(policyText, entry);
  if (parsed.size > PARSED_SLOTS) {
    const [oldest, evicted] = parsed.entries().next().value!;
    parsed.delete(oldest);
    freeSlots.push(evicted.slot);
  }
  return entry;
}

export function evaluate(policyText: string, req: PolicyRequest): PolicyDecision {
  const policy = parsedPolicy(policyText);
  const digest = policy.digest;
  const reserved = reservedCedarForm(req.context.args);
  if (reserved) return { decision: "deny", reasons: [], errors: [`argument ${reserved} uses a reserved Cedar form; arguments are data, never entities or extension values`], policyDigest: digest };
  if (policy.parseErrors.length > 0) return { decision: "deny", reasons: [], errors: [...policy.parseErrors], policyDigest: digest };
  const answer = cedar.statefulIsAuthorized({
    principal: { type: "Agent", id: req.agentId },
    action: { type: "Action", id: req.tool },
    resource: { type: "Tool", id: req.tool },
    context: req.context as cedar.Context,
    preparsedPolicySetId: policy.slot,
    entities: [],
  });
  if (answer.type === "failure") {
    return { decision: "deny", reasons: [], errors: answer.errors.map((e) => e.message), policyDigest: digest };
  }
  const { decision, diagnostics } = answer.response;
  const errors = diagnostics.errors.map((e) => `${e.policyId}: ${e.error.message}`);
  return {
    decision: errors.length > 0 ? "deny" : decision,
    reasons: diagnostics.reason,
    errors,
    policyDigest: digest,
  };
}
