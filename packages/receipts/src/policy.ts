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

export function evaluate(policyText: string, req: PolicyRequest): PolicyDecision {
  const digest = policyDigest(policyText);
  const reserved = reservedCedarForm(req.context.args);
  if (reserved) return { decision: "deny", reasons: [], errors: [`argument ${reserved} uses a reserved Cedar form; arguments are data, never entities or extension values`], policyDigest: digest };
  const answer = cedar.isAuthorized({
    principal: { type: "Agent", id: req.agentId },
    action: { type: "Action", id: req.tool },
    resource: { type: "Tool", id: req.tool },
    context: req.context as cedar.Context,
    policies: { staticPolicies: policyText },
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
