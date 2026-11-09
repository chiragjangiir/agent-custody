import * as cedar from "@cedar-policy/cedar-wasm/nodejs";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { evaluate, policyDigest, type PolicyRequest } from "../src/policy.ts";
import { POLICY } from "../scripts/fixture.ts";

const req = (tool: string, args: Record<string, unknown>, facts: Record<string, unknown> = {}) => ({
  agentId: "support-agent",
  tool,
  context: { args, facts, grant: { principal: "user_456", scopes: ["customer.lookup", "stripe.refund"] } },
});

describe("Cedar policy", () => {
  it("permits a refund under the limit for a verified customer", () => {
    const d = evaluate(POLICY, req("stripe.refund", { customer_id: "cust_123", amount: 50000 }, { customer: { verified: true } }));
    expect(d.decision).toBe("allow");
    expect(d.reasons.length).toBe(1);
    expect(d.errors).toEqual([]);
  });

  it("denies a refund over the limit", () => {
    expect(evaluate(POLICY, req("stripe.refund", { customer_id: "cust_123", amount: 100001 }, { customer: { verified: true } })).decision).toBe("deny");
  });

  it("denies when the verified fact is absent, so the agent cannot assert it via args", () => {
    const d = evaluate(POLICY, req("stripe.refund", { customer_id: "cust_123", amount: 1, customer: { verified: true } }));
    expect(d.decision).toBe("deny");
  });

  it("fails closed on evaluation errors such as a float amount, and reports them", () => {
    const d = evaluate(POLICY, req("stripe.refund", { customer_id: "cust_123", amount: 12.5 }, { customer: { verified: true } }));
    expect(d.decision).toBe("deny");
    expect(d.errors.length).toBeGreaterThan(0);
  });

  it("digest changes when the policy text changes, so receipts pin the exact policy", () => {
    expect(policyDigest(POLICY)).not.toBe(policyDigest(POLICY + "\n"));
    expect(evaluate(POLICY, req("customer.lookup", {})).policyDigest).toBe(policyDigest(POLICY));
  });
});

// evaluate() keeps each policy text parsed. A decision must still come from the exact text it was given: a cached
// parse of an older file, or of an evicted policy, would allow under a policy that denies and sign the new digest beside it.
describe("Cedar policy kept parsed", () => {
  const refund = (amount: number) => req("stripe.refund", { customer_id: "cust_123", amount }, { customer: { verified: true } });
  const capped = (limit: number) => `permit(principal, action == Action::"stripe.refund", resource) when { context.args.amount <= ${limit} };`;

  it("a policy file that is edited is parsed again: the next decision and digest are the new file's", () => {
    const file = join(mkdtempSync(join(tmpdir(), "policy-")), "policy.cedar");
    writeFileSync(file, POLICY);
    expect(evaluate(readFileSync(file, "utf8"), refund(50000)).decision).toBe("allow");
    const tightened = POLICY.replaceAll("100000", "10000");
    writeFileSync(file, tightened);
    const d = evaluate(readFileSync(file, "utf8"), refund(50000));
    expect(d.decision).toBe("deny");
    expect(d.policyDigest).toBe(policyDigest(tightened));
    writeFileSync(file, POLICY);
    const back = evaluate(readFileSync(file, "utf8"), refund(50000));
    expect([back.decision, back.policyDigest]).toEqual(["allow", policyDigest(POLICY)]);
  });

  it("many policies in turn: each decision is its own policy's, including policies the cache let go and parsed again", () => {
    const limits = Array.from({ length: 20 }, (_, i) => (i + 1) * 1000);
    for (const round of [limits, [...limits].reverse(), limits.filter((_, i) => i % 3 === 0)]) {
      for (const limit of round) {
        expect(evaluate(capped(limit), refund(limit)).decision).toBe("allow");
        const over = evaluate(capped(limit), refund(limit + 1));
        expect([over.decision, over.policyDigest]).toEqual(["deny", policyDigest(capped(limit))]);
      }
    }
  });

  it("a policy that does not parse is a deny with Cedar's errors, even when it takes the place of one that allows", () => {
    for (let i = 0; i < 20; i++) expect(evaluate(capped(1_000_000 + i), refund(1)).decision).toBe("allow");
    const broken = `${capped(1_000_000)}\npermit(principal, action, resource) when { context.args.amount <= };`;
    for (let i = 0; i < 2; i++) {
      const d = evaluate(broken, refund(1));
      expect(d.decision).toBe("deny");
      expect(d.errors.join("\n")).toMatch(/failed to parse policies/);
      expect(d.policyDigest).toBe(policyDigest(broken));
    }
  });

  it("decides exactly as Cedar does when it parses the text on every call", () => {
    const direct = (text: string, r: PolicyRequest) => cedar.isAuthorized({ principal: { type: "Agent", id: r.agentId }, action: { type: "Action", id: r.tool }, resource: { type: "Tool", id: r.tool }, context: r.context as cedar.Context, policies: { staticPolicies: text }, entities: [] });
    const requests = [refund(1), refund(100000), refund(100001), refund(12.5), req("stripe.refund", { amount: "1" }, { customer: { verified: true } }), req("customer.lookup", {}), req("stripe.refund", { amount: 1 })];
    for (const r of requests) {
      const d = evaluate(POLICY, r);
      const answer = direct(POLICY, r);
      if (answer.type === "failure") expect(d).toEqual({ decision: "deny", reasons: [], errors: answer.errors.map((e) => e.message), policyDigest: policyDigest(POLICY) });
      else expect([d.decision, d.reasons, d.errors.length > 0]).toEqual([answer.response.diagnostics.errors.length > 0 ? "deny" : answer.response.decision, answer.response.diagnostics.reason, answer.response.diagnostics.errors.length > 0]);
    }
  });
});
