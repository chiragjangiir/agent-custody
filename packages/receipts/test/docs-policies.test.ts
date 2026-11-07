// Every ```cedar block in docs/policies.md must parse, and the behaviour the prose promises must hold.
// Blocks are addressed by position, so editing the doc without updating this test fails loudly.
import { readFileSync } from "node:fs";
import * as cedar from "@cedar-policy/cedar-wasm/nodejs";
import { describe, expect, it } from "vitest";
import { evaluate, policyReasons } from "../src/policy.ts";
import { compileRego, evaluateRego } from "../src/policy-rego.ts";

const doc = readFileSync(new URL("../docs/policies.md", import.meta.url), "utf8");
const blocks = [...doc.matchAll(/```cedar\n([\s\S]*?)```/g)].map((m) => m[1]!);

const grant = { principal: "user_456", scopes: ["customer.lookup", "stripe.refund", "github.merge"] };
const req = (tool: string, args: Record<string, unknown>, facts: Record<string, unknown> = {}, agentId = "support-agent") => ({
  agentId,
  tool,
  context: { args, facts, grant },
});
const decide = (i: number, r: ReturnType<typeof req>) => evaluate(blocks[i]!, r).decision;

describe("docs/policies.md examples", () => {
  it("contains the expected number of examples", () => {
    expect(blocks.length).toBe(16);
  });

  it("every block parses as a Cedar policy set", () => {
    for (const [i, b] of blocks.entries()) {
      const r = cedar.checkParsePolicySet({ staticPolicies: b });
      expect(r.type, `block ${i}:\n${b}`).toBe("success");
    }
  });

  it("0: read permitted, anything else denied by default", () => {
    expect(decide(0, req("customer.lookup", {}))).toBe("allow");
    expect(decide(0, req("stripe.refund", { amount: 1 }))).toBe("deny");
  });

  it("1: amount cap, and a missing amount is an error hence deny", () => {
    expect(decide(1, req("stripe.refund", { amount: 100000 }))).toBe("allow");
    expect(decide(1, req("stripe.refund", { amount: 100001 }))).toBe("deny");
    const d = evaluate(blocks[1]!, req("stripe.refund", {}));
    expect(d.decision).toBe("deny");
    expect(d.errors[0]).toMatch(/amount/);
  });

  it("2: requires the gateway-observed fact; agent-asserted args do nothing", () => {
    expect(decide(2, req("stripe.refund", { amount: 1 }, { customer: { verified: true } }))).toBe("allow");
    expect(decide(2, req("stripe.refund", { amount: 1, verified: true }))).toBe("deny");
    expect(decide(2, req("stripe.refund", { amount: 1 }, { customer: { verified: false } }))).toBe("deny");
  });

  it("3: named agent only", () => {
    expect(decide(3, req("stripe.refund", {}))).toBe("allow");
    expect(decide(3, req("stripe.refund", {}, {}, "other-agent"))).toBe("deny");
  });

  it("4: action set", () => {
    expect(decide(4, req("customer.lookup", {}))).toBe("allow");
    expect(decide(4, req("stripe.refund", {}))).toBe("deny");
  });

  it("5: forbid overrides permit", () => {
    expect(decide(5, req("stripe.refund", { amount: 1 }, { customer: { flagged: false } }))).toBe("allow");
    expect(decide(5, req("stripe.refund", { amount: 1 }, { customer: { flagged: true } }))).toBe("deny");
  });

  it("6: like pattern on a string argument", () => {
    expect(decide(6, req("github.merge", { repo: "acme/api", base: "main" }))).toBe("allow");
    expect(decide(6, req("github.merge", { repo: "evil/api", base: "main" }))).toBe("deny");
    expect(decide(6, req("github.merge", { repo: "acme/api", base: "dev" }))).toBe("deny");
  });

  it("7: unless clause", () => {
    expect(decide(7, req("stripe.refund", { currency: "GBP" }))).toBe("allow");
    expect(decide(7, req("stripe.refund", { currency: "USD" }))).toBe("deny");
  });

  it("9: memory confined to a space", () => {
    expect(decide(9, req("memory.read", { subject: "acct:1" }))).toBe("allow");
    expect(decide(9, req("memory.write", { subject: "acct:1", predicate: "p", value: 1, space: "team:support" }))).toBe("allow");
    expect(decide(9, req("memory.write", { subject: "acct:1", predicate: "p", value: 1, space: "org" }))).toBe("deny");
  });
  it("10: quarantine stays closed except to the reviewer", () => {
    expect(decide(10, req("memory.read", { subject: "acct:1" }))).toBe("allow");
    expect(decide(10, req("memory.read", { subject: "acct:1", includeClaimed: true }))).toBe("deny");
    expect(decide(10, req("memory.read", { subject: "acct:1", includeClaimed: true }, {}, "reviewer"))).toBe("allow");
    expect(decide(10, req("memory.confirm", { factId: "f" }))).toBe("deny");
    expect(decide(10, req("memory.confirm", { factId: "f" }, {}, "reviewer"))).toBe("allow");
  });
  it("11: org writes need evidence", () => {
    expect(decide(11, req("memory.write", { space: "team:support", subject: "s", predicate: "p", value: 1 }))).toBe("allow");
    expect(decide(11, req("memory.write", { space: "org", subject: "s", predicate: "p", value: 1 }))).toBe("deny");
    expect(decide(11, req("memory.write", { space: "org", subject: "s", predicate: "p", value: 1, evidence: { fact: "customer" } }))).toBe("allow");
  });
  it("12: attested org facts cannot be displaced or retracted; claimed ones can", () => {
    expect(decide(12, req("memory.write", { space: "org", supersedes: "f" }, { target: { space: "org", provenance: "attested", actor: "finance" } }))).toBe("deny");
    expect(decide(12, req("memory.write", { space: "org", supersedes: "f" }, { target: { space: "org", provenance: "claimed", actor: "bot" } }))).toBe("allow");
    expect(decide(12, req("memory.retract", { factId: "f", reason: "x" }, { target: { space: "org", provenance: "attested", actor: "finance" } }))).toBe("deny");
    expect(decide(12, req("memory.write", { space: "org", subject: "s", predicate: "p", value: 1 }))).toBe("allow");
  });
  it("13: erasure and holds only for named roles", () => {
    expect(decide(13, req("memory.forget", { factId: "f", reason: "r" }))).toBe("deny");
    expect(decide(13, req("memory.forget", { factId: "f", reason: "r" }, {}, "privacy-officer"))).toBe("allow");
    expect(decide(13, req("memory.sweep", { before: "2026-01-01T00:00:00Z", reason: "r" }, {}, "privacy-officer"))).toBe("allow");
    expect(decide(13, req("memory.hold", { factId: "f", reason: "r" }, {}, "legal"))).toBe("allow");
    expect(decide(13, req("memory.hold", { factId: "f", reason: "r" }, {}, "privacy-officer"))).toBe("deny");
  });
  it("14: the complete support-agent policy", () => {
    expect(decide(14, req("memory.read", { subject: "s" }))).toBe("allow");
    expect(decide(14, req("memory.read", { subject: "s", includeClaimed: true }))).toBe("deny");
    expect(decide(14, req("memory.write", { space: "team:support", subject: "s", predicate: "p", value: 1 }))).toBe("allow");
    expect(decide(14, req("memory.write", { space: "org", subject: "s", predicate: "p", value: 1 }))).toBe("deny");
    expect(decide(14, req("memory.write", { space: "org", subject: "s", predicate: "p", value: 1, evidence: { fact: "customer", path: "email" } }))).toBe("allow");
    expect(decide(14, req("memory.retract", { factId: "f", reason: "r" }, { target: { space: "team:support", provenance: "claimed", actor: "bot" } }))).toBe("allow");
    expect(decide(14, req("memory.retract", { factId: "f", reason: "r" }, { target: { space: "team:support", provenance: "attested", actor: "me" } }))).toBe("deny");
    expect(decide(14, req("memory.forget", { factId: "f", reason: "r" }))).toBe("deny");
    expect(decide(14, req("memory.hold", { factId: "f", reason: "r" }))).toBe("deny");
  });
  it("15: a rule carries its @reason, and the annotation does not change the decision or the rule id", () => {
    expect(policyReasons(blocks[15]!)).toEqual(["force push rewrites shared history"]);
    const forced = evaluate(blocks[15]!, req("Bash", { command: "git push --force origin main" }));
    expect(forced).toMatchObject({ decision: "deny", reasons: ["policy0"], errors: [] });
    expect(evaluate(blocks[15]!, req("Bash", { command: "ls" })).reasons).toEqual([]);
  });
  it("8: grant is reachable from context", () => {
    expect(decide(8, req("stripe.refund", {}))).toBe("allow");
    expect(evaluate(blocks[8]!, { ...req("stripe.refund", {}), context: { args: {}, facts: {}, grant: { ...grant, principal: "someone-else" } } }).decision).toBe("deny");
  });

  it("the Rego example compiles and keeps the promises its prose makes", () => {
    const rego = [...doc.matchAll(/```rego\n([\s\S]*?)```/g)].map((m) => m[1]!);
    expect(rego.length).toBe(1);
    const { policy, errors } = compileRego(rego[0]!);
    expect(errors).toEqual([]);
    const d = (r: ReturnType<typeof req>) => evaluateRego(policy!, "d", r);
    expect(d(req("customer.lookup", {})).decision).toBe("allow");
    expect(d(req("stripe.refund", { amount: 100000 }, { customer: { verified: true } })).decision).toBe("allow");
    expect(d(req("stripe.refund", { amount: 100001 }, { customer: { verified: true } })).decision).toBe("deny");
    // a whole number of pence above 0: Rego has floats and negatives, and <= alone admits both
    for (const amount of [0, -1, 0.5, 99999.5, "500"]) expect(d(req("stripe.refund", { amount }, { customer: { verified: true } })).decision, String(amount)).toBe("deny");
    expect(d(req("stripe.refund", { amount: 1 }, { customer: { verified: true } })).decision).toBe("allow");
    // a missing attribute is undefined, so the rule does not hold: a deny without an error
    expect(d(req("stripe.refund", {}, { customer: { verified: true } }))).toMatchObject({ decision: "deny", errors: [] });
    // the agent's own claim of verification is not the gateway's fact
    expect(d(req("stripe.refund", { amount: 1, customer: { verified: true } })).decision).toBe("deny");
    // deny wins over allow, with its string as the reason
    expect(d(req("stripe.refund", { amount: 1 }, { customer: { verified: true, flagged: true } }))).toMatchObject({ decision: "deny", reasons: ["this customer is flagged for review"] });
  });
});
