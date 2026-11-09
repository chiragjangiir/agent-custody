// evaluate() keeps policy sets parsed in cedar-wasm under slot ids. A live entry must always decide with its own text:
// if a slot it holds were given to another text, it would allow what its policy denies and sign its own digest beside
// the decision. Its own file so that the cache starts empty and the slots are assigned in a known order.
import * as cedarModule from "@cedar-policy/cedar-wasm/nodejs";
import { describe, expect, it, vi } from "vitest";

const slots = vi.hoisted(() => ({ used: new Set<string>(), preparses: 0 }));
vi.mock("@cedar-policy/cedar-wasm/nodejs", async (importOriginal) => {
  const cedar = await importOriginal<typeof cedarModule>();
  return {
    ...cedar,
    preparsePolicySet: (id: string, policies: cedarModule.PolicySet) => {
      slots.used.add(id);
      slots.preparses++;
      return cedar.preparsePolicySet(id, policies);
    },
  };
});

const { evaluate, policyDigest } = await import("../src/policy.ts");

const capped = (limit: number) => `permit(principal, action == Action::"stripe.refund", resource) when { context.args.amount <= ${limit} };`;
const refund = (amount: number) => ({ agentId: "a", tool: "stripe.refund", context: { args: { amount } } });

describe("Cedar policy sets kept parsed", () => {
  it("a preparse that throws never hands a live entry's slot to another text", () => {
    for (let limit = 0; limit <= 7; limit++) expect(evaluate(capped(limit), refund(limit)).decision).toBe("allow");
    // cedar-wasm throws, rather than answering a failure, for policies that are not text, and on a trap
    expect(() => evaluate(1 as unknown as string, refund(1))).toThrow();
    expect(evaluate(capped(100), refund(50)).decision).toBe("allow");
    for (const amount of [50, 8]) {
      const d = evaluate(capped(7), refund(amount));
      expect([d.decision, d.policyDigest]).toEqual(["deny", policyDigest(capped(7))]);
    }
    expect(evaluate(capped(7), refund(7)).decision).toBe("allow");
  });

  it("stays bounded: many policies and failures use a fixed set of slots, and every decision is its policy's own", () => {
    for (let round = 0; round < 3; round++) {
      for (let limit = 1000; limit < 1100; limit++) {
        if (limit % 10 === 0) expect(() => evaluate({} as unknown as string, refund(1))).toThrow();
        if (limit % 7 === 0) expect(evaluate(`${capped(limit)} permit(`, refund(1)).decision).toBe("deny");
        expect(evaluate(capped(limit), refund(limit)).decision).toBe("allow");
        expect(evaluate(capped(limit), refund(limit + 1)).decision).toBe("deny");
      }
    }
    expect(slots.used.size).toBeLessThanOrEqual(9);
  });

  it("parses a text once while it stays in the cache, and parses a changed file again", () => {
    const before = slots.preparses;
    for (let i = 0; i < 5; i++) evaluate(capped(5000), refund(1));
    expect(slots.preparses).toBe(before + 1);
    const edited = capped(4000);
    const d = evaluate(edited, refund(4500));
    expect([d.decision, d.policyDigest, slots.preparses]).toEqual(["deny", policyDigest(edited), before + 2]);
    expect(evaluate(capped(5000), refund(4500)).decision).toBe("allow");
    expect(slots.preparses).toBe(before + 2);
  });
});
