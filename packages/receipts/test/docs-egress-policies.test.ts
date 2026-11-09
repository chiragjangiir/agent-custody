// Every ```cedar block in site/guide/egress-policies.md must parse, and the behaviour the prose promises must hold.
// Blocks are addressed by position, so editing the guide without updating this test fails loudly. Each request is built
// as the witness builds it: the authority through parseAuthority, the action through destinationName.
import { readFileSync } from "node:fs";
import * as cedar from "@cedar-policy/cedar-wasm/nodejs";
import { describe, expect, it } from "vitest";
import { destinationName, parseAuthority, type Destination } from "../src/egress.ts";
import { evaluate } from "../src/policy.ts";

const doc = readFileSync(new URL("../../../site/guide/egress-policies.md", import.meta.url), "utf8");
const blocks = [...doc.matchAll(/```cedar\n([\s\S]*?)```/g)].map((m) => m[1]!);

function ask(i: number, agent: string, authority: string, scheme: Destination["scheme"] = "connect") {
  const target = parseAuthority(authority);
  if (!target) throw new Error(`not an authority: ${authority}`);
  const { host, port } = target;
  const verified = agent !== "unknown";
  const destination: Destination = { host, port, scheme, credential: verified ? "verified" : "absent", remote: "10.1.2.3" };
  return evaluate(blocks[i]!, { agentId: agent, tool: destinationName(host, port), context: { args: { method: scheme === "connect" ? "CONNECT" : "GET", host, port }, facts: { destination } } });
}
const decide = (i: number, agent: string, authority: string, scheme?: Destination["scheme"]) => ask(i, agent, authority, scheme).decision;

describe("site/guide/egress-policies.md examples", () => {
  it("contains the expected number of examples", () => {
    expect(blocks.length).toBe(8);
  });

  it("every block parses as a Cedar policy set", () => {
    for (const [i, b] of blocks.entries()) {
      const r = cedar.checkParsePolicySet({ staticPolicies: b });
      expect(r.type, `block ${i}:\n${b}`).toBe("success");
    }
  });

  it("0: a per-agent allow list names each destination, port included, for that agent only", () => {
    expect(decide(0, "research-agent", "registry.npmjs.org:443")).toBe("allow");
    expect(decide(0, "research-agent", "docs.python.org:443")).toBe("allow");
    expect(decide(0, "research-agent", "registry.npmjs.org:80")).toBe("deny");
    expect(decide(0, "research-agent", "pypi.org:443")).toBe("deny");
    expect(decide(0, "build-agent", "registry.npmjs.org:443")).toBe("deny");
    // the action is canonical: case and a final dot do not make a different destination
    expect(decide(0, "research-agent", "Registry.NPMJS.org.:443")).toBe("allow");
  });

  it("1: *.example.com covers subdomains at any depth but not example.com, which the rule adds by name", () => {
    expect(decide(1, "build-agent", "api.example.com:443")).toBe("allow");
    expect(decide(1, "build-agent", "a.b.example.com:443")).toBe("allow");
    expect(decide(1, "build-agent", "example.com:443")).toBe("allow");
    expect(decide(1, "build-agent", "evilexample.com:443")).toBe("deny");
    expect(decide(1, "build-agent", "api.example.com:80")).toBe("deny");
    expect(decide(1, "research-agent", "api.example.com:443")).toBe("deny");
    // the trap itself: without the explicit name, the pattern alone refuses the bare domain
    const patternOnly = `permit(principal, action, resource) when { context.facts.destination.host like "*.example.com" };`;
    expect(evaluate(patternOnly, { agentId: "build-agent", tool: "example.com:443", context: { args: {}, facts: { destination: { host: "example.com", port: 443 } } } }).decision).toBe("deny");
  });

  it("2: the rule the guide warns against matches a domain someone else registered", () => {
    expect(decide(2, "build-agent", "evilexample.com:443")).toBe("allow");
    expect(decide(2, "build-agent", "api.example.com:443")).toBe("allow");
  });

  it("3: ports are listed; any other port on the host is refused", () => {
    expect(decide(3, "build-agent", "mirror.example.net:443")).toBe("allow");
    expect(decide(3, "build-agent", "mirror.example.net:80", "http")).toBe("allow");
    expect(decide(3, "build-agent", "mirror.example.net:22")).toBe("deny");
    expect(decide(3, "build-agent", "mirror.example.net:8443")).toBe("deny");
  });

  it("4: a rule on an address matches the address however it is spelt, and nothing else", () => {
    expect(decide(4, "research-agent", "10.20.0.5:8443")).toBe("allow");
    expect(decide(4, "research-agent", "0xa.20.0.5:8443")).toBe("allow");
    expect(decide(4, "research-agent", "169082885:8443")).toBe("allow");
    expect(decide(4, "research-agent", "10.20.0.6:8443")).toBe("deny");
    expect(decide(4, "research-agent", "10.20.0.5:443")).toBe("deny");
    // the canonical forms the prose names
    expect(parseAuthority("2130706433:443")?.host).toBe("127.0.0.1");
    expect(parseAuthority("0x7f.1:443")?.host).toBe("127.0.0.1");
    expect(parseAuthority("010.0.0.1:443")?.host).toBe("8.0.0.1");
    expect(destinationName(parseAuthority("[0:0::1]:443")!.host, 443)).toBe("[::1]:443");
  });

  it("5: a rule with no condition on the destination permits the metadata address", () => {
    expect(decide(5, "research-agent", "169.254.169.254:80", "http")).toBe("allow");
    expect(decide(5, "research-agent", "10.0.0.1:443")).toBe("allow");
  });

  it("6: ip() on a host name is an error, and the error denies every name", () => {
    const named = ask(6, "research-agent", "docs.python.org:443");
    expect(named.decision).toBe("deny");
    expect(named.errors.join(" ")).toMatch(/invalid IP address: docs\.python\.org/);
  });

  it("7: forbid overrides the broad permit, for a carve-out and for the providers", () => {
    expect(decide(7, "research-agent", "docs.example.com:443")).toBe("allow");
    expect(decide(7, "build-agent", "cdn.example.com:443")).toBe("allow");
    expect(decide(7, "build-agent", "paste.example.com:443")).toBe("deny");
    expect(decide(7, "build-agent", "api.stripe.com:443")).toBe("deny");
    expect(decide(7, "build-agent", "docs.example.com:80")).toBe("deny");
    // an agent whose credential did not verify does not meet credential == "verified" (and the witness answers 407 anyway)
    expect(decide(7, "unknown", "docs.example.com:443")).toBe("deny");
    // a forbid that wins is named by its position, which is what the 403 reason carries
    expect(ask(7, "build-agent", "paste.example.com:443").reasons).toEqual(["policy1"]);
    // with a permit on the provider added later, the forbid still wins
    const later = blocks[7]! + `\npermit(principal == Agent::"build-agent", action == Action::"api.stripe.com:443", resource);\n`;
    expect(evaluate(later, { agentId: "build-agent", tool: "api.stripe.com:443", context: { args: {}, facts: { destination: { host: "api.stripe.com", port: 443, scheme: "connect", credential: "verified", remote: "10.1.2.3" } } } }).decision).toBe("deny");
  });

  it("the refusal answer the guide shows: no permit matched", () => {
    expect(ask(0, "research-agent", "pypi.org:443")).toMatchObject({ decision: "deny", reasons: [], errors: [] });
  });
});
