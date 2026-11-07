// Rego, beside Cedar. A .rego policy file is compiled with the opa binary when it loads and evaluated in-process; an OPA
// server the operator runs is asked over HTTP. Both read the same contract, `package agentcustody` with `allow` and
// `deny`, and both fail closed: what matters is that no shape of policy, server, or failure turns into an allow, and
// that every receipt still names the policy that decided it.
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { checkConfig } from "../src/check.ts";
import { loadConfig, loadSdkConfig, type GatewayConfig } from "../src/config.ts";
import { loadPublicKey } from "../src/crypto.ts";
import { createGateway, RECEIPT_META_KEY } from "../src/gateway.ts";
import { opaDigest, opaUrlProblem } from "../src/opa-server.ts";
import { policyDigest } from "../src/policy.ts";
import { compileRego, evaluateRego, regoDecision } from "../src/policy-rego.ts";
import type { ReceiptBundle, ReceiptPredicate, ReceiptStatement } from "../src/receipt.ts";
import { createSdkIssuer } from "../src/sdk/index.ts";
import { simulatePolicy } from "../src/simulate.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildFixture, buildSdkFixture, type Fixture } from "../scripts/fixture.ts";

/** The fixture's Cedar policy, in Rego: reads for anyone with the scope; refunds up to £1,000 for a customer the gateway verified. */
const REGO = `package agentcustody

allow if input.action == "customer.lookup"

allow if {
  input.action == "stripe.refund"
  input.context.args.amount <= 100000
  input.context.facts.customer.verified == true
}
`;
const TIGHT = REGO.replace("<= 100000", "<= 1000");
const refund = (amount = 5000, customer_id = "cust_123") => ({ name: "stripe.refund", arguments: { customer_id, amount } });

const quietly = async <T>(fn: () => Promise<T> | T): Promise<T> => {
  const error = console.error;
  console.error = () => {};
  try {
    return await fn();
  } finally {
    console.error = error;
  }
};
const receiptOf = async (fx: Fixture, result: { _meta?: Record<string, unknown> }): Promise<ReceiptPredicate> => {
  const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${String(result._meta![RECEIPT_META_KEY])}.json`), "utf8")) as ReceiptBundle;
  const v = await verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile });
  expect(v.ok, v.checks.filter((c) => !c.ok).map((c) => c.name).join(", ")).toBe(true);
  return (JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString()) as ReceiptStatement).predicate;
};
const reloads = (fx: Fixture) => readFileSync(join(fx.receiptsDir, "policy-reloads.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);

/** The gateway fixture, with its policy replaced: a Rego file, or an OPA server. */
function fixture(policy: { rego: string } | { opa: GatewayConfig["opa"] }): Fixture {
  const fx = buildFixture(mkdtempSync(join(tmpdir(), "policy-rego-")));
  const cfg = JSON.parse(readFileSync(fx.configFile, "utf8")) as Record<string, unknown>;
  delete cfg.policyFile;
  if ("rego" in policy) {
    writeFileSync(join(fx.dir, "policy.rego"), policy.rego);
    cfg.policyFile = "policy.rego";
  } else {
    cfg.opa = policy.opa;
  }
  writeFileSync(fx.configFile, JSON.stringify(cfg, null, 2));
  return fx;
}
const writeRego = (fx: Fixture, text: string) => {
  const path = join(fx.dir, "policy.rego");
  writeFileSync(`${path}.tmp`, text);
  renameSync(`${path}.tmp`, path);
};

describe("the Rego decision contract", () => {
  it("is default deny: only allow exactly true permits, and any deny entry wins with its strings as the reasons", () => {
    expect(regoDecision({ allow: true }, "d")).toEqual({ decision: "allow", reasons: ["data.agentcustody.allow"], errors: [], policyDigest: "d" });
    expect(regoDecision({}, "d")).toMatchObject({ decision: "deny", reasons: [], errors: [] });
    expect(regoDecision({ allow: false }, "d").decision).toBe("deny");
    expect(regoDecision({ allow: true, deny: ["customer flagged"] }, "d")).toMatchObject({ decision: "deny", reasons: ["customer flagged"], errors: [] });
    expect(regoDecision({ allow: true, deny: [] }, "d").decision).toBe("allow");
  });

  it("denies, with an error, a document that does not follow the contract instead of guessing what it meant", () => {
    for (const doc of [undefined, null, [], "allow", { allow: "true" }, { allow: 1 }, { allow: true, deny: "no" }, { allow: true, deny: [{ msg: "x" }] }, { allow: true, deny: { a: true } }]) {
      const d = regoDecision(doc, "d");
      expect(d.decision, JSON.stringify(doc)).toBe("deny");
      expect(d.errors.length, JSON.stringify(doc)).toBe(1);
    }
  });
});

describe("compiling a Rego file", () => {
  const input = (tool: string, args: Record<string, unknown>, facts: Record<string, unknown> = {}) => ({ agentId: "support-agent", tool, context: { args, facts } });

  it("evaluates the compiled policy in-process, and a policy without a deny rule needs none", () => {
    const { policy, errors } = compileRego(REGO);
    expect(errors).toEqual([]);
    expect(evaluateRego(policy!, "d", input("stripe.refund", { amount: 5000 }, { customer: { verified: true } })).decision).toBe("allow");
    expect(evaluateRego(policy!, "d", input("stripe.refund", { amount: 5000 }, { customer: { verified: false } })).decision).toBe("deny");
    // a missing argument is undefined in Rego, so the rule does not hold: a deny, as Cedar's error is
    expect(evaluateRego(policy!, "d", input("stripe.refund", {}, { customer: { verified: true } })).decision).toBe("deny");
    // what the agent asserts in its arguments is not the gateway's fact
    expect(evaluateRego(policy!, "d", input("stripe.refund", { amount: 5000, verified: true, customer: { verified: true } })).decision).toBe("deny");
  });

  it("refuses a policy that cannot be relied on, with opa's reason: a syntax error, another package, or a builtin the SDK cannot run", () => {
    expect(compileRego("package agentcustody\nallow if {").errors[0]).toMatch(/rego_parse_error/);
    expect(compileRego("package authz\nallow := true").errors[0]).toMatch(/must declare package agentcustody/);
    // http.send would make a decision depend on a network call made inside the evaluator, outside the facts the receipt records
    expect(compileRego('package agentcustody\nallow if http.send({"method": "get", "url": "http://x"}).status_code == 200').errors[0]).toMatch(/undefined function http\.send/);
    expect(compileRego("package agentcustody\nallow if time.now_ns() > 0").errors[0]).toMatch(/undefined function time\.now_ns/);
  });

  it("says what is missing when there is no opa binary", () => {
    expect(compileRego(REGO, "no-such-opa-binary").errors).toEqual(["compiling a Rego policy needs the opa binary on PATH (no-such-opa-binary was not found)"]);
  });
});

describe("a gateway with a Rego policy file", () => {
  it("decides each call by the Rego policy, and the receipt pins the sha256 of the Rego text as it does for Cedar", async () => {
    const fx = fixture({ rego: REGO });
    const gw = await createGateway(loadConfig(fx.configFile));
    try {
      const allowed = await receiptOf(fx, await gw.handleCall(refund()));
      expect(allowed.policy).toMatchObject({ decision: "allow", reasons: ["data.agentcustody.allow"], policyDigest: policyDigest(REGO) });
      const over = await quietly(() => gw.handleCall(refund(500000)));
      expect(over.isError).toBe(true);
      expect((await receiptOf(fx, over)).policy).toMatchObject({ decision: "deny", reasons: [] });
      const unverified = await quietly(() => gw.handleCall(refund(5000, "cust_999")));
      expect((await receiptOf(fx, unverified)).execution.status).toBe("denied");
    } finally {
      await gw.close();
    }
  });

  it("a deny rule overrides allow, as a Cedar forbid overrides a permit, and its message is the recorded reason", async () => {
    const fx = fixture({ rego: `${REGO}\ndeny contains "refunds over £500 need a human" if {\n  input.action == "stripe.refund"\n  input.context.args.amount > 50000\n}\n` });
    const gw = await createGateway(loadConfig(fx.configFile));
    try {
      expect((await receiptOf(fx, await gw.handleCall(refund(5000)))).policy!.decision).toBe("allow");
      const denied = await quietly(() => gw.handleCall(refund(60000)));
      const p = await receiptOf(fx, denied);
      expect(p.policy).toMatchObject({ decision: "deny", reasons: ["refunds over £500 need a human"] });
      expect(p.execution).toMatchObject({ status: "denied", reason: "refunds over £500 need a human" });
    } finally {
      await gw.close();
    }
  });

  it("recompiles a changed file from the next call, and refuses one that does not compile: the policy in force stays", async () => {
    const fx = fixture({ rego: REGO });
    const gw = await createGateway(loadConfig(fx.configFile));
    try {
      await quietly(() => writeRego(fx, TIGHT));
      const tight = await receiptOf(fx, await quietly(() => gw.handleCall(refund(5000))));
      expect(tight.policy).toMatchObject({ decision: "deny", policyDigest: policyDigest(TIGHT) });

      const broken = "package agentcustody\nallow := true if {";
      await quietly(() => writeRego(fx, broken));
      const still = await receiptOf(fx, await quietly(() => gw.handleCall(refund(500))));
      expect(still.policy).toMatchObject({ decision: "allow", policyDigest: policyDigest(TIGHT) });
      expect(reloads(fx).map((r) => [r.event, r.to])).toEqual([["reloaded", policyDigest(TIGHT)], ["refused", policyDigest(broken)]]);
      expect(String((reloads(fx)[1]!.errors as string[])[0])).toMatch(/^does not compile: .*rego_parse_error/);
    } finally {
      await gw.close();
    }
  });

  it("does not start with a Rego file that does not compile, since there is nothing to evaluate", async () => {
    const fx = fixture({ rego: "package agentcustody\nallow if {" });
    await expect(createGateway(loadConfig(fx.configFile))).rejects.toThrow(/policy\.rego does not compile: .*rego_parse_error/);
  });

  it("is checked by agent-custody check, which compiles the file", async () => {
    const good = await checkConfig(fixture({ rego: REGO }).configFile);
    expect(good.find((f) => f.check === "policy")).toMatchObject({ level: "ok", message: "the Rego policy compiles" });
    const bad = await checkConfig(fixture({ rego: "package authz\nallow := true" }).configFile);
    expect(bad.find((f) => f.check === "policy")).toMatchObject({ level: "error", message: expect.stringMatching(/must declare package agentcustody/) });
  });
});

describe("Rego in the SDK and in simulation", () => {
  it("an SDK issuer with a .rego file decides by it, and a proposed Rego policy replays Cedar-era receipts", async () => {
    const fx = buildSdkFixture(mkdtempSync(join(tmpdir(), "policy-rego-sdk-")));
    const cfg = loadSdkConfig(fx.configFile);
    const cedarEra = createSdkIssuer(cfg);
    const decode = (b: ReceiptBundle) => (JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement).predicate;
    const ev = { tool: "customer.lookup", args: { customer_id: "cust_123" } };
    const recorded = decode(await cedarEra.record(ev, { status: "executed", result: {} }, cedarEra.decide(ev)));
    expect(recorded.policy!.decision).toBe("allow");

    const proposed = 'package agentcustody\nallow if input.action == "stripe.refund"\n';
    const report = simulatePolicy(proposed, [recorded], { language: "rego" });
    expect(report).toMatchObject({ evaluated: 1, policyDigest: policyDigest(proposed) });
    expect(report.changes.map((c) => [c.previous.decision, c.proposed.decision])).toEqual([["allow", "deny"]]);
    expect(() => simulatePolicy("package agentcustody\nallow if {", [recorded], { language: "rego" })).toThrow(/invalid Rego policy/);

    writeFileSync(join(fx.dir, "policy.rego"), 'package agentcustody\nallow if input.action == "customer.lookup"\n');
    const rego = createSdkIssuer({ ...cfg, policyFile: join(fx.dir, "policy.rego") });
    expect(rego.decide(ev)).toMatchObject({ decision: "allow", reasons: ["data.agentcustody.allow"] });
    expect(rego.decide({ tool: "stripe.refund", args: {} })!.decision).toBe("deny");
    expect(() => createSdkIssuer({ ...cfg, policyFile: (writeFileSync(join(fx.dir, "bad.rego"), "package x\nallow := true"), join(fx.dir, "bad.rego")) })).toThrow(/does not compile/);
  });
});

/** A stand-in OPA server: answers the Data API as `answer` says, and keeps each request. */
async function fakeOpa(answer: (input: Record<string, unknown> | undefined, req: IncomingMessage) => { status?: number; body: unknown; delayMs?: number; location?: string }) {
  const requests: { url: string; authorization?: string; input?: Record<string, unknown> }[] = [];
  const server: Server = createServer(async (req, res) => {
    let raw = "";
    for await (const chunk of req) raw += chunk;
    const input = (JSON.parse(raw || "{}") as { input?: Record<string, unknown> }).input;
    requests.push({ url: req.url ?? "", authorization: req.headers.authorization, input });
    const a = answer(input, req);
    if (a.delayMs) await new Promise((r) => setTimeout(r, a.delayMs));
    res.writeHead(a.status ?? 200, { "content-type": "application/json", ...(a.location ? { location: a.location } : {}) }).end(JSON.stringify(a.body));
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  servers.push(server);
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, requests };
}
const servers: Server[] = [];
const processes: ChildProcess[] = [];
afterAll(() => {
  for (const s of servers) s.close();
  for (const p of processes) p.kill();
});

/** The decision document the fixture policy gives, computed in the test so the server's answer is known. */
const fixtureDecision = (input: Record<string, unknown> | undefined) => {
  const ctx = (input?.context ?? {}) as { args?: { amount?: number }; facts?: { customer?: { verified?: boolean } } };
  if (!input) return { allow: false };
  if (input.action === "customer.lookup") return { allow: true };
  return { allow: input.action === "stripe.refund" && (ctx.args?.amount ?? Infinity) <= 100000 && ctx.facts?.customer?.verified === true };
};

describe("a gateway asking an OPA server", () => {
  it("sends the same input a .rego file reads, and pins the decision URL and bundle revisions in place of policy text", async () => {
    let revision = "rev-1";
    const opa = await fakeOpa((input) => ({ body: { result: fixtureDecision(input), provenance: { version: "1.22.0", bundles: { authz: { revision } } } } }));
    const fx = fixture({ opa: { url: opa.url } });
    const gw = await quietly(() => createGateway(loadConfig(fx.configFile)));
    try {
      const allowed = await receiptOf(fx, await gw.handleCall(refund()));
      const decision = `${opa.url}/v1/data/agentcustody`;
      expect(allowed.policy).toMatchObject({ decision: "allow", reasons: ["data.agentcustody.allow"], policyDigest: opaDigest(decision, { authz: "rev-1" }) });
      const sent = opa.requests.at(-1)!;
      expect(sent.url).toBe("/v1/data/agentcustody?provenance=true");
      expect(sent.input).toEqual({
        principal: "support-agent", action: "stripe.refund", resource: "stripe.refund",
        context: { args: { customer_id: "cust_123", amount: 5000 }, facts: { customer: expect.objectContaining({ verified: true }) }, grant: { principal: "user_456", scopes: ["customer.lookup", "stripe.refund"] } },
      });

      // a new bundle revision is a new digest, recorded once with what it stands for
      revision = "rev-2";
      const denied = await receiptOf(fx, await quietly(() => gw.handleCall(refund(500000))));
      expect(denied.policy).toMatchObject({ decision: "deny", policyDigest: opaDigest(decision, { authz: "rev-2" }) });
      await gw.handleCall(refund());
      expect(reloads(fx).map((r) => [r.event, r.bundles, r.to])).toEqual([
        ["opa-provenance", { authz: "rev-1" }, opaDigest(decision, { authz: "rev-1" })],
        ["opa-provenance", { authz: "rev-2" }, opaDigest(decision, { authz: "rev-2" })],
      ]);
    } finally {
      await gw.close();
    }
  });

  it("denies the call when the server fails, answers late, or answers outside the contract; it never falls back to an allow", async () => {
    let mode = "ok";
    const opa = await fakeOpa((input) => {
      if (mode === "500") return { status: 500, body: { code: "internal_error" } };
      if (mode === "slow") return { delayMs: 300, body: { result: { allow: true } } };
      if (mode === "undefined") return { body: {} };
      if (mode === "shape") return { body: { result: { allow: "yes" } } };
      return { body: { result: fixtureDecision(input), provenance: { bundles: { authz: { revision: "r" } } } } };
    });
    const fx = fixture({ opa: { url: opa.url, timeoutMs: 100 } });
    const gw = await quietly(() => createGateway(loadConfig(fx.configFile)));
    try {
      const decision = `${opa.url}/v1/data/agentcustody`;
      // a call the server did not answer is denied under the URL's unanswered digest, never the revision seen before;
      // an answer outside the contract was still an answer, from a server that reported no revision
      const unanswered = opaDigest(decision, null);
      for (const [m, error, digest] of [["500", /^opa: OPA server answered 500/, unanswered], ["slow", /^opa: .*(abort|timeout|timed out)/i, unanswered], ["undefined", /is undefined$/, opaDigest(decision, {})], ["shape", /allow is not a boolean$/, opaDigest(decision, {})]] as const) {
        mode = m;
        const result = await quietly(() => gw.handleCall(refund()));
        expect(result.isError, m).toBe(true);
        const p = await receiptOf(fx, result);
        expect(p.policy!.decision, m).toBe("deny");
        expect((p.policy!.errors as string[])[0], m).toMatch(error);
        expect(p.policy!.policyDigest, m).toBe(digest);
        expect(p.execution.status, m).toBe("denied");
      }
      expect(unanswered).not.toBe(opaDigest(decision, { authz: "r" }));
      expect(reloads(fx).find((r) => r.to === unanswered)).toMatchObject({ event: "opa-provenance", bundles: null, warnings: [expect.stringMatching(/did not answer/)] });
      mode = "ok";
      expect((await receiptOf(fx, await gw.handleCall(refund()))).policy!.decision).toBe("allow");
    } finally {
      await gw.close();
    }
  });

  it("sends the bearer token from the environment, and refuses to start without the variable or without the package on the server", async () => {
    const opa = await fakeOpa((input) => ({ body: { result: fixtureDecision(input) } }));
    const fx = fixture({ opa: { url: opa.url, tokenEnv: "TEST_OPA_TOKEN", decision: "authz/agents" } });
    await expect(createGateway(loadConfig(fx.configFile))).rejects.toThrow(/TEST_OPA_TOKEN is not set/);
    process.env.TEST_OPA_TOKEN = "s3cret";
    try {
      const gw = await quietly(() => createGateway(loadConfig(fx.configFile)));
      await gw.handleCall(refund());
      await gw.close();
      expect(opa.requests.at(-1)).toMatchObject({ url: "/v1/data/authz/agents?provenance=true", authorization: "Bearer s3cret" });
      // a server without the bundle reports no revision: the gateway starts, and says loudly that receipts cannot name the policy
      expect(reloads(fx)[0]).toMatchObject({ event: "opa-provenance", bundles: {}, warnings: [expect.stringMatching(/no bundle revision/)] });
    } finally {
      delete process.env.TEST_OPA_TOKEN;
    }
    const empty = await fakeOpa(() => ({ body: {} }));
    await expect(createGateway(loadConfig(fixture({ opa: { url: empty.url } }).configFile))).rejects.toThrow(/data\.agentcustody on .* is undefined/);
    const findings = await checkConfig(fixture({ opa: { url: empty.url } }).configFile);
    expect(findings.find((f) => f.check === "policy")).toMatchObject({ level: "error" });
  });

  it("does not follow a redirect, which would resend the arguments and the token to another host", async () => {
    const elsewhere = await fakeOpa(() => ({ body: { result: { allow: true } } }));
    let redirect = false;
    const opa = await fakeOpa((input) => (redirect ? { status: 307, body: {}, location: `${elsewhere.url}/v1/data/agentcustody?provenance=true` } : { body: { result: fixtureDecision(input) } }));
    const fx = fixture({ opa: { url: opa.url } });
    const gw = await quietly(() => createGateway(loadConfig(fx.configFile)));
    try {
      redirect = true;
      const p = await receiptOf(fx, await quietly(() => gw.handleCall(refund())));
      expect(p.policy).toMatchObject({ decision: "deny", errors: [expect.stringMatching(/redirect \(307\)/)] });
      expect(elsewhere.requests).toEqual([]);
    } finally {
      await gw.close();
    }
  });

  it("refuses plain http to a host that is not a loopback address, before sending anything", async () => {
    const fx = fixture({ opa: { url: "http://10.0.0.1:8181" } });
    await expect(createGateway(loadConfig(fx.configFile))).rejects.toThrow(/is not https or a loopback address/);
    expect((await checkConfig(fx.configFile)).find((f) => f.check === "policy")).toMatchObject({ level: "error", message: expect.stringMatching(/not https or a loopback/) });
    expect(opaUrlProblem("https://opa.internal")).toBeNull();
    expect(opaUrlProblem("http://127.0.0.1:8181")).toBeNull();
    expect(opaUrlProblem("http://[::1]:8181")).toBeNull();
    expect(opaUrlProblem("http://localhost:8181")).toBeNull();
    expect(opaUrlProblem("http://127.0.0.1.evil.example")).not.toBeNull();
  });

  it("works against a real OPA server serving the policy as a bundle with a revision", async () => {
    const dir = mkdtempSync(join(tmpdir(), "policy-rego-opa-"));
    writeFileSync(join(dir, "policy.rego"), REGO);
    execFileSync("opa", ["build", "--revision", "release-42", "-o", join(dir, "bundle.tar.gz"), join(dir, "policy.rego")], { cwd: dir });
    const port = await new Promise<number>((r) => { const s = createServer().listen(0, "127.0.0.1", () => { const p = (s.address() as AddressInfo).port; s.close(() => r(p)); }); });
    const opa = spawn("opa", ["run", "--server", "--addr", `127.0.0.1:${port}`, "--log-level", "error", "--bundle", join(dir, "bundle.tar.gz")], { stdio: "ignore" });
    processes.push(opa);
    const url = `http://127.0.0.1:${port}`;
    for (let i = 0; i < 100; i++) {
      if (await fetch(`${url}/health`).then((r) => r.ok, () => false)) break;
      await new Promise((r) => setTimeout(r, 50));
    }
    const fx = fixture({ opa: { url } });
    const gw = await quietly(() => createGateway(loadConfig(fx.configFile)));
    try {
      const digest = opaDigest(`${url}/v1/data/agentcustody`, { [join(dir, "bundle.tar.gz")]: "release-42" });
      expect((await receiptOf(fx, await gw.handleCall(refund()))).policy).toMatchObject({ decision: "allow", policyDigest: digest });
      expect((await receiptOf(fx, await quietly(() => gw.handleCall(refund(500000))))).policy).toMatchObject({ decision: "deny", policyDigest: digest });
      expect(reloads(fx)).toEqual([expect.objectContaining({ event: "opa-provenance", bundles: { [join(dir, "bundle.tar.gz")]: "release-42" } })]);
    } finally {
      await gw.close();
      opa.kill();
    }
  });
});
