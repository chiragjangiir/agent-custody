// `agent-custody check` finds what a config would fail on at startup before it starts: each finding below is a thing
// that, left alone, is a gateway that exits at launch, runs without the protection the config seems to promise, or
// offers a tool nobody can use.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { checkConfig, checkEgressConfig, isEgressConfig, type CheckFinding } from "../src/check.ts";
import { generateKeyPair, writeKeyPair } from "../src/crypto.ts";
import { buildFixture } from "../scripts/fixture.ts";

const cli = join(import.meta.dirname, "..", "src", "cli.ts");
const fresh = (ttlMs?: number) => buildFixture(join(mkdtempSync(join(tmpdir(), "check-")), "fx"), ttlMs);
const edit = (configFile: string, f: (c: Record<string, unknown>) => void) => {
  const c = JSON.parse(readFileSync(configFile, "utf8")) as Record<string, unknown>;
  f(c);
  writeFileSync(configFile, JSON.stringify(c, null, 2));
};
const errors = (fs: CheckFinding[]) => fs.filter((f) => f.level === "error");
const warns = (fs: CheckFinding[]) => fs.filter((f) => f.level === "warn");

describe("agent-custody check on an egress witness config", () => {
  const SECRET = "EGRESS_CHECK_TEST_SECRET";
  const egress = (change: (c: Record<string, unknown>) => void = () => {}) => {
    const dir = mkdtempSync(join(tmpdir(), "check-egress-"));
    const { keyFile } = writeKeyPair(generateKeyPair(), dir, "egress");
    writeFileSync(join(dir, "policy.cedar"), "permit(principal, action, resource);\n");
    const c: Record<string, unknown> = { identity: { keyFile }, agents: [{ id: "research-agent", secretEnv: SECRET }], policyFile: "policy.cedar", receiptsDir: "receipts", logFile: "log.jsonl" };
    change(c);
    const configFile = join(dir, "egress.json");
    writeFileSync(configFile, JSON.stringify(c));
    return { dir, configFile };
  };
  const withSecret = <T>(value: string | undefined, f: () => T): T => {
    const before = process.env[SECRET];
    if (value === undefined) delete process.env[SECRET];
    else process.env[SECRET] = value;
    try {
      return f();
    } finally {
      if (before === undefined) delete process.env[SECRET];
      else process.env[SECRET] = before;
    }
  };
  const find = (fs: CheckFinding[], check: string) => fs.filter((f) => f.check === check);

  it("a mistyped key is an error naming the key it nearly is", () => {
    const r = withSecret("s3cret", () => checkEgressConfig(egress((c) => { c.agnets = c.agents; }).configFile));
    expect(errors(r).some((f) => f.check === "config" && f.message.includes('"agnets"') && f.message.includes('"agents"'))).toBe(true);
  });

  it("a witness key that loads is ok, and one that does not is an error", () => {
    const good = egress();
    expect(find(withSecret("s3cret", () => checkEgressConfig(good.configFile)), "key").map((f) => f.level)).toEqual(["ok"]);
    writeFileSync(join(good.dir, "egress.key"), "not a key");
    expect(find(withSecret("s3cret", () => checkEgressConfig(good.configFile)), "key").map((f) => f.level)).toEqual(["error"]);
  });

  it("an agent whose secret variable is unset is an error naming the variable, and a set one never shows its value", () => {
    const { configFile } = egress();
    const unset = find(withSecret(undefined, () => checkEgressConfig(configFile)), "credentials");
    expect(unset.map((f) => f.level)).toEqual(["error"]);
    expect(unset[0]!.message).toContain(SECRET);
    const set = withSecret("value-that-must-not-leak", () => checkEgressConfig(configFile));
    expect(find(set, "credentials").map((f) => f.level)).toEqual(["ok"]);
    expect(JSON.stringify(set)).not.toContain("value-that-must-not-leak");
  });

  it("a Cedar policy that does not parse is an error, and a Rego policy is left to the witness to compile", () => {
    const bad = egress();
    writeFileSync(join(bad.dir, "policy.cedar"), "permit(principal");
    expect(find(withSecret("s3cret", () => checkEgressConfig(bad.configFile)), "policy").map((f) => f.level)).toEqual(["error"]);
    const rego = egress((c) => { c.policyFile = "policy.rego"; });
    writeFileSync(join(rego.dir, "policy.rego"), "this is not rego");
    const r = find(withSecret("s3cret", () => checkEgressConfig(rego.configFile)), "policy");
    expect(r.map((f) => f.level)).toEqual(["ok"]);
    expect(r[0]!.message).toContain("compiles a Rego policy when it starts");
  });

  it("both logFile and log, or neither, is a log error", () => {
    const both = withSecret("s3cret", () => checkEgressConfig(egress((c) => { c.log = { url: "https://log.example" }; }).configFile));
    expect(find(both, "log").map((f) => f.level)).toEqual(["error"]);
    const neither = withSecret("s3cret", () => checkEgressConfig(egress((c) => { delete c.logFile; }).configFile));
    expect(find(neither, "log").map((f) => f.level)).toEqual(["error"]);
    expect(find(withSecret("s3cret", () => checkEgressConfig(egress().configFile)), "log").map((f) => f.level)).toEqual(["ok"]);
  });

  it("the command routes an egress config here and exits 0 with the secret set and 1 without it", () => {
    const { configFile } = egress();
    const env: NodeJS.ProcessEnv = { ...process.env, [SECRET]: "s3cret" };
    const ok = spawnSync(process.execPath, ["--import", "tsx", cli, "check", "--config", configFile, "--json"], { encoding: "utf8", timeout: 30_000, env });
    expect(ok.status).toBe(0);
    expect((JSON.parse(ok.stdout) as CheckFinding[]).some((f) => f.level === "ok" && f.check === "credentials")).toBe(true);
    delete env[SECRET];
    const bad = spawnSync(process.execPath, ["--import", "tsx", cli, "check", "--config", configFile, "--json"], { encoding: "utf8", timeout: 30_000, env });
    expect(bad.status).toBe(1);
    expect((JSON.parse(bad.stdout) as CheckFinding[]).some((f) => f.level === "error" && f.check === "credentials" && f.message.includes(SECRET))).toBe(true);
  });

  it("a gateway config and a door config are not taken for an egress config", () => {
    expect(isEgressConfig(egress().configFile)).toBe(true);
    expect(isEgressConfig(fresh().configFile)).toBe(false);
    const door = egress((c) => { delete c.agents; c.origin = { url: "http://127.0.0.1:1" }; c.trustedPrincipalKeys = []; });
    expect(isEgressConfig(door.configFile)).toBe(false);
  });
});

describe("agent-custody check", () => {
  it("a good config has no errors and says the upstreams are not started", async () => {
    const fx = fresh();
    const r = await checkConfig(fx.configFile);
    expect(errors(r)).toEqual([]);
    expect(warns(r).map((f) => f.check)).toContain("upstreams");
  });

  it("--connect starts the upstreams, lists their tools, and finds every name the config and grant use", async () => {
    const fx = fresh();
    const r = await checkConfig(fx.configFile, { connect: true });
    expect(errors(r)).toEqual([]);
    expect(r.find((f) => f.check === "upstreams")?.message).toContain("customer.lookup");
    expect(r.find((f) => f.check === "tool names")?.level).toBe("ok");
  });

  it("--connect still tries the upstreams when the gateway key does not exist yet, as in a container's first start", async () => {
    const fx = fresh();
    edit(fx.configFile, (c) => { c.identity = { keyFile: "keys/not-created-yet.key" }; });
    const r = await checkConfig(fx.configFile, { connect: true });
    expect(errors(r)).toEqual([]);
    expect(r.find((f) => f.check === "upstreams")?.message).toContain("customer.lookup");
  });

  it("a mistyped key is an error naming the key it nearly is, because the schema ignores unknown keys and the setting stays at its default", async () => {
    const fx = fresh();
    edit(fx.configFile, (c) => { c.precomit = ["stripe.refund"]; });
    const e = errors(await checkConfig(fx.configFile)).find((f) => f.check === "config");
    expect(e?.message).toContain('"precomit"');
    expect(e?.message).toContain('did you mean "precommit"');
  });

  it("a policy that does not parse is an error with Cedar's own message", async () => {
    const fx = fresh();
    writeFileSync(join(fx.dir, "policy.cedar"), "permit(principal");
    const e = errors(await checkConfig(fx.configFile)).find((f) => f.check === "policy");
    expect(e?.message).toContain("failed to parse");
  });

  it("a permit written only in a comment does not count: the policy still has no permit rule", async () => {
    const fx = fresh();
    writeFileSync(join(fx.dir, "policy.cedar"), '// permit(principal, action, resource);\n//   permit(principal, action == Action::"stripe.refund", resource);\nforbid(principal, action == Action::"stripe.refund", resource);\n');
    const r = await checkConfig(fx.configFile);
    expect(warns(r).some((f) => f.check === "policy" && f.message.includes("no permit"))).toBe(true);
    expect(r.some((f) => f.check === "policy" && f.level === "ok")).toBe(false);
  });

  it("a policy with no permit rule is a warning: every call would be denied", async () => {
    const fx = fresh();
    writeFileSync(join(fx.dir, "policy.cedar"), '// nothing allowed\nforbid(principal, action == Action::"stripe.refund", resource);\n');
    expect(warns(await checkConfig(fx.configFile)).some((f) => f.check === "policy" && f.message.includes("no permit"))).toBe(true);
  });

  it("a credential variable the config names but the environment lacks is an error", async () => {
    const fx = fresh();
    edit(fx.configFile, (c) => { c.log = { url: "https://log.example.com/t/x/", tokenEnv: "CHECK_TEST_LOG_TOKEN_UNSET", hashOnly: true, keys: [] }; delete c.logFile; });
    const r = await checkConfig(fx.configFile);
    expect(errors(r).some((f) => f.check === "environment" && f.message.includes("CHECK_TEST_LOG_TOKEN_UNSET"))).toBe(true);
  });

  it("the Splunk token and OpenTelemetry header variables count as credentials the gateway needs at startup", async () => {
    const fx = fresh();
    edit(fx.configFile, (c) => {
      c.splunk = { url: "https://splunk.example.com:8088/services/collector", tokenEnv: "CHECK_TEST_SPLUNK_UNSET" };
      c.otel = { url: "https://otel.example.com/v1/traces", headersEnv: { authorization: "CHECK_TEST_OTEL_UNSET" } };
    });
    const r = errors(await checkConfig(fx.configFile)).filter((f) => f.check === "environment");
    expect(r.map((f) => f.message).join("\n")).toContain("CHECK_TEST_SPLUNK_UNSET");
    expect(r.map((f) => f.message).join("\n")).toContain("CHECK_TEST_OTEL_UNSET");
  });

  it("an operations database or an approvals directory that cannot be written is an error, as the revocation file is", async () => {
    const fx = fresh();
    edit(fx.configFile, (c) => {
      c.operations = { database: "/proc/no-such-dir/operations.sqlite", budgets: [{ id: "refunds", currency: "GBP", limit: 100000 }], tools: [{ tool: "stripe.refund", budget: "refunds", reconcile: { tool: "customer.lookup", args: { key: "$operation.idempotencyKey" }, statusPath: "status", confirmed: ["succeeded"], failed: ["failed"] } }] };
      c.approvals = { trustedKeys: ["keys/principal.pub"], usedDir: "/proc/no-such-dir/used", tools: [{ tool: "stripe.refund" }] };
    });
    const r = errors(await checkConfig(fx.configFile)).filter((f) => f.check === "paths").map((f) => f.message).join("\n");
    expect(r).toContain("operations.database");
    expect(r).toContain("approvals.usedDir");
  });

  it("an expired grant is an error", async () => {
    const fx = fresh(-60_000);
    const e = errors(await checkConfig(fx.configFile)).find((f) => f.check === "grant");
    expect(e?.message).toContain("validity window");
  });

  it("a missing principal key and a missing policy file are errors", async () => {
    const fx = fresh();
    edit(fx.configFile, (c) => { c.trustedPrincipalKeys = ["keys/nobody.pub"]; c.policyFile = "nope.cedar"; });
    const r = errors(await checkConfig(fx.configFile));
    expect(r.some((f) => f.check === "principal keys")).toBe(true);
    expect(r.some((f) => f.check === "policy" && f.message.includes("does not exist"))).toBe(true);
  });

  it("a stdio command that is not there, and a script argument that is not there, are reported", async () => {
    const fx = fresh();
    edit(fx.configFile, (c) => { c.upstream = { command: "no-such-mcp-server-binary", args: ["/opt/mcp/none.js"] }; });
    const r = await checkConfig(fx.configFile);
    expect(errors(r).some((f) => f.check === "upstream" && f.message.includes("no-such-mcp-server-binary"))).toBe(true);
    expect(warns(r).some((f) => f.check === "upstream" && f.message.includes("/opt/mcp/none.js"))).toBe(true);
  });

  it("a REST tool with idempotencyHeader and no operations entry is an error, because every call to it would fail", async () => {
    const fx = fresh();
    edit(fx.configFile, (c) => {
      c.upstream = { rest: { baseUrl: "https://api.example.com", tools: [{ name: "pay.refund", method: "POST", path: "/refunds", idempotencyHeader: "Idempotency-Key" }] } };
    });
    const e = errors(await checkConfig(fx.configFile)).find((f) => f.check === "upstream");
    expect(e?.message).toContain("pay.refund");
    expect(e?.message).toContain("operations");
  });

  it("a remote log with an empty precommit is a warning about evidence lost in an outage", async () => {
    const fx = fresh();
    edit(fx.configFile, (c) => { c.log = { url: "https://log.example.com/t/x/", hashOnly: true }; delete c.logFile; c.precommit = []; });
    expect(warns(await checkConfig(fx.configFile)).some((f) => f.check === "precommit")).toBe(true);
  });

  it("--connect names a tool in precommit, facts, or the grant that no upstream offers", async () => {
    const fx = fresh();
    edit(fx.configFile, (c) => {
      c.precommit = ["stripe.refnd"];
      c.facts = [{ name: "customer", tool: "customer.lookp", args: { customer_id: "$args.customer_id" }, forTools: ["stripe.refund"] }];
    });
    const r = await checkConfig(fx.configFile, { connect: true });
    expect(errors(r).some((f) => f.check === "tool names" && f.message.includes("stripe.refnd") && f.message.includes("before it is logged"))).toBe(true);
    expect(errors(r).some((f) => f.check === "tool names" && f.message.includes("customer.lookp"))).toBe(true);
  });

  it("--connect reports two upstreams that offer the same tool, which is otherwise found at launch", async () => {
    const fx = fresh();
    edit(fx.configFile, (c) => {
      const up = c.upstream as Record<string, unknown>;
      delete c.upstream;
      c.upstreams = [{ name: "one", ...up }, { name: "two", ...up }];
    });
    const e = errors(await checkConfig(fx.configFile, { connect: true })).find((f) => f.check === "upstreams");
    expect(e?.message).toContain("one owner per tool");
  });

  it("the command exits 0 for a good config and 1 for a broken one, and --json prints the findings", () => {
    const good = fresh();
    const ok = spawnSync(process.execPath, ["--import", "tsx", cli, "check", "--config", good.configFile], { encoding: "utf8", timeout: 30_000 });
    expect(ok.status).toBe(0);
    expect(ok.stdout).toContain("no errors");
    const bad = fresh();
    writeFileSync(join(bad.dir, "policy.cedar"), "permit(principal");
    const r = spawnSync(process.execPath, ["--import", "tsx", cli, "check", "--config", bad.configFile, "--json"], { encoding: "utf8", timeout: 30_000 });
    expect(r.status).toBe(1);
    expect((JSON.parse(r.stdout) as CheckFinding[]).some((f) => f.level === "error" && f.check === "policy")).toBe(true);
  });
});
