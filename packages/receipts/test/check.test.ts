// `agent-custody check` finds what a config would fail on at startup before it starts: each finding below is a thing
// that, left alone, is a gateway that exits at launch, runs without the protection the config seems to promise, or
// offers a tool nobody can use.
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { checkConfig, checkDoorConfig, type CheckFinding } from "../src/check.ts";
import { buildFixture } from "../scripts/fixture.ts";
import { buildDoorFixture, type DoorFixture } from "../scripts/door-fixture.ts";

// A directory named "read-only" is not writable for any user, root included, so the paths findings do not depend on the uid.
vi.mock("node:fs", async (importOriginal) => {
  const fs = await importOriginal<typeof import("node:fs")>();
  const accessSync: typeof fs.accessSync = (path, mode) => {
    if (/[\\/]read-only$/.test(String(path))) throw Object.assign(new Error("EACCES"), { code: "EACCES" });
    fs.accessSync(path, mode);
  };
  return { ...fs, accessSync, default: { ...fs, accessSync } };
});

const cli = join(import.meta.dirname, "..", "src", "cli.ts");
const fresh = (ttlMs?: number) => buildFixture(join(mkdtempSync(join(tmpdir(), "check-")), "fx"), ttlMs);
const edit = (configFile: string, f: (c: Record<string, unknown>) => void) => {
  const c = JSON.parse(readFileSync(configFile, "utf8")) as Record<string, unknown>;
  f(c);
  writeFileSync(configFile, JSON.stringify(c, null, 2));
};
const errors = (fs: CheckFinding[]) => fs.filter((f) => f.level === "error");
const warns = (fs: CheckFinding[]) => fs.filter((f) => f.level === "warn");
const finding = (level: CheckFinding["level"], check: string, text: string) => expect.objectContaining({ level, check, message: expect.stringContaining(text) });

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
  it.each<{ name: string; bad: (fx: ReturnType<typeof fresh>) => void; level: CheckFinding["level"]; check: string; text: string }>([
    { name: "a config that is not JSON", bad: (fx) => writeFileSync(fx.configFile, "{"), level: "error", check: "config", text: "not readable JSON" },
    { name: "a gateway key readable by others", bad: (fx) => chmodSync(join(fx.dir, "keys", "gateway.key"), 0o644), level: "warn", check: "key", text: "readable by other users" },
    { name: "a gateway key that does not load", bad: (fx) => writeFileSync(join(fx.dir, "keys", "gateway.key"), "not a key"), level: "error", check: "key", text: "gateway.key" },
    { name: "an unset upstream token", bad: (fx) => edit(fx.configFile, (c) => { c.upstream = { url: "http://127.0.0.1:9/mcp", tokenEnv: "CHECK_TEST_UPSTREAM_TOKEN_UNSET" }; }), level: "error", check: "environment", text: "upstream upstream: the variable CHECK_TEST_UPSTREAM_TOKEN_UNSET" },
    { name: "an unset A2A header variable", bad: (fx) => edit(fx.configFile, (c) => { c.upstream = { a2a: { url: "http://127.0.0.1:9", headerEnv: { authorization: "CHECK_TEST_A2A_UNSET" } } }; }), level: "error", check: "environment", text: "CHECK_TEST_A2A_UNSET" },
    { name: "an unset capture key variable", bad: (fx) => edit(fx.configFile, (c) => { c.captureKeyEnv = "CHECK_TEST_CAPTURE_KEY_UNSET"; }), level: "error", check: "environment", text: "capture: the variable CHECK_TEST_CAPTURE_KEY_UNSET" },
    { name: "a revokedGrants file that is not an array", bad: (fx) => { writeFileSync(join(fx.dir, "revoked.json"), "{}"); edit(fx.configFile, (c) => { c.revokedGrants = "revoked.json"; }); }, level: "error", check: "revokedGrants", text: "denies every call" },
    { name: "a grant no trusted principal signed", bad: (fx) => edit(fx.configFile, (c) => { c.trustedPrincipalKeys = ["keys/upstream.pub"]; }), level: "error", check: "grant", text: "grant.json" },
    { name: "a grant file that is not JSON", bad: (fx) => writeFileSync(join(fx.dir, "grant.json"), "{"), level: "error", check: "grant", text: "JSON" },
  ])("$name: $level on $check", async ({ bad, level, check, text }) => {
    const fx = fresh();
    bad(fx);
    expect(await checkConfig(fx.configFile)).toContainEqual(finding(level, check, text));
  });

  it("receiptsDir and logFile under a directory that cannot be written are errors", async () => {
    const fx = fresh();
    mkdirSync(join(fx.dir, "read-only"));
    edit(fx.configFile, (c) => { c.receiptsDir = "read-only/receipts"; c.logFile = "read-only/log.jsonl"; });
    const r = await checkConfig(fx.configFile);
    expect(r).toContainEqual(finding("error", "paths", "receiptsDir"));
    expect(r).toContainEqual(finding("error", "paths", "logFile"));
    expect(r.some((f) => f.check === "paths" && f.level === "ok")).toBe(false);
  });

  it("--connect names an approvals tool that no upstream offers", async () => {
    const fx = fresh();
    edit(fx.configFile, (c) => { c.approvals = { trustedKeys: ["keys/principal.pub"], usedDir: "used", tools: [{ tool: "approve.missing" }] }; });
    expect(await checkConfig(fx.configFile, { connect: true })).toContainEqual(finding("error", "tool names", 'approvals names "approve.missing"'));
  });

  // The gateway refuses an operations or reconcile tool that no upstream offers before the tool names are compared.
  it("--connect reports an operations reconcile tool that no upstream offers as a gateway that would not start", async () => {
    const fx = fresh();
    edit(fx.configFile, (c) => {
      c.operations = { database: "operations.sqlite", budgets: [{ id: "refunds", currency: "GBP", limit: 100000 }], tools: [{ tool: "stripe.refund", budget: "refunds", reconcile: { tool: "lookup.missing", args: { key: "$operation.idempotencyKey" }, statusPath: "status", confirmed: ["succeeded"], failed: ["failed"] } }] };
    });
    expect(await checkConfig(fx.configFile, { connect: true })).toContainEqual(finding("error", "upstreams", "reconciliation must name an advertised read tool"));
  });
});

describe("agent-custody check on a door config", () => {
  const door = () => buildDoorFixture(join(mkdtempSync(join(tmpdir(), "check-door-")), "fx"), "http://127.0.0.1:9");

  it.each<{ name: string; bad: (fx: DoorFixture) => void; level: CheckFinding["level"]; check: string; text: string }>([
    { name: "a config that is not JSON", bad: (fx) => writeFileSync(fx.configFile, "{"), level: "error", check: "config", text: "not readable JSON" },
    { name: "a schema issue", bad: (fx) => edit(fx.configFile, (c) => { c.routes = [{ name: "a", path: "/a" }, { name: "a", path: "/b" }]; }), level: "error", check: "config", text: "route names must be unique" },
    { name: "a door key that does not exist", bad: (fx) => edit(fx.configFile, (c) => { c.identity = { keyFile: "keys/none.key" }; }), level: "warn", check: "key", text: "does not exist yet" },
    { name: "a door key readable by others", bad: (fx) => chmodSync(join(fx.dir, "keys", "door.key"), 0o644), level: "warn", check: "key", text: "readable by other users" },
    { name: "a door key that does not load", bad: (fx) => writeFileSync(join(fx.dir, "keys", "door.key"), "not a key"), level: "error", check: "key", text: "door.key" },
    { name: "a principal key that does not load", bad: (fx) => edit(fx.configFile, (c) => { c.trustedPrincipalKeys = ["keys/nobody.pub"]; }), level: "error", check: "principal keys", text: "nobody.pub" },
    { name: "a missing policy", bad: (fx) => edit(fx.configFile, (c) => { c.policyFile = "nope.cedar"; }), level: "error", check: "policy", text: "does not exist" },
    { name: "a policy with no permit rule", bad: (fx) => writeFileSync(join(fx.dir, "policy.cedar"), 'forbid(principal, action == Action::"refund", resource);\n'), level: "warn", check: "policy", text: "no permit rule" },
    { name: "observe mode", bad: (fx) => edit(fx.configFile, (c) => { c.mode = "observe"; }), level: "warn", check: "mode", text: "observe mode" },
    { name: "no routes", bad: (fx) => edit(fx.configFile, (c) => { c.routes = []; }), level: "warn", check: "routes", text: "no routes" },
    { name: "an unset log token variable", bad: (fx) => edit(fx.configFile, (c) => { c.log = { url: "https://log.example.com/t/x/", tokenEnv: "CHECK_TEST_DOOR_LOG_TOKEN_UNSET", keys: ["keys/principal.pub"] }; delete c.logFile; }), level: "error", check: "credentials", text: "CHECK_TEST_DOOR_LOG_TOKEN_UNSET" },
    { name: "a log key that does not exist", bad: (fx) => edit(fx.configFile, (c) => { c.log = { url: "https://log.example.com/t/x/", keys: ["keys/none.pub"] }; delete c.logFile; }), level: "error", check: "log keys", text: "none.pub" },
  ])("$name: $level on $check", ({ bad, level, check, text }) => {
    const fx = door();
    bad(fx);
    expect(checkDoorConfig(fx.configFile)).toContainEqual(finding(level, check, text));
  });

  it("receiptsDir and logFile under a directory that cannot be written are errors", () => {
    const fx = door();
    mkdirSync(join(fx.dir, "read-only"));
    edit(fx.configFile, (c) => { c.receiptsDir = "read-only/receipts"; c.logFile = "read-only/log.jsonl"; });
    const r = checkDoorConfig(fx.configFile);
    expect(r).toContainEqual(finding("error", "paths", "receipts"));
    expect(r).toContainEqual(finding("error", "paths", "log.jsonl cannot be written"));
    expect(r.some((f) => f.check === "paths" && f.level === "ok")).toBe(false);
  });
});
