// `agent-custody check`: what a gateway config would fail on at startup, found before it starts. Static checks read the
// config, the keys, the policy, the grant, the environment, and the paths; --connect also starts the upstreams, which
// is where tool-name collisions and unreachable servers show up, and compares every tool name the config mentions with
// the tools the upstreams actually offer.
import * as cedar from "@cedar-policy/cedar-wasm/nodejs";
import { accessSync, constants, existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, isAbsolute, join, resolve } from "node:path";
import { DoorConfigSchema, GatewayConfigSchema, loadConfig, loadDoorConfig, strictRefusals, type GatewayConfig } from "./config.ts";
import { generateKeyPair, loadPrivateKey, loadPublicKey, writeKeyPair, type Envelope, type PublicKeyRef } from "./crypto.ts";
import { delegationValidAt, verifyDelegation } from "./delegation.ts";
import { hasPermitRule } from "./policy.ts";
import { compileRego, isRegoFile } from "./policy-rego.ts";
import { createOpaServerPolicy } from "./opa-server.ts";
import { createGatewayHost } from "./gateway.ts";

export interface CheckFinding {
  level: "ok" | "warn" | "error";
  check: string;
  message: string;
}

export interface CheckOptions {
  /** start the upstreams and compare tool names with what they offer */
  connect?: boolean;
  /**
   * "check" (the default) requires every credential variable the config names to be set in this process. "skip" is for a
   * process that is not the gateway and deliberately does not hold its credentials, such as the console: they are not
   * checked, and an upstream that needs one is not started.
   */
  environment?: "check" | "skip";
  /** cancels --connect while it is starting the upstreams; whatever was started is closed */
  signal?: AbortSignal;
}

const distance = (a: string, b: string): number => {
  const row = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let prev = row[0]!;
    row[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const keep = row[j]!;
      row[j] = Math.min(row[j]! + 1, row[j - 1]! + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = keep;
    }
  }
  return row[b.length]!;
};

/** the nearest existing directory above a path, to ask whether something can be created there */
function writableAncestor(path: string): string | null {
  let dir = resolve(path);
  while (!existsSync(dir)) {
    const up = dirname(dir);
    if (up === dir) return null;
    dir = up;
  }
  try {
    accessSync(dir, constants.W_OK);
    return dir;
  } catch {
    return null;
  }
}

function onPath(command: string): boolean {
  if (isAbsolute(command) || command.includes("/")) return existsSync(command);
  return (process.env.PATH ?? "").split(delimiter).some((d) => d && existsSync(join(d, command)));
}

/** True when the file is a door config rather than a gateway config: it names an origin, which no gateway config has. */
export function isDoorConfig(configPath: string): boolean {
  try {
    const raw = JSON.parse(readFileSync(configPath, "utf8")) as unknown;
    return !!raw && typeof raw === "object" && !Array.isArray(raw) && "origin" in raw && !("upstream" in raw) && !("upstreams" in raw);
  } catch {
    return false;
  }
}

/**
 * The agents named by permits that do not also require a verified arrival. At the door the principal is the agent of a
 * verified grant, or `unknown`, so such a permit admits only a verified agent; the warning is for the reader who
 * expects it to admit a declared name, as the same text would at the gateway.
 */
export function permitsNamingAgentWithoutVerifiedArrival(policyText: string): string[] {
  const parts = cedar.policySetTextToParts(policyText);
  if (parts.type !== "success") return [];
  const out: string[] = [];
  for (const policy of parts.policies) {
    const j = cedar.policyToJson(policy);
    if (j.type !== "success" || j.json.effect !== "permit") continue;
    const principal = j.json.principal as { op: string; entity?: { type: string; id: string } };
    if (principal.op === "All" || !principal.entity) continue;
    const conditions = JSON.stringify(j.json.conditions ?? []);
    if (conditions.includes('"class"') && conditions.includes('"verified"')) continue;
    out.push(`${principal.entity.type}::"${principal.entity.id}"`);
  }
  return out;
}

/** `agent-custody check` on a door config: what the door would fail on at startup, and what it would silently do less than the config seems to promise. */
export function checkDoorConfig(configPath: string): CheckFinding[] {
  const out: CheckFinding[] = [];
  const add = (level: CheckFinding["level"], check: string, message: string) => out.push({ level, check, message });
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(configPath, "utf8"));
  } catch (e) {
    add("error", "config", `${configPath} is not readable JSON: ${e instanceof Error ? e.message : String(e)}`);
    return out;
  }
  const known = Object.keys(DoorConfigSchema.shape);
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    for (const key of Object.keys(raw)) {
      if (known.includes(key)) continue;
      const near = known.find((k) => distance(k.toLowerCase(), key.toLowerCase()) <= 2);
      add("error", "config", `unknown key "${key}" is ignored by the door${near ? `; did you mean "${near}"?` : ""} A mistyped key leaves the setting it was meant for at its default`);
    }
  }
  const parsed = DoorConfigSchema.safeParse(raw);
  if (!parsed.success) {
    for (const issue of parsed.error.issues) add("error", "config", `${issue.path.join(".") || "(root)"}: ${issue.message}`);
    return out;
  }
  add("ok", "config", "the config parses");
  const cfg = loadDoorConfig(configPath);
  if (!existsSync(cfg.identity.keyFile)) add("warn", "key", `${cfg.identity.keyFile} does not exist yet; \`agent-custody keygen\` creates it`);
  else {
    try {
      loadPrivateKey(cfg.identity.keyFile);
      add("ok", "key", `the door key at ${cfg.identity.keyFile} loads`);
      if (process.platform !== "win32" && (statSync(cfg.identity.keyFile).mode & 0o077) !== 0) add("warn", "key", `${cfg.identity.keyFile} is readable by other users; make it mode 0600`);
    } catch (e) {
      add("error", "key", `${cfg.identity.keyFile}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  let principals = 0;
  for (const f of cfg.trustedPrincipalKeys) {
    try {
      loadPublicKey(f);
      principals++;
    } catch (e) {
      add("error", "principal keys", `${f}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  if (cfg.trustedPrincipalKeys.length === 0) add("warn", "principal keys", "no trusted principal keys: no arrival can be verified, every one is claimed or unknown");
  else if (principals === cfg.trustedPrincipalKeys.length) add("ok", "principal keys", `${principals} trusted principal key${principals === 1 ? "" : "s"} load`);
  if (!existsSync(cfg.policyFile)) add("error", "policy", `${cfg.policyFile} does not exist`);
  else {
    const text = readFileSync(cfg.policyFile, "utf8");
    const r = cedar.checkParsePolicySet({ staticPolicies: text });
    if (r.type !== "success") for (const e of r.errors) add("error", "policy", `${cfg.policyFile}: ${e.message}`);
    else if (!hasPermitRule(text)) add("warn", "policy", `${cfg.policyFile} has no permit rule, so every arrival is refused`);
    else {
      add("ok", "policy", "the policy parses");
      for (const name of permitsNamingAgentWithoutVerifiedArrival(text)) add("warn", "policy", `a permit names ${name} without requiring context.facts.arrival.class == "verified": the principal is that agent only for a verified grant, so this permit admits nothing else; if it was copied from a gateway policy, add the arrival condition`);
    }
  }
  if (cfg.mode === "observe") add("warn", "mode", "observe mode relays every arrival and records what the policy would have decided; nothing is refused by policy");
  add("ok", "precommit", cfg.precommit.includes("*") ? "every arrival is committed to the log before it is relayed" : `every POST, PUT, PATCH, and DELETE${cfg.precommit.length ? `, and every arrival at ${cfg.precommit.join(", ")},` : ""} is committed to the log before it is relayed`);
  if (cfg.routes.length === 0) add("warn", "routes", `no routes: every arrival is the action "${cfg.unmatchedRoute}"`);
  else add("ok", "routes", `${cfg.routes.length} route(s); unmatched arrivals are "${cfg.unmatchedRoute}"`);
  const origin = new URL(cfg.origin.url);
  if (origin.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(origin.hostname)) add("warn", "origin", `${cfg.origin.url} is plain HTTP to a remote host; the relayed traffic is not encrypted on that leg`);
  else add("ok", "origin", `relays to ${cfg.origin.url}`);
  for (const [, variable] of Object.entries(cfg.origin.headerEnv ?? {})) if (!process.env[variable]) add("error", "credentials", `origin header variable ${variable} is not set in this environment`);
  if (cfg.log?.tokenEnv && !process.env[cfg.log.tokenEnv]) add("error", "credentials", `log token variable ${cfg.log.tokenEnv} is not set in this environment`);
  if (cfg.splunk?.tokenEnv && !process.env[cfg.splunk.tokenEnv]) add("error", "credentials", `splunk token variable ${cfg.splunk.tokenEnv} is not set in this environment`);
  for (const v of Object.values(cfg.otel?.headersEnv ?? {})) if (!process.env[v]) add("error", "credentials", `otel header variable ${v} is not set in this environment`);
  for (const f of cfg.log?.keys ?? []) if (!existsSync(f)) add("error", "log keys", `${f} does not exist`);
  if (cfg.captureKeyEnv && !process.env[cfg.captureKeyEnv]) add("error", "credentials", `capture key variable ${cfg.captureKeyEnv} is not set in this environment`);
  if (cfg.challenge) {
    if (!process.env[cfg.challenge.secretEnv]) add("error", "credentials", `challenge secret variable ${cfg.challenge.secretEnv} is not set in this environment`);
    add("ok", "challenge", `${cfg.challenge.provider} tokens in the ${cfg.challenge.header} header are verified with the provider; the outcome is context.facts.arrival.challenge.outcome, and class is unchanged by it`);
  } else add("ok", "challenge", "no challenge: an unknown arrival has no way to become anything else on this door");
  const dir = writableAncestor(cfg.receiptsDir);
  if (!dir) add("error", "paths", `${cfg.receiptsDir} cannot be created: no writable directory above it`);
  else add("ok", "paths", `receipts go to ${cfg.receiptsDir}`);
  if (cfg.logFile) {
    const ldir = writableAncestor(cfg.logFile);
    if (!ldir) add("error", "paths", `${cfg.logFile} cannot be written`);
  }
  return out;
}

export async function checkConfig(configPath: string, options: CheckOptions = {}): Promise<CheckFinding[]> {
  const out: CheckFinding[] = [];
  const add = (level: CheckFinding["level"], check: string, message: string) => out.push({ level, check, message });

  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(configPath, "utf8"));
  } catch (e) {
    add("error", "config", `${configPath} is not readable JSON: ${e instanceof Error ? e.message : String(e)}`);
    return out;
  }

  const known = Object.keys(GatewayConfigSchema.shape);
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    for (const key of Object.keys(raw)) {
      if (known.includes(key)) continue;
      const near = known.find((k) => distance(k.toLowerCase(), key.toLowerCase()) <= 2);
      add("error", "config", `unknown key "${key}" is ignored by the gateway${near ? `; did you mean "${near}"?` : ""} A mistyped key leaves the setting it was meant for at its default`);
    }
  }

  const parsed = GatewayConfigSchema.safeParse(raw);
  if (!parsed.success) {
    for (const issue of parsed.error.issues) add("error", "config", `${issue.path.join(".") || "(root)"}: ${issue.message}`);
    return out;
  }
  add("ok", "config", "the config parses");
  const cfg: GatewayConfig = loadConfig(configPath);

  // the gateway's key
  if (!existsSync(cfg.identity.keyFile)) {
    add("warn", "key", `${cfg.identity.keyFile} does not exist yet; \`agent-custody keygen\` creates it, and the container creates it on first start`);
  } else {
    try {
      loadPrivateKey(cfg.identity.keyFile);
      add("ok", "key", `the gateway key at ${cfg.identity.keyFile} loads`);
      if (process.platform !== "win32" && (statSync(cfg.identity.keyFile).mode & 0o077) !== 0) add("warn", "key", `${cfg.identity.keyFile} is readable by other users; make it mode 0600`);
    } catch (e) {
      add("error", "key", `${cfg.identity.keyFile}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  // the principals whose grants are trusted
  const principals: PublicKeyRef[] = [];
  for (const f of cfg.trustedPrincipalKeys) {
    try {
      principals.push(loadPublicKey(f));
    } catch (e) {
      add("error", "principal keys", `${f}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  if (principals.length === cfg.trustedPrincipalKeys.length) add("ok", "principal keys", `${principals.length} trusted principal key${principals.length === 1 ? "" : "s"} load`);

  // the policy: an OPA server answers for its package, a Rego file compiles, a Cedar file parses
  if (cfg.opa) {
    let bundles: Record<string, string> = {};
    try {
      await createOpaServerPolicy(cfg.opa, (p) => { if (p.bundles) bundles = p.bundles; }).probe();
      add("ok", "policy", `the OPA server at ${cfg.opa.url} answers for data.${(cfg.opa.decision ?? "agentcustody").replaceAll("/", ".")}`);
      if (!Object.keys(bundles).length) add("warn", "policy", "the OPA server reports no bundle revision, so receipts cannot name the policy that decided; serve the policy from a bundle with a revision");
    } catch (e) {
      add("error", "policy", e instanceof Error ? e.message : String(e));
    }
  } else if (!cfg.policyFile || !existsSync(cfg.policyFile)) {
    add("error", "policy", `${cfg.policyFile} does not exist`);
  } else if (isRegoFile(cfg.policyFile)) {
    const errors = compileRego(readFileSync(cfg.policyFile, "utf8")).errors;
    for (const e of errors) add("error", "policy", `${cfg.policyFile}: ${e}`);
    if (!errors.length) add("ok", "policy", "the Rego policy compiles");
  } else {
    const text = readFileSync(cfg.policyFile, "utf8");
    const r = cedar.checkParsePolicySet({ staticPolicies: text });
    if (r.type !== "success") for (const e of r.errors) add("error", "policy", `${cfg.policyFile}: ${e.message}`);
    else if (!hasPermitRule(text)) add("warn", "policy", `${cfg.policyFile} has no permit rule, so every call is denied`);
    else add("ok", "policy", "the policy parses");
  }
  if (cfg.mode === "observe") add("warn", "mode", "observe mode forwards every call the grant allows and records what the policy would have decided; nothing is denied by policy");

  // credentials: a variable the config names must be set where the gateway runs
  const envNames: [string, string][] = [];
  for (const u of cfg.upstreams ?? (cfg.upstream ? [{ name: "upstream", ...cfg.upstream }] : [])) {
    const name = "name" in u ? u.name : "upstream";
    if ("tokenEnv" in u && u.tokenEnv) envNames.push([`upstream ${name}`, u.tokenEnv]);
    if ("rest" in u) for (const v of Object.values(u.rest.headerEnv ?? {})) envNames.push([`upstream ${name}`, v]);
    if ("a2a" in u) for (const v of Object.values(u.a2a.headerEnv ?? {})) envNames.push([`upstream ${name}`, v]);
  }
  if (cfg.log?.tokenEnv) envNames.push(["log", cfg.log.tokenEnv]);
  if (cfg.splunk?.tokenEnv) envNames.push(["splunk", cfg.splunk.tokenEnv]);
  for (const v of Object.values(cfg.otel?.headersEnv ?? {})) envNames.push(["otel", v]);
  if (cfg.captureKeyEnv) envNames.push(["capture", cfg.captureKeyEnv]);
  if (cfg.opa?.tokenEnv) envNames.push(["opa", cfg.opa.tokenEnv]);
  const skipEnvironment = options.environment === "skip";
  const missing = skipEnvironment ? [] : envNames.filter(([, v]) => !process.env[v]);
  for (const [who, v] of missing) add("error", "environment", `${who}: the variable ${v} is not set here, and a gateway does not start without it`);
  if (envNames.length && skipEnvironment) add("ok", "environment", `not checked here: this process does not hold the gateway's credentials (${[...new Set(envNames.map(([, v]) => v))].join(", ")}); run agent-custody check where the gateway runs`);
  else if (envNames.length && !missing.length) add("ok", "environment", `${envNames.length} credential variable${envNames.length === 1 ? " is" : "s are"} set`);

  // stdio upstreams: the command must exist where the gateway runs
  for (const u of cfg.upstreams ?? (cfg.upstream ? [{ name: "upstream", ...cfg.upstream }] : [])) {
    if ("command" in u && !onPath(u.command)) add("error", "upstream", `${"name" in u ? u.name : "upstream"}: the command "${u.command}" is not on the PATH or at that path; in a container it must be inside the image`);
  }

  // a script or file a stdio upstream is started with has to be where the gateway runs, which in a container is inside the image
  for (const u of cfg.upstreams ?? (cfg.upstream ? [{ name: "upstream", ...cfg.upstream }] : [])) {
    if (!("command" in u)) continue;
    for (const a of u.args) if ((a.startsWith("/") || a.startsWith("./")) && !existsSync(a)) add("warn", "upstream", `${"name" in u ? u.name : "upstream"}: the argument ${a} does not exist here; if it is a file the upstream needs, it must be inside the image`);
  }

  // a REST tool with an idempotency header is a financial operation: every call to it fails unless `operations` configures it
  const operationTools = new Set((cfg.operations?.tools ?? []).map((t) => t.tool));
  for (const u of cfg.upstreams ?? (cfg.upstream ? [{ name: "upstream", ...cfg.upstream }] : [])) {
    if (!("rest" in u)) continue;
    for (const t of u.rest.tools) {
      if (t.idempotencyHeader && !operationTools.has(t.name)) add("error", "upstream", `${"name" in u ? u.name : "upstream"}: the tool ${t.name} sets idempotencyHeader, which makes it a financial operation, and every call to it fails unless it is also listed under "operations"; remove idempotencyHeader, or configure it under operations (financial-operations.md)`);
    }
  }

  // where the gateway writes
  const writes: [string, string][] = [["receiptsDir", cfg.receiptsDir]];
  if (cfg.operations) writes.push(["operations.database", cfg.operations.database]);
  if (cfg.approvals) writes.push(["approvals.usedDir", cfg.approvals.usedDir]);
  if (cfg.logFile) writes.push(["logFile", cfg.logFile]);
  if (cfg.revokedGrants) writes.push(["revokedGrants", cfg.revokedGrants]);
  let writable = true;
  for (const [key, path] of writes) {
    if (!writableAncestor(path)) {
      writable = false;
      add("error", "paths", `${key} ${path} cannot be created or written; in a container, use an absolute path under /data (/config is read-only)`);
    }
  }
  if (writable) add("ok", "paths", "every path the gateway writes can be written");
  if (cfg.revokedGrants && existsSync(cfg.revokedGrants)) {
    try {
      if (!Array.isArray(JSON.parse(readFileSync(cfg.revokedGrants, "utf8")))) throw new Error("expected a JSON array of grant digests");
    } catch (e) {
      add("error", "revokedGrants", `${cfg.revokedGrants}: ${e instanceof Error ? e.message : String(e)}; a revocation file that cannot be read denies every call`);
    }
  }

  // the grant a single-grant gateway serves
  let scopes: string[] = [];
  if (cfg.grantFile) {
    try {
      const env = JSON.parse(readFileSync(cfg.grantFile, "utf8")) as Envelope;
      const v = verifyDelegation(env, principals);
      if (!v.ok) add("error", "grant", `${cfg.grantFile}: ${v.error}`);
      else {
        scopes = v.delegation.scopes;
        const now = new Date().toISOString();
        if (!delegationValidAt(v.delegation, now)) add("error", "grant", `${cfg.grantFile} for ${v.delegation.agent} is outside its validity window (${v.delegation.issuedAt} to ${v.delegation.expiresAt})`);
        else if (Date.parse(v.delegation.expiresAt) - Date.now() < 24 * 3600_000) add("warn", "grant", `${cfg.grantFile} for ${v.delegation.agent} expires at ${v.delegation.expiresAt}`);
        else add("ok", "grant", `the grant for ${v.delegation.agent} verifies; scopes: ${scopes.join(", ")}`);
      }
    } catch (e) {
      add("error", "grant", `${cfg.grantFile}: ${e instanceof Error ? e.message : String(e)}`);
    }
  } else {
    add("ok", "grant", "no grantFile: each connection over HTTP presents its own grant");
  }

  // what a log outage costs
  if (cfg.strict) add("ok", "strict", "strict mode: every call is precommitted to a remote, hash-only log with pinned keys, and no receipt goes to the outbox");
  else {
    const refused = strictRefusals(cfg);
    add("ok", "strict", refused.length ? `strict mode is off; turned on, it would refuse: ${refused.join("; ")}` : "strict mode is off; this config would also run strict");
  }
  if (cfg.log && !cfg.precommit.length && !cfg.strict) add("warn", "precommit", "a remote log is set and precommit is empty: every call is forwarded before its receipt is logged, so a log outage after a call puts its receipt in the outbox and the side effect is in the log only later. Name the consequential tools in precommit, or [\"*\"]; requirePrecommit makes this an error");

  // tool names the config mentions, against the tools the upstreams offer
  const mentioned = (): [string, string][] => [
    ...cfg.precommit.filter((t) => t !== "*").map((t): [string, string] => ["precommit", t]),
    ...cfg.facts.flatMap((f): [string, string][] => [["facts", f.tool], ...f.forTools.map((t): [string, string] => ["facts.forTools", t])]),
    ...(cfg.approvals?.tools ?? []).map((t): [string, string] => ["approvals", t.tool]),
    ...(cfg.operations?.tools ?? []).flatMap((t): [string, string][] => [["operations", t.tool], ["operations.reconcile", t.reconcile.tool]]),
    ...scopes.map((t): [string, string] => ["grant scope", t]),
  ];

  if (!options.connect) {
    add("warn", "upstreams", "not started: run with --connect to start the upstreams, catch tool-name collisions and unreachable servers, and compare the tool names above with the tools offered");
    return out;
  }

  // a gateway key that does not exist yet (the container creates it on first start) must not stop the upstreams being tried
  if (skipEnvironment && envNames.length) {
    add("warn", "upstreams", "not started: the upstreams need credentials that this process does not hold, by design. Run `agent-custody check --connect` where the gateway runs, for example `docker compose exec gateway agent-custody check --config /config/gateway.json --connect`");
    return out;
  }
  let connectCfg = cfg;
  let scratch: string | undefined;
  if (!existsSync(cfg.identity.keyFile)) {
    scratch = mkdtempSync(join(tmpdir(), "agent-custody-check-"));
    connectCfg = { ...cfg, identity: { keyFile: writeKeyPair(generateKeyPair(), scratch, "check").keyFile } };
  }
  let tools: string[] | undefined;
  try {
    const host = await createGatewayHost(connectCfg, options.signal ? { signal: options.signal } : {});
    try {
      tools = host.tools();
    } finally {
      await host.close();
    }
    add("ok", "upstreams", `the upstreams start and offer ${tools.length} tool${tools.length === 1 ? "" : "s"}: ${tools.join(", ")}`);
  } catch (e) {
    add("error", "upstreams", `the gateway would not start: ${e instanceof Error ? e.message : String(e)}`);
  } finally {
    if (scratch) rmSync(scratch, { recursive: true, force: true });
  }
  if (tools) {
    const unknown = mentioned().filter(([, t]) => !tools!.includes(t));
    // a scope that names nothing is harmless; a precommit name that matches nothing leaves that tool forwarded with no authorization committed first
    for (const [where, t] of unknown) add(where === "grant scope" ? "warn" : "error", "tool names", `${where} names "${t}", which no upstream offers${where === "precommit" ? "; the tool you meant is forwarded before it is logged" : ""}`);
    if (!unknown.length) add("ok", "tool names", "every tool the config and the grant name is offered by an upstream");
  }
  return out;
}

export function formatFindings(findings: CheckFinding[]): string {
  const mark = { ok: "ok   ", warn: "warn ", error: "ERROR" } as const;
  const lines = findings.map((f) => `${mark[f.level]} ${f.check}: ${f.message}`);
  const errors = findings.filter((f) => f.level === "error").length;
  const warns = findings.filter((f) => f.level === "warn").length;
  lines.push("", errors ? `${errors} error${errors === 1 ? "" : "s"}, ${warns} warning${warns === 1 ? "" : "s"}: the gateway would not start cleanly` : `no errors, ${warns} warning${warns === 1 ? "" : "s"}`);
  return lines.join("\n");
}
