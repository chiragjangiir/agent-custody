// The MCP gateway: sits between an agent and its upstreams, MCP servers or REST APIs, enforces scope + Cedar policy,
// and emits a signed, logged receipt for every tool call, allowed or denied.
import { randomUUID } from "node:crypto";
import { appendFileSync, closeSync, existsSync, fstatSync, mkdirSync, openSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema, type CallToolResult, type Tool } from "@modelcontextprotocol/sdk/types.js";
import { strictRefusals, type FactConfig, type GatewayConfig, type UpstreamConfig } from "./config.ts";
import { digestOf, dsseVerifiers, dsseVerify, loadPrivateKey, loadPublicKey, type Envelope } from "./crypto.ts";
import { delegationValidAt, grantChainDigests, verifyDelegation, type Delegation } from "./delegation.ts";
import { APPROVAL_META_KEY, DEFAULT_APPROVAL_LIFETIME_SECONDS, consumeApproval, verifyApproval, verifyApprovalStatement } from "./approval.ts";
import { createIssuer, ReceiptPending, type FlushResult, type PreparedReceipt } from "./issue.ts";
import { openLog, type LogSink } from "./log-sink.ts";
import { openExporter, type ReceiptExporter } from "./otel.ts";
import { upstreamEvidenceOf } from "./upstream.ts";
import { restUpstream, type UpstreamClient } from "./rest.ts";
import { a2aUpstream } from "./a2a.ts";
import { captureKeyFrom, effectiveRule } from "./capture.ts";
import { evaluate, hasPermitRule, policyDigest, policyParseErrors, type PolicyDecision } from "./policy.ts";
import { compileRego, evaluateRego, isRegoFile, type RegoPolicy } from "./policy-rego.ts";
import { createOpaServerPolicy } from "./opa-server.ts";
import type { ApprovalRecord, AuthorizationBundle, AuthorizationPredicate, FactRecord, OperationEvidence, ReceiptBundle, ReceiptPredicate, ReceiptStatement } from "./receipt.ts";
import { OPERATION_META_KEY, OperationStore, ownerAlive, type OperationRecord, type OperationStatus } from "./operations.ts";

export const GATEWAY_VERSION = "0.1.0";
export const RECEIPT_META_KEY = "agent-custody/receipt";
export const MODEL_META_KEY = "agent-custody/model";
/** true on a result whose receipt is signed and kept in the outbox, and not yet in the log */
export const LOG_PENDING_META_KEY = "agent-custody/log-pending";
/** Set by the gateway on the answer to a retry of a financial operation: the receipt of the retry itself. `agent-custody/receipt` stays the receipt that holds the operation's outcome. */
export const RETRY_RECEIPT_META_KEY = "agent-custody/retry-receipt";
/** Set by the gateway on the call it forwards upstream: the receipt id, and the agent and principal from the attested grant. */
export const AGENT_META_KEY = "agent-custody/agent";
export const PRINCIPAL_META_KEY = "agent-custody/principal";
/** Set by the gateway on the forwarded call: the values of the facts it fetched itself for this call, by name, so an upstream can check a claimed value against what the gateway observed. */
export const OBSERVED_META_KEY = "agent-custody/observed";
/** Set by an upstream on its result: the ids of the facts it served in this call. The gateway remembers them for the session. */
export const FACTS_META_KEY = "agent-custody/facts";

export interface CallParams {
  name: string;
  arguments?: Record<string, unknown>;
  _meta?: Record<string, unknown>;
}

export interface Gateway {
  agentId: string;
  delegation: Delegation;
  /** sha256 over the grant's signed payload (`grantDigest` in delegation.ts): what `revoke` names */
  grantDigest: string;
  /** null while the grant is in force at `at` (default now); otherwise why it is not: "has expired", "is not yet valid", "has been revoked" */
  grantProblem(at?: string): string | null;
  listTools(): Promise<Tool[]>;
  handleCall(params: CallParams): Promise<CallToolResult>;
  close(): Promise<void>;
}

/** Returns null when an optional lookup references a call argument that is absent. */
function resolveFactArgs(template: Record<string, string>, args: Record<string, unknown>, optional = false): Record<string, unknown> | null {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(template)) {
    if (v.startsWith("$args.")) {
      const key = v.slice("$args.".length);
      if (!(key in args) || args[key] === undefined) {
        if (optional) return null;
        throw new Error(`fact argument "${k}" needs call argument "${key}", which is missing`);
      }
      out[k] = args[key];
    } else {
      out[k] = v;
    }
  }
  return out;
}

/** First text content item, JSON-parsed when possible. Tool results carry no signature, so this is "observed", never "attested". */
function extractValue(result: CallToolResult): unknown {
  const text = result.content.find((c) => c.type === "text");
  if (!text || text.type !== "text") return null;
  try {
    return JSON.parse(text.text);
  } catch {
    return text.text;
  }
}

/** Match both verifiers: dot paths traverse own properties of JSON objects, never arrays or prototypes. */
function providerField(result: CallToolResult, path: string): unknown {
  return path.split(".").reduce<unknown>((value, part) => value && typeof value === "object" && !Array.isArray(value) && Object.hasOwn(value, part) ? (value as Record<string, unknown>)[part] : undefined, extractValue(result));
}

/**
 * The environment a stdio upstream is started with: what a child process needs to run, plus what the config names.
 * Never the gateway's own environment, which holds the tokens other upstreams and the log are given. An explicit
 * `env` in the config is added to this base, not to the gateway's variables.
 */
export function upstreamEnv(extra?: Record<string, string>): Record<string, string> {
  const base: Record<string, string> = {};
  for (const k of ["PATH", "HOME", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL", "SystemRoot", "SYSTEMROOT", "USERPROFILE", "APPDATA", "NODE_OPTIONS"]) {
    const v = process.env[k];
    if (v !== undefined) base[k] = v;
  }
  return { ...base, ...(extra ?? {}) };
}

export interface GatewayOptions {
  /** the log to append to, in place of the one the config names; for embedding and tests */
  log?: LogSink;
  /** told about every receipt after it is written, in place of the exporter the config names */
  exporter?: ReceiptExporter;
  /** cancels the start while it is connecting to the upstreams: every upstream already started is closed and the call rejects */
  signal?: AbortSignal;
  /**
   * Appends the outbox at start and every 30 seconds. Only a gateway that serves sets it: `check` and `reconcile` open
   * a host too, and must not append to the log or touch the outbox of a gateway that runs.
   */
  autoFlush?: boolean;
}

/**
 * The shared part of a gateway: the key, the policy, the issuer, the log, the upstreams, and the fact lookups. One host
 * serves many sessions, each opened with its own grant; over stdio there is exactly one, over HTTP one per connection.
 */
export interface GatewayHost {
  keyid: string;
  /** a session for this grant: the grant is verified against the trusted principal keys and its validity window first */
  open(grantEnvelope: Envelope): Gateway;
  /** revokes a grant by its digest: every session under it refuses its next call, and no new session opens for it. Written to the config's revokedGrants file when there is one. */
  revoke(grantDigest: string): void;
  /** the digests revoked so far */
  revoked(): string[];
  /** sha256 of the policy in force: the one the next call is evaluated under */
  policyDigest(): string;
  /** the names of every tool the upstreams offer, before any grant narrows them */
  tools(): string[];
  /** Operator-only provider lookup. Never exposed as an agent tool. Unknown/pending reservations remain held until a terminal reconciliation receipt is committed. */
  reconcile(operationId: string): Promise<ReceiptBundle>;
  /** Appends the receipts in the outbox, whose log append failed. A host opened with `autoFlush` also runs it at start and every 30 seconds; `close()` waits for a flush that runs. */
  flushOutbox(): Promise<FlushResult>;
  /** the receipts in the outbox */
  pendingReceipts(): number;
  /** closes the upstreams; every session opened from this host is finished with */
  close(): Promise<void>;
}

/** Writes the revocation list whole, by rename, so a gateway re-reading it never sees half a file. */
export function writeRevokedGrants(path: string, digests: string[]): void {
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(digests, null, 2) + "\n");
  renameSync(tmp, path);
}

export async function createGatewayHost(cfg: GatewayConfig, options: GatewayOptions = {}): Promise<GatewayHost> {
  const gatewayKey = loadPrivateKey(cfg.identity.keyFile);
  const trusted = cfg.trustedPrincipalKeys.map(loadPublicKey);
  const approvalKeys = cfg.approvals?.trustedKeys.map(loadPublicKey) ?? [];
  const approvalRule = (tool: string) => cfg.approvals?.tools.find((rule) => rule.tool === tool) ?? cfg.approvals?.tools.find((rule) => rule.tool === "*");
  // The policy file, Cedar or Rego, re-read whenever the file changes, like the revocation list. A Rego file is compiled
  // with the opa binary each time it changes, and a compile failure is refused like a Cedar file that does not parse.
  // A call is evaluated under the policy in force when it starts, and its receipt names that policy's digest. A changed
  // file that cannot be read or does not parse is refused and the policy in force stays: never an allow, and never a
  // fall back to no policy. Every change and every refusal is printed and appended to receiptsDir/policy-reloads.jsonl
  // with both digests and the time.
  // The bytes and the metadata come from one open file, so a rename between reading and stat'ing cannot pair them wrongly.
  // ctime is in the key because a program can set mtime back but not ctime, and every write moves it. A file written in
  // the last two seconds may still be being written within one timestamp tick, so its key is not kept: it is re-read on
  // each call until it settles, and a half-written file read meanwhile is replaced by the finished one.
  const keyOf = (st: { dev: number; ino: number; mtimeMs: number; ctimeMs: number; size: number }) => `${st.dev}:${st.ino}:${st.mtimeMs}:${st.ctimeMs}:${st.size}`;
  const settled = (st: { mtimeMs: number; ctimeMs: number }) => Date.now() - Math.max(st.mtimeMs, st.ctimeMs) >= 2000;
  const policyFile = cfg.policyFile ?? "";
  const rego = isRegoFile(policyFile);
  type Policy = { text: string; digest: string; rego?: RegoPolicy };
  const loadPolicy = (text: string): { policy: Policy; errors: [] } | { policy?: undefined; errors: string[] } => {
    const digest = policyDigest(text);
    if (!rego) {
      const errors = policyParseErrors(text);
      return errors.length ? { errors } : { policy: { text, digest }, errors: [] };
    }
    const compiled = compileRego(text);
    return compiled.policy ? { policy: { text, digest, rego: compiled.policy }, errors: [] } : { errors: compiled.errors };
  };
  const readPolicy = () => {
    const fd = openSync(policyFile, "r");
    try {
      const st = fstatSync(fd);
      const text = readFileSync(fd, "utf8");
      return { text, seen: settled(st) ? keyOf(st) : "" };
    } finally {
      closeSync(fd);
    }
  };
  const policyStat = () => keyOf(statSync(policyFile));
  const initialPolicy = cfg.policyFile ? readPolicy() : { text: "", seen: "" };
  let policyNow: Policy = { text: initialPolicy.text, digest: policyDigest(initialPolicy.text) };
  // A Cedar file that does not parse at start denies every call with the parse errors. A Rego file must compile: with
  // no wasm module there is nothing to evaluate, so the gateway does not start.
  if (rego) {
    const loaded = loadPolicy(initialPolicy.text);
    if (!loaded.policy) throw new Error(`agent-custody gateway: ${policyFile} does not compile: ${loaded.errors.join("; ")}`);
    policyNow = loaded.policy;
  }
  let policySeen = initialPolicy.seen;
  // A file that cannot be read is retried on every call, since restoring access changes none of its metadata; this
  // keeps the refusal from being printed and recorded on each of those calls.
  let unreadableSeen = "";
  // A file still settling is re-read on each call; a refusal is recorded once for the same bytes.
  let refusedDigest = "";
  const policyReloads = join(cfg.receiptsDir, "policy-reloads.jsonl");
  const recordReload = (entry: Record<string, unknown>) => {
    try {
      mkdirSync(cfg.receiptsDir, { recursive: true });
      appendFileSync(policyReloads, JSON.stringify({ at: new Date().toISOString(), ...(cfg.opa ? { opa: cfg.opa.url } : { file: policyFile }), ...entry }) + "\n");
    } catch (e) {
      console.error(`agent-custody gateway: cannot record the policy change in ${policyReloads}: ${e instanceof Error ? e.message : String(e)}`);
    }
  };
  const refuseReload = (to: string | null, errors: string[]) => {
    console.error(`agent-custody gateway: POLICY NOT RELOADED: ${policyFile} ${errors.join("; ")}; policy ${policyNow.digest} stays in force`);
    recordReload({ event: "refused", from: policyNow.digest, to, errors });
  };
  // An OPA server holds the policy itself. Every new provenance it reports is printed and recorded beside file reloads,
  // so each digest a receipt carries maps to the bundle revisions that decided it.
  const opaServer = cfg.opa ? createOpaServerPolicy(cfg.opa, (p) => {
    const warnings = p.bundles === null ? ["the OPA server did not answer: the calls it left undecided are denied under this digest"]
      : Object.keys(p.bundles).length ? [] : ["the OPA server reports no bundle revision, so receipts cannot name the policy that decided"];
    console.error(`agent-custody gateway: OPA policy ${p.digest} at ${p.decision}: ${JSON.stringify(p.bundles)}${warnings.length ? `; WARNING: ${warnings.join("; ")}` : ""}`);
    recordReload({ event: "opa-provenance", to: p.digest, decision: p.decision, bundles: p.bundles, ...(warnings.length ? { warnings } : {}) });
  }) : undefined;
  if (opaServer) await opaServer.probe();
  const currentPolicy = (): Policy => {
    if (opaServer) return { text: "", digest: opaServer.digest() };
    const unreadable = (seen: string, e: unknown) => {
      if (unreadableSeen !== seen) refuseReload(null, [`cannot be read (${e instanceof Error ? e.message : String(e)})`]);
      unreadableSeen = seen;
      return policyNow;
    };
    let seen: string;
    try {
      seen = policyStat();
    } catch (e) {
      return unreadable("missing", e);
    }
    if (seen === policySeen) return policyNow;
    let read: { text: string; seen: string };
    try {
      read = readPolicy();
    } catch (e) {
      return unreadable(seen, e);
    }
    unreadableSeen = "";
    policySeen = read.seen;
    const text = read.text;
    const digest = policyDigest(text);
    if (digest === policyNow.digest) return policyNow;
    if (digest === refusedDigest) return policyNow;
    const loaded = loadPolicy(text);
    if (!loaded.policy) {
      refusedDigest = digest;
      refuseReload(digest, [`does not ${rego ? "compile" : "parse"}: ${loaded.errors.join("; ")}`]);
      return policyNow;
    }
    refusedDigest = "";
    // a policy with no permit rule parses and denies every call: fail-closed, but never a reload to pass over quietly
    const warnings = rego || hasPermitRule(text) ? [] : ["no permit rule: every call is denied"];
    console.error(`agent-custody gateway: policy reloaded from ${policyFile}: ${policyNow.digest} -> ${digest}${warnings.length ? `; WARNING: ${warnings.join("; ")}` : ""}`);
    recordReload({ event: "reloaded", from: policyNow.digest, to: digest, ...(warnings.length ? { warnings } : {}) });
    policyNow = loaded.policy;
    return policyNow;
  };
  // Private evidence: the key that encrypts withheld fields, read once; a rule in mode encrypted without it is a config error.
  const captureKey = cfg.captureKeyEnv ? captureKeyFrom(process.env[cfg.captureKeyEnv] ?? (() => { throw new Error(`capture key: environment variable ${cfg.captureKeyEnv} is not set`); })()) : undefined;
  for (const [tool, rule] of Object.entries(cfg.capture ?? {})) {
    for (const side of [rule.args, rule.result, rule.facts]) if (side?.mode === "encrypted" && !captureKey) throw new Error(`capture for ${tool} uses mode encrypted, which needs captureKeyEnv`);
  }
  // The rules are applied by the issuer to every statement it signs, the authorization included: the gateway hands it the call in full.
  if (cfg.strict) {
    const refused = strictRefusals(cfg);
    if (refused.length) throw new Error(`agent-custody gateway: ${refused.join("; ")}`);
  }
  const sink = options.log ?? openLog(cfg, gatewayKey);
  if (cfg.strict && sink.kind !== "http") throw new Error(`agent-custody gateway: strict mode needs a remote log, and ${sink.where} is a file`);
  const issuer = createIssuer(gatewayKey, cfg.receiptsDir, sink, { exporter: options.exporter ?? openExporter(cfg), capture: { rules: cfg.capture, key: captureKey } });
  const issuedBy = { kind: "gateway" as const, keyid: issuer.keyid, version: GATEWAY_VERSION, ...(cfg.strict ? { strict: true } : {}) };
  const precommit = new Set(cfg.precommit);
  const operationRule = (tool: string) => cfg.operations?.tools.find((rule) => rule.tool === tool);
  const consequential = (tool: string) => !!cfg.strict || !!operationRule(tool) || precommit.has("*") || precommit.has(tool);
  // A fact lookup runs before the policy can decide, because the policy decides on it. It is therefore a read the
  // gateway makes on the agent's request, never a consequential call: a fact tool named in precommit is a config error.
  // "*" covers the tools the agent calls; a lookup is the gateway's own read, so only an explicit name makes it consequential.
  for (const f of cfg.facts) {
    if (precommit.has(f.tool) || operationRule(f.tool)) throw new Error(`fact "${f.name}" uses tool ${f.tool}, which ${precommit.has(f.tool) ? "precommit" : "operations"} names as consequential; a fact lookup runs before the policy decides and must be a read`);
    if (cfg.approvals?.tools.some((rule) => rule.tool === f.tool)) throw new Error(`fact "${f.name}" uses tool ${f.tool}, which requires approval; a fact lookup must be a read that does not require approval`);
  }

  // Revoked grants: digests of grant envelopes, from the file the operator edits (or `revoke` appends to), re-read
  // whenever the file changes. Checked when a session opens and again on every call, so revocation takes effect on
  // the next call of a running session, without a key rotation.
  const revokedSet = new Set<string>();
  let revokedSeen = "";
  const reloadRevoked = () => {
    if (!cfg.revokedGrants) return;
    if (!existsSync(cfg.revokedGrants)) {
      if (revokedSeen !== "absent") { revokedSet.clear(); revokedSeen = "absent"; }
      return;
    }
    // inode as well as mtime: `revoke` replaces the file by rename, so two writes in one mtime tick are still seen
    const st = statSync(cfg.revokedGrants);
    const m = `${st.ino}:${st.mtimeMs}:${st.size}`;
    if (m === revokedSeen) return;
    const list = JSON.parse(readFileSync(cfg.revokedGrants, "utf8")) as unknown;
    if (!Array.isArray(list)) throw new Error(`${cfg.revokedGrants}: expected a JSON array of grant digests`);
    revokedSet.clear();
    for (const d of list) if (typeof d === "string") revokedSet.add(d);
    revokedSeen = m;
  };
  const revoke = (digest: string) => {
    reloadRevoked();
    revokedSet.add(digest);
    if (cfg.revokedGrants) writeRevokedGrants(cfg.revokedGrants, [...revokedSet]);
  };

  // One host, as many upstreams as the agents' jobs need. Each tool name belongs to exactly one upstream, decided at
  // startup, so a receipt's tool is unambiguous and consumed facts flow across them.
  const upstreamConfigs: { name: string; cfg: UpstreamConfig }[] = cfg.upstreams ? cfg.upstreams.map((u) => ({ name: u.name, cfg: u })) : [{ name: "upstream", cfg: cfg.upstream! }];
  const upstreams = new Map<string, UpstreamClient>();
  const owner = new Map<string, string>();
  const advertised: Tool[] = [];
  const cancelled = options.signal
    ? new Promise<never>((_, reject) => {
        const stop = () => reject(new Error("the gateway start was cancelled"));
        if (options.signal!.aborted) stop();
        else options.signal!.addEventListener("abort", stop, { once: true });
      })
    : null;
  cancelled?.catch(() => {});
  /** a connection that hangs must not hold the start: it loses the race to a cancel */
  const guard = <T,>(p: Promise<T>): Promise<T> => (cancelled ? Promise.race([p, cancelled]) : p);
  try {
    for (const { name, cfg: u } of upstreamConfigs) {
      options.signal?.throwIfAborted();
      let client: UpstreamClient;
      if ("rest" in u) {
        client = restUpstream(name, { ...u.rest, tools: u.rest.tools.map((tool) => {
          const rule = operationRule(tool.name);
          return rule ? { ...tool, idempotencyHeader: rule.idempotencyHeader } : tool;
        }) });
        upstreams.set(name, client);
      } else if ("a2a" in u) {
        client = a2aUpstream(name, u.a2a);
        upstreams.set(name, client);
      } else if ("url" in u) {
        client = new Client({ name: "agent-custody-gateway", version: GATEWAY_VERSION });
        upstreams.set(name, client);
        const token = u.tokenEnv ? process.env[u.tokenEnv] : undefined;
        if (u.tokenEnv && !token) throw new Error(`upstream ${name}: environment variable ${u.tokenEnv} is not set`);
        await guard((client as Client).connect(new StreamableHTTPClientTransport(new URL(u.url), token ? { requestInit: { headers: { authorization: `Bearer ${token}` } } } : {})));
      } else {
        client = new Client({ name: "agent-custody-gateway", version: GATEWAY_VERSION });
        upstreams.set(name, client);
        await guard((client as Client).connect(new StdioClientTransport({ command: u.command, args: u.args, env: upstreamEnv(u.env), stderr: "inherit" })));
      }
      const { tools } = await guard(client.listTools());
      for (const t of tools) {
        const other = owner.get(t.name);
        if (other) throw new Error(`tool "${t.name}" is offered by both upstream "${other}" and upstream "${name}"; a gateway needs one owner per tool`);
        owner.set(t.name, name);
        advertised.push(t);
      }
    }
  } catch (e) {
    // an upstream that was started stays running unless it is closed here: a failed or cancelled start leaves nothing behind
    for (const c of upstreams.values()) await c.close().catch(() => {});
    throw e;
  }

  for (const rule of cfg.operations?.tools ?? []) {
    const via = upstreamConfigs.find((u) => u.name === owner.get(rule.tool));
    const readVia = upstreamConfigs.find((u) => u.name === owner.get(rule.reconcile.tool));
    // A REST read makes the provider lookup contract explicit. MCP payment providers must honor the operation
    // metadata; A2A has no payment idempotency contract and cannot be used here.
    if (!via || "a2a" in via.cfg) throw new Error(`operation tool ${rule.tool} needs an MCP or REST upstream`);
    if (!readVia || operationRule(rule.reconcile.tool) || precommit.has(rule.reconcile.tool)) throw new Error(`operation ${rule.tool}: reconciliation must name an advertised read tool`);
    if ("rest" in readVia.cfg && readVia.cfg.rest.tools.find((t) => t.name === rule.reconcile.tool)?.method !== "GET") throw new Error(`operation ${rule.tool}: REST reconciliation must use GET`);
  }
  const operations = cfg.operations ? new OperationStore(cfg.operations.database) : undefined;
  const providerDigest = (tool: string) => digestOf({ upstream: upstreamConfigs.find((u) => u.name === owner.get(tool)), reconciliationUpstream: upstreamConfigs.find((u) => u.name === owner.get(operationRule(tool)!.reconcile.tool)), rule: operationRule(tool) });
  const lookupFor = (op: OperationRecord) => {
    const rule = operationRule(op.tool)!;
    return { tool: rule.reconcile.tool, args: Object.fromEntries(Object.entries(rule.reconcile.args).map(([key, value]) => [key, value === "$operation.idempotencyKey" ? op.idempotencyKey : value])), statusPath: rule.reconcile.statusPath, identityPath: rule.reconcile.identityPath, confirmed: rule.reconcile.confirmed, failed: rule.reconcile.failed };
  };
  const operationEvidence = (op: OperationRecord, status = op.status): OperationEvidence => ({ id: op.id, idempotencyKey: op.idempotencyKey, status, originalReceiptId: op.originalReceiptId, budget: { id: op.budget, currency: op.currency, period: op.period }, lookupDigest: digestOf(lookupFor(op)), provenance: "observed" });
  const outcome = (op: OperationRecord, result: CallToolResult): OperationStatus => {
    if (result.isError) return "unknown";
    const rule = operationRule(op.tool)!;
    const value = providerField(result, rule.reconcile.statusPath);
    if (typeof value !== "string") return "pending";
    // Even a provider's initial failure response retains the reservation: only the authoritative reconciliation
    // read releases it. A response can be an error after the provider accepted the transfer.
    if (rule.reconcile.confirmed.includes(value)) return "pending";
    if (rule.reconcile.pending?.includes(value)) return "pending";
    return "unknown";
  };

  const callUpstream = async (name: string, args: Record<string, unknown>, meta?: Record<string, unknown>): Promise<CallToolResult> => {
    const via = owner.get(name);
    if (!via) throw new Error(`no upstream offers tool "${name}"`);
    return (await upstreams.get(via)!.callTool({ name, arguments: args, ...(meta ? { _meta: meta } : {}) })) as CallToolResult;
  };

  /** The facts for a call, the argument template of the fact config each one came from (two configs may share a name), and each lookup's full result. */
  async function gatherFacts(tool: string, args: Record<string, unknown>, meta: Record<string, unknown>): Promise<{ facts: Record<string, FactRecord>; templates: Record<string, Record<string, string>>; results: Record<string, unknown> }> {
    // null-prototype, so a fact named __proto__ or constructor is a fact and not a prototype
    const facts: Record<string, FactRecord> = Object.create(null);
    const templates: Record<string, Record<string, string>> = Object.create(null);
    const results: Record<string, unknown> = Object.create(null);
    for (const f of cfg.facts.filter((f: FactConfig) => f.forTools.includes(tool))) {
      const fargs = resolveFactArgs(f.args, args, f.optional);
      if (fargs === null) continue;
      // Lookups carry the same metadata as the forwarded call: they are the gateway acting for this receipt. A failed
      // lookup, answered isError or thrown, denies the call with the answer in policy.errors; the issuer withholds it
      // under a private rule.
      let result: CallToolResult;
      try {
        result = await callUpstream(f.tool, fargs, meta);
      } catch (e) {
        throw new Error(`fact "${f.name}" lookup via ${f.tool} failed: ${String(e instanceof Error ? e.message : e)}`);
      }
      if (result.isError) throw new Error(`fact "${f.name}" lookup via ${f.tool} failed: ${JSON.stringify(extractValue(result))}`);
      facts[f.name] = { tool: f.tool, args: fargs, value: extractValue(result), resultDigest: digestOf(result), provenance: "observed" };
      templates[f.name] = f.args;
      results[f.name] = result;
    }
    return { facts, templates, results };
  }

  function open(grantEnvelope: Envelope): Gateway {
    const grant = verifyDelegation(grantEnvelope, trusted);
    if (!grant.ok) throw new Error(`delegation grant rejected: ${grant.error}`);
    if (!delegationValidAt(grant.delegation, new Date().toISOString())) throw new Error("delegation grant is outside its validity window");
    const delegation = grant.delegation;
    const principalKeyid = grant.keyid;
    const chainDigests = grantChainDigests(grantEnvelope);
    const grantDigest = chainDigests[0]!;
    reloadRevoked();
    if (chainDigests.some((d) => revokedSet.has(d))) throw new Error("delegation grant has been revoked");
    /** Why the grant is not in force at `at`, or null. Asked on every call, and again just before a forward. */
    const grantProblem = (at: string = new Date().toISOString()): string | null => {
      try {
        reloadRevoked();
      } catch (e) {
        // fail closed: a revocation list that cannot be read revokes everything until it can
        return `cannot be checked against the revocation list (${e instanceof Error ? e.message : String(e)})`;
      }
      if (chainDigests.some((d) => revokedSet.has(d))) return "has been revoked";
      if (!delegationValidAt(delegation, at)) return Date.parse(at) < Date.parse(delegation.issuedAt) ? "is not yet valid" : "has expired";
      return null;
    };

    /** Every fact id an upstream has declared it served to this session, in order of first sight. A session is one agent under one grant. */
    const consumed: string[] = [];
    const noteServedFacts = (result: CallToolResult) => {
      const ids = result._meta?.[FACTS_META_KEY];
      if (!Array.isArray(ids)) return;
      for (const id of ids) if (typeof id === "string" && !consumed.includes(id)) consumed.push(id);
    };

    async function handleCall(params: CallParams): Promise<CallToolResult> {
      const tool = params.name;
      const { text: policyText, digest: pDigest, rego: regoPolicy } = currentPolicy();
      // An embedding caller can mutate its objects while a lookup or log append is awaited. Snapshot the call and
      // approval before the first await, so the approved bytes are the bytes evaluated, logged, and forwarded. A caller
      // also cannot change the payment after its reservation was bound.
      const args = structuredClone(params.arguments ?? {});
      const operationId = params._meta?.[OPERATION_META_KEY];
      const suppliedApproval = params._meta?.[APPROVAL_META_KEY];
      let approvalEnvelope: unknown;
      try { approvalEnvelope = structuredClone(suppliedApproval); } catch { approvalEnvelope = undefined; }
      const receiptId = randomUUID();
      const timestamp = new Date().toISOString();
      const modelClaim = params._meta?.[MODEL_META_KEY];
      // What the agent had been shown before this call; recorded before this call's own result is seen.
      const consumedNow = [...consumed];
      const upstreamMeta = { [RECEIPT_META_KEY]: receiptId, [AGENT_META_KEY]: delegation.agent, [PRINCIPAL_META_KEY]: delegation.principal };

      let facts: Record<string, FactRecord> = {};
      let factTemplates: Record<string, Record<string, string>> = {};
      let factResults: Record<string, unknown> = {};
      let policy: PolicyDecision;
      let execution: ReceiptPredicate["execution"] | undefined;
      /** what the upstream answered, in full: the agent gets this; the receipt gets the captured view */
      let forwarded: CallToolResult | undefined;
      let authorization: AuthorizationBundle | undefined;
      let approval: ApprovalRecord | undefined;
      let approvedWindow: { issuedAt: number; expiresAt: number } | undefined;
      const rule = approvalRule(tool);
      const approvalBinding = { principal: delegation.principal, agent: delegation.agent, tool, args, ...(rule?.fields ? { fields: rule.fields } : {}) };
      // Only an authenticated statement is embedded in the approval record. Untrusted or malformed metadata is never
      // copied there: it could carry arbitrary text from withheld arguments. Under a private rule the issuer then
      // withholds the embedded envelope as a commitment (see CLEAR_IN.approval in capture.ts), because even an
      // authentic one carries the action fields and an unsalted digest of the arguments.
      const signedApproval = rule ? verifyApprovalStatement(approvalEnvelope, approvalKeys) : undefined;
      // Signatures lie outside the signed payload. Keep only entries that independently verify: an attacker can
      // append an untrusted signature, or a forged duplicate of a trusted key id, without invalidating the approval.
      const rawEnvelope = signedApproval?.ok ? approvalEnvelope as Envelope : undefined;
      const envelope = rawEnvelope ? { ...rawEnvelope, signatures: rawEnvelope.signatures.filter((signature) => dsseVerifiers({ ...rawEnvelope, signatures: [signature] }, approvalKeys).length > 0) } : undefined;
      const checkApproval = (at: string) => {
        if (!rule) return undefined;
        const checked = verifyApproval(approvalEnvelope, approvalKeys, approvalBinding, { at, minApprovers: rule.minApprovers, maxLifetimeSeconds: cfg.approvals!.maxLifetimeSeconds ?? DEFAULT_APPROVAL_LIFETIME_SECONDS });
        approval = { ...(envelope ? { envelope } : {}), requiredApprovers: rule.minApprovers, ...(rule.fields ? { fields: rule.fields } : {}), checkedAt: at, status: checked.ok ? "approved" : "denied", approverKeyids: checked.ok ? checked.approverKeyids : [], ...(!checked.ok ? { reason: envelope ? checked.error : "approval rejected: malformed or untrusted statement" } : {}), provenance: "observed" };
        return checked;
      };
      const initialApproval = checkApproval(timestamp);
      const approvalProblem = initialApproval && !initialApproval.ok ? initialApproval.error : undefined;
      let operation: OperationRecord | undefined;
      let createdOperation = false;
      let attemptedOperation = false;

      // The grant is enforced in every mode: a call outside its scopes, or after it expired or was revoked, is denied
      // and never forwarded, observe mode or not. Observe mode suspends the Cedar policy, nothing else.
      const problem = grantProblem(timestamp);
      const inScope = delegation.scopes.includes(tool);
      if (problem) {
        policy = { decision: "deny", reasons: [], errors: [`delegation grant ${problem}`], policyDigest: pDigest };
      } else if (!inScope) {
        policy = { decision: "deny", reasons: [], errors: [`tool "${tool}" is not in the delegation scopes`], policyDigest: pDigest };
      } else if (approvalProblem) {
        policy = { decision: "deny", reasons: [], errors: [`approval rejected: ${approvalProblem}`], policyDigest: pDigest };
      } else {
        try {
          ({ facts, templates: factTemplates, results: factResults } = await gatherFacts(tool, args, upstreamMeta));
          const factValues = Object.fromEntries(Object.entries(facts).map(([k, f]) => [k, f.value]));
          const request = { agentId: delegation.agent, tool, context: { args, facts: factValues, grant: { principal: delegation.principal, scopes: delegation.scopes } } };
          policy = opaServer ? await opaServer.decide(request) : regoPolicy ? evaluateRego(regoPolicy, pDigest, request) : evaluate(policyText, request);
        } catch (e) {
          policy = { decision: "deny", reasons: [], errors: [String(e instanceof Error ? e.message : e)], policyDigest: pDigest };
        }
      }
      // Observe mode: the decision is recorded, never enforced. The receipt says so on every call, so a verifier can
      // tell a policy that was being tested from one that was in force.
      if (cfg.mode === "observe" && !problem && inScope && !approvalProblem) policy = { ...policy, enforced: false };
      const forward = policy.decision === "allow" || policy.enforced === false;

      // Private evidence is applied by the issuer to the whole statement. What it cannot know by itself: a fact's lookup
      // arguments are copied from the call, so a fact argument may stay in clear only when its template is a constant or
      // copies a call argument the args rule keeps in clear (the rule's `clear` names call arguments, and a fact argument
      // may carry one under another name); the template is the one of the fact config that was used, since fact names
      // are not unique across tools. And the lookups' full results, behind the facts' digests.
      // the same rule the issuer will apply: for a name no upstream offers that may be the wildcard, not the name's own
      const argsClear = new Set(effectiveRule(cfg.capture, tool, !owner.has(tool))?.args?.clear ?? []);
      const clearFactArgs = Object.fromEntries(Object.entries(factTemplates).map(([name, template]) => [name, Object.entries(template).filter(([, v]) => !v.startsWith("$args.") || argsClear.has(v.slice("$args.".length))).map(([k]) => k)]));
      // a name no upstream offers is text the agent chose: the issuer selects the rule by it and masks it in the view
      const captureCtx = { clearFactArgs, factResults, unknownTool: !owner.has(tool) };
      const head = {
        receiptId,
        timestamp,
        issuer: issuedBy,
        principal: { id: delegation.principal, keyid: principalKeyid, provenance: "attested" as const },
        agent: { id: delegation.agent, provenance: "attested" as const },
        delegation: { envelope: grantEnvelope, provenance: "attested" as const },
        tool: { name: tool, provenance: "observed" as const, ...(owner.has(tool) && upstreamConfigs.length > 1 ? { upstream: owner.get(tool)! } : {}) },
        request: { args, argsDigest: digestOf(args), provenance: "claimed" as const },
        facts,
        consumed: { factIds: consumedNow, provenance: "observed" as const },
        ...(approval ? { approval } : {}),
        operation: undefined as OperationEvidence | undefined,
      };

      const financial = operationRule(tool);
      if (forward && financial) {
        try {
          if (typeof operationId !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(operationId)) throw new Error(`financial calls require a stable UUID in _meta["${OPERATION_META_KEY}"]`);
          const budget = cfg.operations!.budgets.find((b) => b.id === financial.budget)!;
          if (args[financial.currencyField] !== budget.currency) throw new Error(`operation currency must match budget ${budget.id}`);
          const amount = args[financial.amountField];
          if (typeof amount !== "number" || !Number.isSafeInteger(amount) || amount <= 0) throw new Error("operation amount must be a positive safe integer in minor units");
          const reserved = operations!.reserve({ id: operationId, issuerKeyid: issuer.keyid, providerDigest: providerDigest(tool), principal: delegation.principal, agent: delegation.agent, tool, argsDigest: digestOf(args), budget: budget.id, currency: budget.currency, amount, limit: budget.limit, originalReceiptId: receiptId, unsent: { ...head, policy: { ...policy, provenance: "observed" } } });
          operation = reserved.operation;
          createdOperation = reserved.created;
          head.operation = operationEvidence(operation, operation.status === "submitted" && !createdOperation ? "unknown" : operation.status);
        } catch (e) {
          execution = { status: "withheld", reason: `operation not forwarded: ${e instanceof Error ? e.message : String(e)}`, provenance: "observed" };
        }
      }

      /** The answer to a retry of an existing operation: the stored outcome, which the retry receipt below records as withheld. */
      let cached: CallToolResult | undefined;
      if (!execution && operation && !createdOperation) {
        // An existing reservation can mean another process is still forwarding, or died immediately afterwards.
        // Never repeat the side effect. Reconciliation is the only path from an uncertain operation to closure.
        // The retry gets a receipt of its own, so that the log shows the agent asked again and what it was told.
        const settled = operation.reconciliation as { bundle?: ReceiptBundle; predicate?: ReceiptPredicate } | undefined;
        const result = settled?.bundle && settled.predicate && "result" in settled.predicate.execution ? settled.predicate.execution.result as CallToolResult : operation.result as CallToolResult | undefined;
        const receipt = settled?.bundle ? settled.predicate!.receiptId : operation.originalReceiptId;
        cached = { ...(result ?? { isError: true, content: [{ type: "text" as const, text: head.operation!.status === "failed" ? "Operation failed and the call was not sent; use a new operation id to try again" : `Operation outcome is ${head.operation!.status}; reconcile with the provider before taking further action` }] }), _meta: { ...result?._meta, [RECEIPT_META_KEY]: receipt, ...(operation.original && !existsSync(`${cfg.receiptsDir}/${operation.originalReceiptId}.json`) ? { "agent-custody/authorization": operation.original } : {}) } };
        execution = { status: "withheld", reason: `existing operation: not forwarded again; the stored outcome is ${head.operation!.status}`, provenance: "observed" };
      }

      if (!execution && (policy.decision === "allow" || (financial || cfg.strict) && forward) && consequential(tool)) {
        // A consequential call is committed to the log before it goes out, so that evidence of the side effect exists
        // before the side effect does. If the log will not take the authorization, the call is not forwarded; in
        // observe mode nothing is withheld, and the missing authorization is printed instead, unless the mode is strict.
        try {
          authorization = await issuer.authorize({ ...head, policy: { ...policy, provenance: "observed" } }, captureCtx);
        } catch (e) {
          if (cfg.mode === "observe" && !financial && !cfg.strict) console.error(`agent-custody gateway (observe mode): the log did not commit the authorization for ${tool}, receipt ${receiptId}; the call was forwarded without it: ${String(e instanceof Error ? e.message : e)}`);
          else execution = { status: "withheld", reason: `the log did not commit the authorization, so the call was not forwarded: ${String(e instanceof Error ? e.message : e)}`, provenance: "observed" };
        }
        if (authorization && operation) {
          try {
            operation = operations!.saveAuthorization(operation.id, authorization);
          } catch (e) {
            // Recovery closed this operation as "not forwarded" while the log held the authorization. Its closing receipt
            // has this receipt id, so no second receipt is issued. The call is not forwarded.
            return { isError: true, content: [{ type: "text", text: `Not executed: ${String(e instanceof Error ? e.message : e)} (receipt ${receiptId})` }], _meta: { [RECEIPT_META_KEY]: receiptId, [OPERATION_META_KEY]: operationEvidence(operations!.get(operation.id) ?? operation) } };
          }
        }
      }

      let late = execution ? null : forward ? grantProblem() : null;
      if (!execution && !late && forward && rule) {
        // No awaits between this fresh check, the persistent atomic claim, and entering the upstream call. The
        // claim is shared across sessions and processes, and a storage error withholds the side effect.
        const at = new Date().toISOString();
        const checked = checkApproval(at)!;
        if (!checked.ok) {
          execution = { status: "withheld", reason: `approval rejected before the call was forwarded: ${checked.error}`, provenance: "observed" };
        } else {
          try {
            consumeApproval(cfg.approvals!.usedDir, checked.approval.approvalId, receiptId, at);
            // A synchronous durable claim can block on storage. Recheck after it returns, because the grant or
            // approval may have expired (or the grant been revoked) during that wait. A refusal keeps the claim.
            const afterConsume = new Date().toISOString();
            const finalCheck = checkApproval(afterConsume)!;
            // Signature verification can be slow too. Read revocations after it, immediately before the cheap
            // final window check, so a revocation made during that work still withholds this call.
            late = grantProblem();
            approval = { ...approval!, consumedAt: afterConsume };
            if (!finalCheck.ok) execution = { status: "withheld", reason: `approval rejected before the call was forwarded: ${finalCheck.error}`, provenance: "observed" };
            else approvedWindow = { issuedAt: Date.parse(finalCheck.approval.issuedAt), expiresAt: Date.parse(finalCheck.approval.expiresAt) };
          } catch (e) {
            const reason = `approval could not be consumed: ${String(e instanceof Error ? e.message : e)}`;
            approval = { ...approval!, status: "denied", reason };
            execution = { status: "withheld", reason, provenance: "observed" };
          }
        }
      }
      if (execution) {
        // withheld: nothing was forwarded
      } else if (late) {
        // the grant ran out, or was revoked, while the facts were gathered or the authorization logged
        execution = { status: "withheld", reason: `the delegation grant ${late} before the call was forwarded`, provenance: "observed" };
      } else if (forward) {
        try {
          // The upstream learns which receipt this call is, and who the grant says is calling. An upstream that keeps
          // state, such as the memory server, cites the receipt as the source of what it stores.
          const observed = Object.fromEntries(Object.entries(facts).map(([k, f]) => [k, f.value]));
          // Signature checks and revocation-file I/O can themselves take time. Sample once more after all of them,
          // using the authenticated window directly, so this last check does no crypto or storage before forwarding.
          const forwardAt = new Date().toISOString();
          const forwardMs = Date.parse(forwardAt);
          if (approval) approval = { ...approval, checkedAt: forwardAt, ...(approval.consumedAt ? { consumedAt: forwardAt } : {}) };
          if (rule && (!approvedWindow || forwardMs < approvedWindow.issuedAt || forwardMs >= approvedWindow.expiresAt)) {
            const reason = approvedWindow && forwardMs < approvedWindow.issuedAt ? "approval is not yet valid" : "approval has expired";
            approval = { ...approval!, status: "denied", reason, approverKeyids: [] };
            execution = { status: "withheld", reason: `approval rejected before the call was forwarded: ${reason}`, provenance: "observed" };
          } else if (!delegationValidAt(delegation, forwardAt)) {
            execution = { status: "withheld", reason: "the delegation grant is outside its validity window before the call was forwarded", provenance: "observed" };
          } else {
            attemptedOperation = !!operation;
            const result = await callUpstream(tool, args, { ...upstreamMeta, [OBSERVED_META_KEY]: observed, ...(operation ? { [OPERATION_META_KEY]: { id: operation.id, idempotencyKey: operation.idempotencyKey } } : {}) });
            const evidence = upstreamEvidenceOf(result);
            forwarded = result;
            execution = { status: result.isError ? "failed" : "executed", result, resultDigest: digestOf(result), provenance: "observed", ...(evidence ? { upstream: evidence } : {}) };
            noteServedFacts(result);
            if (operation) operation = operations!.update(operation.id, { status: outcome(operation, result), result });
          }
        } catch (e) {
          execution = { status: "error", error: String(e instanceof Error ? e.message : e), provenance: "observed" };
          if (operation) operation = operations!.update(operation.id, { status: "unknown" });
        }
      } else {
        execution = { status: "denied", reason: [...policy.reasons, ...policy.errors].join("; ") || "no permit policy matched", provenance: "observed" };
      }

      // Only a call known never to have been forwarded may release a reservation without a provider record.
      if (operation && createdOperation && !attemptedOperation) operation = operations!.update(operation.id, { status: "failed", unsent: undefined });
      if (operation) head.operation = operationEvidence(operation, operation.status === "submitted" && !createdOperation ? "unknown" : operation.status);
      // The call is done, so a log outage now must not tell the agent it failed: the receipt waits in the outbox. An
      // operation keeps the old order, because its record holds the bundle and its retry is idempotent. Strict mode
      // keeps no outbox: the authorization is in the log, and a receipt the log refuses leaves the call incomplete.
      let issued: ReceiptBundle | undefined;
      let logPending = false;
      try {
        issued = await issuer.issue({
        ...head,
        ...(approval ? { approval } : {}),
        session: { id: null, toolUseId: null, provenance: "claimed" },
        model: { id: typeof modelClaim === "string" ? modelClaim : null, provenance: "claimed" },
        policy: { ...policy, provenance: "observed" },
        ...(authorization ? { authorization } : {}),
        execution,
      }, captureCtx, undefined, { deferLog: !operation && !cfg.strict });
      } catch (e) {
        if (!(e instanceof ReceiptPending)) throw e;
        console.error(`agent-custody gateway: ${e.message}`);
        logPending = true;
      }
      if (operation && createdOperation && attemptedOperation) operations!.update(operation.id, { original: issued! });

      const meta = { [RECEIPT_META_KEY]: receiptId, ...(head.operation ? { [OPERATION_META_KEY]: head.operation } : {}), ...(logPending ? { [LOG_PENDING_META_KEY]: true } : {}) };
      const refuse = (text: string): CallToolResult => ({ isError: true, content: [{ type: "text", text: `${text} (receipt ${receiptId})` }], _meta: meta });
      switch (execution.status) {
        // the agent gets the real result, the real reason, and the real error: what is withheld is withheld from the receipt
        case "denied":
          return refuse(`Denied by policy: ${execution.reason as string}`);
        case "error":
          return refuse(`Upstream error: ${execution.error as string}`);
        case "withheld":
          if (cached) return { ...cached, _meta: { ...cached._meta, [OPERATION_META_KEY]: head.operation, [RETRY_RECEIPT_META_KEY]: receiptId } };
          return refuse(`Not executed: ${execution.reason as string}`);
        default: {
          const result = forwarded ?? (execution.result as CallToolResult);
          return { ...result, _meta: { ...result._meta, ...meta } };
        }
      }
    }

    return {
      agentId: delegation.agent,
      delegation,
      grantDigest,
      grantProblem,
      async listTools() {
        return advertised.filter((t) => delegation.scopes.includes(t.name));
      },
      handleCall,
      async close() {
        // a session holds nothing of its own beyond what it consumed; the host owns the upstreams
      },
    };
  }

  if (cfg.log && !cfg.precommit.length && !cfg.strict) console.error("agent-custody gateway: a remote log is set and precommit is empty: every call is forwarded before its receipt is logged. Name the consequential tools in precommit, or [\"*\"]; requirePrecommit makes this an error");
  let flushing: Promise<FlushResult> | undefined;
  const flushOutbox = () => flushing ??= (async () => {
    const r = await issuer.flushOutbox();
    if (r.setAside) console.error(`agent-custody gateway: ${r.setAside} outbox entr${r.setAside === 1 ? "y is" : "ies are"} damaged, or not signed under its file name; renamed to .bad and not appended`);
    if (r.foreign) console.error(`agent-custody gateway: ${r.foreign} outbox entr${r.foreign === 1 ? "y is" : "ies are"} signed by a key other than ${issuer.keyid.slice(0, 12)}; left in the outbox and not appended. Restore the key that signed them, or move them away`);
    if (r.error) console.error(`agent-custody gateway: ${r.pending} receipt(s) wait in the outbox: ${r.error}`);
    return r;
  })().finally(() => { flushing = undefined; });
  const autoFlush = () => void flushOutbox().catch((e) => console.error(`agent-custody gateway: the outbox flush failed: ${e instanceof Error ? e.message : String(e)}`));
  // strict mode never adds to the outbox; receipts left there from before it was turned on are appended once, at start
  const outboxTimer = options.autoFlush && !cfg.strict ? setInterval(autoFlush, 30_000).unref() : undefined;
  if (options.autoFlush) autoFlush();

  return {
    keyid: issuer.keyid,
    open,
    revoke,
    policyDigest: () => currentPolicy().digest,
    tools: () => advertised.map((t) => t.name),
    revoked: () => {
      reloadRevoked();
      return [...revokedSet];
    },
    async reconcile(operationId) {
      if (!operations) throw new Error("gateway has no financial operations configured");
      const op = operations.get(operationId);
      if (!op) throw new Error("operation not found");
      if (op.issuerKeyid !== issuer.keyid || op.providerDigest !== providerDigest(op.tool)) throw new Error("operation provider or gateway identity changed; use the original configuration");
      let intent = op.reconciliation as { predicate: ReceiptPredicate; bundle?: ReceiptBundle } | undefined;
      if (intent?.bundle) return intent.bundle;
      if (!intent) {
        if (op.status === "failed") throw new Error("operation was never forwarded and needs no provider reconciliation");
        // SQLite is shared on this machine. A live creator may still be about to send, or awaiting its response;
        // reconciliation cannot release its budget underneath that forward. A process with the same PID but another
        // start time is not the creator. A start time that cannot be read fails closed.
        if (op.status === "submitted" && ownerAlive(op)) throw new Error("operation is still submitted by a live process; wait for its outcome before reconciling");
        const original = op.original as ReceiptBundle | AuthorizationBundle | undefined;
        if (!original) {
          // The authorization is saved before the forward. A dead creator and no authorization prove that the call was
          // never sent. Close it with a receipt that says so, then release the reservation.
          const unsent = op.unsent as AuthorizationPredicate | undefined;
          if (!unsent) throw new Error("operation has no committed authorization and no record of the call; it was not forwarded");
          const predicate: ReceiptPredicate = {
            ...unsent, receiptId: op.originalReceiptId, timestamp: new Date().toISOString(),
            session: { id: null, toolUseId: null, provenance: "claimed" }, model: { id: null, provenance: "claimed" },
            operation: operationEvidence(op, "failed"),
            execution: { status: "withheld", reason: "the gateway stopped before it forwarded the call; the call was not forwarded", provenance: "observed" },
          };
          intent = operations.claimReconciliation(op.id, { predicate }, true) as { predicate: ReceiptPredicate; bundle?: ReceiptBundle };
        }
      }
      if (!intent) {
        const original = op.original as ReceiptBundle | AuthorizationBundle;
        const checked = dsseVerify(original.envelope, [gatewayKey]);
        if (!checked.ok) throw new Error("stored original operation signature is invalid");
        const initial = (checked.payload as ReceiptStatement).predicate;
        const lookup = lookupFor(op);
        const result = await callUpstream(lookup.tool, lookup.args);
        const identity = providerField(result, lookup.identityPath);
        if (identity !== op.idempotencyKey) throw new Error("provider record does not bind this operation's idempotency key; the reservation is retained");
        const value = providerField(result, lookup.statusPath);
        const status = typeof value === "string" && !result.isError ? lookup.confirmed.includes(value) ? "confirmed" : lookup.failed.includes(value) ? "failed" : null : null;
        if (!status) throw new Error("provider outcome remains pending or unknown; the reservation is retained");
        const predicate: ReceiptPredicate = {
          receiptId: randomUUID(), timestamp: new Date().toISOString(),
          issuer: issuedBy,
          principal: initial.principal, agent: initial.agent, delegation: initial.delegation,
          session: { id: null, toolUseId: null, provenance: "claimed" }, model: { id: null, provenance: "claimed" },
          tool: initial.tool, request: { args: lookup.args, argsDigest: digestOf(lookup.args), provenance: "claimed" },
          facts: {}, policy: { decision: "allow", reasons: ["reconciliation: the gateway read the provider record and evaluated no policy"], errors: [], policyDigest: currentPolicy().digest, provenance: "observed" },
          operation: operationEvidence(op, status), reconciliation: { original, lookup },
          execution: { status: "executed", result, resultDigest: digestOf(result), provenance: "observed" },
        };
        intent = operations.claimReconciliation(op.id, { predicate }) as { predicate: ReceiptPredicate; bundle?: ReceiptBundle };
      }
      // Commit the receipt before releasing a failed reservation. A crash before this update retains the amount;
      // the persisted intent allows another operator/process to finish precisely the same resolution.
      // A receipt for an unsent call holds the call's own values, so the issuer applies the capture rule of its tool.
      const ctx = intent.predicate.reconciliation ? undefined : { unknownTool: !owner.has(intent.predicate.tool.name) };
      const bundle = intent.bundle ?? await issuer.issue(intent.predicate, ctx, (prepared) => operations.prepareReconciliation(op.id, prepared) as PreparedReceipt);
      const retained = operations.get(op.id)!.reconciliation as object;
      operations.update(op.id, { status: intent.predicate.operation!.status, reconciliation: { ...retained, bundle }, result: (intent.predicate.execution as { result?: unknown }).result, unsent: undefined });
      return bundle;
    },
    flushOutbox,
    pendingReceipts: () => issuer.pending(),
    async close() {
      if (outboxTimer) clearInterval(outboxTimer);
      await flushing?.catch(() => {});
      for (const c of upstreams.values()) await c.close();
      operations?.close();
    },
  };
}

/** One gateway for the grant the config names: what `agent-custody gateway` serves over stdio. Closing it closes the host. */
export async function createGateway(cfg: GatewayConfig, options: GatewayOptions = {}): Promise<Gateway> {
  if (!cfg.grantFile) throw new Error("config needs grantFile for a single-grant gateway; over HTTP each connection presents its own grant");
  const host = await createGatewayHost(cfg, options);
  let session: Gateway;
  try {
    session = host.open(JSON.parse(readFileSync(cfg.grantFile, "utf8")) as Envelope);
  } catch (e) {
    await host.close();
    throw e;
  }
  return {
    ...session,
    async close() {
      await session.close();
      await host.close();
    },
  };
}

/** Exposes the gateway as an MCP server over stdio. Everything diagnostic must go to stderr. */
export async function serveStdio(gw: Gateway): Promise<void> {
  const server = new Server({ name: "agent-custody-gateway", version: GATEWAY_VERSION }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: await gw.listTools() }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => gw.handleCall(req.params as CallParams));
  await server.connect(new StdioServerTransport());
  await new Promise<void>((resolve) => {
    server.onclose = resolve;
  });
}
