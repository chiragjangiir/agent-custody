import { z } from "zod";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

/** Where receipts are logged: a local file, or a log reached over HTTP whose bearer token comes from an environment variable. */
const LogSchema = z.object({ url: z.string().url(), tokenEnv: z.string().min(1).optional(), /** send leaf hashes only; the log never holds the receipt. Use it for any log run by someone else */ hashOnly: z.boolean().optional(), /** milliseconds one append may take before the log counts as unreachable; default 10000 */ timeoutMs: z.number().int().positive().optional(), /** the log's public key files; every append's answer is checked against them before a call is forwarded. Without them the log's key document is fetched from the log itself on first use and pinned, which catches a log that turns dishonest later but not one dishonest from the start; required with precommit. */ keys: z.array(z.string().min(1)).optional(), /** the id the log must write into every tree head; an answer for another log is refused */ logId: z.string().min(1).optional() });
const oneLog = { message: "exactly one of logFile or log is required" };
/** Optional OpenTelemetry export: every receipt also becomes a span at this OTLP/HTTP collector, after it is issued. Never on the evidence path. */
const OtelSchema = z.object({ url: z.string().url(), headersEnv: z.record(z.string(), z.string().min(1)).optional(), serviceName: z.string().min(1).optional() });
const SplunkSchema = z.object({ url: z.string().url(), tokenEnv: z.string().min(1), index: z.string().min(1).optional(), source: z.string().min(1).optional(), sourcetype: z.string().min(1).optional(), host: z.string().min(1).optional() });
const hasOneLog = (c: { logFile?: string | undefined; log?: unknown }) => (c.logFile ? 1 : 0) + (c.log ? 1 : 0) === 1;

/** What a receipt carries of one side of a call: everything, commitments only, or commitments with the value encrypted under the customer's key; `clear` names the top-level fields kept in clear either way. */
const CaptureSideSchema = z.object({ mode: z.enum(["clear", "digest", "encrypted"]), clear: z.array(z.string().min(1)).optional() });
/** Per tool (or "*"): how the arguments, the result, and the facts are captured. Digests and signatures are always over the whole call. */
const CaptureSchema = z.record(z.string().min(1), z.object({ args: CaptureSideSchema.optional(), result: CaptureSideSchema.optional(), facts: CaptureSideSchema.optional() }));

/** One REST endpoint offered to the agent as a tool. `{name}` segments in the path come from the call's arguments; the rest go to the query on GET and DELETE, or to a JSON body otherwise. */
const RestToolSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]).default("GET"),
  path: z.string().min(1),
  /** argument names sent as query parameters, when the default placement is not wanted */
  query: z.array(z.string().min(1)).optional(),
  /** "none" sends no body even on POST */
  body: z.enum(["json", "none"]).default("json"),
  /** The gateway supplies its durable operation key in this header; callers cannot choose or override it. */
  idempotencyHeader: z.string().regex(/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/).optional(),
  /** the JSON Schema the agent sees; default accepts any object */
  inputSchema: z.record(z.string(), z.unknown()).default({ type: "object" }),
});
export type RestToolConfig = z.infer<typeof RestToolSchema>;

/** A plain HTTP API as an upstream: no MCP server needed. Secrets come from the environment through headerEnv, never from the file or the agent. */
const RestUpstreamSchema = z.object({
  baseUrl: z.string().url(),
  headers: z.record(z.string(), z.string()).optional(),
  /** header name to environment variable, e.g. { "authorization": "STRIPE_BEARER" }; a missing variable fails at startup */
  headerEnv: z.record(z.string(), z.string().min(1)).optional(),
  timeoutMs: z.number().int().positive().default(30_000),
  tools: z.array(RestToolSchema).min(1),
});
export type RestUpstreamConfig = z.infer<typeof RestUpstreamSchema>;

/** Another agent, reached over the A2A protocol, as an upstream. Its agent card is fetched at startup; the gateway offers `<prefix>.send`, which delegates a task to it, and `<prefix>.card`, a read of the card for use as a fact. */
const A2aUpstreamSchema = z.object({
  /** the agent's base URL (its card is at /.well-known/agent-card.json) or the card's URL itself */
  url: z.string().url(),
  headers: z.record(z.string(), z.string()).optional(),
  /** header name to environment variable, as for a REST upstream */
  headerEnv: z.record(z.string(), z.string().min(1)).optional(),
  /** how long one delegated task may take, streamed or not; default two minutes */
  timeoutMs: z.number().int().positive().default(120_000),
  /** the tool names are `<prefix>.send` and `<prefix>.card`; default "a2a". Give each A2A upstream its own prefix. */
  prefix: z.string().min(1).regex(/^[A-Za-z0-9_-]+$/).default("a2a"),
});
export type A2aUpstreamConfig = z.infer<typeof A2aUpstreamSchema>;

const UpstreamSchema = z.union([
  z.object({ command: z.string(), args: z.array(z.string()).default([]), env: z.record(z.string(), z.string()).optional() }),
  z.object({ url: z.string().url(), tokenEnv: z.string().min(1).optional() }),
  z.object({ rest: RestUpstreamSchema }),
  z.object({ a2a: A2aUpstreamSchema }),
]);
export type UpstreamConfig = z.infer<typeof UpstreamSchema>;

const FactSchema = z.object({
  /** key under context.facts */
  name: z.string().min(1),
  /** upstream tool the gateway calls to obtain the fact */
  tool: z.string().min(1),
  /** argument template; values of the form "$args.<key>" are taken from the intercepted call */
  args: z.record(z.string(), z.string()),
  /** which intercepted tools trigger this lookup */
  forTools: z.array(z.string().min(1)).min(1),
  /** when true and a "$args.<key>" the template needs is absent from the call, the lookup is skipped and the fact is simply not present */
  optional: z.boolean().default(false),
});

/** Signed human approvals are independent of Cedar: an approving artifact binds the whole call and is used once. */
const ApprovalsSchema = z.object({
  trustedKeys: z.array(z.string().min(1)).min(1),
  usedDir: z.string().min(1),
  /** The longest lifetime (expiresAt minus issuedAt) that the gateway accepts. The signer chooses the expiry, and this caps it. Default: 3600. */
  maxLifetimeSeconds: z.number().int().positive().optional(),
  tools: z.array(z.object({
    tool: z.string().min(1),
    minApprovers: z.union([z.literal(1), z.literal(2)]).default(1),
    /** Argument names carrying these values; omitted names default to amount, currency, and beneficiary. */
    fields: z.object({ amount: z.string().min(1).optional(), currency: z.string().min(1).optional(), beneficiary: z.string().min(1).optional() }).optional(),
  })).min(1).refine((tools) => new Set(tools.map((t) => t.tool)).size === tools.length, { message: "approval tool names must be unique" }),
});
/** Amounts and limits are integer minor units; one budget is shared by every principal and agent on this database. */
const OperationBudgetSchema = z.object({ id: z.string().min(1).max(128), currency: z.string().regex(/^[A-Z]{3}$/), limit: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER) });
const OperationReconcileSchema = z.object({
  tool: z.string().min(1),
  /** Only the gateway-derived idempotency key may be substituted. The agent's operation id never reaches a receipt, and reconciliation never takes new caller arguments. */
  args: z.record(z.string(), z.string()).refine((args) => Object.values(args).every((v) => !v.startsWith("$") || v === "$operation.idempotencyKey"), { message: "reconciliation templates only support $operation.idempotencyKey" }),
  statusPath: z.string().min(1).max(512).refine((path) => path.split(".").every((part) => part.length > 0), { message: "reconciliation statusPath must have nonempty dot-separated parts" }),
  /** The provider record must echo this operation's idempotency key before it may close the reservation. */
  identityPath: z.string().min(1).max(512).refine((path) => path.split(".").every((part) => part.length > 0), { message: "reconciliation identityPath must have nonempty dot-separated parts" }).default("idempotencyKey"),
  confirmed: z.array(z.string().min(1).max(128)).min(1),
  failed: z.array(z.string().min(1).max(128)).min(1),
  pending: z.array(z.string().min(1)).default([]),
}).refine((r) => {
  const statuses = [...r.confirmed, ...r.failed, ...(r.pending ?? [])];
  return new Set(statuses).size === statuses.length;
}, { message: "reconciliation statuses must be distinct" });
const OperationToolSchema = z.object({
  tool: z.string().min(1),
  budget: z.string().min(1),
  amountField: z.string().min(1).default("amount"),
  currencyField: z.string().min(1).default("currency"),
  idempotencyHeader: z.string().regex(/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/).default("Idempotency-Key"),
  reconcile: OperationReconcileSchema,
});
const OperationsSchema = z.object({
  database: z.string().min(1),
  budgets: z.array(OperationBudgetSchema).min(1),
  tools: z.array(OperationToolSchema).min(1),
}).superRefine((operations, ctx) => {
  const budgets = new Set<string>();
  for (const [i, budget] of operations.budgets.entries()) {
    if (budgets.has(budget.id)) ctx.addIssue({ code: "custom", path: ["budgets", i, "id"], message: "duplicate operation budget" });
    budgets.add(budget.id);
  }
  const tools = new Set<string>();
  for (const [i, tool] of operations.tools.entries()) {
    if (tools.has(tool.tool)) ctx.addIssue({ code: "custom", path: ["tools", i, "tool"], message: "duplicate financial operation tool" });
    tools.add(tool.tool);
    if (!budgets.has(tool.budget)) ctx.addIssue({ code: "custom", path: ["tools", i, "budget"], message: "unknown operation budget" });
  }
  for (const [i, tool] of operations.tools.entries()) {
    if (tools.has(tool.reconcile.tool)) ctx.addIssue({ code: "custom", path: ["tools", i, "reconcile", "tool"], message: "a reconciliation read cannot be a financial operation tool" });
  }
});
export type OperationsConfig = z.infer<typeof OperationsSchema>;
export type OperationToolConfig = z.infer<typeof OperationToolSchema>;

/** What strict mode refuses in a config, whether or not it is on: an empty list means the config can run strict. */
export function strictRefusals(c: { logFile?: string | undefined; log?: { hashOnly?: boolean | undefined; keys?: string[] | undefined } | undefined }): string[] {
  const out: string[] = [];
  if (c.logFile || !c.log) out.push("strict mode needs a remote log: logFile is a log the operator can rewrite; set log.url to a log someone else runs");
  else {
    if (!c.log.hashOnly) out.push("strict mode needs log.hashOnly: the log is run by someone else, so send it leaf hashes, not receipts");
    if (!c.log.keys?.length) out.push("strict mode needs log.keys: the log's public key files, pinned, to check its answer before any call is forwarded");
  }
  return out;
}

export const GatewayConfigSchema = z.object({
  identity: z.object({ keyFile: z.string() }),
  /** the upstream: an MCP server to spawn over stdio, an MCP URL to reach over Streamable HTTP with an optional bearer token from the environment, or a REST API described as tools */
  upstream: UpstreamSchema.optional(),
  /** several upstreams behind one gateway and one grant; each tool name must belong to exactly one of them */
  upstreams: z.array(UpstreamSchema.and(z.object({ name: z.string().min(1) }))).min(1).optional(),
  /** the one grant a stdio gateway serves; over HTTP each connection presents its own, and this is not needed */
  grantFile: z.string().optional(),
  trustedPrincipalKeys: z.array(z.string()).min(1),
  /** the policy file: Cedar, or Rego when it ends in .rego (compiled with the opa binary on PATH when it loads) */
  policyFile: z.string().optional(),
  /** an OPA server that decides each call instead of a local file; its package defines allow and deny, as a .rego file does */
  opa: z.object({
    url: z.string().url(),
    /** the package path under /v1/data whose allow and deny rules decide; default agentcustody */
    decision: z.string().min(1).regex(/^[A-Za-z_][A-Za-z0-9_]*([./][A-Za-z_][A-Za-z0-9_]*)*$/, "a package path such as agentcustody or authz/agents").optional(),
    tokenEnv: z.string().min(1).optional(),
    /** milliseconds one decision may take before the call is denied; default 2000 */
    timeoutMs: z.number().int().positive().optional(),
  }).optional(),
  facts: z.array(FactSchema).default([]),
  /**
   * Consequential tools, by name or "*" for all: before forwarding one of these, the gateway commits a signed
   * authorization to the log and refuses the call if the log will not take it. Evidence then precedes the side effect.
   */
  precommit: z.array(z.string().min(1)).default([]),
  /** with a remote log, refuse to start when precommit is empty; without it the gateway only warns */
  requirePrecommit: z.boolean().optional(),
  /**
   * Strict mode: every tool is precommitted, the log must be remote, hash-only, and pinned, and no receipt goes to the
   * outbox. A call is forwarded only once its authorization is in a log the operator does not run, and every receipt says
   * `issuer.strict`, so a verifier can require it.
   */
  strict: z.boolean().optional(),
  /** Tools that require a signed, unexpired, single-use approval, in every mode; "*" covers all agent calls. */
  approvals: ApprovalsSchema.optional(),
  /** Durable idempotency, daily budget reservations, and provider reconciliation for financial operations. */
  operations: OperationsSchema.optional(),
  /** a JSON file listing digests of revoked grant envelopes (`agent-custody revoke` appends to it); re-read whenever it changes, checked on every call */
  revokedGrants: z.string().min(1).optional(),
  /** private evidence: what the receipt file carries of each tool's arguments, result, and facts */
  capture: CaptureSchema.optional(),
  /** the environment variable holding the 32-byte key (hex or base64) that encrypts withheld fields in mode encrypted; read at startup, never in the file */
  captureKeyEnv: z.string().min(1).optional(),
  /**
   * "enforce" (the default when absent) denies what the policy denies. "observe" forwards every call the grant and required human approval allow and records the
   * decision the policy would have made, with `enforced: false` on the receipt: the way to run a new policy against
   * real traffic before turning it on. A log that refuses a consequential call's authorization does not withhold the
   * call in observe mode; it is printed.
   */
  mode: z.enum(["enforce", "observe"]).optional(),
  receiptsDir: z.string(),
  logFile: z.string().optional(),
  log: LogSchema.optional(),
  otel: OtelSchema.optional(),
  splunk: SplunkSchema.optional(),
}).refine(hasOneLog, oneLog).refine((c) => (c.upstream ? 1 : 0) + (c.upstreams ? 1 : 0) === 1, { message: "exactly one of upstream or upstreams is required" })
  .refine((c) => (c.policyFile ? 1 : 0) + (c.opa ? 1 : 0) === 1, { message: "exactly one of policyFile or opa is required" })
  // a key fetched from the log itself proves nothing about a log that is dishonest from the start, so a remote log that
  // gates consequential calls must have its keys pinned in the config (issue #99)
  .refine((c) => !c.log || (!c.precommit.length && !c.operations) || !!c.log.keys?.length, { message: "precommit with a remote log needs log.keys: the log's public key files, pinned, to check its answer before a consequential call is forwarded" })
  .superRefine((c, ctx) => { if (c.strict) for (const message of strictRefusals(c)) ctx.addIssue({ code: "custom", path: ["strict"], message }); })
  .refine((c) => !c.requirePrecommit || !c.log || c.precommit.length > 0 || !!c.strict, { message: "requirePrecommit is set and precommit is empty: name the consequential tools in precommit, or [\"*\"]" })
  .refine((c) => !c.operations || !c.facts.some((fact) => c.operations!.tools.some((tool) => tool.tool === fact.tool)), { message: "a fact lookup cannot invoke a financial operation tool" });
export type GatewayConfig = z.infer<typeof GatewayConfigSchema>;
export type FactConfig = z.infer<typeof FactSchema>;

/** Loads a config file and resolves every path relative to the file's directory. */
export function loadConfig(path: string): GatewayConfig {
  const cfg = GatewayConfigSchema.parse(JSON.parse(readFileSync(path, "utf8")));
  const base = dirname(resolve(path));
  const r = (p: string) => resolve(base, p);
  return {
    ...cfg,
    identity: { keyFile: r(cfg.identity.keyFile) },
    ...(cfg.grantFile ? { grantFile: r(cfg.grantFile) } : {}),
    trustedPrincipalKeys: cfg.trustedPrincipalKeys.map(r),
    ...(cfg.policyFile ? { policyFile: r(cfg.policyFile) } : {}),
    receiptsDir: r(cfg.receiptsDir),
    ...(cfg.logFile ? { logFile: r(cfg.logFile) } : {}),
    ...(cfg.log?.keys ? { log: { ...cfg.log, keys: cfg.log.keys.map(r) } } : {}),
    ...(cfg.revokedGrants ? { revokedGrants: r(cfg.revokedGrants) } : {}),
    ...(cfg.approvals ? { approvals: { ...cfg.approvals, trustedKeys: cfg.approvals.trustedKeys.map(r), usedDir: r(cfg.approvals.usedDir) } } : {}),
    ...(cfg.operations ? { operations: { ...cfg.operations, database: r(cfg.operations.database) } } : {}),
  };
}

/** One route of the door: a name the policy sees as the action, and what arrives there. `path` is exact, a prefix when it ends in `/*`, or `*` for anything. The first route that matches wins. */
const DoorRouteSchema = z.object({
  name: z.string().min(1),
  /** methods this route covers; default every method */
  methods: z.array(z.enum(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])).min(1).optional(),
  path: z.string().min(1).regex(/^(\*|\/[^*]*(\/\*)?)$/, "a path is exact (/refunds), a prefix (/api/*), or *"),
});
export type DoorRouteConfig = z.infer<typeof DoorRouteSchema>;

/**
 * The door: a reverse proxy in front of a business's own website, API, or forms. Every arrival is classified (verified,
 * claimed, or unknown), decided by the Cedar policy per route, forwarded to the origin or refused, and receipted either
 * way. The origin's credentials, if any, come from the environment through headerEnv, never from the file or the caller.
 */
export const DoorConfigSchema = z.object({
  identity: z.object({ keyFile: z.string() }),
  /** where allowed requests go: the site or API the door stands in front of */
  origin: z.object({
    url: z.string().url(),
    headers: z.record(z.string(), z.string()).optional(),
    headerEnv: z.record(z.string(), z.string().min(1)).optional(),
    timeoutMs: z.number().int().positive().default(30_000),
  }),
  routes: z.array(DoorRouteSchema).default([]),
  /** the action name for an arrival no route matches; default "other" */
  unmatchedRoute: z.string().min(1).default("other"),
  /** principal keys whose grants the door accepts as a passport: an arrival carrying one of their grants, in scope for its route, is `verified` */
  trustedPrincipalKeys: z.array(z.string()).default([]),
  policyFile: z.string(),
  /** "enforce" (default) refuses what the policy denies; "observe" forwards everything and records the decision with `enforced: false` */
  mode: z.enum(["enforce", "observe"]).optional(),
  /** behind a reverse proxy you run: the arrival's address is the last in X-Forwarded-For, the one that proxy appended, and the client-address headers are relayed as it sent them */
  trustProxy: z.boolean().optional(),
  /** the largest request body the door relays; a larger one is refused with 413 and receipted. Default 1 MiB */
  maxBodyBytes: z.number().int().positive().default(1024 * 1024),
  /** the largest origin response the door relays; a larger one is recorded by size and the client gets 502. Default 32 MiB */
  maxResponseBytes: z.number().int().positive().default(32 * 1024 * 1024),
  /** arrivals handled at once; past this the next is answered 503 before its body is read, and not receipted. Default 256 */
  maxInFlight: z.number().int().positive().default(256),
  /** routes whose arrivals are committed to the log before they are relayed whatever the method, or ["*"]; every arrival whose method is not GET, HEAD, or OPTIONS is committed regardless */
  precommit: z.array(z.string().min(1)).default([]),
  /** the human branch: a Turnstile or hCaptcha token an arrival sends in `header` is verified with the provider, and the outcome is the arrival's `challenge` signal */
  challenge: z.object({
    provider: z.enum(["turnstile", "hcaptcha"]),
    /** the public site key, given back to a refused arrival so a page can render the widget */
    siteKey: z.string().min(1),
    /** the environment variable holding the provider's secret key */
    secretEnv: z.string().min(1),
    header: z.string().min(1).default("x-agent-custody-challenge"),
    timeoutMs: z.number().int().positive().default(5_000),
    /** the hostnames of the pages that render the widget; a token the provider issued on any other host fails */
    hostnames: z.array(z.string().min(1).transform((h) => h.toLowerCase())).min(1),
    /** the widget's action (Turnstile only); when set, a token issued for another action fails */
    action: z.string().min(1).optional(),
    /** checks with the provider at once; an arrival past this is `unavailable`, never relayed on a pass it did not get. Default 64 */
    maxInFlight: z.number().int().positive().default(64),
  }).refine((c) => !c.action || c.provider === "turnstile", { message: "challenge.action is a Turnstile field; hCaptcha does not report an action" }).optional(),
  receiptsDir: z.string(),
  logFile: z.string().optional(),
  log: LogSchema.optional(),
  otel: OtelSchema.optional(),
  splunk: SplunkSchema.optional(),
  capture: CaptureSchema.optional(),
  captureKeyEnv: z.string().min(1).optional(),
}).refine(hasOneLog, oneLog).refine((c) => new Set(c.routes.map((r) => r.name)).size === c.routes.length, { message: "route names must be unique" })
  .refine((c) => !c.log || !!c.log.keys?.length, { message: "a remote log needs log.keys: the log's public key files, pinned, to check its answer before a request is relayed" });
export type DoorConfig = z.infer<typeof DoorConfigSchema>;

/**
 * The egress witness: a forward proxy in the agent's network path for every connection that does not go to the gateway.
 * Each agent proves who it is with its own proxy credential (`Proxy-Authorization: Basic`, id and secret); the secret
 * comes from the environment, never from the file. The Cedar policy decides per destination, and every connection,
 * relayed or refused, is receipted. It records where traffic went, never what was sent: there is no TLS interception.
 */
export const EgressConfigSchema = z.object({
  identity: z.object({ keyFile: z.string() }),
  /** the agents the witness knows, each with the environment variable that holds its proxy secret */
  agents: z.array(z.object({ id: z.string().min(1).max(200).regex(/^[^:\s]+$/, "an agent id has no colon or whitespace: Basic credentials split at the first colon"), secretEnv: z.string().min(1) })).min(1),
  policyFile: z.string(),
  /** "enforce" (default) refuses what the policy denies; "observe" relays every connection from a known agent and records the decision with `enforced: false` */
  mode: z.enum(["enforce", "observe"]).optional(),
  /** how long the witness waits for the destination to accept the connection. Default 10 s */
  connectTimeoutMs: z.number().int().positive().default(10_000),
  /** a relayed connection with no bytes either way for this long is closed. Default 5 minutes */
  idleTimeoutMs: z.number().int().positive().default(300_000),
  /** connections handled at once; past this the next is answered 503 and is not relayed or receipted. Default 256 */
  maxInFlight: z.number().int().positive().default(256),
  receiptsDir: z.string(),
  logFile: z.string().optional(),
  log: LogSchema.optional(),
  otel: OtelSchema.optional(),
  splunk: SplunkSchema.optional(),
}).refine(hasOneLog, oneLog).refine((c) => new Set(c.agents.map((a) => a.id)).size === c.agents.length, { message: "agent ids must be unique" });
export type EgressConfig = z.infer<typeof EgressConfigSchema>;

export function loadEgressConfig(path: string): EgressConfig {
  const cfg = EgressConfigSchema.parse(JSON.parse(readFileSync(path, "utf8")));
  const base = dirname(resolve(path));
  const r = (p: string) => resolve(base, p);
  return {
    ...cfg,
    identity: { keyFile: r(cfg.identity.keyFile) },
    policyFile: r(cfg.policyFile),
    receiptsDir: r(cfg.receiptsDir),
    ...(cfg.logFile ? { logFile: r(cfg.logFile) } : {}),
    ...(cfg.log?.keys ? { log: { ...cfg.log, keys: cfg.log.keys.map(r) } } : {}),
  };
}

export function loadDoorConfig(path: string): DoorConfig {
  const cfg = DoorConfigSchema.parse(JSON.parse(readFileSync(path, "utf8")));
  const base = dirname(resolve(path));
  const r = (p: string) => resolve(base, p);
  return {
    ...cfg,
    identity: { keyFile: r(cfg.identity.keyFile) },
    trustedPrincipalKeys: cfg.trustedPrincipalKeys.map(r),
    policyFile: r(cfg.policyFile),
    receiptsDir: r(cfg.receiptsDir),
    ...(cfg.logFile ? { logFile: r(cfg.logFile) } : {}),
    ...(cfg.log?.keys ? { log: { ...cfg.log, keys: cfg.log.keys.map(r) } } : {}),
  };
}

export const SdkConfigSchema = z.object({
  /** identity the receipts will name; nothing checks it, so it is recorded as claimed */
  agentId: z.string().min(1),
  principalId: z.string().min(1).optional(),
  identity: z.object({ keyFile: z.string() }),
  /** optional policy, Cedar or Rego (.rego); when present, wrapped tools and PreToolUse hooks can deny */
  policyFile: z.string().optional(),
  /** "observe" records the policy's decision with `enforced: false` and never blocks; "enforce" (default) blocks a deny */
  mode: z.enum(["enforce", "observe"]).optional(),
  receiptsDir: z.string(),
  logFile: z.string().optional(),
  log: LogSchema.optional(),
  otel: OtelSchema.optional(),
  splunk: SplunkSchema.optional(),
  /** free-text label of the host framework, e.g. "claude-code", "openai-agents" */
  framework: z.string().optional(),
  /** private evidence, as for the gateway */
  capture: CaptureSchema.optional(),
  captureKeyEnv: z.string().min(1).optional(),
}).refine(hasOneLog, oneLog);
export type SdkConfig = z.infer<typeof SdkConfigSchema>;

export function loadSdkConfig(path: string): SdkConfig {
  const cfg = SdkConfigSchema.parse(JSON.parse(readFileSync(path, "utf8")));
  const base = dirname(resolve(path));
  const r = (p: string) => resolve(base, p);
  return {
    ...cfg,
    identity: { keyFile: r(cfg.identity.keyFile) },
    ...(cfg.policyFile ? { policyFile: r(cfg.policyFile) } : {}),
    receiptsDir: r(cfg.receiptsDir),
    ...(cfg.logFile ? { logFile: r(cfg.logFile) } : {}),
    ...(cfg.log?.keys ? { log: { ...cfg.log, keys: cfg.log.keys.map(r) } } : {}),
  };
}
