// Where log leaves go.
// The file sink is the local Merkle log, with tree heads signed by the issuer's own key: tamper-evident, but the
// operator holds the file. The HTTP sink hands each leaf to a log run by someone else, who signs the tree head with
// their key. A verifier who trusts that key learns the receipt was in a log the operator cannot rewrite.
// logHandler and serveLog are the other side: a reference log server over node:http, the same code a hosted log runs.
import { timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { dsseSign, dsseVerify, loadPublicKey, type Envelope, type KeyPair, type PublicKeyRef } from "./crypto.ts";
import { createHash } from "node:crypto";
import { leafHash, MerkleLog, verifyInclusion, type InclusionProof } from "./log.ts";
import { type AuditEntry, type QuotaState, fileBackend, RateLimiter, type LogBackend, type PostgresTenancy, type RateLimitOptions , type PolicyRecord } from "./log-store.ts";
import { fetchLogKeys, localSigner, shownUrl, type Signer } from "./signer.ts";
import type { Checkpoint, CheckpointStore } from "./checkpoints.ts";
import { adminRoutes, type AdminOptions } from "./log-admin.ts";
import { TREEHEAD_TYPE, type TreeHead } from "./receipt.ts";

export interface LogAppend {
  inclusion: InclusionProof;
  /** signed TreeHead; the signature's keyid says who runs the log */
  treeHead: Envelope;
}

export interface LogSink {
  readonly kind: "file" | "http";
  /** the file path or the URL, for reports */
  readonly where: string;
  append(leaf: string): Promise<LogAppend>;
}

function signedHead(e: { treeSize: number; rootHash: string }, key: KeyPair, logId?: string): Envelope {
  const head: TreeHead = { treeSize: e.treeSize, rootHash: e.rootHash, timestamp: new Date().toISOString(), ...(logId ? { log: logId } : {}) };
  return dsseSign(TREEHEAD_TYPE, head, key);
}

async function signHead(e: { treeSize: number; rootHash: string }, signer: Signer, logId?: string): Promise<Envelope> {
  const head: TreeHead = { treeSize: e.treeSize, rootHash: e.rootHash, timestamp: new Date().toISOString(), ...(logId ? { log: logId } : {}) };
  return signer.sign(TREEHEAD_TYPE, head);
}

async function appendSigned(log: LogBackend, signer: Signer, leaf: { leaf: string } | { leafHash: string }, logId?: string): Promise<LogAppend> {
  const e = "leaf" in leaf ? await log.append(leaf.leaf) : await log.appendHash(leaf.leafHash);
  return { inclusion: { leafIndex: e.leafIndex, treeSize: e.treeSize, hashes: e.hashes }, treeHead: await signHead(e, signer, logId) };
}

/** A local JSONL Merkle log. Tree heads are signed with the given key, normally the issuer's own. */
export function fileLog(file: string, key: KeyPair): LogSink {
  const log = new MerkleLog(file);
  return {
    kind: "file",
    where: file,
    async append(leaf) {
      const e = log.append(leaf);
      return { inclusion: { leafIndex: e.leafIndex, treeSize: e.treeSize, hashes: e.hashes }, treeHead: signedHead(e, key) };
    },
  };
}

export interface HttpLogOptions {
  /** sent as a bearer token; the log decides what it is worth */
  token?: string;
  /** send only the leaf hash; the log then commits to the receipt without ever holding it. Use it for any log run by someone else. */
  hashOnly?: boolean;
  /** attempts on 429 and 5xx; default 3 */
  retries?: number;
  /** how long one append may take before it counts as unreachable; default 10000. A log that accepts and never answers must not hold a call forever. */
  timeoutMs?: number;
  /** the log's public keys, pinned: the tree head in every append's answer must be signed by one of them. Without them, the key document at the log's /.well-known/agent-custody-log.json is fetched on first use and pinned for the life of the sink. */
  keys?: PublicKeyRef[];
  /** the id the log must write into every tree head; an answer naming another log, or none, is refused */
  logId?: string;
  fetch?: typeof fetch;
}

/**
 * A log reached over HTTP: POST <url>/append with {leaf} or {leafHash}, expecting a LogAppend back. A 429 or a 5xx
 * is retried a few times with backoff, honouring Retry-After; anything else, or the last failure, is the caller's.
 *
 * The answer is not taken on trust. Before it is returned, and so before a pre-committed call is forwarded, the tree
 * head must verify against the log's pinned keys, name the expected log, match the proof's size, and the inclusion
 * proof must place this very leaf under the signed root. A log that answers with anything else has refused the append.
 */
export function httpLog(url: string, opts: HttpLogOptions = {}): LogSink {
  const f = opts.fetch ?? fetch;
  const shown = shownUrl(url);
  const base = url.endsWith("/") ? url : `${url}/`;
  const attempts = opts.retries ?? 3;
  const timeoutMs = opts.timeoutMs ?? 10_000;
  let pinned: Promise<PublicKeyRef[]> | null = opts.keys?.length ? Promise.resolve(opts.keys) : null;
  const keys = () => (pinned ??= fetchLogKeys(base, f).then((r) => r.keys).catch((e) => { pinned = null; throw new Error(`log ${shown}: its keys could not be fetched to check the append, and none are configured: ${e instanceof Error ? e.message : String(e)}`); }));
  const checked = async (entry: LogAppend, leaf: string): Promise<LogAppend> => {
    const th = dsseVerify(entry.treeHead, await keys());
    if (!th.ok || entry.treeHead.payloadType !== TREEHEAD_TYPE) throw new Error(`log ${shown} answered with a tree head that does not verify against its keys${th.ok ? " (wrong payload type)" : `: ${th.error}`}`);
    const head = th.payload as TreeHead;
    if (opts.logId !== undefined && head.log !== opts.logId) throw new Error(`log ${shown} signed a tree head for log "${head.log ?? ""}", not "${opts.logId}"`);
    if (head.treeSize !== entry.inclusion.treeSize) throw new Error(`log ${shown} answered with a tree head of size ${head.treeSize} and a proof for size ${entry.inclusion.treeSize}`);
    if (!verifyInclusion(leafHash(leaf), entry.inclusion, head.rootHash)) throw new Error(`log ${shown} answered with an inclusion proof that does not place this leaf under the signed root`);
    return entry;
  };
  return {
    kind: "http",
    where: url,
    async append(leaf) {
      let last = "";
      for (let i = 0; i < attempts; i++) {
        let res: Response;
        try {
          res = await f(new URL("append", base), {
            method: "POST",
            headers: { "content-type": "application/json", ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}) },
            body: JSON.stringify(opts.hashOnly ? { leafHash: leafHash(leaf).toString("hex") } : { leaf }),
            signal: AbortSignal.timeout(timeoutMs),
          });
        } catch (e) {
          last = `log ${shown} unreachable: ${e instanceof Error ? e.message : String(e)}`;
          if (i + 1 < attempts) await new Promise((r) => setTimeout(r, 200 * 2 ** i));
          continue;
        }
        if (res.ok) {
          const body = (await res.json()) as Partial<LogAppend>;
          if (!body.inclusion || !body.treeHead) throw new Error(`log ${shown} returned a malformed append result`);
          return checked(body as LogAppend, leaf);
        }
        last = `log ${shown} refused the append: ${res.status} ${(await res.text()).slice(0, 200)}`;
        if (res.status !== 429 && res.status < 500) break;
        if (i + 1 < attempts) {
          const after = Number(res.headers.get("retry-after"));
          await new Promise((r) => setTimeout(r, Number.isFinite(after) && after > 0 ? Math.min(after, 5) * 1000 : 200 * 2 ** i));
        }
      }
      throw new Error(last);
    },
  };
}

export interface LogConfig {
  logFile?: string | undefined;
  log?: { url: string; tokenEnv?: string | undefined; hashOnly?: boolean | undefined; timeoutMs?: number | undefined; keys?: string[] | undefined; logId?: string | undefined } | undefined;
}

/** The sink a config asks for: a remote log when `log` is set, otherwise the local file. */
export function openLog(cfg: LogConfig, key: KeyPair): LogSink {
  if (cfg.log) {
    const token = cfg.log.tokenEnv ? process.env[cfg.log.tokenEnv] : undefined;
    if (cfg.log.tokenEnv && !token) throw new Error(`log token: environment variable ${cfg.log.tokenEnv} is not set`);
    return httpLog(cfg.log.url, { ...(token === undefined ? {} : { token }), ...(cfg.log.hashOnly ? { hashOnly: true } : {}), ...(cfg.log.timeoutMs ? { timeoutMs: cfg.log.timeoutMs } : {}), ...(cfg.log.keys ? { keys: cfg.log.keys.map(loadPublicKey) } : {}), ...(cfg.log.logId ? { logId: cfg.log.logId } : {}) });
  }
  if (!cfg.logFile) throw new Error("config needs logFile or log.url");
  return fileLog(cfg.logFile, key);
}

export interface LogServerOptions {
  /** bearer tokens accepted on append; when empty, anyone may append */
  tokens?: string[];
  /** the id written into every tree head this log signs, so a head cannot be presented as another log's */
  logId?: string;
  /**
   * More logs behind the same server, one per tenant, reached at /t/<tenant>/...: each with its own file, tokens,
   * and id. The default log stays at the root paths. This is the shape a hosted log takes; the reference server
   * runs it from a small JSON file.
   */
  tenants?: Record<string, { file: string; tokens?: string[]; logId?: string }>;
  /** appends per token (or per address without one); default 50 a second, burst 100 */
  rateLimit?: RateLimitOptions;
  /** accept only { leafHash } on append: a log run for other people must never receive a receipt */
  hashOnly?: boolean;
  /** largest append body accepted, in bytes; default 65536 */
  maxBodyBytes?: number;
  /** where published checkpoints go and are listed from; without one, /checkpoints answers with none */
  checkpoints?: CheckpointStore;
  /** the operator's admin API and page under /admin, behind its own token; only with a Postgres tenancy */
  admin?: AdminOptions;
  /**
   * Behind a reverse proxy every request arrives from the proxy's address, so per-address limits would be shared by
   * everyone. With this on, the first address in X-Forwarded-For is the client. Only set it when a proxy you run
   * is the only way to reach this server, since the header is otherwise the client's to forge.
   */
  trustProxy?: boolean;
}

/** The address a limit is keyed by: the socket's, or the proxy's forwarded one when the proxy is trusted. */
/**
 * The address a per-client limit keys on. Behind a proxy you run, the proxy appends the real client to
 * X-Forwarded-For, so the rightmost entry is the one it wrote; everything left of it is whatever the client sent.
 */
export function clientAddress(req: IncomingMessage, trustProxy = false): string {
  if (trustProxy) {
    const xff = req.headers["x-forwarded-for"];
    const entries = (Array.isArray(xff) ? xff.join(",") : xff ?? "").split(",").map((s) => s.trim()).filter(Boolean);
    const last = entries[entries.length - 1];
    if (last) return last;
  }
  return req.socket.remoteAddress ?? "?";
}

/** One log as the handler sees it, whatever stands behind it. */
export interface TenantUsage {
  month: string;
  appends: number;
  totalLeaves: number;
  liveTokens: number;
}

export interface ResolvedLog {
  backend: LogBackend;
  logId: string | undefined;
  authorize(token: string | null): Promise<boolean>;
  /** this log's own metering for a month, where the store keeps it */
  usage?(month: string): Promise<TenantUsage>;
  /** administrative actions on this log, newest first, where the store keeps them */
  audit?(limit: number): Promise<AuditEntry[]>;
  /** the plan's monthly allowance and what is used, where the store keeps plans */
  quota?(): Promise<QuotaState>;
  /** told after an append lands, so a cached quota count stays honest */
  appended?(): void;
  /** the policy versions the tenant published, with their text, for the export */
  policies?: () => Promise<PolicyRecord[] & { text?: string }[]>;
}

/** Turns the tenant in a path, or null for the root paths, into a log. */
export interface LogResolver {
  resolve(tenant: string | null): Promise<ResolvedLog | null>;
  /** every log this server has, null for the root one; what the checkpoint publisher walks */
  tenants(): Promise<(string | null)[]>;
}

const tokenMatches = (tokens: string[], token: string | null): boolean => {
  if (tokens.length === 0) return true;
  if (!token) return false;
  const given = Buffer.from(token);
  return tokens.some((t) => {
    const want = Buffer.from(t);
    return want.length === given.length && timingSafeEqual(want, given);
  });
};

/** The reference server's logs: one file for the root paths and, optionally, a file per tenant from the options. */
export function fileResolver(file: string, opts: LogServerOptions = {}): LogResolver {
  const root: ResolvedLog = { backend: fileBackend(file), logId: opts.logId, authorize: async (t) => tokenMatches(opts.tokens ?? [], t) };
  const tenants = new Map<string, ResolvedLog>();
  for (const [name, t] of Object.entries(opts.tenants ?? {})) tenants.set(name, { backend: fileBackend(t.file), logId: t.logId ?? name, authorize: async (tok) => tokenMatches(t.tokens ?? [], tok) });
  return {
    async resolve(tenant) {
      return tenant === null ? root : (tenants.get(tenant) ?? null);
    },
    async tenants() {
      return [null, ...tenants.keys()];
    },
  };
}

/**
 * Logs in Postgres: every tenant from the tenants table, each with its own log and tokens; the root paths serve the
 * tenant named `defaultTenant`, which also accepts `staticTokens` so a server can keep its environment token.
 */
export function postgresResolver(tenancy: PostgresTenancy, opts: { defaultTenant?: string; staticTokens?: string[] } = {}): LogResolver {
  const def = opts.defaultTenant ?? "default";
  return {
    async resolve(tenant) {
      const id = tenant ?? def;
      const t = await tenancy.tenant(id);
      if (!t || t.disabledAt) return null;
      const backend = await tenancy.log(id);
      return {
        backend,
        logId: t.logId,
        authorize: async (tok) => (tenant === null && (opts.staticTokens?.length ?? 0) > 0 && tokenMatches(opts.staticTokens!, tok)) || (await tenancy.authorize(id, tok)),
        usage: async (month) => {
          const u = await tenancy.usage(month);
          const row = u.tenants.find((t) => t.id === id);
          return { month, appends: row?.appends ?? 0, totalLeaves: row?.totalLeaves ?? 0, liveTokens: row?.liveTokens ?? 0 };
        },
        audit: (limit) => tenancy.audit({ tenant: id, limit }),
        policies: async () => Promise.all((await tenancy.listPolicies(id)).map(async (p) => ({ ...p, text: (await tenancy.policy(id, p.id))?.text }))),
        quota: () => tenancy.quota(id),
        appended: () => tenancy.noteAppend(id),
      };
    },
    async tenants() {
      return (await tenancy.listTenants()).filter((t) => !t.disabledAt).map((t) => (t.id === def ? null : t.id));
    },
  };
}

/**
 * Publishes one checkpoint per log whose tree has grown since the last one: the current head, signed, into the
 * checkpoint store. Call publishOnce on a timer, or start() to run it every `everyMs`.
 */
export class CheckpointPublisher {
  private timer: ReturnType<typeof setInterval> | null = null;
  private readonly resolver: LogResolver;
  private readonly signer: Signer;
  private readonly store: CheckpointStore;
  private readonly everyMs: number;
  private readonly heartbeatMs: number;
  private readonly warn: (m: string) => void;
  /**
   * `heartbeatMs`: a log that has not grown still gets its head re-signed this often (default six hours), so a fresh
   * signature says "still this head, as of now" and a quiet log is not mistaken for a stalled publisher.
   */
  constructor(resolver: LogResolver, signer: Signer, store: CheckpointStore, everyMs = 300_000, warn: (m: string) => void = (m) => console.error(m), heartbeatMs = 6 * 3_600_000) {
    this.resolver = resolver;
    this.signer = signer;
    this.store = store;
    this.everyMs = everyMs;
    this.heartbeatMs = heartbeatMs;
    this.warn = warn;
  }

  /** Publishes for every log that has grown, or whose latest checkpoint is older than the heartbeat; returns the checkpoints written. */
  async publishOnce(): Promise<Checkpoint[]> {
    const out: Checkpoint[] = [];
    for (const tenant of await this.resolver.tenants()) {
      try {
        const r = await this.resolver.resolve(tenant);
        if (!r) continue;
        const name = tenant ?? "default";
        const size = await r.backend.size();
        if (size === 0) continue; // an empty tree is not a checkpoint worth publishing
        const last = await this.store.latest(name);
        if (last && last.treeSize >= size && Date.now() - Date.parse(last.signedAt) < this.heartbeatMs) continue;
        const rootHash = await r.backend.root(size);
        const envelope = await signHead({ treeSize: size, rootHash }, this.signer, r.logId);
        const c: Checkpoint = { tenant: name, logId: r.logId, treeSize: size, rootHash, signedAt: new Date().toISOString(), envelope };
        await this.store.save(c);
        out.push(c);
      } catch (e) {
        this.warn(`agent-custody log: checkpoint for ${tenant ?? "default"} failed: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
    return out;
  }

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.publishOnce(), this.everyMs);
    this.timer.unref?.();
    void this.publishOnce();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }
}

/**
 * The reference log server as a node:http request handler.
 *   POST /append  {leaf}   -> LogAppend, tree head signed with the log's key
 *   GET  /root?size=N      -> {treeSize, rootHash}, for auditors checking a tree head against the log
 *   GET  /consistency?old=M&new=N -> {oldSize, newSize, hashes}, proof that the log at N extends the log at M
 *   GET  /head             -> {treeHead}, the current tree head signed with the log's key
 */
export function logHandler(source: string | LogResolver, keyOrSigner: KeyPair | Signer, opts: LogServerOptions = {}): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  const resolver = typeof source === "string" ? fileResolver(source, opts) : source;
  const signer: Signer = "privateKey" in keyOrSigner ? localSigner(keyOrSigner) : keyOrSigner;
  const admin = opts.admin ? adminRoutes({ ...opts.admin, keyid: opts.admin.keyid ?? signer.keyid, trustProxy: opts.trustProxy ?? opts.admin.trustProxy }) : null;
  const limiter = new RateLimiter(opts.rateLimit);
  const maxBody = opts.maxBodyBytes ?? 65_536;
  const bearer = (req: IncomingMessage): string | null => {
    const h = req.headers.authorization ?? "";
    return h.startsWith("Bearer ") && h.length > 7 ? h.slice(7) : null;
  };
  return async (req, res) => {
    const json = (status: number, body: unknown, headers: Record<string, string> = {}) => {
      res.writeHead(status, { "content-type": "application/json", ...headers });
      res.end(JSON.stringify(body));
    };
    const url = new URL(req.url ?? "/", "http://localhost");
    if (admin && (await admin(req, res, url))) return;
    if (req.method === "GET" && url.pathname === "/health") {
      // Liveness for a load balancer or a container: the signer answers and the default log answers. No secrets, no sizes.
      try {
        const doc = await signer.keys();
        const root = await resolver.resolve(null);
        return json(root ? 200 : 503, { ok: !!root, keyid: doc.keys[0]?.keyid ?? null, checkpoints: !!opts.checkpoints }, { "cache-control": "no-store" });
      } catch (e) {
        return json(503, { ok: false, error: e instanceof Error ? e.message : String(e) });
      }
    }
    if (req.method === "GET" && url.pathname === "/.well-known/agent-custody-log.json") {
      try {
        const doc = await signer.keys();
        const root = await resolver.resolve(null);
        return json(200, { ...(root?.logId ? { log: root.logId } : {}), ...doc }, { "cache-control": "public, max-age=300" });
      } catch (e) {
        return json(503, { error: `keys unavailable: ${e instanceof Error ? e.message : String(e)}` });
      }
    }
    // /t/<tenant>/<op> reaches that tenant's log; anything else is the default log.
    const m = /^\/t\/([A-Za-z0-9_.-]+)\/(append|root|consistency|head|checkpoints|leaves|usage|audit|policies)$/.exec(url.pathname);
    let which: ResolvedLog | null;
    try {
      which = await resolver.resolve(m ? m[1]! : null);
    } catch (e) {
      return json(503, { error: `log unavailable: ${e instanceof Error ? e.message : String(e)}` });
    }
    if (!which) return json(404, { error: "unknown log" });
    const { backend: log, logId } = which;
    try {
      if (req.method === "POST" && url.pathname.endsWith("/append")) {
        const token = bearer(req);
        if (!(await which.authorize(token))) return json(401, { error: "unauthorized" });
        if (which.quota) {
          // The plan's monthly allowance. Over it, the append is refused with the numbers, and the gateway behind it
          // withholds pre-committed calls: a tenant out of quota never acts without evidence.
          const q = await which.quota();
          if (q.quota !== null && q.used >= q.quota) {
            const now = new Date();
            const monthEnd = Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1);
            return json(429, { error: `monthly quota reached: ${q.used} of ${q.quota} appends on the ${q.plan} plan; it resets at the start of next month, or move to a larger plan` }, { "retry-after": String(Math.max(1, Math.ceil((monthEnd - now.getTime()) / 1000))) });
          }
        }
        const limitKey = token ? createHash("sha256").update(token).digest("hex").slice(0, 16) : `addr:${clientAddress(req, opts.trustProxy)}`;
        if (!limiter.take(limitKey)) return json(429, { error: "too many appends; retry shortly" }, { "retry-after": "1" });
        let body = "";
        for await (const chunk of req) {
          body += chunk;
          if (body.length > maxBody) return json(413, { error: `append body larger than ${maxBody} bytes` });
        }
        let parsed: { leaf?: unknown; leafHash?: unknown };
        try {
          parsed = JSON.parse(body) as { leaf?: unknown; leafHash?: unknown };
        } catch {
          return json(400, { error: "body must be JSON {leaf} or {leafHash}" });
        }
        if (typeof parsed.leafHash === "string") {
          if (!/^[0-9a-f]{64}$/.test(parsed.leafHash)) return json(400, { error: "leafHash must be 64 lowercase hex characters" });
          const r = await appendSigned(log, signer, { leafHash: parsed.leafHash }, logId);
          which.appended?.();
          return json(200, r);
        }
        if (opts.hashOnly) return json(400, { error: "this log accepts leaf hashes only; set \"hashOnly\": true in your log config so the receipt never leaves your machine" });
        if (typeof parsed.leaf !== "string" || parsed.leaf.length === 0) return json(400, { error: "leaf must be a non-empty string, or send leafHash" });
        const r = await appendSigned(log, signer, { leaf: parsed.leaf }, logId);
        which.appended?.();
        return json(200, r);
      }
      const current = await log.size();
      // A tenant's own data, with their token: every leaf hash, in pages, and their metering. The export command
      // pages through these and rebuilds a log file the verifier reads directly.
      if (req.method === "GET" && (url.pathname.endsWith("/leaves") || url.pathname.endsWith("/usage") || url.pathname.endsWith("/audit") || url.pathname.endsWith("/policies"))) {
        if (!(await which.authorize(bearer(req)))) return json(401, { error: "unauthorized" });
        if (url.pathname.endsWith("/policies")) {
          if (!which.policies) return json(404, { error: "this log keeps no policies" });
          return json(200, { policies: await which.policies() }, { "cache-control": "no-store" });
        }
        if (url.pathname.endsWith("/audit")) {
          if (!which.audit) return json(404, { error: "this log keeps no audit trail" });
          const limit = url.searchParams.has("limit") ? Number(url.searchParams.get("limit")) : 200;
          if (!Number.isInteger(limit) || limit < 1 || limit > 1000) return json(400, { error: "limit must be an integer in 1..1000" });
          return json(200, { entries: await which.audit(limit) }, { "cache-control": "no-store" });
        }
        if (url.pathname.endsWith("/usage")) {
          if (!which.usage) return json(404, { error: "this log keeps no usage" });
          const month = url.searchParams.get("month") ?? new Date().toISOString().slice(0, 7);
          if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(month)) return json(400, { error: "month must be YYYY-MM" });
          const u = await which.usage(month);
          const q = which.quota ? await which.quota() : null;
          return json(200, { ...u, ...(q ? { plan: q.plan, quota: q.quota } : {}) }, { "cache-control": "no-store" });
        }
        const since = url.searchParams.has("since") ? Number(url.searchParams.get("since")) : 0;
        const limit = url.searchParams.has("limit") ? Number(url.searchParams.get("limit")) : 10_000;
        if (!Number.isInteger(since) || since < 0 || since > current) return json(400, { error: `since must be an integer in 0..${current}` });
        if (!Number.isInteger(limit) || limit < 1 || limit > 10_000) return json(400, { error: "limit must be an integer in 1..10000" });
        return json(200, { since, size: current, leaves: await log.leafHashes(since, since + limit) }, { "cache-control": "no-store" });
      }
      if (req.method === "GET" && url.pathname.endsWith("/root")) {
        const size = url.searchParams.has("size") ? Number(url.searchParams.get("size")) : current;
        if (!Number.isInteger(size) || size < 0 || size > current) return json(400, { error: `size must be an integer in 0..${current}` });
        return json(200, { treeSize: size, rootHash: await log.root(size) });
      }
      if (req.method === "GET" && url.pathname.endsWith("/consistency")) {
        const oldSize = Number(url.searchParams.get("old"));
        const newSize = url.searchParams.has("new") ? Number(url.searchParams.get("new")) : current;
        if (![oldSize, newSize].every(Number.isInteger) || oldSize < 0 || oldSize > newSize || newSize > current) return json(400, { error: `old and new must be integers with 0 <= old <= new <= ${current}` });
        return json(200, { oldSize, newSize, hashes: await log.consistencyProof(oldSize, newSize) });
      }
      if (req.method === "GET" && url.pathname.endsWith("/head")) {
        return json(200, { treeHead: await signHead({ treeSize: current, rootHash: await log.root(current) }, signer, logId) });
      }
      if (req.method === "GET" && url.pathname.endsWith("/checkpoints")) {
        const since = url.searchParams.has("since") ? Number(url.searchParams.get("since")) : -1;
        if (!Number.isInteger(since)) return json(400, { error: "since must be an integer tree size" });
        const list = opts.checkpoints ? await opts.checkpoints.list(m ? m[1]! : "default", since) : [];
        return json(200, { checkpoints: list.map((c) => ({ treeSize: c.treeSize, rootHash: c.rootHash, signedAt: c.signedAt, treeHead: c.envelope })) });
      }
      return json(404, { error: "not found" });
    } catch (e) {
      return json(500, { error: e instanceof Error ? e.message : String(e) });
    }
  };
}

export interface RunningLog {
  url: string;
  close(): Promise<void>;
}

/** Starts the reference log server. Port 0 picks a free port. */
export function serveLog(source: string | LogResolver, keyOrSigner: KeyPair | Signer, opts: LogServerOptions & { port: number; host?: string }): Promise<RunningLog> {
  const host = opts.host ?? "127.0.0.1";
  const handler = logHandler(source, keyOrSigner, opts);
  const server = createServer((req, res) => {
    void handler(req, res);
  });
  return new Promise((resolve) => {
    server.listen(opts.port, host, () => {
      const { port } = server.address() as AddressInfo;
      resolve({ url: `http://${host}:${port}/`, close: () => new Promise((r) => server.close(() => r())) });
    });
  });
}
