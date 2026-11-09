// The egress witness: an HTTP forward proxy in the agent's network path, the door turned around to face outbound
// traffic. An agent whose environment is locked down (default-deny egress except the gateway and this witness) reaches
// anything else only through here. Each connection is tied to an agent by the proxy credential the witness checked,
// decided by the Cedar policy for its destination, relayed or refused, and receipted either way with issuer kind
// `egress`. CONNECT is relayed as an opaque tunnel: the witness sees the destination, the times, and the byte counts,
// never the request, the response, or anything inside TLS. A receipt is an observed bypass of the gateway, not a record
// of what was done.
import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { closeSync, fstatSync, openSync, readFileSync } from "node:fs";
import { createServer, request as httpRequest, type IncomingMessage, type Server as HttpServer, type ServerResponse } from "node:http";
import { lookup as dnsLookup } from "node:dns";
import { connect, isIP, type AddressInfo, type LookupFunction, type Socket } from "node:net";
import type { Duplex } from "node:stream";
import type { EgressConfig } from "./config.ts";
import { internalAddress } from "./addresses.ts";
import { digestOf, loadPrivateKey } from "./crypto.ts";
import { RECEIPT_HEADER } from "./door.ts";
import { createIssuer, ReceiptPending, type FlushResult } from "./issue.ts";
import { openLog, type LogSink } from "./log-sink.ts";
import { openExporter, type ReceiptExporter } from "./otel.ts";
import { evaluate, hasPermitRule, policyDigest, policyParseErrors, type PolicyDecision } from "./policy.ts";
import type { AuthorizationBundle, FactRecord, ReceiptPredicate } from "./receipt.ts";

export const EGRESS_VERSION = "0.1.0";
/** the fact every egress receipt carries, and the policy reads as `context.facts.destination` */
export const DESTINATION_FACT = "destination";
export const PROXY_REALM = "agent-custody egress";

/** What the witness observed about one connection before it decided. Only `declared` is the agent's word, and says so. */
export interface Destination {
  host: string;
  port: number;
  /** `connect`: a CONNECT tunnel, opaque to the witness. `http`: a plain HTTP request in absolute form */
  scheme: "connect" | "http";
  /** what became of the proxy credential: it matched the secret the witness holds for that agent, it did not, or none was sent */
  credential: "verified" | "invalid" | "absent";
  /** the agent id in a credential that did not verify; a claim, never checked */
  declared?: string;
  /** the socket's address: a forward proxy has nothing in front of it, so no header the agent wrote is believed */
  remote: string;
}

/** How a relayed connection ended: both sides closed, one side failed, no bytes for `idleTimeoutMs`, or the witness stopped. */
export type EgressEnd = "closed" | "reset" | "idle-timeout" | "witness-stopped";

/** What a receipt records of a relayed connection: where the witness actually connected, when, how many bytes, how it ended. */
export interface EgressResult {
  /** the address the witness connected to, after its own name resolution */
  peer: string;
  openedAt: string;
  closedAt: string;
  /** bytes from the agent to the destination: the tunnel's payload, or a plain request's body */
  bytesUp: number;
  /** bytes from the destination to the agent: the tunnel's payload, or a plain response's body */
  bytesDown: number;
  end: EgressEnd;
  /** a plain HTTP request only: the status the destination answered */
  status?: number;
}

/**
 * Lowercase, without a final dot or IPv6 brackets; refused unless it is an IP address or a DNS name. A name whose last
 * label is all digits or starts with `0x` is refused: the URL parser and `getaddrinfo` read it as an IPv4 address
 * (`2130706433`, `0x7f.1`), so the policy would decide on a string that is not the address dialled.
 */
export function normalizeHost(raw: string): string | null {
  let h = raw.toLowerCase();
  if (h.startsWith("[") && h.endsWith("]")) {
    h = h.slice(1, -1);
    return isIP(h) === 6 ? h : null;
  }
  if (h.endsWith(".")) h = h.slice(0, -1);
  if (isIP(h)) return h;
  if (h.length === 0 || h.length > 253) return null;
  const last = h.slice(h.lastIndexOf(".") + 1);
  if (/^\d+$/.test(last) || last.startsWith("0x")) return null;
  return h.split(".").every((label) => /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/.test(label)) ? h : null;
}

function parsePort(raw: string): number | null {
  if (!/^\d{1,5}$/.test(raw)) return null;
  const n = Number(raw);
  return n >= 1 && n <= 65535 ? n : null;
}

/**
 * A CONNECT authority, `host:port` or `[v6]:port`; the port is required. The host goes through the same URL parser as a
 * plain request's, so both paths decide on one canonical string: `010.0.0.1` is `8.0.0.1` and `2130706433` is
 * `127.0.0.1`, the addresses `getaddrinfo` would dial.
 */
export function parseAuthority(authority: string): { host: string; port: number } | null {
  const m = /^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._-]+):(\d+)$/.exec(authority);
  if (!m) return null;
  let canonical: string;
  try {
    canonical = new URL(`http://${m[1]!}/`).hostname;
  } catch {
    return null;
  }
  const host = normalizeHost(canonical);
  const port = parsePort(m[2]!);
  return host && port ? { host, port } : null;
}

/** The policy's action for a destination: `host:port`, with an IPv6 address in brackets. */
export const destinationName = (host: string, port: number) => `${isIP(host) === 6 ? `[${host}]` : host}:${port}`;

export interface AgentCredential {
  id: string;
  secret: string;
}

const sha = (s: string) => createHash("sha256").update(s).digest();
/** compared against on every unknown id, so a miss costs what a hit costs: one hash of the presented secret and one compare */
const STAND_IN = sha(`stand-in:${randomUUID()}`);

/**
 * Checks `Proxy-Authorization: Basic base64(id:secret)` against the secrets the witness holds. The comparison is over
 * sha256 digests in constant time, and runs against one stand-in, hashed once, when the id is unknown, so the answer
 * time does not say which ids exist.
 */
export function checkProxyCredential(header: string | undefined, agents: ReadonlyMap<string, Buffer>): { credential: Destination["credential"]; agent?: string; declared?: string } {
  if (!header) return { credential: "absent" };
  const m = /^basic\s+([A-Za-z0-9+/=]+)\s*$/i.exec(header);
  if (!m) return { credential: "invalid" };
  const decoded = Buffer.from(m[1]!, "base64").toString("utf8");
  const colon = decoded.indexOf(":");
  if (colon < 1) return { credential: "invalid" };
  const id = decoded.slice(0, colon);
  const presented = sha(decoded.slice(colon + 1));
  const expected = agents.get(id);
  const match = timingSafeEqual(presented, expected ?? STAND_IN) && expected !== undefined;
  return match ? { credential: "verified", agent: id } : { credential: "invalid", declared: id.slice(0, 200) };
}

/**
 * Wraps a resolver so that a host name never leads to an internal address: the policy decided on the name, and a name
 * the agent chose (or a DNS answer someone else chose) must not turn a permit for a public host into a request to the
 * metadata service, loopback, or the private network. Addresses that are internal are dropped before any connection is
 * made; a name with none left fails. An IP literal is never looked up: it is the Cedar action itself, so a rule permits
 * it by name. The check sits in the resolver the socket connects with, so there is no second lookup to rebind.
 */
export function publicOnlyLookup(resolve: LookupFunction = dnsLookup as unknown as LookupFunction): LookupFunction {
  return ((hostname: string, options: { all?: boolean }, callback: (err: NodeJS.ErrnoException | null, address?: string | { address: string; family: number }[], family?: number) => void) => {
    resolve(hostname, { ...options, all: true }, ((err: NodeJS.ErrnoException | null, found: { address: string; family: number }[]) => {
      if (err) return callback(err);
      const list = Array.isArray(found) ? found : [];
      const usable = list.filter((a) => !internalAddress(a.address));
      if (!usable.length) return callback(Object.assign(new Error(`${hostname} resolves only to internal addresses (${list.map((a) => a.address).join(", ") || "none"}); the witness does not dial them for a host name`), { code: "EGRESS_INTERNAL" }));
      if (options.all) callback(null, usable);
      else callback(null, usable[0]!.address, usable[0]!.family);
    }) as never);
  }) as LookupFunction;
}

/** Headers that belong to the connection to the witness, never relayed to the destination. Proxy-Authorization is the agent's secret. */
const HOP_BY_HOP = new Set(["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade"]);

export interface EgressOptions {
  /** the log to append to, in place of the one the config names; for embedding and tests */
  log?: LogSink;
  exporter?: ReceiptExporter;
  /** appends the outbox at start and every 30 seconds; only a serving witness sets it */
  autoFlush?: boolean;
  /** the resolver for host names, before the internal-address filter; for tests */
  lookup?: LookupFunction;
}

export interface EgressHost {
  keyid: string;
  policyDigest(): string;
  /** a plain HTTP request in absolute form */
  handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void>;
  /** a CONNECT request: the tunnel, if the policy allows it */
  handleConnect(req: IncomingMessage, client: Duplex, head: Buffer): Promise<void>;
  flushOutbox(): Promise<FlushResult>;
  pendingReceipts(): number;
  /** closes every relayed connection (each is receipted as `witness-stopped`) and waits for their receipts */
  close(): Promise<void>;
}

interface Decided {
  receiptId: string;
  timestamp: string;
  destination: Destination;
  /** the agent the credential proved, else undefined */
  agent: string | undefined;
  policy: PolicyDecision;
  forward: boolean;
  /** why the connection is refused, when it is */
  refusal?: { status: 403 | 407; reason: string };
  head: Omit<ReceiptPredicate, "execution" | "session" | "model">;
  /** the open, committed to the log before any byte of the agent's moved */
  authorization?: AuthorizationBundle;
}

export async function createEgressHost(cfg: EgressConfig, options: EgressOptions = {}): Promise<EgressHost> {
  const key = loadPrivateKey(cfg.identity.keyFile);
  const agents = new Map<string, Buffer>();
  for (const a of cfg.agents) {
    const secret = process.env[a.secretEnv];
    if (!secret) throw new Error(`agent ${a.id}: environment variable ${a.secretEnv} is not set`);
    agents.set(a.id, sha(secret));
  }
  const sink = options.log ?? openLog(cfg, key);
  const issuer = createIssuer(key, cfg.receiptsDir, sink, { exporter: options.exporter ?? openExporter(cfg) });

  // The policy, re-read when the file changes, as the gateway and the door do; a file that does not parse is refused and
  // the policy in force stays. The bytes and the metadata come from one open file.
  const readPolicy = () => {
    const fd = openSync(cfg.policyFile, "r");
    try {
      const st = fstatSync(fd);
      return { text: readFileSync(fd, "utf8"), key: `${st.ino}:${st.mtimeMs}:${st.ctimeMs}:${st.size}` };
    } finally {
      closeSync(fd);
    }
  };
  const first = readPolicy();
  const errors = policyParseErrors(first.text);
  if (errors.length) throw new Error(`policy ${cfg.policyFile} does not parse: ${errors.join("; ")}`);
  if (!hasPermitRule(first.text)) console.error(`agent-custody egress: ${cfg.policyFile} has no permit rule, so every connection is refused`);
  let policyNow = { text: first.text, digest: policyDigest(first.text), key: first.key };
  const currentPolicy = () => {
    try {
      const next = readPolicy();
      if (next.key !== policyNow.key) {
        const problems = policyParseErrors(next.text);
        if (problems.length) console.error(`agent-custody egress: POLICY NOT RELOADED: ${cfg.policyFile} ${problems.join("; ")}; policy ${policyNow.digest} stays in force`);
        else policyNow = { text: next.text, digest: policyDigest(next.text), key: next.key };
      }
    } catch (e) {
      console.error(`agent-custody egress: cannot read ${cfg.policyFile}: ${e instanceof Error ? e.message : String(e)}; policy ${policyNow.digest} stays in force`);
    }
    return policyNow;
  };

  let inFlight = 0;
  let closing = false;
  const open = new Set<() => void>();
  const pending = new Set<Promise<unknown>>();

  function decide(req: IncomingMessage, scheme: Destination["scheme"], host: string, port: number): Decided {
    const receiptId = randomUUID();
    const timestamp = new Date().toISOString();
    const header = req.headers["proxy-authorization"];
    const checked = checkProxyCredential(typeof header === "string" ? header : undefined, agents);
    const destination: Destination = { host, port, scheme, credential: checked.credential, ...(checked.declared ? { declared: checked.declared } : {}), remote: req.socket.remoteAddress ?? "unknown" };
    const name = destinationName(host, port);
    const method = (req.method ?? "GET").toUpperCase();
    const args = { method, host, port };
    const { text, digest } = currentPolicy();
    // The Cedar principal is an agent whose credential the witness checked; an id in a credential that failed stays in
    // the destination fact as a claim, so a permit on `principal == Agent::"x"` cannot be met by naming x.
    let policy: PolicyDecision;
    try {
      policy = evaluate(text, { agentId: checked.agent ?? "unknown", tool: name, context: { args, facts: { [DESTINATION_FACT]: destination } } });
    } catch (e) {
      policy = { decision: "deny", reasons: [], errors: [String(e instanceof Error ? e.message : e)], policyDigest: digest };
    }
    if (cfg.mode === "observe") policy = { ...policy, enforced: false };
    // An agent the witness could not identify is refused in every mode: a receipt that names nobody proves nothing.
    const refusal = checked.agent === undefined
      ? { status: 407 as const, reason: checked.credential === "absent" ? "no proxy credential was presented" : "the proxy credential did not verify" }
      : policy.decision === "allow" || policy.enforced === false
        ? undefined
        : { status: 403 as const, reason: [...policy.reasons, ...policy.errors].join("; ") || "no permit policy matched" };
    const facts: Record<string, FactRecord> = { [DESTINATION_FACT]: { tool: "egress.destination", args: {}, value: destination, resultDigest: digestOf(destination), provenance: "observed" } };
    const head: Omit<ReceiptPredicate, "execution" | "session" | "model"> = {
      receiptId,
      timestamp,
      issuer: { kind: "egress", keyid: issuer.keyid, version: EGRESS_VERSION, framework: scheme },
      principal: { id: null, provenance: "claimed" },
      agent: { id: checked.agent ?? "unknown", provenance: checked.agent ? "observed" : "claimed" },
      tool: { name, provenance: "observed" },
      request: { args, argsDigest: digestOf(args), provenance: "claimed" },
      facts,
      policy: { ...policy, provenance: "observed" },
    };
    return { receiptId, timestamp, destination, agent: checked.agent, policy, forward: !refusal, ...(refusal ? { refusal } : {}), head };
  }

  /** Signs, logs, and writes the receipt. A log that does not answer leaves it in the outbox; any other failure is printed and returns false. */
  async function record(d: Decided, execution: ReceiptPredicate["execution"]): Promise<{ written: boolean; logPending: boolean }> {
    try {
      await issuer.issue({ ...d.head, session: { id: null, toolUseId: null, provenance: "claimed" }, model: { id: null, provenance: "claimed" }, ...(d.authorization ? { authorization: d.authorization } : {}), execution }, undefined, undefined, { deferLog: true });
      return { written: true, logPending: false };
    } catch (e) {
      if (e instanceof ReceiptPending) {
        console.error(`agent-custody egress: ${e.message}`);
        return { written: true, logPending: true };
      }
      console.error(`agent-custody egress: receipt ${d.receiptId} was not written: ${e instanceof Error ? e.message : String(e)}`);
      return { written: false, logPending: false };
    }
  }

  /**
   * Commits the connection to the log before any byte of the agent's moves, as the door commits a request that can change
   * something: the bypass is on record even if the witness dies while the tunnel is open, or the closing receipt is never
   * written. If the log will not take it, nothing is relayed; in observe mode it is relayed and the gap is printed.
   */
  async function commitOpen(d: Decided): Promise<string | undefined> {
    try {
      d.authorization = await issuer.authorize(d.head);
      return undefined;
    } catch (e) {
      const why = e instanceof Error ? e.message : String(e);
      if (cfg.mode === "observe") {
        console.error(`agent-custody egress (observe mode): the log did not commit connection ${d.receiptId} to ${d.head.tool.name}; it was relayed without it: ${why}`);
        return undefined;
      }
      return `the log did not commit the connection, so it was not relayed: ${why}`;
    }
  }

  const lookup = publicOnlyLookup(options.lookup);
  const STOPPED = "the witness stopped before the connection opened";

  const tracked = <T>(p: Promise<T>): Promise<T> => {
    pending.add(p);
    void p.finally(() => pending.delete(p)).catch(() => undefined);
    return p;
  };

  /** Writes a whole HTTP/1.1 answer on a raw socket and closes it: a CONNECT is answered on the socket, not through a response object. */
  const answerSocket = (socket: Duplex, status: number, phrase: string, headers: Record<string, string>, body: unknown) => {
    const text = JSON.stringify(body);
    const lines = [`HTTP/1.1 ${status} ${phrase}`, "content-type: application/json", `content-length: ${Buffer.byteLength(text)}`, "connection: close", ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`)];
    socket.end(`${lines.join("\r\n")}\r\n\r\n${text}`);
  };

  const refusalHeaders = (d: Decided, logPending: boolean): Record<string, string> => ({
    [RECEIPT_HEADER]: d.receiptId,
    ...(d.refusal?.status === 407 ? { "proxy-authenticate": `Basic realm="${PROXY_REALM}"` } : {}),
    ...(logPending ? { "x-agent-custody-log-pending": "true" } : {}),
  });

  async function handleConnect(req: IncomingMessage, client: Duplex, head: Buffer): Promise<void> {
    if (closing || inFlight >= cfg.maxInFlight) {
      answerSocket(client, 503, "Service Unavailable", { "retry-after": "1" }, { error: `the witness is handling ${cfg.maxInFlight} connections; this one was not decided, relayed, or receipted. Retry` });
      return;
    }
    const target = parseAuthority(req.url ?? "");
    if (!target) {
      answerSocket(client, 400, "Bad Request", {}, { error: "a CONNECT target is host:port; nothing was relayed or receipted" });
      return;
    }
    inFlight += 1;
    try {
      await tracked(tunnel(req, client, head, target));
    } finally {
      inFlight -= 1;
    }
  }

  async function tunnel(req: IncomingMessage, client: Duplex, head: Buffer, target: { host: string; port: number }): Promise<void> {
    client.on("error", () => undefined);
    const d = decide(req, "connect", target.host, target.port);
    if (!d.forward) {
      const r = await record(d, { status: "denied", reason: d.refusal!.reason, provenance: "observed" });
      if (!r.written) return answerSocket(client, 500, "Internal Server Error", {}, { error: "the witness could not record this connection; nothing was relayed", receipt: d.receiptId });
      return answerSocket(client, d.refusal!.status, d.refusal!.status === 407 ? "Proxy Authentication Required" : "Forbidden", refusalHeaders(d, r.logPending), { error: d.refusal!.status === 407 ? "the witness needs a proxy credential it can check" : "refused by the egress policy", reason: d.refusal!.reason, receipt: d.receiptId });
    }
    // Registered before anything is awaited: close() must reach a connection that is still committing or connecting,
    // or it would open after shutdown began and outlive it.
    let stopped = false;
    let upstream: Socket | undefined;
    let wake: (() => void) | undefined;
    const stopEarly = () => { stopped = true; upstream?.destroy(); wake?.(); };
    open.add(stopEarly);
    let connected: { ok: true } | { ok: false; error: string };
    try {
      const withheld = await commitOpen(d);
      if (withheld) {
        const r = await record(d, { status: "withheld", reason: withheld, provenance: "observed" });
        return answerSocket(client, 503, "Service Unavailable", { [RECEIPT_HEADER]: d.receiptId, ...(r.logPending ? { "x-agent-custody-log-pending": "true" } : {}) }, { error: "not relayed", reason: withheld, receipt: d.receiptId });
      }
      const socket = connect({ host: target.host, port: target.port, lookup });
      upstream = socket;
      socket.on("error", () => undefined);
      if (stopped) socket.destroy();
      connected = stopped ? { ok: false, error: STOPPED } : await new Promise<{ ok: true } | { ok: false; error: string }>((resolve) => {
        const timer = setTimeout(() => { socket.destroy(); resolve({ ok: false, error: `no connection within ${cfg.connectTimeoutMs} ms` }); }, cfg.connectTimeoutMs);
        const done = (v: { ok: true } | { ok: false; error: string }) => { clearTimeout(timer); resolve(v); };
        wake = () => done({ ok: false, error: STOPPED });
        socket.once("connect", () => done({ ok: true }));
        socket.once("error", (e) => done({ ok: false, error: e.message }));
        client.once("close", () => { socket.destroy(); done({ ok: false, error: "the agent closed the connection before the destination answered" }); });
      });
    } finally {
      open.delete(stopEarly);
    }
    if (!connected.ok || stopped) {
      // the tunnel never opened, so no byte of the agent's reached the destination
      upstream?.destroy();
      const error = stopped ? STOPPED : (connected as { error: string }).error;
      const r = await record(d, { status: "error", error: stopped ? STOPPED : `the destination could not be reached: ${error}`, provenance: "observed" });
      const mark = { [RECEIPT_HEADER]: d.receiptId, ...(r.logPending ? { "x-agent-custody-log-pending": "true" } : {}) };
      return stopped
        ? answerSocket(client, 503, "Service Unavailable", mark, { error: STOPPED, receipt: d.receiptId })
        : answerSocket(client, 502, "Bad Gateway", mark, { error: "the destination could not be reached", detail: error, receipt: d.receiptId });
    }
    const tunnelTo = upstream!;
    const openedAt = new Date().toISOString();
    const peer = tunnelTo.remoteAddress ?? "unknown";
    let bytesUp = head.length;
    let bytesDown = 0;
    let end: EgressEnd = "closed";
    const ended = new Promise<void>((resolve) => {
      let done = false;
      const finish = (why?: EgressEnd) => {
        if (why && end === "closed") end = why;
        if (done) return;
        done = true;
        open.delete(stop);
        client.destroy();
        tunnelTo.destroy();
        resolve();
      };
      const stop = () => finish("witness-stopped");
      open.add(stop);
      for (const s of [client, tunnelTo as Socket | Duplex]) {
        s.on("error", () => finish("reset"));
        s.on("close", () => finish());
      }
      tunnelTo.setTimeout(cfg.idleTimeoutMs, () => finish("idle-timeout"));
      // a socket's timeout counts reads and writes, so either direction keeps the tunnel open
      client.on("data", (c: Buffer) => { bytesUp += c.length; });
      tunnelTo.on("data", (c: Buffer) => { bytesDown += c.length; });
    });
    client.write(`HTTP/1.1 200 Connection Established\r\n${RECEIPT_HEADER}: ${d.receiptId}\r\n\r\n`);
    if (head.length) tunnelTo.write(head);
    client.pipe(tunnelTo);
    tunnelTo.pipe(client);
    await ended;
    const result: EgressResult = { peer, openedAt, closedAt: new Date().toISOString(), bytesUp, bytesDown, end };
    await record(d, { status: "executed", result, resultDigest: digestOf(result), provenance: "observed" });
  }

  async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const json = (status: number, headers: Record<string, string>, body: unknown) => {
      res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", ...headers });
      res.end(JSON.stringify(body));
    };
    if (closing || inFlight >= cfg.maxInFlight) {
      req.resume();
      return json(503, { "retry-after": "1" }, { error: `the witness is handling ${cfg.maxInFlight} connections; this one was not decided, relayed, or receipted. Retry` });
    }
    let url: URL | undefined;
    try { url = new URL(req.url ?? ""); } catch { /* not absolute form */ }
    const host = url ? normalizeHost(url.hostname) : null;
    const port = url ? (url.port ? parsePort(url.port) : 80) : null;
    if (!url || url.protocol !== "http:" || !host || !port || url.username || url.password) {
      req.resume();
      return json(400, {}, { error: "a proxied request names an absolute http:// URL with no credentials in it; HTTPS goes through CONNECT. Nothing was relayed or receipted" });
    }
    inFlight += 1;
    try {
      await tracked(relayPlain(req, res, url, host, port, json));
    } finally {
      inFlight -= 1;
    }
  }

  async function relayPlain(req: IncomingMessage, res: ServerResponse, url: URL, host: string, port: number, json: (status: number, headers: Record<string, string>, body: unknown) => void): Promise<void> {
    const d = decide(req, "http", host, port);
    if (!d.forward) {
      req.resume();
      const r = await record(d, { status: "denied", reason: d.refusal!.reason, provenance: "observed" });
      if (!r.written) return json(500, {}, { error: "the witness could not record this connection; nothing was relayed", receipt: d.receiptId });
      return json(d.refusal!.status, refusalHeaders(d, r.logPending), { error: d.refusal!.status === 407 ? "the witness needs a proxy credential it can check" : "refused by the egress policy", reason: d.refusal!.reason, receipt: d.receiptId });
    }
    let stoppedEarly = false;
    const stopEarly = () => { stoppedEarly = true; };
    open.add(stopEarly);
    let withheld: string | undefined;
    try {
      withheld = await commitOpen(d);
    } finally {
      open.delete(stopEarly);
    }
    if (withheld || stoppedEarly) {
      req.resume();
      const r = await record(d, withheld ? { status: "withheld", reason: withheld, provenance: "observed" } : { status: "error", error: STOPPED, provenance: "observed" });
      return json(503, { [RECEIPT_HEADER]: d.receiptId, ...(r.logPending ? { "x-agent-custody-log-pending": "true" } : {}) }, { error: withheld ? "not relayed" : STOPPED, ...(withheld ? { reason: withheld } : {}), receipt: d.receiptId });
    }
    const headers: Record<string, string | string[]> = {};
    for (const [name, value] of Object.entries(req.headers)) if (value !== undefined && !HOP_BY_HOP.has(name) && name !== "host" && name !== "expect") headers[name] = value;
    // the destination the policy decided on is the one the request names, whatever Host the agent wrote
    headers.host = port === 80 ? (isIP(host) === 6 ? `[${host}]` : host) : destinationName(host, port);
    const openedAt = new Date().toISOString();
    let bytesUp = 0;
    let bytesDown = 0;
    let end: EgressEnd = "closed";
    let peer = "unknown";
    let status: number | undefined;
    let sent = false;
    const outcome = await new Promise<{ ok: true } | { ok: false; error: string }>((resolve) => {
      let settled = false;
      const settle = (v: { ok: true } | { ok: false; error: string }) => { if (!settled) { settled = true; open.delete(stop); resolve(v); } };
      const up = httpRequest({ host, port, method: req.method, path: `${url.pathname}${url.search}`, headers, agent: false, setHost: false, lookup });
      const stop = () => { end = "witness-stopped"; up.destroy(); res.destroy(); settle({ ok: true }); };
      open.add(stop);
      const connectTimer = setTimeout(() => up.destroy(new Error(`no connection within ${cfg.connectTimeoutMs} ms`)), cfg.connectTimeoutMs);
      up.on("socket", (s: Socket) => s.once("connect", () => { clearTimeout(connectTimer); sent = true; peer = s.remoteAddress ?? "unknown"; }));
      up.setTimeout(cfg.idleTimeoutMs, () => { end = "idle-timeout"; up.destroy(new Error(`no bytes for ${cfg.idleTimeoutMs} ms`)); });
      up.on("error", (e) => {
        clearTimeout(connectTimer);
        if (status !== undefined) { if (end === "closed") end = "reset"; res.destroy(); settle({ ok: true }); }
        else settle({ ok: false, error: e.message });
      });
      up.on("response", (answer) => {
        status = answer.statusCode ?? 502;
        const back: Record<string, string | string[]> = {};
        for (const [name, value] of Object.entries(answer.headers)) if (value !== undefined && !HOP_BY_HOP.has(name)) back[name] = value;
        res.writeHead(status, { ...back, [RECEIPT_HEADER]: d.receiptId });
        answer.on("data", (c: Buffer) => { bytesDown += c.length; });
        answer.on("error", () => { if (end === "closed") end = "reset"; });
        answer.pipe(res);
        answer.on("end", () => settle({ ok: true }));
        answer.on("close", () => settle({ ok: true }));
      });
      res.on("close", () => {
        if (res.writableFinished) return;
        if (end === "closed") end = "reset";
        up.destroy();
        settle(sent ? { ok: true } : { ok: false, error: "the agent closed the connection before the destination answered" });
      });
      req.on("data", (c: Buffer) => { bytesUp += c.length; });
      req.on("error", () => { if (end === "closed") end = "reset"; up.destroy(); });
      req.pipe(up);
    });
    if (!outcome.ok) {
      // a refused or unresolved connection never reached the destination; any later failure may have
      const error = sent ? `the destination may have received the request: ${outcome.error}` : `the destination could not be reached: ${outcome.error}`;
      const r = await record(d, { status: "error", error, provenance: "observed" });
      if (!res.headersSent) json(sent ? 504 : 502, { [RECEIPT_HEADER]: d.receiptId, ...(r.logPending ? { "x-agent-custody-log-pending": "true" } : {}) }, { error, receipt: d.receiptId });
      return;
    }
    const result: EgressResult = { peer, openedAt, closedAt: new Date().toISOString(), bytesUp, bytesDown, end, ...(status !== undefined ? { status } : {}) };
    await record(d, { status: "executed", result, resultDigest: digestOf(result), provenance: "observed" });
  }

  let timer: ReturnType<typeof setInterval> | undefined;
  if (options.autoFlush) {
    const flush = () => void issuer.flushOutbox().catch((e: unknown) => console.error(`agent-custody egress: outbox flush failed: ${e instanceof Error ? e.message : String(e)}`));
    flush();
    timer = setInterval(flush, 30_000);
    timer.unref?.();
  }

  return {
    keyid: issuer.keyid,
    policyDigest: () => currentPolicy().digest,
    handleRequest,
    handleConnect,
    flushOutbox: () => issuer.flushOutbox(),
    pendingReceipts: () => issuer.pending(),
    async close() {
      closing = true;
      if (timer) clearInterval(timer);
      for (const stop of [...open]) stop();
      await Promise.allSettled([...pending]);
    },
  };
}

export interface EgressServerOptions {
  port: number;
  host?: string;
  log?: (message: string) => void;
}

export interface RunningEgress {
  url: string;
  close(): Promise<void>;
}

/**
 * Serves an egress host as an HTTP forward proxy. A request in origin form is for the witness itself:
 * `GET /.well-known/agent-custody-egress` answers the key id and the policy digest, anything else 404. Bind it where
 * only the locked-down agents can reach it.
 */
export async function serveEgress(host: EgressHost, opts: EgressServerOptions): Promise<RunningEgress> {
  const bind = opts.host ?? "127.0.0.1";
  const log = opts.log ?? ((m) => console.error(m));
  const fail = (e: unknown) => log(`agent-custody egress: ${e instanceof Error ? e.message : String(e)}`);
  const server: HttpServer = createServer((req, res) => {
    if ((req.url ?? "").startsWith("/")) {
      req.resume();
      if (req.method === "GET" && req.url === "/.well-known/agent-custody-egress") {
        res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify({ keyid: host.keyid, policyDigest: host.policyDigest(), version: EGRESS_VERSION, pendingReceipts: host.pendingReceipts() }));
      } else {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "this is a forward proxy: name an absolute http:// URL, or CONNECT host:port" }));
      }
      return;
    }
    host.handleRequest(req, res).catch((e: unknown) => {
      fail(e);
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "the witness failed before it could answer; whether the destination received the request is unknown", receipt: res.getHeader(RECEIPT_HEADER) ?? null }));
      } else res.end();
    });
  });
  server.on("connect", (req: IncomingMessage, socket: Duplex, head: Buffer) => {
    host.handleConnect(req, socket, head).catch((e: unknown) => { fail(e); socket.destroy(); });
  });
  await new Promise<void>((resolve) => server.listen(opts.port, bind, resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://${bind.includes(":") ? `[${bind}]` : bind}:${port}`,
    async close() {
      server.closeAllConnections?.();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
