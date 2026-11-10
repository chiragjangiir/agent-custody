// The signer: the one process that holds the log's key. The log server asks it to sign tree heads over a private
// HTTP call with a shared secret, so the key never sits in the process that faces the internet, and the same key
// document it serves is what the log publishes at /.well-known/agent-custody-log.json for verifiers to pin.
// A local signer wraps a key in-process for the reference server and for tests; both look the same to the handler.
import { timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { dsseSign, publicKeyFromPem, type Envelope, type KeyPair, type PublicKeyRef } from "./crypto.ts";

/** What a log publishes about its keys. Verifiers pin by keyid; retired keys stay listed so old heads keep verifying. */
export interface KeyDocument {
  /** the id of the log served at the root paths, when it has one */
  log?: string;
  keys: { keyid: string; alg: "ed25519"; publicKeyPem: string; validFrom: string; validTo?: string }[];
}

export interface Signer {
  readonly keyid: string;
  sign(payloadType: string, payload: unknown): Promise<Envelope>;
  keys(): Promise<KeyDocument>;
}

export interface RetiredKey {
  key: PublicKeyRef;
  pem: string;
  validFrom?: string;
  validTo?: string;
}

const pemOf = (k: PublicKeyRef): string => k.publicKey.export({ type: "spki", format: "pem" }) as string;

/** A key held in this process. `retired` keys are listed in the document, never used to sign. */
export function localSigner(kp: KeyPair, opts: { retired?: RetiredKey[]; validFrom?: string } = {}): Signer {
  const validFrom = opts.validFrom ?? new Date().toISOString();
  const doc: KeyDocument = {
    keys: [
      { keyid: kp.keyid, alg: "ed25519", publicKeyPem: pemOf(kp), validFrom },
      ...(opts.retired ?? []).map((r) => ({ keyid: r.key.keyid, alg: "ed25519" as const, publicKeyPem: r.pem, validFrom: r.validFrom ?? "1970-01-01T00:00:00.000Z", ...(r.validTo ? { validTo: r.validTo } : {}) })),
    ],
  };
  return {
    keyid: kp.keyid,
    async sign(payloadType, payload) {
      return dsseSign(payloadType, payload, kp);
    },
    async keys() {
      return structuredClone(doc);
    },
  };
}

export interface RemoteSignerOptions {
  /** the shared secret the signer requires */
  token?: string;
  fetch?: typeof fetch;
}

/** The signer over HTTP. Fetches the key document once to learn the keyid, then signs through POST /sign. */
export async function connectSigner(url: string, opts: RemoteSignerOptions = {}): Promise<Signer> {
  const f = opts.fetch ?? fetch;
  const base = url.endsWith("/") ? url : `${url}/`;
  const shown = shownUrl(url);
  const headers = { "content-type": "application/json", ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}) };
  const res = await f(new URL("keys", base), { headers, signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new Error(`signer ${shown} refused the key request: ${res.status}`);
  const doc = (await res.json()) as KeyDocument;
  const current = doc.keys[0];
  if (!current) throw new Error(`signer ${shown} lists no key`);
  return {
    keyid: current.keyid,
    async sign(payloadType, payload) {
      const r = await f(new URL("sign", base), { method: "POST", headers, body: JSON.stringify({ payloadType, payload }), signal: AbortSignal.timeout(5000) });
      if (!r.ok) throw new Error(`signer ${shown} refused to sign: ${r.status} ${(await r.text()).slice(0, 200)}`);
      const env = (await r.json()) as Envelope;
      if (typeof env.payload !== "string" || !Array.isArray(env.signatures)) throw new Error(`signer ${shown} returned a malformed envelope`);
      return env;
    },
    async keys() {
      const k = await f(new URL("keys", base), { headers, signal: AbortSignal.timeout(10_000) });
      if (!k.ok) throw new Error(`signer ${shown} refused the key request: ${k.status}`);
      return (await k.json()) as KeyDocument;
    },
  };
}

export interface SignerServerOptions {
  /** the shared secret; without one, anyone who can reach the port may sign, so bind to loopback or a private network */
  token?: string;
  retired?: RetiredKey[];
  validFrom?: string;
}

/**
 * The signer as a node:http handler.
 *   POST /sign  {payloadType, payload}  -> DSSE envelope     (token required when one is configured)
 *   GET  /keys                          -> KeyDocument
 *   GET  /health                        -> {keyid}
 */
export function signerHandler(kp: KeyPair, opts: SignerServerOptions = {}): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  const signer = localSigner(kp, opts);
  const authorized = (req: IncomingMessage): boolean => {
    if (!opts.token) return true;
    const h = req.headers.authorization ?? "";
    const given = Buffer.from(h.startsWith("Bearer ") ? h.slice(7) : "");
    const want = Buffer.from(opts.token);
    return want.length === given.length && timingSafeEqual(want, given);
  };
  return async (req, res) => {
    const json = (status: number, body: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };
    const url = new URL(req.url ?? "/", "http://localhost");
    if (req.method === "GET" && url.pathname === "/health") return json(200, { keyid: kp.keyid });
    if (req.method === "GET" && url.pathname === "/keys") return json(200, await signer.keys());
    if (req.method === "POST" && url.pathname === "/sign") {
      if (!authorized(req)) return json(401, { error: "unauthorized" });
      let body = "";
      for await (const chunk of req) {
        body += chunk;
        if (body.length > 65_536) return json(413, { error: "payload too large" });
      }
      let parsed: { payloadType?: unknown; payload?: unknown };
      try {
        parsed = JSON.parse(body) as { payloadType?: unknown; payload?: unknown };
      } catch {
        return json(400, { error: "body must be JSON {payloadType, payload}" });
      }
      if (typeof parsed.payloadType !== "string" || parsed.payload === undefined) return json(400, { error: "body must be JSON {payloadType, payload}" });
      return json(200, await signer.sign(parsed.payloadType, parsed.payload));
    }
    return json(404, { error: "not found" });
  };
}

export interface RunningSigner {
  url: string;
  keyid: string;
  close(): Promise<void>;
}

export function serveSigner(kp: KeyPair, opts: SignerServerOptions & { port: number; host?: string }): Promise<RunningSigner> {
  const host = opts.host ?? "127.0.0.1";
  const handler = signerHandler(kp, opts);
  const server = createServer((req, res) => {
    void handler(req, res);
  });
  return new Promise((resolve) => {
    server.listen(opts.port, host, () => {
      const { port } = server.address() as AddressInfo;
      resolve({ url: `http://${host}:${port}/`, keyid: kp.keyid, close: () => new Promise((r) => server.close(() => r())) });
    });
  });
}

/** The URL for an error message: no user, password, query, or fragment. */
export function shownUrl(url: string): string {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}${u.pathname}`;
  } catch {
    return "(a URL that does not parse)";
  }
}

/** For verifiers: the keys a log publishes, fetched from its origin and returned as key references pinned by keyid. */
export async function fetchLogKeys(logUrl: string, f: typeof fetch = fetch): Promise<{ doc: KeyDocument; keys: PublicKeyRef[] }> {
  const res = await f(new URL("/.well-known/agent-custody-log.json", logUrl), { signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new Error(`log ${shownUrl(logUrl)} serves no key document: ${res.status}`);
  const doc = (await res.json()) as KeyDocument;
  if (!Array.isArray(doc.keys) || doc.keys.length === 0) throw new Error(`log ${shownUrl(logUrl)} lists no keys`);
  const keys = doc.keys.map((k) => {
    const ref = publicKeyFromPem(k.publicKeyPem);
    if (ref.keyid !== k.keyid) throw new Error(`log ${shownUrl(logUrl)} lists key ${k.keyid.slice(0, 12)} whose pem has keyid ${ref.keyid.slice(0, 12)}`);
    return ref;
  });
  return { doc, keys };
}
