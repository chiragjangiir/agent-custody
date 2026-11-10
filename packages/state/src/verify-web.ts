// The receipt verifier for the browser: the same checks as @agent-custody/receipts' verifyBundle, over WebCrypto.
// Asynchronous because WebCrypto is. No dependencies. Conformance is proven by running it against the published
// vectors in the test next to this file, which is how any second implementation should prove itself.
export interface Envelope { payloadType: string; payload: string; signatures: { keyid: string; sig: string }[] }
export interface Bundle { envelope: Envelope; treeHead: Envelope; inclusion: { leafIndex: number; treeSize: number; hashes: string[] } }
export interface Check { name: string; ok: boolean; detail?: string }
export interface PublicKey { key: CryptoKey; keyid: string; pem: string }
export interface Result { ok: boolean; checks: Check[]; statement: any | null; issuerNote: string | null; treeHeadSigner: "log key" | "issuer key" | null }

const RECEIPT_TYPE = "application/vnd.in-toto+json";
const PREDICATE_TYPE = "https://agent-custody.dev/receipt/v0.2";
const TREEHEAD_TYPE = "application/vnd.agent-custody.treehead+json";

// A copy of packages/receipts/src/addresses.ts: this file has no imports. Keep the two lists identical.
const V4: [string, number][] = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
  ["192.0.0.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["224.0.0.0", 4], ["240.0.0.0", 4],
];
const V6: [string, number][] = [["::", 128], ["::1", 128], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8], ["64:ff9b:1::", 48]];

function v4(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    // no leading zeros: `010` is octal to getaddrinfo and an error to Python's ipaddress, so it is not an address here either
    if (!/^(0|[1-9]\d{0,2})$/.test(p) || Number(p) > 255) return null;
    n = n * 256 + Number(p);
  }
  return n;
}

function v6(ip: string): number[] | null {
  let s = ip.toLowerCase();
  // an embedded IPv4 tail (::ffff:10.0.0.1) becomes its two hex groups
  if (s.includes(".")) {
    const at = s.lastIndexOf(":");
    const n = at < 0 ? null : v4(s.slice(at + 1));
    if (n === null) return null;
    s = `${s.slice(0, at + 1)}${Math.floor(n / 65536).toString(16)}:${(n % 65536).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const read = (h: string) => (h === "" ? [] : h.split(":").map((g) => (/^[0-9a-f]{1,4}$/.test(g) ? parseInt(g, 16) : NaN)));
  const head = read(halves[0]!);
  const rest = halves.length === 2 ? read(halves[1]!) : [];
  const fill = 8 - head.length - rest.length;
  if (halves.length === 1 ? fill !== 0 : fill < 1) return null;
  const groups = [...head, ...Array<number>(halves.length === 2 ? fill : 0).fill(0), ...rest];
  return groups.every((g) => Number.isInteger(g)) ? groups : null;
}

function inV6(g: number[], base: number[], bits: number): boolean {
  for (let i = 0; i < 8 && bits > 0; i++, bits -= 16) {
    const mask = bits >= 16 ? 0xffff : (0xffff << (16 - bits)) & 0xffff;
    if ((g[i]! & mask) !== (base[i]! & mask)) return false;
  }
  return true;
}

/** True when `ip` is not a public address, or is not an address at all: a caller that cannot read it must not dial it. */
function internalAddress(ip: string): boolean {
  const n = v4(ip);
  if (n !== null) return V4.some(([base, bits]) => Math.floor(n / 2 ** (32 - bits)) === Math.floor(v4(base)! / 2 ** (32 - bits)));
  const g = v6(ip.replace(/^\[|\]$/g, "").replace(/%.*$/, ""));
  if (!g) return true;
  const embedded = embeddedV4(g);
  if (embedded) return internalAddress(embedded);
  return V6.some(([base, bits]) => inV6(g, v6(base)!, bits));
}

/** The IPv4 address inside an IPv4-mapped (::ffff:0:0/96) or NAT64 (64:ff9b::/96) address, else null: a DNS64 answer can wrap an internal IPv4 address. */
function embeddedV4(g: number[]): string | null {
  const mapped = g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff;
  const nat64 = g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0);
  return mapped || nat64 ? `${g[6]! >> 8}.${g[6]! & 255}.${g[7]! >> 8}.${g[7]! & 255}` : null;
}

/** The address in a canonical form (IPv4 dotted, or eight IPv6 groups; a mapped IPv4 address as IPv4), or null when it is not one. */
function canonicalAddress(ip: string): string | null {
  if (v4(ip) !== null) return ip.split(".").map(Number).join(".");
  const g = v6(ip.replace(/^\[|\]$/g, "").replace(/%.*$/, ""));
  if (!g) return null;
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) return embeddedV4(g);
  return g.map((x) => x.toString(16)).join(":");
}

/** True when `a` and `b` are the same address, written however (::1 and 0:0::1; 10.0.0.1 and ::ffff:10.0.0.1). */
function sameAddress(a: string, b: string): boolean {
  const x = canonicalAddress(a);
  return x !== null && x === canonicalAddress(b);
}

/** True when `host` is an IP address rather than a name. */
function isAddressLiteral(host: string): boolean {
  return canonicalAddress(host) !== null;
}

const DELEGATION_TYPE = "application/vnd.agent-custody.delegation+json";
const UPSTREAM_TYPE = "application/vnd.agent-custody.upstream+json";
const AUTHORIZATION_TYPE = "https://agent-custody.dev/authorization/v0.1";
const APPROVAL_TYPE = "application/vnd.agent-custody.approval+json";
const subtle = () => globalThis.crypto.subtle;

type Bytes = Uint8Array<ArrayBuffer>;
const enc = new TextEncoder();
const b64 = { decode: (s: string): Bytes => Uint8Array.from(atob(s), (c) => c.charCodeAt(0)) };
const hex = (buf: ArrayBuffer | Uint8Array) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const unhex = (h: string): Bytes => Uint8Array.from(h.match(/.{2}/g) ?? [], (x) => parseInt(x, 16));
const concat = (...parts: Bytes[]): Bytes => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };
const sha256 = async (data: Bytes): Promise<Bytes> => new Uint8Array(await subtle().digest("SHA-256", data));

export function canonicalize(value: unknown): string {
  const sort = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(sort);
    // null-prototype, so an own property named __proto__ survives (mirrors src/crypto.ts)
    if (v && typeof v === "object") { const o: Record<string, unknown> = Object.create(null); for (const k of Object.keys(v as object).sort()) { const x = (v as any)[k]; if (x !== undefined) o[k] = sort(x); } return o; }
    return v;
  };
  return JSON.stringify(sort(value));
}
/** sha256 over the canonical JSON. A digest over withheld values is salted from their salts, which the browser never has, so it recomputes only digests over values in clear. */
export const digestOf = async (v: unknown) => hex(await sha256(enc.encode(canonicalize(v))));

/** Loads an Ed25519 public key from SPKI PEM. keyid is the sha256 of the DER. */
export async function publicKeyFromPem(pem: string): Promise<PublicKey> {
  const der = b64.decode(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""));
  const key = await subtle().importKey("spki", der, { name: "Ed25519" }, true, ["verify"]);
  return { key, keyid: hex(await sha256(der)), pem };
}

function pae(payloadType: string, payload: Bytes): Bytes {
  return concat(enc.encode(`DSSEv1 ${enc.encode(payloadType).length} ${payloadType} ${payload.length} `), payload);
}

export async function dsseVerify(env: Envelope, trusted: PublicKey[]): Promise<{ ok: true; payload: any; keyid: string } | { ok: false; error: string }> {
  if (!env || typeof env.payload !== "string" || !Array.isArray(env.signatures) || env.signatures.length === 0) return { ok: false, error: "malformed envelope" };
  const payload = b64.decode(env.payload);
  const data = pae(env.payloadType, payload);
  for (const s of env.signatures) {
    const key = trusted.find((t) => t.keyid === s.keyid);
    if (!key) continue;
    const good = await subtle().verify({ name: "Ed25519" }, key.key, b64.decode(s.sig), data);
    if (good) { try { return { ok: true, payload: JSON.parse(new TextDecoder().decode(payload)), keyid: s.keyid }; } catch { return { ok: false, error: "payload is not JSON" }; } }
    return { ok: false, error: `signature by ${s.keyid.slice(0, 12)} did not verify` };
  }
  return { ok: false, error: `no trusted key matches keyids [${env.signatures.map((s) => s.keyid.slice(0, 12)).join(", ")}]` };
}

// ---- delegation chains ----
const delegationShape = (d: any) => !!d && d.version === "0.1" && typeof d.principal === "string" && typeof d.agent === "string" && Array.isArray(d.scopes) && typeof d.issuedAt === "string" && typeof d.expiresAt === "string";
function decodeDelegationPayload(env: Envelope): any {
  try { const d = JSON.parse(new TextDecoder().decode(b64.decode(env.payload))); return delegationShape(d) ? d : null; } catch { return null; }
}
export function delegationHasParent(env: Envelope): boolean {
  return decodeDelegationPayload(env)?.parent !== undefined;
}
/** Mirrors verifyDelegation in the package: walks a chain to a grant signed by a trusted principal key. */
export async function verifyDelegationChain(env: Envelope, trusted: PublicKey[], depth = 1): Promise<{ ok: true; delegation: any; keyid: string; chain: any[] } | { ok: false; error: string }> {
  if (env.payloadType !== DELEGATION_TYPE) return { ok: false, error: `unexpected payloadType ${env.payloadType}` };
  if (depth > 4) return { ok: false, error: "delegation chain deeper than 4" };
  const unverified = decodeDelegationPayload(env);
  if (!unverified) return { ok: false, error: "malformed delegation" };
  if (unverified.parent === undefined) {
    const r = await dsseVerify(env, trusted);
    if (!r.ok) return r;
    if (!delegationShape(r.payload)) return { ok: false, error: "malformed delegation" };
    return { ok: true, delegation: r.payload, keyid: r.keyid, chain: [r.payload] };
  }
  const up = await verifyDelegationChain(unverified.parent, trusted, depth + 1);
  if (!up.ok) return { ok: false, error: `link ${depth}: ${up.error}` };
  const parent = up.delegation;
  if (typeof parent.agentKey !== "string") return { ok: false, error: `link ${depth}: ${parent.agent} holds no agent key and cannot delegate` };
  let parentKey: PublicKey;
  try { parentKey = await publicKeyFromPem(parent.agentKey); } catch { return { ok: false, error: `link ${depth}: the agent key named for ${parent.agent} is not a public key` }; }
  const r = await dsseVerify(env, [parentKey]);
  if (!r.ok) return { ok: false, error: `link ${depth}: not signed by ${parent.agent}'s key: ${r.error}` };
  const d = r.payload;
  if (!delegationShape(d)) return { ok: false, error: "malformed delegation" };
  if (d.principal !== parent.principal) return { ok: false, error: `link ${depth}: principal changed from ${parent.principal} to ${d.principal}` };
  const extra = (d.scopes as string[]).filter((s) => !parent.scopes.includes(s));
  if (extra.length) return { ok: false, error: `link ${depth}: ${d.agent} was given scopes ${parent.agent} does not hold: ${extra.join(", ")}` };
  const [ci, ce, pi, pe] = [d.issuedAt, d.expiresAt, parent.issuedAt, parent.expiresAt].map((x) => Date.parse(x));
  if ([ci, ce, pi, pe].some(Number.isNaN)) return { ok: false, error: `link ${depth}: a window timestamp is not a date` };
  if (ci < pi || ce > pe) return { ok: false, error: `link ${depth}: ${d.agent}'s window is not inside ${parent.agent}'s` };
  return { ok: true, delegation: d, keyid: up.keyid, chain: [...up.chain, d] };
}

// ---- RFC 6962 / 9162 ----
const leafHash = (data: string) => sha256(concat(new Uint8Array([0]), enc.encode(data)));
const nodeHash = (l: Bytes, r: Bytes) => sha256(concat(new Uint8Array([1]), l, r));
// every hash a proof check reads is 32 bytes: a proof hash and a root are each a string of 64 lowercase hex digits;
// sizes and indices are integers, since the loops halve them with Math.floor
const HASH_HEX = /^[0-9a-f]{64}$/;
const isHash = (x: unknown): x is string => typeof x === "string" && HASH_HEX.test(x);
const isSize = (n: unknown): n is number => Number.isSafeInteger(n) && (n as number) >= 0;
// exact for every safe integer: `(n & (n - 1)) === 0` reads only the low 32 bits of n
const isPowerOfTwo = (n: number) => { let k = 1; while (k < n) k *= 2; return k === n; };
const EMPTY_ROOT = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
export async function verifyInclusion(leaf: Bytes, proof: Bundle["inclusion"], rootHex: string): Promise<boolean> {
  if (!isSize(proof.leafIndex) || !isSize(proof.treeSize)) return false;
  let fn = proof.leafIndex, sn = proof.treeSize - 1;
  if (fn < 0 || sn < 0 || fn > sn) return false;
  if (leaf.length !== 32 || !isHash(rootHex) || !Array.isArray(proof.hashes) || !proof.hashes.every(isHash)) return false;
  let r = leaf;
  for (const h of proof.hashes) {
    if (sn === 0) return false;
    const p = unhex(h);
    if (fn % 2 === 1 || fn === sn) { r = await nodeHash(p, r); if (fn % 2 === 0) { while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); } } }
    else r = await nodeHash(r, p);
    fn = Math.floor(fn / 2); sn = Math.floor(sn / 2);
  }
  return sn === 0 && hex(r) === rootHex;
}
export async function verifyConsistency(oldSize: number, oldRoot: string, newSize: number, newRoot: string, proofHex: string[]): Promise<boolean> {
  if (!isSize(oldSize) || !isSize(newSize) || oldSize > newSize) return false;
  if (!isHash(oldRoot) || !isHash(newRoot) || !Array.isArray(proofHex) || !proofHex.every(isHash)) return false;
  // the empty tree has one root, sha256 of nothing; any other root at size 0, old or new, is a head no log could have signed
  if (oldSize === 0) return proofHex.length === 0 && oldRoot === EMPTY_ROOT && (newSize > 0 || newRoot === EMPTY_ROOT);
  if (oldSize === newSize) return proofHex.length === 0 && oldRoot === newRoot;
  if (proofHex.length === 0) return false;
  const proof = proofHex.map(unhex);
  if (isPowerOfTwo(oldSize)) proof.unshift(unhex(oldRoot));
  let fn = oldSize - 1, sn = newSize - 1;
  while (fn % 2 === 1) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
  let fr = proof[0]!, sr = proof[0]!;
  for (const c of proof.slice(1)) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) { fr = await nodeHash(c, fr); sr = await nodeHash(c, sr); while (fn % 2 === 0 && fn !== 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); } }
    else sr = await nodeHash(sr, c);
    fn = Math.floor(fn / 2); sn = Math.floor(sn / 2);
  }
  return sn === 0 && hex(fr) === oldRoot && hex(sr) === newRoot;
}

const ISSUER_NOTE: Record<string, string> = {
  gateway: "enforced outside the agent's process; the agent could neither skip nor forge this receipt",
  sdk: "self-reported by the agent's own process; tamper-evident after issue, but nothing here was enforced outside the agent",
  door: "enforced in front of the business's own HTTP surface; the arriving party could not forge this receipt and is attested only when it presented a grant, and a request that reached the origin some other way leaves no receipt",
  guardian: "decided by an ACS Guardian outside the agent's process and signed with its own key, so the decision is attributable to it; the call is the agent's own report, and the agent could skip the Guardian or ignore its answer",
  egress: "observed by a forward proxy in the agent's network path, for a connection that went around the gateway: where it went and how much, never what was sent; the agent is known only by the proxy credential the witness checked, and a connection that skipped the proxy (no lockdown) leaves no receipt at all",
};
const short = (s: string) => s.slice(0, 12);

export interface Options { issuerKeys: PublicKey[]; principalKeys: PublicKey[]; approvalKeys?: PublicKey[]; logKeys?: PublicKey[]; upstreamKeys?: PublicKey[]; providerSecrets?: { stripe?: string; github?: string }; logId?: string; requireStrict?: boolean; logLeaves?: (string | { pruned?: string; hash?: string })[] }

async function hmacHex(secret: string, data: string): Promise<string> {
  const key = await subtle().importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await subtle().sign("HMAC", key, enc.encode(data)));
}

async function checkProvider(att: any, secrets: { stripe?: string; github?: string }, timestamp: string, result: unknown): Promise<{ ok: boolean; detail: string }> {
  const secret = att.provider === "stripe-webhook" ? secrets.stripe : secrets.github;
  if (!secret) return { ok: false, detail: `no ${att.provider === "stripe-webhook" ? "Stripe" : "GitHub"} secret given` };
  if (att.provider === "stripe-webhook") {
    const parts = Object.fromEntries(String(att.signature).split(",").map((kv: string) => kv.split("=")));
    if (!parts.t || !parts.v1) return { ok: false, detail: "Stripe-Signature header lacks t or v1" };
    if ((await hmacHex(secret, `${parts.t}.${att.rawBody}`)) !== parts.v1) return { ok: false, detail: "Stripe signature does not verify with this secret" };
    const skew = Math.abs(Number(parts.t) * 1000 - Date.parse(timestamp)) / 1000;
    if (!(skew <= 300)) return { ok: false, detail: `Stripe timestamp is ${Math.round(skew)}s from the receipt, beyond tolerance` };
  } else {
    const hexSig = String(att.signature).startsWith("sha256=") ? String(att.signature).slice(7) : "";
    if (!hexSig || (await hmacHex(secret, att.rawBody)) !== hexSig) return { ok: false, detail: "GitHub signature does not verify with this secret" };
  }
  let body: any;
  try { body = JSON.parse(att.rawBody); } catch { return { ok: false, detail: "delivery body is not JSON" }; }
  const bound = String(att.bind).split(".").reduce((v: any, k: string) => (v && typeof v === "object" ? v[k] : undefined), body);
  if (bound === undefined || bound === null || bound === "") return { ok: false, detail: `delivery has no value at ${att.bind}` };
  // what the agent received, never _meta: the delivery copy there always contains the bound value
  const received = result as { content?: unknown; isError?: unknown; structuredContent?: unknown };
  if (!JSON.stringify({ content: received.content, isError: received.isError, structuredContent: received.structuredContent }).includes(JSON.stringify(bound).replace(/^"|"$/g, ""))) return { ok: false, detail: `delivery's ${att.bind} (${String(bound)}) does not appear in the receipt's result` };
  return { ok: true, detail: `shared secret (${att.provider}, bound on ${att.bind})` };
}

const isObj = (v: unknown): v is Record<string, any> => !!v && typeof v === "object" && !Array.isArray(v);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const hex64 = (v: unknown) => typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
function operationProblem(o: unknown): string | null {
  if (!isObj(o) || (o.id !== undefined && (typeof o.id !== "string" || !UUID.test(o.id))) || typeof o.originalReceiptId !== "string" || !UUID.test(o.originalReceiptId)) return "operation ids are not UUIDs";
  if (!hex64(o.idempotencyKey) || !hex64(o.lookupDigest)) return "operation idempotencyKey or lookupDigest is not a sha256";
  if (!["submitted", "pending", "confirmed", "failed", "unknown"].includes(String(o.status)) || o.provenance !== "observed") return "operation status or provenance is invalid";
  if (!isObj(o.budget) || typeof o.budget.id !== "string" || !o.budget.id.length || o.budget.id.length > 128 || typeof o.budget.currency !== "string" || !/^[A-Z]{3}$/.test(o.budget.currency) || typeof o.budget.period !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(o.budget.period)) return "operation budget is invalid";
  return null;
}
/** Provider records are JSON in the first text result, just as the gateway's ordinary fact extraction reads them. */
function providerValue(result: unknown, path: string): unknown {
  let record: unknown;
  if (isObj(result) && Array.isArray(result.content)) {
    const text = result.content.find((c) => isObj(c) && c.type === "text");
    if (isObj(text) && typeof text.text === "string") {
      try { record = JSON.parse(text.text); } catch { return undefined; }
    }
  }
  return path.split(".").reduce<unknown>((v, k) => isObj(v) && Object.hasOwn(v, k) ? v[k] : undefined, record);
}

/** A committed authorization is sufficient original evidence after a process crash before the outcome receipt. */
async function verifyOriginalAuthorization(bundle: Bundle, opts: Options): Promise<{ ok: boolean; checks: Check[] }> {
  const checks: Check[] = [];
  const add = (name: string, ok: boolean, detail?: string) => checks.push({ name, ok, ...(detail === undefined ? {} : { detail }) });
  const sig = await dsseVerify(bundle.envelope, opts.issuerKeys);
  const st = sig.ok ? sig.payload : null;
  const typed = !!st && bundle.envelope.payloadType === RECEIPT_TYPE && st.predicateType === AUTHORIZATION_TYPE;
  add("authorization signature (issuer key)", sig.ok && typed);
  if (!sig.ok || !st || !typed) return { ok: false, checks };
  const p = st.predicate;
  const problem = structuralProblem({ ...p, session: { id: null, toolUseId: null, provenance: "claimed" }, model: { id: null, provenance: "claimed" }, execution: { status: "withheld", provenance: "observed" } });
  add("structural parts in clear", !problem, problem ?? undefined);
  if (problem) return { ok: false, checks };
  add("authorization issued by the gateway", (p.issuer.kind === "gateway" || p.issuer.kind === "door") && p.issuer.keyid === sig.keyid, p.issuer.kind === "door" ? "a door commits a request before relaying it, as a gateway commits a call" : undefined);
  add("authorization operation is submitted", p.issuer.kind === "door" || p.operation?.status === "submitted", p.issuer.kind === "door" ? "a door has no operations" : undefined);
  add("authorization permits the original call", p.policy?.decision === "allow" ? Array.isArray(p.policy.errors) && p.policy.errors.length === 0 : p.policy?.decision === "deny" && p.policy.enforced === false);
  const del = p.delegation && await verifyDelegationChain(p.delegation.envelope, opts.principalKeys);
  add("delegation signature (principal key)", !!del?.ok);
  if (del?.ok) {
    const d = del.delegation;
    add("delegation binds principal and agent", d.principal === p.principal.id && d.agent === p.agent.id && p.principal.provenance === "attested" && p.principal.keyid === del.keyid);
    const at = Date.parse(p.timestamp);
    add("delegation valid at receipt time", !Number.isNaN(at) && Date.parse(d.issuedAt) <= at && at <= Date.parse(d.expiresAt));
    add("executed tool within delegated scope", d.scopes.includes(p.tool.name));
  }
  const getAt = (root: any, path: string[]) => path.reduce((v, k) => isObj(v) && Object.hasOwn(v, k) ? v[k] : undefined, root);
  const isCommitment = (v: any) => isObj(v) && hex64(v.sha256) && (v.$custody === "withheld" || (v.$custody === "encrypted" && v.alg === "A256GCM" && hex64(v.keyid) && [v.iv, v.ciphertext, v.tag].every((f: unknown) => typeof f === "string" && f.length > 0 && /^[A-Za-z0-9+/]+=*$/.test(f)) && v.iv.length === 16 && v.tag.length === 24));
  const paths: string[][] = p.capture?.withheld ?? [];
  add("captured commitments are well formed", paths.every((w) => isCommitment(getAt(p, w))));
  const missingArgs = paths.some((w) => w[0] === "request" && w[1] === "args");
  add("request args digest", st.subject[0]?.digest.sha256 === p.request.argsDigest && (missingArgs || (await digestOf(p.request.args)) === p.request.argsDigest));
  const th = await dsseVerify(bundle.treeHead, [...(opts.logKeys ?? []), ...opts.issuerKeys]);
  add("tree head signature", th.ok && bundle.treeHead.payloadType === TREEHEAD_TYPE);
  if (th.ok) {
    const head = th.payload;
    if (opts.logId !== undefined) add("tree head names the expected log", head.log === opts.logId);
    add("log inclusion proof", head.treeSize === bundle.inclusion.treeSize && await verifyInclusion(await leafHash(canonicalize(bundle.envelope)), bundle.inclusion, head.rootHash));
    if (opts.logLeaves) {
      const hashes: Bytes[] = [];
      for (const l of opts.logLeaves) hashes.push(typeof l === "string" ? await leafHash(l) : unhex((l.pruned ?? l.hash)!));
      add("log file root matches tree head", head.treeSize <= hashes.length && await rootOf(hashes, head.treeSize) === head.rootHash);
    }
  }
  return { ok: checks.every((c) => c.ok), checks };
}

/** mirrors isApprovalTime in src/approval.ts: an ISO time with an offset, as the approval and the receipt's approval record write it */
const iso = (v: unknown) => {
  if (typeof v !== "string") return false;
  const m = /^(\d{4})-(\d{2})-(\d{2})T([01]\d|2[0-3]):([0-5]\d):([0-5]\d)(?:\.\d+)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/.exec(v);
  if (!m || !Number.isFinite(Date.parse(v))) return false;
  const y = Number(m[1]), month = Number(m[2]), day = Number(m[3]);
  const days = [31, y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return month >= 1 && month <= 12 && day >= 1 && day <= days[month - 1]!;
};
const STRUCTURAL_TOP = new Set(["receiptId", "timestamp", "issuer", "principal", "agent", "delegation", "tool", "authorization", "capture"]);
// The approval record's envelope and reason are withheld under a private rule; its status, times, and signer ids are not.
const STRUCTURAL_IN: Record<string, Set<string>> = { approval: new Set(["status", "requiredApprovers", "checkedAt", "consumedAt", "approverKeyids", "fields", "provenance"]), request: new Set(["argsDigest", "provenance"]), execution: new Set(["status", "provenance"]), policy: new Set(["decision", "reasons", "policyDigest", "enforced", "provenance"]), consumed: new Set(["provenance"]), session: new Set(["provenance"]), model: new Set(["provenance"]), operation: new Set(["idempotencyKey", "lookupDigest", "status", "budget", "originalReceiptId", "provenance"]), reconciliation: new Set(["original", "lookup"]) };
const pathTextOf = (w: string[]) => w.map((s) => (/^[A-Za-z0-9_$-]+$/.test(s) ? s : JSON.stringify(s))).join(".");
/** mirrors src/verify.ts structuralProblem: a capture note may never name what a verifier reads to run its checks, and those parts must be what every check assumes */
export function structuralProblem(p: unknown): string | null {
  if (!isObj(p)) return "the predicate is not an object";
  const note = p.capture;
  if (note !== undefined) {
    if (!isObj(note) || (note.mode !== "digest" && note.mode !== "encrypted") || !Array.isArray(note.withheld)) return "the capture note is malformed";
    if (new Set(note.withheld.map((w: unknown) => JSON.stringify(w))).size !== note.withheld.length) return "the capture note names a path twice";
    for (const w of note.withheld) {
      if (!Array.isArray(w) || w.length === 0 || !w.every((s: unknown) => typeof s === "string")) return "the capture note names a malformed path";
      const path = w as string[];
      const head = path[0]!;
      const named = STRUCTURAL_TOP.has(head) || (path.length === 1 && Object.hasOwn(STRUCTURAL_IN, head)) || (path.length === 2 && Object.hasOwn(STRUCTURAL_IN, head) && STRUCTURAL_IN[head]!.has(path[1]!)) || head === "facts" && (path.length <= 2 || path[2] === "tool" || path[2] === "provenance") || (head === "execution" && path.length === 2 && path[1] === "upstream") || (head === "execution" && path.length === 3 && path[1] === "upstream" && path[2] === "provider") || (head === "execution" && path.length === 3 && path[1] === "result" && path[2] === "isError");
      if (named) return `the capture note names a structural part: ${pathTextOf(path)}`;
    }
  }
  if (typeof p.receiptId !== "string" || typeof p.timestamp !== "string") return "receiptId or timestamp is not a string";
  if (!isObj(p.issuer) || !isObj(p.principal) || !isObj(p.agent) || !isObj(p.session) || !isObj(p.model)) return "issuer, principal, agent, session, or model is not an object";
  if (p.principal.provenance === "attested" && typeof p.principal.keyid !== "string") return "an attested principal has no keyid";
  if (!isObj(p.tool) || typeof p.tool.name !== "string") return "tool.name is not a string";
  if (!isObj(p.request) || typeof p.request.argsDigest !== "string" || !isObj(p.request.args)) return "request.args or request.argsDigest is not what it should be";
  if (!isObj(p.execution) || typeof p.execution.status !== "string" || !["executed", "failed", "denied", "error", "withheld"].includes(p.execution.status)) return "execution.status is not a status";
  if (p.policy !== null && (!isObj(p.policy) || (p.policy.decision !== "allow" && p.policy.decision !== "deny") || !Array.isArray(p.policy.reasons) || typeof p.policy.policyDigest !== "string")) return "policy is neither null nor a decision";
  if (!isObj(p.facts) || Object.values(p.facts).some((f) => !isObj(f) || typeof f.tool !== "string")) return "facts is not a map of facts";
  if (p.consumed !== undefined && !isObj(p.consumed)) return "consumed is not an object";
  if (p.delegation !== undefined && (!isObj(p.delegation) || !isObj(p.delegation.envelope))) return "delegation is not a signed envelope";
  if (p.authorization !== undefined && (!isObj(p.authorization) || !isObj(p.authorization.envelope) || !isObj(p.authorization.treeHead) || !isObj(p.authorization.inclusion))) return "authorization is not a bundle";
  if (p.approval !== undefined) {
    const a = p.approval;
    if (!isObj(a) || typeof a.status !== "string" || !["approved", "denied"].includes(a.status) || (a.requiredApprovers !== 1 && a.requiredApprovers !== 2) || !iso(a.checkedAt) || !Array.isArray(a.approverKeyids) || !a.approverKeyids.every((k: unknown) => typeof k === "string") || a.provenance !== "observed") return "approval is not an approval record";
    if (a.consumedAt !== undefined && !iso(a.consumedAt)) return "approval consumption time is not a timestamp";
    if (a.fields !== undefined && (!isObj(a.fields) || Object.entries(a.fields).some(([k, v]) => !["amount", "currency", "beneficiary"].includes(k) || typeof v !== "string" || !v.length))) return "approval field mapping is malformed";
  }
  if (p.operation !== undefined) {
    const problem = operationProblem(p.operation);
    if (problem) return problem;
  }
  if (p.reconciliation !== undefined) {
    const r = p.reconciliation;
    if (!isObj(r) || !isObj(r.original) || !isObj(r.original.envelope) || !isObj(r.original.treeHead) || !isObj(r.original.inclusion) || !isObj(r.lookup)) return "reconciliation is not a lookup and an original bundle";
    const l = r.lookup;
    const statuses = (v: unknown) => Array.isArray(v) && v.length > 0 && v.every((s) => typeof s === "string" && s.length > 0 && s.length <= 128);
    const path = (v: unknown) => typeof v === "string" && v.length > 0 && v.length <= 512 && v.split(".").every((s) => s.length > 0);
    if (typeof l.tool !== "string" || !l.tool.length || !isObj(l.args) || !path(l.statusPath) || !path(l.identityPath) || !statuses(l.confirmed) || !statuses(l.failed) || (l.confirmed as string[]).some((s) => (l.failed as string[]).includes(s))) return "reconciliation lookup is malformed or its terminal statuses overlap";
  }
  if (isObj(p.execution.upstream) && typeof p.execution.upstream.provider !== "undefined" && typeof p.execution.upstream.provider !== "string") return "execution.upstream.provider is not a string";
  return null;
}

/** Strict human-approval envelope and payload checks, mirroring src/approval.ts without a runtime dependency. */
async function verifyApprovalStatement(env: any, trusted: PublicKey[], minimum: number): Promise<{ ok: true; approval: any; approverKeyids: string[] } | { ok: false; error: string }> {
  const exact = (v: any, required: string[], optional: string[] = []) => isObj(v) && required.every((k) => Object.hasOwn(v, k)) && Object.keys(v).every((k) => required.includes(k) || optional.includes(k));
  const base64 = (v: unknown) => { try { return typeof v === "string" && v.length > 0 && v.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(v) && btoa(atob(v)) === v; } catch { return false; } };
  const nonempty = (v: unknown) => typeof v === "string" && v.length > 0;
  try {
    if (!exact(env, ["payloadType", "payload", "signatures"]) || env.payloadType !== APPROVAL_TYPE || !base64(env.payload) || !Array.isArray(env.signatures) || !env.signatures.length || !env.signatures.every((s: any) => exact(s, ["keyid", "sig"]) && nonempty(s.keyid) && base64(s.sig) && b64.decode(s.sig).length === 64)) return { ok: false, error: "malformed approval envelope" };
    const approvers = new Set<string>();
    const data = pae(env.payloadType, b64.decode(env.payload));
    for (const s of env.signatures) {
      const k = trusted.find((key) => key.keyid === s.keyid);
      if (k && await subtle().verify({ name: "Ed25519" }, k.key, b64.decode(s.sig), data)) approvers.add(k.keyid);
    }
    if (approvers.size < minimum) return { ok: false, error: `approval requires ${minimum} distinct trusted signature${minimum === 1 ? "" : "s"}` };
    const a = JSON.parse(new TextDecoder().decode(b64.decode(env.payload)));
    const uuid = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$/i;
    if (!exact(a, ["version", "approvalId", "principal", "agent", "tool", "argsDigest", "issuedAt", "expiresAt"], ["amount", "currency", "beneficiary"]) || a.version !== "0.1" || typeof a.approvalId !== "string" || !uuid.test(a.approvalId) || ![a.principal, a.agent, a.tool].every(nonempty) || typeof a.argsDigest !== "string" || !/^[0-9a-f]{64}$/.test(a.argsDigest) || (Object.hasOwn(a, "amount") && !Number.isSafeInteger(a.amount)) || ["currency", "beneficiary"].some((k) => Object.hasOwn(a, k) && !nonempty(a[k])) || !iso(a.issuedAt) || !iso(a.expiresAt) || Date.parse(a.expiresAt) <= Date.parse(a.issuedAt)) return { ok: false, error: "invalid approval payload" };
    return { ok: true, approval: a, approverKeyids: [...approvers] };
  } catch { return { ok: false, error: "invalid approval" }; }
}

/** The same checks, in the same order, with the same names, as the reference verifyBundle. */
export async function verifyBundle(bundle: Bundle, opts: Options): Promise<Result> {
  const checks: Check[] = [];
  const add = (name: string, ok: boolean, detail?: string) => { checks.push(detail === undefined ? { name, ok } : { name, ok, detail }); return ok; };
  let treeHeadSigner: Result["treeHeadSigner"] = null;
  const done = (statement: any | null): Result => ({ ok: checks.every((c) => c.ok), checks, statement, issuerNote: statement ? (ISSUER_NOTE[statement.predicate.issuer.kind] ?? "unknown issuer kind") : null, treeHeadSigner });

  const sig = await dsseVerify(bundle.envelope, opts.issuerKeys);
  if (!sig.ok) { add("receipt signature (issuer key)", false, sig.error); return done(null); }
  add("receipt signature (issuer key)", true, `keyid ${short(sig.keyid)}`);
  const st = sig.payload;
  if (!add("receipt payload type", bundle.envelope.payloadType === RECEIPT_TYPE && st.predicateType === PREDICATE_TYPE)) return done(null);
  const broken = structuralProblem(st.predicate);
  if (!add("structural parts in clear", !broken, broken ?? undefined)) return done(null);
  const p = st.predicate;
  add("issuer kind is known", p.issuer.kind === "gateway" || p.issuer.kind === "sdk" || p.issuer.kind === "door" || p.issuer.kind === "egress" || p.issuer.kind === "guardian", `${p.issuer.kind}${p.issuer.framework ? ` / ${p.issuer.framework}` : ""}`);
  add("issuer keyid matches signer", p.issuer.keyid === sig.keyid);
  if (opts.requireStrict) {
    add("strict mode in force", p.issuer.kind === "gateway" && p.issuer.strict === true, p.issuer.strict === true ? undefined : "the issuer does not say it ran in strict mode");
    // under strict mode every call is precommitted; a provider read the operator ran is a lookup, not a call
    const forwarded = p.execution.status === "executed" || p.execution.status === "failed" || p.execution.status === "error";
    add("strict: call precommitted before forwarding", !forwarded || !!p.reconciliation || !!p.authorization, forwarded && !p.reconciliation && !p.authorization ? `the call was ${p.execution.status} with no authorization committed first` : undefined);
  }
  if (p.operation) {
    add("operation observed by gateway", p.issuer.kind === "gateway" && p.operation.provenance === "observed");
    if (!p.reconciliation) {
      // A retry of an existing operation has a receipt of its own. It is withheld (never forwarded again) and names the original.
      const retry = p.operation.originalReceiptId !== p.receiptId;
      add("operation names this original receipt", !retry || p.execution.status === "withheld");
      const refused = p.execution.status === "withheld" || p.execution.status === "denied";
      add("operation awaits provider reconciliation", retry || ["submitted", "pending", "unknown"].includes(p.operation.status) || refused && p.operation.status === "failed");
      add("operation carries committed authorization", refused || !!p.authorization);
    }
  }

  if (p.issuer.kind === "gateway") {
    add("gateway receipt carries a delegation", p.delegation !== undefined);
    add("gateway receipt carries a policy decision", p.policy !== null);
  }
  if (p.issuer.kind === "door") add("door receipt carries a policy decision", p.policy !== null);
  // An egress witness saw a connection that went around the gateway: where it went and how much, never what was sent.
  // Its destination is its own observation; its agent is only as good as the proxy credential it checked.
  if (p.issuer.kind === "egress") {
    add("egress receipt carries a policy decision", p.policy !== null);
    const dest = Object.hasOwn(p.facts, "destination") ? p.facts.destination : undefined;
    const seen = dest?.value as { host?: unknown; port?: unknown } | undefined;
    const name = typeof seen?.host === "string" && typeof seen.port === "number" ? `${seen.host.includes(":") ? `[${seen.host}]` : seen.host}:${seen.port}` : undefined;
    add("egress destination observed", p.tool.provenance === "observed" && dest?.provenance === "observed" && name === p.tool.name, name === p.tool.name ? `${p.tool.name}; an observed bypass of the gateway, not a record of what was sent` : `the destination fact names ${name ?? "nothing"}, the receipt ${p.tool.name}`);
    const relayed = p.execution.status === "executed" || p.execution.status === "failed" || p.execution.status === "error";
    add("egress relayed only for a checked agent", !relayed || p.agent.provenance === "observed", p.agent.provenance === "observed" ? `${p.agent.id}, by the proxy credential the witness checked` : relayed ? `the connection was ${p.execution.status} for an agent the witness did not check` : "no agent was checked and nothing was relayed");
    add("egress open committed before relaying", !relayed || !!p.authorization, relayed ? (p.authorization ? "the connection was in the log before any byte moved" : `the connection was ${p.execution.status} with nothing committed first`) : "nothing was relayed");
    // An IP literal is the action itself: the peer must be that very address. A host name must have led to a public address.
    const host = typeof seen?.host === "string" ? seen.host : "";
    const literal = isAddressLiteral(host);
    const reached = p.execution.status === "executed" || p.execution.status === "failed";
    const peer = p.execution.status === "executed" || p.execution.status === "failed" ? (p.execution.result as { peer?: unknown } | null)?.peer : undefined;
    const peerOk = typeof peer === "string" && (literal ? sameAddress(peer, host) : !internalAddress(peer));
    add("egress peer matches the destination", !reached || peerOk, !reached ? "no connection was made" : literal ? `${host}, an address the policy named, reached ${typeof peer === "string" ? peer : "no recorded peer"}` : `${host} reached ${typeof peer === "string" ? peer : "no recorded peer"}${peerOk ? ", a public address" : ""}`);
  }
  // A Guardian decides and carries out nothing: an allow is withheld (nothing forwarded), a deny is denied.
  if (p.issuer.kind === "guardian") {
    add("guardian receipt carries a policy decision", !!p.policy && typeof p.policy === "object" && !Array.isArray(p.policy));
    const decided = p.execution.status === "denied" ? p.policy?.decision === "deny" : p.execution.status === "withheld" && p.policy?.decision === "allow";
    add("guardian decided, executed nothing", decided, decided ? `${p.policy?.decision}; the agent asked, reports the call itself, and is trusted to honor the answer` : `the receipt says ${p.execution.status} with a policy ${p.policy?.decision ?? "absent"}`);
  }

  if (p.delegation) {
    const del = await verifyDelegationChain(p.delegation.envelope, opts.principalKeys);
    const d = del.ok ? del.delegation : null;
    const shape = !!d;
    add("delegation signature (principal key)", del.ok, del.ok ? `signed by ${short(del.keyid)}` : del.error);
    if (delegationHasParent(p.delegation.envelope)) add("delegation chain to the principal", del.ok, del.ok ? `${[del.chain[0].principal, ...del.chain.map((c) => c.agent)].join(" → ")} (${del.chain.length - 1} delegation(s))` : del.error);
    if (del.ok && shape) {
      const principalKeyid = p.principal.provenance === "attested" ? p.principal.keyid : null;
      add("delegation binds principal and agent", d.principal === p.principal.id && d.agent === p.agent.id && del.keyid === principalKeyid);
      const at = Date.parse(p.timestamp);
      const inScope = d.scopes.includes(p.tool.name);
      const executed = p.execution.status === "executed" || p.execution.status === "failed";
      // mirrors src/verify.ts: a call refused after the grant ran out is a true record; only an executed call must sit inside the window
      const valid = !Number.isNaN(at) && Date.parse(d.issuedAt) <= at && at <= Date.parse(d.expiresAt);
      add("delegation valid at receipt time", valid || !executed || !!p.reconciliation, valid ? `${d.issuedAt} .. ${d.expiresAt}` : p.reconciliation ? "operator reconciliation; the original authorization's grant window is checked separately" : `${d.issuedAt} .. ${d.expiresAt}; the call was ${p.execution.status}, so the grant need not have been in force`);
      add("executed tool within delegated scope", !executed || inScope, inScope ? p.tool.name : `${p.tool.name} not in [${d.scopes.join(", ")}]`);
    }
  } else {
    add("principal is claimed, not attested", p.principal.provenance === "claimed", "no signed delegation in this receipt");
  }
  // Private evidence (mirrors src/verify.ts): the signed capture note names every path whose value is withheld behind
  // a commitment. The browser has no key and takes no disclosure, so a digest over withheld values passes as committed
  // and says so; a digest over values the receipt carries in clear is recomputed, with the salt the statement carries.
  // The note decides, never the shape of the data: a path it names must hold a commitment (else the check fails), and
  // commitment-shaped data it does not name is ordinary data, inside the digest.
  // a commitment is one only when it carries what a verifier checks: the sha256 (the salt is never in the receipt), and for an encrypted one the fields the key needs, a 12-byte iv and a 16-byte tag
  // a string check before each pattern: RegExp.test coerces, and an array of one hex string is not a hash
  const hex64 = (v: unknown) => typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
  const isCommitment = (v: any) => !!v && typeof v === "object" && !Array.isArray(v) && hex64(v.sha256) && (v.$custody === "withheld" || (v.$custody === "encrypted" && v.alg === "A256GCM" && hex64(v.keyid) && [v.iv, v.ciphertext, v.tag].every((f: unknown) => typeof f === "string" && f.length > 0 && /^[A-Za-z0-9+/]+=*$/.test(f)) && v.iv.length === 16 && v.tag.length === 24));
  type Path = string[];
  const note = p.capture as { mode: string; withheld: Path[] } | undefined;
  const under = (w: Path, prefix: Path) => prefix.length <= w.length && prefix.every((s, i) => w[i] === s);
  const getAt = (root: any, path: Path) => path.reduce((v, k) => (v && typeof v === "object" && !Array.isArray(v) && Object.prototype.hasOwnProperty.call(v, k) ? v[k] : undefined), root);
  const pathText = (w: Path) => w.map((s) => (/^[A-Za-z0-9_$-]+$/.test(s) ? s : JSON.stringify(s))).join(".");
  const committedNote = (paths: Path[]) => {
    const encrypted = paths.filter((w) => getAt(p, w)?.$custody === "encrypted").length;
    return `committed, not recomputed: ${paths.length} value(s) withheld${encrypted ? ` (${encrypted} encrypted)` : ""}; ${encrypted ? "give the capture key or " : ""}disclose them with the command-line verifier to recompute`;
  };
  const claimed = new Set<string>();
  /** the withheld paths under a prefix, and the first one the receipt bears no commitment for */
  const region = (prefix: Path) => {
    const paths = (note?.withheld ?? []).filter((w) => under(w, prefix));
    for (const w of paths) claimed.add(JSON.stringify(w));
    const bad = paths.find((w) => !isCommitment(getAt(p, w)));
    return { paths, problem: bad ? `the capture note says ${pathText(bad)} is withheld, but the receipt carries no commitment for it` : null };
  };
  const subjectOk = st.subject[0]?.digest.sha256 === p.request.argsDigest;
  const args = region(["request", "args"]);
  if (args.problem) add("request args digest", false, args.problem);
  else if (args.paths.length) add("request args digest", subjectOk, committedNote(args.paths));
  else add("request args digest", (await digestOf(p.request.args)) === p.request.argsDigest && subjectOk);
  const forwarded = ["executed", "failed", "error"].includes(p.execution.status);
  if (p.approval) {
    const a = p.approval;
    const consumed = a.consumedAt !== undefined && Date.parse(a.consumedAt) >= Date.parse(a.checkedAt) && Date.parse(a.checkedAt) >= Date.parse(p.timestamp);
    add("approval consistent with execution", !forwarded || (a.status === "approved" && consumed), a.status === "denied" ? `approval refused: ${typeof a.reason === "string" ? a.reason : "not approved"}` : "single use is enforced by the gateway's persistent store; one receipt cannot prove absence of reuse elsewhere");
    // Only a forwarded call must rest on a valid approval; a refusal is an authentic record whatever its approval was.
    if (forwarded && a.status === "approved") {
      const sealed = region(["approval", "envelope"]);
      if (sealed.problem) add("approval signatures (human keys)", false, sealed.problem);
      // The issuer withholds the envelope only when it withholds the arguments. With the arguments in clear, a withheld
      // envelope would let an issuer skip the binding check, so it fails rather than passes as committed.
      else if (sealed.paths.length && !args.paths.length) add("approval signatures (human keys)", false, "the approval envelope is withheld but the arguments are in clear; the binding cannot be checked");
      else if (sealed.paths.length) add("approval signatures (human keys)", true, committedNote(sealed.paths));
      else {
        const signed = await verifyApprovalStatement(a.envelope, opts.approvalKeys ?? [], a.requiredApprovers);
        const reported = signed.ok && new Set(a.approverKeyids).size >= a.requiredApprovers && a.approverKeyids.every((id: string) => signed.approverKeyids.includes(id));
        add("approval signatures (human keys)", signed.ok && reported, signed.ok ? `${signed.approverKeyids.length} distinct trusted signature(s)` : signed.error);
        if (signed.ok) {
          const at = a.consumedAt ?? a.checkedAt;
          const atValid = Date.parse(at) >= Date.parse(signed.approval.issuedAt) && Date.parse(at) < Date.parse(signed.approval.expiresAt);
          const valid = [a.checkedAt, at].every((time) => Date.parse(time) >= Date.parse(signed.approval.issuedAt) && Date.parse(time) < Date.parse(signed.approval.expiresAt));
          add("approval valid at forward time", valid, `${signed.approval.issuedAt} .. ${signed.approval.expiresAt}; checked at ${at}`);
          if (args.problem) add("approval payload binding", false, args.problem);
          else if (args.paths.length) add("approval payload binding", true, committedNote(args.paths));
          else {
            const action: Record<string, unknown> = { principal: p.principal.id ?? "", agent: p.agent.id, tool: p.tool.name, argsDigest: await digestOf(p.request.args) };
            for (const field of ["amount", "currency", "beneficiary"]) {
              const name = a.fields?.[field] ?? field;
              if (Object.hasOwn(p.request.args, name)) action[field] = p.request.args[name];
            }
            const mismatch = ["principal", "agent", "tool", "argsDigest", "amount", "currency", "beneficiary"].find((k) => signed.approval[k] !== action[k]);
            add("approval payload binding", !mismatch && atValid, mismatch ? `approval ${mismatch} does not match this call` : atValid ? "principal, agent, tool, full arguments, amount, currency, and beneficiary match" : "approval has expired or is not yet valid");
          }
        }
      }
    }
  }
  for (const name of Object.keys(p.facts)) {
    for (const part of ["value", "args"]) {
      const r = region(["facts", name, part]);
      if (!r.paths.length) continue;
      add(`fact ${name} ${part}`, !r.problem, r.problem ?? committedNote(r.paths));
    }
  }
  const executedOrFailed = p.execution.status === "executed" || p.execution.status === "failed";
  let resultInClear = false;
  if (executedOrFailed) {
    const r = region(["execution", "result"]);
    if (r.problem) add("execution result digest", false, r.problem);
    else if (r.paths.length) {
      add("execution result digest", true, committedNote(r.paths));
      // the upstream checks read the content, isError, and structuredContent, never _meta, which carries what the
      // upstream wrote and is withheld beside a result the rule leaves in clear: with only _meta withheld they still run
      if (r.paths.every((w) => JSON.stringify(w) === JSON.stringify(["execution", "result", "_meta"]))) resultInClear = true;
    } else {
      add("execution result digest", (await digestOf(p.execution.result)) === p.execution.resultDigest);
      resultInClear = true;
    }
  }
  // every other withheld path gets its own line: a message, a denial reason, a provider's delivery body, a part added later
  for (const w of note?.withheld ?? []) {
    if (claimed.has(JSON.stringify(w))) continue;
    const ok = isCommitment(getAt(p, w));
    add(`withheld ${pathText(w)}`, ok, ok ? committedNote([w]) : `the capture note says ${pathText(w)} is withheld, but the receipt carries no commitment for it`);
  }
  const stringOrCommitment = (v: unknown) => typeof v === "string" || isCommitment(v);
  const isProvider = (v: any) => !!v && (v.provider === "stripe-webhook" || v.provider === "github-delivery") && stringOrCommitment(v.rawBody) && stringOrCommitment(v.signature) && stringOrCommitment(v.bind);
  // a check is skipped only for a part the signed note declares withheld; a part that is simply not there, or commitment-shaped without the note saying so, fails
  const declared = (path: Path) => (note?.withheld ?? []).some((w) => JSON.stringify(w) === JSON.stringify(path));
  if (executedOrFailed && p.execution.upstream && isProvider(p.execution.upstream)) {
    if (opts.providerSecrets) {
      const parts = ["rawBody", "signature", "bind"];
      if (!resultInClear || parts.some((f) => declared(["execution", "upstream", f]))) add("upstream signature not checked", true, "the result, the delivery body, its signature, or its bind is withheld; disclose them with the command-line verifier to check the provider's delivery");
      else if (parts.some((f) => typeof p.execution.upstream[f] !== "string")) add("upstream signature (provider secret)", false, "the receipt carries no delivery body, signature, or bind to check, and the capture note does not say they are withheld");
      else {
        const u = await checkProvider(p.execution.upstream, opts.providerSecrets, p.timestamp, p.execution.result);
        add("upstream signature (provider secret)", u.ok, u.detail);
      }
    }
  } else if (executedOrFailed && p.execution.upstream && (opts.upstreamKeys?.length ?? 0) > 0) {
    const env = p.execution.upstream.envelope;
    const wellFormed = !!env && typeof env === "object" && typeof env.payload === "string" && Array.isArray(env.signatures);
    if (!resultInClear) add("upstream signature not checked", true, "the result is withheld; disclose it with the command-line verifier to check the upstream's signature against it");
    else if (declared(["execution", "upstream", "envelope"])) add("upstream signature (upstream key)", false, "the result is in clear but the upstream's signature is withheld; disclose it or give the capture key to check it");
    else if (!wellFormed) add("upstream signature (upstream key)", false, "the receipt carries no upstream envelope to check, and the capture note does not say it is withheld");
    else {
      const u = await dsseVerify(p.execution.upstream.envelope, opts.upstreamKeys!);
      let ok = u.ok && p.execution.upstream.envelope.payloadType === UPSTREAM_TYPE;
      let detail = u.ok ? `keyid ${short(u.keyid)}` : u.error;
      if (u.ok) {
        const expectedDigest = await digestOf({ content: p.execution.result.content, isError: !!p.execution.result.isError });
        if (u.payload.receiptId !== p.receiptId) { ok = false; detail = "signed for a different receipt"; }
        else if (u.payload.tool !== p.tool.name) { ok = false; detail = `signed for tool ${u.payload.tool}`; }
        else if (u.payload.contentDigest !== expectedDigest) { ok = false; detail = "signed content differs from the result in the receipt"; }
      }
      add("upstream signature (upstream key)", ok, detail);
    }
  }
  if (p.policy) {
    // a deny that was not enforced (observe mode, enforced: false on the receipt) may sit beside an executed call; an enforced one never does
    const consistent = p.policy.decision === "allow" ? p.execution.status !== "denied" : p.policy.enforced === false ? p.execution.status !== "denied" : p.execution.status === "denied";
    add("policy decision consistent with execution", consistent, `${p.policy.decision}${p.policy.enforced === false ? " (observe mode, not enforced)" : ""} -> ${p.execution.status}`);
    // a withheld error list is a non-empty one: the issuer leaves an empty list in clear
    const errors = isCommitment(p.policy.errors) || (Array.isArray(p.policy.errors) && p.policy.errors.length > 0);
    add("no policy errors on an allow", !(p.policy.decision === "allow" && errors));
  }
  if (p.reconciliation) {
    const r = p.reconciliation;
    // Refuse nesting before the recursive verifier is called; the original must be the first operation attempt.
    const osig = await dsseVerify(r.original.envelope, opts.issuerKeys);
    const ost = osig.ok ? osig.payload as any : null;
    const original = ost?.predicate;
    const eligible = isObj(original) && !("reconciliation" in original);
    let originalOk = false;
    if (eligible && ost) {
      try {
        const nested = ost.predicateType === PREDICATE_TYPE
          ? await verifyBundle(r.original, opts)
          : await verifyOriginalAuthorization(r.original, opts);
        originalOk = nested.ok;
        for (const c of nested.checks) add(`reconciliation original ${c.name}`, c.ok, c.detail);
      } catch {
        add("reconciliation original bundle is well formed", false);
      }
    }
    add("reconciliation original evidence verifies", eligible && originalOk);
    const o = original?.operation;
    const op = p.operation;
    const linked = !!o && !!op && !operationProblem(o) && ["submitted", "pending", "unknown"].includes(o.status) && o.originalReceiptId === original!.receiptId && op.originalReceiptId === original!.receiptId && p.receiptId !== original!.receiptId && (op.id === undefined || o.id === undefined || op.id === o.id) && op.idempotencyKey === o.idempotencyKey && op.lookupDigest === o.lookupDigest && canonicalize(op.budget) === canonicalize(o.budget) && canonicalize(p.principal) === canonicalize(original!.principal) && canonicalize(p.agent) === canonicalize(original!.agent) && canonicalize(p.tool) === canonicalize(original!.tool) && canonicalize(p.delegation) === canonicalize(original!.delegation) && p.issuer.keyid === original!.issuer.keyid && Date.parse(p.timestamp) >= Date.parse(original!.timestamp);
    add("reconciliation links the original operation", linked);
    add("reconciliation lookup matches authorization", !!o && (await digestOf(r.lookup)) === o.lookupDigest);
    const lookupArgs = region(["request", "args"]);
    add("reconciliation lookup args match request", !lookupArgs.problem && (lookupArgs.paths.length > 0 || canonicalize(p.request.args) === canonicalize(r.lookup.args)), lookupArgs.paths.length > 0 ? "request arguments committed under the capture rule" : undefined);
    const before = r.original.inclusion.leafIndex < bundle.inclusion.leafIndex && r.original.inclusion.treeSize <= bundle.inclusion.treeSize;
    const oth = await dsseVerify(r.original.treeHead, [...(opts.logKeys ?? []), ...opts.issuerKeys]);
    const cth = await dsseVerify(bundle.treeHead, [...(opts.logKeys ?? []), ...opts.issuerKeys]);
    add("reconciliation logged after original", before && oth.ok && cth.ok && isObj(oth.payload) && isObj(cth.payload) && oth.payload.log === cth.payload.log);
    const terminal = op?.status === "confirmed" || op?.status === "failed";
    add("reconciliation records a terminal provider outcome", terminal && p.execution.status === "executed" && p.execution.provenance === "observed");
    const rr = region(["execution", "result"]);
    if (rr.problem) add("reconciliation provider status", false, rr.problem);
    else if (rr.paths.some((w) => JSON.stringify(w) !== JSON.stringify(["execution", "result", "_meta"]))) add("reconciliation provider status", true, "provider result withheld; disclose it or give the capture key to recompute the gateway-observed status");
    else {
      const ex = p.execution as { result?: unknown };
      const status = providerValue(ex.result, r.lookup.statusPath);
      const mapped = typeof status === "string" ? r.lookup.confirmed.includes(status) ? "confirmed" : r.lookup.failed.includes(status) ? "failed" : null : null;
      const identity = providerValue(ex.result, r.lookup.identityPath);
      add("reconciliation provider status", terminal && mapped === op?.status && identity === op?.idempotencyKey && !(isObj(ex.result) && ex.result.isError === true), "provider read observed by the gateway and bound to its idempotency key; no independent provider signature is implied");
    }
  }

  const logKeys = opts.logKeys ?? [];
  if (p.authorization) {
    const a = p.authorization;
    const asig = await dsseVerify(a.envelope, opts.issuerKeys);
    const ast = asig.ok ? asig.payload : null;
    const typed = !!ast && a.envelope.payloadType === RECEIPT_TYPE && ast.predicateType === AUTHORIZATION_TYPE;
    add("authorization signature (issuer key)", asig.ok && typed && asig.keyid === sig.keyid, asig.ok ? (typed ? `keyid ${short(asig.keyid)}` : "not an authorization statement") : asig.error);
    if (ast && typed) {
      const ap = ast.predicate;
      const same = ap.receiptId === p.receiptId && ap.tool?.name === p.tool.name && ap.request?.argsDigest === p.request.argsDigest && ap.agent?.id === p.agent.id && ap.principal?.id === p.principal.id && (ap.policy?.decision === "allow" || ap.policy?.decision === "deny" && ap.policy.enforced === false);
      add("authorization names this call", same, same ? `${ap.tool.name} for receipt ${short(ap.receiptId)}` : "committed for a different receipt, tool, arguments, agent, or decision");
      if (ap.approval || p.approval) {
        const stable = (approval: any) => approval ? { envelope: approval.envelope, requiredApprovers: approval.requiredApprovers, fields: approval.fields } : null;
        add("authorization carries this approval", canonicalize(stable(ap.approval)) === canonicalize(stable(p.approval)), "approval envelope, signer requirement, and argument mapping must match the precommit");
        // A refusal needs no human keys, so the precommit's approval is checked for a forwarded call only.
        if (forwarded) {
          const ac = ap.approval;
          // Under a private rule the precommit carries a commitment to the envelope, which this verifier cannot open.
          // an envelope withheld beside arguments in clear is not a private receipt: see "approval signatures (human keys)"
          const sealed = isCommitment(ac?.envelope) && args.paths.length > 0;
          const signed = ac && !sealed && (ac.requiredApprovers === 1 || ac.requiredApprovers === 2) ? await verifyApprovalStatement(ac.envelope, opts.approvalKeys ?? [], ac.requiredApprovers) : null;
          const valid = !!ac && ac.status === "approved" && ac.provenance === "observed" && iso(ac.checkedAt) && (sealed || !!signed?.ok) &&
            (!signed?.ok || (Date.parse(ac.checkedAt) >= Date.parse(signed.approval.issuedAt) && Date.parse(ac.checkedAt) < Date.parse(signed.approval.expiresAt))) &&
            Date.parse(ac.checkedAt) >= Date.parse(p.timestamp) && Date.parse(ac.checkedAt) <= Date.parse(p.approval?.checkedAt ?? "") &&
            Array.isArray(ac.approverKeyids) && new Set(ac.approverKeyids).size >= ac.requiredApprovers && (!signed?.ok || ac.approverKeyids.every((id: unknown) => typeof id === "string" && signed.approverKeyids.includes(id)));
          add("authorization approval was valid", valid, sealed ? "the envelope is withheld, so only the recorded status, times, and signer count are checked; disclose it or give the capture key to check the signatures" : "the precommit must record an approved statement with trusted signer observations and a check inside its validity window");
        }
      }
      if (p.operation || ap.operation) {
        const o = p.operation;
        const aop = ap.operation;
        add("authorization names this operation", !!o && !!aop && !operationProblem(aop) && aop.status === "submitted" && (aop.id === undefined || o.id === undefined || aop.id === o.id) && aop.idempotencyKey === o.idempotencyKey && aop.lookupDigest === o.lookupDigest && aop.originalReceiptId === o.originalReceiptId && canonicalize(aop.budget) === canonicalize(o.budget));
      }
      const ath = await dsseVerify(a.treeHead, [...logKeys, ...opts.issuerKeys]);
      add("authorization tree head signature", ath.ok && a.treeHead.payloadType === TREEHEAD_TYPE, ath.ok ? `keyid ${short(ath.keyid)}` : ath.error);
      if (ath.ok) {
        const ahead = ath.payload;
        const included = ahead.treeSize === a.inclusion.treeSize && (await verifyInclusion(await leafHash(canonicalize(a.envelope)), a.inclusion, ahead.rootHash));
        add("authorization log inclusion proof", included, `leaf ${a.inclusion.leafIndex} of ${a.inclusion.treeSize}`);
        const before = a.inclusion.leafIndex < bundle.inclusion.leafIndex && a.inclusion.treeSize <= bundle.inclusion.treeSize;
        add("authorization logged before execution", before, `authorization leaf ${a.inclusion.leafIndex}, receipt leaf ${bundle.inclusion.leafIndex}`);
      }
    }
  }
  const th = await dsseVerify(bundle.treeHead, [...logKeys, ...opts.issuerKeys]);
  const byLog = th.ok && logKeys.some((k) => k.keyid === th.keyid);
  treeHeadSigner = th.ok ? (byLog ? "log key" : "issuer key") : null;
  add("tree head signature", th.ok && bundle.treeHead.payloadType === TREEHEAD_TYPE, th.ok ? `${byLog ? "log key" : "issuer key"} ${short(th.keyid)}` : th.error);
  if (th.ok) {
    const head = th.payload;
    if (opts.logId !== undefined) add("tree head names the expected log", head.log === opts.logId, head.log ? `log ${head.log}` : "tree head names no log");
    add("tree head matches inclusion proof size", head.treeSize === bundle.inclusion.treeSize);
    const included = await verifyInclusion(await leafHash(canonicalize(bundle.envelope)), bundle.inclusion, head.rootHash);
    add("log inclusion proof", included, `leaf ${bundle.inclusion.leafIndex} of ${bundle.inclusion.treeSize}, root ${short(head.rootHash)}`);
    if (opts.logLeaves) {
      const hashes: Bytes[] = [];
      // a log copy holds leaf strings, or {pruned} and {hash} lines that already are the leaf hash
      for (const l of opts.logLeaves) hashes.push(typeof l === "string" ? await leafHash(l) : unhex((l.pruned ?? l.hash)!));
      if (head.treeSize > hashes.length) add("log file root matches tree head", false, `log copy has ${hashes.length} leaves, tree head is at ${head.treeSize}`);
      else { const root = await rootOf(hashes, head.treeSize); add("log file root matches tree head", root === head.rootHash, `recomputed ${short(root)}`); }
    }
  }
  return done(st);
}

async function rootOf(hashes: Bytes[], size: number): Promise<string> {
  const split = (n: number) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
  const mth = async (lo: number, hi: number): Promise<Bytes> => {
    const n = hi - lo;
    if (n === 0) return sha256(new Uint8Array(0));
    if (n === 1) return hashes[lo]!;
    const k = split(n);
    return nodeHash(await mth(lo, lo + k), await mth(lo + k, hi));
  };
  return hex(await mth(0, size));
}

export interface AuditResult { ok: boolean; checks: Check[] }
export async function auditExtends(older: Envelope, newer: Envelope, proof: string[], keys: PublicKey[], logId?: string, opts: { witnessKeys?: PublicKey[] } = {}): Promise<AuditResult> {
  const checks: Check[] = [];
  const add = (name: string, ok: boolean, detail?: string) => { checks.push(detail === undefined ? { name, ok } : { name, ok, detail }); return ok; };
  const decode = async (label: string, env: Envelope) => { const v = await dsseVerify(env, keys); add(`${label} tree head signature`, v.ok && env.payloadType === TREEHEAD_TYPE, v.ok ? `keyid ${short(v.keyid)}` : v.error); return v.ok ? v.payload : null; };
  const a = await decode("older", older);
  const b = await decode("newer", newer);
  if (!a || !b) return { ok: false, checks };
  if (logId !== undefined) add("both tree heads name the expected log", a.log === logId && b.log === logId, `expected ${logId}, got ${a.log ?? "none"} and ${b.log ?? "none"}`);
  else if (a.log !== b.log) add("both tree heads name the same log", false, `${a.log ?? "none"} and ${b.log ?? "none"}`);
  if (!add("older is not larger than newer", a.treeSize <= b.treeSize, `${a.treeSize} -> ${b.treeSize}`)) return { ok: false, checks };
  const consistent = await verifyConsistency(a.treeSize, a.rootHash, b.treeSize, b.rootHash, proof);
  add("newer log extends older log", consistent, consistent ? `${proof.length} proof hashes` : "history was rewritten, or the proof is for other tree heads");
  if (opts.witnessKeys && opts.witnessKeys.length > 0) {
    // every witness key whose signature on the newer head verifies
    const by: string[] = [];
    for (const s of newer.signatures) {
      const k = opts.witnessKeys.find((w) => w.keyid === s.keyid);
      if (!k) continue;
      const payload = b64.decode(newer.payload);
      if (await subtle().verify({ name: "Ed25519" }, k.key, b64.decode(s.sig), pae(newer.payloadType, payload))) by.push(s.keyid);
    }
    add("newer tree head countersigned by a witness", by.length > 0, by.length ? `witness ${short(by[0]!)}` : "no witness signature on the newer head");
  }
  return { ok: checks.every((c) => c.ok), checks };
}

/** The human-readable report, the same shape the CLI prints. */
export function formatReport(r: Result): string {
  const lines = r.checks.map((c) => `${c.ok ? "PASS" : "FAIL"}  ${c.name}${c.detail ? `  (${c.detail})` : ""}`);
  lines.push("", r.ok ? "RESULT: VERIFIED" : "RESULT: NOT VERIFIED");
  if (!r.statement) return lines.join("\n");
  const p = r.statement.predicate;
  lines.push("", `ISSUER: ${p.issuer.kind}${p.issuer.framework ? ` (${p.issuer.framework})` : ""}${p.issuer.strict ? ", strict mode" : ""}, ${r.issuerNote}`, "", "field           provenance  value");
  const row = (f: string, prov: string, v: unknown) => lines.push(`${f.padEnd(15)} ${prov.padEnd(11)} ${typeof v === "string" ? v : JSON.stringify(v)}`);
  row("principal", p.principal.provenance, p.principal.id ?? "(none)");
  row("agent", p.agent.provenance, p.agent.id);
  const idText = (v: unknown) => (typeof v === "string" ? v : v === null || v === undefined ? "-" : "(withheld under the capture rule)");
  if (p.session.id || p.session.toolUseId) row("session", p.session.provenance, `${idText(p.session.id)} / ${idText(p.session.toolUseId)}`);
  row("model", p.model.provenance, p.model.id === null ? "(none supplied)" : idText(p.model.id));
  row("tool", p.tool.provenance, p.tool.name);
  row("args", p.request.provenance, p.request.args);
  for (const [k, f] of Object.entries<any>(p.facts)) row(`fact.${k}`, f.provenance, f.value);
  if (p.reconciliation) row("policy", "-", "(none evaluated: a provider read, not a call)");
  else if (p.policy) row("policy", p.policy.provenance, `${p.policy.decision}${p.policy.enforced === false ? " (observe mode, not enforced)" : ""} [${p.policy.reasons.join(",")}] policy ${short(p.policy.policyDigest)}`); else row("policy", "-", "(none evaluated)");
  if (p.consumed) row("consumed", p.consumed.provenance, !Array.isArray(p.consumed.factIds) ? "(withheld under the capture rule)" : p.consumed.factIds.length === 0 ? "(no facts shown before this call)" : p.consumed.factIds);
  if (p.approval) row("approval", p.approval.provenance, `${p.approval.status}; ${p.approval.requiredApprovers} approver(s) required${p.approval.consumedAt ? `; consumed ${p.approval.consumedAt}` : ""}${typeof p.approval.reason === "string" ? `; ${p.approval.reason}` : ""}`);
  const upstreamCheck = r.checks.find((c) => c.name === "upstream signature (upstream key)" || c.name === "upstream signature (provider secret)");
  const hasUpstream = (p.execution.status === "executed" || p.execution.status === "failed") && !!p.execution.upstream;
  const byProvider = hasUpstream && !!(p.execution.upstream as any).provider;
  const attestedAs = upstreamCheck?.ok ? (byProvider ? "attested (shared secret)" : "attested") : p.execution.provenance;
  const note = !hasUpstream ? "" : upstreamCheck ? (upstreamCheck.ok ? ` (${byProvider ? upstreamCheck.detail : `signed by upstream ${upstreamCheck.detail}`})` : " (upstream signature FAILED)") : byProvider ? " (carries a provider delivery; add the provider secret to check it)" : " (carries an upstream signature; add the upstream key to check it)";
  row("execution", attestedAs, `${p.reconciliation ? "provider read, " : ""}${p.execution.status}${note}`);
  return lines.join("\n");
}
