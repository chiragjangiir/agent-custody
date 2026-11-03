// The witness: a second signer, run by someone who is not the log's operator, that watches a log's published
// checkpoints and countersigns each one only after proving to itself that it extends the last one it signed. A
// verifier who requires the witness's signature on a head is protected against the log showing different histories
// to different people, and against the log's operator rewriting history, because the witness kept the earlier
// head and refuses, loudly, when the new one does not extend it. It is the phase of the hosted log that makes the
// log hold against us. It publishes what it signs as files, to be served from a host of its own.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { dsseCountersign, dsseVerify, publicKeyFromPem, type Envelope, type KeyPair, type PublicKeyRef } from "./crypto.ts";
import { verifyConsistency } from "./log.ts";
import { TREEHEAD_TYPE, type TreeHead } from "./receipt.ts";
import type { KeyDocument } from "./signer.ts";

export interface WitnessOptions {
  /** the log's API base, e.g. https://log.example.com/; the key document and consistency proofs come from here */
  logUrl: string;
  /** where the log publishes checkpoints, e.g. https://checkpoints.example.com/ */
  checkpointsUrl: string;
  /** which logs to watch: "default" for the root paths, else tenant names */
  tenants: string[];
  key: KeyPair;
  /** where countersigned checkpoints, alarms, the witness's own key document, and its state go */
  outDir: string;
  fetch?: typeof fetch;
  warn?: (message: string) => void;
}

export interface WitnessedCheckpoint {
  tenant: string;
  logId: string | undefined;
  treeSize: number;
  rootHash: string;
  /** the log's checkpoint envelope with the witness's signature added */
  envelope: Envelope;
  witness: { keyid: string; at: string };
}

export type WitnessOutcome =
  | { tenant: string; outcome: "countersigned"; treeSize: number }
  | { tenant: string; outcome: "unchanged"; treeSize: number }
  | { tenant: string; outcome: "refused"; reason: string }
  | { tenant: string; outcome: "unavailable"; reason: string };

interface State {
  treeSize: number;
  rootHash: string;
  logId: string | undefined;
}

const safe = (s: string) => s.replace(/[^A-Za-z0-9_.-]/g, "_");

export class Witness {
  private readonly o: WitnessOptions;
  private readonly f: typeof fetch;
  private readonly warn: (m: string) => void;
  private timer: ReturnType<typeof setInterval> | null = null;
  constructor(opts: WitnessOptions) {
    this.o = opts;
    this.f = opts.fetch ?? fetch;
    this.warn = opts.warn ?? ((m) => console.error(m));
    mkdirSync(join(opts.outDir, ".well-known"), { recursive: true });
    // The witness's own key document, for verifiers to pin the way they pin the log's.
    const doc: KeyDocument = { keys: [{ keyid: opts.key.keyid, alg: "ed25519", publicKeyPem: opts.key.publicKey.export({ type: "spki", format: "pem" }) as string, validFrom: new Date().toISOString() }] };
    writeFileSync(join(opts.outDir, ".well-known", "agent-custody-witness.json"), JSON.stringify(doc, null, 2));
  }

  get keyid(): string {
    return this.o.key.keyid;
  }

  private folder(tenant: string): string {
    const d = join(this.o.outDir, safe(tenant));
    mkdirSync(d, { recursive: true });
    return d;
  }

  private state(tenant: string): State | null {
    try {
      return JSON.parse(readFileSync(join(this.folder(tenant), "state.json"), "utf8")) as State;
    } catch {
      return null;
    }
  }

  private async logKeys(): Promise<PublicKeyRef[]> {
    const res = await this.f(new URL("/.well-known/agent-custody-log.json", this.o.logUrl), { signal: AbortSignal.timeout(10_000) });
    if (!res.ok) throw new Error(`log key document: ${res.status}`);
    const doc = (await res.json()) as KeyDocument;
    return doc.keys.map((k) => publicKeyFromPem(k.publicKeyPem));
  }

  private async latest(tenant: string): Promise<{ envelope: Envelope } | null> {
    const base = this.o.checkpointsUrl.endsWith("/") ? this.o.checkpointsUrl : `${this.o.checkpointsUrl}/`;
    const res = await this.f(new URL(`${safe(tenant)}/latest.json`, base), { signal: AbortSignal.timeout(10_000) });
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`checkpoint for ${tenant}: ${res.status}`);
    return (await res.json()) as { envelope: Envelope };
  }

  private async proof(tenant: string, oldSize: number, newSize: number): Promise<string[]> {
    const base = this.o.logUrl.endsWith("/") ? this.o.logUrl : `${this.o.logUrl}/`;
    const path = tenant === "default" ? `consistency?old=${oldSize}&new=${newSize}` : `t/${tenant}/consistency?old=${oldSize}&new=${newSize}`;
    const res = await this.f(new URL(path, base), { signal: AbortSignal.timeout(10_000) });
    if (!res.ok) throw new Error(`consistency proof for ${tenant}: ${res.status}`);
    return ((await res.json()) as { hashes: string[] }).hashes;
  }

  /** One pass over every watched log. Never throws; every outcome is returned and the bad ones are also on disk. */
  async runOnce(): Promise<WitnessOutcome[]> {
    const out: WitnessOutcome[] = [];
    let keys: PublicKeyRef[];
    try {
      keys = await this.logKeys();
    } catch (e) {
      const reason = e instanceof Error ? e.message : String(e);
      this.warn(`agent-custody witness: ${reason}`);
      return this.o.tenants.map((tenant) => ({ tenant, outcome: "unavailable", reason }));
    }
    for (const tenant of this.o.tenants) {
      try {
        out.push(await this.witnessOne(tenant, keys));
      } catch (e) {
        const reason = e instanceof Error ? e.message : String(e);
        this.warn(`agent-custody witness: ${tenant}: ${reason}`);
        out.push({ tenant, outcome: "unavailable", reason });
      }
    }
    return out;
  }

  private async witnessOne(tenant: string, keys: PublicKeyRef[]): Promise<WitnessOutcome> {
    const cp = await this.latest(tenant);
    if (!cp) return { tenant, outcome: "unavailable", reason: "no checkpoint published yet" };
    const v = dsseVerify(cp.envelope, keys);
    if (!v.ok || cp.envelope.payloadType !== TREEHEAD_TYPE) return this.refuse(tenant, `checkpoint does not verify against the log's published keys: ${v.ok ? "not a tree head" : v.error}`, cp.envelope);
    const head = v.payload as TreeHead;
    const prev = this.state(tenant);
    if (prev) {
      if (prev.logId !== head.log) return this.refuse(tenant, `checkpoint names log ${head.log ?? "none"}, the last one signed named ${prev.logId ?? "none"}`, cp.envelope);
      if (head.treeSize < prev.treeSize) return this.refuse(tenant, `checkpoint at size ${head.treeSize} is smaller than the last one signed at ${prev.treeSize}`, cp.envelope);
      if (head.treeSize === prev.treeSize) {
        if (head.rootHash !== prev.rootHash) return this.refuse(tenant, `a different root at the same size ${head.treeSize}: the log shows two histories`, cp.envelope);
        return { tenant, outcome: "unchanged", treeSize: head.treeSize };
      }
      const proof = await this.proof(tenant, prev.treeSize, head.treeSize);
      if (!verifyConsistency(prev.treeSize, prev.rootHash, head.treeSize, head.rootHash, proof)) return this.refuse(tenant, `the log at ${head.treeSize} does not extend the head signed at ${prev.treeSize}: history was rewritten`, cp.envelope);
    }
    const envelope = dsseCountersign(cp.envelope, this.o.key);
    const at = new Date().toISOString();
    const record: WitnessedCheckpoint = { tenant, logId: head.log, treeSize: head.treeSize, rootHash: head.rootHash, envelope, witness: { keyid: this.o.key.keyid, at } };
    const dir = this.folder(tenant);
    const text = JSON.stringify(record, null, 2);
    writeFileSync(join(dir, `${head.treeSize}.json`), text);
    writeFileSync(join(dir, "latest.json"), text);
    writeFileSync(join(dir, "state.json"), JSON.stringify({ treeSize: head.treeSize, rootHash: head.rootHash, logId: head.log } satisfies State));
    return { tenant, outcome: "countersigned", treeSize: head.treeSize };
  }

  /** A refusal is written where the countersignatures would have gone, so whoever reads the witness's host sees it. */
  private refuse(tenant: string, reason: string, envelope: Envelope): WitnessOutcome {
    const dir = this.folder(tenant);
    const at = new Date().toISOString();
    // one file per alarm, never overwritten: two refusals in the same millisecond get distinct names
    const stamp = at.replace(/[:.]/g, "-");
    let file = join(dir, `ALARM-${stamp}.json`);
    for (let n = 2; existsSync(file); n++) file = join(dir, `ALARM-${stamp}-${n}.json`);
    writeFileSync(file, JSON.stringify({ tenant, at, reason, checkpoint: envelope }, null, 2));
    writeFileSync(join(dir, "ALARM.json"), JSON.stringify({ tenant, at, reason }, null, 2));
    this.warn(`agent-custody witness: REFUSED ${tenant}: ${reason}`);
    return { tenant, outcome: "refused", reason };
  }

  start(everyMs = 300_000): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.runOnce(), everyMs);
    this.timer.unref?.();
    void this.runOnce();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }
}

/** For verifiers: the witness's published keys, fetched from its host and pinned by keyid. */
export async function fetchWitnessKeys(witnessUrl: string, f: typeof fetch = fetch): Promise<PublicKeyRef[]> {
  const res = await f(new URL("/.well-known/agent-custody-witness.json", witnessUrl), { signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new Error(`witness ${witnessUrl} serves no key document: ${res.status}`);
  const doc = (await res.json()) as KeyDocument;
  if (!Array.isArray(doc.keys) || doc.keys.length === 0) throw new Error(`witness ${witnessUrl} lists no keys`);
  return doc.keys.map((k) => publicKeyFromPem(k.publicKeyPem));
}
