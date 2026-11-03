// Append-only Merkle log with RFC 6962 / RFC 9162 hashing and inclusion proofs.
// Leaves are stored as JSONL so anyone holding the file can recompute the root.
import { createHash } from "node:crypto";
import { appendFileSync, closeSync, mkdirSync, openSync, readSync, statSync, truncateSync } from "node:fs";
import { dirname } from "node:path";
import { withLock } from "./lock.ts";

export interface InclusionProof {
  leafIndex: number;
  treeSize: number;
  hashes: string[]; // hex, leaf-to-root order
}

const h = (...parts: Buffer[]) => {
  const c = createHash("sha256");
  for (const p of parts) c.update(p);
  return c.digest();
};

export function leafHash(data: string): Buffer {
  return h(Buffer.from([0x00]), Buffer.from(data));
}

const nodeHash = (l: Buffer, r: Buffer) => h(Buffer.from([0x01]), l, r);

/** largest power of two strictly less than n (n >= 2) */
function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/**
 * Subtree hashes over a growing list of leaves. A subtree over an aligned, complete, power-of-two range never changes
 * once its leaves exist, so those are cached; everything else is recomputed from at most log(n) cached parts. That
 * makes appends, roots, and proofs O(log n) instead of O(n), which is what keeps a long session's receipts cheap.
 */
export class SubtreeCache {
  private readonly perfect = new Map<string, Buffer>();
  private readonly leaves: Buffer[];
  constructor(leaves: Buffer[]) {
    this.leaves = leaves;
  }
  mth(lo: number, hi: number): Buffer {
    const n = hi - lo;
    if (n === 0) return createHash("sha256").digest();
    if (n === 1) return this.leaves[lo]!;
    const aligned = (n & (n - 1)) === 0 && lo % n === 0;
    const key = aligned ? `${lo}:${hi}` : "";
    if (aligned) {
      const hit = this.perfect.get(key);
      if (hit) return hit;
    }
    const k = split(n);
    const h = nodeHash(this.mth(lo, lo + k), this.mth(lo + k, hi));
    if (aligned) this.perfect.set(key, h);
    return h;
  }
  path(m: number, lo: number, hi: number): Buffer[] {
    const n = hi - lo;
    if (n <= 1) return [];
    const k = split(n);
    return m < k ? [...this.path(m, lo, lo + k), this.mth(lo + k, hi)] : [...this.path(m - k, lo + k, hi), this.mth(lo, lo + k)];
  }
  subproof(m: number, lo: number, hi: number, b: boolean): Buffer[] {
    const n = hi - lo;
    if (m === n) return b ? [] : [this.mth(lo, hi)];
    const k = split(n);
    return m <= k ? [...this.subproof(m, lo, lo + k, b), this.mth(lo + k, hi)] : [...this.subproof(m - k, lo + k, hi, false), this.mth(lo, lo + k)];
  }
}

const mth = (leaves: Buffer[], lo: number, hi: number): Buffer => new SubtreeCache(leaves).mth(lo, hi);
const path = (m: number, leaves: Buffer[], lo: number, hi: number): Buffer[] => new SubtreeCache(leaves).path(m, lo, hi);

/** RFC 9162 section 2.1.4.1: SUBPROOF(m, D[n], b). */
const subproof = (m: number, leaves: Buffer[], lo: number, hi: number, b: boolean): Buffer[] => new SubtreeCache(leaves).subproof(m, lo, hi, b);

/** Proof that the tree of size newSize extends the tree of size oldSize. Empty when oldSize is 0 or equal to newSize. */
export function consistencyProof(leafHashes: Buffer[], oldSize: number, newSize = leafHashes.length): string[] {
  if (oldSize < 0 || oldSize > newSize || newSize > leafHashes.length) throw new Error("sizes out of range");
  if (oldSize === 0 || oldSize === newSize) return [];
  return subproof(oldSize, leafHashes, 0, newSize, true).map((b) => b.toString("hex"));
}

/** RFC 9162 section 2.1.4.2. Pure: needs only the two sizes, the two roots, and the proof. */
export function verifyConsistency(oldSize: number, oldRootHex: string, newSize: number, newRootHex: string, proofHex: string[]): boolean {
  if (oldSize < 0 || oldSize > newSize) return false;
  if (oldSize === newSize) return proofHex.length === 0 && oldRootHex === newRootHex;
  if (oldSize === 0) return proofHex.length === 0;
  if (proofHex.length === 0) return false;
  const proof = proofHex.map((x) => Buffer.from(x, "hex"));
  if ((oldSize & (oldSize - 1)) === 0) proof.unshift(Buffer.from(oldRootHex, "hex"));
  let fn = oldSize - 1;
  let sn = newSize - 1;
  while (fn % 2 === 1) {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  let fr = proof[0]!;
  let sr = proof[0]!;
  for (const c of proof.slice(1)) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      sr = nodeHash(sr, c);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && fr.toString("hex") === oldRootHex && sr.toString("hex") === newRootHex;
}

export function rootOf(leafHashes: Buffer[], size = leafHashes.length): string {
  return mth(leafHashes, 0, size).toString("hex");
}

export function inclusionProof(leafHashes: Buffer[], leafIndex: number, treeSize = leafHashes.length): InclusionProof {
  if (leafIndex < 0 || leafIndex >= treeSize || treeSize > leafHashes.length) throw new Error("index out of range");
  return { leafIndex, treeSize, hashes: path(leafIndex, leafHashes, 0, treeSize).map((b) => b.toString("hex")) };
}

/** RFC 9162 section 2.1.3.2 verification. Pure function: needs only the leaf hash, proof and claimed root. */
export function verifyInclusion(leaf: Buffer, proof: InclusionProof, rootHex: string): boolean {
  let fn = proof.leafIndex;
  let sn = proof.treeSize - 1;
  if (fn < 0 || sn < 0 || fn > sn) return false;
  let r = leaf;
  for (const hex of proof.hashes) {
    if (sn === 0) return false;
    const p = Buffer.from(hex, "hex");
    if (fn % 2 === 1 || fn === sn) {
      r = nodeHash(p, r);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      r = nodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && r.toString("hex") === rootHex;
}

const LOCK_STALE_MS = 60_000;
const LOG_LOCK_WAIT_MS = 20_000;

/** Each hook of a coding agent is its own process, so appends overlap: one writer at a time holds `<file>.lock`. */
export function logLocked<T>(file: string, fn: () => T): T {
  return withLock(`${file}.lock`, { staleMs: LOCK_STALE_MS, waitMs: LOG_LOCK_WAIT_MS }, fn);
}

export class MerkleLog {
  private readonly hashes: Buffer[] = [];
  private tree = new SubtreeCache(this.hashes);
  private readonly file: string;
  private bytes = 0;
  private inode: number | bigint = -1;

  constructor(file: string) {
    this.file = file;
    mkdirSync(dirname(file), { recursive: true });
    this.catchUp();
  }

  /**
   * Reads the leaves that another handle or process appended since the last read. A file that was replaced or cut
   * short is read again from the start. Bytes after the last newline are not read: a writer may be in the middle of its
   * write, or may have died in it.
   */
  private catchUp(): void {
    let st;
    try { st = statSync(this.file); } catch { st = null; }
    if (!st || st.ino !== this.inode || st.size < this.bytes) {
      this.hashes.length = 0;
      this.tree = new SubtreeCache(this.hashes);
      this.bytes = 0;
    }
    if (!st) return;
    this.inode = st.ino;
    if (st.size === this.bytes) return;
    const buf = Buffer.alloc(st.size - this.bytes);
    const fd = openSync(this.file, "r");
    let got = 0;
    try {
      while (got < buf.length) {
        const n = readSync(fd, buf, got, buf.length - got, this.bytes + got);
        if (n === 0) break;
        got += n;
      }
    } finally {
      closeSync(fd);
    }
    got = buf.subarray(0, got).lastIndexOf(0x0a) + 1;
    this.bytes += got;
    for (const line of buf.subarray(0, got).toString("utf8").split("\n")) {
      if (!line.trim()) continue;
      const parsed = JSON.parse(line) as string | { pruned?: string; hash?: string };
      // A pruned leaf keeps only its hash, and a leaf appended by hash never had content here: the tree, its
      // roots, and every proof are the same either way.
      this.hashes.push(typeof parsed === "string" ? leafHash(parsed) : Buffer.from((parsed.pruned ?? parsed.hash)!, "hex"));
    }
  }

  /**
   * Under the lock: a last line with no newline is the remains of a writer that died in the middle of its write. No
   * leaf was acknowledged for it. The bytes go to `<file>.torn`, so no data is lost, and the file ends after the last whole line.
   */
  private cutTornTail(): void {
    let size: number;
    try { size = statSync(this.file).size; } catch { return; }
    if (size <= this.bytes) return;
    const tail = Buffer.alloc(size - this.bytes);
    const fd = openSync(this.file, "r");
    try {
      readSync(fd, tail, 0, tail.length, this.bytes);
    } finally {
      closeSync(fd);
    }
    appendFileSync(`${this.file}.torn`, tail, { mode: 0o600 });
    truncateSync(this.file, this.bytes);
  }

  /** Under the lock: reads what other writers appended, then writes this line, so each leaf gets the next index. */
  private appendLine(line: string, hash: () => Buffer): InclusionProof & { rootHash: string } {
    return logLocked(this.file, () => {
      this.catchUp();
      this.cutTornTail();
      appendFileSync(this.file, line);
      this.bytes += Buffer.byteLength(line);
      return this.pushHash(hash());
    });
  }

  get size(): number {
    return this.hashes.length;
  }

  /** Leaf hashes `from` (inclusive) to `to` (exclusive), as hex: what an export carries and what a copy is rebuilt from. */
  leafHashes(from: number, to: number = this.hashes.length): string[] {
    return this.hashes.slice(Math.max(0, from), Math.min(to, this.hashes.length)).map((h) => h.toString("hex"));
  }

  /** Appends a leaf (an opaque string, typically a canonical JSON envelope). Returns its proof against the new root. */
  append(leaf: string): InclusionProof & { rootHash: string } {
    return this.appendLine(JSON.stringify(leaf) + "\n", () => leafHash(leaf));
  }

  /**
   * Appends a leaf by its RFC 6962 leaf hash, sha256(0x00 || leaf), as hex. The log commits to the leaf without ever
   * holding it, which is what a log run for someone else should do: the receipt stays with its issuer.
   */
  appendHash(leafHashHex: string): InclusionProof & { rootHash: string } {
    if (!/^[0-9a-f]{64}$/.test(leafHashHex)) throw new Error("leafHash must be 64 lowercase hex characters");
    return this.appendLine(JSON.stringify({ hash: leafHashHex }) + "\n", () => Buffer.from(leafHashHex, "hex"));
  }

  private pushHash(hash: Buffer): InclusionProof & { rootHash: string } {
    this.hashes.push(hash);
    const treeSize = this.hashes.length;
    return { leafIndex: treeSize - 1, treeSize, hashes: this.tree.path(treeSize - 1, 0, treeSize).map((b) => b.toString("hex")), rootHash: this.tree.mth(0, treeSize).toString("hex") };
  }

  root(size = this.size): string {
    if (size < 0 || size > this.size) throw new Error("size out of range");
    return this.tree.mth(0, size).toString("hex");
  }

  /** Proof that this log at newSize extends its own earlier state at oldSize. */
  consistencyProof(oldSize: number, newSize = this.size): string[] {
    if (oldSize < 0 || oldSize > newSize || newSize > this.size) throw new Error("sizes out of range");
    if (oldSize === 0 || oldSize === newSize) return [];
    return this.tree.subproof(oldSize, 0, newSize, true).map((b) => b.toString("hex"));
  }

  /** Reads a log file and returns the root at the given size, for auditors holding a copy of the log. */
  static rootFromFile(file: string, size: number): string {
    return new MerkleLog(file).root(size);
  }
}
