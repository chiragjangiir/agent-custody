import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { consistencyProof, inclusionProof, leafHash, MerkleLog, rootOf, verifyConsistency, verifyInclusion } from "../src/log.ts";

describe("Merkle log", () => {
  it("proves inclusion of every leaf for every tree size up to 10", () => {
    for (let n = 1; n <= 10; n++) {
      const leaves = Array.from({ length: n }, (_, i) => leafHash(`leaf-${i}`));
      const root = rootOf(leaves);
      for (let i = 0; i < n; i++) {
        expect(verifyInclusion(leaves[i]!, inclusionProof(leaves, i), root), `n=${n} i=${i}`).toBe(true);
      }
    }
  });

  it("rejects a proof for altered leaf content, a wrong index, or a wrong root", () => {
    const leaves = Array.from({ length: 7 }, (_, i) => leafHash(`leaf-${i}`));
    const root = rootOf(leaves);
    const proof = inclusionProof(leaves, 3);
    expect(verifyInclusion(leafHash("leaf-3-edited"), proof, root)).toBe(false);
    expect(verifyInclusion(leaves[3]!, { ...proof, leafIndex: 4 }, root)).toBe(false);
    expect(verifyInclusion(leaves[3]!, proof, rootOf(leaves.slice(0, 6)))).toBe(false);
  });

  it("matches RFC 6962 test vector for the empty tree", () => {
    expect(rootOf([])).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });

  it("persists to JSONL so an auditor can recompute the root at any earlier size", () => {
    const dir = mkdtempSync(join(tmpdir(), "mlog-"));
    const file = join(dir, "log.jsonl");
    const log = new MerkleLog(file);
    const entries = ["a", "b", "c", "d", "e"].map((s) => log.append(JSON.stringify({ s })));
    const reopened = new MerkleLog(file);
    expect(reopened.size).toBe(5);
    for (const e of entries) {
      expect(MerkleLog.rootFromFile(file, e.treeSize)).toBe(e.rootHash);
      expect(verifyInclusion(leafHash(JSON.stringify({ s: "abcde"[e.leafIndex] })), e, e.rootHash)).toBe(true);
    }
  });

  it("detects a rewritten history: an edited log line changes the root", () => {
    const dir = mkdtempSync(join(tmpdir(), "mlog-"));
    const file = join(dir, "log.jsonl");
    const log = new MerkleLog(file);
    log.append("one");
    const second = log.append("two");
    writeFileSync(file, JSON.stringify("one") + "\n" + JSON.stringify("TWO") + "\n");
    expect(MerkleLog.rootFromFile(file, 2)).not.toBe(second.rootHash);
  });

  it("proves that every later tree extends every earlier one, for every pair of sizes up to 12", () => {
    const leaves = Array.from({ length: 12 }, (_, i) => leafHash(`leaf-${i}`));
    for (let n = 0; n <= 12; n++) {
      for (let m = 0; m <= n; m++) {
        const proof = consistencyProof(leaves, m, n);
        expect(verifyConsistency(m, rootOf(leaves, m), n, rootOf(leaves, n), proof), `m=${m} n=${n}`).toBe(true);
      }
    }
  });

  it("a rewritten prefix fails consistency: the whole point of keeping old tree heads", () => {
    const honest = Array.from({ length: 9 }, (_, i) => leafHash(`leaf-${i}`));
    const oldRoot = rootOf(honest, 5);
    const rewritten = honest.map((h, i) => (i === 2 ? leafHash("leaf-2-edited") : h));
    expect(verifyConsistency(5, oldRoot, 9, rootOf(rewritten, 9), consistencyProof(rewritten, 5, 9))).toBe(false);
    // a proof for other sizes, or a truncated proof, is rejected too
    expect(verifyConsistency(5, oldRoot, 9, rootOf(honest, 9), consistencyProof(honest, 4, 9))).toBe(false);
    expect(verifyConsistency(5, oldRoot, 9, rootOf(honest, 9), consistencyProof(honest, 5, 9).slice(1))).toBe(false);
    expect(verifyConsistency(5, oldRoot, 9, rootOf(honest, 9), [])).toBe(false);
  });

  it("an old size of 2^32 + 1 is not a power of two: an honest proof from it verifies", () => {
    // `(n & (n - 1)) === 0` reads only the low 32 bits, so it took 2^32 + 1 for a power of two and refused this proof.
    // With every leaf the same, a subtree's hash depends only on its size: the tree of 2^32 + 1 leaves is
    // node(MTH(2^32), L), and its proof to 2^32 + 2 leaves is [L, L, MTH(2^32)].
    const node = (l: Buffer, r: Buffer) => createHash("sha256").update(Buffer.from([1])).update(l).update(r).digest();
    const L = leafHash("same");
    let top = L;
    for (let i = 0; i < 32; i++) top = node(top, top);
    const [m, n] = [2 ** 32 + 1, 2 ** 32 + 2];
    const oldRoot = node(top, L).toString("hex");
    const newRoot = node(top, node(L, L)).toString("hex");
    const proof = [L, L, top].map((b) => b.toString("hex"));
    expect(verifyConsistency(m, oldRoot, n, newRoot, proof)).toBe(true);
    expect(verifyConsistency(m, oldRoot, n, newRoot, [oldRoot, ...proof])).toBe(false);
  });

  it("a head of size 0, old or new, has only the empty tree's root, as the Python verifier requires", () => {
    const leaves = Array.from({ length: 9 }, (_, i) => leafHash(`leaf-${i}`));
    expect(verifyConsistency(0, rootOf(leaves, 0), 9, rootOf(leaves, 9), [])).toBe(true);
    // a head that claims size 0 with another root was never the log's: before, any root passed here
    expect(verifyConsistency(0, rootOf(leaves, 9), 9, rootOf(leaves, 9), [])).toBe(false);
    expect(verifyConsistency(0, "00".repeat(32), 9, rootOf(leaves, 9), [])).toBe(false);
    // RFC 9162 has no proof from size 0: a hash beside the empty root is refused
    expect(verifyConsistency(0, rootOf(leaves, 0), 9, rootOf(leaves, 9), [leaves[0]!.toString("hex")])).toBe(false);
    // two signed heads of size 0 with the same made-up root would otherwise pass auditExtends as "newer extends older"
    expect(verifyConsistency(0, "ab".repeat(32), 0, "ab".repeat(32), [])).toBe(false);
    expect(verifyConsistency(0, rootOf(leaves, 0), 0, rootOf(leaves, 0), [])).toBe(true);
    // a root is 64 lowercase hex digits, as a signed tree head carries it and the Python verifier requires
    expect(verifyConsistency(0, rootOf(leaves, 0).toUpperCase(), 9, rootOf(leaves, 9), [])).toBe(false);
    expect(verifyConsistency(5, rootOf(leaves, 5), 9, rootOf(leaves, 9).toUpperCase(), consistencyProof(leaves, 5, 9))).toBe(false);
  });

  it("refuses a size or an index that is not an integer: the loops halve with floor, so a fraction walks a real path", () => {
    const leaves = Array.from({ length: 8 }, (_, i) => leafHash(`leaf-${i}`));
    const proof = inclusionProof(leaves, 6, 8);
    expect(verifyInclusion(leaves[6]!, proof, rootOf(leaves, 8))).toBe(true);
    expect(verifyInclusion(leaves[6]!, { ...proof, leafIndex: 6.5 }, rootOf(leaves, 8))).toBe(false);
    expect(verifyInclusion(leaves[6]!, { ...proof, treeSize: 8.5 }, rootOf(leaves, 8))).toBe(false);
    expect(verifyConsistency(1, rootOf(leaves, 1), 2, rootOf(leaves, 2), consistencyProof(leaves, 1, 2))).toBe(true);
    expect(verifyConsistency(1.5, rootOf(leaves, 1), 2, rootOf(leaves, 2), consistencyProof(leaves, 1, 2))).toBe(false);
    expect(verifyConsistency(1, rootOf(leaves, 1), Number.MAX_SAFE_INTEGER + 2, rootOf(leaves, 2), consistencyProof(leaves, 1, 2))).toBe(false);
  });

  it("reads a hash only from a string: a one-element array matches the pattern once stringified, and is refused", () => {
    const leaves = Array.from({ length: 9 }, (_, i) => leafHash(`leaf-${i}`));
    const root = rootOf(leaves, 9);
    const proof = inclusionProof(leaves, 3, 9);
    const wrap = (x: string) => [x] as unknown as string;
    expect(verifyInclusion(leaves[3]!, { ...proof, hashes: [wrap(proof.hashes[0]!), ...proof.hashes.slice(1)] }, root)).toBe(false);
    expect(verifyInclusion(leaves[3]!, proof, wrap(root))).toBe(false);
    const cp = consistencyProof(leaves, 5, 9);
    expect(verifyConsistency(5, rootOf(leaves, 5), 9, root, [wrap(cp[0]!), ...cp.slice(1)])).toBe(false);
    expect(verifyConsistency(5, wrap(rootOf(leaves, 5)), 9, root, cp)).toBe(false);
    expect(verifyConsistency(0, wrap(rootOf(leaves, 0)), 9, root, [])).toBe(false);
  });

  it("reads only 32-byte hashes: a proof hash of another width, or not lowercase hex, is refused before the loop", () => {
    const leaves = Array.from({ length: 9 }, (_, i) => leafHash(`leaf-${i}`));
    const root = rootOf(leaves, 9);
    const proof = inclusionProof(leaves, 3, 9);
    expect(verifyInclusion(leaves[3]!, proof, root)).toBe(true);
    expect(verifyInclusion(leaves[3]!, proof, root.toUpperCase())).toBe(false);
    expect(verifyInclusion(leaves[3]!, { ...proof, hashes: [`${proof.hashes[0]}\n`, ...proof.hashes.slice(1)] }, root)).toBe(false);
    // Buffer.from(hex, "hex") read these before: an uppercase hash as the same bytes, a short one as fewer
    expect(verifyInclusion(leaves[3]!, { ...proof, hashes: proof.hashes.map((x) => x.toUpperCase()) }, root)).toBe(false);
    expect(verifyInclusion(leaves[3]!, { ...proof, hashes: [proof.hashes[0]!.slice(2), ...proof.hashes.slice(1)] }, root)).toBe(false);
    // the reason for the width check: moving the boundary between two children keeps the preimage of a node.
    // sha256(0x01 || n01 || n23) is the root of four leaves; split as 31 bytes || 33 bytes it "proves" a 31-byte leaf
    const n01 = Buffer.from(rootOf(leaves, 2), "hex");
    const n23 = Buffer.from(rootOf(leaves.slice(2, 4), 2), "hex");
    const split = { leafIndex: 0, treeSize: 2, hashes: [Buffer.concat([n01.subarray(31), n23]).toString("hex")] };
    expect(verifyInclusion(n01.subarray(0, 31), split, rootOf(leaves, 4))).toBe(false);
    expect(verifyInclusion(leaves[3]!, proof, root.slice(2))).toBe(false);
    const cp = consistencyProof(leaves, 5, 9);
    expect(verifyConsistency(5, rootOf(leaves, 5), 9, root, [cp[0]! + "00", ...cp.slice(1)])).toBe(false);
    expect(verifyConsistency(5, rootOf(leaves, 5), 9, root, cp.map((x) => x.toUpperCase()))).toBe(false);
  });

  it("the log serves consistency proofs between its own states", () => {
    const dir = mkdtempSync(join(tmpdir(), "mlog-"));
    const log = new MerkleLog(join(dir, "log.jsonl"));
    const heads = ["a", "b", "c", "d", "e", "f"].map((s) => log.append(s));
    expect(verifyConsistency(2, heads[1]!.rootHash, 6, heads[5]!.rootHash, log.consistencyProof(2, 6))).toBe(true);
    expect(verifyConsistency(2, heads[1]!.rootHash, 5, heads[4]!.rootHash, log.consistencyProof(2, 5))).toBe(true);
    expect(() => log.consistencyProof(4, 3)).toThrow(/out of range/);
  });
});

describe("Merkle log shared by several processes", () => {
  it("a second handle on the same file appends after the first handle's leaves, and both stay in step", () => {
    const file = join(mkdtempSync(join(tmpdir(), "mlog-")), "log.jsonl");
    const a = new MerkleLog(file);
    const b = new MerkleLog(file);
    const first = a.append("from a");
    const second = b.append("from b");
    const third = a.append("from a again");
    expect([first.leafIndex, second.leafIndex, third.leafIndex]).toEqual([0, 1, 2]);
    expect(third.rootHash).toBe(MerkleLog.rootFromFile(file, 3));
    expect(verifyInclusion(leafHash("from b"), second, second.rootHash)).toBe(true);
    expect(a.size).toBe(3);
    expect(new MerkleLog(file).root()).toBe(third.rootHash);
  });

  it("leaves no lock file behind, and breaks a lock that a crashed process left", () => {
    const file = join(mkdtempSync(join(tmpdir(), "mlog-")), "log.jsonl");
    const log = new MerkleLog(file);
    log.append("x");
    expect(existsSync(`${file}.lock`)).toBe(false);
    writeFileSync(`${file}.lock`, "99999\n");
    const old = new Date(Date.now() - 120_000);
    utimesSync(`${file}.lock`, old, old);
    expect(log.append("y").leafIndex).toBe(1);
    expect(existsSync(`${file}.lock`)).toBe(false);
  });

  it("follows a file that another process rewrote shorter", () => {
    const file = join(mkdtempSync(join(tmpdir(), "mlog-")), "log.jsonl");
    const log = new MerkleLog(file);
    log.append("a");
    log.append("b");
    writeFileSync(file, `${JSON.stringify("z")}\n`);
    const next = log.append("c");
    expect([next.leafIndex, next.treeSize]).toEqual([1, 2]);
    expect(next.rootHash).toBe(MerkleLog.rootFromFile(file, 2));
  });
});
