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
    const old = new Date(Date.now() - 60_000);
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
