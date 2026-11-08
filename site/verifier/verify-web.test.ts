// The browser verifier must agree with the reference on every published vector. This is the conformance suite in use.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { auditExtends, canonicalize, digestOf, dsseVerify, formatReport, publicKeyFromPem, verifyBundle, verifyConsistency, verifyInclusion } from "./verify-web.ts";

const dir = join(import.meta.dirname, "..", "..", "packages", "receipts", "vectors");
const load = (f: string) => JSON.parse(readFileSync(join(dir, f), "utf8"));
const receipts = load("receipts.json");
const audit = load("audit.json");
const merkle = load("merkle.json");
const canonical = load("canonical.json");
const keyOf = (name: string) => publicKeyFromPem(receipts.keys[name].publicKeyPem);
const all = (names: string[]) => Promise.all(names.map(keyOf));

describe("browser verifier against the conformance vectors", () => {
  it("keyids", async () => {
    for (const [name, k] of Object.entries<any>(receipts.keys)) expect((await publicKeyFromPem(k.publicKeyPem)).keyid, name).toBe(k.keyid);
  });
  for (const c of receipts.cases as any[]) {
    it(`receipts: ${c.name}`, async () => {
      const r = await verifyBundle(c.bundle, { issuerKeys: await all(c.issuerKeys), principalKeys: await all(c.principalKeys), logKeys: await all(c.logKeys), ...(c.approvalKeys ? { approvalKeys: await all(c.approvalKeys) } : {}), ...(c.upstreamKeys ? { upstreamKeys: await all(c.upstreamKeys) } : {}), ...(c.providerSecrets ? { providerSecrets: c.providerSecrets } : {}), ...(c.logId ? { logId: c.logId } : {}), ...(c.requireStrict ? { requireStrict: true } : {}), ...(c.log ? { logLeaves: c.log } : {}) });
      expect({ ok: r.ok, failing: r.checks.filter((x) => !x.ok).map((x) => x.name) }).toEqual(c.expected);
    });
  }
  for (const c of audit.cases as any[]) {
    it(`audit: ${c.name}`, async () => {
      const r = await auditExtends(c.older, c.newer, c.proof, await all(c.keys));
      expect({ ok: r.ok, failing: r.checks.filter((x) => !x.ok).map((x) => x.name) }).toEqual(c.expected);
    });
  }
  it("merkle consistency", async () => {
    for (const c of merkle.consistency) expect(await verifyConsistency(c.oldSize, c.oldRoot, c.newSize, c.newRoot, c.hashes), `${c.oldSize}->${c.newSize}`).toBe(c.expected);
  });
  it("merkle inclusion", async () => {
    const h = (x: string) => Uint8Array.from(Buffer.from(x, "hex"));
    for (const p of merkle.inclusion) expect(await verifyInclusion(h(p.leafHash ?? merkle.leafHashes[p.leafIndex]), p, p.root), p.description ?? `${p.leafIndex}`).toBe(p.expected);
  });
  it("merkle inclusion reads only 32-byte hashes from strings, as the reference does", async () => {
    const h = (x: string) => Uint8Array.from(Buffer.from(x, "hex"));
    const leaf = h(merkle.leafHashes[0]);
    const proof = merkle.inclusion[0];
    expect(await verifyInclusion(leaf, proof, proof.root)).toBe(true);
    expect(await verifyInclusion(leaf, { ...proof, hashes: proof.hashes.map((x: string) => x.toUpperCase()) }, proof.root)).toBe(false);
    // sha256(0x01 || n01 || n23), the root of four leaves, split as 31 bytes || 33 bytes "proves" a 31-byte leaf
    const n01 = merkle.roots[2] as string;
    const n23 = merkle.inclusion[0].hashes[1] as string;
    const split = { leafIndex: 0, treeSize: 2, hashes: [n01.slice(62) + n23] };
    expect(await verifyInclusion(h(n01).subarray(0, 31), split, merkle.roots[4])).toBe(false);
    // a one-element array matches the pattern once stringified; it is not a hash
    const wrap = (x: string) => [x] as unknown as string;
    expect(await verifyInclusion(leaf, { ...proof, hashes: [wrap(proof.hashes[0]), ...proof.hashes.slice(1)] }, proof.root)).toBe(false);
    expect(await verifyInclusion(leaf, proof, wrap(proof.root))).toBe(false);
    expect(await verifyConsistency(0, wrap(merkle.roots[0]), 7, merkle.roots[7], [])).toBe(false);
  });
  it("an old size of 2^32 + 1 is not a power of two: an honest proof from it verifies", async () => {
    // the same case as log.test.ts: with every leaf the same, the tree of 2^32 + 1 leaves is node(MTH(2^32), L)
    const node = (l: Buffer, r: Buffer) => createHash("sha256").update(Buffer.from([1])).update(l).update(r).digest();
    const L = createHash("sha256").update(Buffer.from([0])).update("same").digest();
    let top = L;
    for (let i = 0; i < 32; i++) top = node(top, top);
    const oldRoot = node(top, L).toString("hex");
    const newRoot = node(top, node(L, L)).toString("hex");
    const proof = [L, L, top].map((b) => b.toString("hex"));
    expect(await verifyConsistency(2 ** 32 + 1, oldRoot, 2 ** 32 + 2, newRoot, proof)).toBe(true);
    expect(await verifyConsistency(2 ** 32 + 1, oldRoot, 2 ** 32 + 2, newRoot, [oldRoot, ...proof])).toBe(false);
  });
  it("canonical JSON, digests, DSSE", async () => {
    for (const v of canonical.values) { expect(canonicalize(v.value)).toBe(v.canonical); expect(await digestOf(v.value)).toBe(v.digest); }
    expect((await publicKeyFromPem(canonical.keyid.publicKeyPem)).keyid).toBe(canonical.keyid.keyid);
    expect((await dsseVerify(canonical.dsse.envelope, [await publicKeyFromPem(canonical.dsse.publicKeyPem)])).ok).toBe(canonical.dsse.expected);
  });
  it("reports a reconciliation receipt as a provider read", async () => {
    const c = receipts.cases.find((x: any) => x.expected.ok && x.bundle.envelope);
    const r = await verifyBundle(c.bundle, { issuerKeys: await all(c.issuerKeys), principalKeys: await all(c.principalKeys), logKeys: await all(c.logKeys) });
    expect(formatReport(r)).toMatch(/policy\s+\S+\s+(allow|deny)/);
    const predicate = { ...r.statement!.predicate, reconciliation: {} };
    const text = formatReport({ ...r, statement: { ...r.statement!, predicate } as any });
    expect(text).toMatch(/policy\s+-\s+\(none evaluated: a provider read, not a call\)/);
    expect(text).toMatch(/execution\s+\S+\s+provider read, executed/);
  });
});
