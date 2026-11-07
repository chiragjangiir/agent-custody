// The committed vectors are the conformance suite. This test pins that the reference implementation still produces
// exactly the verdicts the vectors promise, so a change in behaviour shows up as a change in the vectors, on purpose.
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { canonicalize, digestOf, dsseVerify, publicKeyFromPem } from "../src/crypto.ts";
import { leafHash, rootOf, verifyConsistency, verifyInclusion } from "../src/log.ts";
import { auditExtends, verifyBundle } from "../src/verify.ts";

const dir = join(import.meta.dirname, "..", "vectors");
const load = (f: string) => JSON.parse(readFileSync(join(dir, f), "utf8"));
const receipts = load("receipts.json");
const audit = load("audit.json");
const merkle = load("merkle.json");
const canonical = load("canonical.json");
const keyOf = (name: string) => publicKeyFromPem(receipts.keys[name].publicKeyPem);

describe("conformance vectors", () => {
  it("every key's keyid is the sha256 of its SPKI DER", () => {
    for (const [name, k] of Object.entries<any>(receipts.keys)) expect(publicKeyFromPem(k.publicKeyPem).keyid, name).toBe(k.keyid);
  });

  for (const c of receipts.cases as any[]) {
    it(`receipts: ${c.name}`, () => {
      const logFile = c.log ? join(mkdtempSync(join(tmpdir(), "vec-")), "log.jsonl") : undefined;
      if (logFile) writeFileSync(logFile, (c.log as string[]).map((l) => JSON.stringify(l)).join("\n") + "\n");
      const r = verifyBundle(c.bundle, { issuerKeys: c.issuerKeys.map(keyOf), principalKeys: c.principalKeys.map(keyOf), logKeys: c.logKeys.map(keyOf), ...(c.approvalKeys ? { approvalKeys: c.approvalKeys.map(keyOf) } : {}), ...(c.upstreamKeys ? { upstreamKeys: c.upstreamKeys.map(keyOf) } : {}), ...(c.providerSecrets ? { providerSecrets: c.providerSecrets } : {}), ...(c.logId ? { logId: c.logId } : {}), ...(c.requireStrict ? { requireStrict: true } : {}), ...(logFile ? { logFile } : {}) });
      expect({ ok: r.ok, failing: r.checks.filter((x) => !x.ok).map((x) => x.name) }).toEqual(c.expected);
    });
  }

  for (const c of audit.cases as any[]) {
    it(`audit: ${c.name}`, () => {
      const r = auditExtends(c.older, c.newer, c.proof, c.keys.map(keyOf));
      expect({ ok: r.ok, failing: r.checks.filter((x) => !x.ok).map((x) => x.name) }).toEqual(c.expected);
    });
  }

  it("merkle: roots, inclusion proofs, and consistency proofs", () => {
    const hashes = (merkle.leaves as string[]).map(leafHash);
    expect(hashes.map((h) => h.toString("hex"))).toEqual(merkle.leafHashes);
    for (let n = 0; n <= 7; n++) expect(rootOf(hashes, n)).toBe(merkle.roots[n]);
    for (const p of merkle.inclusion) expect(verifyInclusion(p.leafHash ? Buffer.from(p.leafHash, "hex") : hashes[p.leafIndex]!, p, p.root), p.description ?? `${p.leafIndex}`).toBe(p.expected);
    for (const c of merkle.consistency) expect(verifyConsistency(c.oldSize, c.oldRoot, c.newSize, c.newRoot, c.hashes), `${c.oldSize}->${c.newSize}`).toBe(c.expected);
  });

  it("canonical JSON, digests, and the DSSE envelope", () => {
    for (const v of canonical.values) {
      expect(canonicalize(v.value)).toBe(v.canonical);
      expect(digestOf(v.value)).toBe(v.digest);
    }
    expect(publicKeyFromPem(canonical.keyid.publicKeyPem).keyid).toBe(canonical.keyid.keyid);
    const r = dsseVerify(canonical.dsse.envelope, [publicKeyFromPem(canonical.dsse.publicKeyPem)]);
    expect(r.ok).toBe(canonical.dsse.expected);
    expect(Buffer.from(canonical.dsse.envelope.payload, "base64").toString()).toBe(canonical.dsse.payloadJson);
  });
});
