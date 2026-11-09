// What one receipt costs on the issuer's hot path, step by step, on one machine. No network, no fsync.
// Run from packages/receipts: bun run bench   (or: node scripts/hot-path-bench.ts [iterations])
// Not part of `ci`: the numbers depend on the machine, and the docs quote them with the machine named.
import { appendFileSync, closeSync, mkdtempSync, openSync, rmSync, writeSync } from "node:fs";
import { cpus, tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalize, dsseSign, generateKeyPair } from "../src/crypto.ts";
import { leafHash, MerkleLog, SubtreeCache } from "../src/log.ts";
import { processStamp } from "../src/operations.ts";
import { evaluate, policyDigest } from "../src/policy.ts";
import { compileRego, evaluateRego } from "../src/policy-rego.ts";
import { RECEIPT_TYPE, TREEHEAD_TYPE } from "../src/receipt.ts";
import { POLICY } from "./fixture.ts";

const N = Number(process.argv[2] ?? 20_000);
const WARM = Math.min(2_000, N);
const dir = mkdtempSync(join(tmpdir(), "hot-path-"));
const key = generateKeyPair();
const log = new MerkleLog(join(dir, "log.jsonl"));
const merkle: Buffer[] = [];
const tree = new SubtreeCache(merkle);
const rawFile = join(dir, "raw.jsonl");
const rawFd = openSync(join(dir, "raw-fd.jsonl"), "a");

// The fixture's Cedar policy in Rego, compiled once with the opa binary as a gateway does when the file loads or changes.
const REGO = `package agentcustody

allow if input.action == "customer.lookup"

allow if {
  input.action == "stripe.refund"
  input.context.args.amount <= 100000
  input.context.facts.customer.verified == true
}
`;
const compiled = compileRego(REGO);
const rego = compiled.policy ? { policy: compiled.policy, digest: policyDigest(REGO) } : undefined;

const steps = ["cedar evaluate", "receipt signature", "log append (all)", "  of which Merkle", "tree-head signature"] as const;
// The append takes the log lock, whose owner record carries this process's start time: /proc on Linux, `ps` elsewhere.
const refs = ["rego evaluate (alternative)", "appendFileSync (reference)", "write on open fd (reference)", "lock owner stamp (reference)"] as const;
const samples = new Map<string, number[]>([...steps, ...refs].map((s) => [s, []]));
const ns = (t: bigint) => Number(process.hrtime.bigint() - t);

// Requests vary by amount, verification, and tool, so a decision cache could not answer them all from one entry.
const request = (i: number) => ({
  agentId: "support-agent",
  tool: i % 5 === 0 ? "customer.lookup" : "stripe.refund",
  context: { args: { customer_id: `cust_${i % 997}`, amount: (i * 7919) % 150_000 }, facts: { customer: { id: `cust_${i % 997}`, verified: i % 3 !== 0 } }, grant: { principal: "user_456", scopes: ["customer.lookup", "stripe.refund"] } },
});

function once(i: number, record: boolean): void {
  const put = (name: string, t: bigint) => { const d = ns(t); if (record) samples.get(name)!.push(d); };
  const req = request(i);
  let t = process.hrtime.bigint();
  const decision = evaluate(POLICY, req);
  put("cedar evaluate", t);
  if (rego) {
    t = process.hrtime.bigint();
    const other = evaluateRego(rego.policy, rego.digest, req);
    put("rego evaluate (alternative)", t);
    if (other.decision !== decision.decision) throw new Error(`cedar and rego disagree on request ${i}: ${decision.decision} and ${other.decision}`);
  }

  const statement = { _type: "https://in-toto.io/Statement/v1", subject: [{ name: `tool-call:${req.tool}:r${i}`, digest: { sha256: "0".repeat(64) } }], predicateType: "https://agent-custody.dev/receipt/v0.1", predicate: { receiptId: `r${i}`, timestamp: new Date().toISOString(), tool: { name: req.tool }, request: { args: req.context.args }, policy: decision } };
  t = process.hrtime.bigint();
  const envelope = dsseSign(RECEIPT_TYPE, statement, key);
  put("receipt signature", t);

  const leaf = canonicalize(envelope);
  t = process.hrtime.bigint();
  const entry = log.append(leaf);
  put("log append (all)", t);

  // The same push, proof, and root that MerkleLog.append does after its write, on an in-memory copy of the tree.
  t = process.hrtime.bigint();
  merkle.push(leafHash(leaf));
  const size = merkle.length;
  tree.path(size - 1, 0, size);
  tree.mth(0, size);
  put("  of which Merkle", t);

  t = process.hrtime.bigint();
  dsseSign(TREEHEAD_TYPE, { treeSize: entry.treeSize, rootHash: entry.rootHash, timestamp: new Date().toISOString() }, key);
  put("tree-head signature", t);

  const line = JSON.stringify(leaf) + "\n";
  t = process.hrtime.bigint();
  appendFileSync(rawFile, line);
  put("appendFileSync (reference)", t);
  t = process.hrtime.bigint();
  writeSync(rawFd, line);
  put("write on open fd (reference)", t);
  t = process.hrtime.bigint();
  processStamp(process.pid);
  put("lock owner stamp (reference)", t);
}

for (let i = 0; i < WARM; i++) once(i, false);
for (let i = 0; i < N; i++) once(WARM + i, true);
closeSync(rawFd);
rmSync(dir, { recursive: true, force: true });

const us = (x: number) => (x / 1000).toFixed(1).padStart(7);
const stats = (xs: number[]) => {
  const s = [...xs].sort((a, b) => a - b);
  return { mean: s.reduce((a, b) => a + b, 0) / s.length, p50: s[Math.floor(s.length * 0.5)]!, p99: s[Math.floor(s.length * 0.99)]! };
};
console.log(`node ${process.version}, ${process.platform}/${process.arch}, ${cpus()[0]?.model ?? "unknown cpu"}, ${N} receipts after ${WARM} warm-up`);
console.log(`${"step (µs per receipt)".padEnd(30)}   mean     p50     p99`);
let total = 0;
for (const name of [...steps, ...refs]) {
  if (samples.get(name)!.length === 0) {
    console.log(`${name.padEnd(30)} skipped: ${compiled.errors.join("; ")}`);
    continue;
  }
  const s = stats(samples.get(name)!);
  if (name === "cedar evaluate" || name === "receipt signature" || name === "log append (all)" || name === "tree-head signature") total += s.mean;
  console.log(`${name.padEnd(30)} ${us(s.mean)} ${us(s.p50)} ${us(s.p99)}`);
}
console.log(`${"total of the four steps".padEnd(30)} ${us(total)}`);
