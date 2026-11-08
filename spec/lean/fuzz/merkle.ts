// Differential fuzzing of the Merkle checks. Generates random trees, their honest inclusion and consistency proofs, and
// changes to each, then asks four verifiers for a verdict on every case: the Lean model (`lake exe oracle`),
// `packages/receipts/src/log.ts`, `packages/state/src/verify-web.ts`, and the Python `agent_custody.verify` (`merkle.py`).
// It fails when any two disagree, or when any refuses an honest proof.
//
//   bun fuzz/merkle.ts [--seed <n> | --seed random] [--trees <n>]      (from spec/lean)
import { spawnSync } from "node:child_process";
import { createHash, randomInt } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as ts from "../../../packages/receipts/src/log.ts";
import * as web from "../../../packages/state/src/verify-web.ts";

interface Inclusion { kind: "inclusion"; leaf: string; leafIndex: number; treeSize: number; root: string; hashes: string[] }
interface Consistency { kind: "consistency"; oldSize: number; newSize: number; oldRoot: string; newRoot: string; hashes: string[] }
type Case = (Inclusion | Consistency) & { what: string; honest: boolean };

const here = dirname(fileURLToPath(import.meta.url));
const leanDir = join(here, "..");
const pyDir = join(here, "../../../packages/python");

const arg = (name: string) => {
  const i = process.argv.indexOf(name);
  return i < 0 ? undefined : process.argv[i + 1];
};
const seedArg = arg("--seed") ?? "20261108";
const seed = seedArg === "random" ? randomInt(2 ** 32) : Number(seedArg);
const trees = Number(arg("--trees") ?? 200);
if (!Number.isSafeInteger(seed) || !Number.isSafeInteger(trees)) throw new Error("usage: merkle.ts [--seed <n> | --seed random] [--trees <n>]");
console.log(`seed ${seed} (replay with: bun fuzz/merkle.ts --seed ${seed} --trees ${trees})`);

// mulberry32: small, seeded, and the same on every machine
let state = seed >>> 0;
const rand = () => {
  state = (state + 0x6d2b79f5) | 0;
  let t = Math.imul(state ^ (state >>> 15), 1 | state);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 2 ** 32;
};
/** an integer in [0, n), for any n up to 2^53 */
const below = (n: number) => (Math.floor(rand() * 2 ** 21) * 2 ** 32 + Math.floor(rand() * 2 ** 32)) % n;
const bytes = (k: number) => Buffer.from(Array.from({ length: k }, () => below(256)));
const randomHash = () => bytes(32).toString("hex");
const replace = <T>(xs: T[], i: number, x: T) => xs.map((y, j) => (j === i ? x : y));

const sha = (...parts: Buffer[]) => parts.reduce((c, p) => c.update(p), createHash("sha256")).digest();
const node = (l: Buffer, r: Buffer) => sha(Buffer.from([1]), l, r);
const EMPTY = sha();

/** largest power of two strictly less than n (n >= 2), as `split` in log.ts */
const split = (n: number) => {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
};

/** A tree: its leaves, the root of each prefix, and the proofs the log hands out. */
interface Tree { label: string; size: number; leaf(i: number): Buffer; root(n: number): string; path(i: number, n: number): string[]; proof(m: number, n: number): string[] }

/** Random leaves; the honest proofs come from log.ts, as the log serves them. */
function randomTree(size: number): Tree {
  const leaves = Array.from({ length: size }, () => bytes(32));
  return {
    label: `random tree of ${size}`,
    size,
    leaf: (i) => leaves[i]!,
    root: (n) => ts.rootOf(leaves, n),
    path: (i, n) => ts.inclusionProof(leaves, i, n).hashes,
    proof: (m, n) => ts.consistencyProof(leaves, m, n),
  };
}

/**
 * Every leaf the same, so a subtree's hash depends only on its size: roots and proofs of trees of 2^53 - 1 leaves cost
 * a few hundred hashes. The functions are MTH, PATH and SUBPROOF of RFC 9162 on sizes alone.
 */
function sameLeafTree(size: number): Tree {
  const L = bytes(32);
  const memo = new Map<number, Buffer>();
  const mth = (n: number): Buffer => {
    if (n === 0) return EMPTY;
    if (n === 1) return L;
    let h = memo.get(n);
    if (!h) memo.set(n, (h = node(mth(split(n)), mth(n - split(n)))));
    return h;
  };
  const path = (i: number, n: number): Buffer[] => {
    if (n <= 1) return [];
    const k = split(n);
    return i < k ? [...path(i, k), mth(n - k)] : [...path(i - k, n - k), mth(k)];
  };
  const subproof = (m: number, n: number, b: boolean): Buffer[] => {
    if (m === n) return b ? [] : [mth(n)];
    const k = split(n);
    return m <= k ? [...subproof(m, k, b), mth(n - k)] : [...subproof(m - k, n - k, false), mth(k)];
  };
  return {
    label: "same-leaf tree",
    size,
    leaf: () => L,
    root: (n) => mth(n).toString("hex"),
    path: (i, n) => path(i, n).map((b) => b.toString("hex")),
    proof: (m, n) => (m === 0 || m === n ? [] : subproof(m, n, true).map((b) => b.toString("hex"))),
  };
}

function inclusionCases(t: Tree, i: number, n: number): Case[] {
  const what = `${t.label}: inclusion ${i}/${n}`;
  if (n === 0) return [{ kind: "inclusion", leaf: randomHash(), leafIndex: 0, treeSize: 0, root: EMPTY.toString("hex"), hashes: [], what, honest: false }];
  const honest: Inclusion = { kind: "inclusion", leaf: t.leaf(i).toString("hex"), leafIndex: i, treeSize: n, root: t.root(n), hashes: t.path(i, n) };
  const { leaf, root, hashes } = honest;
  const changed: [string, Partial<Inclusion>][] = [
    ["another leaf of the tree", { leaf: t.leaf((i + 1) % n).toString("hex") }],
    ["a random leaf", { leaf: randomHash() }],
    ["a 31-byte leaf", { leaf: leaf.slice(2) }],
    ["a 33-byte leaf", { leaf: leaf + "00" }],
    ["the next index", { leafIndex: (i + 1) % n }],
    ["a random index", { leafIndex: below(n + 2) }],
    ["tree size + 1", { treeSize: n + 1 }],
    ["tree size - 1", { treeSize: n - 1 }],
    ["the root of a smaller tree", { root: t.root(below(n)) }],
    ["a random root", { root: randomHash() }],
    ["an uppercase root", { root: root.toUpperCase() }],
    ["a short proof", { hashes: hashes.slice(0, -1) }],
    ["the first hash dropped", { hashes: hashes.slice(1) }],
    ["a long proof", { hashes: [...hashes, randomHash()] }],
    ["a hash in front", { hashes: [randomHash(), ...hashes] }],
    ["an uppercase proof", { hashes: hashes.map((x) => x.toUpperCase()) }],
    ["one hash changed", { hashes: hashes.length ? replace(hashes, below(hashes.length), randomHash()) : [randomHash()] }],
  ];
  return [{ ...honest, what, honest: true }, ...changed.map(([m, c]): Case => ({ ...honest, ...c, what: `${what}: ${m}`, honest: false }))];
}

function consistencyCases(t: Tree, m: number, n: number): Case[] {
  const what = `${t.label}: consistency ${m} -> ${n}`;
  const honest: Consistency = { kind: "consistency", oldSize: m, newSize: n, oldRoot: t.root(m), newRoot: t.root(n), hashes: t.proof(m, n) };
  const { oldRoot, newRoot, hashes } = honest;
  const changed: [string, Partial<Consistency>][] = [
    ["the old root of another size", { oldRoot: t.root(m > 0 ? m - 1 : Math.min(1, t.size)) }],
    ["a random old root", { oldRoot: randomHash() }],
    ["an uppercase old root", { oldRoot: oldRoot.toUpperCase() }],
    ["the new root of a smaller tree", { newRoot: t.root(below(n + 1)) }],
    ["a random new root", { newRoot: randomHash() }],
    ["old size + 1", { oldSize: m + 1 }],
    ["old size - 1", { oldSize: Math.max(0, m - 1) }],
    ["new size + 1", { newSize: n + 1 }],
    ["new size - 1", { newSize: Math.max(0, n - 1) }],
    ["old and new swapped", { oldSize: n, newSize: m, oldRoot: newRoot, newRoot: oldRoot }],
    ["a short proof", { hashes: hashes.slice(0, -1) }],
    ["the first hash dropped", { hashes: hashes.slice(1) }],
    ["the old root in front", { hashes: [oldRoot, ...hashes] }],
    ["a long proof", { hashes: [...hashes, randomHash()] }],
    ["an uppercase proof", { hashes: hashes.map((x) => x.toUpperCase()) }],
    ["one hash changed", { hashes: hashes.length ? replace(hashes, below(hashes.length), randomHash()) : [randomHash()] }],
  ];
  return [{ ...honest, what, honest: true }, ...changed.map(([d, c]): Case => ({ ...honest, ...c, what: `${what}: ${d}`, honest: false }))];
}

const cases: Case[] = [];

// Random trees of 0 to 300 leaves, the edges of the power-of-two shapes first.
const sizes = [0, 1, 2, 3, 4, 5, 7, 8, 9, 255, 256, 257, 300];
for (let k = 0; k < trees; k++) {
  const t = randomTree(k < sizes.length ? sizes[k]! : below(301));
  const N = t.size;
  if (N === 0) cases.push(...inclusionCases(t, 0, 0), ...consistencyCases(t, 0, 0));
  else {
    const n1 = 1 + below(N);
    for (const [i, n] of [[0, N], [N - 1, N], [below(N), N], [below(n1), n1]] as const) cases.push(...inclusionCases(t, i, n));
    let pow = 1;
    while (pow * 2 <= N) pow *= 2;
    const m1 = below(N + 1);
    for (const [m, n] of [[0, N], [N, N], [below(N + 1), N], [pow, N], [m1, m1 + below(N - m1 + 1)], [Math.max(1, N - 1), N]] as const) cases.push(...consistencyCases(t, m, n));
  }
}

// Sizes past 32 bits, where a power-of-two test on the low 32 bits goes wrong, up to the largest safe integer.
const MAX = Number.MAX_SAFE_INTEGER;
const big = sameLeafTree(MAX);
const bigSizes = [2 ** 32 - 1, 2 ** 32, 2 ** 32 + 1, 2 ** 32 + 2, MAX];
for (const n of bigSizes) {
  for (const i of new Set([0, 1, n - 2, n - 1, Math.floor(n / 2), below(n)])) cases.push(...inclusionCases(big, i, n));
  const olds = [0, 1, 2, 3, 5, 2 ** 31, 2 ** 32 - 1, 2 ** 32, 2 ** 32 + 1, 2 ** 32 + 2, 3 * 2 ** 32, n - 1, n, below(n) + 1];
  for (const m of new Set(olds.filter((m) => m <= n))) cases.push(...consistencyCases(big, m, n));
}
// log.ts takes no size past 2^53 - 1 (`Number.isSafeInteger`); the model and Python take any natural number
const sizesOf = (c: Case) => (c.kind === "inclusion" ? [c.leafIndex, c.treeSize] : [c.oldSize, c.newSize]);
const run = cases.filter((c) => sizesOf(c).every((s) => s <= MAX));
const jsonl = run.map((c) => JSON.stringify(c)).join("\n") + "\n";

function child(name: string, cmd: string, args: string[]): string[] {
  const started = Date.now();
  const r = spawnSync(cmd, args, { cwd: leanDir, input: jsonl, encoding: "utf8", maxBuffer: 1 << 28 });
  if (r.error || r.status !== 0) throw new Error(`${name} failed (${r.error?.message ?? `exit ${r.status}`}):\n${r.stderr}`);
  const out = r.stdout.split("\n").filter(Boolean);
  if (out.length !== run.length) throw new Error(`${name} answered ${out.length} lines for ${run.length} cases:\n${r.stderr}`);
  console.log(`${name}: ${Date.now() - started} ms`);
  return out;
}

async function inProcess(name: string, verify: (c: Case) => boolean | Promise<boolean>): Promise<string[]> {
  const started = Date.now();
  const out: string[] = [];
  for (const c of run) out.push((await verify(c)) ? "accept" : "refuse");
  console.log(`${name}: ${Date.now() - started} ms`);
  return out;
}

const hexBytes = (x: string) => Buffer.from(x, "hex");
const verdicts: [string, string[]][] = [
  ["lean", child("lean", "lake", ["exe", "oracle"])],
  ["log.ts", await inProcess("log.ts", (c) => c.kind === "inclusion" ? ts.verifyInclusion(hexBytes(c.leaf), c, c.root) : ts.verifyConsistency(c.oldSize, c.oldRoot, c.newSize, c.newRoot, c.hashes))],
  ["verify-web.ts", await inProcess("verify-web.ts", (c) => c.kind === "inclusion" ? web.verifyInclusion(new Uint8Array(hexBytes(c.leaf)), c, c.root) : web.verifyConsistency(c.oldSize, c.oldRoot, c.newSize, c.newRoot, c.hashes))],
  ["verify.py", child("verify.py", "uv", ["run", "--quiet", "--project", pyDir, "--extra", "verify", "--inexact", "python", join(here, "merkle.py")])],
];

let problems = 0;
let accepted = 0;
run.forEach((c, k) => {
  const answers = verdicts.map(([name, v]) => `${name} ${v[k]}`);
  const agree = verdicts.every(([, v]) => v[k] === verdicts[0]![1][k]);
  const honestOk = !c.honest || verdicts.every(([, v]) => v[k] === "accept");
  if (verdicts[0]![1][k] === "accept") accepted++;
  if (agree && honestOk) return;
  if (++problems <= 20) console.log(`\n${agree ? "HONEST PROOF REFUSED" : "DISAGREEMENT"}: ${c.what}\n  ${answers.join(", ")}\n  ${JSON.stringify(c)}`);
});
console.log(`\n${run.length} cases: ${accepted} accepted, ${run.length - accepted} refused by the model`);
if (problems) {
  console.log(`${problems} cases failed (seed ${seed})`);
  process.exit(1);
}
console.log(`the four verifiers agree on every case, and accept every honest proof`);
