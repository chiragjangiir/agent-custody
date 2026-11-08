# A Lean 4 specification of the verifier

This is a model of the verifier's core in [Lean 4](https://lean-lang.org), with machine-checked proofs. It is not shipped. The TypeScript and Python verifiers stay the ones people run. The model states the acceptance rule precisely. It also checks the conformance vectors as a third implementation, beside those two verifiers, and a differential fuzzer checks that it gives the same verdict as each of them on tens of thousands of generated proofs.

Tracking issue: #224.

## What is proved

[`AgentCustodySpec/MerkleProofs.lean`](AgentCustodySpec/MerkleProofs.lean) covers the inclusion proofs of RFC 9162. The model in [`Merkle.lean`](AgentCustodySpec/Merkle.lean) follows `packages/receipts/src/log.ts` step for step.

| Theorem | Statement |
| --- | --- |
| `verifyInclusion_complete` | For every leaf of every tree, its audit path verifies against the tree's root. |
| `verifyInclusion_sound` | If the node hash is injective, then any proof that verifies against the root of tree `l`, for leaf `x` at index `i`, satisfies two things: `x` is the leaf at index `i` of `l`, and the proof is exactly that leaf's audit path. |
| `inclusionRoot_eq_down` | The RFC's verification loop, which steers by the bits of the leaf index and of the last index, computes the same root as reading the audit path from the root down along the tree's own splits. This holds for every list of hashes, including ones that are too short, too long, or wrong. |

[`AgentCustodySpec/ConsistencyProofs.lean`](AgentCustodySpec/ConsistencyProofs.lean) covers the consistency proofs, modelled from `verifyConsistency` and `subproof` in `log.ts`.

| Theorem | Statement |
| --- | --- |
| `iterC_eq_downC` | For `0 < m < n` and every list of hashes, the RFC's consistency loop computes the same old and new roots as reading the proof from the root down along the tree's splits. |
| `verifyConsistency_sound` | If the node hash is injective, an old root that the check accepts against the root of tree `l`, for any old size `m ≤ l.length`, is the root of the first `m` leaves of `l`. A log cannot pass off a head as extending an old head unless the old tree is a prefix of the new one. |

Writing this proof found a gap. `log.ts` accepted any old root at old size 0, while the Python verifier required the empty tree's root. With that case the theorem is false. Since #226, all three verifiers require `sha256("")` at size 0, for the new head too when both sizes are 0, and vectors cover both cases. This model follows the rules of #226, so it lands after #226.

Those theorems hold for any hash type with an injective `node`. [`AgentCustodySpec/LogProofs.lean`](AgentCustodySpec/LogProofs.lean) applies them to the log's own hash. [`Log.lean`](AgentCustodySpec/Log.lean) runs on 32-byte digests, behind the same hex checks that `log.ts` runs before its loops.

| Theorem | Statement |
| --- | --- |
| `nodeCollisionFree_of_sha256` | If SHA-256 returns 32 bytes and has no collision on 65-byte inputs, then `NodeCollisionFree` holds: `nodeHash` is injective on 32-byte children. |
| `Log.verifyInclusion_sound` | With `NodeCollisionFree`, a check that `Log.verifyInclusion` accepts against the root of tree `leaves` puts the 32-byte leaf at its index. |
| `Log.verifyConsistency_sound` | With `NodeCollisionFree`, an old root that `Log.verifyConsistency` accepts against the root of tree `leaves` is the root of the first `m` leaves. |
| `Log.verifyInclusion_parsed` | The hex layer only refuses: an accepted check is the generic check on the parsed digests. |

Each theorem depends only on Lean's standard axioms: `propext`, `Classical.choice` and `Quot.sound`. [`check-axioms.sh`](check-axioms.sh) prints the axioms of every theorem above with `#print axioms` ([`Axioms.lean`](Axioms.lean)). It fails if any theorem depends on another axiom, which is how a `sorry` (`sorryAx`), a `native_decide` (`Lean.ofReduceBool`), or a new `axiom` would show.

## What is assumed

- **One assumption: `NodeCollisionFree`.** Two node inputs, `0x01 ‖ left ‖ right` with 32-byte children, never have the same SHA-256 digest. `nodeCollisionFree_of_sha256` derives it from two facts about SHA-256: it has no collision on 65-byte inputs, and it returns 32 bytes. `lake exe vectors` checks the second; the first is the usual trust in SHA-256. The width is what makes this a collision. On byte arrays of any width, `sha256(0x01 ‖ left ‖ right)` keeps its preimage when the boundary between the children moves. So the model, like `log.ts` and the Python verifier, refuses before the loop any proof hash that is not 64 lowercase hex digits, any root that is not 64 lowercase hex digits, and any leaf that is not 32 bytes.
- **Sizes and indices are integers.** The model takes natural numbers. `log.ts` works on JavaScript numbers, so before its loops it refuses any index or size that is not a non-negative safe integer (`Number.isSafeInteger`). Without that check, the loops halve with floor and a fraction walks a real path: leaf 2's proof also passed at index 2.5. Vectors cover it, and `lake exe vectors` requires a case whose size is not a natural number to expect a refusal.
- **Sizes below 2^53.** `log.ts` works on JavaScript numbers, which are exact up to 2^53, and refuses any size above 2^53 − 1. The model and the Python verifier take any natural number, so the three agree on sizes up to 2^53 − 1 only. Until the fuzzer below was added, the power-of-two test of `verifyConsistency` was `(oldSize & (oldSize - 1)) === 0` in both TypeScript verifiers. JavaScript's `&` works on the low 32 bits of each side, so an old size such as 2^32 + 1 counted as a power of two, and an honest proof from it was refused. The model copied that test. The fuzzer's cases past 2^32 found that Python disagreed. Now all three test the whole size: `isPowerOfTwo` in TypeScript, `&&&` on natural numbers here, `&` on Python integers. This was a completeness gap, not a soundness one: the soundness theorem held whichever way the test went.
- **`subproof` within its domain.** `log.ts` calls `subproof` only with `0 < m < n`. Outside that range it would reach a range of one leaf and recurse forever. The model answers `[]` there instead.
- **The tree size comes from the signed head.** An inclusion check does not pin the tree size by itself. For a leaf in the left subtree, the same proof verifies at size 6 against a 7-leaf root, and a 6-leaf list with that root exists. `verifyBundle` compares the proof's `treeSize` with the signed tree head.

## Run it

Install [elan](https://github.com/leanprover/elan), then run this from this directory:

```bash
lake build
```

```bash
lake exe vectors
```

`lake build` checks every proof. `lake exe vectors` runs these checks:
- the FIPS 180-4 SHA-256 examples;
- `packages/receipts/vectors/merkle.json`: the leaf hashes, the root of every prefix, each inclusion and consistency verdict, and that `path` and `consistencyProof` produce each vector's proof;
- changes that each accepted vector must refuse, because the vectors themselves hold almost only accepted proofs:
  - another leaf, index or root;
  - a proof that is too short or too long;
  - each proof hash replaced in turn;
  - uppercase proof hashes, and an uppercase root;
  - a 31-byte leaf;
  - for consistency, another old root or old size.

```bash
./check-axioms.sh
```

## Differential fuzzing

The vectors hold 7 leaves. The fuzzer ties the model to the shipped verifiers on many more cases. Run this from this directory, with `bun` and `uv` installed:

```bash
bun fuzz/merkle.ts --seed random
```

[`fuzz/merkle.ts`](fuzz/merkle.ts) makes 200 trees of random leaves (`--trees`), of 0 to 300 leaves, with the sizes around powers of two first. For each tree it takes honest inclusion and consistency proofs from `log.ts` and changes each one in turn:
- another leaf, a 31-byte or 33-byte leaf, another index or tree size, another root;
- for consistency, another old or new root, old or new size, or the two heads swapped;
- a proof that is too short or too long, has its first hash dropped, has the old root put in front, or has one hash replaced;
- uppercase proof hashes, and an uppercase root.

It adds the same cases for a tree whose leaves are all the same. There a subtree's hash depends only on its size, so the roots and proofs of trees of 2^32 − 1, 2^32, 2^32 + 1, 2^32 + 2 and 2^53 − 1 leaves cost a few hundred hashes. No case has a size above 2^53 − 1, the limit of `log.ts`.

Each case goes to four verifiers:
- the model, through `lake exe oracle` ([`Oracle.lean`](Oracle.lean)), which reads the cases as JSON lines and prints `accept` or `refuse` for each;
- `verifyInclusion` and `verifyConsistency` of `packages/receipts/src/log.ts`;
- the same functions of `packages/state/src/verify-web.ts`, the WebCrypto verifier of the browser page and the offline case files;
- the Python verifier `agent_custody.verify`, through [`fuzz/merkle.py`](fuzz/merkle.py). It runs the same hex checks as a bundle check (`_hashes`, `HEX64`), then `root_from_inclusion` or `verify_consistency`.

The run fails when two verifiers disagree on a case, or when any verifier refuses an honest proof. It prints the first 20 failing cases and the seed. `--seed <n>` replays a run.

The `lean` workflow runs the build, the axioms check, the vectors, and the fuzzer twice: once with the fixed seed 20261108, and once with a random seed. It fails on any `sorry`.

## Still to do

The fuzzer checks the hand-written code against the model on the cases it generates. It does not prove that they are the same program.

The remaining items of #224:
- completeness of the consistency check (each proof that `consistencyProof` makes verifies);
- the receipt acceptance rule of `verifyBundle`;
- canonical JSON.
