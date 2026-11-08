/-
The Merkle tree of RFC 9162 section 2.1, over an abstract hash type `H`.

`node` is the interior hash, `sha256(0x01 || left || right)` in the log. Leaves are given as their leaf hashes,
`sha256(0x00 || leaf)`, which is how `packages/receipts/src/log.ts` keeps them. `empty` is the root of the empty tree,
`sha256("")`.

Each definition here mirrors a function of `log.ts`:
- `mth` is `SubtreeCache.mth` (MTH, section 2.1.1);
- `path` is `SubtreeCache.path` (PATH, section 2.1.3.1);
- `inclusionRoot` and `verifyInclusion` are `verifyInclusion` (section 2.1.3.2), step for step.
-/
namespace AgentCustodySpec.Merkle

/-- The largest power of two strictly less than `n`, for `n ≥ 2`: `split` in `log.ts`. -/
def split (n : Nat) : Nat := 2 ^ Nat.log2 (n - 1)

theorem split_pos (n : Nat) : 0 < split n := Nat.two_pow_pos _

theorem split_lt {n : Nat} (h : 2 ≤ n) : split n < n := by
  unfold split
  have := Nat.log2_self_le (n := n - 1) (by omega)
  omega

variable {H : Type} (node : H → H → H) (empty : H)

/-- MTH(D[n]): the root of the tree over the leaf hashes `l`. -/
def mth (l : List H) : H :=
  if _h : l.length ≤ 1 then l.headD empty
  else node (mth (l.take (split l.length))) (mth (l.drop (split l.length)))
termination_by l.length
decreasing_by
  all_goals simp only [List.length_take, List.length_drop]
  · have := split_lt (n := l.length) (by omega); omega
  · have := split_pos l.length; omega

/-- PATH(m, D[n]): the audit path of leaf `m`, leaf to root. -/
def path (m : Nat) (l : List H) : List H :=
  if _h : l.length ≤ 1 then []
  else if m < split l.length then path m (l.take (split l.length)) ++ [mth node empty (l.drop (split l.length))]
  else path (m - split l.length) (l.drop (split l.length)) ++ [mth node empty (l.take (split l.length))]
termination_by l.length
decreasing_by
  all_goals simp only [List.length_take, List.length_drop]
  · have := split_lt (n := l.length) (by omega); omega
  · have := split_pos l.length; omega

/-- While `fn` is even and not zero, halve `fn` and `sn`: the inner `while` of `verifyInclusion`. -/
def strip (fn sn : Nat) : Nat × Nat :=
  if fn % 2 = 0 ∧ fn ≠ 0 then strip (fn / 2) (sn / 2) else (fn, sn)
termination_by fn
decreasing_by omega

/--
The loop of RFC 9162 section 2.1.3.2 as `verifyInclusion` in `log.ts` runs it: `fn` is the node index at the current
level, `sn` the last index at that level, and `r` the hash computed so far. It answers the root the proof leads to, or
`none` where the TypeScript returns `false` (a hash left over when `sn` is already 0, or `sn` not 0 at the end).

`log.ts` runs `strip` only when `fn` is even; when `fn` is odd `strip` changes nothing, so this form is the same.
-/
def inclusionRoot : Nat → Nat → H → List H → Option H
  | _, sn, r, [] => if sn = 0 then some r else none
  | fn, sn, r, p :: ps =>
    if sn = 0 then none
    else if fn % 2 = 1 ∨ fn = sn then
      let s := strip fn sn
      inclusionRoot (s.1 / 2) (s.2 / 2) (node p r) ps
    else inclusionRoot (fn / 2) (sn / 2) (node r p) ps

/-- `verifyInclusion(leaf, { leafIndex: i, treeSize: n, hashes }, root)` of `log.ts`. -/
def verifyInclusion [DecidableEq H] (leaf : H) (i n : Nat) (proof : List H) (root : H) : Bool :=
  decide (i < n) && inclusionRoot node i (n - 1) leaf proof == some root

/--
SUBPROOF(m, D[n], b) of RFC 9162 section 2.1.4.1: `subproof` in `log.ts`, which returns only when `m = n`. Its domain
is `0 < m ≤ n`, the only sizes `consistencyProof` gives it. Outside that, `log.ts` reaches a range of one leaf with
`m ≠ 1`, where `split` is 1 and it recurses on the same range for ever; this model answers `[]` there instead.
-/
def subproof (m : Nat) (l : List H) (b : Bool) : List H :=
  if l.length = m then (if b then [] else [mth node empty l])
  else if _h : l.length ≤ 1 then []
  else if m ≤ split l.length then subproof m (l.take (split l.length)) b ++ [mth node empty (l.drop (split l.length))]
  else subproof (m - split l.length) (l.drop (split l.length)) false ++ [mth node empty (l.take (split l.length))]
termination_by l.length
decreasing_by
  all_goals simp only [List.length_take, List.length_drop]
  · have := split_lt (n := l.length) (by omega); omega
  · have := split_pos l.length; omega

/-- `consistencyProof(leafHashes, oldSize, newSize)` of `log.ts`. -/
def consistencyProof (l : List H) (oldSize newSize : Nat) : List H :=
  if oldSize = 0 ∨ oldSize = newSize then [] else subproof node empty oldSize (l.take newSize) true

/-- While `fn` is odd, halve `fn` and `sn`: the first `while` of `verifyConsistency`. -/
def stripOdd (fn sn : Nat) : Nat × Nat :=
  if fn % 2 = 1 then stripOdd (fn / 2) (sn / 2) else (fn, sn)
termination_by fn
decreasing_by omega

/--
The loop of RFC 9162 section 2.1.4.2 as `verifyConsistency` in `log.ts` runs it, from the second hash on. `fr` and `sr`
are the old and the new root computed so far. It answers both, or `none` where the TypeScript returns `false`.
-/
def consistencyRoots : Nat → Nat → H → H → List H → Option (H × H)
  | _, sn, fr, sr, [] => if sn = 0 then some (fr, sr) else none
  | fn, sn, fr, sr, c :: cs =>
    if sn = 0 then none
    else if fn % 2 = 1 ∨ fn = sn then
      let s := strip fn sn
      consistencyRoots (s.1 / 2) (s.2 / 2) (node c fr) (node c sr) cs
    else consistencyRoots (fn / 2) (sn / 2) fr (node sr c) cs

/--
`verifyConsistency(oldSize, oldRoot, newSize, newRoot, proof)` of `log.ts`. At old size 0 the proof is empty and the old
root must be the empty tree's root, and so must the new root when the new size is 0 too.
-/
def verifyConsistency [DecidableEq H] (oldSize : Nat) (oldRoot : H) (newSize : Nat) (newRoot : H)
    (proof : List H) : Bool :=
  if oldSize > newSize then false
  else if oldSize = 0 then proof.isEmpty && oldRoot == empty && (decide (0 < newSize) || newRoot == empty)
  else if oldSize = newSize then proof.isEmpty && oldRoot == newRoot
  else if proof.isEmpty then false
  else
    -- a power-of-two old size: its root is the first hash, and the proof leaves it out (`isPowerOfTwo` in `log.ts`)
    let p := if oldSize &&& (oldSize - 1) = 0 then oldRoot :: proof else proof
    match p with
    | [] => false
    | first :: rest =>
      let s := stripOdd (oldSize - 1) (newSize - 1)
      consistencyRoots node s.1 s.2 first first rest == some (oldRoot, newRoot)

end AgentCustodySpec.Merkle
