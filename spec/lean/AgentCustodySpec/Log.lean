/-
The Merkle model of `Merkle.lean` with the log's real hashes: SHA-256 with the RFC 9162 domain separation, over 32-byte
digests, behind the hex checks that `log.ts` runs before its loops.

The generic theorems assume an injective `node`. On byte arrays of any width `sha256(0x01 || left || right)` is not:
moving the boundary between `left` and `right` keeps the preimage. On 32-byte children it is, unless SHA-256 has a
collision. So the model runs on `Digest`, and the hex layer refuses any hash that is not 32 bytes, as `log.ts` does.
-/
import AgentCustodySpec.Sha256
import AgentCustodySpec.Hex
import AgentCustodySpec.Merkle
namespace AgentCustodySpec.Log
open AgentCustodySpec

instance : DecidableEq ByteArray := fun a b =>
  if h : a.data = b.data then isTrue (by cases a; cases b; simp_all) else isFalse (by intro e; cases e; exact h rfl)

/-- A SHA-256 digest: 32 bytes. Every hash that a proof check reads has this width. -/
abbrev Digest := { b : ByteArray // b.size = 32 }

/-- The 32 bytes of a SHA-256 output. `Sha256.hash` always returns 32 bytes (`lake exe vectors` checks it); the other
branch only makes the function total. -/
def toDigest (b : ByteArray) : Digest :=
  if h : b.size = 32 then ⟨b, h⟩ else ⟨ByteArray.mk (Array.replicate 32 0), by simp [ByteArray.size]⟩

/-- `leafHash` of `log.ts`: sha256(0x00 || data). -/
def leafHash (data : ByteArray) : Digest := toDigest (Sha256.hash (ByteArray.mk #[0x00] ++ data))
/-- `nodeHash` of `log.ts`: sha256(0x01 || left || right), on 32-byte children. -/
def nodeHash (l r : Digest) : Digest := toDigest (Sha256.hash (ByteArray.mk #[0x01] ++ l.1 ++ r.1))
/-- The root of the empty tree: sha256 of nothing. -/
def emptyRoot : Digest := toDigest (Sha256.hash ByteArray.empty)

def root (leafHashes : List Digest) : Digest := Merkle.mth nodeHash emptyRoot leafHashes
def path (m : Nat) (leafHashes : List Digest) : List Digest := Merkle.path nodeHash emptyRoot m leafHashes
def consistencyProof (l : List Digest) (oldSize newSize : Nat) : List Digest :=
  Merkle.consistencyProof nodeHash emptyRoot l oldSize newSize

/-! ## The hex checks of `log.ts`, before its loops -/

/-- 32 bytes, or nothing. -/
def digestOf (b : ByteArray) : Option Digest := if h : b.size = 32 then some ⟨b, h⟩ else none

/-- A proof hash: 64 lowercase hex digits (`HASH_HEX`), as the Python verifier requires. -/
def hashOfHex (s : String) : Option Digest := if s.length = 64 then Hex.decode s >>= digestOf else none

/-- A root: 64 lowercase hex digits, as a signed tree head carries it. The same rule as a proof hash. -/
def rootOfHex (s : String) : Option Digest := hashOfHex s

/-- `verifyInclusion(leaf, { leafIndex: i, treeSize: n, hashes }, rootHex)` of `log.ts`. -/
def verifyInclusion (leaf : ByteArray) (i n : Nat) (proof : List String) (rootHex : String) : Bool :=
  match digestOf leaf, proof.mapM hashOfHex, rootOfHex rootHex with
  | some l, some p, some r => Merkle.verifyInclusion nodeHash l i n p r
  | _, _, _ => false

/-- `verifyConsistency(oldSize, oldRoot, newSize, newRoot, proof)` of `log.ts`. -/
def verifyConsistency (oldSize : Nat) (oldRootHex : String) (newSize : Nat) (newRootHex : String)
    (proof : List String) : Bool :=
  match rootOfHex oldRootHex, rootOfHex newRootHex, proof.mapM hashOfHex with
  | some o, some r, some p => Merkle.verifyConsistency nodeHash emptyRoot oldSize o newSize r p
  | _, _, _ => false

end AgentCustodySpec.Log
