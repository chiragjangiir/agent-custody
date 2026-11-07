/-
The theorems of `MerkleProofs.lean` and `ConsistencyProofs.lean` for the log's own hash, `Log.nodeHash`, and its hex
checks. They rest on one assumption, `NodeCollisionFree`, and `nodeCollisionFree_of_sha256` reduces it to SHA-256 having
no collision on two different 65-byte inputs.
-/
import AgentCustodySpec.Log
import AgentCustodySpec.MerkleProofs
import AgentCustodySpec.ConsistencyProofs

namespace AgentCustodySpec.Log
open AgentCustodySpec

/-- The assumption: two node inputs, 0x01 ‖ left ‖ right with 32-byte children, never hash alike. -/
def NodeCollisionFree : Prop := ∀ a b c d : Digest, nodeHash a b = nodeHash c d → a = c ∧ b = d

/-- `NodeCollisionFree` holds when SHA-256 returns 32 bytes and has no collision on 65-byte inputs. -/
theorem nodeCollisionFree_of_sha256 (hsize : ∀ m, (Sha256.hash m).size = 32)
    (hcr : ∀ x y : ByteArray, x.size = 65 → y.size = 65 → Sha256.hash x = Sha256.hash y → x = y) :
    NodeCollisionFree := by
  intro a b c d h
  unfold nodeHash toDigest at h
  simp only [hsize, dite_true, Subtype.mk.injEq] at h
  have hs : ∀ u v : Digest, (ByteArray.mk #[0x01] ++ u.1 ++ v.1).size = 65 := by
    intro u v; rw [ByteArray.size_append, ByteArray.size_append, u.2, v.2]; rfl
  have e := congrArg ByteArray.data (hcr _ _ (hs a b) (hs c d) h)
  simp only [ByteArray.data_append] at e
  have ha : a.1.data.size = 32 := a.2
  have hc : c.1.data.size = 32 := c.2
  obtain ⟨e1, e2⟩ := Array.append_inj e (by simp [Array.size_append, ha, hc])
  obtain ⟨-, e3⟩ := Array.append_inj e1 rfl
  exact ⟨Subtype.ext (ByteArray.ext e3), Subtype.ext (ByteArray.ext e2)⟩

/-- What the hex layer adds: it only refuses. An accepted check is the generic check on the parsed digests. -/
theorem verifyInclusion_parsed {leaf : ByteArray} {i n : Nat} {proof : List String} {rootHex : String}
    (h : verifyInclusion leaf i n proof rootHex = true) :
    ∃ l p r, digestOf leaf = some l ∧ proof.mapM hashOfHex = some p ∧ rootOfHex rootHex = some r ∧
      Merkle.verifyInclusion nodeHash l i n p r = true := by
  unfold verifyInclusion at h
  split at h
  · exact ⟨_, _, _, by assumption, by assumption, by assumption, h⟩
  · simp at h

/--
Soundness of the log's inclusion check: with no node-hash collision, a check that `log.ts` accepts against the root of
the tree `leaves` puts the 32-byte `leaf` at index `i`.
-/
theorem verifyInclusion_sound (hcf : NodeCollisionFree) (leaves : List Digest) (i : Nat) (leaf : ByteArray)
    (proof : List String) (rootHex : String) (hr : rootOfHex rootHex = some (root leaves))
    (h : verifyInclusion leaf i leaves.length proof rootHex = true) :
    ∃ d, leaves[i]? = some d ∧ d.1 = leaf := by
  obtain ⟨l, p, r, hl, -, hr', hv⟩ := verifyInclusion_parsed h
  rw [hr] at hr'; cases hr'
  have := (Merkle.verifyInclusion_sound nodeHash emptyRoot hcf leaves i l p hv).1
  refine ⟨l, this, ?_⟩
  unfold digestOf at hl
  split at hl
  · cases hl; rfl
  · cases hl

/-- Completeness of the log's inclusion check, on parsed digests: every audit path verifies. -/
theorem verifyInclusion_complete (leaves : List Digest) (i : Nat) (x : Digest) (hx : leaves[i]? = some x) :
    Merkle.verifyInclusion nodeHash x i leaves.length (path i leaves) (root leaves) = true :=
  Merkle.verifyInclusion_complete nodeHash emptyRoot leaves i x hx

/--
Soundness of the log's consistency check: with no node-hash collision, an old root that `log.ts` accepts against the
root of the tree `leaves`, for an old size `m ≤ leaves.length`, is the root of the first `m` leaves.
-/
theorem verifyConsistency_sound (hcf : NodeCollisionFree) (leaves : List Digest) (m : Nat) (oldRootHex newRootHex : String)
    (proof : List String) (hm : m ≤ leaves.length) (hr : rootOfHex newRootHex = some (root leaves))
    (h : verifyConsistency m oldRootHex leaves.length newRootHex proof = true) :
    ∃ o, rootOfHex oldRootHex = some o ∧ o = root (leaves.take m) := by
  unfold verifyConsistency at h
  split at h
  · rename_i o r p ho hr' hp
    rw [hr] at hr'; cases hr'
    exact ⟨o, ho, Merkle.verifyConsistency_sound nodeHash emptyRoot hcf leaves m o p hm h⟩
  · simp at h

end AgentCustodySpec.Log
