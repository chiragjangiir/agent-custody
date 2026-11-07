/-
The axioms behind each theorem that README.md lists. `check-axioms.sh` runs this file and fails when any theorem
depends on an axiom other than Lean's standard three, `propext`, `Classical.choice` and `Quot.sound`: an unfinished proof
shows as `sorryAx`, `native_decide` as `Lean.ofReduceBool`, and a new `axiom` by its name.
-/
import AgentCustodySpec

#print axioms AgentCustodySpec.Merkle.verifyInclusion_complete
#print axioms AgentCustodySpec.Merkle.verifyInclusion_sound
#print axioms AgentCustodySpec.Merkle.inclusionRoot_eq_down
#print axioms AgentCustodySpec.Merkle.iterC_eq_downC
#print axioms AgentCustodySpec.Merkle.verifyConsistency_sound
#print axioms AgentCustodySpec.Log.nodeCollisionFree_of_sha256
#print axioms AgentCustodySpec.Log.verifyInclusion_parsed
#print axioms AgentCustodySpec.Log.verifyInclusion_sound
#print axioms AgentCustodySpec.Log.verifyInclusion_complete
#print axioms AgentCustodySpec.Log.verifyConsistency_sound
