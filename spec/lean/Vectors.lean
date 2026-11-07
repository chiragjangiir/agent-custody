/-
Runs the Lean model against the conformance vectors that the TypeScript and Python verifiers also pass. A mismatch
means the model, or a verifier, disagrees with the format: the run prints it and exits 1.

  lake exe vectors [path to packages/receipts/vectors]
-/
import Lean.Data.Json
import AgentCustodySpec
open Lean AgentCustodySpec

abbrev Check := StateT (Nat × Nat) IO

def expect (what : String) (ok : Bool) : Check Unit := do
  let (pass, fail) ← get
  if ok then set (pass + 1, fail) else do
    IO.eprintln s!"FAIL {what}"
    set (pass, fail + 1)

def field {α} [FromJson α] (j : Json) (k : String) : IO α :=
  match j.getObjValAs? α k with
  | .ok v => pure v
  | .error e => throw (IO.userError s!"vector field {k}: {e}")

def sha256Examples : Check Unit := do
  -- FIPS 180-4 examples: "abc", the empty message, and the two-block message.
  expect "sha256(\"abc\")" <|
    Hex.encode (Sha256.hash "abc".toUTF8) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  expect "sha256(\"\")" <|
    Hex.encode (Sha256.hash ByteArray.empty) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  expect "sha256(448-bit message)" <|
    Hex.encode (Sha256.hash "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".toUTF8) ==
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"

/--
A size or an index. The model's are natural numbers; `log.ts` refuses any other number (`Number.isSafeInteger`) before
its loop, so a vector whose size is not a natural number must expect a refusal.
-/
def size (c : Json) (k : String) : IO (Option Nat) := do
  let v ← field (α := Json) c k
  match v with
  | .num _ => pure (v.getNat?.toOption)
  | _ => throw (IO.userError s!"vector field {k}: not a number")

/-- The hashes of a vector as `log.ts` gets them: hex strings. -/
def strs (c : Json) (k : String) : IO (List String) := do return (← field c k : Array String).toList

/-- Replaces hash `j` with another valid 32-byte hash. -/
def swapHash (p : List String) (j : Nat) : List String := p.set j (Hex.encode (Log.leafHash "not in the tree".toUTF8).1)

def merkleVectors (j : Json) : Check Unit := do
  let leaves : Array String ← field j "leaves"
  let leafHashes : Array String ← field j "leafHashes"
  let roots : Array String ← field j "roots"
  let hs := leaves.toList.map (fun l => Log.leafHash l.toUTF8)
  for (l, h, want) in leaves.toList.zip (hs.zip leafHashes.toList) do
    expect s!"leafHash({l})" (Hex.encode h.1 == want)
  for n in [0:roots.size] do
    expect s!"root of size {n}" (Hex.encode (Log.root (hs.take n)).1 == roots[n]!)
  let cases : Array Json ← field j "inclusion"
  for c in cases do
    let proof ← strs c "hashes"
    let root : String ← field c "root"
    let expected : Bool ← field c "expected"
    let (some i, some n) := (← size c "leafIndex", ← size c "treeSize")
      | expect s!"inclusion {c.getObjValD "leafIndex"}/{c.getObjValD "treeSize"}: a size that is not a natural number is refused" (!expected)
    -- a case names its leaf hash when the leaf is not leafHashes[leafIndex]
    let leaf ← match c.getObjValAs? String "leafHash" with
      | .ok h => match Hex.decode h with
        | some b => pure b
        | none => throw (IO.userError s!"vector leafHash {h}: not hex")
      | .error _ => pure (hs.getD i Log.emptyRoot).1
    let ok := Log.verifyInclusion leaf i n proof root
    expect s!"inclusion leafIndex {i} treeSize {n}" (ok == expected)
    if expected then
      expect s!"path({i}) of size {n} is the vector's proof" ((Log.path i (hs.take n)).map (Hex.encode ·.1) == proof)
      -- the vectors only hold accepted proofs: each of these changes must be refused
      let other := (hs.getD ((i + 1) % n) Log.emptyRoot).1
      expect s!"inclusion {i}/{n}: another leaf is refused" (!Log.verifyInclusion other i n proof root)
      expect s!"inclusion {i}/{n}: another index is refused" (!Log.verifyInclusion leaf ((i + 1) % n) n proof root)
      -- not checked: the same proof at another tree size. For a leaf of the left subtree the loop runs the same at
      -- 6 as at 7, and a 6-leaf list with that root exists. The size is authenticated by the signed tree head, which
      -- `verifyBundle` compares with the proof's `treeSize`.
      expect s!"inclusion {i}/{n}: another root is refused" (!Log.verifyInclusion leaf i n proof roots[n - 1]!)
      expect s!"inclusion {i}/{n}: a short proof is refused" (!Log.verifyInclusion leaf i n proof.dropLast root)
      expect s!"inclusion {i}/{n}: a long proof is refused" (!Log.verifyInclusion leaf i n (proof ++ [proof.head!]) root)
      for k in [0:proof.length] do
        expect s!"inclusion {i}/{n}: hash {k} changed is refused" (!Log.verifyInclusion leaf i n (swapHash proof k) root)
      expect s!"inclusion {i}/{n}: uppercase proof hashes are refused" (!Log.verifyInclusion leaf i n (proof.map String.toUpper) root)
      expect s!"inclusion {i}/{n}: an uppercase root is refused" (!Log.verifyInclusion leaf i n proof root.toUpper)
      expect s!"inclusion {i}/{n}: a 31-byte leaf is refused" (!Log.verifyInclusion (leaf.extract 1 32) i n proof root)

def consistencyVectors (j : Json) : Check Unit := do
  let leaves : Array String ← field j "leaves"
  let hs := leaves.toList.map (fun l => Log.leafHash l.toUTF8)
  let cases : Array Json ← field j "consistency"
  for c in cases do
    let oldRoot : String ← field c "oldRoot"
    let newRoot : String ← field c "newRoot"
    let proof ← strs c "hashes"
    let expected : Bool ← field c "expected"
    let (some m, some n) := (← size c "oldSize", ← size c "newSize")
      | expect s!"consistency {c.getObjValD "oldSize"} -> {c.getObjValD "newSize"}: a size that is not a natural number is refused" (!expected)
    expect s!"consistency {m} -> {n}" (Log.verifyConsistency m oldRoot n newRoot proof == expected)
    if expected && 0 < m && m < n then
      expect s!"consistencyProof {m} -> {n} is the vector's proof"
        ((Log.consistencyProof hs m n).map (Hex.encode ·.1) == proof)
      let wrongOld := Hex.encode (Log.root (hs.take (m - 1))).1
      expect s!"consistency {m} -> {n}: another old root is refused" (!Log.verifyConsistency m wrongOld n newRoot proof)
      expect s!"consistency {m} -> {n}: another old size is refused" (!Log.verifyConsistency (m + 1) oldRoot n newRoot proof)
      expect s!"consistency {m} -> {n}: a short proof is refused" (!Log.verifyConsistency m oldRoot n newRoot proof.dropLast)
      for k in [0:proof.length] do
        expect s!"consistency {m} -> {n}: hash {k} changed is refused" (!Log.verifyConsistency m oldRoot n newRoot (swapHash proof k))

def main (args : List String) : IO UInt32 := do
  let dir := args.headD "../../packages/receipts/vectors"
  let merkle ← match Json.parse (← IO.FS.readFile s!"{dir}/merkle.json") with
    | .ok j => pure j
    | .error e => throw (IO.userError s!"merkle.json: {e}")
  let ((), (pass, fail)) ← (do sha256Examples; merkleVectors merkle; consistencyVectors merkle : Check Unit).run (0, 0)
  IO.println s!"{pass} passed, {fail} failed"
  return if fail == 0 then 0 else 1
