/-
The model as an oracle: reads Merkle proof checks as JSON lines on standard input and prints, for each, `accept` or
`refuse`. The differential fuzzer in `fuzz/` sends the same lines to `log.ts`, `verify-web.ts` and the Python verifier,
and fails on any disagreement.

  lake exe oracle < cases.jsonl

An inclusion check: {"kind":"inclusion","leaf":hex,"leafIndex":n,"treeSize":n,"root":hex,"hashes":[hex,...]}.
`leaf` is the leaf hash that `verifyInclusion` takes, in hex, of any number of bytes.
A consistency check: {"kind":"consistency","oldSize":n,"newSize":n,"oldRoot":hex,"newRoot":hex,"hashes":[hex,...]}.
Other fields are ignored. A size that is not a natural number is refused, as `log.ts` refuses it. A line the oracle
cannot read stops the run with exit 2.
-/
import Lean.Data.Json
import AgentCustodySpec
open Lean AgentCustodySpec

def field {α} [FromJson α] (j : Json) (k : String) : Except String α :=
  (j.getObjValAs? α k).mapError (s!"field {k}: " ++ ·)

/-- A size or an index: `none` when the number is not a natural number. -/
def size (j : Json) (k : String) : Except String (Option Nat) := do
  match ← field (α := Json) j k with
  | v@(.num _) => pure v.getNat?.toOption
  | _ => throw s!"field {k}: not a number"

def verdict (c : Json) : Except String Bool := do
  let hashes := (← field (α := Array String) c "hashes").toList
  match ← field (α := String) c "kind" with
  | "inclusion" =>
    let leafHex : String ← field c "leaf"
    let some leaf := Hex.decode leafHex | throw s!"leaf {leafHex}: not lowercase hex"
    let root : String ← field c "root"
    let (some i, some n) := (← size c "leafIndex", ← size c "treeSize") | pure false
    pure (Log.verifyInclusion leaf i n hashes root)
  | "consistency" =>
    let oldRoot : String ← field c "oldRoot"
    let newRoot : String ← field c "newRoot"
    let (some m, some n) := (← size c "oldSize", ← size c "newSize") | pure false
    pure (Log.verifyConsistency m oldRoot n newRoot hashes)
  | k => throw s!"kind {k}: neither inclusion nor consistency"

def main : IO UInt32 := do
  let stdin ← IO.getStdin
  let stdout ← IO.getStdout
  let mut n := 0
  repeat
    let line ← stdin.getLine
    if line.isEmpty then break
    n := n + 1
    if line.all Char.isWhitespace then continue
    match Json.parse line >>= verdict with
    | .ok ok => stdout.putStrLn (if ok then "accept" else "refuse")
    | .error e =>
      IO.eprintln s!"line {n}: {e}"
      return 2
  stdout.flush
  return 0
