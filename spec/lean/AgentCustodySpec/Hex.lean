/- Lowercase hex, the form every hash takes in a receipt, a proof, and the vectors. -/
namespace AgentCustodySpec.Hex

def encode (b : ByteArray) : String :=
  b.foldl (fun s x => s ++ String.singleton (Nat.toDigits 16 (x.toNat / 16)).head! ++
    String.singleton (Nat.toDigits 16 (x.toNat % 16)).head!) ""

private def nibble (c : Char) : Option UInt8 :=
  if '0' ≤ c ∧ c ≤ '9' then some (c.toNat - '0'.toNat).toUInt8
  else if 'a' ≤ c ∧ c ≤ 'f' then some (c.toNat - 'a'.toNat + 10).toUInt8
  else none

/-- Strict: lowercase only, an even number of digits. Anything else is `none`. -/
def decode (s : String) : Option ByteArray := do
  let cs := s.toList
  if cs.length % 2 != 0 then none
  let rec go : List Char → ByteArray → Option ByteArray
    | a :: b :: rest, acc => do go rest (acc.push ((← nibble a) * 16 + (← nibble b)))
    | _, acc => some acc
  go cs ByteArray.empty

end AgentCustodySpec.Hex
