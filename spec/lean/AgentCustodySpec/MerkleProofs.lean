/-
Proofs about the Merkle model of `Merkle.lean`.

The RFC 9162 verification loop walks the audit path from the leaf up, steering by the bits of the leaf index and of
the last index. The tree is defined top down, by splitting at the largest power of two. The proofs meet in the middle:
`down` reads the audit path from the root down, following the same split as `mth` and `path`, and
`inclusionRoot_eq_down` shows that the loop computes exactly what `down` computes, for every list of hashes. Then
completeness and soundness are proved about `down`, where they are plain structural inductions.
-/
import AgentCustodySpec.Merkle

namespace AgentCustodySpec.Merkle

/-! ## `split` -/

theorem split_eq (n : Nat) : split n = 2 ^ Nat.log2 (n - 1) := rfl

/-- For `n ≥ 2`, `split n ≤ n - 1 < 2 * split n`: the last index has the same top bit as `split n`. -/
theorem split_bounds {n : Nat} (h : 2 ≤ n) : split n ≤ n - 1 ∧ n - 1 < 2 * split n := by
  unfold split
  have h1 := Nat.log2_self_le (n := n - 1) (by omega)
  have h2 := Nat.lt_log2_self (n := n - 1)
  rw [Nat.pow_succ] at h2
  omega

variable {H : Type} (node : H → H → H) (empty : H)

/-! ## Unfolding `mth` and `path` -/

theorem mth_nil : mth node empty [] = empty := by
  rw [mth]; simp

theorem mth_single (x : H) : mth node empty [x] = x := by
  rw [mth]; simp

theorem mth_split {l : List H} (h : 2 ≤ l.length) :
    mth node empty l =
      node (mth node empty (l.take (split l.length))) (mth node empty (l.drop (split l.length))) := by
  rw [mth]; simp only [show ¬ l.length ≤ 1 by omega, dite_false]

theorem path_short {m : Nat} {l : List H} (h : l.length ≤ 1) : path node empty m l = [] := by
  rw [path]; simp only [h, dite_true]

theorem path_left {m : Nat} {l : List H} (h : 2 ≤ l.length) (hm : m < split l.length) :
    path node empty m l =
      path node empty m (l.take (split l.length)) ++ [mth node empty (l.drop (split l.length))] := by
  rw [path]; simp only [show ¬ l.length ≤ 1 by omega, dite_false, hm, ite_true]

theorem path_right {m : Nat} {l : List H} (h : 2 ≤ l.length) (hm : ¬ m < split l.length) :
    path node empty m l =
      path node empty (m - split l.length) (l.drop (split l.length)) ++
        [mth node empty (l.take (split l.length))] := by
  rw [path]; simp only [show ¬ l.length ≤ 1 by omega, dite_false, hm, ite_false]

/-! ## The audit path read from the root down -/

/--
The root that the audit path `q`, given root first, leads to from leaf `x` at index `i` of a tree of `n` leaves.
It follows the split of `mth`: the first hash is the sibling of the subtree that holds leaf `i`. `none` when `q` is
too short or too long for that leaf.
-/
def down (i n : Nat) (x : H) : List H → Option H
  | [] => if n ≤ 1 then some x else none
  | s :: q =>
    if n ≤ 1 then none
    else if i < split n then (down i (split n) x q).map (node · s)
    else (down (i - split n) (n - split n) x q).map (node s ·)

/-! ## Completeness and soundness of `down` -/

/-- The audit path of leaf `i`, read root first, leads from that leaf to the root. -/
theorem down_path (n : Nat) : ∀ (l : List H) (i : Nat) (x : H), l.length = n → l[i]? = some x →
    down node i n x (path node empty i l).reverse = some (mth node empty l) := by
  induction n using Nat.strongRecOn with
  | ind n ih =>
  intro l i x hl hx
  have hi : i < n := by
    have := (List.getElem?_eq_some_iff.mp hx).1; omega
  subst hl
  by_cases h2 : l.length ≤ 1
  · obtain ⟨d, rfl⟩ : ∃ d, l = [d] := List.length_eq_one_iff.mp (by omega)
    have : i = 0 := by simp at hi; omega
    subst this
    simp at hx
    rw [path_short node empty (by simp), mth_single]
    simp [down, hx]
  · have hn : 2 ≤ l.length := by omega
    have ⟨hk1, hk2⟩ := split_bounds (n := l.length) (by omega)
    have hk0 := split_pos l.length
    by_cases hik : i < split l.length
    · rw [path_left node empty hn (by omega), mth_split node empty hn]
      simp only [List.reverse_append, List.reverse_cons, List.reverse_nil, List.nil_append, List.cons_append]
      simp only [down, h2, ite_false, hik, ite_true]
      rw [ih (split l.length) (by omega) (l.take (split l.length)) i x (by simp; omega)
        (by rw [List.getElem?_take]; simp [hik, hx])]
      simp
    · rw [path_right node empty hn (by omega), mth_split node empty hn]
      simp only [List.reverse_append, List.reverse_cons, List.reverse_nil, List.nil_append, List.cons_append]
      simp only [down, h2, ite_false, hik]
      rw [ih (l.length - split l.length) (by omega) (l.drop (split l.length)) (i - split l.length) x (by simp)
        (by rw [List.getElem?_drop, show split l.length + (i - split l.length) = i by omega]; exact hx)]
      simp

/--
Soundness: if the node hash is injective, a list of hashes that `down` takes from `x` to the root of the tree `l` puts
`x` at index `i` of `l`, and is exactly the audit path of `i`.
-/
theorem down_sound (hinj : ∀ a b c d, node a b = node c d → a = c ∧ b = d) :
    ∀ (q l : List H) (i : Nat) (x : H), i < l.length →
      down node i l.length x q = some (mth node empty l) → l[i]? = some x ∧ q = (path node empty i l).reverse := by
  intro q
  induction q with
  | nil =>
    intro l i x hi h
    by_cases h2 : l.length ≤ 1
    · obtain ⟨d, rfl⟩ : ∃ d, l = [d] := List.length_eq_one_iff.mp (by omega)
      have : i = 0 := by simp at hi; omega
      subst this
      simp [down, mth_single] at h
      simp [h, path_short node empty (show [d].length ≤ 1 by simp)]
    · simp [down, h2] at h
  | cons s q ih =>
    intro l i x hi h
    by_cases h2 : l.length ≤ 1
    · simp [down, h2] at h
    have hn : 2 ≤ l.length := by omega
    have ⟨hk1, hk2⟩ := split_bounds (n := l.length) (by omega)
    have hk0 := split_pos l.length
    rw [mth_split node empty hn] at h
    by_cases hik : i < split l.length
    · simp only [down, h2, hik, ite_true, ite_false, Option.map_eq_some_iff] at h
      obtain ⟨r, hr, he⟩ := h
      obtain ⟨rfl, rfl⟩ := hinj _ _ _ _ he
      have := ih (l.take (split l.length)) i x (by simp; omega)
        (by rw [List.length_take, Nat.min_eq_left (by omega)]; exact hr)
      refine ⟨?_, ?_⟩
      · rw [← this.1, List.getElem?_take]; simp [hik]
      · rw [path_left node empty hn hik, this.2]; simp
    · simp only [down, h2, hik, ite_false, Option.map_eq_some_iff] at h
      obtain ⟨r, hr, he⟩ := h
      obtain ⟨rfl, rfl⟩ := hinj _ _ _ _ he
      have := ih (l.drop (split l.length)) (i - split l.length) x (by simp; omega)
        (by rw [List.length_drop]; exact hr)
      refine ⟨?_, ?_⟩
      · rw [← this.1, List.getElem?_drop, show split l.length + (i - split l.length) = i by omega]
      · rw [path_right node empty hn hik, this.2]; simp

/-! ## The verification loop -/

theorem strip_eq (fn sn : Nat) :
    strip fn sn = if fn % 2 = 0 ∧ fn ≠ 0 then strip (fn / 2) (sn / 2) else (fn, sn) := by
  rw [strip]

theorem strip_odd {fn sn : Nat} (h : fn % 2 = 1) : strip fn sn = (fn, sn) := by
  rw [strip_eq]; simp [h]

/-- A power of two strips to one. -/
theorem strip_pow (b : Nat) : strip (2 ^ b) (2 ^ b) = (1, 1) := by
  induction b with
  | zero => rw [strip_eq]; simp
  | succ b ih =>
    rw [strip_eq, Nat.pow_succ]
    have := Nat.two_pow_pos b
    simp only [show 2 ^ b * 2 % 2 = 0 by omega, show 2 ^ b * 2 ≠ 0 by omega, ne_eq, not_false_eq_true,
      and_self, ite_true, show 2 ^ b * 2 / 2 = 2 ^ b by omega, ih]

/--
Stripping `f + 2^b` takes off the same factors of two as stripping `f`, when `0 < f < 2^b`: the extra top bit rides
along, one place lower each time.
-/
theorem strip_top (b : Nat) : ∀ f, 0 < f → f < 2 ^ b →
    ∃ g c, strip f f = (g, g) ∧ strip (f + 2 ^ b) (f + 2 ^ b) = (g + 2 ^ c, g + 2 ^ c) ∧
      g % 2 = 1 ∧ 0 < c ∧ g < 2 ^ c := by
  induction b with
  | zero => intro f h0 h1; simp at h1; omega
  | succ b ih =>
    intro f h0 h1
    rw [Nat.pow_succ] at h1 ⊢
    have hb := Nat.two_pow_pos b
    by_cases hf : f % 2 = 1
    · refine ⟨f, b + 1, strip_odd hf, ?_, hf, by omega, by rw [Nat.pow_succ]; omega⟩
      rw [strip_odd (by omega), Nat.pow_succ]
    · have hb1 : 1 ≤ b := by
        rcases b with _ | b
        · simp at h1; omega
        · omega
      obtain ⟨g, c, h1', h2', h3', h4', h5'⟩ := ih (f / 2) (by omega) (by omega)
      refine ⟨g, c, ?_, ?_, h3', h4', h5'⟩
      · rw [strip_eq]; simp only [show f % 2 = 0 by omega, show f ≠ 0 by omega, ne_eq, not_false_eq_true,
          and_self, ite_true, h1']
      · rw [strip_eq]
        simp only [show (f + 2 ^ b * 2) % 2 = 0 by omega, show f + 2 ^ b * 2 ≠ 0 by omega, ne_eq,
          not_false_eq_true, and_self, ite_true, show (f + 2 ^ b * 2) / 2 = f / 2 + 2 ^ b by omega, h2']

/-- With no hash left, the loop answers `r` exactly when `sn` is 0. -/
theorem inclusionRoot_nil (fn sn : Nat) (r : H) :
    inclusionRoot node fn sn r [] = if sn = 0 then some r else none := by
  simp [inclusionRoot]

/-- With `sn` at 0, a hash left over is refused. -/
theorem inclusionRoot_zero (fn : Nat) (r p : H) (ps : List H) : inclusionRoot node fn 0 r (p :: ps) = none := by
  simp [inclusionRoot]

theorem inclusionRoot_zero_append (fn : Nat) (r s : H) (ps : List H) :
    inclusionRoot node fn 0 r (ps ++ [s]) = none := by
  cases ps <;> simp [inclusionRoot]

/--
The leaf is in the left subtree, of `2^b` leaves, and the tree's last index `sn` is in `[2^b, 2^(b+1))`. Then the loop
runs over the left subtree as if the tree ended there, at last index `2^b - 1`, and the last hash is the right sibling.
-/
theorem inclusionRoot_left (s : H) : ∀ (ps : List H) (b fn sn : Nat) (r : H),
    fn < 2 ^ b → 2 ^ b ≤ sn → sn < 2 ^ (b + 1) →
    inclusionRoot node fn sn r (ps ++ [s]) = (inclusionRoot node fn (2 ^ b - 1) r ps).map (node · s) := by
  intro ps
  induction ps with
  | nil =>
    intro b fn sn r h1 h2 h3
    rw [Nat.pow_succ] at h3
    rcases b with _ | b
    · simp at h1 h2 h3
      have : sn = 1 := by omega
      subst h1; subst this
      simp [inclusionRoot]
    · rw [Nat.pow_succ] at h1 h2 h3 ⊢
      have hb := Nat.two_pow_pos b
      have hfs : fn ≠ sn := by omega
      simp only [List.nil_append, inclusionRoot, show sn ≠ 0 by omega, ite_false, hfs, or_false,
        show 2 ^ b * 2 - 1 ≠ 0 by omega, Option.map_none]
      split
      · rename_i hodd
        rw [strip_odd hodd]; simp only [show sn / 2 ≠ 0 by omega, ite_false]
      · simp only [show sn / 2 ≠ 0 by omega, ite_false]
  | cons p ps ih =>
    intro b fn sn r h1 h2 h3
    rw [Nat.pow_succ] at h3
    rcases b with _ | b
    · simp at h1 h2 h3
      have : sn = 1 := by omega
      subst h1; subst this
      simp [inclusionRoot, inclusionRoot_zero_append]
    · rw [Nat.pow_succ] at h1 h2 h3 ⊢
      have hb := Nat.two_pow_pos b
      have hfs : fn ≠ sn := by omega
      simp only [List.cons_append, inclusionRoot, show sn ≠ 0 by omega, ite_false, hfs, or_false,
        show 2 ^ b * 2 - 1 ≠ 0 by omega]
      by_cases hodd : fn % 2 = 1
      · simp only [hodd, true_or, ite_true, strip_odd hodd]
        rw [ih b (fn / 2) (sn / 2) (node p r) (by omega) (by omega) (by rw [Nat.pow_succ]; omega),
          show (2 ^ b * 2 - 1) / 2 = 2 ^ b - 1 by omega]
      · have : ¬ fn = 2 ^ b * 2 - 1 := by omega
        simp only [hodd, false_or, this, ite_false]
        rw [ih b (fn / 2) (sn / 2) (node r p) (by omega) (by omega) (by rw [Nat.pow_succ]; omega),
          show (2 ^ b * 2 - 1) / 2 = 2 ^ b - 1 by omega]

/--
The leaf is in the right subtree. Its index and the last index both carry the top bit `2^b`, which the right subtree
does not see. Then the loop runs over the right subtree as if that bit were not there, and the last hash is the left
sibling.
-/
theorem inclusionRoot_right (s : H) : ∀ (ps : List H) (b fn sn : Nat) (r : H), fn ≤ sn → sn < 2 ^ b →
    inclusionRoot node (fn + 2 ^ b) (sn + 2 ^ b) r (ps ++ [s]) = (inclusionRoot node fn sn r ps).map (node s ·) := by
  intro ps
  induction ps with
  | nil =>
    intro b fn sn r h1 h2
    have hb := Nat.two_pow_pos b
    by_cases hs : sn = 0
    · subst hs
      have : fn = 0 := by omega
      subst this
      simp [inclusionRoot, strip_pow]
    · rcases b with _ | b
      · simp at h2; omega
      rw [Nat.pow_succ] at h2 ⊢
      have hb := Nat.two_pow_pos b
      simp only [List.nil_append, inclusionRoot, show sn + 2 ^ b * 2 ≠ 0 by omega, ite_false, hs, Option.map_none]
      by_cases hodd : fn % 2 = 1
      · simp only [show (fn + 2 ^ b * 2) % 2 = 1 by omega, true_or, ite_true,
          strip_odd (show (fn + 2 ^ b * 2) % 2 = 1 by omega)]
        simp only [show (sn + 2 ^ b * 2) / 2 ≠ 0 by omega, ite_false]
      · by_cases he : fn = sn
        · subst he
          obtain ⟨g, c, -, h2', -, h4', -⟩ := strip_top (b + 1) fn (by omega) (by rw [Nat.pow_succ]; omega)
          rw [Nat.pow_succ] at h2'
          have hc := Nat.two_pow_pos c
          simp only [ite_true, or_true, h2']
          rcases c with _ | c
          · omega
          · rw [Nat.pow_succ]; simp only [show (g + 2 ^ c * 2) / 2 ≠ 0 by have := Nat.two_pow_pos c; omega, ite_false]
        · simp only [show ¬ (fn + 2 ^ b * 2) % 2 = 1 by omega, show ¬ fn + 2 ^ b * 2 = sn + 2 ^ b * 2 by omega,
            or_self, ite_false, show (sn + 2 ^ b * 2) / 2 ≠ 0 by omega]
  | cons p ps ih =>
    intro b fn sn r h1 h2
    have hb := Nat.two_pow_pos b
    by_cases hs : sn = 0
    · subst hs
      have : fn = 0 := by omega
      subst this
      simp [inclusionRoot, strip_pow, inclusionRoot_zero_append]
    · rcases b with _ | b
      · simp at h2; omega
      rw [Nat.pow_succ] at h2 ⊢
      have hb := Nat.two_pow_pos b
      simp only [List.cons_append, inclusionRoot, show sn + 2 ^ b * 2 ≠ 0 by omega, ite_false, hs]
      by_cases hodd : fn % 2 = 1
      · simp only [show (fn + 2 ^ b * 2) % 2 = 1 by omega, hodd, true_or, ite_true,
          strip_odd (show (fn + 2 ^ b * 2) % 2 = 1 by omega), strip_odd hodd]
        rw [show (fn + 2 ^ b * 2) / 2 = fn / 2 + 2 ^ b by omega, show (sn + 2 ^ b * 2) / 2 = sn / 2 + 2 ^ b by omega,
          ih b (fn / 2) (sn / 2) (node p r) (by omega) (by omega)]
      · by_cases he : fn = sn
        · subst he
          obtain ⟨g, c, h1', h2', h3', h4', h5'⟩ := strip_top (b + 1) fn (by omega) (by rw [Nat.pow_succ]; omega)
          rw [Nat.pow_succ] at h2'
          simp only [ite_true, or_true, h1', h2']
          rcases c with _ | c
          · omega
          · rw [Nat.pow_succ] at h5' ⊢
            rw [show (g + 2 ^ c * 2) / 2 = g / 2 + 2 ^ c by omega,
              ih c (g / 2) (g / 2) (node p r) (by omega) (by omega)]
        · simp only [show ¬ (fn + 2 ^ b * 2) % 2 = 1 by omega, show ¬ fn + 2 ^ b * 2 = sn + 2 ^ b * 2 by omega,
            hodd, he, or_self, ite_false]
          rw [show (fn + 2 ^ b * 2) / 2 = fn / 2 + 2 ^ b by omega, show (sn + 2 ^ b * 2) / 2 = sn / 2 + 2 ^ b by omega,
            ih b (fn / 2) (sn / 2) (node r p) (by omega) (by omega)]

/--
The RFC 9162 loop computes what `down` computes: for every leaf index inside the tree and every list of hashes, given
leaf first to the loop and root first to `down`.
-/
theorem inclusionRoot_eq_down : ∀ (q : List H) (i n : Nat) (x : H), i < n →
    inclusionRoot node i (n - 1) x q.reverse = down node i n x q := by
  intro q
  induction q with
  | nil =>
    intro i n x hi
    simp only [List.reverse_nil, inclusionRoot_nil, down]
    by_cases h : n ≤ 1 <;> simp [h] <;> omega
  | cons s q ih =>
    intro i n x hi
    rw [List.reverse_cons]
    by_cases h2 : n ≤ 1
    · rw [show n - 1 = 0 by omega, inclusionRoot_zero_append]; simp [down, h2]
    have ⟨hk1, hk2⟩ := split_bounds (n := n) (by omega)
    have hk0 := split_pos n
    simp only [down, h2, ite_false]
    by_cases hik : i < split n
    · simp only [hik, ite_true]
      rw [inclusionRoot_left node s q.reverse (Nat.log2 (n - 1)) i (n - 1) x (by rw [← split_eq]; omega)
        (by rw [← split_eq]; omega) (by rw [Nat.pow_succ, ← split_eq]; omega), ← split_eq, ih i (split n) x hik]
    · simp only [hik, ite_false]
      have hr := inclusionRoot_right node s q.reverse (Nat.log2 (n - 1)) (i - split n) (n - 1 - split n) x
        (by omega) (by rw [← split_eq]; omega)
      rw [← split_eq, show i - split n + split n = i by omega, show n - 1 - split n + split n = n - 1 by omega,
        show n - 1 - split n = n - split n - 1 by omega] at hr
      rw [hr, ih (i - split n) (n - split n) x (by omega)]

/-! ## Completeness and soundness of `verifyInclusion` -/

/-- Completeness: the audit path of every leaf verifies against the tree's root. -/
theorem verifyInclusion_complete [DecidableEq H] (l : List H) (i : Nat) (x : H) (hx : l[i]? = some x) :
    verifyInclusion node x i l.length (path node empty i l) (mth node empty l) = true := by
  have hi : i < l.length := (List.getElem?_eq_some_iff.mp hx).1
  have := inclusionRoot_eq_down node (path node empty i l).reverse i l.length x hi
  rw [List.reverse_reverse] at this
  simp [verifyInclusion, hi, this, down_path node empty l.length l i x rfl hx]

/--
Soundness: if the node hash is injective, a proof that `verifyInclusion` accepts against the root of the tree `l`
puts the leaf at index `i` of `l`, and is exactly the audit path of `i`.

For SHA-256 this reads: accepting a leaf that is not at index `i`, or a proof that is not the audit path, would need
two different inputs to `nodeHash` with the same digest, a SHA-256 collision.
-/
theorem verifyInclusion_sound [DecidableEq H] (hinj : ∀ a b c d, node a b = node c d → a = c ∧ b = d)
    (l : List H) (i : Nat) (x : H) (p : List H)
    (h : verifyInclusion node x i l.length p (mth node empty l) = true) :
    l[i]? = some x ∧ p = path node empty i l := by
  simp only [verifyInclusion, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at h
  obtain ⟨hi, h⟩ := h
  have e := inclusionRoot_eq_down node p.reverse i l.length x hi
  rw [List.reverse_reverse, h] at e
  obtain ⟨h1, h2⟩ := down_sound node empty hinj p.reverse l i x hi e.symm
  exact ⟨h1, by rw [← List.reverse_reverse p, h2, List.reverse_reverse]⟩

end AgentCustodySpec.Merkle
