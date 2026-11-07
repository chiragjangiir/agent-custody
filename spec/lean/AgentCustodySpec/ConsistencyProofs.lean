/-
Proofs about the consistency check of RFC 9162 section 2.1.4, as `Merkle.lean` models it from `log.ts`.

The plan is the one of `MerkleProofs.lean`. `downC` reads a consistency proof from the root down, following the split
of `mth`, and computes the old and the new root. The verification loop is shown to compute the same pair. Soundness is
then a structural induction on `downC`: an old root that the check accepts is the root of the first `m` leaves of the
new tree.
-/
import AgentCustodySpec.MerkleProofs

namespace AgentCustodySpec.Merkle

/-- A size strictly between `split n` and `n` splits where `n` does. -/
theorem split_of_between {m n : Nat} (h2 : 2 ≤ n) (h1 : split n < m) (h3 : m ≤ n) : split m = split n := by
  have ⟨hk1, hk2⟩ := split_bounds (n := n) h2
  unfold split at *
  congr 1
  rw [Nat.log2_eq_iff (by omega)]
  have := Nat.log2_self_le (n := n - 1) (by omega)
  have := Nat.lt_log2_self (n := n - 1)
  rw [Nat.pow_succ] at this ⊢
  omega

variable {H : Type} (node : H → H → H) (empty : H)

/--
The old and the new root that the consistency proof `q`, given root first, leads to, for an old tree of `m` leaves
inside a new tree of `n`. At the subtree that the old tree fills exactly (`m = n`), the proof gives that subtree's
root, which is both an old and a new root. `log.ts` leaves that hash out of the proof when the old size is a power of
two, and puts the old root in its place.
-/
def downC (m n : Nat) : List H → Option (H × H)
  | [] => none
  | s :: q =>
    if m = n then (if q = [] then some (s, s) else none)
    else if m ≤ split n then (downC m (split n) q).map (fun p => (p.1, node p.2 s))
    else (downC (m - split n) (n - split n) q).map (fun p => (node s p.1, node s p.2))

/--
Soundness of `downC`: if the node hash is injective, an old root that a consistency proof leads to, together with the
root of the tree `l`, is the root of the first `m` leaves of `l`.
-/
theorem downC_sound (hinj : ∀ a b c d, node a b = node c d → a = c ∧ b = d) :
    ∀ (q l : List H) (m : Nat) (o : H), 0 < m → m ≤ l.length →
      downC node m l.length q = some (o, mth node empty l) → o = mth node empty (l.take m) := by
  intro q
  induction q with
  | nil => intro l m o _ _ h; simp [downC] at h
  | cons s q ih =>
    intro l m o h0 hm h
    by_cases he : m = l.length
    · subst he
      simp only [downC, ite_true] at h
      split at h
      · simp at h; rw [List.take_length]; exact h.1.symm.trans h.2
      · simp at h
    have hn : 2 ≤ l.length := by
      rcases l with _ | ⟨a, _ | ⟨b, l⟩⟩ <;> simp at hm he ⊢ <;> omega
    have ⟨hk1, hk2⟩ := split_bounds (n := l.length) hn
    have hk0 := split_pos l.length
    rw [mth_split node empty hn] at h
    by_cases hmk : m ≤ split l.length
    · simp only [downC, he, hmk, ite_true, ite_false, Option.map_eq_some_iff] at h
      obtain ⟨⟨o', w⟩, hr, he'⟩ := h
      simp only [Prod.mk.injEq] at he'
      obtain ⟨rfl, he2⟩ := he'
      obtain ⟨rfl, rfl⟩ := hinj _ _ _ _ he2
      have := ih (l.take (split l.length)) m o' h0 (by simp; omega)
        (by rw [List.length_take, Nat.min_eq_left (by omega)]; exact hr)
      rw [this, List.take_take, Nat.min_eq_left hmk]
    · simp only [downC, he, hmk, ite_false, Option.map_eq_some_iff] at h
      obtain ⟨⟨o', w⟩, hr, he'⟩ := h
      simp only [Prod.mk.injEq] at he'
      obtain ⟨rfl, he2⟩ := he'
      obtain ⟨rfl, rfl⟩ := hinj _ _ _ _ he2
      have := ih (l.drop (split l.length)) (m - split l.length) o' (by omega) (by simp; omega)
        (by rw [List.length_drop]; exact hr)
      have hlen : (l.take m).length = m := by simp; omega
      have hsm : split m = split l.length := split_of_between hn (by omega) hm
      rw [mth_split node empty (l := l.take m) (by rw [hlen]; omega)]
      rw [hlen, hsm, List.take_take, Nat.min_eq_left (by omega), this, List.drop_take]

/-! ## The consistency loop -/

theorem consistencyRoots_zero_append (fn : Nat) (fr sr s : H) (ps : List H) :
    consistencyRoots node fn 0 fr sr (ps ++ [s]) = none := by
  cases ps <;> simp [consistencyRoots]

/-- As `inclusionRoot_left`: the old tree ends inside the left subtree, whose new root then meets its right sibling. -/
theorem consistencyRoots_left (s : H) : ∀ (ps : List H) (b fn sn : Nat) (fr sr : H),
    fn < 2 ^ b → 2 ^ b ≤ sn → sn < 2 ^ (b + 1) →
    consistencyRoots node fn sn fr sr (ps ++ [s]) =
      (consistencyRoots node fn (2 ^ b - 1) fr sr ps).map (fun p => (p.1, node p.2 s)) := by
  intro ps
  induction ps with
  | nil =>
    intro b fn sn fr sr h1 h2 h3
    rw [Nat.pow_succ] at h3
    rcases b with _ | b
    · simp at h1 h2 h3
      have : sn = 1 := by omega
      subst h1; subst this
      simp [consistencyRoots]
    · rw [Nat.pow_succ] at h1 h2 h3 ⊢
      have hb := Nat.two_pow_pos b
      have hfs : fn ≠ sn := by omega
      simp only [List.nil_append, consistencyRoots, show sn ≠ 0 by omega, ite_false, hfs, or_false,
        show 2 ^ b * 2 - 1 ≠ 0 by omega, Option.map_none]
      split
      · rename_i hodd
        rw [strip_odd hodd]; simp only [show sn / 2 ≠ 0 by omega, ite_false]
      · simp only [show sn / 2 ≠ 0 by omega, ite_false]
  | cons p ps ih =>
    intro b fn sn fr sr h1 h2 h3
    rw [Nat.pow_succ] at h3
    rcases b with _ | b
    · simp at h1 h2 h3
      have : sn = 1 := by omega
      subst h1; subst this
      simp [consistencyRoots, consistencyRoots_zero_append]
    · rw [Nat.pow_succ] at h1 h2 h3 ⊢
      have hb := Nat.two_pow_pos b
      have hfs : fn ≠ sn := by omega
      simp only [List.cons_append, consistencyRoots, show sn ≠ 0 by omega, ite_false, hfs, or_false,
        show 2 ^ b * 2 - 1 ≠ 0 by omega]
      by_cases hodd : fn % 2 = 1
      · simp only [hodd, true_or, ite_true, strip_odd hodd]
        rw [ih b (fn / 2) (sn / 2) _ _ (by omega) (by omega) (by rw [Nat.pow_succ]; omega),
          show (2 ^ b * 2 - 1) / 2 = 2 ^ b - 1 by omega]
      · have : ¬ fn = 2 ^ b * 2 - 1 := by omega
        simp only [hodd, false_or, this, ite_false]
        rw [ih b (fn / 2) (sn / 2) _ _ (by omega) (by omega) (by rw [Nat.pow_succ]; omega),
          show (2 ^ b * 2 - 1) / 2 = 2 ^ b - 1 by omega]

/-- As `inclusionRoot_right`: the old tree covers the left subtree, which is the left sibling of both roots. -/
theorem consistencyRoots_right (s : H) : ∀ (ps : List H) (b fn sn : Nat) (fr sr : H), fn ≤ sn → sn < 2 ^ b →
    consistencyRoots node (fn + 2 ^ b) (sn + 2 ^ b) fr sr (ps ++ [s]) =
      (consistencyRoots node fn sn fr sr ps).map (fun p => (node s p.1, node s p.2)) := by
  intro ps
  induction ps with
  | nil =>
    intro b fn sn fr sr h1 h2
    have hb := Nat.two_pow_pos b
    by_cases hs : sn = 0
    · subst hs
      have : fn = 0 := by omega
      subst this
      simp [consistencyRoots, strip_pow]
    · rcases b with _ | b
      · simp at h2; omega
      rw [Nat.pow_succ] at h2 ⊢
      have hb := Nat.two_pow_pos b
      simp only [List.nil_append, consistencyRoots, show sn + 2 ^ b * 2 ≠ 0 by omega, ite_false, hs,
        Option.map_none]
      by_cases hodd : fn % 2 = 1
      · simp only [show (fn + 2 ^ b * 2) % 2 = 1 by omega, true_or, ite_true,
          strip_odd (show (fn + 2 ^ b * 2) % 2 = 1 by omega)]
        simp only [show (sn + 2 ^ b * 2) / 2 ≠ 0 by omega, ite_false]
      · by_cases he : fn = sn
        · subst he
          obtain ⟨g, c, -, h2', -, h4', -⟩ := strip_top (b + 1) fn (by omega) (by rw [Nat.pow_succ]; omega)
          rw [Nat.pow_succ] at h2'
          simp only [ite_true, or_true, h2']
          rcases c with _ | c
          · omega
          · rw [Nat.pow_succ]; simp only [show (g + 2 ^ c * 2) / 2 ≠ 0 by have := Nat.two_pow_pos c; omega, ite_false]
        · simp only [show ¬ (fn + 2 ^ b * 2) % 2 = 1 by omega, show ¬ fn + 2 ^ b * 2 = sn + 2 ^ b * 2 by omega,
            or_self, ite_false, show (sn + 2 ^ b * 2) / 2 ≠ 0 by omega]
  | cons p ps ih =>
    intro b fn sn fr sr h1 h2
    have hb := Nat.two_pow_pos b
    by_cases hs : sn = 0
    · subst hs
      have : fn = 0 := by omega
      subst this
      simp [consistencyRoots, strip_pow, consistencyRoots_zero_append]
    · rcases b with _ | b
      · simp at h2; omega
      rw [Nat.pow_succ] at h2 ⊢
      have hb := Nat.two_pow_pos b
      simp only [List.cons_append, consistencyRoots, show sn + 2 ^ b * 2 ≠ 0 by omega, ite_false, hs]
      by_cases hodd : fn % 2 = 1
      · simp only [show (fn + 2 ^ b * 2) % 2 = 1 by omega, hodd, true_or, ite_true,
          strip_odd (show (fn + 2 ^ b * 2) % 2 = 1 by omega), strip_odd hodd]
        rw [show (fn + 2 ^ b * 2) / 2 = fn / 2 + 2 ^ b by omega, show (sn + 2 ^ b * 2) / 2 = sn / 2 + 2 ^ b by omega,
          ih b (fn / 2) (sn / 2) _ _ (by omega) (by omega)]
      · by_cases he : fn = sn
        · subst he
          obtain ⟨g, c, h1', h2', h3', h4', h5'⟩ := strip_top (b + 1) fn (by omega) (by rw [Nat.pow_succ]; omega)
          rw [Nat.pow_succ] at h2'
          simp only [ite_true, or_true, h1', h2']
          rcases c with _ | c
          · omega
          · rw [Nat.pow_succ] at h5' ⊢
            rw [show (g + 2 ^ c * 2) / 2 = g / 2 + 2 ^ c by omega,
              ih c (g / 2) (g / 2) _ _ (by omega) (by omega)]
        · simp only [show ¬ (fn + 2 ^ b * 2) % 2 = 1 by omega, show ¬ fn + 2 ^ b * 2 = sn + 2 ^ b * 2 by omega,
            hodd, he, or_self, ite_false]
          rw [show (fn + 2 ^ b * 2) / 2 = fn / 2 + 2 ^ b by omega, show (sn + 2 ^ b * 2) / 2 = sn / 2 + 2 ^ b by omega,
            ih b (fn / 2) (sn / 2) _ _ (by omega) (by omega)]

/-! ## Where the loop starts -/

theorem stripOdd_eq (fn sn : Nat) :
    stripOdd fn sn = if fn % 2 = 1 then stripOdd (fn / 2) (sn / 2) else (fn, sn) := by
  rw [stripOdd]

/-- `fn` ending in `c` one bits above an even `q` strips to `q`, and `sn` loses the same `c` bits. -/
theorem stripOdd_of_trailing : ∀ (c q fn sn : Nat), fn = q * 2 ^ c + (2 ^ c - 1) → q % 2 = 0 →
    stripOdd fn sn = (q, sn / 2 ^ c) := by
  intro c
  induction c with
  | zero => intro q fn sn h hq; subst h; rw [stripOdd_eq]; simp [hq]
  | succ c ih =>
    intro q fn sn h hq
    have hc := Nat.two_pow_pos c
    rw [Nat.pow_succ, ← Nat.mul_assoc] at h
    rw [stripOdd_eq, ite_eq_left (show fn % 2 = 1 by omega), ih q (fn / 2) (sn / 2) (by omega) hq,
      Nat.div_div_eq_div_mul, Nat.pow_succ, Nat.mul_comm 2]

/-- Every number is an even `q`, shifted up by `c`, with `c` one bits below. -/
theorem trailing_exists (fn : Nat) : ∃ c q, fn = q * 2 ^ c + (2 ^ c - 1) ∧ q % 2 = 0 := by
  induction fn using Nat.strongRecOn with
  | ind fn ih =>
  by_cases h : fn % 2 = 1
  · obtain ⟨c, q, hq, he⟩ := ih (fn / 2) (by omega)
    refine ⟨c + 1, q, ?_, he⟩
    have hc := Nat.two_pow_pos c
    rw [Nat.pow_succ, ← Nat.mul_assoc]
    omega
  · exact ⟨0, fn, by simp, by omega⟩

/-- The consistency loop from its start: the first hash at the node where `stripOdd` leaves the old tree's last index. -/
def iterC (m n : Nat) : List H → Option (H × H)
  | [] => none
  | first :: rest => consistencyRoots node (stripOdd (m - 1) (n - 1)).1 (stripOdd (m - 1) (n - 1)).2 first first rest

theorem pow_split {a c : Nat} (h : c ≤ a) : 2 ^ a = 2 ^ (a - c) * 2 ^ c := by
  rw [← Nat.pow_add, Nat.sub_add_cancel h]

/-- `x`, ending in `c` one bits, is below `2^a - 1`: then `c < a`. -/
theorem trailing_lt {a c q x : Nat} (hx : x = q * 2 ^ c + (2 ^ c - 1)) (hxa : x + 1 < 2 ^ a) : c < a := by
  apply Nat.lt_of_not_le
  intro h
  have := Nat.pow_le_pow_right (n := 2) (by omega) h
  have := Nat.two_pow_pos c
  omega

/-- The arithmetic of the left case: the old tree ends inside the left subtree of `2^a` leaves. -/
theorem left_bounds {a c q x y : Nat} (hx : x = q * 2 ^ c + (2 ^ c - 1)) (hxa : x + 1 < 2 ^ a)
    (hy1 : 2 ^ a ≤ y) (hy2 : y < 2 ^ (a + 1)) :
    q < 2 ^ (a - c) ∧ 2 ^ (a - c) ≤ y / 2 ^ c ∧ y / 2 ^ c < 2 ^ (a - c + 1) ∧
      (2 ^ a - 1) / 2 ^ c = 2 ^ (a - c) - 1 := by
  have hca := trailing_lt hx hxa
  have e := pow_split (Nat.le_of_lt hca)
  have hP := Nat.two_pow_pos c
  have hQ := Nat.two_pow_pos (a - c)
  have e1 : 2 ^ (a - c + 1) * 2 ^ c = 2 ^ (a + 1) := by
    rw [← Nat.pow_add, show a - c + 1 + c = a + 1 by omega]
  refine ⟨?_, ?_, ?_, ?_⟩
  · apply Nat.lt_of_mul_lt_mul_right (a := 2 ^ c); omega
  · rw [Nat.le_div_iff_mul_le hP]; omega
  · rw [Nat.div_lt_iff_lt_mul hP]; omega
  · apply Nat.div_eq_of_lt_le
    · rw [Nat.sub_one_mul]; omega
    · rw [Nat.sub_add_cancel (by omega)]; omega

/-- The arithmetic of the right case: the old tree covers the left subtree and ends at `x` past it. -/
theorem right_bounds {a c q x y : Nat} (hx : x = q * 2 ^ c + (2 ^ c - 1)) (hq : q % 2 = 0) (hxy : x ≤ y)
    (hy : y < 2 ^ a) (hxa : x + 1 < 2 ^ a) :
    x + 2 ^ a = (q + 2 ^ (a - c)) * 2 ^ c + (2 ^ c - 1) ∧ (q + 2 ^ (a - c)) % 2 = 0 ∧
      (y + 2 ^ a) / 2 ^ c = y / 2 ^ c + 2 ^ (a - c) ∧ q ≤ y / 2 ^ c ∧ y / 2 ^ c < 2 ^ (a - c) := by
  have hca := trailing_lt hx hxa
  have e := pow_split (Nat.le_of_lt hca)
  have hP := Nat.two_pow_pos c
  have hQ : 2 ^ (a - c) = 2 ^ (a - c - 1) * 2 := by rw [← Nat.pow_succ]; congr 1; omega
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · rw [Nat.add_mul]; omega
  · omega
  · rw [e, Nat.add_mul_div_right _ _ hP]
  · rw [Nat.le_div_iff_mul_le hP]; omega
  · rw [Nat.div_lt_iff_lt_mul hP]; omega

/-- A list of two or more hashes is too long for an old tree that fills its subtree. -/
theorem downC_long (m : Nat) (L : List H) (h : 2 ≤ L.length) : downC node m m L = none := by
  match L, h with
  | _ :: _ :: _, _ => simp [downC]

/-- The consistency loop computes what `downC` computes, for every list of hashes and `0 < m < n`. -/
theorem iterC_eq_downC : ∀ (q : List H) (m n : Nat), 0 < m → m < n →
    iterC node m n q.reverse = downC node m n q := by
  intro q
  induction q with
  | nil => intro m n _ _; simp [iterC, downC]
  | cons s q ih =>
    intro m n h0 hmn
    have hn : 2 ≤ n := by omega
    have ⟨hk1, hk2⟩ := split_bounds (n := n) hn
    obtain ⟨a, ha⟩ : ∃ a, split n = 2 ^ a := ⟨_, split_eq n⟩
    have hA := Nat.two_pow_pos a
    have hk2' : n - 1 < 2 ^ (a + 1) := by rw [Nat.pow_succ]; omega
    rw [List.reverse_cons]
    simp only [downC, show m ≠ n by omega, ite_false]
    rw [ha] at hk1 hk2 ⊢
    rcases hq : q.reverse with _ | ⟨first, rest⟩
    · have : q = [] := List.reverse_eq_nil_iff.mp hq
      subst this
      obtain ⟨c, qq, hm1, hqe⟩ := trailing_exists (m - 1)
      have hP := Nat.two_pow_pos c
      have hne : (n - 1) / 2 ^ c ≠ 0 := by
        have : 1 ≤ (n - 1) / 2 ^ c := by rw [Nat.le_div_iff_mul_le hP]; omega
        omega
      simp only [List.nil_append, iterC, stripOdd_of_trailing c qq (m - 1) (n - 1) hm1 hqe, consistencyRoots, hne,
        ite_false]
      split <;> simp [downC]
    · have hq' : q = (first :: rest).reverse := by rw [← hq, List.reverse_reverse]
      by_cases hmk : m ≤ 2 ^ a
      · simp only [hmk, ite_true]
        by_cases hmeq : m = 2 ^ a
        · -- the old tree is the whole left subtree, a power of two
          have h1 : (n - 1) / 2 ^ a = 1 := by
            apply Nat.div_eq_of_lt_le <;> rw [Nat.pow_succ] at hk2' <;> omega
          simp only [List.cons_append, iterC,
            stripOdd_of_trailing a 0 (m - 1) (n - 1) (by omega) (by rfl), h1]
          rw [consistencyRoots_left node s rest 0 0 1 first first (by simp) (by simp) (by simp)]
          simp only [Nat.pow_zero, Nat.sub_self]
          rw [← hmeq]
          congr 1
          rcases rest with _ | ⟨r, rs⟩
          · rw [hq']; simp [consistencyRoots, downC]
          · rw [show consistencyRoots node 0 0 first first (r :: rs) = none by simp [consistencyRoots],
              downC_long node m q (by rw [hq']; simp)]
        · -- the old tree ends inside the left subtree
          obtain ⟨c, qq, hm1, hqe⟩ := trailing_exists (m - 1)
          have ⟨b1, b2, b3, b4⟩ := left_bounds (y := n - 1) hm1 (by omega) hk1 hk2'
          simp only [List.cons_append, iterC, stripOdd_of_trailing c qq (m - 1) (n - 1) hm1 hqe]
          rw [consistencyRoots_left node s rest (a - c) qq ((n - 1) / 2 ^ c) first first b1 b2 b3,
            ← ih m (2 ^ a) h0 (by omega), hq]
          simp only [iterC, stripOdd_of_trailing c qq (m - 1) (2 ^ a - 1) hm1 hqe, b4]
      · -- the old tree covers the left subtree
        simp only [hmk, ite_false]
        obtain ⟨c, qq, hx, hqe⟩ := trailing_exists (m - 1 - 2 ^ a)
        have ⟨r1, r2, r3, r4, r5⟩ := right_bounds (a := a) (y := n - 1 - 2 ^ a) hx hqe (by omega) (by omega) (by omega)
        simp only [List.cons_append, iterC,
          stripOdd_of_trailing c (qq + 2 ^ (a - c)) (m - 1) (n - 1)
            (by rw [← r1]; omega) r2]
        rw [show (n - 1) / 2 ^ c = (n - 1 - 2 ^ a) / 2 ^ c + 2 ^ (a - c) by
              rw [← r3, show n - 1 - 2 ^ a + 2 ^ a = n - 1 by omega],
          consistencyRoots_right node s rest (a - c) qq ((n - 1 - 2 ^ a) / 2 ^ c) first first r4 r5,
          ← ih (m - 2 ^ a) (n - 2 ^ a) (by omega) (by omega), hq]
        simp only [iterC, show m - 2 ^ a - 1 = m - 1 - 2 ^ a by omega, show n - 2 ^ a - 1 = n - 1 - 2 ^ a by omega,
          stripOdd_of_trailing c qq (m - 1 - 2 ^ a) (n - 1 - 2 ^ a) hx hqe]

/-! ## Soundness of `verifyConsistency` -/

/--
Soundness: if the node hash is injective, an old root that `verifyConsistency` accepts against the root of the tree
`l`, for an old size `m ≤ l.length`, is the root of the first `m` leaves of `l`. A log cannot show a head that the check
takes as extending an old head unless the old tree is a prefix of the new one. At `m = 0` that root is the empty
tree's root.

For SHA-256 this reads: an accepted old root that is not the root of the prefix needs a SHA-256 collision.
-/
theorem verifyConsistency_sound [DecidableEq H] (hinj : ∀ a b c d, node a b = node c d → a = c ∧ b = d)
    (l : List H) (m : Nat) (r0 : H) (p : List H) (hm : m ≤ l.length)
    (h : verifyConsistency node empty m r0 l.length (mth node empty l) p = true) :
    r0 = mth node empty (l.take m) := by
  unfold verifyConsistency at h
  by_cases h0 : m = 0
  · subst h0
    simp only [show ¬ 0 > l.length by omega, ite_false, ite_true, Bool.and_eq_true, beq_iff_eq] at h
    rw [List.take_zero, mth_nil]; exact h.1.2
  by_cases he : m = l.length
  · subst he
    simp [h0] at h
    rw [List.take_length]; exact h.2
  simp only [show ¬ m > l.length by omega, he, h0, ite_false] at h
  rcases p with _ | ⟨p0, ps⟩
  · simp at h
  simp only [List.isEmpty_cons] at h
  -- the hashes the loop reads, with the old root in front when the old size is a power of two
  generalize hP : (if m % 4294967296 &&& (m - 1) % 4294967296 = 0 then r0 :: p0 :: ps else p0 :: ps) = P at h
  have hne : P ≠ [] := by rw [← hP]; split <;> simp
  have hloop : iterC node m l.length P = some (r0, mth node empty l) := by
    match P, hne with
    | first :: rest, _ => simpa [iterC] using h
  rw [← List.reverse_reverse P, iterC_eq_downC node P.reverse m l.length (by omega) (by omega)] at hloop
  exact downC_sound node empty hinj P.reverse l m r0 (by omega) hm hloop

end AgentCustodySpec.Merkle
