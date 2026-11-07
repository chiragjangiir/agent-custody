#!/bin/sh
# Prints the axioms of each theorem in Axioms.lean and fails unless every one depends only on propext,
# Classical.choice and Quot.sound, and every theorem the file names was printed. Run from spec/lean after `lake build`.
set -eu
out=$(lake env lean Axioms.lean)
echo "$out"
want=$(grep -c '^#print axioms' Axioms.lean)
got=$(echo "$out" | grep -c "depends on axioms\|does not depend on any axioms" || true)
[ "$got" -eq "$want" ] || { echo "expected $want theorems, $got printed"; exit 1; }
extra=$(echo "$out" | grep "depends on axioms" | sed 's/.*depends on axioms: \[\(.*\)\]/\1/' | tr ',' '\n' | tr -d ' ' | grep -v -x -e propext -e Classical.choice -e Quot.sound || true)
[ -z "$extra" ] || { echo "a theorem depends on another axiom: $extra"; exit 1; }
echo "every theorem depends only on propext, Classical.choice and Quot.sound"
