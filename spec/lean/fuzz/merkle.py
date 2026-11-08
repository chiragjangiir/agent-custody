"""The Python verifier's verdict on each Merkle check that `merkle.ts` writes: JSON lines in, `accept` or `refuse` out.

It calls what `agent_custody.verify` calls on a bundle and on `audit extends`: the hex checks of `_hashes` and `HEX64`,
then `root_from_inclusion` or `verify_consistency`. Run it through `merkle.ts`, or by hand from spec/lean:

    uv run --project ../../packages/python --extra verify --inexact python fuzz/merkle.py < cases.jsonl
"""

import json
import sys

from agent_custody import verify


def root_ok(value):
    return isinstance(value, str) and bool(verify.HEX64.fullmatch(value))


def verdict(case):
    hashes = verify._hashes(case["hashes"])
    if hashes is None:
        return False
    if case["kind"] == "inclusion":
        if not root_ok(case["root"]):
            return False
        root = verify.root_from_inclusion(case["leafIndex"], case["treeSize"], bytes.fromhex(case["leaf"]), hashes)
        return root is not None and root.hex() == case["root"]
    if case["kind"] == "consistency":
        if not (root_ok(case["oldRoot"]) and root_ok(case["newRoot"])):
            return False
        old, new = bytes.fromhex(case["oldRoot"]), bytes.fromhex(case["newRoot"])
        return verify.verify_consistency(case["oldSize"], case["newSize"], old, new, hashes)
    raise ValueError(f"kind {case['kind']}: neither inclusion nor consistency")


def main():
    out = []
    for line in sys.stdin:
        if line.strip():
            out.append("accept" if verdict(json.loads(line)) else "refuse")
    sys.stdout.write("".join(f"{v}\n" for v in out))


if __name__ == "__main__":
    main()
