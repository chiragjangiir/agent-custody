"""Receipt verification, written from the receipt specification v0.2 (site/receipt/v0.2.md).

This module shares no code with the TypeScript verifiers. It reads a bundle, the
public keys a verifier trusts, and optionally a copy of the log, and reports
every check by the name the specification gives it.

    python -m agent_custody.verify receipts/<id>.json --issuer-key gateway.pub --principal-key principal.pub
"""

from __future__ import annotations

import argparse
import base64
import binascii
import calendar
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

RECEIPT_PREDICATE = "https://agent-custody.dev/receipt/v0.2"
AUTHORIZATION_PREDICATE = "https://agent-custody.dev/authorization/v0.1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
IN_TOTO = "application/vnd.in-toto+json"
TREEHEAD = "application/vnd.agent-custody.treehead+json"
DELEGATION = "application/vnd.agent-custody.delegation+json"
APPROVAL = "application/vnd.agent-custody.approval+json"
UPSTREAM = "application/vnd.agent-custody.upstream+json"

FORWARDED = ("executed", "failed", "error")


# Addresses that are not the public internet; the same list as packages/receipts/src/addresses.ts.
_INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
    "64:ff9b:1::/48")]
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _address(ip: str):
    """The address, with an IPv4-mapped one as IPv4, or None when it is not an address."""
    try:
        addr = ipaddress.ip_address(ip.strip("[]").split("%")[0])
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _internal_address(ip: str) -> bool:
    """True when ip is not a public address, or not an address at all."""
    addr = _address(ip)
    if addr is None:
        return True
    if addr.version == 6 and addr in _NAT64:
        # a DNS64 answer can wrap an internal IPv4 address
        addr = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    return any(addr.version == n.version and addr in n for n in _INTERNAL_NETWORKS)
STATUSES = ("executed", "failed", "denied", "error", "withheld")
MAX_CHAIN_DEPTH = 3
STRIPE_TOLERANCE_SECONDS = 300
MAX_SAFE_INTEGER = 2**53 - 1

HEX64 = re.compile(r"^[0-9a-f]{64}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
INSTANT = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$"
)


# Canonical JSON and digests


ARRAY_INDEX = re.compile(r"^(0|[1-9][0-9]*)$")


def _is_index(key: str) -> bool:
    return bool(ARRAY_INDEX.match(key)) and int(key) < 2**32 - 1


def _key_order(keys: Iterable[str]) -> list[str]:
    """Array-index keys first in numeric order, then the rest by UTF-16 code unit: the order JSON.stringify emits
    for keys inserted sorted, which is what the v0.2 producer hashes."""
    indexes = sorted((k for k in keys if _is_index(k)), key=int)
    rest = sorted((k for k in keys if not _is_index(k)), key=lambda k: k.encode("utf-16-be", "surrogatepass"))
    return indexes + rest


def _number(value: float) -> str:
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("JSON has no NaN or Infinity")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    mantissa, _, exponent = repr(abs(value)).partition("e")
    whole, _, fraction = mantissa.partition(".")
    all_digits = whole + fraction
    stripped = all_digits.lstrip("0")
    n = len(whole) + int(exponent or 0) - (len(all_digits) - len(stripped))
    digits = stripped.rstrip("0")
    k = len(digits)
    if k <= n <= 21:
        text = digits + "0" * (n - k)
    elif 0 < n <= 21:
        text = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        text = "0." + "0" * -n + digits
    else:
        e = n - 1
        text = (digits[0] + ("." + digits[1:] if k > 1 else "")) + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + text


def _string(value: str) -> str:
    text = json.dumps(value, ensure_ascii=False)
    return re.sub(r"[\ud800-\udfff]", lambda m: "\\u%04x" % ord(m.group()), text)


def canonical_json(value: Any) -> str:
    """No whitespace, keys in the producer's order, numbers as ECMAScript prints them (integers beyond 2^53 as the
    double a JavaScript parser reads)."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value) if abs(value) <= MAX_SAFE_INTEGER else _number(float(value))
    if isinstance(value, float):
        return _number(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(_string(k) + ":" + canonical_json(value[k]) for k in _key_order(value)) + "}"
    raise TypeError(f"not a JSON value: {type(value).__name__}")


def _utf8(text: str) -> bytes:
    return text.encode("utf-8", "surrogatepass")


def digest(value: Any) -> str:
    return hashlib.sha256(_utf8(canonical_json(value))).hexdigest()


def _strict_object(pairs: list) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def parse_json(data: bytes | str) -> Any:
    return json.loads(data, object_pairs_hook=_strict_object)


# Keys and DSSE


@dataclass(frozen=True)
class PublicKey:
    keyid: str
    key: Ed25519PublicKey


def load_public_key(pem: str | bytes) -> PublicKey:
    key = serialization.load_pem_public_key(pem.encode() if isinstance(pem, str) else pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("not an Ed25519 public key")
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return PublicKey(hashlib.sha256(der).hexdigest(), key)


def pae(payload_type: str, payload: bytes) -> bytes:
    t = _utf8(payload_type)
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def _b64(text: Any) -> Optional[bytes]:
    if not isinstance(text, str):
        return None
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None


def _is_envelope(env: Any) -> bool:
    return (
        isinstance(env, dict)
        and isinstance(env.get("payloadType"), str)
        and isinstance(env.get("payload"), str)
        and isinstance(env.get("signatures"), list)
        and all(isinstance(s, dict) and isinstance(s.get("keyid"), str) and isinstance(s.get("sig"), str) for s in env["signatures"])
    )


def dsse_signers(env: Any, keys: Iterable[PublicKey]) -> list[str]:
    """Keyids of the given keys whose signature on the envelope verifies, each once."""
    if not _is_envelope(env):
        return []
    payload = _b64(env["payload"])
    if payload is None:
        return []
    message = pae(env["payloadType"], payload)
    by_id = {k.keyid: k for k in keys}
    found: list[str] = []
    for sig in env["signatures"]:
        key = by_id.get(sig["keyid"])
        raw = _b64(sig["sig"])
        if key is None or raw is None or key.keyid in found:
            continue
        try:
            key.key.verify(raw, message)
        except InvalidSignature:
            continue
        found.append(key.keyid)
    return found


def dsse_payload(env: Any) -> Any:
    if not _is_envelope(env):
        return None
    payload = _b64(env["payload"])
    if payload is None:
        return None
    try:
        return parse_json(payload)
    except ValueError:
        return None


# Merkle tree, RFC 6962 hashing, RFC 9162 proofs


def leaf_hash(leaf: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + leaf).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def tree_root(leaf_hashes: list[bytes]) -> bytes:
    n = len(leaf_hashes)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hashes[0]
    k = 1
    while k * 2 < n:
        k *= 2
    return node_hash(tree_root(leaf_hashes[:k]), tree_root(leaf_hashes[k:]))


def _digests(*values: Any) -> bool:
    """Every value is 32 bytes. With children of other widths, sha256(0x01 || left || right) no longer fixes where one
    child ends and the other begins, so a 16-byte leaf and a 48-byte sibling hash like the real 32-byte children."""
    return all(isinstance(v, (bytes, bytearray)) and len(v) == 32 for v in values)


def root_from_inclusion(index: int, size: int, leaf: bytes, proof: list[bytes]) -> Optional[bytes]:
    if not (_is_size(index) and _is_size(size)) or not 0 <= index < size:
        return None
    if not isinstance(proof, list) or not _digests(leaf, *proof):
        return None
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return None
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return r if sn == 0 else None


def verify_consistency(old_size: int, new_size: int, old_root: bytes, new_root: bytes, proof: list[bytes]) -> bool:
    if not (_is_size(old_size) and _is_size(new_size)) or old_size > new_size:
        return False
    if not isinstance(proof, list) or not _digests(old_root, new_root, *proof):
        return False
    # the empty tree has one root, sha256 of nothing; any other root at size 0, old or new, is a head no log could have signed
    empty = hashlib.sha256(b"").digest()
    if old_size == 0:
        return not proof and old_root == empty and (new_size > 0 or new_root == empty)
    if old_size == new_size:
        return not proof and old_root == new_root
    if not proof:
        return False
    path = list(proof)
    if old_size & (old_size - 1) == 0:
        path.insert(0, old_root)
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == old_root and sr == new_root and sn == 0


def _hashes(values: Any) -> Optional[list[bytes]]:
    if not isinstance(values, list) or not all(isinstance(h, str) and HEX64.fullmatch(h) for h in values):
        return None
    return [bytes.fromhex(h) for h in values]


def _is_size(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_inclusion(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and _is_size(value.get("leafIndex"))
        and _is_size(value.get("treeSize"))
        and _hashes(value.get("hashes")) is not None
    )


# Time


def parse_instant(text: Any) -> Optional[float]:
    """Seconds since the epoch for an ISO 8601 time with an offset, or None."""
    if not isinstance(text, str):
        return None
    m = INSTANT.match(text)
    if not m:
        return None
    year, month, day, hour, minute, second = (int(g) for g in m.groups()[:6])
    if not (1 <= month <= 12 and 1 <= day <= calendar.monthrange(year, month)[1]):
        return None
    if hour > 23 or minute > 59 or second > 59:
        return None
    seconds = calendar.timegm((year, month, day, hour, minute, second, 0, 0, 0))
    seconds += float("0." + m.group(7)) if m.group(7) else 0.0
    zone = m.group(8)
    if zone != "Z":
        hours, minutes = int(zone[1:3]), int(zone[4:6])
        if hours > 23 or minutes > 59:
            return None
        offset = hours * 3600 + minutes * 60
        seconds -= offset if zone[0] == "+" else -offset
    return seconds


# Commitments and the capture note


def is_commitment(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    kind = value.get("$custody")
    if not isinstance(value.get("sha256"), str) or not HEX64.fullmatch(value["sha256"]):
        return False
    if kind == "withheld":
        return set(value) == {"$custody", "sha256"}
    if kind == "encrypted":
        if set(value) != {"$custody", "alg", "keyid", "iv", "ciphertext", "tag", "sha256"}:
            return False
        iv, tag, ciphertext = _b64(value["iv"]), _b64(value["tag"]), _b64(value["ciphertext"])
        return (
            value["alg"] == "A256GCM"
            and isinstance(value["keyid"], str)
            and bool(HEX64.fullmatch(value["keyid"]))
            and iv is not None
            and len(iv) == 12
            and tag is not None
            and len(tag) == 16
            and ciphertext is not None
        )
    return False


_MISSING = object()


def _at(value: Any, path: Iterable[str]) -> Any:
    for segment in path:
        if not isinstance(value, dict) or segment not in value:
            return _MISSING
        value = value[segment]
    return value


def _under(path: list[str], prefix: tuple[str, ...]) -> bool:
    return tuple(path[: len(prefix)]) == prefix


def _related(a: tuple[str, ...], b: tuple[str, ...]) -> bool:
    n = min(len(a), len(b))
    return a[:n] == b[:n]


# What every check reads. A capture note may not name these, or anything above or below them.
STRUCTURAL = [
    ("receiptId",),
    ("issuer", "kind"),
    ("issuer", "keyid"),
    ("issuer", "strict"),
    ("principal", "id"),
    ("principal", "keyid"),
    ("principal", "provenance"),
    ("agent", "id"),
    ("tool", "name"),
    ("delegation", "envelope"),
    ("request", "argsDigest"),
    ("execution", "status"),
    ("execution", "resultDigest"),
    ("policy", "decision"),
    ("policy", "policyDigest"),
    ("policy", "enforced"),
    ("authorization", "envelope"),
    ("authorization", "treeHead"),
    ("authorization", "inclusion"),
    ("approval", "status"),
    ("approval", "requiredApprovers"),
    ("approval", "checkedAt"),
    ("approval", "consumedAt"),
    ("approval", "approverKeyids"),
    ("approval", "fields"),
    ("approval", "provenance"),
    ("operation", "idempotencyKey"),
    ("operation", "lookupDigest"),
    ("operation", "status"),
    ("operation", "budget"),
    ("operation", "originalReceiptId"),
    ("reconciliation", "original"),
    ("reconciliation", "lookup"),
]


def _note_paths(predicate: dict) -> tuple[Optional[list[list[str]]], str]:
    """The capture note's paths, or None and the reason it is malformed."""
    if "capture" not in predicate:
        return [], ""
    note = predicate["capture"]
    if not isinstance(note, dict) or note.get("mode") not in ("digest", "encrypted"):
        return None, "capture note has no mode"
    paths = note.get("withheld")
    if not isinstance(paths, list):
        return None, "capture note has no path list"
    seen = set()
    for path in paths:
        if not isinstance(path, list) or not path or not all(isinstance(s, str) and s for s in path):
            return None, "capture path is not a list of segments"
        if tuple(path) in seen:
            return None, f"capture path {'.'.join(path)} named twice"
        seen.add(tuple(path))
        for part in STRUCTURAL:
            if _related(tuple(path), part):
                return None, f"capture note names structural part {'.'.join(path)}"
    return paths, ""


# Reports


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)
    fields: list[tuple[str, str, str]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)

    @property
    def failing(self) -> list[str]:
        return [c.name for c in self.checks if not c.ok]

    def add(self, name: str, ok: bool, detail: str = "") -> bool:
        self.checks.append(Check(name, bool(ok), detail))
        return bool(ok)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "checks": [{"name": c.name, "ok": c.ok, "detail": c.detail} for c in self.checks],
            "fields": [{"field": f, "provenance": p, "value": v} for f, p, v in self.fields],
        }


@dataclass
class Trust:
    issuer: list[PublicKey]
    principal: list[PublicKey] = field(default_factory=list)
    approval: list[PublicKey] = field(default_factory=list)
    upstream: list[PublicKey] = field(default_factory=list)
    log: list[PublicKey] = field(default_factory=list)
    provider_secrets: dict = field(default_factory=dict)


# Structure


def _is_str(value: Any) -> bool:
    return isinstance(value, str)


def _structural(statement: Any) -> str:
    """Empty when every part the checks read is present and typed, else the fault."""
    if not isinstance(statement, dict) or not isinstance(statement.get("predicate"), dict):
        return "statement has no predicate"
    subject = statement.get("subject")
    if not isinstance(subject, list) or len(subject) != 1 or not isinstance(subject[0], dict):
        return "statement has no single subject"
    if not _is_str(_at(subject[0], ("digest", "sha256"))) or not _is_str(subject[0].get("name")):
        return "subject has no name and sha256 digest"
    p = statement["predicate"]
    paths, fault = _note_paths(p)
    if paths is None:
        return fault
    if not _is_str(p.get("receiptId")):
        return "receiptId is not a string"
    if not isinstance(p.get("issuer"), dict) or not _is_str(p["issuer"].get("keyid")):
        return "issuer keyid is not a string"
    if "strict" in p["issuer"] and not isinstance(p["issuer"]["strict"], bool):
        return "issuer.strict is not a boolean"
    principal = p.get("principal")
    if not isinstance(principal, dict) or principal.get("provenance") not in ("attested", "claimed"):
        return "principal has no provenance"
    if principal["provenance"] == "attested" and not (_is_str(principal.get("id")) and _is_str(principal.get("keyid"))):
        return "attested principal has no id and keyid"
    if not isinstance(p.get("agent"), dict) or not _is_str(p["agent"].get("id")):
        return "agent id is not a string"
    if not isinstance(p.get("tool"), dict) or not _is_str(p["tool"].get("name")):
        return "tool name is not a string"
    if "delegation" in p and not (isinstance(p["delegation"], dict) and _is_envelope(p["delegation"].get("envelope"))):
        return "delegation has no envelope"
    request = p.get("request")
    if not isinstance(request, dict) or "args" not in request or not _is_str(request.get("argsDigest")):
        return "request has no args and argsDigest"
    execution = p.get("execution")
    if not isinstance(execution, dict) or not _is_str(execution.get("status")) or execution["status"] not in STATUSES:
        return "execution status is not a known string"
    if execution["status"] in ("executed", "failed") and not (_is_str(execution.get("resultDigest")) and "result" in execution):
        return "executed call has no result and resultDigest"
    policy = p.get("policy")
    if policy is not None:
        if not isinstance(policy, dict) or policy.get("decision") not in ("allow", "deny"):
            return "policy decision is not allow or deny"
        if not _is_str(policy.get("policyDigest")):
            return "policy has no policyDigest"
        if "enforced" in policy and not isinstance(policy["enforced"], bool):
            return "policy.enforced is not a boolean"
        if not isinstance(policy.get("errors", []), (list, dict)):
            return "policy errors is not a list"
    if "authorization" in p:
        a = p["authorization"]
        if not (isinstance(a, dict) and _is_envelope(a.get("envelope")) and _is_envelope(a.get("treeHead")) and _is_inclusion(a.get("inclusion"))):
            return "authorization has no envelope, tree head, and inclusion proof"
    if "approval" in p:
        fault = _approval_record_fault(p["approval"])
        if fault:
            return fault
    if "operation" in p:
        fault = _operation_fault(p["operation"])
        if fault:
            return fault
    if "reconciliation" in p:
        r = p["reconciliation"]
        if not (isinstance(r, dict) and isinstance(r.get("original"), dict) and isinstance(r.get("lookup"), dict)):
            return "reconciliation has no original and lookup"
    return ""


def _approval_record_fault(a: Any) -> str:
    if not isinstance(a, dict):
        return "approval is not a record"
    if a.get("status") not in ("approved", "denied"):
        return "approval status is not approved or denied"
    if a.get("requiredApprovers") not in (1, 2) or isinstance(a.get("requiredApprovers"), bool):
        return "approval requiredApprovers is not 1 or 2"
    ids = a.get("approverKeyids")
    if not isinstance(ids, list) or not all(_is_str(k) for k in ids):
        return "approval approverKeyids is not a list of strings"
    if parse_instant(a.get("checkedAt")) is None:
        return "approval checkedAt is not a time with an offset"
    if "consumedAt" in a and parse_instant(a["consumedAt"]) is None:
        return "approval consumedAt is not a time with an offset"
    if a.get("provenance") != "observed":
        return "approval provenance is not observed"
    if "fields" in a and not (isinstance(a["fields"], dict) and all(k in ACTION_FIELDS and _is_str(v) and v for k, v in a["fields"].items())):
        return "approval fields is not a map of names"
    return ""


# Approval payloads

APPROVAL_FIELDS = {"version", "approvalId", "principal", "agent", "tool", "argsDigest", "amount", "currency", "beneficiary", "issuedAt", "expiresAt"}
ACTION_FIELDS = ("amount", "currency", "beneficiary")


def _approval_payload_fault(payload: Any) -> str:
    if not isinstance(payload, dict):
        return "approval payload is not an object"
    unknown = set(payload) - APPROVAL_FIELDS
    if unknown:
        return f"approval payload has unknown field {sorted(unknown)[0]}"
    if payload.get("version") != "0.1":
        return "approval version is not 0.1"
    if not (_is_str(payload.get("approvalId")) and UUID.match(payload["approvalId"])):
        return "approvalId is not a UUID"
    for name in ("principal", "agent", "tool"):
        if not _is_str(payload.get(name)):
            return f"approval {name} is not a string"
    if not (_is_str(payload.get("argsDigest")) and HEX64.fullmatch(payload["argsDigest"])):
        return "approval argsDigest is not a sha256"
    if "amount" in payload:
        amount = payload["amount"]
        if isinstance(amount, bool) or not isinstance(amount, int) or abs(amount) > MAX_SAFE_INTEGER:
            return "approval amount is not a safe integer"
    for name in ("currency", "beneficiary"):
        if name in payload and not (_is_str(payload[name]) and payload[name]):
            return f"approval {name} is not a nonempty string"
    issued, expires = parse_instant(payload.get("issuedAt")), parse_instant(payload.get("expiresAt"))
    if issued is None or expires is None:
        return "approval window is not two valid times with offsets"
    if expires <= issued:
        return "approval expires before it is issued"
    return ""


def _within(t: float, payload: dict) -> bool:
    return parse_instant(payload["issuedAt"]) <= t < parse_instant(payload["expiresAt"])


# Delegations


def _delegation_chain(env: Any, principal_keys: list[PublicKey]) -> tuple[Optional[list[dict]], str, list[str]]:
    """The grant's links leaf first, with the principal's signing keyid, or None and the fault."""
    links: list[dict] = []
    envelopes: list[Any] = []
    current = env
    while True:
        if len(links) == MAX_CHAIN_DEPTH:
            return None, f"chain deeper than {MAX_CHAIN_DEPTH} delegations", []
        if not _is_envelope(current) or current["payloadType"] != DELEGATION:
            return None, "a link is not a delegation envelope", []
        payload = dsse_payload(current)
        fault = _delegation_payload_fault(payload)
        if fault:
            return None, fault, []
        links.append(payload)
        envelopes.append(current)
        if "parent" not in payload:
            break
        current = payload["parent"]
    root_signers = dsse_signers(envelopes[-1], principal_keys)
    if not root_signers:
        return None, "the root grant is not signed by a trusted principal key", []
    for child, child_env, parent in zip(links, envelopes, links[1:]):
        if not _is_str(parent.get("agentKey")):
            return None, f"{parent['agent']} names no key to delegate with", root_signers
        try:
            delegator = load_public_key(parent["agentKey"])
        except ValueError:
            return None, f"{parent['agent']}'s key is not an Ed25519 public key", root_signers
        if not dsse_signers(child_env, [delegator]):
            return None, f"the grant to {child['agent']} is not signed by {parent['agent']}'s key", root_signers
        if not set(child["scopes"]) <= set(parent["scopes"]):
            return None, f"the grant to {child['agent']} holds a scope {parent['agent']} lacks", root_signers
        if not (parse_instant(parent["issuedAt"]) <= parse_instant(child["issuedAt"]) and parse_instant(child["expiresAt"]) <= parse_instant(parent["expiresAt"])):
            return None, f"the grant to {child['agent']} is outside {parent['agent']}'s window", root_signers
        if child["principal"] != parent["principal"]:
            return None, f"the grant to {child['agent']} names another principal", root_signers
    return links, "", root_signers


def _delegation_payload_fault(payload: Any) -> str:
    if not isinstance(payload, dict) or payload.get("version") != "0.1":
        return "grant is not a version 0.1 delegation"
    if not (_is_str(payload.get("principal")) and _is_str(payload.get("agent"))):
        return "grant has no principal and agent"
    if not (isinstance(payload.get("scopes"), list) and all(_is_str(s) for s in payload["scopes"])):
        return "grant scopes is not a list of tool names"
    if parse_instant(payload.get("issuedAt")) is None or parse_instant(payload.get("expiresAt")) is None:
        return "grant window is not two valid times with offsets"
    return ""


# Tree heads


def _tree_head(env: Any, trust: Trust, report: Report, prefix: str = "") -> Optional[dict]:
    payload = dsse_payload(env)
    signer = ""
    if _is_envelope(env) and env["payloadType"] == TREEHEAD and isinstance(payload, dict):
        log_signers = dsse_signers(env, trust.log)
        issuer_signers = [] if log_signers else dsse_signers(env, trust.issuer)
        signer = f"log key {log_signers[0][:12]}" if log_signers else f"issuer key {issuer_signers[0][:12]}" if issuer_signers else ""
    ok = bool(signer) and _is_size(payload.get("treeSize")) and _is_str(payload.get("rootHash")) and bool(HEX64.fullmatch(payload["rootHash"]))
    report.add(prefix + "tree head signature", ok, f"signed by the {signer}" if ok else "no trusted log or issuer key signed this tree head")
    return payload if ok else None


def _inclusion(leaf: bytes, inclusion: dict, head: dict) -> bool:
    root = root_from_inclusion(inclusion["leafIndex"], inclusion["treeSize"], leaf_hash(leaf), _hashes(inclusion["hashes"]))
    return root is not None and root.hex() == head["rootHash"]


# The bundle


def verify_bundle(
    bundle: Any,
    trust: Trust,
    *,
    log: Optional[list] = None,
    log_id: Optional[str] = None,
    require_strict: bool = False,
) -> Report:
    report = Report()
    _verify(bundle, trust, report, log=log, log_id=log_id, require_strict=require_strict, prefix="")
    return report


def _verify(bundle: Any, trust: Trust, report: Report, *, log, log_id, require_strict, prefix: str, nested: bool = False) -> None:
    def add(name: str, ok: bool, detail: str = "") -> bool:
        return report.add(prefix + name, ok, detail)

    env = bundle.get("envelope") if isinstance(bundle, dict) else None
    signers = dsse_signers(env, trust.issuer)
    if not add("receipt signature (issuer key)", bool(signers), f"signed by {signers[0][:12]}" if signers else "no trusted issuer key signed this envelope"):
        return
    statement = dsse_payload(env)
    typed = env["payloadType"] == IN_TOTO and isinstance(statement, dict) and statement.get("_type") == STATEMENT_TYPE and statement.get("predicateType") == RECEIPT_PREDICATE
    if not add("receipt payload type", typed, "" if typed else "not an in-toto statement with the receipt predicate type"):
        return
    fault = _structural(statement)
    if not isinstance(bundle.get("treeHead"), dict) or not _is_inclusion(bundle.get("inclusion")):
        fault = fault or "bundle has no tree head and inclusion proof"
    if not add("structural parts in clear", not fault, fault):
        return

    p = statement["predicate"]
    paths, _ = _note_paths(p)
    status = p["execution"]["status"]
    reconciliation = "reconciliation" in p
    forwarded = status in FORWARDED

    kind = p["issuer"].get("kind")
    add("issuer kind is known", kind in ("gateway", "sdk", "door", "egress", "guardian"), str(kind))
    add("issuer keyid matches signer", p["issuer"]["keyid"] in signers, p["issuer"]["keyid"][:12])
    if kind == "gateway":
        add("gateway receipt carries a delegation", "delegation" in p)
        add("gateway receipt carries a policy decision", isinstance(p.get("policy"), dict))
    if kind == "door":
        add("door receipt carries a policy decision", isinstance(p.get("policy"), dict))
    if kind == "guardian":
        # a Guardian decides and carries out nothing: an allow is withheld (nothing forwarded), a deny is denied
        policy = p.get("policy") if isinstance(p.get("policy"), dict) else None
        add("guardian receipt carries a policy decision", policy is not None)
        decision = policy.get("decision") if policy else None
        decided = decision == "deny" if status == "denied" else status == "withheld" and decision == "allow"
        add("guardian decided, executed nothing", decided, f"{decision}; the agent asked, reports the call itself, and is trusted to honor the answer" if decided else f"the receipt says {status} with a policy {decision or 'absent'}")
    if kind == "egress":
        # where a connection around the gateway went and how much, never what was sent; the agent is only as good as
        # the proxy credential the witness checked
        add("egress receipt carries a policy decision", isinstance(p.get("policy"), dict))
        facts = p.get("facts") if isinstance(p.get("facts"), dict) else {}
        dest = facts.get("destination") if isinstance(facts.get("destination"), dict) else {}
        seen = dest.get("value") if isinstance(dest.get("value"), dict) else {}
        host, port = seen.get("host"), seen.get("port")
        name = None
        if isinstance(host, str) and isinstance(port, int) and not isinstance(port, bool):
            name = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        tool = p.get("tool") if isinstance(p.get("tool"), dict) else {}
        add("egress destination observed", tool.get("provenance") == "observed" and dest.get("provenance") == "observed" and name == tool.get("name"), str(tool.get("name")))
        agent = p.get("agent") if isinstance(p.get("agent"), dict) else {}
        add("egress relayed only for a checked agent", not forwarded or agent.get("provenance") == "observed", str(agent.get("id")))
        add("egress open committed before relaying", not forwarded or isinstance(p.get("authorization"), dict))
        reached = status in ("executed", "failed")
        host_s = host if isinstance(host, str) else ""
        literal = _address(host_s)
        result = p["execution"].get("result") if reached else None
        peer = result.get("peer") if isinstance(result, dict) else None
        if literal is not None:
            # an IP literal is the action itself: the peer must be that very address
            peer_ok = isinstance(peer, str) and _address(peer) == literal
        else:
            peer_ok = isinstance(peer, str) and not _internal_address(peer)
        add("egress peer matches the destination", not reached or peer_ok, f"{host_s} reached {peer}")

    _delegation_checks(p, trust, add, forwarded and not reconciliation)
    approval_withheld = ["approval", "envelope"] in paths
    args_withheld = any(_under(path, ("request", "args")) for path in paths)
    if "approval" in p:
        _approval_checks(p, trust, add, forwarded, approval_withheld, args_withheld)
    _digest_checks(statement, paths, add)
    _upstream_checks(p, paths, trust, add)

    policy = p.get("policy")
    if isinstance(policy, dict):
        decision, enforced = policy["decision"], policy.get("enforced", True)
        if decision == "allow":
            consistent, detail = status != "denied", "allow"
        elif enforced:
            consistent, detail = status == "denied", "enforced deny"
        else:
            consistent, detail = status != "denied", "observe mode, not enforced"
        add("policy decision consistent with execution", consistent, f"{detail}, {status}")
        add("no policy errors on an allow", decision != "allow" or not policy.get("errors"))

    if "operation" in p:
        _operation_checks(p, kind, status, reconciliation, add)
    if "authorization" in p:
        _authorization_checks(statement, bundle, trust, add, forwarded)
    if reconciliation and not nested:
        _reconciliation_checks(p, bundle, trust, report, add, prefix)

    if require_strict:
        add("strict mode in force", kind == "gateway" and p["issuer"].get("strict") is True)
        add("strict: call precommitted before forwarding", not forwarded or reconciliation or "authorization" in p, status)

    head = _tree_head(bundle["treeHead"], trust, report, prefix)
    if head is None:
        return
    if log_id is not None:
        add("tree head names the expected log", head.get("log") == log_id, str(head.get("log")))
    inclusion = bundle["inclusion"]
    add("tree head matches inclusion proof size", inclusion["treeSize"] == head["treeSize"], f"{inclusion['treeSize']} / {head['treeSize']}")
    add("log inclusion proof", _inclusion(_utf8(canonical_json(env)), inclusion, head), f"leaf {inclusion['leafIndex']} of {inclusion['treeSize']}")
    if log is not None:
        hashes = [_log_leaf(line) for line in log[: head["treeSize"]]]
        ok = len(hashes) == head["treeSize"] and None not in hashes and tree_root(hashes).hex() == head["rootHash"]
        add("log file root matches tree head", ok, f"{len(log)} lines")


def _log_leaf(line: Any) -> Optional[bytes]:
    if isinstance(line, str):
        return leaf_hash(_utf8(line))
    if isinstance(line, dict) and _is_str(line.get("hash")) and HEX64.fullmatch(line["hash"]):
        return bytes.fromhex(line["hash"])
    return None


def _delegation_checks(p: dict, trust: Trust, add, must_be_in_window: bool) -> None:
    if "delegation" not in p:
        add("principal is claimed, not attested", p["principal"]["provenance"] == "claimed" and p["agent"].get("provenance") != "attested")
        return
    env = p["delegation"]["envelope"]
    links, fault, root_signers = _delegation_chain(env, trust.principal)
    if links is None:
        add("delegation signature (principal key)", False, fault)
        if isinstance(dsse_payload(env), dict) and "parent" in dsse_payload(env):
            add("delegation chain to the principal", False, fault)
        return
    leaf, root = links[0], links[-1]
    add("delegation signature (principal key)", True, f"signed by {root_signers[0][:12]}")
    if len(links) > 1:
        add("delegation chain to the principal", True, " <- ".join(link["agent"] for link in links))
    principal = p["principal"]
    binds = (
        principal["provenance"] == "attested"
        and leaf["principal"] == principal["id"] == root["principal"]
        and leaf["agent"] == p["agent"]["id"]
        and principal["keyid"] in root_signers
    )
    add("delegation binds principal and agent", binds)
    t = parse_instant(p.get("timestamp"))
    issued = max(parse_instant(link["issuedAt"]) for link in links)
    expires = min(parse_instant(link["expiresAt"]) for link in links)
    inside = t is not None and issued <= t < expires
    if inside or not must_be_in_window:
        add("delegation valid at receipt time", t is not None, "" if inside else "outside the window, but the call was not forwarded")
    else:
        add("delegation valid at receipt time", False, "a forwarded call outside the grant's window")
    if p["execution"]["status"] in ("executed", "failed"):
        add("executed tool within delegated scope", p["tool"]["name"] in leaf["scopes"], p["tool"]["name"])


def _approval_checks(p: dict, trust: Trust, add, forwarded: bool, envelope_withheld: bool, args_withheld: bool) -> None:
    a = p["approval"]
    signer_ids = set(a["approverKeyids"])
    if not forwarded:
        add("approval consistent with execution", True, f"a refusal ({p['execution']['status']}) records the approval without endorsing it")
        return

    payload = None
    if envelope_withheld:
        add("approval signatures (human keys)", args_withheld, "committed, not checked" if args_withheld else "the envelope is withheld beside arguments in clear")
    else:
        env = a.get("envelope")
        payload = dsse_payload(env) if _is_envelope(env) and env["payloadType"] == APPROVAL else None
        fault = _approval_payload_fault(payload) if payload is not None else "no approval envelope"
        signers = dsse_signers(env, trust.approval) if not fault else []
        enough = len(signers) >= a["requiredApprovers"]
        add("approval signatures (human keys)", not fault and enough, fault or f"{len(signers)} of {a['requiredApprovers']} trusted approvers")
        if fault:
            payload = None
        else:
            signer_ids = signer_ids if signer_ids == {s["keyid"] for s in env["signatures"]} else None

    consumed = parse_instant(a.get("consumedAt"))
    checked = parse_instant(a["checkedAt"])
    if payload is not None:
        args = p["request"]["args"]
        fields = a.get("fields", {})
        binds = payload["principal"] == p["principal"].get("id") and payload["agent"] == p["agent"]["id"] and payload["tool"] == p["tool"]["name"]
        if not args_withheld:
            binds = binds and payload["argsDigest"] == digest(args) and isinstance(args, dict)
            for name in ACTION_FIELDS:
                source = fields.get(name, name)
                if name in payload or (isinstance(args, dict) and source in args):
                    binds = binds and isinstance(args, dict) and args.get(source, _MISSING) == payload.get(name, _MISSING)
        binds = binds and (consumed is None or _within(consumed, payload))
        add("approval payload binding", binds, "committed arguments" if args_withheld else "")
        times = [t for t in (checked, consumed) if t is not None]
        add("approval valid at forward time", all(_within(t, payload) for t in times))
    elif envelope_withheld:
        add("approval payload binding", True, "committed, not checked")
        add("approval valid at forward time", True, "committed, not checked")

    consistent = (
        a["status"] == "approved"
        and consumed is not None
        and checked is not None
        and checked <= consumed
        and parse_instant(p.get("timestamp")) is not None
        and parse_instant(p["timestamp"]) <= checked
        and signer_ids is not None
        and len(signer_ids) == len(a["approverKeyids"]) >= a["requiredApprovers"]
    )
    add("approval consistent with execution", consistent)


def _digest_checks(statement: dict, paths: list, add) -> None:
    p = statement["predicate"]
    subject = statement["subject"][0]["digest"]["sha256"]
    used: set = set()

    def committed_part(part: tuple[str, ...]) -> Optional[bool]:
        named = [path for path in paths if _under(path, part)]
        used.update(tuple(path) for path in named)
        if not named:
            return None
        return all(is_commitment(_at(p, path)) for path in named)

    request = p["request"]
    match = request["argsDigest"] == subject
    committed = committed_part(("request", "args"))
    if committed is None:
        ok = match and digest(request["args"]) == request["argsDigest"]
        add("request args digest", ok, "" if ok else "args, argsDigest, and the subject disagree")
    else:
        add("request args digest", committed and match, "committed, not recomputed" if committed else "a named path holds no commitment")

    execution = p["execution"]
    if execution["status"] in ("executed", "failed"):
        committed = committed_part(("execution", "result"))
        if committed is None:
            add("execution result digest", digest(execution["result"]) == execution["resultDigest"])
        else:
            add("execution result digest", committed, "committed, not recomputed" if committed else "a named path holds no commitment")

    facts = p.get("facts") if isinstance(p.get("facts"), dict) else {}
    for name in facts:
        for part in ("value", "args"):
            committed = committed_part(("facts", name, part))
            if committed is not None:
                add(f"fact {name} {part}", committed, "committed, not recomputed" if committed else "a named path holds no commitment")

    for path in paths:
        if tuple(path) in used:
            continue
        add(f"withheld {'.'.join(path)}", is_commitment(_at(p, path)))


def _result_withheld(paths: list) -> bool:
    return any(_under(path, ("execution", "result")) and not _under(path, ("execution", "result", "_meta")) for path in paths)


_PROVIDERS = {"stripe-webhook": ("stripe", "Stripe"), "github-delivery": ("github", "GitHub")}


def _is_provider_attestation(v: Any) -> bool:
    # Only a recognised, well-formed delivery takes the provider branch, so unknown or malformed evidence cannot
    # suppress the upstream-key check.
    return isinstance(v, dict) and v.get("provider") in _PROVIDERS and all(_is_str(v.get(f)) or is_commitment(v.get(f)) for f in ("rawBody", "signature", "bind"))


def _upstream_checks(p: dict, paths: list, trust: Trust, add) -> None:
    execution = p["execution"]
    if execution["status"] not in ("executed", "failed") or "upstream" not in execution:
        return
    upstream = execution["upstream"]
    result = execution["result"]
    if _is_provider_attestation(upstream):
        if not trust.provider_secrets:
            return
        if _result_withheld(paths) or any(_under(path, ("execution", "upstream")) for path in paths):
            add("upstream signature not checked", True, "the result or the delivery is withheld")
            return
        name, label = _PROVIDERS[upstream["provider"]]
        secret = trust.provider_secrets.get(name)
        if secret is None:
            add("upstream signature (provider secret)", False, f"no {label} secret given")
            return
        ok, detail = _provider_delivery(upstream, result, secret, parse_instant(p.get("timestamp")))
        add("upstream signature (provider secret)", ok, detail)
        return
    if not trust.upstream:
        return
    if _result_withheld(paths):
        add("upstream signature not checked", True, "the result is withheld")
        return
    if ["execution", "upstream", "envelope"] in paths:
        add("upstream signature (upstream key)", False, "the result is in clear but the upstream's signature is withheld")
        return
    env = upstream.get("envelope") if isinstance(upstream, dict) else None
    if not _is_envelope(env):
        add("upstream signature (upstream key)", False, "the receipt carries no upstream envelope, and the capture note does not say it is withheld")
        return
    payload = dsse_payload(env)
    content = {"content": result.get("content"), "isError": result.get("isError", False)} if isinstance(result, dict) else None
    ok = (
        env["payloadType"] == UPSTREAM
        and bool(dsse_signers(env, trust.upstream))
        and isinstance(payload, dict)
        and payload.get("receiptId") == p["receiptId"]
        and payload.get("tool") == p["tool"]["name"]
        and payload.get("contentDigest") == digest(content)
    )
    add("upstream signature (upstream key)", ok)


def _provider_delivery(upstream: dict, result: Any, secret: str, receipt_time: Optional[float]) -> tuple[bool, str]:
    raw, signature, bind = upstream.get("rawBody"), upstream.get("signature"), upstream.get("bind")
    if not (_is_str(raw) and _is_str(signature) and _is_str(bind)):
        return False, "delivery has no raw body, signature, and binding"
    key = _utf8(secret)
    if upstream["provider"] == "stripe-webhook":
        parts = [item.split("=", 1) for item in signature.split(",") if "=" in item]
        stamps = [v for k, v in parts if k == "t"]
        if len(stamps) != 1 or not stamps[0].isdigit():
            return False, "Stripe signature has no timestamp"
        expected = hmac.new(key, _utf8(stamps[0] + "." + raw), hashlib.sha256).hexdigest()
        if not any(k == "v1" and hmac.compare_digest(v, expected) for k, v in parts):
            return False, "HMAC does not verify"
        if receipt_time is None or abs(int(stamps[0]) - receipt_time) > STRIPE_TOLERANCE_SECONDS:
            return False, "Stripe timestamp outside tolerance of the receipt's"
    elif upstream["provider"] == "github-delivery":
        expected = "sha256=" + hmac.new(key, _utf8(raw), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return False, "HMAC does not verify"
    else:
        return False, f"unknown provider {upstream['provider']}"
    try:
        bound = _at(parse_json(raw), bind.split("."))
    except ValueError:
        return False, "raw body is not JSON"
    if bound is _MISSING or isinstance(bound, (dict, list)) or bound is None:
        return False, f"{bind} is not a value in the delivery"
    needle = bound if isinstance(bound, str) else canonical_json(bound)
    texts = [c.get("text") for c in result.get("content", []) if isinstance(c, dict)] if isinstance(result, dict) and isinstance(result.get("content"), list) else []
    if not any(_is_str(t) and needle in t for t in texts):
        return False, f"{bind} does not appear in the result"
    return True, f"attested (shared secret), bound {bind}"


def _authorization_checks(statement: dict, bundle: dict, trust: Trust, add, forwarded: bool) -> None:
    p = statement["predicate"]
    a = p["authorization"]
    env = a["envelope"]
    signers = dsse_signers(env, trust.issuer)
    signed = bool(signers) and p["issuer"]["keyid"] in signers
    add("authorization signature (issuer key)", signed)
    auth = dsse_payload(env)
    q = auth.get("predicate") if isinstance(auth, dict) else None
    names = (
        env["payloadType"] == IN_TOTO
        and auth.get("_type") == STATEMENT_TYPE
        and auth.get("predicateType") == AUTHORIZATION_PREDICATE
        and isinstance(q, dict)
        and auth.get("subject") == statement["subject"]
        and q.get("receiptId") == p["receiptId"]
        and _at(q, ("tool", "name")) == p["tool"]["name"]
        and _at(q, ("request", "argsDigest")) == p["request"]["argsDigest"]
        and _at(q, ("agent", "id")) == p["agent"]["id"]
        and _at(q, ("principal", "id")) == p["principal"].get("id")
        and _at(q, ("policy", "decision")) == "allow"
    )
    add("authorization names this call", names)
    if not isinstance(q, dict):
        q = {}

    if "approval" in p or "approval" in q:
        pre, final = q.get("approval"), p.get("approval")
        carries = isinstance(pre, dict) and isinstance(final, dict) and all(pre.get(k, _MISSING) == final.get(k, _MISSING) for k in ("envelope", "requiredApprovers", "fields"))
        add("authorization carries this approval", carries, "" if carries else "the approval in the precommit and in the receipt differ, or only one of them has one")
        if forwarded:
            paths = _note_paths(q)[0] or []
            withheld = ["approval", "envelope"] in paths
            args_withheld = any(_under(path, ("request", "args")) for path in paths)
            add("authorization approval was valid", _precommit_approval_valid(pre, final, parse_instant(p.get("timestamp")), trust, withheld, args_withheld))

    if "operation" in p or "operation" in q:
        add("authorization names this operation", _same_operation(p.get("operation"), q.get("operation"), submitted=True))

    head = _tree_head(a["treeHead"], trust, Report(), "")
    add("authorization tree head signature", head is not None)
    if head is None:
        return
    inclusion = a["inclusion"]
    included = inclusion["treeSize"] == head["treeSize"] and _inclusion(_utf8(canonical_json(env)), inclusion, head)
    add("authorization log inclusion proof", included)
    receipt = bundle["inclusion"]
    before = inclusion["leafIndex"] < receipt["leafIndex"] and inclusion["treeSize"] <= receipt["treeSize"]
    add("authorization logged before execution", before, f"leaf {inclusion['leafIndex']} before leaf {receipt['leafIndex']}")


def _precommit_approval_valid(pre: Any, final: Any, receipt_time: Optional[float], trust: Trust, envelope_withheld: bool, args_withheld: bool) -> bool:
    if _approval_record_fault(pre) or pre["status"] != "approved" or not isinstance(final, dict) or parse_instant(final.get("checkedAt")) is None:
        return False
    ids = pre["approverKeyids"]
    if len(set(ids)) != len(ids) or len(ids) < pre["requiredApprovers"]:
        return False
    checked = parse_instant(pre["checkedAt"])
    if receipt_time is None or not receipt_time <= checked <= parse_instant(final["checkedAt"]):
        return False
    if envelope_withheld:
        return args_withheld
    env = pre.get("envelope")
    payload = dsse_payload(env) if _is_envelope(env) and env["payloadType"] == APPROVAL else None
    if payload is None or _approval_payload_fault(payload):
        return False
    trusted = set(dsse_signers(env, trust.approval))
    return set(ids) <= trusted and _within(checked, payload)


OPERATION_STATUSES = ("submitted", "pending", "confirmed", "failed", "unknown")
OPEN_STATUSES = ("submitted", "pending", "unknown")
BUDGET_PERIOD = re.compile(r"^\d{4}-\d{2}-\d{2}$")
CURRENCY = re.compile(r"^[A-Z]{3}$")


def _operation_fault(op: Any) -> str:
    if not isinstance(op, dict):
        return "operation is not an object"
    if "id" in op and not (_is_str(op["id"]) and UUID.match(op["id"])):
        return "operation id is not a UUID"
    if not (_is_str(op.get("originalReceiptId")) and UUID.match(op["originalReceiptId"])):
        return "operation originalReceiptId is not a UUID"
    if not all(_is_str(op.get(k)) and HEX64.fullmatch(op[k]) for k in ("idempotencyKey", "lookupDigest")):
        return "operation idempotencyKey or lookupDigest is not a sha256"
    if op.get("status") not in OPERATION_STATUSES or op.get("provenance") != "observed":
        return "operation status or provenance is invalid"
    budget = op.get("budget")
    if not (
        isinstance(budget, dict)
        and _is_str(budget.get("id"))
        and 0 < len(budget["id"]) <= 128
        and _is_str(budget.get("currency"))
        and CURRENCY.match(budget["currency"])
        and _is_str(budget.get("period"))
        and BUDGET_PERIOD.match(budget["period"])
    ):
        return "operation budget is invalid"
    return ""


def _same_operation(op: Any, first: Any, *, submitted: bool = False) -> bool:
    """The same logical operation; an id withheld on either side is not compared."""
    if not isinstance(op, dict) or _operation_fault(first):
        return False
    if submitted and first["status"] != "submitted":
        return False
    same_id = "id" not in op or "id" not in first or op["id"] == first["id"]
    return same_id and all(op.get(k, _MISSING) == first.get(k, _MISSING) for k in ("idempotencyKey", "lookupDigest", "originalReceiptId")) and canonical_json(op.get("budget")) == canonical_json(first.get("budget"))


def _operation_checks(p: dict, kind: Any, status: str, reconciliation: bool, add) -> None:
    op = p["operation"]
    add("operation observed by gateway", kind == "gateway" and op["provenance"] == "observed")
    if reconciliation:
        return
    retry = op["originalReceiptId"] != p["receiptId"]
    add("operation names this original receipt", not retry or status == "withheld", "a retry is withheld and names the first receipt" if retry else "")
    refused = status in ("withheld", "denied")
    awaits = retry or op["status"] in OPEN_STATUSES or (refused and op["status"] == "failed")
    add("operation awaits provider reconciliation", awaits, "" if awaits else f"a {op['status']} outcome needs a provider reconciliation receipt")
    add("operation carries committed authorization", refused or "authorization" in p, "" if refused or "authorization" in p else f"a {status} financial call with no authorization committed first")


def _reconciliation_checks(p: dict, bundle: dict, trust: Trust, report: Report, add, prefix: str) -> None:
    r = p["reconciliation"]
    original = r["original"]
    signers = dsse_signers(original.get("envelope"), trust.issuer)
    original_statement = dsse_payload(original.get("envelope")) if signers else None
    q = original_statement.get("predicate") if isinstance(original_statement, dict) else None
    eligible = isinstance(q, dict) and "reconciliation" not in q
    original_ok = False
    if eligible:
        sub = Report()
        if original_statement.get("predicateType") == RECEIPT_PREDICATE:
            _verify(original, trust, sub, log=None, log_id=None, require_strict=False, prefix="", nested=True)
        else:
            _verify_authorization_bundle(original, trust, sub)
        original_ok = sub.ok
        for c in sub.checks:
            report.add(prefix + "reconciliation original " + c.name, c.ok, c.detail)
    add("reconciliation original evidence verifies", eligible and original_ok)
    q = q if isinstance(q, dict) else {}
    op, first = p.get("operation"), q.get("operation")
    first_t, t = parse_instant(q.get("timestamp")), parse_instant(p.get("timestamp"))
    links = (
        isinstance(first, dict)
        and not _operation_fault(first)
        and first["status"] in OPEN_STATUSES
        and first["originalReceiptId"] == q.get("receiptId")
        and isinstance(op, dict)
        and op.get("originalReceiptId") == q.get("receiptId")
        and p["receiptId"] != q.get("receiptId")
        and _same_operation(op, first)
        and all(canonical_json(p.get(k)) == canonical_json(q.get(k)) for k in ("principal", "agent", "tool", "delegation"))
        and p["issuer"]["keyid"] == _at(q, ("issuer", "keyid"))
        and first_t is not None
        and t is not None
        and t >= first_t
    )
    add("reconciliation links the original operation", links)
    lookup = r["lookup"]
    add("reconciliation lookup matches authorization", isinstance(first, dict) and digest(lookup) == first.get("lookupDigest"))
    paths = _note_paths(p)[0] or []
    if any(_under(path, ("request", "args")) for path in paths):
        add("reconciliation lookup args match request", True, "request arguments committed under the capture rule")
    else:
        add("reconciliation lookup args match request", canonical_json(lookup.get("args")) == canonical_json(p["request"]["args"]))
    included = original.get("inclusion")
    before = _is_inclusion(included) and included["leafIndex"] < bundle["inclusion"]["leafIndex"] and included["treeSize"] <= bundle["inclusion"]["treeSize"]
    heads = [dsse_payload(h) if dsse_signers(h, trust.log + trust.issuer) else None for h in (original.get("treeHead"), bundle["treeHead"])]
    same_log = all(isinstance(h, dict) for h in heads) and heads[0].get("log") == heads[1].get("log")
    add("reconciliation logged after original", before and same_log)
    terminal = isinstance(op, dict) and op.get("status") in ("confirmed", "failed")
    add("reconciliation records a terminal provider outcome", terminal and p["execution"]["status"] == "executed" and p["execution"].get("provenance") == "observed")
    if _result_withheld(paths):
        add("reconciliation provider status", True, "provider result withheld; disclose it to recompute the observed status")
    else:
        add("reconciliation provider status", *_provider_status(p, lookup, terminal))


def _provider_value(result: Any, path: Any) -> Any:
    content = result.get("content") if isinstance(result, dict) else None
    text = next((c for c in content if isinstance(c, dict) and c.get("type") == "text"), None) if isinstance(content, list) else None
    if not (isinstance(text, dict) and _is_str(text.get("text")) and _is_str(path)):
        return _MISSING
    try:
        record = parse_json(text["text"])
    except ValueError:
        return _MISSING
    return _at(record, path.split("."))


def _provider_status(p: dict, lookup: dict, terminal: bool) -> tuple[bool, str]:
    op = p.get("operation") or {}
    result = p["execution"].get("result")
    state = _provider_value(result, lookup.get("statusPath"))
    confirmed, failed = lookup.get("confirmed"), lookup.get("failed")
    mapped = None
    if _is_str(state):
        mapped = "confirmed" if isinstance(confirmed, list) and state in confirmed else "failed" if isinstance(failed, list) and state in failed else None
    identity = _provider_value(result, lookup.get("identityPath"))
    errored = isinstance(result, dict) and result.get("isError") is True
    ok = terminal and mapped == op.get("status") and identity == op.get("idempotencyKey") and not errored
    return ok, f"provider state {state if state is not _MISSING else 'missing'} maps to {mapped}; the gateway observed the read, no provider signature is implied"


def _verify_authorization_bundle(bundle: dict, trust: Trust, report: Report) -> None:
    env = bundle.get("envelope")
    signers = dsse_signers(env, trust.issuer)
    st = dsse_payload(env) if signers else None
    typed = isinstance(st, dict) and env["payloadType"] == IN_TOTO and st.get("predicateType") == AUTHORIZATION_PREDICATE
    if not report.add("authorization signature (issuer key)", typed):
        return
    p = st.get("predicate")
    shaped = dict(st, predicate=dict(p, session={"id": None, "toolUseId": None, "provenance": "claimed"}, model={"id": None, "provenance": "claimed"}, execution={"status": "withheld", "provenance": "observed"})) if isinstance(p, dict) else st
    fault = _structural(shaped)
    if not (isinstance(bundle.get("treeHead"), dict) and _is_inclusion(bundle.get("inclusion"))):
        fault = fault or "the authorization has no tree head and inclusion proof"
    if not report.add("structural parts in clear", not fault, fault):
        return
    kind = p["issuer"].get("kind")
    report.add("authorization issued by the gateway", kind in ("gateway", "door") and p["issuer"]["keyid"] in signers)
    report.add("authorization operation is submitted", kind == "door" or _at(p, ("operation", "status")) == "submitted", "a door has no operations" if kind == "door" else "")
    policy = p.get("policy")
    permits = isinstance(policy, dict) and (
        (policy["decision"] == "allow" and isinstance(policy.get("errors"), list) and not policy["errors"])
        or (policy["decision"] == "deny" and policy.get("enforced") is False)
    )
    report.add("authorization permits the original call", permits)
    links, fault, root_signers = _delegation_chain(_at(p, ("delegation", "envelope")), trust.principal) if "delegation" in p else (None, "no delegation", [])
    report.add("delegation signature (principal key)", links is not None, fault)
    if links is not None:
        leaf = links[0]
        principal = p["principal"]
        report.add("delegation binds principal and agent", principal["provenance"] == "attested" and leaf["principal"] == principal["id"] and leaf["agent"] == p["agent"]["id"] and principal["keyid"] in root_signers)
        t = parse_instant(p.get("timestamp"))
        report.add("delegation valid at receipt time", t is not None and max(parse_instant(x["issuedAt"]) for x in links) <= t < min(parse_instant(x["expiresAt"]) for x in links))
        report.add("executed tool within delegated scope", p["tool"]["name"] in leaf["scopes"])
    paths = _note_paths(p)[0] or []
    report.add("captured commitments are well formed", all(is_commitment(_at(p, path)) for path in paths))
    args_withheld = any(_under(path, ("request", "args")) for path in paths)
    report.add("request args digest", st["subject"][0]["digest"]["sha256"] == p["request"]["argsDigest"] and (args_withheld or digest(p["request"]["args"]) == p["request"]["argsDigest"]))
    head = _tree_head(bundle["treeHead"], trust, report)
    if head is not None:
        inclusion = bundle["inclusion"]
        report.add("log inclusion proof", inclusion["treeSize"] == head["treeSize"] and _inclusion(_utf8(canonical_json(env)), inclusion, head))


# Auditing across receipts


def audit_extends(older: Any, newer: Any, proof: Any, keys: list[PublicKey]) -> Report:
    report = Report()
    trust = Trust(issuer=[], log=keys)
    old = _tree_head(older, trust, report, "older ")
    new = _tree_head(newer, trust, report, "newer ")
    if old is None or new is None:
        return report
    if not report.add("older is not larger than newer", old["treeSize"] <= new["treeSize"], f"{old['treeSize']} <= {new['treeSize']}"):
        return report
    hashes = _hashes(proof)
    ok = hashes is not None and verify_consistency(old["treeSize"], new["treeSize"], bytes.fromhex(old["rootHash"]), bytes.fromhex(new["rootHash"]), hashes)
    report.add("newer log extends older log", ok)
    return report


# Command line


def _keys(paths: Optional[list[str]]) -> list[PublicKey]:
    keys = []
    for path in paths or []:
        with open(path, encoding="utf-8") as f:
            keys.append(load_public_key(f.read()))
    return keys


def read_log(path: str) -> list:
    """A log file: one JSON value per line, the leaf as a string or, in a hash-only log, {"hash"}."""
    with open(path, encoding="utf-8") as f:
        return [parse_json(line) for line in f.read().splitlines() if line]


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="agent-custody-verify", description="Verify an agent-custody receipt bundle against the public keys you trust.")
    parser.add_argument("bundle", help="receipts/<receiptId>.json")
    parser.add_argument("--issuer-key", action="append", required=True, help="PEM public key of a trusted issuer; repeatable")
    parser.add_argument("--principal-key", action="append", help="PEM public key of a trusted principal; repeatable")
    parser.add_argument("--approval-key", action="append", help="PEM public key of a trusted human approver; repeatable")
    parser.add_argument("--upstream-key", action="append", help="PEM public key of a trusted upstream; repeatable")
    parser.add_argument("--log-key", action="append", help="PEM public key of a trusted remote log; repeatable")
    parser.add_argument("--provider-secret-env", action="append", default=[], metavar="PROVIDER=VAR", help="environment variable holding a provider's shared secret, e.g. stripe=STRIPE_WEBHOOK_SECRET")
    parser.add_argument("--log", help="a copy of the log, one leaf per line")
    parser.add_argument("--log-id", help="the log id the tree head must name")
    parser.add_argument("--require-strict", action="store_true", help="require a strict gateway and a precommit on every forwarded call")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args(argv)

    secrets = {}
    for item in args.provider_secret_env:
        provider, _, var = item.partition("=")
        if not var or var not in os.environ:
            parser.error(f"--provider-secret-env {item}: set the variable and pass PROVIDER=VAR")
        secrets[provider] = os.environ[var]
    trust = Trust(
        issuer=_keys(args.issuer_key),
        principal=_keys(args.principal_key),
        approval=_keys(args.approval_key),
        upstream=_keys(args.upstream_key),
        log=_keys(args.log_key),
        provider_secrets=secrets,
    )
    with open(args.bundle, encoding="utf-8") as f:
        bundle = parse_json(f.read())
    report = verify_bundle(bundle, trust, log=read_log(args.log) if args.log else None, log_id=args.log_id, require_strict=args.require_strict)
    report.fields = _fields(bundle)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        for c in report.checks:
            print(f"{'PASS' if c.ok else 'FAIL'}  {c.name}" + (f"  ({c.detail})" if c.detail else ""))
        for name, provenance, value in report.fields:
            print(f"{name:<15} {provenance:<11} {value}")
        print("VERIFIED" if report.ok else "NOT VERIFIED")
    return 0 if report.ok else 1


def _fields(bundle: Any) -> list[tuple[str, str, str]]:
    statement = dsse_payload(bundle.get("envelope")) if isinstance(bundle, dict) else None
    p = statement.get("predicate") if isinstance(statement, dict) else None
    if not isinstance(p, dict):
        return []
    rows = []
    for name in ("principal", "agent", "model", "tool"):
        part = p.get(name)
        if isinstance(part, dict):
            rows.append((name, str(part.get("provenance")), str(part.get("name", part.get("id")))))
    if isinstance(p.get("request"), dict):
        rows.append(("args", str(p["request"].get("provenance")), canonical_json(p["request"].get("args"))))
    for name, fact in (p.get("facts") or {}).items():
        if isinstance(fact, dict):
            rows.append((f"fact.{name}", str(fact.get("provenance")), canonical_json(fact.get("value"))))
    if isinstance(p.get("policy"), dict):
        rows.append(("policy", str(p["policy"].get("provenance")), str(p["policy"].get("decision"))))
    if isinstance(p.get("execution"), dict):
        rows.append(("execution", str(p["execution"].get("provenance")), str(p["execution"].get("status"))))
    return rows


if __name__ == "__main__":
    sys.exit(main())
