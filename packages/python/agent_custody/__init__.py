"""Receipts for tool calls, from Python.

The signing key, the policy, and the log live in the agent-custody sidecar, `agent-custody serve --config sdk.json`,
a local process. This client talks to it over HTTP with nothing but the standard library. Everything recorded is
claimed, exactly as with the in-process TypeScript SDK: the sidecar trusts what this process reports.
"""
from __future__ import annotations

import base64
import json
import logging
import urllib.error
import urllib.request
from urllib.parse import urlsplit, urlunsplit
from typing import Any, Callable, Dict, Optional

__all__ = ["Client", "PolicyDeniedError", "SidecarError", "no_receipt", "receipt_id_of"]

DEFAULT_URL = "http://127.0.0.1:8788/"

_log = logging.getLogger("agent_custody")


class SidecarError(RuntimeError):
    """The sidecar refused or could not complete a request. No receipt was written.

    `kind` is "unreachable", "status" (the sidecar answered an HTTP error; `status` holds the code), "malformed"
    (the answer was not JSON), or None."""

    def __init__(self, message: str, kind: Optional[str] = None, status: Optional[int] = None):
        super().__init__(message)
        self.kind = kind
        self.status = status


class PolicyDeniedError(PermissionError):
    def __init__(self, tool: str, reason: str, receipt_id: str):
        super().__init__(f"Denied by policy: {reason} (receipt {receipt_id})")
        self.tool = tool
        self.reason = reason
        self.receipt_id = receipt_id


def denies(policy: Optional[Dict[str, Any]]) -> bool:
    """True when a decision is a deny that must be enforced. A deny made in observe mode carries enforced=False: recorded, not acted on."""
    return bool(policy) and policy["decision"] == "deny" and policy.get("enforced", True) is not False


def _shown(url: str) -> str:
    """The URL for an error message: no user, password, query, or fragment."""
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc.rpartition("@")[2], p.path, "", ""))


def no_receipt(e: BaseException) -> str:
    """The end of a deny reason whose receipt could not be written: `no receipt: <why>`. The reason reaches the
    model, so it names the failure class only; the error itself, which can carry a sidecar URL with credentials or
    the text of an upstream answer, goes to the `agent_custody` logger."""
    _log.warning("agent-custody: no receipt: %s", e)
    if isinstance(e, SidecarError):
        if e.kind == "unreachable":
            return "no receipt: the sidecar could not be reached"
        if e.kind == "status" and e.status is not None:
            return f"no receipt: the sidecar answered HTTP {e.status}"
        if e.kind != "malformed":
            return "no receipt: the sidecar refused the request"
    if isinstance(e, (SidecarError, KeyError, TypeError, ValueError)):
        return "no receipt: the sidecar's answer was malformed"
    return f"no receipt: an unexpected {type(e).__name__}"


def receipt_id_of(bundle: Dict[str, Any]) -> str:
    payload = json.loads(base64.b64decode(bundle["envelope"]["payload"]))
    return payload["predicate"]["receiptId"]


def _event(tool: str, args: Optional[Dict[str, Any]], model: Optional[str], session: Optional[Dict[str, Optional[str]]]) -> Dict[str, Any]:
    ev: Dict[str, Any] = {"tool": tool, "args": args or {}}
    if model is not None:
        ev["model"] = model
    if session is not None:
        ev["session"] = session
    return ev


class Client:
    def __init__(self, url: str = DEFAULT_URL, timeout: float = 10.0):
        self.url = url if url.endswith("/") else url + "/"
        self.timeout = timeout

    def _post(self, path: str, body: Any) -> Any:
        req = urllib.request.Request(self.url + path, data=json.dumps(body).encode(), headers={"content-type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as res:
                raw = res.read()
        except urllib.error.HTTPError as e:
            try:
                detail = json.loads(e.read()).get("error", "")
            except Exception:
                detail = ""
            raise SidecarError(f"sidecar {path}: {e.code} {detail}".strip(), "status", e.code) from None
        except urllib.error.URLError as e:
            raise SidecarError(f"sidecar unreachable at {_shown(self.url)}: {e.reason}", "unreachable") from None
        except OSError as e:
            raise SidecarError(f"sidecar unreachable at {_shown(self.url)}: {e}", "unreachable") from None
        try:
            return json.loads(raw)
        except ValueError:
            raise SidecarError(f"sidecar {path}: the answer is not JSON", "malformed") from None

    def health(self) -> Dict[str, Any]:
        with urllib.request.urlopen(self.url + "health", timeout=self.timeout) as res:
            return json.loads(res.read())

    def decide(self, tool: str, args: Optional[Dict[str, Any]] = None, *, model: Optional[str] = None, session: Optional[Dict[str, Optional[str]]] = None) -> Optional[Dict[str, Any]]:
        """The configured policy's decision for this call, or None when the sidecar has no policy."""
        return self._post("decide", _event(tool, args, model, session))

    def record(self, tool: str, args: Optional[Dict[str, Any]], outcome: Dict[str, Any], policy: Optional[Dict[str, Any]] = None, *, model: Optional[str] = None, session: Optional[Dict[str, Optional[str]]] = None) -> Dict[str, Any]:
        """Issues one receipt. `outcome` is {"status": "executed"|"failed", "result": ...}, {"status": "denied", "reason": ...}, or {"status": "error", "error": ...}."""
        return self._post("record", {"event": _event(tool, args, model, session), "outcome": outcome, "policy": policy})

    def wrap(self, tool: str, fn: Callable[[Dict[str, Any]], Any], *, model: Optional[str] = None) -> Callable[[Dict[str, Any]], Any]:
        """decide, run, record. Raises PolicyDeniedError on deny, after recording the denial."""

        def wrapped(args: Dict[str, Any]) -> Any:
            policy = self.decide(tool, args, model=model)
            if denies(policy):
                reason = "; ".join(policy["reasons"] + policy["errors"]) or "no permit policy matched"
                bundle = self.record(tool, args, {"status": "denied", "reason": reason}, policy, model=model)
                raise PolicyDeniedError(tool, reason, receipt_id_of(bundle))
            try:
                result = fn(args)
            except Exception as e:
                self.record(tool, args, {"status": "error", "error": str(e)}, policy, model=model)
                raise
            self.record(tool, args, {"status": "executed", "result": result}, policy, model=model)
            return result

        wrapped.__name__ = getattr(fn, "__name__", tool)
        return wrapped
