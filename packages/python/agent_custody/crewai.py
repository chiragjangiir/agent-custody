"""CrewAI adapter: every tool call is decided, run, and recorded through the sidecar.

Enforce. A denied call never runs; the agent receives the denial text as the tool's result and the crew continues,
which is how CrewAI expects a tool to report a problem. Each wrapped tool keeps its name, description, and argument
schema, so the crew and the model see the same tool as before; only its run goes through custody.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional, Type

from crewai.tools import BaseTool
from pydantic import BaseModel, PrivateAttr

from . import Client, denies, no_receipt, receipt_id_of


def _result(v: Any) -> Any:
    if not isinstance(v, str):
        return v
    try:
        return json.loads(v)
    except ValueError:
        return v


class CustodyTool(BaseTool):
    """A CrewAI tool whose run is decided, executed, and recorded. Built by `wrap_tools`; not constructed by hand."""

    name: str
    description: str
    args_schema: Optional[Type[BaseModel]] = None
    _inner: BaseTool = PrivateAttr()
    _client: Client = PrivateAttr()

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        recorded: Dict[str, Any] = dict(kwargs) if kwargs else ({"input": args[0]} if len(args) == 1 else {"input": list(args)} if args else {})
        try:
            policy = self._client.decide(self.name, recorded)
            if policy is not None and (not isinstance(policy, dict) or policy.get("decision") not in ("allow", "deny")):
                raise ValueError("the sidecar answered without an allow or deny decision")
            denied = denies(policy)
            reason = ("; ".join(str(r) for r in [*(policy.get("reasons") or []), *(policy.get("errors") or [])]) or "no permit policy matched") if denied else ""
        except Exception as e:  # noqa: BLE001 - CrewAI hands a tool's exception text to the model, so a failure is a denial
            return f"Denied by policy: the policy could not be evaluated; {no_receipt(e)}"
        if denied:
            try:
                bundle = self._client.record(self.name, recorded, {"status": "denied", "reason": reason}, policy)
                return f"Denied by policy: {reason} (receipt {receipt_id_of(bundle)})"
            except Exception as e:  # noqa: BLE001 - the call stays denied; the missing receipt is the message
                return f"Denied by policy: {reason} ({no_receipt(e)})"
        try:
            result = self._inner._run(*args, **kwargs)
        except Exception as e:  # noqa: BLE001 - recorded, then re-raised as the tool raised it
            self._client.record(self.name, recorded, {"status": "error", "error": str(e)}, policy)
            raise
        self._client.record(self.name, recorded, {"status": "executed", "result": _result(result)}, policy)
        return result


def wrap_tools(client: Client, tools: Iterable[BaseTool]) -> List[BaseTool]:
    """Returns one CustodyTool per tool, same name, description, and schema, with the run under custody."""
    out: List[BaseTool] = []
    for t in tools:
        w = CustodyTool(name=t.name, description=t.description, args_schema=getattr(t, "args_schema", None))
        w._inner = t
        w._client = client
        out.append(w)
    return out
