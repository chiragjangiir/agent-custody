"""OpenAI Agents SDK (Python) adapter: wraps each FunctionTool's on_invoke_tool. Decides, runs, records.

A denied call never runs; the model receives the denial text as the tool result and the run continues.
"""
from __future__ import annotations

import dataclasses
import json
from typing import Any, Dict, List

from agents import FunctionTool

from . import Client, denies, no_receipt, receipt_id_of


def _parse(input_json: str) -> Dict[str, Any]:
    try:
        v = json.loads(input_json) if input_json else {}
        return v if isinstance(v, dict) else {"input": v}
    except ValueError:
        return {"input": input_json}


def _result(v: Any) -> Any:
    if not isinstance(v, str):
        return v
    try:
        return json.loads(v)
    except ValueError:
        return v


def wrap_tools(client: Client, tools: List[FunctionTool]) -> List[FunctionTool]:
    out: List[FunctionTool] = []
    for t in tools:
        original = t.on_invoke_tool

        async def invoke(ctx: Any, input_json: str, _t: FunctionTool = t, _orig=original) -> Any:
            args = _parse(input_json)
            policy = client.decide(_t.name, args)
            if denies(policy):
                reason = "; ".join(policy["reasons"] + policy["errors"]) or "no permit policy matched"
                try:
                    bundle = client.record(_t.name, args, {"status": "denied", "reason": reason}, policy)
                    return f"Denied by policy: {reason} (receipt {receipt_id_of(bundle)})"
                except Exception as e:  # noqa: BLE001 - the call stays denied; the missing receipt is the message
                    return f"Denied by policy: {reason} ({no_receipt(e)})"
            try:
                result = await _orig(ctx, input_json)
            except Exception as e:
                client.record(_t.name, args, {"status": "error", "error": str(e)}, policy)
                raise
            client.record(_t.name, args, {"status": "executed", "result": _result(result)}, policy)
            return result

        out.append(dataclasses.replace(t, on_invoke_tool=invoke))
    return out
