"""Google ADK callbacks. ADK runs `before_tool_callback(tool, args, tool_context)` before every tool call; a dict
returned there skips the tool and becomes its result. `after_tool_callback(tool, args, tool_context, tool_response)`
runs after the tool and may replace the response. This module gives both, built on the sidecar client, so every
tool call an ADK agent makes gets a receipt and a denied one never runs.

    from google.adk.agents import LlmAgent
    from agent_custody import Client
    from agent_custody.adk import adk_callbacks

    agent = LlmAgent(name="billing", model="gemini-2.5-flash", tools=[...], **adk_callbacks(Client()))

before_tool_callback: evaluate the policy; on deny, record a denial receipt and return the error dict naming the
receipt, which the model sees as the tool's result. On allow, or with no policy, return None so the tool runs. If the
denial receipt cannot be recorded the call is still skipped: nothing runs without evidence. after_tool_callback
records the completed call and returns None, leaving the response as it was; the denial dict the before callback
returned is recognised and not recorded a second time.

Delegations an ADK agent makes to another agent over A2A (RemoteA2aAgent) are not tool calls and do not pass through
these callbacks; the gateway's A2A front (`agent-custody gateway --a2a`) covers them.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from . import Client, denies, no_receipt, receipt_id_of

RECEIPT_KEY = "agent-custody/receipt"


def _session(tool_context: Any) -> Dict[str, Optional[str]]:
    return {"id": getattr(tool_context, "invocation_id", None), "toolUseId": getattr(tool_context, "function_call_id", None)}


def _plain(value: Any) -> Any:
    """What the sidecar records as the result: JSON as it is, anything else as text."""
    if value is None or isinstance(value, (bool, int, float, str, list, dict)):
        return value
    return str(value)


def adk_callbacks(client: Client) -> Dict[str, Callable[..., Any]]:
    """The two callbacks, keyed by the LlmAgent fields they go in: `LlmAgent(..., **adk_callbacks(client))`."""

    def before_tool_callback(tool: Any, args: Dict[str, Any], tool_context: Any) -> Optional[Dict[str, Any]]:
        session = _session(tool_context)
        policy = client.decide(tool.name, args, session=session)
        if not denies(policy):
            return None
        reason = "; ".join(policy["reasons"] + policy["errors"]) or "no permit policy matched"
        try:
            bundle = client.record(tool.name, args, {"status": "denied", "reason": reason}, policy, session=session)
            rid = receipt_id_of(bundle)
            return {"error": f"agent-custody: {reason} (receipt {rid})", RECEIPT_KEY: rid}
        except Exception as e:  # noqa: BLE001 - the call stays skipped; the missing receipt is the message
            return {"error": f"agent-custody: {reason} ({no_receipt(e)})", RECEIPT_KEY: None}

    def after_tool_callback(tool: Any, args: Dict[str, Any], tool_context: Any, tool_response: Any) -> Optional[Dict[str, Any]]:
        if isinstance(tool_response, dict) and RECEIPT_KEY in tool_response:
            return None  # the denial above, already recorded
        session = _session(tool_context)
        client.record(tool.name, args, {"status": "executed", "result": _plain(tool_response)}, client.decide(tool.name, args, session=session), session=session)
        return None

    return {"before_tool_callback": before_tool_callback, "after_tool_callback": after_tool_callback}
