"""Claude Agent SDK (Python) hooks. Same contract as the TypeScript adapter and the Claude Code command hook.

PreToolUse: evaluate policy; on deny, record a denial receipt and block. When the sidecar cannot answer, its answer or
the event is malformed, or the receipt cannot be recorded, it still blocks, and the reason says "no receipt: <why>". On
allow or no policy return no decision, so the host's own permission flow still applies. This never auto-approves.
PostToolUse / PostToolUseFailure record.

    from claude_agent_sdk import HookMatcher
    hooks = {event: [HookMatcher(hooks=[claude_hook(client)])] for event in ("PreToolUse", "PostToolUse", "PostToolUseFailure")}
"""
from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from . import Client, denies, receipt_id_of


def _event(input_data: Dict[str, Any]) -> Dict[str, Any]:
    raw = input_data.get("tool_input")
    args = raw if isinstance(raw, dict) else {"input": raw}
    return {"tool": input_data["tool_name"], "args": args, "session": {"id": input_data.get("session_id"), "toolUseId": input_data.get("tool_use_id")}}


def _deny(text: str) -> Dict[str, Any]:
    return {"continue": True, "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": f"agent-custody: {text}"}}


def handle_hook_event(client: Client, input_data: Dict[str, Any]) -> Dict[str, Any]:
    name = input_data.get("hook_event_name")
    if name == "PreToolUse":
        # A hook that raises does not block the call, so every failure here must still answer deny.
        try:
            ev = _event(input_data)
            policy = client.decide(ev["tool"], ev["args"], session=ev["session"])
            if not isinstance(policy, dict) or policy.get("decision") not in ("allow", "deny"):
                raise ValueError("the sidecar answered without an allow or deny decision")
            if not denies(policy):
                return {}
            reason = "; ".join(str(r) for r in [*(policy.get("reasons") or []), *(policy.get("errors") or [])]) or "no permit policy matched"
        except Exception as e:  # noqa: BLE001
            return _deny(f"the policy could not be evaluated; no receipt: {e}")
        try:
            bundle = client.record(ev["tool"], ev["args"], {"status": "denied", "reason": reason}, policy, session=ev["session"])
            evidence = f"receipt {receipt_id_of(bundle)}"
        except Exception as e:  # noqa: BLE001
            evidence = f"no receipt: {e}"
        return _deny(f"{reason} ({evidence})")
    if name not in ("PostToolUse", "PostToolUseFailure"):
        return {}
    ev = _event(input_data)
    if name == "PostToolUse":
        client.record(ev["tool"], ev["args"], {"status": "executed", "result": input_data.get("tool_response")}, client.decide(ev["tool"], ev["args"]), session=ev["session"])
        return {}
    if name == "PostToolUseFailure":
        client.record(ev["tool"], ev["args"], {"status": "failed", "result": input_data.get("error", input_data.get("tool_response"))}, client.decide(ev["tool"], ev["args"]), session=ev["session"])
        return {}
    return {}


def claude_hook(client: Client) -> Callable[[Dict[str, Any], Optional[str], Any], Any]:
    """A hook callable in the shape the Claude Agent SDK expects: (input_data, tool_use_id, context) -> dict."""

    async def hook(input_data: Dict[str, Any], tool_use_id: Optional[str], context: Any) -> Dict[str, Any]:
        return handle_hook_event(client, input_data)

    return hook
