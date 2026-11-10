"""Hermes Agent plugin hooks. Hermes (Nous Research) runs Python plugins in the agent's process and fires
`pre_tool_call`, which may block a call, and `post_tool_call`, which carries the result. This module gives both,
built on the sidecar client, and a `register(ctx)` so the directory can be dropped in as a plugin.

    ~/.hermes/plugins/agent-custody/plugin.yaml   (see packages/python/hermes-plugin/)
    ~/.hermes/plugins/agent-custody/__init__.py   from agent_custody.hermes import register

pre_tool_call: evaluate the policy; on deny, record a denial receipt and return the block, whose message names the
receipt. On allow, or with no policy, return None so Hermes's own guardrails and approvals still apply; this never
auto-approves. When the sidecar cannot answer, answers without an allow or deny decision, or cannot record the denial,
the call is blocked all the same, and the message says "no receipt: <why>": nothing runs without evidence. Hermes
releases before v2026.9.24 skip a hook that raises and run the tool, so this hook never raises. post_tool_call
records the completed call; Hermes passes the result as the tool's JSON string.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from . import Client, denies, no_receipt, receipt_id_of


def _session(task_id: Optional[str], kwargs: Dict[str, Any]) -> Dict[str, Optional[str]]:
    return {"id": task_id, "toolUseId": kwargs.get("tool_call_id")}


def hermes_hooks(client: Client) -> Dict[str, Callable[..., Any]]:
    """The two callbacks, keyed by the hook name Hermes registers them under."""

    def pre_tool_call(tool_name: str, args: Optional[Dict[str, Any]] = None, task_id: Optional[str] = None, **kwargs: Any) -> Optional[Dict[str, str]]:
        # Older Hermes releases run the tool when this hook raises, and an answer read as "not a deny" lets it run, so
        # every failure answers a block instead.
        try:
            session = _session(task_id, kwargs)
            policy = client.decide(tool_name, args, session=session)
            if policy is not None and (not isinstance(policy, dict) or policy.get("decision") not in ("allow", "deny")):
                raise ValueError("the sidecar answered without an allow or deny decision")
            if not denies(policy):
                return None
            reason = "; ".join(str(r) for r in [*(policy.get("reasons") or []), *(policy.get("errors") or [])]) or "no permit policy matched"
        except Exception as e:  # noqa: BLE001
            return {"action": "block", "message": f"agent-custody: the policy could not be evaluated; {no_receipt(e)}"}
        try:
            evidence = f"receipt {receipt_id_of(client.record(tool_name, args, {'status': 'denied', 'reason': reason}, policy, session=session))}"
        except Exception as e:  # noqa: BLE001 - the block stands; the missing receipt is the message
            evidence = no_receipt(e)
        return {"action": "block", "message": f"agent-custody: {reason} ({evidence})"}

    def post_tool_call(tool_name: str, args: Optional[Dict[str, Any]] = None, result: Any = None, task_id: Optional[str] = None, duration_ms: Optional[int] = None, **kwargs: Any) -> None:
        session = _session(task_id, kwargs)
        client.record(tool_name, args, {"status": "executed", "result": result}, client.decide(tool_name, args, session=session), session=session)

    return {"pre_tool_call": pre_tool_call, "post_tool_call": post_tool_call}


def register_hermes(ctx: Any, client: Client) -> None:
    """Registers both hooks on a plugin context (`ctx.register_hook(name, fn)`)."""
    for name, fn in hermes_hooks(client).items():
        ctx.register_hook(name, fn)


def register(ctx: Any) -> None:
    """The plugin entry point Hermes calls once at startup. The sidecar URL comes from the plugin's settings
    (`sidecar_url`, default http://127.0.0.1:8788), the same sidecar every other Python adapter uses."""
    url = ctx.get_config("sidecar_url", default="http://127.0.0.1:8788") if hasattr(ctx, "get_config") else "http://127.0.0.1:8788"
    register_hermes(ctx, Client(url))
