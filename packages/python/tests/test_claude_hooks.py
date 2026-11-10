# The documented Claude Agent SDK hook contract, driven the way the SDK drives it.
import asyncio

from agent_custody.claude_agent_sdk import claude_hook, handle_hook_event
from conftest import receipt_count, verify


def test_pretooluse_denies_with_a_receipt_and_never_auto_approves(client, sidecar):
    out = handle_hook_event(client, {"hook_event_name": "PreToolUse", "session_id": "s1", "tool_use_id": "t1", "tool_name": "stripe.refund", "tool_input": {"amount": 999999}})
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    rid = out["hookSpecificOutput"]["permissionDecisionReason"].split("receipt ")[1].rstrip(")")
    assert verify(sidecar, rid)["statement"]["predicate"]["execution"]["status"] == "denied"
    assert handle_hook_event(client, {"hook_event_name": "PreToolUse", "tool_name": "stripe.refund", "tool_input": {"amount": 1}}) == {}


def test_posttooluse_records_through_the_async_hook_callable(client, sidecar):
    before = receipt_count(sidecar)
    out = asyncio.run(claude_hook(client)({"hook_event_name": "PostToolUse", "tool_name": "customer.lookup", "tool_input": {"id": "c1"}, "tool_response": {"name": "Dana"}}, "t2", None))
    assert out == {} and receipt_count(sidecar) == before + 1


def test_posttoolusefailure_records_a_failed_receipt_with_the_error(client, recorded):
    out = handle_hook_event(client, {"hook_event_name": "PostToolUseFailure", "session_id": "s1", "tool_use_id": "t3", "tool_name": "customer.lookup", "tool_input": "ls -la", "error": "exit 1"})
    assert out == {}
    (p,) = recorded
    assert p["request"]["args"] == {"input": "ls -la"}
    assert (p["execution"]["status"], p["execution"]["result"]) == ("failed", "exit 1")
