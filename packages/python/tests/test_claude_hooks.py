# The documented Claude Agent SDK hook contract, driven the way the SDK drives it.
import asyncio

from agent_custody import Client, SidecarError
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


# The SDK does not block a call whose hook raises, so a sidecar or log failure must still come back as a deny.
def test_a_denial_that_cannot_be_recorded_still_denies(client, monkeypatch):
    def broken(*a, **k):
        raise SidecarError("sidecar /record: 503 log unreachable")

    monkeypatch.setattr(client, "record", broken)
    out = handle_hook_event(client, {"hook_event_name": "PreToolUse", "tool_name": "stripe.refund", "tool_input": {"amount": 999999}})
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert out["hookSpecificOutput"]["permissionDecisionReason"].endswith("(no receipt: sidecar /record: 503 log unreachable)")


def test_an_unreachable_sidecar_denies_instead_of_raising():
    out = asyncio.run(claude_hook(Client("http://127.0.0.1:9/", timeout=2))({"hook_event_name": "PreToolUse", "tool_name": "customer.lookup", "tool_input": {"id": "c1"}}, "t3", None))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "the policy could not be evaluated; no receipt: sidecar unreachable" in out["hookSpecificOutput"]["permissionDecisionReason"]
