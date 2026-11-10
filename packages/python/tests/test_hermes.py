# The documented Hermes hook contract, driven the way Hermes drives it: pre_tool_call(tool_name, args, task_id, **kwargs)
# returning a block or None, post_tool_call(tool_name, args, result, task_id, duration_ms, **kwargs). Against the real sidecar.
import pytest

from agent_custody import Client, SidecarError
from agent_custody.hermes import hermes_hooks, register, register_hermes
from conftest import receipt_count, verify


class Ctx:
    def __init__(self, url):
        self.hooks = {}
        self.url = url

    def register_hook(self, name, fn):
        self.hooks[name] = fn

    def get_config(self, key, default=None):
        return self.url if key == "sidecar_url" else default


def test_pre_tool_call_blocks_a_denied_call_with_a_receipt_and_stays_silent_on_allow(client, sidecar):
    hooks = hermes_hooks(client)
    out = hooks["pre_tool_call"]("stripe.refund", {"amount": 999999}, "task-1", tool_call_id="call-2", extra="ignored")
    assert out["action"] == "block"
    rid = out["message"].split("receipt ")[1].rstrip(")")
    st = verify(sidecar, rid)["statement"]["predicate"]
    assert st["execution"]["status"] == "denied" and st["session"]["id"] == "task-1" and st["session"]["toolUseId"] == "call-2"
    assert hooks["pre_tool_call"]("stripe.refund", {"amount": 1}, "task-1") is None  # never auto-approves: no action, Hermes decides


def test_post_tool_call_records_the_result_and_the_plugin_entry_registers_both(client, sidecar):
    before = receipt_count(sidecar)
    hermes_hooks(client)["post_tool_call"]("customer.lookup", {"id": "c1"}, '{"name": "Dana"}', "task-1", 12, tool_call_id="call-3")
    assert receipt_count(sidecar) == before + 1
    ctx = Ctx(sidecar["url"])
    register(ctx)
    assert set(ctx.hooks) == {"pre_tool_call", "post_tool_call"}
    assert ctx.hooks["pre_tool_call"]("stripe.refund", {"amount": 999999}, "task-2")["action"] == "block"
    ctx2 = Ctx(sidecar["url"])
    register_hermes(ctx2, client)
    assert set(ctx2.hooks) == {"pre_tool_call", "post_tool_call"}


def test_a_denial_that_cannot_be_recorded_still_blocks(client, monkeypatch):
    def refuse(*a, **k):
        raise SidecarError("sidecar record: 503")

    monkeypatch.setattr(client, "record", refuse)
    out = hermes_hooks(client)["pre_tool_call"]("stripe.refund", {"amount": 999999}, "task-3")
    assert out == {"action": "block", "message": "agent-custody: no permit policy matched (no receipt: the sidecar refused the request)"}


# Hermes releases before v2026.9.24 log a pre_tool_call hook that raises and run the tool, and a hook that returns None
# lets it run on every release. So each failure on the way to a decision must come back as a block, never a raise.
def test_an_unreachable_sidecar_blocks_instead_of_raising():
    out = hermes_hooks(Client("http://127.0.0.1:9/", timeout=2))["pre_tool_call"]("customer.lookup", {"id": "c1"}, "task-4")
    assert out["action"] == "block"
    assert out["message"] == "agent-custody: the policy could not be evaluated; no receipt: the sidecar could not be reached"


@pytest.mark.parametrize("answer", [{}, {"decision": "maybe"}, {"verdict": "allow"}, [], "allow"])
def test_an_answer_without_allow_or_deny_blocks(client, monkeypatch, answer):
    monkeypatch.setattr(client, "decide", lambda *a, **k: answer)
    out = hermes_hooks(client)["pre_tool_call"]("customer.lookup", {"id": "c1"}, "task-5")
    assert out == {"action": "block", "message": "agent-custody: the policy could not be evaluated; no receipt: the sidecar's answer was malformed"}


@pytest.mark.parametrize("answer", [{"decision": "deny"}, {"decision": "deny", "reasons": None, "errors": None}, {"decision": "deny", "reasons": 7}])
def test_a_deny_without_reasons_or_errors_still_blocks(client, monkeypatch, answer):
    monkeypatch.setattr(client, "decide", lambda *a, **k: answer)
    out = hermes_hooks(client)["pre_tool_call"]("stripe.refund", {"amount": 999999}, "task-6")
    assert out["action"] == "block" and out["message"].startswith("agent-custody: ")


def test_no_policy_stays_silent(client, monkeypatch):
    monkeypatch.setattr(client, "decide", lambda *a, **k: None)  # what /decide answers when the sidecar has no policy
    assert hermes_hooks(client)["pre_tool_call"]("customer.lookup", {"id": "c1"}, "task-7") is None


def test_credentials_in_the_sidecar_url_never_reach_the_model():
    out = hermes_hooks(Client("http://user:pass@127.0.0.1:9/?token=abc", timeout=2))["pre_tool_call"]("stripe.refund", {"amount": 999999}, "task-8")
    assert out["action"] == "block"
    for secret in ("user", "pass", "token", "abc", "127.0.0.1"):
        assert secret not in out["message"]
