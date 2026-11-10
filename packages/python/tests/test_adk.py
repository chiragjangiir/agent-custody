# Google ADK, the real package, driven by its own runner with a scripted model and no network: the before callback
# skips a denied tool and the model sees the receipt id; an allowed tool runs and is recorded once; every receipt
# passes the TypeScript verifier.
import asyncio
from types import SimpleNamespace

import pytest
from google.adk.agents import LlmAgent
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import InMemoryRunner
from google.adk.tools.base_tool import BaseTool
from google.genai import types

from agent_custody import Client, SidecarError
from agent_custody.adk import RECEIPT_KEY, adk_callbacks
from conftest import receipt_count, verify


class RefundTool(BaseTool):
    """A tool named as the policy names it. ADK's FunctionTool takes its name from the function, which cannot hold a dot."""

    def __init__(self, calls):
        super().__init__(name="stripe.refund", description="Refund a customer, amount in minor units")
        self._calls = calls

    def _get_declaration(self):
        return types.FunctionDeclaration(name=self.name, description=self.description, parameters=types.Schema(type="OBJECT", properties={"amount": types.Schema(type="INTEGER")}, required=["amount"]))

    async def run_async(self, *, args, tool_context):
        self._calls.append(dict(args))
        return {"refund_id": "re_1", "amount": args["amount"], "status": "succeeded"}


class Scripted(BaseLlm):
    """Turn one: call stripe.refund with the amount in the user's text. Turn two: repeat what the tool answered."""

    model: str = "scripted"

    async def generate_content_async(self, llm_request, stream=False):
        contents = llm_request.contents
        responses = [p.function_response for c in contents for p in (c.parts or []) if p.function_response]
        if responses:
            yield LlmResponse(content=types.Content(role="model", parts=[types.Part(text=f"tool answered: {responses[-1].response}")]))
            return
        user = next(p.text for c in contents for p in (c.parts or []) if p.text)
        amount = int(user.split()[-1])
        yield LlmResponse(content=types.Content(role="model", parts=[types.Part(function_call=types.FunctionCall(name="stripe.refund", args={"amount": amount}))]))


def run(agent, text):
    async def go():
        runner = InMemoryRunner(agent=agent, app_name="t")
        session = await runner.session_service.create_session(app_name="t", user_id="u")
        out = []
        async for ev in runner.run_async(user_id="u", session_id=session.id, new_message=types.Content(role="user", parts=[types.Part(text=text)])):
            out.append(ev)
        return out

    return asyncio.run(go())


def final_text(events):
    return next(p.text for ev in reversed(events) for p in (ev.content.parts if ev.content else []) if p.text)


def function_responses(events):
    return [p.function_response.response for ev in events for p in (ev.content.parts if ev.content else []) if p.function_response]


def test_denied_tool_is_skipped_and_the_model_sees_the_receipt(sidecar, client):
    calls = []
    agent = LlmAgent(name="billing", model=Scripted(), tools=[RefundTool(calls)], **adk_callbacks(client))
    before = receipt_count(sidecar)
    events = run(agent, "refund 999999")
    assert calls == []
    (response,) = function_responses(events)
    assert response["error"].startswith("agent-custody: no permit policy matched (receipt ")
    assert "agent-custody: no permit policy matched" in final_text(events)
    assert receipt_count(sidecar) == before + 1
    rid = response[RECEIPT_KEY]
    report = verify(sidecar, rid)
    assert report["ok"], report
    predicate = report["statement"]["predicate"]
    assert predicate["execution"]["status"] == "denied"
    assert predicate["tool"]["name"] == "stripe.refund"
    assert predicate["session"]["id"] and predicate["session"]["toolUseId"]


def test_allowed_tool_runs_and_is_recorded_once(sidecar, client):
    calls = []
    agent = LlmAgent(name="billing", model=Scripted(), tools=[RefundTool(calls)], **adk_callbacks(client))
    before = receipt_count(sidecar)
    events = run(agent, "refund 2500")
    assert calls == [{"amount": 2500}]
    (response,) = function_responses(events)
    assert response["status"] == "succeeded" and RECEIPT_KEY not in response
    assert "succeeded" in final_text(events)
    assert receipt_count(sidecar) == before + 1
    newest = max(sidecar["receipts"].glob("*.json"), key=lambda p: p.stat().st_mtime)
    report = verify(sidecar, newest.stem)
    assert report["ok"], report
    predicate = report["statement"]["predicate"]
    assert predicate["execution"]["status"] == "executed"
    assert predicate["execution"]["result"]["refund_id"] == "re_1"
    assert predicate["request"]["args"] == {"amount": 2500}


def test_callbacks_are_the_two_llm_agent_fields():
    assert set(adk_callbacks(None)) == {"before_tool_callback", "after_tool_callback"}


def test_a_denial_that_cannot_be_recorded_still_skips_the_tool(client, monkeypatch):
    def refuse(*a, **k):
        raise SidecarError("sidecar record: 503")

    monkeypatch.setattr(client, "record", refuse)
    out = adk_callbacks(client)["before_tool_callback"](SimpleNamespace(name="stripe.refund"), {"amount": 999999}, SimpleNamespace())
    assert out == {"error": "agent-custody: no permit policy matched (no receipt: the sidecar refused the request)", RECEIPT_KEY: None}


def test_a_response_that_is_not_json_is_recorded_as_text(client, recorded):
    class Answer:
        def __str__(self):
            return "Dana"

    ctx = SimpleNamespace(invocation_id="inv-1", function_call_id="fc-1")
    assert adk_callbacks(client)["after_tool_callback"](SimpleNamespace(name="customer.lookup"), {"id": "c1"}, ctx, Answer()) is None
    assert recorded[0]["execution"]["result"] == "Dana"


# A before_tool_callback that raises ends the whole ADK run, and one that returns None lets the tool run. So a sidecar
# that cannot answer, or answers something that is neither a decision nor "no policy", must come back as the error
# dict: the tool is skipped, the model is told why, and the run goes on. Driven through ADK's own runner.
def test_an_unreachable_sidecar_skips_the_tool_and_the_run_goes_on():
    calls = []
    agent = LlmAgent(name="billing", model=Scripted(), tools=[RefundTool(calls)], **adk_callbacks(Client("http://127.0.0.1:9/", timeout=2)))
    events = run(agent, "refund 2500")
    assert calls == []
    (response,) = function_responses(events)
    assert response["error"] == "agent-custody: the policy could not be evaluated; no receipt: the sidecar could not be reached"
    assert response[RECEIPT_KEY] is None


@pytest.mark.parametrize("answer", [{}, {"decision": "maybe"}, {"verdict": "allow"}, [], "allow"])
def test_an_answer_without_allow_or_deny_skips_the_tool(client, monkeypatch, answer):
    monkeypatch.setattr(client, "decide", lambda *a, **k: answer)
    calls = []
    agent = LlmAgent(name="billing", model=Scripted(), tools=[RefundTool(calls)], **adk_callbacks(client))
    events = run(agent, "refund 2500")
    assert calls == []
    (response,) = function_responses(events)
    assert response["error"] == "agent-custody: the policy could not be evaluated; no receipt: the sidecar's answer was malformed"


@pytest.mark.parametrize("answer", [{"decision": "deny"}, {"decision": "deny", "reasons": None, "errors": None}, {"decision": "deny", "reasons": 7}])
def test_a_deny_without_reasons_or_errors_still_skips_the_tool(client, monkeypatch, answer):
    monkeypatch.setattr(client, "decide", lambda *a, **k: answer)
    out = adk_callbacks(client)["before_tool_callback"](SimpleNamespace(name="stripe.refund"), {"amount": 999999}, SimpleNamespace())
    assert out["error"].startswith("agent-custody: ") and RECEIPT_KEY in out


def test_no_policy_lets_the_tool_run(client, monkeypatch):
    monkeypatch.setattr(client, "decide", lambda *a, **k: None)  # what /decide answers when the sidecar has no policy
    assert adk_callbacks(client)["before_tool_callback"](SimpleNamespace(name="customer.lookup"), {"id": "c1"}, SimpleNamespace()) is None


def test_credentials_in_the_sidecar_url_never_reach_the_model():
    calls = []
    agent = LlmAgent(name="billing", model=Scripted(), tools=[RefundTool(calls)], **adk_callbacks(Client("http://user:pass@127.0.0.1:9/?token=abc", timeout=2)))
    events = run(agent, "refund 2500")
    assert calls == []
    (response,) = function_responses(events)
    for secret in ("user", "pass", "token", "abc", "127.0.0.1"):
        assert secret not in response["error"] and secret not in final_text(events)
