# Against the real openai-agents package: a FunctionTool built by @function_tool, invoked the way the runner invokes it.
import asyncio

import pytest
from agents import ModelBehaviorError, RunConfig, function_tool
from agents.tool_context import ToolContext

from agent_custody.openai_agents import wrap_tools
from conftest import receipt_count, verify


@function_tool(name_override="stripe.refund")
def refund(amount: int) -> dict:
    """Refund an amount."""
    return {"refund_id": "re_oa", "amount": amount}


def test_wrapped_tool_enforces_and_records(client, sidecar):
    wrapped = wrap_tools(client, [refund])[0]
    ctx = lambda input_json: ToolContext(context=None, tool_name="stripe.refund", tool_call_id="call-1", tool_arguments=input_json, run_config=RunConfig())
    before = receipt_count(sidecar)
    ok = asyncio.run(wrapped.on_invoke_tool(ctx('{"amount": 9}'), '{"amount": 9}'))
    denied = asyncio.run(wrapped.on_invoke_tool(ctx('{"amount": 900000}'), '{"amount": 900000}'))
    assert "re_oa" in str(ok)
    assert str(denied).startswith("Denied by policy:")
    assert receipt_count(sidecar) == before + 2
    assert wrapped.name == refund.name and wrapped.params_json_schema == refund.params_json_schema


@function_tool(name_override="customer.lookup", failure_error_function=None)
def lookup(id: str) -> str:
    """Look a customer up."""
    if id == "down":
        raise RuntimeError("upstream down")
    return "plain " + id


def invoke(tool, input_json):
    ctx = ToolContext(context=None, tool_name=tool.name, tool_call_id="call-2", tool_arguments=input_json, run_config=RunConfig())
    return asyncio.run(tool.on_invoke_tool(ctx, input_json))


def test_a_tool_that_raises_is_recorded_as_an_error_and_reraised(client, recorded):
    wrapped = wrap_tools(client, [lookup])[0]
    with pytest.raises(RuntimeError, match="upstream down"):
        invoke(wrapped, '{"id": "down"}')
    with pytest.raises(ModelBehaviorError):
        invoke(wrapped, "not json")
    assert [(p["request"]["args"], p["execution"]["status"]) for p in recorded] == [({"id": "down"}, "error"), ({"input": "not json"}, "error")]
    assert recorded[0]["execution"]["error"] == "upstream down"


def test_a_plain_text_result_is_recorded_as_text(client, recorded):
    assert invoke(wrap_tools(client, [lookup])[0], '{"id": "c1"}') == "plain c1"
    assert recorded[0]["execution"]["result"] == "plain c1"
