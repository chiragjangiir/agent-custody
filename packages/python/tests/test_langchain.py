# Against the real langchain-core: a StructuredTool invoked with the handler in the config. No model, no network.
from uuid import uuid4

import pytest
from langchain_core.messages import ToolMessage
from langchain_core.tools import tool

from agent_custody.langchain import ReceiptCallbackHandler
from conftest import receipt_count, verify


@tool
def refund(amount: int) -> dict:
    """Refund an amount."""
    return {"refund_id": "re_lc", "amount": amount}


@tool
def flaky(id: str) -> dict:
    """Always fails."""
    raise RuntimeError("upstream down")


def test_every_tool_run_gets_a_receipt(client, sidecar):
    handler = ReceiptCallbackHandler(client)
    before = receipt_count(sidecar)
    assert refund.invoke({"amount": 7}, config={"callbacks": [handler]}) == {"refund_id": "re_lc", "amount": 7}
    try:
        flaky.invoke({"id": "c1"}, config={"callbacks": [handler]})
    except RuntimeError:
        pass
    assert receipt_count(sidecar) == before + 2
    newest = sorted(sidecar["receipts"].glob("*.json"), key=lambda p: p.stat().st_mtime)[-2:]
    statuses = {verify(sidecar, p.stem)["statement"]["predicate"]["execution"]["status"] for p in newest}
    assert statuses == {"executed", "error"}


def test_unparsed_input_and_tool_message_output_are_recorded_as_they_are(client, recorded):
    handler = ReceiptCallbackHandler(client)
    a, b = uuid4(), uuid4()
    handler.on_tool_start({"name": "customer.lookup"}, "not json", run_id=a)
    handler.on_tool_end(ToolMessage(content="plain text", tool_call_id="t1"), run_id=a)
    handler.on_tool_start({"name": "customer.lookup"}, "[1, 2]", run_id=b)
    handler.on_tool_end(ToolMessage(content='{"name": "Dana"}', tool_call_id="t2"), run_id=b)
    assert [(p["request"]["args"], p["execution"]["result"]) for p in recorded] == [({"input": "not json"}, "plain text"), ({"input": [1, 2]}, {"name": "Dana"})]


def test_a_tool_error_is_recorded_with_its_message(client, recorded):
    with pytest.raises(RuntimeError, match="upstream down"):
        flaky.invoke({"id": "c1"}, config={"callbacks": [ReceiptCallbackHandler(client)]})
    (p,) = recorded
    assert p["request"]["args"] == {"id": "c1"}
    assert (p["execution"]["status"], p["execution"]["error"]) == ("error", "upstream down")


def test_an_end_or_error_with_no_pending_run_records_nothing(client, sidecar):
    handler = ReceiptCallbackHandler(client)
    before = receipt_count(sidecar)
    handler.on_tool_end("out", run_id=uuid4())
    handler.on_tool_error(RuntimeError("x"), run_id=uuid4())
    assert receipt_count(sidecar) == before
