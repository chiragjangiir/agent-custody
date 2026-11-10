# Against the real crewai package: a BaseTool built with @tool, run the way a crew runs it, through the sidecar.
import pytest
from crewai.tools import tool

from agent_custody.crewai import wrap_tools
from conftest import receipt_count, verify


@tool("stripe.refund")
def refund(amount: int) -> dict:
    """Refund an amount, in minor units."""
    return {"refund_id": "re_crew", "amount": amount}


@tool("customer.lookup")
def lookup(customer_id: str) -> str:
    """Look a customer up."""
    return '{"id": "' + customer_id + '", "verified": true}'


def test_wrapped_tools_enforce_and_record(client, sidecar):
    wrapped = wrap_tools(client, [refund, lookup])
    r, l = wrapped
    assert r.name == "stripe.refund" and r.description == refund.description and r.args_schema is refund.args_schema
    before = receipt_count(sidecar)
    ok = r.run(amount=9)
    assert ok == {"refund_id": "re_crew", "amount": 9}
    denied = r.run(amount=900000)
    assert str(denied).startswith("Denied by policy:")
    found = l.run(customer_id="cust_7")
    assert '"verified": true' in found
    assert receipt_count(sidecar) == before + 3
    # the newest receipts verify with the sidecar's key, and the denial ran nothing
    newest = sorted(sidecar["receipts"].glob("*.json"), key=lambda p: p.stat().st_mtime)[-3:]
    reports = [verify(sidecar, p.stem) for p in newest]
    assert all(r["ok"] for r in reports)
    assert sorted(r["statement"]["predicate"]["execution"]["status"] for r in reports) == ["denied", "executed", "executed"]


@tool("customer.lookup")
def flaky(customer_id: str) -> str:
    """Look a customer up."""
    if customer_id == "down":
        raise RuntimeError("upstream down")
    return "plain " + customer_id


def test_a_tool_that_raises_is_recorded_as_an_error_and_reraised(client, recorded):
    wrapped = wrap_tools(client, [flaky])[0]
    with pytest.raises(RuntimeError, match="upstream down"):
        wrapped.run(customer_id="down")
    assert wrapped.run(customer_id="c1") == "plain c1"
    assert [(p["execution"]["status"], p["execution"].get("error"), p["execution"].get("result")) for p in recorded] == [("error", "upstream down", None), ("executed", None, "plain c1")]
