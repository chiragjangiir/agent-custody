import io
import urllib.error
import urllib.request

import pytest

from agent_custody import Client, PolicyDeniedError, SidecarError, receipt_id_of
from conftest import closed_port, receipt_count, verify


def test_health_names_the_agent(client):
    h = client.health()
    assert h["agentId"] == "py-bot" and h["log"]["kind"] == "file"


def test_decide_runs_the_policy_on_args(client):
    assert client.decide("stripe.refund", {"amount": 500})["decision"] == "allow"
    assert client.decide("stripe.refund", {"amount": 500000})["decision"] == "deny"


def test_record_produces_a_receipt_the_typescript_verifier_accepts(client, sidecar):
    policy = client.decide("stripe.refund", {"amount": 500})
    bundle = client.record("stripe.refund", {"amount": 500}, {"status": "executed", "result": {"refund_id": "re_1"}}, policy, session={"id": "s1", "toolUseId": "t1"})
    v = verify(sidecar, receipt_id_of(bundle))
    assert v["ok"], [c for c in v["checks"] if not c["ok"]]
    p = v["statement"]["predicate"]
    assert p["issuer"]["kind"] == "sdk" and p["issuer"]["framework"] == "python"
    assert p["session"] == {"id": "s1", "toolUseId": "t1", "provenance": "claimed"}
    assert p["policy"]["decision"] == "allow"


def test_wrap_decides_runs_records_and_denies(client, sidecar):
    calls = []
    refund = client.wrap("stripe.refund", lambda args: calls.append(args) or {"ok": True, **args})
    before = receipt_count(sidecar)
    assert refund({"amount": 500}) == {"ok": True, "amount": 500}
    with pytest.raises(PolicyDeniedError) as e:
        refund({"amount": 500000})
    assert calls == [{"amount": 500}], "the denied call never ran"
    assert receipt_count(sidecar) == before + 2
    assert verify(sidecar, e.value.receipt_id)["statement"]["predicate"]["execution"]["status"] == "denied"


def test_wrap_records_an_error_and_rethrows(client, sidecar):
    def boom(args):
        raise RuntimeError("upstream down")

    lookup = client.wrap("customer.lookup", boom)
    before = receipt_count(sidecar)
    with pytest.raises(RuntimeError, match="upstream down"):
        lookup({"id": "c1"})
    assert receipt_count(sidecar) == before + 1


def test_a_malformed_record_is_refused_and_nothing_is_written(client, sidecar):
    before = receipt_count(sidecar)
    with pytest.raises(SidecarError, match="400"):
        client.record("t", {}, {"status": "maybe"})
    assert receipt_count(sidecar) == before


def test_an_unreachable_sidecar_is_a_sidecar_error():
    url = f"http://127.0.0.1:{closed_port()}/"
    with pytest.raises(SidecarError, match=f"^sidecar unreachable at {url}: "):
        Client(url).decide("customer.lookup", {})


def test_an_http_error_carries_the_sidecars_detail(sidecar):
    with pytest.raises(SidecarError, match="^sidecar decide: 404 not found$"):
        Client(sidecar["url"] + "nope/").decide("customer.lookup", {})


def test_an_http_error_without_a_json_body_carries_the_status(monkeypatch):
    def fail(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 502, "Bad Gateway", {}, io.BytesIO(b"<html>bad gateway</html>"))

    monkeypatch.setattr(urllib.request, "urlopen", fail)
    with pytest.raises(SidecarError, match="^sidecar decide: 502$"):
        Client().decide("customer.lookup", {})
