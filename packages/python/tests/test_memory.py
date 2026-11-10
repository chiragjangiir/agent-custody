# Against the real memory server over HTTP, started from the state package. Writes from here are claimed and quarantined.
import asyncio
import json

import httpx
import pytest

from agent_custody.memory import MemoryClient, MemoryError, _refusal
from conftest import closed_port


def run(coro):
    return asyncio.run(coro)


def test_write_read_retract_history(memory_server):
    async def go():
        async with MemoryClient(memory_server["url"], token=memory_server["token"]) as memory:
            w = await memory.write("acct:42", "plan", "pro", space="team:support", actor="py-agent")
            assert w["fact"]["provenance"] == "claimed" and w["fact"]["actor"] == "py-agent" and w["fact"]["source"] == {"receiptId": None}
            assert await memory.read(subject="acct:42") == [], "quarantined until a gateway confirms it"
            seen = await memory.read(subject="acct:42", include_claimed=True)
            assert [f["value"] for f in seen] == ["pro"]
            w2 = await memory.write("acct:42", "plan", "enterprise", space="team:support", supersedes=w["fact"]["factId"])
            assert [f["value"] for f in await memory.read(subject="acct:42", include_claimed=True)] == ["enterprise"]
            await memory.retract(w2["fact"]["factId"], "wrong")
            assert [f["value"] for f in await memory.read(subject="acct:42", include_claimed=True)] == ["pro"]
            assert [e["kind"] for e in await memory.history(w2["fact"]["factId"])] == ["assert", "retract"]
    run(go())
    lines = [json.loads(l) for l in memory_server["ledger"].read_text().splitlines()]
    assert [e["kind"] for e in lines] == ["assert", "assert", "retract"]


def test_refusals_are_errors_and_write_nothing(memory_server):
    async def go():
        async with MemoryClient(memory_server["url"], token=memory_server["token"]) as memory:
            with pytest.raises(MemoryError, match="invalid arguments"):
                await memory.write("", "p", 1, space="org")
            with pytest.raises(MemoryError, match="unknown fact"):
                await memory.retract("nope", "x")
    ledger = memory_server["ledger"]
    before = ledger.read_text() if ledger.exists() else ""
    run(go())
    assert (ledger.read_text() if ledger.exists() else "") == before


def test_wrong_token_is_refused(memory_server):
    async def go():
        async with MemoryClient(memory_server["url"], token="nope") as memory:
            await memory.read()
    with pytest.raises(MemoryError, match="refused the connection: HTTP 401"):
        run(go())


def test_refusal_finds_the_http_status_inside_exception_groups():
    status = httpx.HTTPStatusError("bad", request=httpx.Request("POST", "http://127.0.0.1/mcp"), response=httpx.Response(503))
    assert _refusal(ExceptionGroup("outer", [ValueError("other"), ExceptionGroup("inner", [status])])) == "HTTP 503"
    assert _refusal(ExceptionGroup("outer", [ExceptionGroup("inner", [ValueError("socket closed")])])) == "socket closed"
    assert _refusal(ExceptionGroup("outer", [TimeoutError()])) == "TimeoutError"


def test_a_failed_handshake_is_a_memory_error(sidecar):
    async def go():
        async with MemoryClient(sidecar["url"] + "mcp") as memory:
            await memory.read()
    # the sidecar answers the probe with 404, not 401, so the MCP handshake runs and fails
    with pytest.raises(MemoryError, match="refused the connection") as e:
        run(go())
    assert e.value.__cause__ is None


@pytest.mark.xfail(strict=True, raises=httpx.ConnectError, reason="the probe runs outside the try, so a closed port raises httpx.ConnectError")
def test_a_closed_port_is_a_memory_error():
    async def go():
        async with MemoryClient(f"http://127.0.0.1:{closed_port()}/mcp") as memory:
            await memory.read()
    with pytest.raises(MemoryError, match="refused the connection"):
        run(go())
