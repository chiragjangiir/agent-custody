# Every test runs against a real sidecar: `node ../receipts/src/cli.ts serve`, started here on a free port with an
# application key and a policy generated for the session. No mocks of the sidecar; it is the thing being integrated.
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
from pathlib import Path

import pytest

from agent_custody import Client, receipt_id_of

RECEIPTS = Path(__file__).resolve().parents[2] / "receipts"
POLICY = 'permit(principal, action == Action::"customer.lookup", resource);\npermit(principal, action == Action::"stripe.refund", resource) when { context.args.amount <= 100000 };\n'


@pytest.fixture(scope="session")
def sidecar():
    node = shutil.which("node")
    assert node, "node is required: the sidecar is the agent-custody CLI"
    d = Path(tempfile.mkdtemp(prefix="agent-custody-py-"))
    subprocess.run([node, str(RECEIPTS / "src/cli.ts"), "keygen", "--dir", str(d / "keys"), "--name", "app"], check=True, capture_output=True)
    (d / "policy.cedar").write_text(POLICY)
    (d / "sdk.json").write_text(json.dumps({"agentId": "py-bot", "principalId": "user_456", "identity": {"keyFile": "keys/app.key"}, "policyFile": "policy.cedar", "receiptsDir": "receipts", "logFile": "log.jsonl", "framework": "python"}))
    p = subprocess.Popen([node, str(RECEIPTS / "src/cli.ts"), "serve", "--config", str(d / "sdk.json"), "--port", "0"], stderr=subprocess.PIPE, text=True)
    line = p.stderr.readline()
    m = re.search(r"(http://[^ ]+)", line)
    assert m, f"sidecar did not start: {line}"
    yield {"url": m.group(1), "dir": d, "receipts": d / "receipts", "app_pub": d / "keys" / "app.pub", "log": d / "log.jsonl", "node": node}
    p.terminate()
    p.wait(timeout=10)


@pytest.fixture
def client(sidecar):
    return Client(sidecar["url"])


@pytest.fixture
def recorded(client, sidecar, monkeypatch):
    """The verified predicate of each receipt that `client.record` issues during the test, in order."""
    out = []
    real = client.record

    def record(*a, **k):
        bundle = real(*a, **k)
        report = verify(sidecar, receipt_id_of(bundle))
        assert report["ok"], report
        out.append(report["statement"]["predicate"])
        return bundle

    monkeypatch.setattr(client, "record", record)
    return out


def closed_port() -> int:
    """A port on 127.0.0.1 that nothing listens on."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def receipt_count(sidecar) -> int:
    return len(list(sidecar["receipts"].glob("*.json"))) if sidecar["receipts"].exists() else 0


def verify(sidecar, receipt_id: str) -> dict:
    """The TypeScript verifier is the reference; a receipt from Python must pass it."""
    out = subprocess.run([sidecar["node"], str(RECEIPTS / "src/cli.ts"), "verify", str(sidecar["receipts"] / f"{receipt_id}.json"), "--issuer-key", str(sidecar["app_pub"]), "--log", str(sidecar["log"]), "--json"], capture_output=True, text=True)
    return json.loads(out.stdout)


STATE = Path(__file__).resolve().parents[2] / "state"


@pytest.fixture(scope="session")
def memory_server():
    """The shared memory server over HTTP, accepting direct writers under their own token, as an SDK-only Python agent would reach it."""
    node = shutil.which("node")
    d = Path(tempfile.mkdtemp(prefix="agent-custody-memory-"))
    env = dict(os.environ, MEMORY_TOKEN="gateway-secret", MEMORY_DIRECT_TOKEN="py-secret")
    p = subprocess.Popen([node, str(STATE / "src/cli.ts"), "serve", "--ledger", str(d / "ledger.jsonl"), "--http", "--port", "0", "--token-env", "MEMORY_TOKEN", "--allow-direct", "--direct-token-env", "MEMORY_DIRECT_TOKEN"], stderr=subprocess.PIPE, text=True, env=env)
    # the address is on the startup line; warnings may precede or follow it, so read until it appears
    lines = []
    m = None
    for _ in range(10):
        line = p.stderr.readline()
        if not line:
            break
        lines.append(line)
        m = re.search(r"(http://[^ ]+)", line)
        if m:
            break
    assert m, f"memory server did not start: {''.join(lines)}"
    yield {"url": m.group(1), "token": "py-secret", "ledger": d / "ledger.jsonl"}
    p.terminate()
    p.wait(timeout=10)
