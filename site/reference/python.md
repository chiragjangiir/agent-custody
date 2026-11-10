# Python

```bash
pip install agent-custody            # the sidecar client and the memory client
pip install "agent-custody[langchain]"  # plus one adapter: langchain, openai-agents, crewai, claude-agent-sdk, adk
```

Python 3.10 or later. The package talks to the [sidecar](./sidecar) for receipts and to the memory server over MCP for beliefs; it holds no key and signs nothing itself.

## `Client`

```python
from agent_custody import Client, PolicyDeniedError, SidecarError, receipt_id_of
client = Client("http://127.0.0.1:8788/", timeout=10.0)
```

| method | request | response |
| --- | --- | --- |
| `client.health()` | `GET /health` | `{"agentId": "…", "keyid": "…", "log": {"kind": "http", "where": "…"}}` |
| `client.decide(tool, args=None, *, model=None, session=None)` | `POST /decide` with `{"tool", "args", "model"?, "session"?}` | the policy decision `{"decision": "allow"\|"deny", "reasons": [...], "errors": [...], "policyDigest": "…"}`, or `None` when the sidecar has no policy |
| `client.record(tool, args, outcome, policy=None, *, model=None, session=None)` | `POST /record` with `{"event", "outcome", "policy"}` | the receipt bundle `{"envelope", "treeHead", "inclusion"}` |
| `client.wrap(tool, fn, *, model=None)` | decide, run `fn(args)`, record | a callable that returns `fn`'s result; raises `PolicyDeniedError(tool, reason, receipt_id)` after recording the denial; records `{"status": "error"}` and re-raises when `fn` raises |

`outcome` is `{"status": "executed"|"failed", "result": …}`, `{"status": "denied", "reason": "…"}`, or `{"status": "error", "error": "…"}`. `session` is `{"id": …, "toolUseId": …}`. `receipt_id_of(bundle)` decodes the statement and returns the receipt id. `SidecarError` is raised for any HTTP failure, with the sidecar's `error` text. Its `kind` is `"unreachable"`, `"status"` (with the HTTP code in `status`), or `"malformed"` (the answer is not JSON).

```python
refund = client.wrap("stripe.refund", lambda args: stripe.Refund.create(**args))
try:
    refund({"customer_id": "cust_123", "amount": 2500})
except PolicyDeniedError as e:
    print(e.reason, e.receipt_id)
```

## Adapters

| import | entry point | behaviour |
| --- | --- | --- |
| `agent_custody.langchain` | `ReceiptCallbackHandler(client)` | record-only: `on_tool_start` / `on_tool_end` issue an executed receipt per tool run with the LangChain `tool_call_id` as the session's tool-use id; pass it in `callbacks=[...]` |
| `agent_custody.openai_agents` | `wrap_tools(client, tools)` | enforce: each `FunctionTool`'s `on_invoke_tool` decides, runs, records; a denial is returned as the tool's result text |
| `agent_custody.crewai` | `wrap_tools(client, tools)` | enforce: one `CustodyTool` per tool, same name, description, and schema; `_run` decides, runs, records; a denial is returned as `Denied by policy: … (receipt …)` |
| `agent_custody.claude_agent_sdk` | `claude_hook(client)` | the async hook callable `(input_data, tool_use_id, context) -> dict` for the Claude Agent SDK; `handle_hook_event(client, input_data)` is the same for any host that passes the hook JSON. Same semantics as [Claude Code](./claude-code) |
| `agent_custody.hermes` | `hermes_hooks(client)` → `{"pre_tool_call", "post_tool_call"}` | Hermes Agent plugin hooks: `pre_tool_call(tool_name, args, task_id, **kwargs)` returns `{"action": "block", "message": "agent-custody: … (receipt …)"}` on a policy deny after recording the denial, `None` otherwise; `post_tool_call(tool_name, args, result, task_id, duration_ms, **kwargs)` records the call. `register_hermes(ctx, client)` registers both with `ctx.register_hook`; `register(ctx)` is the plugin entry, reading `sidecar_url` from the plugin's settings |
| `agent_custody.adk` | `adk_callbacks(client)` → `{"before_tool_callback", "after_tool_callback"}` | Google ADK callbacks, for `LlmAgent(..., **adk_callbacks(client))`: `before_tool_callback(tool, args, tool_context)` returns `{"error": "agent-custody: … (receipt …)", "agent-custody/receipt": "…"}` on an enforced policy deny after recording the denial, which skips the tool and shows the model the receipt, `None` otherwise; `after_tool_callback(tool, args, tool_context, tool_response)` records the executed call (the response as JSON when it is JSON, else as text) and returns `None`, skipping the denial dict it recognises. The session is ADK's `invocation_id` and `function_call_id`. Extra `adk` (`google-adk[a2a]`). Delegations over A2A are not tool calls; the gateway's `--a2a` front covers them |

When an enforcing adapter (OpenAI Agents, CrewAI, Hermes, ADK, the Claude Agent SDK hook) cannot record the denial receipt, the call stays denied and the reason ends with `(no receipt: <why>)` in place of `(receipt <id>)`. `<why>` is one of `the sidecar could not be reached`, `the sidecar answered HTTP <status>`, `the sidecar refused the request`, `the sidecar's answer was malformed`, or `an unexpected <exception type>`. The reason reaches the model, and the exception text can carry the sidecar URL with its credentials or the text of an upstream answer, so the exception goes to the `agent_custody` logger at `WARNING`, which prints to stderr when no handler is configured, and never into the reason; a `SidecarError` names the sidecar URL without its user, password, or query string. `agent_custody.no_receipt(e)` builds the text. CrewAI also answers `Denied by policy: the policy could not be evaluated; no receipt: <why>` when the sidecar cannot decide or answers without an allow or deny decision, because CrewAI hands a tool's exception text to the model.

## `agent_custody.verify`

An independent verifier, written from the [receipt specification](/receipt/v0.2) and checked against every [conformance vector](/receipt/vectors). Its canonical JSON matches the producer's: array-index keys first in numeric order, then the other keys by UTF-16 code unit. It needs the extra `verify` (`cryptography`, for Ed25519) and no sidecar.

```bash
agent-custody-verify receipts/<id>.json --issuer-key gateway.pub --principal-key principal.pub --log log.jsonl
```

| flag | meaning |
| --- | --- |
| `--issuer-key`, `--principal-key`, `--approval-key`, `--upstream-key`, `--log-key` | PEM public keys, each repeatable; signatures are matched by keyid |
| `--provider-secret-env PROVIDER=VAR` | the environment variable holding a provider's shared secret (`stripe`, `github`); never the secret itself |
| `--log` | a copy of the log, one JSON value per line |
| `--log-id` | the log id the tree head must name |
| `--require-strict` | adds `strict mode in force` and `strict: call precommitted before forwarding` |
| `--json` | the report as JSON |

Exit code 0 when every check passes, 1 otherwise.

| function | returns |
| --- | --- |
| `verify_bundle(bundle, trust, *, log=None, log_id=None, require_strict=False)` | a `Report`: `ok`, `failing`, and `checks`, each a `Check(name, ok, detail)` named as the specification names it |
| `audit_extends(older, newer, proof, keys)` | a `Report` with `older tree head signature`, `newer tree head signature`, `older is not larger than newer`, `newer log extends older log` |
| `Trust(issuer, principal=[], approval=[], upstream=[], log=[], provider_secrets={})` | the keys and secrets a verifier holds |
| `load_public_key(pem)` | a `PublicKey` with its `keyid` |
| `read_log(path)` | the leaves of a log file, for `log=` |
| `canonical_json(value)`, `digest(value)`, `pae(payload_type, payload)` | the building blocks of the specification |

It does not decrypt or restore withheld fields; a receipt under a capture rule verifies as committed.

## `MemoryClient`

The memory tools over MCP, against a memory server started with `agent-custody-memory serve --http --allow-direct`. Pass the direct writers' token (`--direct-token-env`), never the gateways' token. Writes made this way are `claimed` and quarantined until a gateway confirms them; that is the honest position of an SDK-only agent.

```python
from agent_custody.memory import MemoryClient, MemoryError
async with MemoryClient("http://127.0.0.1:8790/mcp", token="…") as memory:
    fact = await memory.write("acct:42", "plan", "pro", space="team:support", actor="py-agent")
    facts = await memory.read(subject="acct:42", include_claimed=True)
```

| method | tool called | response |
| --- | --- | --- |
| `write(subject, predicate, value, *, space, actor=None, supersedes=None, valid_from=None)` | `memory.write` | `{"fact": {...}, "eventId", "txTime", "supersedes"}`; the fact's `provenance` is `claimed` |
| `read(*, subject=None, predicate=None, space=None, valid_at=None, tx_at=None, include_claimed=False, require_verified=False)` | `memory.read` | the list of facts believed at that moment |
| `retract(fact_id, reason, *, actor=None)` | `memory.retract` | `{"eventId", "factId", "txTime", "actor", "reason", "source", "removedFrom", "verification"}` |
| `history(fact_id)` | `memory.history` | the list of events, oldest first |

A refused connection (wrong token) raises `MemoryError("memory server at … refused the connection: HTTP 401")`; a tool error raises `MemoryError` with the server's text. The tool contracts are on the [memory](./memory) page.
