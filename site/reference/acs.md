# The ACS Guardian

An [OWASP Agent Control Standard](https://github.com/GenAI-Security-Project/agent-control-standard) Guardian for `steps/toolCallRequest` and `steps/toolCallResult`. The Cedar policy decides each one, and each decision is a signed, logged receipt with `issuer.kind: "guardian"`, returned in the answer. The guide, including the ACS sections it relies on and what it does not implement, is [the ACS Guardian](/receipts/acs). This page is the exact contract.

The agent chooses to ask, and nothing makes it honor the answer. A guardian receipt proves the decision, not enforcement.

## Config

`acs.json`, paths relative to the file. `loadAcsGuardianConfig(path)`; schema `AcsGuardianConfigSchema`.

| key | type | default | meaning |
| --- | --- | --- | --- |
| `identity.keyFile` | path | required | the Guardian's signing key |
| `policyFile` | path | required | Cedar; re-read when it changes, and a changed file that does not parse is refused while the policy in force stays; a file that does not parse at start stops the start |
| `receiptsDir` | path | required | |
| `logFile` or `log` | | exactly one | as for the gateway |

## Running it

```bash
agent-custody acs --config acs.json < request.json > answer.json
```

`acs` reads one JSON document from stdin (one request, or a batch) and prints the answer. It exits 1 when any answer is an error, including a document that is not JSON (`-32700`), and 0 otherwise, deny included. Session state lives for the process.

In code:

```ts
import { createAcsGuardian, loadAcsGuardianConfig } from "@agent-custody/receipts";
const guardian = createAcsGuardian(loadAcsGuardianConfig("acs.json"));
const answer = await guardian.handle(request); // one JSON-RPC message or a batch; never throws
```

`createAcsGuardian(cfg, { log? })` returns `{ keyid, policyDigest, handle(message) }`; `policyDigest` is the digest of the policy in force now. Calls in one session are decided one at a time; a session belongs to the `agent_id` that opened it. Also exported: `acsEntryHash(entry, previousHash)` (ACS §8.2), `ACS_ERROR`, `ACS_METHODS`, `ACS_RECEIPT_KEY` (`"agent-custody"`), `ACS_STEP_FACT` (`"acsStep"`), `ACS_VERSION` (`"0.1.0"`), `ACS_GUARDIAN_VERSION`, and the types `AcsGuardian`, `AcsGuardianConfig`, `AcsMethod`, `AcsResponse`.

## The Cedar request

| part | value |
| --- | --- |
| principal | `Agent::"<params.metadata.agent_id>"`, a claim |
| action, resource | `Action::"<payload.tool.name>"`, `Tool::"<payload.tool.name>"` |
| `context.args` | toolCallRequest: each argument's `value`. toolCallResult: `{ exit_status, outputs: [value, …], duration_ms?, request_id_ref? }` |
| `context.acs` | `{ method, capability?, operation?, requestRef?: { resolved, decision?, tool?, agent?, consumed? } }`; `requestRef` is present on a result that names `request_id_ref`: the decision this Guardian gave that request in the session, its tool and agent, and `consumed`, true once a result for it was allowed |

## The answer

A decision is `{ jsonrpc: "2.0", id, result }` with:

| field | value |
| --- | --- |
| `type`, `acs_version`, `request_id` | `"final"`, `"0.1.0"`, the request's |
| `decision` | `"allow"` or `"deny"` |
| `reasoning` | the `@reason` of each rule that decided, the evaluation errors, or `no permit policy matched` |
| `reason_codes` | on a deny: `["policy_denied"]` or `["policy_error"]` |
| `policy_references` | `[{ policy_id: "cedar:<sha256>", policy_version: "<sha256>", rule_id: "policyN", policy_name? }]` |
| `chain_hash` | the session's ACS chain head after this step (§8.2) |
| `policy_data["agent-custody"]` | `{ receiptId, keyid, receipt }`, the receipt bundle |
| `metadata` | `{ evaluator: "deterministic", evaluator_version, evaluation_duration_ms }` |

Errors:

| code | when |
| --- | --- |
| `-32700` | stdin is not JSON (CLI only) |
| `-32600` | not JSON-RPC 2.0 with a method and an id, or an empty batch |
| `-32601` | a method other than the two hooks and `system/ping`, including `handshake/hello` |
| `-32602` | params or payload missing a required field |
| `-32000` | the `session_id` was opened by another `agent_id`; `data.reason: "agent_mismatch"` |
| `-32001` | `acs_version` of another major; `data.supported_versions` |
| `-32005` | a `request_id` already decided in the session; no receipt is written |
| `-32603` | the receipt could not be written; `data.reason: "receipt_not_written"`, and no decision is given |

`system/ping` is always answered `allow` with `payload: { status: "ok", echo?, server_timestamp }`, and writes no receipt. No error writes a receipt. The CLI exits 0 when every answer is a decision, and 1 when any is an error.

## The receipt

`issuer: { kind: "guardian", framework: "acs <method>" }`. `agent`, `session`, `tool`, and `request` are `claimed`. `policy` is `observed`. `execution` is `{ status: "withheld", reason }` for an allow, or `{ status: "denied", reason }` for a deny. `facts.acsStep` (`observed`) is `{ method, request_id, request_hash, entry_id, previous_hash, chain_hash, request_ref? }`, where `request_hash` is the sha256 of the canonical JSON of `params`. Verifiers check `guardian receipt carries a policy decision` and `guardian decided, executed nothing`.
