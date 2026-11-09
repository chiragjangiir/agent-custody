# The ACS Guardian

The [OWASP Agent Control Standard](https://github.com/GenAI-Security-Project/agent-control-standard) (ACS) is a wire contract between an agent and a separate policy point. Before the agent acts, its instrumentation sends a JSON-RPC 2.0 hook, such as `steps/toolCallRequest`, to a **Guardian**. The Guardian answers `allow`, `deny`, `modify`, `ask`, or `defer`, and the agent is expected to honor the answer. `agent-custody acs` is a Guardian for two of those hooks. It decides each one with a Cedar policy and returns the decision with a signed, logged receipt (`issuer.kind: "guardian"`). A third party can check that receipt with the Guardian's public key alone.

This is a spike: enough to show the two fit together. It is not an ACS-Core conformant Guardian. The list of what it leaves out is [below](#what-it-does-not-implement). It was written against the ACS repository at commit `db457a8` (`version.txt` 0.1.4, schemas under `specification/v0.1.0/`).

## Why a receipt and not just the ACS answer

ACS already asks the Guardian to keep an audit chain and publish its head. Two passages in the specification set the limits of that record. A receipt from this Guardian is meant to supply what they say is missing:

- **ACS §8.6, chain head publication.** The baseline signature is HMAC-SHA256, with a per-session key that both the Guardian and the agent derive (§10). The section says a valid HMAC shows that *a* holder of the session key produced a message, not *which* one. So under the baseline a Guardian decision is not attributable to the Guardian against the agent. The agent can produce a validly signed `allow` that the Guardian never sent, and the Guardian can re-sign a rewritten chain. ACS leaves non-repudiation to its optional asymmetric ACS-Crypto profile.
- **ACS Trace README, "Observability Goals".** Trace events are self-reported observations, produced inside the environment being observed. The README says they become evidence only when a party outside the emitting runtime attests to them.

A receipt from this Guardian is signed by a key that only the Guardian holds (Ed25519, DSSE). It goes into an append-only Merkle log, which a witness can countersign, and the same `agent-custody verify` checks it that checks every other receipt. Neither party can mint or edit one without the Guardian's key, and the Guardian cannot quietly drop one from a log that others have already seen.

## ACS issue #18: an audit chain that does not rest on one Guardian

[ACS issue #18](https://github.com/GenAI-Security-Project/agent-control-standard/issues/18) points out that the §8 chain is only as trustworthy as the one Guardian that keeps it. It notes there is no way for an auditor who trusts no Guardian to check or compare chains, and it proposes three directions for later versions. Here is each one against what this Guardian does:

1. **Sign `chain_hash` under a long-lived audit key, and export it as a signed checkpoint.** Done. Every decision's receipt carries the session's `chain_hash`, `previous_hash`, and `request_hash` in its `acsStep` fact. The receipt is signed with the Guardian's long-lived Ed25519 key, which is not an ACS session key. The bundle (receipt, signed tree head, and inclusion proof) is the exported checkpoint, and it verifies offline with the Guardian's public key. The receipt carries a head for every decision, not only a periodic one.
2. **Guardians exchange and commit to each other's chain heads when they mediate an A2A interaction.** Not done. Nothing here sends a chain head to another Guardian or records one received. Two Guardians that append to the same log, or to logs that one witness watches, can be compared by an auditor after the fact. That is not the exchange protocol #18 describes.
3. **Publish signed chain heads to an external append-only log, Sigstore/Rekor style.** Done, with agent-custody's own log rather than Rekor. Each receipt is a leaf in an RFC 6962 Merkle log. When the log is run by someone else (`log: { url, keys }`), the tree head is signed by that operator's key, and the verifier checks it with `--log-key`. So a verifier learns the decision was in a log the Guardian could not rewrite. `agent-custody audit` (or `auditExtends`) checks a consistency proof (RFC 9162) between two tree heads, which shows a later head extends an earlier one. The [witness](verification.md) countersigns the log's checkpoints, so the log operator cannot show different histories to different parties. The witness is not part of example 43.

[Example 43](../examples/43-acs-guardian.ts) shows directions 1 and 3 end to end. It starts a log under a separate key. It pipes the ACS README's sample `toolCallRequest` through `agent-custody acs`. It verifies the receipt with only the Guardian's and the log's public keys. Then it checks that the log after a later deny extends the log that held the first decision.

## What it does, and what it does not prove

The Guardian decides, signs, and logs. It carries out nothing. The agent chose to ask. It reports the call in its own words, and nothing makes it honor the answer or ask at all. So a guardian receipt proves **what the Guardian decided, on what request, under which policy, and when**. It does not prove that the call happened or did not happen. The [gateway](usage.md) is the enforcement point an agent cannot skip: it holds the tool credentials and forwards the call itself. ACS supplies the hooks. agent-custody supplies the proof, and the gateway where it matters.

| ACS | receipt |
| --- | --- |
| `params.metadata.agent_id` | `agent.id`, `claimed`: nothing on the wire binds it to the agent |
| `params.metadata.session_id`, `params.request_id` | `session.id`, `session.toolUseId`, `claimed` |
| `payload.tool.name` | `tool.name`, `claimed`; also the Cedar action and resource |
| toolCallRequest `payload.arguments` | `request.args`, `claimed`: each `{value, provenance}` unwrapped to its value |
| toolCallResult `exit_status`, `outputs`, `duration_ms`, `request_id_ref` | `request.args`, `claimed`: the result is what the agent submitted for a decision |
| the method | `issuer.framework`, e.g. `acs steps/toolCallRequest` |
| the decision | `policy`, `observed`; `execution.status` is `withheld` for an allow (the Guardian forwards nothing) and `denied` for a deny |
| `request_hash` and `chain_hash` (§8.1, §8.2) | the `acsStep` fact, `observed`: `{method, request_id, request_hash, entry_id, previous_hash, chain_hash, request_ref?}` |

The answer is an ordinary ACS result: `type: "final"`, `decision`, `reasoning`, `reason_codes` on a deny (`policy_denied` or `policy_error`), `policy_references` (the Cedar rule ids, each with its `@reason` and the policy's sha256), `chain_hash`, and `metadata.evaluator: "deterministic"`. The receipt rides in `policy_data["agent-custody"]` as `{receiptId, keyid, receipt}`. The README sample and the Guardian's answer to it both validate against the ACS `request-envelope.json`, `hooks/tool-call-request.json`, and `response-envelope.json`.

### The policy

Cedar, as everywhere else in agent-custody. The principal is `Agent::"<agent_id>"`, and the action and resource are the tool name. The context is:

```
context.args         the argument values (toolCallRequest), or {exit_status, outputs, duration_ms?, request_id_ref?} (toolCallResult)
context.acs.method   "steps/toolCallRequest" | "steps/toolCallResult"
context.acs.capability, context.acs.operation    when the payload carries them
context.acs.requestRef   on a result with request_id_ref: {resolved, decision?, tool?, agent?, consumed?}: the decision this
                         Guardian gave that request in this session, its tool and agent, and whether a result for it was already allowed
```

`examples/acs/policy.cedar` allows `file_read` under `/reports/`, and refuses any path containing `..`, because `like` matches characters, not paths: `/reports/../etc/passwd` matches `/reports/*`. The tool should resolve the path as well. The policy lets one result through, and only for a `file_read` request this Guardian allowed. A policy that permits results for several tools should compare `context.acs.requestRef.tool` with the action, or a result for one tool could ride on a request allowed for another. When a result names a `request_id_ref` the Guardian cannot resolve, the receipt records it as `resolved: false`, as ACS `hooks.md` (toolCallResult) requires, and the policy decides what that means. Everything else is denied: Cedar is default deny, and an evaluation error is a deny.

The policy file is re-read when it changes, and the next call is decided under the new one. A changed file that does not parse is refused with a message on stderr, and the policy in force stays. Each receipt names the digest of the policy it was decided under.

## Run it

```bash
agent-custody keygen --dir keys --name guardian
cp examples/acs/policy.cedar .
cat > acs.json <<'EOF'
{ "identity": { "keyFile": "keys/guardian.key" }, "policyFile": "policy.cedar", "receiptsDir": "receipts", "logFile": "log.jsonl" }
EOF
agent-custody acs --config acs.json < examples/acs/tool-call-request.json > answer.json
jq '.result.policy_data["agent-custody"].receipt' answer.json > receipt.json
agent-custody verify receipt.json --issuer-key keys/guardian.pub --log log.jsonl
```

`examples/acs/tool-call-request.json` is the sample from the ACS README ("A hook, on the wire"), byte for byte. The answer is `allow`. The verifier reports `issuer kind is known (guardian / acs steps/toolCallRequest)`, `guardian receipt carries a policy decision`, `guardian decided, executed nothing`, the signature, and the log inclusion, then `RESULT: VERIFIED`. With the Guardian's own local log, as here, the tree head is signed by the Guardian's key too. For a verifier who should not have to trust the Guardian, point `log` at a log someone else runs and verify with `--log-key` as well. [Example 43](../examples/43-acs-guardian.ts) does that, then runs a denied read, a result let through, a result for an unknown request, and a consistency check of the log.

`acs` reads one JSON document from stdin, either one request or a JSON-RPC batch evaluated in order, and prints the answer. It exits 0 when every answer is a decision, deny included, and 1 when any answer is an error, such as `-32603` for a receipt that could not be written. In code, `createAcsGuardian(cfg).handle(message)` does the same with no transport, so it can sit behind any HTTP or stdio server. Calls in one session are decided one at a time, in arrival order, so concurrent calls cannot both pass the replay check or fork the chain. Calls in different sessions do not wait for each other.

A session belongs to the agent that opened it. A call that names the same `session_id` with another `agent_id` is refused with `-32000` (`SESSION_REFUSED`, `data.reason: "agent_mismatch"`), so a second caller who knows a session id cannot extend its chain or ride on its allowed requests. That binds the claimed id, not the agent. Without ACS signatures, a caller who knows both ids can still speak for the agent.

Only a decision gets a receipt. An invalid request, an unknown method, a version mismatch, a replay, an agent mismatch, and a receipt that could not be written are answered with a JSON-RPC error and leave no receipt. A `system/ping` leaves none either.

## What a verifier checks

Besides the checks every receipt gets (signature, structure, argument digest, log inclusion):

- `guardian receipt carries a policy decision`: every step is decided by policy.
- `guardian decided, executed nothing`: an allow is `withheld` and a deny is `denied`. A guardian receipt that says `executed` is one someone re-signed.

The TypeScript, browser, and Python verifiers all run these. `vectors/receipts.json` carries `guardian-acs-allow`, `guardian-acs-deny`, and two re-signed cases that must fail.

The verifiers do not read the `acsStep` fact. They do not recompute `chain_hash` from `previous_hash` and `request_hash`, and they do not check that one receipt's `previous_hash` is the previous receipt's `chain_hash`. The fields are signed, so nobody but the key holder can change them. But a verifier that holds a session's receipts could recompute the links itself (`acsEntryHash` does it, and the tests do it with an independent implementation). That check is not built.

Trust is by key, not by kind. A verifier accepts a `guardian` receipt signed by any key it is given as an issuer key, so the holder of a gateway's or an SDK's trusted key could sign one. Give `--issuer-key` only the Guardian's key when checking Guardian decisions.

## What it does not implement

- **The handshake (§4).** There is no `handshake/hello` and no ServerHello. Nothing negotiates versions, methods, timeouts, `on_decision_failure`, or profiles. `handshake/hello` gets `-32601`. ACS-Core requires the handshake.
- **ACS signatures (§10).** A request's `signature` is not checked, with HMAC or anything else, and the answer carries none. The answer therefore does not meet ACS-Core's signature requirement, and its `chain_hash` is not covered by a response signature as §8.6 requires. The receipt's own signature covers it instead. Ed25519 is not in the ACS algorithm registry (§10.1), so the receipt sits beside an ACS-Crypto signature and does not replace one.
- **Most of the hooks.** Only `steps/toolCallRequest` and `steps/toolCallResult` are decided, and `system/ping` is answered. The other 17 `steps/*` hooks, `protocols/MCP/*`, and `agbom/*` get `-32601`.
- **Dispositions other than allow and deny.** There is no `modify`, `ask`, or `defer`, and so none of the substitution rules in §6.5 and §9.2.
- **Replay protection (§10.3), in part.** A repeated `request_id` in a session is refused with `REPLAY_DETECTED` (`-32005`), and no second receipt is written. The timestamp skew window is not enforced, so the README sample, stamped September 2026, is accepted. Nonces are not tracked.
- **Provenance (§7).** Argument and output `provenance` objects are dropped before the policy sees the values. There is no trust derivation from `origin`, and no `provenance_producer`. A policy cannot express FIDES or CaMeL-style rules here.
- **SessionContext and Intent (§8).** The chain is kept in memory, per process, with no bound or expiry. The CLI runs one process per document, so each run starts a new chain at `previous_hash: null`. Use `handle()` in one long-lived process, or a batch, to keep a session together. There is no `provenance_summary`, no Intent, and no `CHAIN_MISMATCH` check against the agent's `session_state.chain_hash`.
- **Canonical JSON.** `request_hash` and `entry_hash` use agent-custody's canonical JSON (sorted keys, no whitespace). That matches RFC 8785 for ordinary JSON, but it is not a full JCS implementation: edge cases in number formatting and lone surrogates may differ. ACS publishes no chain-hash vector to check against. The tests recompute the chain with an independent implementation.
- **Engines.** The Guardian uses Cedar only. ACS §12.1 names OPA/Rego as its v0.1 reference engine and Cedar as v0.2. The gateway already evaluates Rego, but it is not wired in here. There is no agent (LLM) layer, which §12.2 makes optional.
- **Transports.** There is no HTTP server and no stdio `Content-Length` framing. The CLI reads one document from stdin.
- **Decision failure (§6.4).** When the receipt cannot be written, the Guardian gives no decision: it answers `-32603` with `data.reason: "receipt_not_written"`. ACS's default failure posture is `proceed`, so an agent left at that default carries on unguarded. A deployment that wants every decision on record sets `on_decision_failure: deny`.
- **Trace and Inspect.** No OTel or OCSF events, and no AgBOM.
- **Identity.** `agent_id` is whatever the wire says. ACS leaves authentication to the deployment (§11), and nothing here binds the id to the agent. For agent identity, the gateway's signed grant is the mechanism.
