# The gateway

A separate process between the agent and its tools. The agent connects to it as an MCP server and sees only the tools its grant names; the gateway checks the grant, fetches the facts the policy needs, evaluates the policy, forwards or refuses the call, and issues a signed receipt whose hash goes to the log. For tools named in `precommit`, the authorization is logged before the call is forwarded. Tools named in `approvals` also require short-lived human signatures over the exact action.

## The config file

`gateway.json`, paths relative to the file. Loaded with `loadConfig(path)`.

```json
{
  "identity": { "keyFile": "keys/gateway.key" },
  "upstream": { "command": "node", "args": ["memory-server.js"], "env": { "TOKEN": "..." } },
  "grantFile": "grant.json",
  "trustedPrincipalKeys": ["keys/principal.pub"],
  "policyFile": "policy.cedar",
  "facts": [
    { "name": "customer", "tool": "customer.lookup", "args": { "customer_id": "$args.customer_id" }, "forTools": ["stripe.refund"], "optional": false }
  ],
  "precommit": ["stripe.refund"],
  "receiptsDir": "receipts",
  "logFile": "log.jsonl",
  "otel": { "url": "http://localhost:4318", "headersEnv": { "x-api-key": "OTEL_KEY" }, "serviceName": "support-agents" },
  "splunk": { "url": "https://splunk.example.com:8088", "tokenEnv": "HEC_TOKEN", "index": "agents" }
}
```

| field | type | meaning |
| --- | --- | --- |
| `identity.keyFile` | path | the gateway's Ed25519 private key; signs every receipt. From `agent-custody keygen` |
| `upstream` | one of four shapes | `{ command, args?, env? }` spawns an MCP server over stdio; `{ url, tokenEnv? }` connects to an MCP server over Streamable HTTP with a bearer token from the environment; `{ rest: {...} }` describes a plain HTTP API as tools; `{ a2a: {...} }` is another agent reached over the A2A protocol, both below |
| `upstreams` | array of the above, each with `name` | several upstreams behind one gateway; each tool name must belong to exactly one, checked at startup. Exactly one of `upstream` or `upstreams` |
| `grantFile` | path, *optional* | the signed delegation the stdio gateway serves. Not needed over HTTP, where each connection presents its own |
| `trustedPrincipalKeys` | paths | public keys of principals whose grants are accepted; matched by keyid |
| `policyFile` | path | the policy: Cedar, or Rego when the path ends in `.rego` ([Rego](/receipts/policies#rego)); its SHA-256 is in every receipt. A Rego file is compiled with the `opa` binary on `PATH` when it loads, and a gateway whose Rego file does not compile does not start. Re-read whenever the file changes (and on each call while it is under two seconds old) and applied from the next call, with no restart; a changed file that does not parse or cannot be read is refused and the policy in force stays. Each change and refusal is appended to `<receiptsDir>/policy-reloads.jsonl` with both digests |
| `opa` | object | instead of `policyFile`: an OPA server that decides each call. `url`; `decision`, the package path under `/v1/data` (default `agentcustody`); `tokenEnv`, a variable holding a bearer token; `timeoutMs` (default 2000), after which the call is denied. The URL must be `https`, or `http` on a loopback address, and a redirect is refused. The receipt's `policyDigest` is the sha256 of the decision URL and the bundle revisions the server reports, each new one recorded in `<receiptsDir>/policy-reloads.jsonl` as `opa-provenance`; a call the server did not answer carries the URL's unanswered digest, recorded with `bundles: null`. The gateway does not start when the server cannot be reached or does not define the package. Exactly one of `policyFile` and `opa` |
| `facts` | array | lookups the gateway makes itself before deciding: `name` under `context.facts`, the upstream `tool` to call, `args` templates where `"$args.<key>"` copies the agent's argument, `forTools` the intercepted tools that trigger it, `optional` skips the lookup when the template's argument is absent |
| `precommit` | array of tool names or `["*"]` | consequential tools: the authorization is logged before the call is forwarded, and the call is withheld if the log will not take it or answers with a head or proof that does not verify |
| `requirePrecommit` | boolean, *optional* | with a remote `log`, refuse to start when `precommit` is empty; without it the gateway prints a warning |
| `strict` | boolean, *optional* | strict mode: every tool is precommitted, as with `precommit: ["*"]`, so no call is forwarded before its authorization is in the log, in observe mode too; the log must be remote, `hashOnly`, and pinned with `keys`, or the gateway does not start; no receipt goes to the outbox, so a receipt the log refuses after the forward is not kept, the call returns an error, and the authorization in the log stands; receipts left in the outbox from before are appended once at start, with no 30-second retry. Every receipt and authorization carries `issuer.strict: true`, which `verify --require-strict` requires. A fact lookup and a `reconcile` read are the gateway's own reads and still go out before any log entry |
| `approvals` | `{ trustedKeys: path[], usedDir: path, maxLifetimeSeconds?: number, tools: [{ tool, minApprovers?: 1 \| 2, fields?: { amount?, currency?, beneficiary? } }] }`, *optional* | exact-action human approval rules; nonempty trust list and tools, unique tool names; paths resolve relative to this file. Defaults to one trusted signer and a lifetime cap of 3600 seconds (`maxLifetimeSeconds`, a positive integer: the gateway refuses an approval whose `expiresAt` minus `issuedAt` is longer). `"*"` covers all agent calls, an exact rule takes precedence. [Below](#human-approvals) |
| `operations` | `{ database, budgets, tools }`, *optional* | durable financial operations: stable ids, provider keys, atomic daily reservations and reconciliation; configured tools always precommit, including observe mode. [Below](#financial-operations) |
| `revokedGrants` | path, *optional* | a JSON array of grant digests (sha256 over the grant's signed payload), re-read whenever the file changes and checked on every call against every link of the grant's chain; `agent-custody revoke` appends to it. A file that cannot be read denies every call |
| `capture` | map of tool name or `"*"` to `{ args?, result?, facts? }`, *optional* | private evidence: what the receipt file carries of each tool's arguments, result, and facts. Each side is `{ "mode": "clear" \| "digest" \| "encrypted", "clear"?: [fields] }`: `clear` records the value (the default); `digest` withholds every top-level field not listed in `clear` and leaves a salted sha256 commitment in its place; `encrypted` does the same and carries the value encrypted under the capture key. Digests and signatures are always over the whole call, and the policy decides on the real values. [Below](#private-evidence) |
| `captureKeyEnv` | environment variable name, *optional* | the 32-byte key (64 hex characters or base64) that encrypts withheld fields in mode `encrypted`, read at startup and never from the file; a rule in mode `encrypted` without it fails at startup |
| `mode` | `"enforce"` (default) or `"observe"` | observe records Cedar decisions with `enforced: false` and forwards calls despite Cedar denial; authorization log failure is printed instead of withholding. Grants and configured human approvals remain enforced, including fresh checks before forwarding. The way to run a new policy against real traffic before turning it on |
| `receiptsDir` | path | one `<receiptId>.json` per receipt, and `<receiptId>.authorization.json` for pre-committed calls |
| `logFile` | path | a local Merkle log, one leaf per line. Exactly one of `logFile` or `log` |
| `log` | `{ url, tokenEnv?, hashOnly?, timeoutMs?, keys?, logId? }` | a remote log: the tenant's append URL, the bearer token's environment variable, `hashOnly: true` to send only the leaf hash (use it for any log run by someone else), how long one append may take (default 10000 ms), the log's public key files to pin (without them its key document is fetched from the log once and pinned; required when `precommit` is not empty), and the id its tree heads must carry. Every append's answer is verified against them before a pre-committed call is forwarded |
| `otel` | *optional* | OpenTelemetry export, one span per receipt, after the receipt, never on its path |
| `splunk` | *optional* | Splunk HTTP Event Collector export, one event per receipt, the token from the environment |

### Human approvals

```json
{ "approvals": {
  "trustedKeys": ["keys/approver.pub", "keys/second-approver.pub"],
  "usedDir": "approvals-used",
  "maxLifetimeSeconds": 900,
  "tools": [{ "tool": "stripe.refund", "minApprovers": 2, "fields": { "beneficiary": "customer_id" } }]
} }
```

`Gateway.handleCall` and MCP `tools/call` take a DSSE envelope in `_meta["agent-custody/approval"]`, made with [`createApproval`](./sdk-typescript#human-approvals). This key is removed before forwarding. The signed payload binds the grant's principal and agent, tool name, full argument digest, optional amount/currency/beneficiary, and validity window. Action field names default to `amount`, `currency`, and `beneficiary`; `fields` maps each to a top-level argument name. Amounts must be safe integers in minor units. Extra arguments also affect the digest.

`minApprovers: 2` counts two distinct trusted keys. The operator assigns keys to distinct people; the signatures do not prove that two keys belong to different humans. An exact rule for a configured fact-lookup tool is rejected at startup. The wildcard protects agent calls and leaves internal fact lookups unchanged.

The first check runs before facts and Cedar; failures issue denial receipts even in observe mode. A valid approval does not override grants or Cedar. After awaited facts and any pre-commit append, a fresh check and exclusive consumption happen immediately before forwarding; expiry or a concurrent use then withholds the call. The receipt records `approval: { envelope?, requiredApprovers, fields?, checkedAt, status, reason?, approverKeyids, consumedAt?, provenance: "observed" }`. `status` is `"approved"` or `"denied"`; a malformed or untrusted approval statement is not embedded, and only individually verified trusted signatures are retained. Pre-commit authorizations include the initial approval record; the final receipt adds the consumption result.

`usedDir` must persist across restarts and be shared by every gateway accepting these approvals, on a filesystem with consistent exclusive creation. A consumed id stays burned after crashes, log failures, or unknown upstream outcomes. Do not remove records while the approvals can remain valid. No automatic pruning or outcome reconciliation is supplied. An offline verifier checks approval signatures and action binding with separately trusted [`approvalKeys`](./verify#verify); it cannot establish global single use.

Under a private capture rule the receipt withholds `approval.envelope` and `approval.reason` as commitments, because the envelope carries the action fields and an unsalted full-argument digest that would disclose private values or confirm guesses. The status, times, and signer key ids stay in clear. Verifying the signatures and the full binding needs the capture key or a disclosure. When nothing under `request.args` is withheld for the call, an approved envelope stays in clear. The [approval guide](/receipts/approvals) covers the complete workflow and privacy boundary.

### A REST API as an upstream

```json
{ "rest": {
  "baseUrl": "https://api.example.com",
  "headerEnv": { "authorization": "PAYMENTS_BEARER" },
  "headers": { "accept": "application/json" },
  "timeoutMs": 30000,
  "tools": [
    { "name": "customer.lookup", "method": "GET", "path": "/customers/{customer_id}", "inputSchema": { "type": "object", "properties": { "customer_id": { "type": "string" } }, "required": ["customer_id"] } },
    { "name": "stripe.refund", "method": "POST", "path": "/refunds", "body": "json", "description": "Refund a customer" }
  ]
} }
```

`{name}` segments in `path` are filled from the call's arguments; the remaining arguments go to the query string on GET and DELETE and to a JSON body otherwise, or `query` names the ones for the query and `body: "none"` sends no body. The response body is the tool result, JSON kept as JSON; a non-2xx status is a failed execution with the API's answer in the receipt.

### Financial operations

`operations.database` is a SQLite path relative to the config, in an owner-only directory. `budgets` contains `{ id, currency, limit }`, with limits in integer minor units and UTC daily periods. Each entry of `tools` contains `{ tool, budget, amountField?, currencyField?, idempotencyHeader?, reconcile }`. Defaults: `amount`, `currency`, and `Idempotency-Key`.

`reconcile` is `{ tool, args, statusPath, identityPath?, confirmed, failed, pending? }`. Argument templates substitute `$operation.idempotencyKey` only. `identityPath` defaults to `idempotencyKey`; it and `statusPath` read own properties of the JSON provider record in its first text result. Terminal status mappings must be disjoint, the record must echo the exact idempotency key, and failed states must be final provider failures. A REST reconciliation tool must be a GET. Financial MCP upstreams must honor operation metadata; A2A financial tools are refused.

Financial calls require a retained lowercase UUID at `_meta[OPERATION_META_KEY]`, where the exported constant is `"agent-custody/operation"`. The gateway atomically binds it to identity, tool, full arguments, provider and budget before forwarding. REST receives the derived key in the configured header; MCP receives `{ id, idempotencyKey }` at that metadata key. Results expose `OperationEvidence` there: `{ id, idempotencyKey, lookupDigest, status, budget: { id, currency, period }, originalReceiptId, provenance: "observed" }`. `status` is `submitted`, `pending`, `unknown`, `confirmed`, or `failed`; `execution.status` continues to describe the API response. A retry returns the recorded logical call without another forward or reservation, and gets a `withheld` receipt of its own: its id is at `_meta["agent-custody/retry-receipt"]` (the exported constant `RETRY_RECEIPT_META_KEY`), and `operation.originalReceiptId` names the first receipt. Under a private capture rule `operation.id` is withheld; receipts link by `idempotencyKey`.

`serveConsole({ configFile, token, port?, host?, gatewayUrl?, stateDir? }): Promise<{ url, close() }>` is the admin console ([console](/receipts/console)).

`GatewayHost.flushOutbox(): Promise<{ sent, pending, setAside, foreign, error? }>` appends the receipts in `receipts/outbox/`, oldest signed statement first, and stops at a log refusal (`error`). `setAside` counts the entries renamed to `<name>.bad` (a damaged file, a bad signature under this gateway's key id, or a receipt id that is not the file name). `foreign` counts the entries that another key signed; they stay in the outbox and are not appended. A lock file in the outbox keeps two flushers apart; when another process holds it, the call does nothing. The host runs the flush at start and every 30 seconds only when it opens with `createGatewayHost(cfg, { autoFlush: true })`, which `agent-custody gateway` sets in all three modes; `check` and `reconcile` do not. `close()` waits for a flush that runs. `GatewayHost.pendingReceipts()` counts them. `createIssuer(...).issue(predicate, ctx, retain, { deferLog: true })` keeps the receipt in the outbox and throws `ReceiptPending` when the log does not take it; without `deferLog` it throws the log's error as before.

`GatewayHost.policyDigest(): string` is the sha256 of the policy in force, the one the next call is evaluated under; reading it picks up a changed `policyFile` as a call would. `GatewayHost.tools(): string[]` lists every tool the upstreams offer, before a grant narrows them; `checkConfig(path, { connect? })` and `formatFindings(findings)` are what `agent-custody check` runs, returning findings `{ level: "ok" | "warn" | "error", check, message }` ([configuration](/receipts/configuration#check-it-before-you-start-it)).

`GatewayHost.reconcile(id): Promise<ReceiptBundle>` is an operator method, never an agent tool. It fetches the configured provider record and commits a terminal receipt linked to the original receipt or authorization before releasing failed budget. Pending/unknown provider responses reject and keep the amount reserved. A submitted call owned by a live process cannot be reconciled underneath its forward; the owner is the PID and its kernel start time, so a later process with the same PID is not the owner. A submitted call with a dead owner and no saved authorization was never forwarded: `reconcile` commits a `withheld` receipt with `operation.status: "failed"` and releases the amount. Completed calls return their cached reconciliation bundle. CLI: `agent-custody reconcile --config gateway.json --operation <uuid>`, returning `{ operation, status, receipt }` on stdout. It works after the original grant expires or is revoked.

`new OperationStore(path)` exposes `reserve(OperationReservation) -> { created, operation }`, `get(id) -> OperationRecord | undefined`, `list() -> OperationRecord[]`, `update(id, OperationUpdate) -> OperationRecord`, `claimReconciliation(id, candidate) -> unknown`, `prepareReconciliation(id, prepared) -> unknown`, and `close()`. It is a local operator API: `reserve` uses `BEGIN IMMEDIATE` to claim the binding and budget together; `update` is trusted and must only release failure after evidence commits. Terminal outcomes cannot change. `ownerAlive(record)` says whether the creator may still run, and `processStamp(pid)` returns the kernel start time that it compares (`undefined` when unreadable, which counts as alive). `saveAuthorization(id, original)` is a compare-and-set that the gateway calls before it forwards: it throws once the operation is closed or a reconciliation is claimed. `claimReconciliation(id, candidate, unsent?)` with `unsent` set throws when an authorization was saved. A record keeps `unsent`, the call as the gateway decided it, until its authorization is saved. Recovery data includes raw requests, responses, and private salts; keep the database private and retain its operation ids. Several gateway processes must share this database and use a remote receipt log.

For the complete config, outcome table, durable recovery behavior, and provider requirements, see [financial operations](../../packages/receipts/docs/financial-operations.md).

### An A2A agent as an upstream

```json
{ "a2a": {
  "url": "https://docs-agent.internal",
  "headerEnv": { "authorization": "DOCS_AGENT_BEARER" },
  "headers": { "accept": "application/json" },
  "timeoutMs": 120000,
  "prefix": "docs"
} }
```

`url` is the agent's base URL, whose card the gateway fetches at startup from `/.well-known/agent-card.json` or `/.well-known/agent.json`, or the card's own URL when it ends in `.json`. `headers` and `headerEnv` are as for a REST upstream; `timeoutMs` is how long one delegated task may take, streamed or not, default 120000; `prefix` names the tools, default `a2a`, one per A2A upstream. The card decides the wire format: A2A 1.0 (`supportedInterfaces`, `SendMessage`, `ROLE_USER`) or 0.3 (`url`, `message/send`, `kind`). The upstream offers two tools:

| tool | arguments | result |
| --- | --- | --- |
| `<prefix>.send` | `text` (the task; the gateway builds the message) or `message` (a full A2A message, forwarded as is); optional `taskId`, `contextId`, `configuration`, `metadata` | the agent's task or message, as JSON text. A streamed delegation is relayed after the agent finishes, the events in `_meta["agent-custody/a2a-stream"]` and the final task as the result; a JSON-RPC error from the agent is `isError: true` with the error, recorded as `failed` |
| `<prefix>.card` | none | the agent card, fetched afresh; name it in `facts` (`{ "name": "card", "tool": "docs.card", "args": {}, "forTools": ["docs.send"] }`) so a policy reads `context.facts.card.name` |

Programmatically: `a2aUpstream(name, cfg, { fetch?, env? })` returns the upstream client with `resolved(): Promise<ResolvedCard>`; `fetchAgentCard(url, headers, fetch, timeoutMs): Promise<{ card, cardUrl, endpoint, legacy }>` is the lookup it uses; `textOf(message)` joins a message's text parts, which is what a policy reads as `context.args.text`.

### Private evidence

```json
"capture": {
  "stripe.refund": {
    "args": { "mode": "encrypted", "clear": ["customer_id", "amount"] },
    "result": { "mode": "digest" },
    "facts": { "mode": "encrypted" }
  },
  "*": { "facts": { "mode": "digest" } }
},
"captureKeyEnv": "AGENT_CUSTODY_CAPTURE_KEY"
```

A rule names a tool, or `"*"` for every tool without a rule of its own. Each side (`args`, `result`, `facts`) has a `mode` and, in `digest` or `encrypted` mode, the top-level fields to keep in `clear`; every other field goes into one commitment at `$rest`, so that neither values nor field names appear; a value that is not a plain object is withheld whole. The rule is applied by the issuer to the whole statement before it is signed: once any side is private, a side the rule does not set is withheld whole, field by field, and so is every value that is not structural (policy error messages, a denial reason, a thrown message, the result's `_meta` even beside a result left in clear, a provider delivery's body, signature, and bind, an upstream's signed envelope, the consumed fact ids, the session and model ids the agent supplied, a tool name no upstream offers), in the rule's mode (`encrypted` as soon as any side is). What stays in clear is a fixed list: ids, key ids, timestamps, the tool name, the grant, the digests, the decision and policy ids, the status, the provenance fields, and the note. On a result, `isError` stays in clear and `_meta` never does. A fact lookup's arguments follow the `args` side, by the call argument they copy. The policy decides on the real values and the agent gets the real result, error, and reason; only the receipt file, the log, and the exporters carry the view.

A withheld value holds a commitment, `{ "$custody": "withheld", "sha256": "<sha256 over a random 16-byte salt and the canonical value>" }`, or in mode `encrypted` `{ "$custody": "encrypted", "alg": "A256GCM", "keyid": "<sha256 of the key>", "iv", "ciphertext", "tag", "sha256" }` with the value and its salt under AES-256-GCM. The salt is never in the receipt: the issuer keeps it in `receipts/salts/<id>.json` (mode 0600, in a 0700 directory), which stays with the operator, is backed up with the receipts, and in mode `digest` is the only copy. The statement carries one note, `capture: { "mode", "withheld": [["request", "args", "$rest"], …] }`, naming every path that holds a commitment; `request.argsDigest` and `execution.resultDigest` are then salted from the salts of the values withheld under them, and each fact's `resultDigest` is a commitment to the lookup's full result. The fields are optional; the format stays v0.2. A verifier recomputes the digests when given the key or a disclosure and passes them as committed otherwise; `agent-custody reveal` writes the disclosure from the key. Both are on the [verify](./verify#reveal) page.

## Grants

A grant is a DSSE envelope over this payload, signed by a principal's key:

```json
{ "version": "0.1", "principal": "user_456", "agent": "support-agent", "scopes": ["customer.lookup", "stripe.refund"], "issuedAt": "2026-09-21T09:27:30.384Z", "expiresAt": "2026-09-21T10:27:31.384Z", "agentKey": "-----BEGIN PUBLIC KEY-----…", "parent": { "payloadType": "…", "payload": "…", "signatures": [] } }
```

`agentKey` (*optional*, SPKI PEM) names the agent's own key so it may delegate; `parent` (*optional*) is the grant this one was delegated from. See [delegation chains](#delegation-chains).

```bash
agent-custody grant --key keys/principal.key --principal user_456 --agent support-agent --scopes customer.lookup,stripe.refund --ttl-hours 24 --agent-key keys/agent.pub --out grant.json
```

Programmatically: `createDelegation(principalKey, payload): Envelope`, `verifyDelegation(envelope, trustedPrincipalKeys): { ok: true, delegation, keyid, chain } | { ok: false, error }`, `delegationValidAt(delegation, isoInstant): boolean`.

### Delegation chains

An agent whose grant names its key delegates a narrower grant to a sub-agent:

```bash
agent-custody delegate --key keys/agent.key --parent grant.json --agent refunder --scopes stripe.refund --ttl-hours 2 --out refunder.json
```

`delegateFrom(parentEnvelope, agentKeyPair, { agent, scopes, issuedAt?, expiresAt?, agentKey? }): Envelope` refuses, before signing, a scope the parent lacks or a window outside the parent's. The verifier walks the chain to a trusted principal key, three delegations deep at most: every link signed by the key its parent names, no scope the parent lacks, a window inside the parent's, the same principal throughout. A receipt issued under a chained grant names the sub-agent as `agent`, the principal as `principal`, and carries the whole chain in `delegation.envelope`.

## Running it

The grant is checked on every call, in every mode, and again just before the forward; over HTTP a session whose grant has expired or been revoked is closed on its next request with `403` and must initialize again with a current grant. `Gateway.grantProblem(at?)` says why a grant is not in force (`"has expired"`, `"is not yet valid"`, `"has been revoked"`), `Gateway.grantDigest` (sha256 over the grant's signed payload, `grantDigest(envelope)` from the package) is what `GatewayHost.revoke(digest)` and `agent-custody revoke` name, and `GatewayHost.revoked()` lists them. Revoking a grant revokes every grant delegated from it. `writeRevokedGrants(path, digests)` writes the file by rename, so a running gateway never reads half of it.

**One agent, over stdio.** The agent's MCP host spawns the gateway; the config's `grantFile` is the grant.

```bash
agent-custody gateway --config gateway.json
```

**Many agents, over HTTP.** One process; each connection presents its own grant on `initialize`, base64url of the envelope's JSON, as `Authorization: Bearer <value>` or `X-Agent-Custody-Grant: <value>`.

```bash
agent-custody gateway --config gateway.json --http --port 8790 --host 127.0.0.1 --idle-minutes 30
```

| route | meaning |
| --- | --- |
| `POST /mcp` | MCP Streamable HTTP. The first request of a session must be `initialize` with the grant; the response carries `mcp-session-id`, sent back on every later request |
| `GET /mcp`, `DELETE /mcp` | the session's event stream and its termination, per the MCP transport |
| `GET /health` | `{ "ok": true, "sessions": 2, "keyid": "9d44…", "pendingReceipts": 0 }`; `pendingReceipts` counts the receipts in the outbox that the log has not taken yet |

A grant signed by a stranger, an expired one, or none gets `403` with the reason in a JSON-RPC error body, for example `{ "jsonrpc": "2.0", "error": { "code": -32000, "message": "delegation grant rejected: no trusted key matches keyids [19b2…]" }, "id": null }`. Sessions share the upstreams, the policy, the key, and the log; each has its own tools, its own receipts, and its own consumed facts. Idle sessions close after `--idle-minutes`.

From JavaScript:

```ts
import { createGatewayHost, serveHttp, grantHeader, loadConfig } from "@agent-custody/receipts";
const host = await createGatewayHost(loadConfig("gateway.json"));   // shared: key, policy, issuer, upstreams
const running = await serveHttp(host, { port: 8790 });               // { url, sessions(), close() }
// a client:
new StreamableHTTPClientTransport(new URL(running.url), { requestInit: { headers: { authorization: `Bearer ${grantHeader(grantEnvelope)}` } } });
```

`host.open(grantEnvelope): Gateway` opens a session by hand; `createGateway(cfg): Promise<Gateway>` is the single-grant form. A `Gateway` has `agentId`, `delegation`, `listTools(): Promise<Tool[]>`, `handleCall({ name, arguments, _meta? }): Promise<CallToolResult>`, and `close()`.

**As an A2A agent.** The gateway speaks A2A itself in front of the config's one `a2a` upstream (exactly one is required, or the command refuses to start). An A2A client, Google ADK's `RemoteA2aAgent` for one, is given the gateway's card URL instead of the remote agent's.

```bash
agent-custody gateway --config gateway.json --a2a --port 8790 --host 127.0.0.1
```

| route | meaning |
| --- | --- |
| `GET /.well-known/agent-card.json`, `GET /.well-known/agent.json` | the remote agent's card with the gateway's own address as its endpoint (`supportedInterfaces[0].url` on a 1.0 card, `url` on a 0.3 card) and its `signatures` removed, since they signed a card that named another address |
| `POST /` | JSON-RPC. `SendMessage` and `SendStreamingMessage` (0.3: `message/send`, `message/stream`) become a `<prefix>.send` call; every other method (`GetTask`, `CancelTask`, the push notification configs) is forwarded to the remote agent as it is, with the `a2a-version` header the client sent, only under a grant in force; otherwise `403` with the reason |
| `POST /message:send`, `POST /message:stream` | the 1.0 HTTP+JSON binding of the same two methods, the request in the body and the task or message answered without the JSON-RPC wrapper |
| `GET /health` | `{ "ok": true, "agent": "document_agent", "keyid": "9d44…" }` |

A delegation runs under the grant in `grantFile` or, when the request carries one, the grant in `Authorization: Bearer <base64url envelope>` or `X-Agent-Custody-Grant`, as for `--http`; one session per distinct grant. Without a `grantFile` a grant header is required, and a request without one, or with an envelope that does not verify, gets `403` with the reason. `<prefix>.send` receives `text` (the message's text parts joined), `message`, `method`, and the `taskId`, `contextId`, `configuration`, and `metadata` the request carried, so a policy reads `context.args.text`.

What the client gets back, in the remote agent's wire format:

| outcome | answer |
| --- | --- |
| allowed | the remote agent's task or message, with `metadata["agent-custody/receipt"]` set to the receipt id; a stream is relayed after the remote agent finishes, each event carrying the key |
| denied by scope or policy, or withheld because the log refused the pre-commit | a task in state `TASK_STATE_REJECTED` (0.3: `rejected`) with the request's `taskId` and `contextId` or fresh ones, the status message `agent-custody: <reason> (receipt <id>)`, and the receipt id in `metadata`; nothing reached the remote agent |
| the remote agent could not be reached | a task in state `TASK_STATE_FAILED` (0.3: `failed`), the same shape |
| the remote agent answered a JSON-RPC error | that error, with `data.receipt` set to the receipt id; the receipt records the call as `failed` |

```json
{ "jsonrpc": "2.0", "id": "1", "result": { "id": "0f3c…", "contextId": "7a1e…", "status": { "state": "TASK_STATE_REJECTED", "message": { "role": "ROLE_AGENT", "messageId": "…", "parts": [{ "text": "agent-custody: Denied by policy: no permit policy matched (receipt 36c85dc9-…)" }] }, "timestamp": "2026-10-10T09:27:31.401Z" }, "metadata": { "agent-custody/receipt": "36c85dc9-43c1-46a9-9be7-9210210a7aa1" } } }
```

From JavaScript, `serveA2a(host, cfg.a2a, { port, host?, grant?, log? }): Promise<{ url, close() }>` is the same server; `A2A_CARD_PATH`, `A2A_RECEIPT_METADATA_KEY` (`"agent-custody/receipt"`), and `A2A_STREAM_META_KEY` (`"agent-custody/a2a-stream"`) are the constants. Example 25 in the repository runs it in front of a stand-in agent.

## What the agent sees

`tools/list` returns the upstreams' tools filtered to the grant's scopes, unchanged. `tools/call` returns the upstream's result with one addition, `_meta["agent-custody/receipt"]`, the receipt id:

```json
{ "content": [{ "type": "text", "text": "{\"refund_id\":\"re_cf4d8b16\",\"status\":\"succeeded\"}" }], "_meta": { "agent-custody/receipt": "36c85dc9-43c1-46a9-9be7-9210210a7aa1" } }
```

A refused call is a tool error, never an exception, so the agent can carry on:

| execution status | tool result text | what happened |
| --- | --- | --- |
| `denied` | `Denied by policy: <reasons> (receipt <id>)` | the grant or the policy refused it; nothing went upstream |
| `withheld` | `Not executed: the log did not commit the authorization… (receipt <id>)` | a pre-committed tool whose authorization the log refused; nothing went upstream |
| `error` | `Upstream error: <message> (receipt <id>)` | the upstream threw or could not be reached |
| `failed` | the upstream's own error result | the upstream answered `isError: true` |
| `executed` | the upstream's result | forwarded and answered |

When the log did not take the receipt, the result also carries `_meta["agent-custody/log-pending"]: true` (the exported constant `LOG_PENDING_META_KEY`). The outcome is real; the receipt waits in `receipts/outbox/` and its bundle appears when the log takes it. A financial operation never gets this mark: its receipt append still fails the call, and `reconcile` finishes it.

The agent may set `_meta["agent-custody/model"]` on a call to have a model id recorded, as `claimed`.

## The policy's view

Each call becomes a Cedar request: principal `Agent::"<agent>"`, action and resource the tool name, and a context:

```json
{ "args": { "customer_id": "cust_123", "amount": 50000 }, "facts": { "customer": { "id": "cust_123", "verified": true } }, "grant": { "principal": "user_456", "scopes": ["customer.lookup", "stripe.refund"] } }
```

`args` is what the agent sent (`claimed`); `facts` is what the gateway fetched itself (`observed`); `grant` is the signed delegation (`attested`). No match is a deny; a `forbid` beats every `permit`; an evaluation error is a deny recorded in the receipt. The decision object in the receipt:

```json
{ "decision": "allow", "reasons": ["policy1"], "errors": [], "policyDigest": "ba4e4461…", "provenance": "observed" }
```

## The receipt bundle

`receipts/<receiptId>.json`, self-contained apart from public keys:

```json
{
  "envelope": { "payloadType": "application/vnd.in-toto+json", "payload": "<base64 statement>", "signatures": [{ "keyid": "9d44…", "sig": "…" }] },
  "treeHead": { "payloadType": "application/vnd.agent-custody.treehead+json", "payload": "<base64 { treeSize, rootHash, timestamp, log? }>", "signatures": [{ "keyid": "6ddd…", "sig": "…" }] },
  "inclusion": { "leafIndex": 0, "treeSize": 1, "hashes": [] }
}
```

The statement inside `envelope.payload` is an in-toto Statement whose predicate is the receipt:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "tool-call:stripe.refund:36c85dc9-…", "digest": { "sha256": "<args digest>" } }],
  "predicateType": "https://agent-custody.dev/receipt/v0.2",
  "predicate": {
    "receiptId": "36c85dc9-43c1-46a9-9be7-9210210a7aa1",
    "timestamp": "2026-09-21T09:27:31.401Z",
    "issuer": { "kind": "gateway", "keyid": "9d44…", "version": "0.1.0" },
    "principal": { "id": "user_456", "keyid": "19b2…", "provenance": "attested" },
    "agent": { "id": "support-agent", "provenance": "attested" },
    "delegation": { "envelope": { "…": "the grant" }, "provenance": "attested" },
    "session": { "id": null, "toolUseId": null, "provenance": "claimed" },
    "model": { "id": "vector-model", "provenance": "claimed" },
    "tool": { "name": "stripe.refund", "provenance": "observed", "upstream": "payments" },
    "request": { "args": { "customer_id": "cust_123", "amount": 50000 }, "argsDigest": "33fc…", "provenance": "claimed" },
    "facts": { "customer": { "tool": "customer.lookup", "args": { "customer_id": "cust_123" }, "value": { "id": "cust_123", "verified": true }, "resultDigest": "8a47…", "provenance": "observed" } },
    "consumed": { "factIds": [], "provenance": "observed" },
    "policy": { "decision": "allow", "reasons": ["policy1"], "errors": [], "policyDigest": "ba4e…", "provenance": "observed" },
    "authorization": { "envelope": { "…": "the authorization statement, pre-committed tools only" }, "treeHead": { "…": "" }, "inclusion": { "leafIndex": 0, "treeSize": 1, "hashes": [] } },
    "execution": { "status": "executed", "result": { "content": [{ "type": "text", "text": "…" }] }, "resultDigest": "d650…", "provenance": "observed", "upstream": { "envelope": { "…": "the upstream's signature, when it signs" } } }
  }
}
```

`execution` is one of `{ status: "executed" | "failed", result, resultDigest, upstream? }`, `{ status: "denied", reason }`, `{ status: "withheld", reason }`, or `{ status: "error", error }`. `tool.upstream` appears when several upstreams are configured. Under a [capture rule](#private-evidence), withheld values hold commitments and the statement's `capture` note names their paths.

## Exporters

Both run after the receipt is written and never block or fail it; a collector that is down costs a line on stderr.

| config | what is sent |
| --- | --- |
| `otel: { url, headersEnv?, serviceName? }` | `POST <url>/v1/traces`, OTLP/HTTP JSON, one span per receipt: trace id = receipt id without hyphens, span name = tool, attributes `agent_custody.receipt_id`, `.issuer.kind`, `.tool`, `.agent`, `.principal`, `.execution.status`, `.policy.decision`, `.policy.digest`, `.operation.status`, `.operation.original_receipt_id`, `.log.leaf_index`, `.log.tree_size`, `.consumed.count`, `.model`, `.session`; status error only for `failed` and `error`. A reconciliation receipt has the span name `<tool> reconciliation`, `agent_custody.reconciliation` and `.reconciliation.lookup_tool`, the status `reconciled`, and no policy attributes; its span status is an error when `operation.status` is `failed` |
| `splunk: { url, tokenEnv, index?, source?, sourcetype?, host? }` | `POST <url>/services/collector/event` with `Authorization: Splunk <token>`, one event `{ time, source: "agent-custody", sourcetype: "agent-custody:receipt", index?, host?, event: { receipt_id, issuer_kind, issuer_keyid, tool, upstream, agent, agent_provenance, principal, status, reason, policy_decision, policy_digest, policy_reasons, args_digest, log_leaf_index, log_tree_size, authorization_leaf_index, consumed_count, model, session, reconciliation, reconciliation_lookup_tool, operation_status, operation_original_receipt_id } }`; a reconciliation receipt has `status: "reconciled"` and null policy fields |

Programmatically: `otlpExporter(cfg)`, `splunkExporter(cfg)`, `openExporter(config)` (every configured exporter as one), each a `ReceiptExporter` with `exported(predicate, bundle): Promise<void>`; `createGateway(cfg, { exporter })` and `createGatewayHost(cfg, { exporter, log })` accept one for tests.
