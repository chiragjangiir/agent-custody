# Usage guide: the gateway

This page covers the gateway, the out-of-process producer. For the in-process interceptor that hooks Claude Code, the Claude Agent SDK, or any framework's tool functions, see [sdk.md](sdk.md).

For who may use which tools, where the tools live, a worked example with two agents on one shared gateway, how the config works in the Docker image, and how to check it before you start, see [configuration.md](configuration.md). This page is the setup in order.

## The parts

| part | what it is | who controls it |
| --- | --- | --- |
| principal | the human or organisation on whose authority the agent acts | you |
| agent | any MCP client: Claude Desktop, Claude Code, a LangGraph node, your own loop | you, but its behaviour is not trusted |
| gateway | this project, run as an MCP server over stdio | you, holds the gateway signing key |
| upstream | the real MCP server the agent wants: Stripe, a database, GitHub | the tool provider |
| grant | a signed statement: principal P lets agent A use tools [..] from T1 to T2 | signed by the principal's key |
| policy | a Cedar file evaluated on every call | you |
| receipt bundle | one JSON file per call, signed, with a log inclusion proof | produced by the gateway |
| log | an append-only JSONL file whose Merkle root every receipt commits to | produced by the gateway |

One gateway process serves one delegation grant. That maps cleanly onto "one agent session, spawned per user, with a scoped grant". Run several gateways for several agents.

## Setup, step by step

All commands run from `packages/receipts`. `node src/cli.ts` works on Node 22 and later without a build step.

**1. Generate keys.** One pair for the gateway, one for the principal. Keep the `.key` files private; distribute the `.pub` files to anyone who will verify receipts.

```bash
node src/cli.ts keygen --dir ./keys --name gateway
node src/cli.ts keygen --dir ./keys --name principal
```

**2. Issue a grant.** The principal signs which agent may use which tools, and for how long.

```bash
node src/cli.ts grant \
  --key ./keys/principal.key \
  --principal user_456 \
  --agent support-agent \
  --scopes customer.lookup,stripe.refund \
  --ttl-hours 8 \
  --out ./grant.json
```

The gateway refuses to start if the grant is outside its validity window, and every receipt records the grant so a verifier can re-check it.

**Sub-agents.** A grant that names the agent's own public key (`--agent-key agent.pub`, carried as `agentKey`) lets that agent delegate: `agent-custody delegate --key agent.key --parent grant.json --agent refunder --scopes stripe.refund --out refunder.json` signs a narrower grant for the sub-agent with the parent grant embedded. The chain may go three delegations deep. A verifier walks it back to the principal: every link must be signed by the key its parent names, every scope must be one the parent holds, every window must sit inside the parent's, and the principal never changes; the gateway applies the same rule before opening a session, and the receipt names the sub-agent as the agent and the principal as the principal, with the whole chain inside, so `verify` reports `delegation chain to the principal: user_456 → planner → refunder`. Nothing about the tools changes: the sub-agent sees the scopes its own grant names and no more.

**3. Write a policy.** A Cedar file. Default is deny. See [policies.md](policies.md).

```cedar
permit(principal, action == Action::"customer.lookup", resource);

permit(principal, action == Action::"stripe.refund", resource)
when {
  context.args.amount <= 100000 &&
  context.facts has customer &&
  context.facts.customer.verified == true
};
```

**4. Write the gateway config.** Paths resolve relative to the config file.

```json
{
  "identity": { "keyFile": "keys/gateway.key" },
  "upstream": { "command": "node", "args": ["/path/to/stripe-mcp-server.js"], "env": { "STRIPE_KEY": "sk_..." } },
  "grantFile": "grant.json",
  "trustedPrincipalKeys": ["keys/principal.pub"],
  "policyFile": "policy.cedar",
  "facts": [
    {
      "name": "customer",
      "tool": "customer.lookup",
      "args": { "customer_id": "$args.customer_id" },
      "forTools": ["stripe.refund"]
    }
  ],
  "precommit": ["stripe.refund"],
  "receiptsDir": "receipts",
  "logFile": "log.jsonl"
}
```

`upstream` is spawned by the gateway exactly as an MCP host would spawn it, with a minimal environment: the path, home, and temp directories, the locale, and what `env` names. It never inherits the gateway's own variables, where the tokens for other upstreams and the log live, so a tool process cannot read them; `env` is where that upstream's own credentials go, and the agent never sees them. Several upstreams sit behind one gateway and one grant with `"upstreams": [{ "name": "memory", "command": ..., "args": [...] }, { "name": "payments", "url": ... }]` in place of `upstream`. Each tool name must be offered by exactly one of them, checked at startup; the receipt's `tool.upstream` says which served the call, and consumed facts flow across them, so a refund made after a memory read carries the facts the agent had been shown. An upstream that is already running is reached instead with `"upstream": { "url": "https://memory.internal/mcp", "tokenEnv": "MEMORY_TOKEN" }`, over Streamable HTTP with a bearer token from the environment; the shared memory server in `@agent-custody/state` is the usual case.

An upstream need not be an MCP server. A plain HTTP API is described as tools:

```json
  "upstream": {
    "rest": {
      "baseUrl": "https://api.stripe.com",
      "headerEnv": { "authorization": "STRIPE_BEARER" },
      "tools": [
        { "name": "customer.lookup", "method": "GET", "path": "/v1/customers/{customer_id}",
          "inputSchema": { "type": "object", "properties": { "customer_id": { "type": "string" } }, "required": ["customer_id"] } },
        { "name": "stripe.refund", "method": "POST", "path": "/v1/refunds", "description": "Refund a customer, amount in minor units",
          "inputSchema": { "type": "object", "properties": { "customer_id": { "type": "string" }, "amount": { "type": "integer" } }, "required": ["customer_id", "amount"] } }
      ]
    }
  }
```

`{name}` segments in `path` are filled from the call's arguments; the remaining arguments go to the query string on GET and DELETE and to a JSON body otherwise, or `query` names the ones that go to the query and `body: "none"` sends no body. `headers` are sent as written; `headerEnv` maps a header to an environment variable read once at startup, so the credential is never in the file and never reaches the agent, and a missing variable fails at startup. The response body is the tool result, JSON kept as JSON, and a non-2xx status is a failed execution with the API's answer in the receipt. Everything else is unchanged: the tools appear in the grant's scopes, `facts` may name a REST tool for a lookup, `precommit` applies, and each call has a receipt. `rest` can be one of several `upstreams` beside MCP servers. This is how an agent's direct HTTP calls come under custody: they become tool calls through the gateway. Tutorial 17 runs one against a stand-in API.

Another agent is an upstream too. An agent that speaks the A2A protocol publishes an agent card and takes tasks as messages; described as an upstream, delegating to it becomes a tool call:

```json
  "upstream": {
    "a2a": {
      "url": "https://docs-agent.internal",
      "headerEnv": { "authorization": "DOCS_AGENT_BEARER" },
      "prefix": "docs"
    }
  }
```

At startup the gateway fetches the agent's card from `<url>/.well-known/agent-card.json` (or `/.well-known/agent.json`, or `url` itself when it ends in `.json`) and offers two tools. `<prefix>.send` delegates a task: `text` is the task as text and the gateway builds the A2A message from it, or `message` is a full A2A message forwarded as it is; `taskId`, `contextId`, `configuration`, and `metadata` are optional and pass through. `<prefix>.card` reads the card, which is how a policy decides on the agent the gateway is actually talking to: `"facts": [{ "name": "card", "tool": "docs.card", "args": {}, "forTools": ["docs.send"] }]` puts it under `context.facts.card`, fetched by the gateway, and `context.args.text` is the task. The card says which wire format the agent speaks, A2A 1.0 (`SendMessage`, `supportedInterfaces`) or 0.3 (`message/send`, `url`), and the gateway speaks that one. The result is the agent's task or message; a streamed delegation is relayed once the agent has finished, and the receipt records the task's final state. A JSON-RPC error from the agent is a failed execution with the error in the receipt. `prefix` defaults to `a2a` (give each A2A upstream its own), `timeoutMs` to 120000, and `headers` and `headerEnv` work as for a REST upstream. `precommit: ["docs.send"]` logs the authorization before the task goes out, as for any consequential tool. An agent that delegates over A2A does not call `docs.send` itself; it reads a card and sends messages, which is what the gateway's A2A front, [below](#the-gateway-as-an-a2a-agent), is for. Tutorial 25 runs both against a stand-in agent.

`logFile` is the local Merkle log, with tree heads signed by the gateway's own key. To log to a server the operator does not control, replace it with `log`:

```json
  "log": { "url": "https://log.example.com/", "tokenEnv": "AGENT_CUSTODY_LOG_TOKEN" }
```

Exactly one of the two. The bearer token comes from the named environment variable, never from the file, and a missing variable fails at startup. Add `"hashOnly": true` for any log run by someone else: the gateway then sends only the leaf hash, sha256 of the receipt envelope with the RFC 6962 prefix, so the log commits to the receipt without ever holding it, and the receipts with their arguments and results stay in `receiptsDir`. The verifier does not change; it hashes the envelope itself. A log that serves several tenants is reached at `<url>/t/<tenant>/`, and each of its tree heads names its log, which a verifier checks with `--log-id`. With a remote log the tree head in each receipt is signed by the log's key, and a verifier must be given that key with `--log-key`. The gateway does not take the log's answer on trust either: the tree head in every append's answer must verify against the log's keys, name the expected log, match the proof's size, and the inclusion proof must place that very leaf under the signed root, all before a pre-committed call is forwarded and before any receipt is handed out; an answer that fails any of it is a refusal. `"keys": ["keys/log.pub"]` pins the log's public keys, `"logId"` the id its heads must carry; without `keys` the log's key document at `/.well-known/agent-custody-log.json` is fetched from the log itself once, on the first append, and pinned. That catches a log that turns dishonest later, not one that is dishonest from the start, so a gateway config with `precommit` and a remote log must list `keys`. When the log rotates its key, add the new public key to `keys`; a gateway that fetched the keys needs a restart. An append that gets no answer within `timeoutMs` (default 10000) counts as unreachable and is retried like a server error, so a log that accepts connections and never answers cannot hold a call forever. If the log does not take a receipt, the gateway keeps the signed receipt in `receipts/outbox/<receiptId>.json` and returns the real outcome of the call to the agent, with the receipt id and `_meta["agent-custody/log-pending"]: true`. The gateway appends the outbox at startup and every 30 seconds, and writes `receipts/<receiptId>.json` when the log takes the receipt. Until then no bundle exists, so no receipt that was never logged is handed out. The table [below](#when-the-log-fails) gives each case. For a tool named in `precommit` the order is reversed, below, and the action never happens. A fact lookup is different: it runs before the policy decides, because the policy decides on it, and only once the intercepted tool is in the grant's scope, so a fact tool must be a read. Naming a fact tool in `precommit` is refused at startup; `"*"` covers the tools the agent calls, not the gateway's own lookups. Every lookup is on the receipt with its arguments. The reference log server is `node src/cli.ts log --file log.jsonl --key keys/log.key --port 8787 --token-env AGENT_CUSTODY_LOG_TOKEN [--log-id <id>] [--tenants tenants.json]`. It serves `POST /append` with `{leaf}` or `{leafHash}` (token required when one is configured), `GET /root?size=N`, `GET /consistency?old=M&new=N`, and `GET /head`; [verification.md](verification.md) says what each proves. `--log-id` writes that id into every tree head. `--tenants` names a JSON file, `{ "acme": { "file": "acme.jsonl", "tokenEnv": "ACME_TOKEN", "logId": "acme-eu" } }`, and each tenant is its own log at `/t/acme/…` with its own token and id; the default log stays at the root paths. With `--hash-only` the server refuses `{leaf}` at append and accepts only `{leafHash}`, so a log run for other people never receives a receipt regardless of the client's configuration; the hosted deployment sets it. With `--db-env DATABASE_URL` the server keeps its logs in Postgres instead of files, and needs the `pg` package beside it: leaves as hashes in one table keyed by tenant, one writer per tenant enforced with an advisory lock so a second instance is safe, tenants and their tokens in tables of their own with tokens stored only as hashes, and rate limits per token (50 appends a second, burst 100, a 64 KB body cap; a refused append answers 429 with `retry-after`, and the gateway's sink retries a few times). Tenants are managed with `log-admin --db-env DATABASE_URL`: `tenant add <id> [--log-id <id>]`, `token add <tenant> --label <text>` (the token is printed once), `token revoke <tenant> <hash-prefix>`, `tenant disable <id>`, `tenant plan <id> <free|team|enterprise>`, and `import --file log.jsonl [--tenant default]` to bring an existing file log in as hashes. Every tenant is on a plan, `free` unless moved: free allows ten thousand appends a calendar month, team a million, enterprise has no allowance. An append past the allowance is refused with 429, the numbers, and a `retry-after` that reaches the start of next month; the gateway behind it then withholds pre-committed calls and financial operations, so a tenant out of quota never acts on those without evidence. Any other call is forwarded, and its receipt waits in the outbox ([below](#when-the-log-fails)). The tenant's own `GET /t/<name>/usage` reports the plan and quota beside the month's appends. The tenant portal, `agent-custody portal --db-env DATABASE_URL --secret-env PORTAL_SECRET --public-url <log url> [--checkpoints-url <url>] [--portal-url <url>] [--stripe-key-env NAME --stripe-webhook-env NAME --stripe-price-team <price id>] [--trust-proxy]`, is the self-serve front of the same tables: a team registers with an email, a password (scrypt), and a tenant id and gets the tenant and its first key shown once with the welcome sheet; the dashboard shows appends against the plan, the tree size and root, the latest checkpoint, the log's URLs, keys, and the audit rows; keys are minted and revoked there, recorded as `portal:<email>`; the export command is on the page; and with the three Stripe variables the team plan is bought through Stripe Checkout, the signed webhook moving the plan (`stripe:<event>` in the audit trail) and the customer portal handling cancellation. Sessions are a signed cookie, `SameSite=Strict`, and every write needs a JSON body. Each member has a role (`owner`, `admin`, `reviewer`, `readonly`), an account can turn on TOTP MFA, and the operator can set up single sign-on through the tenant's own OIDC or SAML identity provider with `log-admin sso set`; the [hosted log reference](https://docs.agent-custody.dev/reference/hosted) lists the routes. SAML needs `@node-saml/node-saml` beside the CLI. The compose file runs it as the `portal` service at `PORTAL_HOST`. The root paths serve the tenant `default`, created on first start with `--log-id`, and `--token-env` still works for it. The key that signs tree heads can live in its own process: `agent-custody signer --key keys/log.key --port 8790 --token-env SIGNER_TOKEN` holds it and answers `POST /sign` with the shared secret and `GET /keys` to anyone; the log server then runs with `--signer-url http://signer:8790/ --signer-token-env SIGNER_TOKEN` instead of `--key`, and the process that faces the internet never holds the key. Either way the log serves its keys at `/.well-known/agent-custody-log.json`, current key first and retired keys (`--retired-key old.pub`) after it, so verifiers fetch and pin them with `verify --log-url` and `audit --log-url` rather than receiving a key file from the operator. With `--checkpoint-dir <dir>` the server publishes a signed checkpoint, every `--checkpoint-every` seconds (default 300), for each log whose tree has grown, and every `--checkpoint-heartbeat` seconds (default 21600, six hours) for a log that has not, so a quiet log's latest checkpoint is never more than six hours old and the monitor can tell quiet from stalled, as `<dir>/<tenant>/<treeSize>.json` and `latest.json`, and with a database also as rows; `GET /checkpoints?since=<size>` and `GET /t/<tenant>/checkpoints` list them. Serve the directory read-only from a second host, so the record of what the log signed does not depend on the log's API being up; a verifier who kept an earlier head audits against a later checkpoint with `audit --older <bundle> --newer <checkpoint> --log-url <url>`. With `--admin-token-env ADMIN_TOKEN` (Postgres only) the server also serves the operator's page at `/admin` and its API under `/admin/`: list and create tenants, mint a token that is shown once beside the tenant's welcome sheet, revoke tokens, disable tenants. Everything under `/admin`, the page included, needs the admin token: the browser asks for it (any user name, the token as the password) and an API client sends it as a bearer; a handful of wrong attempts from one address are throttled for a minute. Every change made there or with `log-admin` is recorded: who (the name entered at the browser prompt and the address, `bearer` for an API client, or the user and host for the command line), what (`tenant.add`, `tenant.disable`, `token.add`, `token.revoke`), which tenant, and the detail, never the token itself; the page shows it under Activity, `GET /admin/audit?tenant=&limit=` and `log-admin audit` list it, and a tenant reads their own rows at `GET /t/<name>/audit` with their token. Nothing else is stored by the page. Behind a reverse proxy, start the server with `--trust-proxy` so those per-address limits key on `X-Forwarded-For` instead of on the proxy's own address, and only there, since the header is otherwise the client's to forge. `--public-url` and `--checkpoints-url` fill the sheet in. The witness closes the last gap: `agent-custody witness --key witness.key --log-url <url> --checkpoints-url <url> --out <dir> [--tenant <name>]...` runs on a machine the log's operator does not control, fetches each watched log's latest checkpoint, verifies it against the log's published keys, proves with the log's consistency proof that it extends the last head the witness signed, and countersigns it into `<dir>/<tenant>/<size>.json` and `latest.json`; a checkpoint that does not extend, or a second history at the same size, gets `ALARM.json` instead. Its key document is `<dir>/.well-known/agent-custody-witness.json`. Serve `<dir>` from the witness's own host; verifiers add `--witness-url` (or `--witness-key`) to `audit`, and the newer head must then carry the witness's signature. Two more things an operator needs. `agent-custody log-check --log-url <url> --checkpoints-url <url> [--witness-url <url>] [--tenant <name>]... [--max-lag <seconds>]` is the outside monitor: it verifies the head against the published keys, that the latest checkpoint verifies and keeps up with the head, that the head extends the checkpoint, and, with a witness, that the witness has countersigned, keeps up, and has raised no alarm; it exits 1 on any failure, so cron or a scheduled workflow on a machine that is not the log's turns it into an alert. `GET /health` on the server is the liveness check for a load balancer. And `GET /admin/usage?month=YYYY-MM`, on the admin page and as `/admin/usage.csv`, is the metering: appends per tenant for the month, leaves in total, live tokens, the numbers any invoice rests on. A tenant needs none of that to leave with their evidence: `agent-custody log-export --log-url <url> --tenant <name> --token-env AGENT_CUSTODY_LOG_TOKEN --out <dir>` fetches, with their own token, every leaf hash (`GET /t/<name>/leaves?since=&limit=`, pages of up to ten thousand), the signed head, the published keys, the signed checkpoints, their own usage (`GET /t/<name>/usage?month=`), and the administrative actions on their tenant (`GET /t/<name>/audit`, into `audit.json`), checks that the head and every checkpoint verify against the keys and that the leaves fetched hash to their roots, and writes `log.jsonl` in the format `verify --log` and `audit --log` read, so the export verifies receipts with no server at all. It exits 1 and says what did not add up if anything does not. Both routes answer only to that tenant's token. [deploy/](../../deploy/README.md) runs the server, the signer, Postgres, and the checkpoints host as containers, and [deploy/witness/](../../deploy/witness/) the witness.

`otel`, optional in both the gateway and SDK configs, sends every receipt to the collector you already run as one span over OTLP/HTTP, after the receipt is issued: `"otel": { "url": "http://localhost:4318", "headersEnv": { "x-api-key": "OTEL_KEY" }, "serviceName": "support-agents" }`. The span's trace id is the receipt id, its attributes carry the tool, agent, principal, execution status, policy decision, and log position, and its status is an error only when the upstream failed or errored, since a denial is the policy working. Export is best effort: a collector that is down or refuses costs a line on stderr, never a receipt. Tutorial 18 shows it against a stand-in collector.

`splunk`, optional in both configs and usable beside `otel`, sends every receipt to a Splunk HTTP Event Collector as one event: `"splunk": { "url": "https://splunk.example.com:8088", "tokenEnv": "HEC_TOKEN", "index": "agents" }`, with optional `source` (default `agent-custody`), `sourcetype` (default `agent-custody:receipt`), and `host`. The token is read from the named environment variable at startup and never appears in the config. Each event carries `receipt_id`, `tool`, `agent`, `principal`, `status`, `reason`, `policy_decision`, `policy_digest`, `args_digest`, `log_leaf_index`, `log_tree_size`, and `authorization_leaf_index` as plain fields, so a search like `sourcetype="agent-custody:receipt" status=denied` needs no field extraction and every alert leads to the receipt by id. The same rule holds: the event is a copy, the receipt is the evidence, and a collector outage costs a warning. Tutorial 19 shows it.

`facts` tells the gateway which upstream tool to call before evaluating policy for a given tool. `$args.<key>` copies a value from the intercepted call. The result appears in Cedar as `context.facts.<name>` and in the receipt with its own digest, labelled `observed`. If a fact lookup fails, the call is denied and the receipt says why. A lookup with `"optional": true` is skipped when a `$args.<key>` it needs is absent from the call, and the fact is then simply not present, which a policy tests with `context.facts has <name>`; this is how a policy sees the fact a `memory.write` is about to supersede without denying every write that supersedes nothing.

`mode` is `"enforce"` by default. Set it to `"observe"` to run a new policy against real traffic before turning it on: every call the grant allows is forwarded, the decision the policy would have made is recorded on the receipt with `enforced: false`, and nothing is withheld. Observe mode suspends the policy and nothing else: a tool outside the grant's scopes, or a call after the grant expired or was revoked, is denied and never forwarded in either mode. The verifier accepts such a receipt and names the mode; strip the flag and the same receipt fails. Switch to `"enforce"` when the receipts stop saying "would have been denied" for calls you meant to allow.

To test a different policy against the history already collected, run `agent-custody policy simulate --policy proposed.cedar --receipts receipts --issuer-key keys/gateway.pub --principal-key keys/principal.pub --out simulation.json`. It replays recorded arguments and fact values without calling upstreams, lists changed decisions by tool and reason with the receipt ids, and records the proposed policy digest. Missing replay inputs make the report incomplete. See [the policy simulation guide](policies.md#simulating-a-policy-against-recorded-history).

The grant is checked on every call, not only when the session opens: a call after `expiresAt` is denied with a receipt that says so, the check is repeated just before the forward (a grant that ran out while the facts were gathered leaves the call `withheld`), and over HTTP a session whose grant has expired or been revoked is closed on its next request with `403`. `"revokedGrants": "revoked.json"` names a file of grant digests the gateway re-reads whenever it changes. The digest is sha256 over the grant's signed payload, so extra signatures or fields on the envelope do not change it, and revoking a grant also revokes every grant delegated from it. A file that cannot be read denies every call until it can be read; `agent-custody revoke --config gateway.json --grant grant.json` appends a grant's digest to it, after which every session under that grant refuses its next call and no new session opens for it, with no key rotation. The Cedar policy is re-read the same way: when `policyFile` changes (device, inode, mtime, ctime, or size; a file written in the last two seconds is re-read on each call until it settles), the next call is evaluated under the new policy, with no restart and no dropped session, and a call already evaluating finishes under the policy it started with, whose digest its receipt carries. A changed file that does not parse, or that cannot be read, is refused: the policy in force stays, never an allow, and the gateway prints `POLICY NOT RELOADED` on stderr. Every change and every refusal is appended to `receipts/policy-reloads.jsonl` as `{ at, file, event: "reloaded" | "refused", from, to, errors?, warnings? }`, with the digest in force and the digest of the new file (`null` when the file was removed or cannot be read), so the change between two receipts' `policyDigest`s has a time. A reloaded policy with no permit rule is applied, since it denies every call, but is printed and recorded with the warning `no permit rule: every call is denied`. Write the file by rename, as `agent-custody console` does. A file written in place can be read half-written: a prefix that parses, missing a trailing `forbid`, decides calls until the write finishes and the settled file is read. `precommit` names the consequential tools, or `["*"]` for all of them. For every other tool the gateway forwards the call and then records it, so if the log is unreachable at that moment the side effect exists before its evidence is in the log: the receipt waits in the outbox. With a remote log and an empty `precommit`, the gateway prints a warning at startup and `agent-custody check` reports it; `"requirePrecommit": true` makes it a startup error, and [strict mode](#strict-mode) precommits every tool. For a tool in `precommit` the gateway first signs an authorization statement, everything the receipt will say except the outcome, and appends it to the log. Only if the log took it does the call go upstream. The receipt then embeds that authorization with its own inclusion proof, and a verifier checks that it names this call and sits in the log before the receipt does. If the log will not take it, or answers with a head or proof that does not verify, the call is not forwarded, the agent is told `Not executed`, and the receipt records `execution.status: "withheld"` with the policy's `allow` beside it. The authorization is also written on its own as `receipts/<receiptId>.authorization.json`, which is the evidence that survives if the gateway dies between forwarding and the receipt. Use it for money, for anything irreversible, and for anything a counterparty could later dispute; the cost is one extra log append per call.

#### When the log fails

"Down" is a log that does not answer or answers 5xx. "Slow" is an append that takes longer than `log.timeoutMs` (default 10000 ms), which counts as down. "Refusing" is a 4xx answer other than 429, or an answer whose tree head or proof does not verify. "Quota" is 429, after the sink's retries. The sink makes three attempts before the gateway treats the append as failed.

| log state | ordinary tool | tool in `precommit` | financial operation |
| --- | --- | --- | --- |
| down, slow, or quota (429) | forwarded; the agent gets the real result and `log-pending`; the receipt waits in the outbox and is appended when the log answers again | not forwarded; the agent gets `Not executed` and `log-pending`; the `withheld` receipt waits in the outbox | the call returns an error and nothing is forwarded, because the authorization is not in the log; if only the receipt append fails after the forward, the call also returns an error, and `reconcile` finishes the operation |
| refusing | as above, but the outbox does not empty until the operator fixes the cause (a token, a quota, the pinned keys); the gateway prints the reason on each attempt | as above | as above |

The outbox is appended in the order of the signed statements' timestamps, oldest first. A log refusal stops the flush, so one receipt that the log refuses holds the receipts after it. `GET /health` on the HTTP gateway reports `pendingReceipts`. Only a gateway that serves (stdio, `--http`, `--a2a`) runs the flush, at start and every 30 seconds; `check`, `reconcile`, and the other commands never append the outbox. A gateway that stops waits for a flush that runs. A gateway that stops before the log takes the receipt keeps the outbox on disk and appends it on the next start. The gateway writes the outbox entry to disk, and syncs the file and its directory, before the agent gets the result.

Several gateways, or a gateway and a command, can share one `receipts/` directory. A flush takes the lock file `receipts/outbox/.lock` with an exclusive create. When another process holds the lock, the flush does nothing and reports the entries as `pending`. The gateway breaks a lock whose owner process no longer runs on this host. It never breaks the lock of a live process on this host. It breaks the lock of a process on another host, or a lock file with no readable owner, when nobody has touched it for 15 minutes (one minute for a file with no owner). It uses the same break procedure as the local log ([sdk.md](sdk.md)).

When the log takes a receipt, the gateway records the log's answer in the outbox entry before it writes the bundle. If the bundle write then fails (a full disk, a permission error), the gateway prints the error on stderr, and the next flush writes the bundle from the recorded answer and does not append the leaf again. A process that dies between the append and that record appends the leaf again on the next flush; the log then holds it twice, and either copy proves the receipt. A gateway that dies after the forward and before the outbox write leaves no receipt; `precommit` is the guard for the calls where that matters. Before the gateway appends an outbox entry, it checks the entry. It renames an entry to `<name>.bad`, does not append it, and prints a warning, when the file is damaged, when the entry carries this gateway's key id but the signature does not verify, or when the receipt id in the statement is not the id in the file name. An entry that another key signed (a rotated gateway key, or a restored backup) is not appended, is not called forged, and stays in the outbox; the gateway prints a warning on each flush. Restore the key that signed it, or move the entry away. Until the log takes a pending receipt, `receipts/<id>.json` does not exist, so `verify`, `explain`, `blast`, the review console, and `prune` do not see the call yet.

#### Strict mode

The outbox keeps the receipt of a call through a log outage, but the operator runs the gateway: killing it between the forward and the outbox write, or deleting the outbox entry, leaves a call with no receipt, and a local log can be rewritten outright. `"strict": true` closes that for the calls the agent makes:

```json
{
  "strict": true,
  "log": { "url": "https://log.example.com/t/acme/", "tokenEnv": "AGENT_CUSTODY_LOG_TOKEN", "hashOnly": true, "keys": ["keys/log.pub"] }
}
```

- The gateway does not start with `logFile`, with a `log` that is not `hashOnly`, or with a `log` without `keys`. Each is a startup error that names the setting, and `agent-custody check` reports it. On a config without `strict`, `check` lists what strict mode would refuse.
- Every tool is precommitted, as with `precommit: ["*"]`: the authorization is in the log before the call is forwarded, and a call whose authorization the log will not take is `withheld`. In observe mode too, where a call the policy would deny is still forwarded and is precommitted like any other.
- No receipt goes to the outbox. A receipt that the log refuses after the forward is not kept, the call returns an error to the agent, and the authorization in the log stands. A gateway killed at any point leaves either no call or an authorization with no outcome, which a verifier reports as incomplete. Receipts left in the outbox from before strict mode was turned on are appended once, at start; there is no 30-second retry.
- Every receipt and authorization carries `issuer.strict: true`, and `verify --require-strict` refuses a receipt without it, or a forwarded call without its authorization ([verification.md](verification.md)).

The cost is one extra log append per call, and a log outage stops every call. What strict mode does not cover: a fact lookup and a `reconcile` read are reads the gateway makes itself, before the policy decides or on the operator's command, and go out before any log entry; each is on the receipt that follows. The flag is the gateway's own statement, signed with its key: it binds an honest gateway's operator to a mode a verifier can hold them to, and a modified gateway can still claim it. Only a gateway the operator cannot change ([the plan](../README.md#plan)) closes that.

**5. Run the gateway.** It speaks MCP on stdin/stdout and logs to stderr only.

```bash
node src/cli.ts gateway --config ./gateway.json
```

You will not normally run this by hand. The agent host spawns it, as below.

## Require a human approval

A grant can permit a tool while a human must still approve each exact action. Add `approvals` to the gateway config:

```json
{
  "approvals": {
    "trustedKeys": ["keys/approver.pub", "keys/second-approver.pub"],
    "usedDir": "approvals-used",
    "tools": [{ "tool": "stripe.refund", "minApprovers": 2, "fields": { "beneficiary": "customer_id" } }]
  }
}
```

The caller puts an approver-signed DSSE envelope in `_meta["agent-custody/approval"]`. It binds the principal, agent, tool, complete argument digest, amount in integer minor units, currency, beneficiary, and expiry. The gateway refuses an approval whose lifetime exceeds `approvals.maxLifetimeSeconds` (default `3600`). A second approver countersigns the same envelope for a two-key rule. Missing, expired, mismatched, or insufficiently signed approvals deny the call even in observe mode. A valid approval still needs a valid grant and an allowing policy.

The gateway checks again and consumes the approval id immediately before forwarding. Keep `usedDir` persistent and shared by every gateway that accepts the same approvals; a restart, crash, or unknown upstream outcome never releases a consumed id. The receipt embeds the approval evidence; `verify --approval-key` uses separate human public keys to check it. Single use is enforced by the store, not proved globally by one offline receipt.

Under a private capture rule the receipt withholds the approval envelope as a commitment, because it carries the action fields and an unsalted digest of all arguments. The status, the times, and the signer key ids stay in clear. Full approval verification then requires the capture key or a disclosure. [The approval guide](approvals.md) covers signing, field mappings, failure recovery, and these privacy limits; [tutorial 30](../examples/30-payload-bound-approvals.ts) runs it end to end.

## Review a transaction and export its case

The state package's `agent-custody-memory review` opens the receipts as a local review console, with one receipt's ten answers and verification report behind each index row:

```bash
agent-custody-memory review --receipts receipts --issuer-key keys/gateway.pub --principal-key keys/principal.pub --transaction re_123 --customer cust_123 --agent support-agent --from 2026-10-01T00:00:00Z --to 2026-10-31T23:59:59Z
agent-custody-memory review --receipts receipts --issuer-key keys/gateway.pub --principal-key keys/principal.pub --out review-site/
agent-custody-memory review --receipts receipts --issuer-key keys/gateway.pub --principal-key keys/principal.pub --case <receiptId> --out refund.case.html
agent-custody-memory review --receipts receipts --issuer-key keys/gateway.pub --principal-key keys/principal.pub --case <receiptId> --out refund.case.json
agent-custody-memory review --verify-case refund.case.json --issuer-key keys/gateway.pub --principal-key keys/principal.pub --json
agent-custody-memory review --verify-case refund.case.html --issuer-key keys/gateway.pub --principal-key keys/principal.pub
```

`--transaction`, `--customer`, and `--agent` match exact case-sensitive ids; all filters combine with AND. `--from` and `--to` are inclusive ISO date-times with `Z` or a UTC offset. Search covers public arguments, results, and gateway facts; a withheld identifier is unavailable. A record whose receipt id differs from its file name stays in the index as NOT VERIFIED, and the header counts the files that cannot be read. A receipt with a value that search skipped (deeper than 64 levels, or JSON text over 64 KiB) is marked "partially indexed" and stays in the list under an id filter. `--ledger <path>` adds belief dependencies, `--log-key <pub>` and `--log-id <id>` check the log, and `--upstream-key <pub>` checks signed upstream results. `--host` defaults to `127.0.0.1`, `--port` to `8791`; `--title <text>` labels the console. It has no authentication of its own. A directory export includes the index, receipt pages and bundles, and portable HTML/JSON cases; its browser search covers the exported set.

The standalone `.case.html` repeats cryptographic checks on the signed evidence with embedded WebCrypto code, offline and without external requests. That result is not independent, because the script is in the same file as the data, and the page does not compare the ten answers with the receipts. Check the `.case.html` or its JSON companion independently with `--verify-case`. The file name sets the format: `.json` is read as JSON, every other name is read as a page, and content that does not match fails. It rebuilds the ten answers from the signed receipt and prints them, it fails a `.case.html` that is not exactly what its data renders, and it exits 1 on failure. Trust the printed answers, not the page. The belief, dependency, and reversal lines come from the unsigned ledger snapshot and are not attested; public key flags may be repeated and replace the entire bundled trust set. Confirm bundled key fingerprints with a trusted source. Cases include signed receipts, authorizations, log heads and proofs, public keys, and the ten answers; explanation and ledger snapshots are unsigned exporter assertions. Verification proves the recorded gateway decision and detects receipt tampering, not an external payment side effect. Without a ledger the belief questions remain unknown. Private keys, capture keys, disclosures, and issuer salts files are not exported, and withheld values stay unavailable. [The state guide](../../state/README.md#explain-one-action) and [runnable example](../../state/examples/08-review-console.ts) cover the full flow.

## Financial operations

For payments, configure `operations` to bind a caller-retained operation UUID to the full call, reserve its amount atomically, and pass an idempotency key to the provider. Existing operations are never forwarded again on retry, and an allowed retry gets a `withheld` receipt of its own. API execution and financial settlement have separate statuses; uncertain outcomes hold their reservations until an operator's provider read commits a reconciliation receipt. The [financial operations guide](financial-operations.md) has the config, provider contract, and `agent-custody reconcile` command. [Tutorial 29](../examples/29-financial-operations.ts) runs the lost-response/restart scenario offline.

## Private evidence

A receipt carries the call as it happened: the arguments, the result, and the facts the policy decided on. Some of that a reviewer has no business seeing: the note on a refund with the caller's phone number, the customer record the policy read, the provider's full answer. `capture` in the config says, per tool, what the receipt file carries of each part:

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

A rule names a tool, or `"*"` for every tool without a rule of its own, and gives a side for the arguments, the result, and the facts, each with a `mode`:

- `clear`: the side in the receipt as it was.
- `digest`: the fields listed in `clear` stay, and every other top-level field is withheld together, as one commitment at `$rest`, `{ "$custody": "withheld", "sha256": "<sha256 over a random salt and the canonical object of those fields>" }`, so that not even their names appear (a field name is chosen by the agent or the upstream, like a value). The salt is not in the receipt: the issuer keeps it in `receipts/salts/<id>.json`, a private file beside the receipts that never goes to a reviewer, and nowhere else. Whoever holds the value and the salt can later show them, and the commitment proves it is the value the receipt was made over; without the salt, nobody can confirm a guess of the value against it.
- `encrypted`: the same commitment, carrying the value and its salt as well under a 32-byte key you hold, `{ "$custody": "encrypted", "alg": "A256GCM", "keyid", "iv", "ciphertext", "tag", "sha256" }`. The key is read at startup from the environment variable `captureKeyEnv` names, 64 hex characters or base64, never from the file; a rule in mode `encrypted` without it fails at startup. `keyid` is the sha256 of the key, so a reviewer knows which key reveals a value.

The rule is applied in one place, by the issuer, to the whole statement just before it is signed, so nothing it guards reaches the receipt file, the log, or an exporter in clear. Once any side is private, the receipt for that tool is: a side the rule does not set is withheld whole, field by field, and so is every other value that is not structural: the policy's error messages, a denial reason, the message of a tool that threw, the result's `_meta` (which carries whatever an upstream put there, even when the result itself is left in clear), a provider delivery's body, an upstream's signed envelope (whose payload may carry any claim the upstream chose; beside a result the rule leaves in clear, an envelope that is exactly the plain attestation for this call stays, so the signature over that public result can be checked: the three envelope fields, one signature entry of a key id and a signature, and a canonical payload naming this receipt, this tool, and this result's digest; any other field, claim, or encoding withholds it, and a verifier given the upstream's key then fails the check until the envelope is disclosed or opened with the key), the fact ids an upstream declared it served (`consumed.factIds`), a provider's signature and bind (the signature is a MAC over the withheld body: whoever holds the secret could confirm a guess of the body against it), and the session and model ids the agent's call or process supplied. Only the provider's name stays. What stays in clear is a fixed list: the receipt id, the key ids and timestamps, the tool name (a name no upstream offers is recorded as `(unknown tool)` under a private rule, since it is text the agent chose, and takes its name's rule and the wildcard together, side by side: the more private mode and only the fields both keep in clear, so a rule left for a retired name never widens what the wildcard keeps private), the grant, the digests, the decision and the ids of the policies behind it, the status, the provenance fields, a provider's name, and the note itself. The test: the issuer, the grant, or the config produced it; nothing the agent, an upstream, or a provider wrote stays in clear. A side set to `clear` stays in clear. A field added to the receipt later starts withheld, never in clear. The values outside the three sides take the rule's mode: `encrypted` as soon as any side is, so the key brings everything back, `digest` otherwise.

`clear` lists the top-level fields kept in clear, each kept whole whatever it holds (list a field only when everything it may carry is fit for a reviewer); a value that is not a plain object is withheld whole; a field literally named `$rest` is never kept in clear. On a result, `isError` stays in clear when it is the boolean status flag (anything else under that name is a value and is withheld), and `_meta` is withheld whatever the list says. The receipt's `request.args` is then `{ "amount": 2500, "customer_id": "cust_123", "$rest": { "$custody": "withheld", "sha256": "…" } }`, and the same shape holds for `execution.result` and each fact's `value`; a fact's lookup arguments are captured field by field, since their names are the fact config's. Facts are captured field by field under the `facts` side. A fact lookup's arguments follow the call's `args` side, because they are copied from the call: a fact argument stays in clear only when its template is a constant or copies a call argument the rule keeps in clear, so a field withheld from the request does not reappear as the argument of the lookup that used it. What the lookup answers follows the `facts` side, which is private unless you set it to `clear`. The same two fields work in the SDK config, where the same issuer applies the rule, so every adapter's receipts get it, a wrapped tool's thrown message included. The SDK trusts the tool name it is given, since the application chose it; the sidecar records whatever name its caller sends.

What changes is the receipt file and nothing else. The policy decides on the real values; the agent gets the real result, the real error, and the real reason; the digests and the signature are over the whole call. Under a private rule `request.argsDigest` and `execution.resultDigest` are sha256 over the full value and a salt derived from the salts of the withheld values under them, so whoever can restore those values can recompute the digest and nobody else can confirm a guess against it; a digest over values that are all in clear is unsalted, as before. A fact's `resultDigest` becomes a commitment to the lookup's full result, since the receipt shows only the selected value and the rest of that result (its metadata, its other content) is never public under a private rule, whatever the selected fields are; it is disclosed, decrypted, and checked like any withheld value. The signed statement carries one note, `capture: { "mode", "withheld": [["request", "args", "$rest"], ["execution", "result", "$rest"], ["execution", "upstream", "rawBody"], …] }`, naming every path that holds a commitment in place of its value. The note is what a verifier trusts, not the shape of the data: a path the note names must hold a commitment, or the check fails, and commitment-shaped data at a path the note does not name is ordinary data inside the digest. The receipt format stays v0.2; the fields are optional.

A reviewer verifies such a receipt three ways:

- With the receipt alone, every signature and proof checks as before. `request args digest` and `execution result digest` pass as committed, with the detail "committed, not recomputed: N value(s) withheld; give the capture key or disclose them to recompute", because the signed statement carries the digest; a captured fact gets a `fact <name> value` line, and `fact <name> args` when its arguments were withheld, saying the same; every other withheld path gets a `withheld <path>` line. With an upstream key or a provider secret and a withheld result, body, or envelope, `upstream signature not checked` passes with a note in place of the signature check.
- With the key: `agent-custody verify ... --capture-key-env AGENT_CUSTODY_CAPTURE_KEY` decrypts every encrypted value, checks each against its commitment, and recomputes the digests and the upstream's signature from the real values. A key that is not the one the values were encrypted under fails the checks, naming the key id, rather than passing them as committed.
- With a disclosure: `agent-custody verify ... --disclose disclosure.json` does the same from a file holding, at each withheld path, the real value and the salt its commitment was made with: `{ "receiptId", "request": { "args": { "$rest": { "$custody": "disclosed", "salt": "<hex>", "value": { "reason": "…" } } } }, "execution": { "result": { "$rest": { … } }, "error", "upstream": { "rawBody", "signature", "bind" } }, "policy": { "errors" }, "facts": { "<name>": { "value": { "$rest": { … } }, "args": { … }, "resultDigest" } } }`, any part of it. A disclosed `$rest` is folded back into its object before the digest is recomputed. A value without its salt cannot be checked and is refused as such. A disclosure that contradicts a commitment fails the check with the path named, a fact's value included: a reviewer cannot be handed a false policy fact. A disclosure for another receipt is refused.

`agent-custody reveal receipts/<id>.json --capture-key-env AGENT_CUSTODY_CAPTURE_KEY --issuer-key keys/gateway.pub --out disclosure.json` writes that disclosure from the key, every encrypted value decrypted and checked against its commitment, with its salt. The bundle must verify against the issuer key given, and each ciphertext is bound to its receipt and path, so a bundle someone assembled around another receipt's ciphertexts reveals nothing. The file is written owner-only and never through a symlink. A value withheld as a digest only carries nothing to reveal, and the command says which paths it could not reveal. With `--include-salts` it also writes, at each such path, the salt from the issuer's salts file beside the receipt, for whoever holds the value to add `value` beside; a file with a salt and no value does not verify, so it cannot be handed over unfinished by mistake. Hand the finished file to the reviewer with the receipt, never the salts file.

The salts file, `receipts/salts/<id>.json`, is written for the owner alone (mode 0600 in a 0700 directory) and is as sensitive as the values: with it a guess can be confirmed. In mode `digest` it is also the only copy of each salt: lose it, and nobody can disclose those values again, not even the party that holds them, since a value alone cannot be checked against its commitment; the receipt then verifies only as committed. Back the directory up with the receipts, under the same access control as the values themselves. Mode `encrypted` carries each salt inside the ciphertext and nowhere else (the salts file holds only the digest-only ones), so the key alone recovers everything; choose it when a key is easier to keep safe than a directory of files. The key must be 32 random bytes: a reviewer sees its sha256 as `keyid` in every encrypted commitment, which is harmless for a random key and an offline oracle for a key derived from a passphrase. `agent-custody prune` removes the salts and the pre-committed authorization with the receipt.

The limits. A signed human approval carries its action fields and an unsalted full-argument digest, so a private rule withholds its envelope; see [approval privacy limits](approvals.md#privacy-limits). A commitment covers a top-level field, so a field is withheld whole, not in part; put what a reviewer may see in fields of its own. An upstream's own signature covers `contentDigest`, an unsalted sha256 over `{ content, isError }` that the upstream computes, so a reviewer holding the upstream's key and a guess of the whole result can confirm the guess; the gateway cannot salt what the upstream signs. A `digest`-only value can be recomputed only by whoever holds it. A result's top-level `_meta` is withheld whatever the rule says, but a `content` item listed in `clear` is kept whole, its own item-level `_meta` or annotations included; list `content` in `clear` only when every item is fit for a reviewer. The verifier cannot tell a redacted receipt from a complete one beyond the capture note; what it establishes is that whatever is shown, disclosed, or decrypted is the value the signed digest was made over. Nothing here changes what the log receives: a remote log run with `hashOnly` gets leaf hashes, as before, and the exporters are handed the same view as the file and carry digests only. The browser verifier at agent-custody.dev/verify reports the committed case and takes no key or disclosure; use the command-line verifier for those. Tutorial 26 runs the refund above end to end.

## One gateway for many agents, over HTTP

`agent-custody gateway --config gateway.json --http --port 8790` serves the same gateway as an MCP server over Streamable HTTP at `/mcp`, and every connection presents its own grant: the delegation envelope, base64url-encoded, as `Authorization: Bearer <value>` or `X-Agent-Custody-Grant` on the initialize request. The gateway verifies it against `trustedPrincipalKeys` and its validity window, and opens a session for exactly that grant; a grant signed by a stranger, an expired one, or none at all gets 403 with the reason and no session (403 rather than 401, because MCP clients treat 401 as an OAuth challenge and hide the body). Sessions share the key, the policy, the upstreams, the log, and the fact lookups; each has its own tools (the scopes its grant names), its own receipts (its own principal and agent, attested), and its own consumed facts. `grantFile` in the config is then optional and ignored. A session ends when the client terminates it or after `--idle-minutes` (default 30) without a request; `GET /health` reports the live count and the gateway's key id. SIGINT or SIGTERM closes the gateway, so a container runtime or systemd stops it cleanly. The transport is plain HTTP: bind to loopback, a private network, or put TLS in front. From JavaScript, `grantHeader(envelope)` builds the header value; from any language it is `base64url(JSON.stringify(envelope))`. Tutorial 20 runs two agents against one gateway.

## The gateway as an A2A agent

`agent-custody gateway --config gateway.json --a2a --port 8790 --host 127.0.0.1` serves the gateway as an A2A agent itself, in front of the config's one `a2a` upstream (exactly one is required). An agent that delegates over A2A is pointed at the gateway instead of at the remote agent and needs no other change. With Google ADK:

```python
from google.adk.agents.remote_a2a_agent import RemoteA2aAgent
docs = RemoteA2aAgent(name="document_agent", agent_card="http://127.0.0.1:8790/.well-known/agent-card.json")
```

The gateway serves the remote agent's card at `/.well-known/agent-card.json` (and `/.well-known/agent.json`) with its own address as the endpoint; the card's `signatures` are dropped, since they signed a card that named another address. `POST /` takes JSON-RPC. `SendMessage` and `SendStreamingMessage` (0.3: `message/send` and `message/stream`; the 1.0 HTTP+JSON binding at `POST /message:send` and `POST /message:stream` as well) become a `<prefix>.send` call under the grant in `grantFile`, or under the grant the request presents in `Authorization: Bearer` or `X-Agent-Custody-Grant`, base64url, exactly as for `--http`; every other method, `GetTask`, `CancelTask`, the push notification configs, is forwarded to the remote agent untouched, with no receipt, but only under a grant in force: a missing, expired, or revoked grant gets `403`. An allowed delegation answers with the remote agent's task or message with `metadata["agent-custody/receipt"]` set to the receipt id, on every event of a stream too. A refused one answers a task in state `TASK_STATE_REJECTED` (0.3: `rejected`) whose status message reads `agent-custody: <reason> (receipt <id>)`, and nothing reached the remote agent; a delegation the log would not pre-commit is rejected the same way. A remote agent the gateway could not reach is a task in `TASK_STATE_FAILED`; a JSON-RPC error the remote agent answered is relayed as a JSON-RPC error with the receipt id under `error.data.receipt`, and the receipt records the call as failed. `GET /health` reports the fronted agent's name and the gateway's key id. ADK 2.x with a2a-sdk 1.x speaks A2A 1.0 and streams by default; both are handled. Tutorial 25 is the whole thing: a stand-in document agent, the gateway in front of it, an engagement agent delegating twice, one allowed and one refused because the task names a privileged matter, both receipts verified.

## Wiring it into an agent host

The gateway is an ordinary MCP server, so any host that can launch a stdio MCP server can use it. Point the host at the gateway instead of at the upstream server.

### Claude Desktop

In `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "stripe": {
      "command": "node",
      "args": ["/abs/path/agent-custody/packages/receipts/src/cli.ts", "gateway", "--config", "/abs/path/gateway.json"]
    }
  }
}
```

Claude sees only the tools inside the grant's scopes. Every call it makes produces a receipt. Denials come back as tool errors with the receipt id in the text.

### Claude Code

```bash
claude mcp add stripe -- node /abs/path/agent-custody/packages/receipts/src/cli.ts gateway --config /abs/path/gateway.json
```

### Python hosts

The gateway is language-neutral: any host that can launch a stdio MCP server can use it. Claude Agent SDK for Python:

```python
from claude_agent_sdk import ClaudeAgentOptions, query

options = ClaudeAgentOptions(mcp_servers={"stripe": {"command": "node", "args": ["/abs/path/agent-custody/packages/receipts/src/cli.ts", "gateway", "--config", "/abs/path/gateway.json"]}})
async for message in query(prompt="Refund customer cust_123 by 50 dollars", options=options):
    ...
```

OpenAI Agents SDK for Python:

```python
from agents import Agent, Runner
from agents.mcp import MCPServerStdio

async with MCPServerStdio(params={"command": "node", "args": ["/abs/path/agent-custody/packages/receipts/src/cli.ts", "gateway", "--config", "/abs/path/gateway.json"]}) as stripe:
    agent = Agent(name="support", instructions="...", mcp_servers=[stripe])
    result = await Runner.run(agent, "Refund customer cust_123 by 50 dollars")
```

With the npm package installed globally, `"command": "agent-custody", "args": ["gateway", "--config", ...]` replaces the node invocation. Every tool the agent sees comes through the gateway; denied calls never reach Stripe and still produce a receipt. For receipts from tools that are plain Python functions rather than MCP servers, use the sidecar and the Python package, in [sdk.md](sdk.md).

### Your own agent loop (TypeScript)

This is what [scripts/demo.ts](../scripts/demo.ts) does.

```ts
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const agent = new Client({ name: "my-agent", version: "1.0.0" });
await agent.connect(new StdioClientTransport({
  command: "node",
  args: ["/abs/path/agent-custody/packages/receipts/src/cli.ts", "gateway", "--config", "/abs/path/gateway.json"],
}));

const { tools } = await agent.listTools();               // only tools in the grant's scopes

const result = await agent.callTool({
  name: "stripe.refund",
  arguments: { customer_id: "cust_123", amount: 50000 },
  _meta: { "agent-custody/model": "claude-fable-5-1" },  // optional, recorded as "claimed"
});

const receiptId = result._meta?.["agent-custody/receipt"];
if (result.isError) {
  // denied by scope or policy, or upstream failed; the text says which, and a receipt exists either way
}
```

Any other MCP client works the same way: Python's `mcp` package, LangGraph's MCP adapters, or the OpenAI Agents SDK MCP support. None of them need to know the gateway is there.

## What the agent gets back

| outcome | `isError` | content | receipt |
| --- | --- | --- | --- |
| executed | as returned by upstream | upstream's content, untouched | `_meta["agent-custody/receipt"]` |
| upstream returned an error | `true` | upstream's content | same |
| denied by scope, approval, or policy | `true` | `Denied by policy: <reason> (receipt <id>)` | same |
| upstream unreachable | `true` | `Upstream error: <message> (receipt <id>)` | same |

The receipt id is the file name under `receiptsDir`.

## What the upstream gets

The call the gateway forwards carries three `_meta` keys the agent cannot set: `agent-custody/receipt`, the id of the receipt being issued for this call; `agent-custody/agent` and `agent-custody/principal`, from the signed delegation grant. An upstream that keeps state can cite the receipt as the source of what it stores and record the attested caller rather than a claimed one. The memory server in `@agent-custody/state` does exactly that. Fact lookups carry the same keys, since they are the gateway acting for the same receipt.

The forwarded call also carries `agent-custody/observed`: the values of the facts the gateway fetched for this call, by name, so an upstream can check a value the agent claims against what the gateway itself saw. The memory server's evidence check works this way.

The upstream can answer in kind. A result whose `_meta` carries `agent-custody/facts`, an array of fact ids, tells the gateway which facts it just served; the gateway remembers them for the rest of the session and every later receipt carries them as `consumed`, labelled `observed` because the gateway saw those results itself. That is what the agent had been shown by the time of each call, an upper bound on what it relied on, and it is what the state package's blast-radius query walks.

## Operational notes

- **Money is integer minor units.** Cedar has no floating point. A float in `args` that a policy touches is an evaluation error, which is a deny.
- **The gateway key is the trust root for receipts.** Keep it out of the agent's reach. The upstream credentials in `upstream.env` are likewise never exposed to the agent.
- **Rotate keys by adding, not replacing.** The verifier accepts a list of gateway keys and principal keys and matches by keyid, so old receipts stay verifiable.
- **Evidence before the side effect, for the calls that matter.** Without `precommit`, a call is forwarded and then logged, and a log outage at that moment leaves an executed action whose receipt waits in the outbox until the log takes it (the agent gets the real result, marked `log-pending`). With `precommit`, the authorization is logged first and the call is withheld if that fails. The receipt of a withheld call shows `allow` next to `withheld`, so an auditor can tell a log outage from a denial.
- **The log is append-only by convention, not enforcement.** Copy it somewhere the operator cannot rewrite, on a schedule. The receipts' tree heads let an auditor check that the copy matches.
- **stdout is the MCP channel.** Anything the gateway prints goes to stderr. Do not add `console.log` to gateway code paths.
