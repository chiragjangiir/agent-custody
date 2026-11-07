# agent-custody

Chain of custody for AI agents: a signed receipt for every tool call, checkable with public keys alone. What each check proves, and against whom, is [a table below](#what-a-receipt-proves-and-what-it-does-not).

Three producers, one receipt format, one verifier.

- **The gateway** is an MCP proxy between an agent and the systems it can affect: MCP servers, REST APIs described as tools, and other agents it delegates to over A2A. For every tool call, allowed or denied, it checks a delegation grant signed by the human principal and any required human approval of the exact arguments, gathers the facts the policy needs by calling upstream itself, evaluates a Cedar or Rego policy that fails closed (Rego from a file or from your own OPA server), forwards the call only on allow, and emits a signed receipt appended to a Merkle transparency log.
- **The door** is the gateway turned around: a reverse proxy in front of your own website, API, or forms. Every arrival, a browser, an API client, a crawler, or an agent, is classified by what it presented (a grant signed by a principal you trust makes it `verified`; an assertion the door cannot check is `claimed`; nothing is `unknown`), decided by a Cedar policy for its route, relayed or refused, and receipted either way with the same receipt. It is the first piece of an agent front door; it does not yet detect agents in web traffic, and says so ([the door](docs/door.md)).
- **The SDK** is an interceptor inside the agent's own process, hooked into the framework's tool-call callbacks: Claude Code, the Claude Agent SDK, the OpenAI Agents SDK, the Vercel AI SDK, OpenClaw, DeepSeek Harness, Hermes, Google ADK, LangChain, or any function you wrap. It reaches everything the gateway cannot see and issues the same receipts, labelled as self-reported.

Anyone holding the public keys can verify a receipt offline. The agent is not trusted. The layer around it is, and the receipt says exactly how far that trust extends, starting with who issued it. What the receipt file carries of a call is a choice per tool: a field can be withheld as a commitment or encrypted under your key, and the verifier recomputes the digests when it is shown the values.

- [Reference](https://docs.agent-custody.dev/reference/): every function, endpoint, MCP tool, and command with its request and response
- [Tutorials](docs/tutorials.md): runnable examples, one per aspect of the code, all executed by the test suite
- [The door](docs/door.md): a receipted reverse proxy in front of your own site or API; what it knows about an arrival, how an arrival becomes a Cedar request, what the arrival gets back, and what it does not do yet
- [Financial operations](docs/financial-operations.md): durable operation ids, provider idempotency keys, atomic daily budget reservations, and reconciliation receipts for uncertain outcomes
- [The gateway console](docs/console.md): an admin service for the person who runs a gateway: config, tools, receipts with a verdict each, a policy editor that replays recorded calls before it saves, grant revocation, and an audit trail
- [Configuring the gateway](docs/configuration.md): who may use which tools and where the tools live, a worked example with two agents, the Docker image, and `agent-custody check` to validate a config before it starts
- [Usage guide](docs/usage.md): gateway setup, wiring into Claude Desktop, Claude Code, or your own agent loop, and the gateway as an A2A agent between agents that delegate to each other, private evidence: what the receipt file carries of each call, and searching receipts and exporting offline cases with the state package's review console
- [Live Codex recovery demo](docs/codex-recovery.md): a real support agent, incorrect CRM memory, operator-reviewed compensation, and verified receipts; an opt-in live run with offline regression coverage
- [Human approvals](docs/approvals.md): short-lived signatures over the exact action, two-person thresholds, single-use enforcement, and offline verification
- [The interceptor SDK](docs/sdk.md): Claude Code hooks, the Claude Agent SDK, adapters for the OpenAI Agents SDK, Vercel AI SDK, LangChain, OpenClaw and DeepSeek Harness, a Hermes Agent plugin and Google ADK callbacks through the Python package, and wrapping tool functions in anything else
- [Writing policies](docs/policies.md): how a tool call becomes a Cedar request or Rego input, with tested examples, a Rego file against an OPA server, and replaying history against a proposed policy with `policy simulate`
- [Verifying a receipt](docs/verification.md): what each check means and what a verified receipt does and does not prove
- [What the evidence satisfies](docs/compliance.md): the receipts, packs, and certificates mapped to SOC 2, ISO 27001, UK GDPR, the EU AI Act, FINRA, MAS, Colorado, DORA, the CSA AI Controls Matrix, the OWASP agentic guidance, and ISO/IEC 42001. Each regulation has a primary source, an "as of" date, and a list of what a receipt does not supply
- [Anchoring the log on a chain](docs/anchoring.md): the log's checkpoints committed to Ethereum mainnet, or another EVM chain the installation picks, from a published address, what that proves and what it does not, running the anchor, and `log-check` against the chain
- [Receipts on a pull request](docs/github-action.md): the GitHub Action that verifies a directory of receipt bundles and posts one table on the pull request, the workflow file to copy, the `export` command that copies the receipts into the branch, and why a committed receipt publishes the call unless a capture rule withholds it
- [Completeness](docs/completeness.md): an auditor's read-only key lists the provider's objects and matches each to a verified receipt, so an action taken outside the gateway shows up
- [Payment mandates and agent identity](docs/mandates.md): the design for fitting grants and receipts to Google's AP2 mandates, Visa's Trusted Agent Protocol and Mastercard Agent Pay; not yet built
- [Threat model](docs/threat-model.md): every party who could make a receipt false, the move, what stops it, and whether that is a property of the evidence or of the deployment; and what is not defended
- [Aligning with IETF SCITT](docs/scitt.md): the receipt as a SCITT signed statement, the log as a transparency service, our RFC 9162 proofs as COSE Receipts (RFC 9942), what differs and the options for each, an agent-action profile, and the steps toward the working group

## Getting started

```bash
npm install @agent-custody/receipts        # or bun add, pnpm add
```

Published on npm as [`@agent-custody/receipts`](https://www.npmjs.com/package/@agent-custody/receipts): compiled JavaScript with type declarations, Node 22 or later, Apache-2.0.

Record receipts from inside your own agent, no gateway needed. Generate a signing key, point a config at it, wrap the functions the agent calls:

```bash
npx @agent-custody/receipts keygen --dir keys --name app
```

```json
{ "agentId": "billing-bot", "identity": { "keyFile": "keys/app.key" }, "receiptsDir": "receipts", "logFile": "log.jsonl" }
```

```ts
import { createSdkIssuer, loadSdkConfig, loadPublicKey, verifyBundle } from "@agent-custody/receipts";

const issuer = createSdkIssuer(loadSdkConfig("./sdk.json"));
const refund = issuer.wrap("stripe.refund", async (args: { amount: number }) => stripe.refund(args));
await refund({ amount: 5000 });                 // one signed receipt in receipts/, one leaf in log.jsonl

const bundle = JSON.parse(readFileSync("receipts/<id>.json", "utf8"));
verifyBundle(bundle, { issuerKeys: [loadPublicKey("keys/app.pub")], logFile: "log.jsonl" }).ok;   // true
```

For your own Claude Code sessions, one command does the whole setup (key, config in observe mode, starter deny policy, hooks), and `agent-custody report` lists the calls the policy would have denied: `npm install -g @agent-custody/receipts`, then `agent-custody init claude-code`, then see [docs/sdk.md](docs/sdk.md#claude-code).

Framework hooks and adapters, including Claude Code, the OpenAI Agents SDK, the Vercel AI SDK, LangChain, OpenClaw, DeepSeek Harness, Hermes and Google ADK, are in [docs/sdk.md](docs/sdk.md). To enforce rather than record, put the gateway between the agent and its tools: `npx @agent-custody/receipts gateway --config gateway.json`, set up in [docs/usage.md](docs/usage.md); between an agent and the agents it delegates to over A2A, `--a2a` serves the gateway as an A2A agent itself. The gateway is listed in the [MCP Registry](https://registry.modelcontextprotocol.io/) as `io.github.svayatta/agent-custody`; its entry is [server.json](server.json), published after each npm release by running the `mcp-registry` workflow from the Actions tab (GitHub OIDC, no token).

## How it fits together

The [architecture guide](../../site/guide/architecture.md) adds the customer-side and hosted split, the data model, and sequence diagrams for onboarding, revocation, and verification.

```mermaid
flowchart LR
    P["Principal<br/>(human or org, holds a signing key)"]
    A["Agent host<br/>Claude Desktop, Claude Code,<br/>LangGraph, custom loop"]
    S["SDK interceptor<br/>inside the agent process:<br/>hooks or wrapped tools"]
    G["agent-custody gateway<br/>scope check → fact lookups → Cedar policy"]
    U["Upstream MCP server<br/>Stripe, database, GitHub, ..."]
    R[("receipt bundles<br/>receipts/*.json")]
    L[("Merkle log<br/>local file, or a remote log<br/>run by someone else")]
    V["Verifier<br/>auditor, counterparty, CI job"]
    O["Observability<br/>OTel, Splunk, LangSmith, Arize"]

    P -- "signed delegation grant" --> G
    A -- "MCP tools/call" --> G
    G -- "only on allow" --> U
    U -- "result" --> G
    G -- "result + receipt id, or denial + receipt id" --> A
    G -- "signed receipt (issuer: gateway)" --> R
    G -- "leaf hash" --> L
    A -. "in-process tool calls" .-> S
    S -- "signed receipt (issuer: sdk)" --> R
    S -- "leaf hash" --> L
    R --> V
    L -. "copy of the log (optional)" .-> V
    P -. "public key" .-> V
    G -. "public key" .-> V
    A -. "traces (unchanged)" .-> O
    G -. "one span per receipt, OTLP" .-> O
    S -. "one span per receipt, OTLP" .-> O
```

Three parties hold keys. The **principal** signs a grant saying which agent may use which tools until when. The **issuer**, gateway or SDK, signs every receipt and every tree head. The **verifier** holds only public keys and needs no access to the issuer, the agent, or the upstream system.

## Three producers, one receipt

| | gateway | door | SDK |
| --- | --- | --- | --- |
| where it runs | separate process between agent and tools | separate process between the world and your own site or API | inside the agent's process |
| what it sees | MCP tool calls | every HTTP arrival, by route | whatever the framework's hooks expose |
| enforcement | yes, denied calls never reach upstream | yes, refused arrivals never reach the origin | only where a hook can block |
| provenance of its fields | `attested` and `observed` | `observed`; `attested` only when the arrival presented a grant, else `claimed` | `claimed`, all of them |
| what a verifier learns | the agent could not skip or forge this | the arrival could not skip or forge this; who it was is proven only with a grant | the agent's process reported this and it has not changed since |
| install | one line in the host's MCP config | a reverse proxy in front of the origin | a hook entry or a wrapped function |

Every receipt names its issuer, and the verifier prints what that issuer kind is worth before anything else. A dashboard full of `sdk` rows is the reason to route the consequential calls through the gateway. The door is the gateway turned around ([the door](docs/door.md)).

### Supported hosts and frameworks

| host or framework | producer | enforce + record | record only | tested against |
| --- | --- | --- | --- | --- |
| any MCP host: Claude Desktop, Claude Code, Cursor, custom | gateway | yes | | a real MCP client and upstream over stdio |
| Codex CLI (headless) | gateway | yes | | a manual `codex exec` run and offline MCP recovery checks; [guide](docs/codex-recovery.md) |
| Claude Code | SDK | `hook` command, PreToolUse deny; `init claude-code` sets it up | PostToolUse | the documented hook contract, via stdin; `init` and `report` against a temporary home |
| Claude Agent SDK | SDK | `claudeAgentHooks` | same | the same handler |
| OpenAI Agents SDK (JS) | SDK | `wrapTools` | `observeRunner` | a real `Runner` with a scripted model |
| Vercel AI SDK | SDK | `wrapTools` | | a real `generateText` loop over the SDK's mock model |
| LangChain / LangGraph (JS) | SDK | `tool(issuer.wrap(fn))` | `ReceiptCallbackHandler` | real `StructuredTool` invocations |
| OpenClaw | SDK | `registerOpenClaw` / `openclawHooks`: `before_tool_call` deny | `after_tool_call` | OpenClaw's documented hook contract, in the plugin's process |
| DeepSeek Harness | SDK | the module is the plugin: `tools/pre-execute` deny | `tools/post-execute` | the harness's tool waterfall types, driven as the harness drives them |
| Hermes Agent | sidecar + [Python package](../python/README.md) | `agent_custody.hermes`: `pre_tool_call` block | `post_tool_call` | the documented hook contract, against a live sidecar |
| Google ADK | sidecar + [Python package](../python/README.md) | `adk_callbacks`: `before_tool_callback` skips | `after_tool_callback` | the real package, ADK's runner with a scripted model |
| anything else | SDK | `issuer.wrap(name, fn)` | `issuer.record` | plain functions |
| Python: LangChain, OpenAI Agents SDK, CrewAI, Claude Agent SDK | sidecar + [Python package](../python/README.md) | `wrap_tools` (OpenAI Agents, CrewAI), `claude_hook` PreToolUse deny, `client.wrap` | `ReceiptCallbackHandler` | the real Python packages, receipts checked by this verifier |
| Go, Java, Rust, any language with HTTP | sidecar | decide then record | record | [examples/languages](examples/languages), each run against a live sidecar |
| any MCP host in any language: Claude Agent SDK Python, OpenAI Agents Python | gateway | yes | | the gateway is an MCP server; [usage.md](docs/usage.md#python-hosts) |
| any REST API, as tools the agent reaches through the gateway | gateway, `rest` upstream | yes | | a stand-in HTTP API; [usage.md](docs/usage.md#setup-step-by-step) |
| any agent reached over A2A (Google ADK `RemoteA2aAgent`, or any A2A client) | gateway, `a2a` upstream and `gateway --a2a` | yes | | stand-in A2A agents in both wire formats; ADK's own `to_a2a` and `RemoteA2aAgent` in the Python suite; [usage.md](docs/usage.md#the-gateway-as-an-a2a-agent) |

The framework packages, `pg`, and `@node-saml/node-saml` (for SAML sign-in to the portal) are optional peer dependencies. Each adapter imports only from its own package.

## One tool call, end to end

```mermaid
sequenceDiagram
    participant Agent
    participant Gateway
    participant Upstream as Upstream MCP server
    participant Log as Merkle log

    Agent->>Gateway: tools/call stripe.refund {customer_id, amount}
    Gateway->>Gateway: tool in signed grant's scopes?
    Gateway->>Upstream: tools/call customer.lookup {customer_id}
    Upstream-->>Gateway: {verified: true}
    Note over Gateway: facts.customer = that result, labelled "observed"
    Gateway->>Gateway: Cedar: permit if amount ≤ limit and facts.customer.verified
    alt allow
        Gateway->>Upstream: tools/call stripe.refund {customer_id, amount}
        Upstream-->>Gateway: {refund_id, status}
    else deny
        Note over Gateway: no upstream call is made
    end
    Gateway->>Gateway: build in-toto statement, sign (DSSE, Ed25519)
    Gateway->>Log: append canonical envelope
    Log-->>Gateway: leaf index, inclusion proof, root
    Gateway->>Gateway: sign tree head, write bundle to receipts/
    Gateway-->>Agent: result or denial, _meta["agent-custody/receipt"] = id
```

Denied calls get receipts too. "The agent tried to pay out funds and was refused" is evidence worth keeping.

## Anatomy of a receipt bundle

```mermaid
flowchart TB
    B["receipt bundle (one JSON file)"]
    B --> E["envelope: DSSE, signed by gateway key"]
    B --> T["treeHead: DSSE, signed by gateway key<br/>{treeSize, rootHash, timestamp}"]
    B --> I["inclusion: {leafIndex, treeSize, hashes[]}"]
    E --> S["in-toto Statement v1"]
    S --> SU["subject: tool-call:&lt;tool&gt;:&lt;id&gt;<br/>digest = sha256(args)"]
    S --> PR["predicate"]
    PR --> P0["issuer: gateway or sdk, keyid, framework"]
    PR --> P1["principal, agent, delegation<br/><b>attested</b>: signed by principal key (gateway)"]
    PR --> P2["tool, facts, policy decision, execution<br/><b>observed</b>: gateway obtained it (gateway)"]
    PR --> P3["args, model id, session<br/><b>claimed</b>: agent-supplied, unchecked (both)<br/>every field, when issued by the sdk"]
```

Every field carries a provenance label. This is the design decision that matters most, and it is what a verifier reads back.

| provenance | meaning | today's examples |
| --- | --- | --- |
| `attested` | signed by a key other than the issuer's | principal id, agent id, the delegation grant (gateway receipts) |
| `observed` | the issuer obtained it deterministically, outside the agent's control | upstream tool results, fact lookups, the policy decision, execution status (gateway receipts) |
| `claimed` | originated from the agent, the model, or the agent's own process, no independent check | tool arguments, the model id, session ids, and every field of an SDK receipt |

## Quick start

```bash
bun install                              # from the repository root, once for the workspace
cd packages/receipts
node scripts/demo.ts                     # gateway: keys, grant, policy, four tool calls, verification, a tampering attempt; then the SDK wrapping the same tool
node examples/01-keys-and-signing.ts     # first of the step-by-step examples, see docs/tutorials.md
bun run test                             # this package; `bun run test` at the root runs every package
```

Everything runs on plain Node 22 or later. No build step, no `npx`, no `tsx` needed on the command line.

The demo leaves everything in `demo-out/`, including receipts from both producers. Verify a receipt by hand:

```bash
node src/cli.ts verify demo-out/receipts/<id>.json \
  --issuer-key demo-out/keys/gateway.pub \
  --principal-key demo-out/keys/principal.pub \
  --log demo-out/log.jsonl
```

Exit code 0 means every check passed. See [docs/verification.md](docs/verification.md) for what the report means.

To issue receipts from your own agent code, without a gateway:

```ts
import { loadSdkConfig } from "./src/config.ts";
import { createSdkIssuer } from "./src/sdk/index.ts";

const issuer = createSdkIssuer(loadSdkConfig("./sdk.json"));
const refund = issuer.wrap("stripe.refund", async (args: { amount: number }) => stripe.refund(args));
```

[docs/sdk.md](docs/sdk.md) has the config file and the per-framework adapters.

## What a receipt proves, and what it does not

| claim | verifier | adversary | mechanism | status |
| --- | --- | --- | --- | --- |
| receipt was not altered after issue | anyone | later editor | DSSE signature over canonical JSON | done |
| receipt was issued in sequence, none removed | auditor with a log copy | operator rewriting history | Merkle inclusion proof + recomputed root | done |
| the principal really delegated this scope to this agent | anyone with the principal's key | operator, agent | grant signed by principal key, checked for scope and validity window | done |
| the policy decision was made against this exact policy | anyone | operator swapping policies | sha256 of policy text in the receipt | done |
| facts the policy relied on were not asserted by the agent | anyone reading the receipt | agent | facts fetched by the gateway, recorded with their own digests, labelled `observed` | done |
| the side effect was committed to the log before it happened | anyone with a log copy | operator, log outage | for tools in `precommit`, or every tool under `strict`, a signed authorization logged first, embedded in the receipt with its leaf position, checked to precede the receipt | done |
| the upstream system actually executed the action | anyone with the upstream's key or the provider's secret | operator | the upstream signs its result for the receipt, or the provider's own delivery signature (Stripe, GitHub) is embedded and checked | done, for upstreams that sign |
| the operator itself cannot mint a false receipt | regulator, counterparty | operator | needs a TEE gateway with an attested build ([#179](https://github.com/svayatta/agent-custody/issues/179)), and the provider's own records to catch actions outside the gateway ([#178](https://github.com/svayatta/agent-custody/issues/178)) | **not done** |
| which model produced the call | anyone | operator | no hosted provider signs model identity | **not possible today**, labelled `claimed` |
| an SDK receipt reflects what the tool really did | anyone | agent's own process | none; the SDK shares a process with the agent | **by design not claimed**; issuer kind `sdk` says so |

If a vendor tells you their receipts prove more than the first five rows, ask them which key signed it.

## Layout

```
src/config.ts      gateway and SDK config schemas, path resolution
src/crypto.ts      canonical JSON, sha256, Ed25519 keys, DSSE sign/verify
src/log.ts         Merkle log: append, root, inclusion and consistency proofs, verify, JSONL persistence; a lock file makes an append safe when several processes share one log file, and a partial last line from a killed writer is moved to `<file>.torn`
src/lock.ts        the one lock file design (owner token, liveness check, rename to break a stale lock) that the local log, prune, and the gateway outbox share
src/log-check.ts   the outside monitor: verifies the head, checkpoints, witness, and anchor of a running log
src/portal.ts      the tenant portal: register, first key, usage against plan, keys, Stripe billing, export, member roles, TOTP MFA, single sign-on, on the log's Postgres
src/sso.ts         enterprise sign-in for the portal: OIDC (code and PKCE, id_token checked against the IdP's key set) and SAML 2.0 (signed assertions only, through @node-saml/node-saml)
src/log-export.ts  a tenant's export of their own log, self-checked, as a log file the verifier reads
src/witness.ts     the witness: countersigns the log's checkpoints from another operator's machine, or refuses with an alarm
src/anchor.ts      the anchor: commits a Merkle root over new checkpoints to a chain, or refuses with an alarm; checks a record against JSON-RPC
src/anchor-evm.ts  the anchor's transactions on Ethereum or another EVM chain, through the optional dependency viem
src/completeness.ts  completeness from the provider's side: the provider's own list, matched against verified receipts
src/pr-summary.ts  `verify --markdown`: a directory of bundles verified into one Markdown table, for the GitHub Action
src/export.ts      `export`: verified receipt bundles that keep their values private, copied byte for byte into a directory for a pull request
src/signer.ts      the signer: the log's key in its own process, the key document verifiers fetch
src/checkpoints.ts signed heads published on a schedule, to files and to Postgres
src/log-store.ts   the log server's backends: the file, and Postgres with tenants, hashed tokens, one writer per tenant, rate limits
src/log-sink.ts    where leaves go: the local file, or a remote log over HTTP; plus the reference log server
src/policy.ts      Cedar evaluation wrapper, fail-closed
src/policy-rego.ts Rego: compiled with opa build, evaluated in-process with the OPA WebAssembly SDK, fail-closed
src/opa-server.ts  an OPA server's Data API as the policy, with bundle revisions as the digest
src/simulate.ts    replay recorded policy decisions against a proposed Cedar or Rego policy, grouped changes and run digest
src/delegation.ts  signed delegation grants
src/approval.ts    exact-action human approvals, distinct trusted signatures, persistent single-use consumption
src/receipt.ts     receipt and authorization statement types and provenance labels
src/issue.ts       sign, log, and write a receipt, or commit an authorization first; shared by every producer
src/gateway.ts     the MCP proxy: a host (key, policy, upstreams, log) and a session per grant; scope check, facts, policy, forward, receipt
src/operations.ts  SQLite operation claims and daily budget reservations, retained across retries and process crashes
src/gateway-http.ts the gateway over Streamable HTTP: one process, a session per connection, each under the grant it presents
src/door.ts        the door: a reverse proxy in front of your own HTTP surface; every arrival classified, decided per route, relayed or refused, receipted as issuer kind door
src/sdk/index.ts   the interceptor: policy decision, record, wrap(tool fn)
src/sdk/claude.ts  Claude Code command hook and Claude Agent SDK in-process hooks
src/sdk/openai-agents.ts, vercel-ai.ts, langchain.ts   framework adapters, tested against the real packages
src/sidecar.ts     the SDK issuer behind a local HTTP API, for agents in other languages
src/otel.ts        OpenTelemetry export: one OTLP/HTTP span per receipt, after the receipt, no SDK dependency
src/splunk.ts      Splunk export: one HTTP Event Collector event per receipt, token from the environment, beside or instead of otel
src/rest.ts        the REST connector: an HTTP API described as tools, standing where an MCP upstream stands
src/a2a.ts         agents delegating to agents: a remote A2A agent as an upstream, and the gateway serving A2A itself in front of it
src/upstream.ts    attested execution: an upstream signs its result for the receipt; the verifier checks it with the upstream key
src/capture.ts     private evidence: per-tool capture rules applied by the issuer to the whole statement, withheld values as salted commitments or encrypted under the customer's key, restore and reveal
vectors/           conformance vectors: receipts, keys, logs, proofs, and expected verdicts; `bun run vectors` regenerates them
src/verify.ts      offline verification, the human-readable report, and the audit that a later log extends an earlier one
src/claude-init.ts `init claude-code`: the agent key, the observe-mode config, the starter policy, and the three hooks merged into the settings file with absolute paths
src/deny-report.ts `report`: verifies the receipts of an SDK config and lists the calls the policy would have denied
templates/         the starter Cedar policy that `init claude-code` copies (shipped in the package)
src/cli.ts         keygen, grant, gateway, door, init, report, hook, serve, log, prune, verify, reveal, audit, policy simulate
src/retention.ts   pruning the log: leaves become their hashes, bundles are removed, proofs survive
src/index.ts       the package's public surface; adapters are exported on ./sdk/<framework> subpaths
tsconfig.build.json  emits dist/ (JavaScript plus declarations) for consumers; the repo itself runs the .ts directly
scripts/           fake Stripe upstream (signs its results with --key), a second fake upstream, fixture builders for gateway, SDK, and door (with a stand-in origin), the replay builder (`replay.ts`: example 27 and state example 07 as a folder of receipts and public keys anyone can verify with the published packages), demo
examples/          runnable tutorials, plus examples/languages/: Python, Go, Java, and Rust clients of the sidecar, run by the test suite, one per aspect; each is run by the test suite
test/              unit tests per module, end-to-end gateway test, SDK and hook tests,
                   adapter tests against the real packages, and a test that runs every policy in docs/policies.md
docs/              tutorials, usage (gateway), codex-recovery (live demo), approvals, sdk, policies, verification
```

## Plan

The design is three producers feeding one verifier. The SDK is the top of the funnel: cheap to install, wide reach, honest about being self-reported. The gateway is what a security or compliance owner mandates for consequential actions. The door turns the gateway around, in front of the business's own surface. All three exist; the work is widening each, and the door's next steps are detection signals with published error rates, standards-based passports (RFC 9421, AP2), and a challenge branch.

**Done**

- An incident replay: `node examples/38-incident-replay.ts` plays a Claude Code session against the starter deny set in enforce mode. `terraform destroy` and `rm -rf ~` are denied before they run, and the denial receipts verify offline with the public key only. The site page [An incident replay](../../site/guide/incident-replay.md) shows the output and the limit: a credential in the agent's environment goes around the hook (tutorial 38).
- One command for Claude Code (issue #204): `agent-custody init claude-code` makes the agent key, writes `sdk.json` in observe mode with no log, writes a starter deny policy, and merges the three hooks into `.claude/settings.local.json` or `~/.claude/settings.json` with absolute paths, safe to run two times. `agent-custody report` verifies the receipts and prints the calls the policy would have denied, with the reason, the rule, and the receipt id; removing the `mode` line enforces. The default local log takes a lock for each append, so hooks that run at the same time keep one log; `--log-url` needs `--log-key`; a second run keeps the pinned log key and warns about log flags it does not apply; `init` warns when git does not ignore the project settings file ([sdk.md](docs/sdk.md#claude-code), tutorial 36).
- `agent-custody export`: copies the receipt bundles of a session into a directory for a pull request, byte for byte. It verifies each receipt against the issuer key, refuses one that carries plain arguments, results, or facts (unless `--allow-clear`), reads only `<id>.json` at the top level (never `salts/`, `outbox/`, or `*.authorization.json`), and keeps only the receipts issued at or after `--since`; [guide](docs/github-action.md), tutorial 39.
- A GitHub Action (`action.yml` at the repository root) that runs `verify --markdown` on a directory of receipt bundles, posts one table as a pull request comment that it edits on each push, writes the same table to the job summary, and fails when a receipt does not verify or none exists; [guide](docs/github-action.md). [Issue #205](https://github.com/svayatta/agent-custody/issues/205).
- The door, step one of the agent front door: `agent-custody door` is a reverse proxy in front of a business's own site or API. Every arrival is classified by what it presented (`verified` by a grant from a trusted principal in scope for its route, `claimed`, or `unknown`), decided by the Cedar policy for its route with the door's own arrival fact in context (the Cedar principal is a verified agent or `unknown`, never a declared name), committed to the log before any request that can change something is relayed, relayed to the origin or refused with 403, and receipted either way as issuer kind `door`; both verifiers, the Python verifier, and `policy simulate` accept the receipts, and five conformance vectors pin them. It does not yet detect agents in web traffic, check HTTP message signatures, or challenge a human ([the door](docs/door.md), tutorial 40).
- Strict mode: `"strict": true` refuses a local log, a log that is not hash-only, and a log without pinned keys; precommits every tool, in observe mode too; and turns the outbox off. No call the agent makes is forwarded before its authorization is in a log the operator does not run, every receipt says `issuer.strict`, and `verify --require-strict` requires it ([usage](docs/usage.md#strict-mode), tutorial 34). [Issue #177](https://github.com/svayatta/agent-custody/issues/177).
- Policy reload: the gateway re-reads `policy.cedar` whenever it changes and applies it from the next call, with no restart and no dropped session; a policy that does not parse is refused and the one in force stays, and every change or refusal is recorded in `receipts/policy-reloads.jsonl` ([usage](docs/usage.md)).
- Live Codex support recovery demo: model-selected MCP calls, incorrect CRM memory, a reviewed recovery plan, simulated credit compensation, and verified evidence; [guide](docs/codex-recovery.md), with offline regression coverage.
- Payload-bound human approvals: short-lived signatures over the principal, agent, tool, full arguments, amount, currency, and beneficiary; configurable one- or two-key thresholds, enforced even in observe mode, a configurable lifetime cap, persistent atomic single-use consumption before forwarding, and independent approval-key verification. [Guide](docs/approvals.md), tutorial 30.
- Gateway: MCP proxy, signed delegation, gateway-fetched facts, Cedar policy, denial receipts, Merkle log, offline verifier.
- Receipt schema carries the issuer kind, so a verifier reads gateway versus SDK before anything else.
- SDK core: policy decision, record, and a generic `wrap(tool, fn)` for any framework whose tools are functions.
- Claude Code command hook for PreToolUse, PostToolUse, and PostToolUseFailure, with blocking on deny.
- Claude Agent SDK in-process hooks over the same handler.
- Provider-native deliveries: an upstream wrapping Stripe or GitHub attaches the signed webhook or delivery for the call; a verifier with the shared secret checks the HMAC, the timestamp, and the binding to the result, and reports the execution as attested by shared secret.
- Logarithmic appends: the Merkle log caches complete subtrees, so issuing a receipt costs the same at the millionth leaf as at the first; measured at 0.15 ms per receipt and about half a millisecond per gateway call including policy, a fact lookup, and the upstream signature. A remote log adds one network round trip plus about five milliseconds of server work per call, two for a pre-committed call; the [deployment guide](https://agent-custody.dev/guide/deployment) has the measurements against the live log.
- Retention on the log: `prune` replaces leaves older than a cutoff with their hashes and removes their bundles, so proofs still verify and the content is gone.
- Several upstreams under one gateway and one grant, each tool owned by exactly one, with the receipt naming which served the call; consumed facts flow across them.
- Attested execution: an upstream that holds a key signs its result for the receipt, the gateway embeds it, and a verifier given the upstream key reports the execution as attested rather than observed. The memory server and the demo upstream sign.
- HTTP upstreams: the gateway reaches an already-running MCP server over Streamable HTTP with a bearer token from the environment, as well as spawning one over stdio.
- Optional fact lookups: a lookup that references a call argument the call does not carry is skipped rather than denying, so policy can see the fact a write is about to supersede without refusing writes that supersede nothing.
- Consumed facts: an upstream declares the facts it served in its result `_meta`, and every later gateway receipt in the session carries those ids as `consumed`, observed, so what the agent had been shown before each call is on the record.
- The forwarded call carries the receipt id and the attested agent and principal in `_meta`, so a stateful upstream can cite the receipt; the memory server in `@agent-custody/state` runs this way.
- Conformance vectors, generated by the test suite and published with the spec, and a browser verifier on agent-custody.dev that passes all of them.
- Sidecar: the SDK issuer behind a local HTTP API (`serve`), with a Python package on PyPI-ready footing and Go, Java, and Rust clients, so agents in any language get the same receipts from one signing implementation.
- Consistency proofs between tree heads (RFC 9162), served by the log and checked by the `audit` command, so an auditor holding an old tree head can prove nothing before it was rewritten.
- Remote log: the issuer can append to a log run by someone else over HTTP, whose key then signs the tree heads, so a verifier learns the receipt was in a log the operator could not rewrite. Includes the reference log server, bearer-token auth, and a root endpoint for auditors.
- Framework adapters, each tested against the real package with a scripted model and no network: OpenAI Agents SDK (`wrapTools` enforces, `observeRunner` records from lifecycle events), Vercel AI SDK (`wrapTools` over a real `generateText` loop), LangChain (`ReceiptCallbackHandler` records, `issuer.wrap` enforces).

- Plans and the tenant portal: every tenant is on a plan (free, ten thousand appends a month; team, a million; enterprise, no allowance) enforced at append with a clear 429; the portal at the operator's `PORTAL_HOST` lets a team register, get its tenant and first key, watch usage against the plan, mint and revoke keys, buy the team plan through Stripe, and copy the export command, with every action in the audit trail.
- An audit trail of administrative actions: every tenant created or disabled and every token minted or revoked is recorded with who did it, from the admin page or the command line, shown on the page and carried in the tenant's export.
- A tenant's export: `log-export` takes, with the tenant's own token, every leaf hash, the signed head, the published keys, the checkpoints, and their usage, checks that they add up, and writes a log copy the verifier reads offline; the evidence never depends on the operator staying in business.
- Monitoring and metering: `log-check`, the outside probe that verifies the head, the checkpoints, and the witness and exits 1 on trouble, run every ten minutes by the `monitor` workflow; `GET /health`; and usage per tenant per month on the admin page and as CSV.
- The witness: a second signer on a machine the log's operator does not control countersigns each checkpoint after proving it extends the last one it signed, refuses a rewritten or forked history with an alarm, and publishes its key; `audit --witness-url` requires it. Phase 6 of [issue #6](https://github.com/svayatta/agent-custody/issues/6).
- The signer, keys, and checkpoints: the key in its own process (`signer`, `--signer-url`), the key document at `/.well-known/agent-custody-log.json` fetched and pinned by `verify --log-url` and `audit --log-url`, and signed checkpoints per log published to a directory and a table for a verifier who was not watching. Phase 3 of [issue #6](https://github.com/svayatta/agent-custody/issues/6).
- The log over Postgres: `log --db-env`, leaves as hashes in one table keyed by tenant, one writer per tenant by advisory lock, tenants and hashed tokens in tables managed by `log-admin`, rate limits and a body cap, retries in the sink, and `import` for an existing file log. Phase 2 of [issue #6](https://github.com/svayatta/agent-custody/issues/6).
- A log for someone else: `hashOnly` sends leaf hashes so the log never holds a receipt; the reference server runs several tenant logs at `/t/<tenant>/` with their own tokens and ids; tree heads name their log and the verifier checks it with `--log-id`. Phase 1 of the hosted log, [issue #6](https://github.com/svayatta/agent-custody/issues/6).
- OpenTelemetry export: with `otel` in either config, every receipt is also one span at the collector the team already runs, trace id equal to the receipt id, attributes for tool, agent, principal, status, decision, and log position; after the receipt, best effort, never on the evidence path. A reconciliation receipt is marked and carries no policy decision, so a dashboard never counts it as a second allowed call.
- Delegation chains for sub-agents: a grant that names the agent's key lets it delegate a narrower grant, with the parent embedded, up to three deep; the verifier and the gateway walk the chain to the principal, refusing any link that escalates scope, widens the window, changes the principal, or is signed by the wrong key; the receipt names the sub-agent and the principal and carries the chain. Pinned by the `gateway-chain-*` vectors and mirrored in the browser verifier.
- One gateway for many agents: `gateway --http` serves the gateway over Streamable HTTP, one session per connection under the grant that connection presents, sessions sharing the upstreams and the policy and nothing else; a platform team runs one gateway in front of the tools instead of one process per agent.
- Splunk export: with `splunk` in either config, every receipt is also one event at the HTTP Event Collector, with the receipt id, tool, agent, principal, status, decision, and log position as searchable fields and the token from the environment; the same best-effort rule.
- The REST connector: a plain HTTP API described as tools in the gateway config, credentials from the environment, so an agent's direct API calls become receipted, policy-checked tool calls through the gateway.
- Pre-commit authorization for consequential tools: named in `precommit`, a call is signed and logged before it is forwarded, withheld if the log will not take it, and its receipt carries the committed authorization with proof that it precedes the execution.
- The grant on every call (issue #97): expiry and revocation are checked on every call and again before the forward, in every mode, on the MCP, HTTP, and A2A fronts; `agent-custody revoke` revokes a grant and every grant delegated from it. The remote log's answer is verified against pinned keys before a pre-committed call goes upstream (issue #99). The portal verifies an address only from the account's own session before a provider sign-in can link to it (issue #103). The verifier recomputes the execution result digest (issue #104). The Stripe webhook ignores a repeated or out-of-order event (issue #105).
- Agent-to-agent delegation under custody: the A2A upstream and the gateway's A2A front; receipts per delegation with the delegate's card as a fact. A Google ADK `RemoteA2aAgent`, or any A2A client, is pointed at the gateway and a refused delegation comes back as a rejected task the delegate never saw. The delegate does not yet countersign its answer; the receipt attests what the gateway sent and observed, not what the delegate did with it.
- Private evidence: per-tool capture rules, applied by the issuer to the whole statement so nothing outside a fixed structural list is in clear under a private rule; withheld values as salted commitments whose salts never enter the receipt, encrypted under the customer's key, revealed and recomputed by the verifier; the commitments do not confirm a guess of a withheld value. A human approval envelope carries the action fields and an unsalted argument digest, so a private rule withholds it as a commitment; the [privacy limits](docs/approvals.md#privacy-limits) apply.
- Enterprise identity for the hosted portal: member roles (`owner`, `admin`, `reviewer`, `readonly`) with invites, TOTP MFA with single-use codes and an operator reset (`log-admin user mfa-reset`), and single sign-on per tenant through the tenant's own IdP, OIDC or SAML 2.0, set by the operator (`log-admin sso set`), with an enforce mode that closes the password, GitHub, and Google paths to members. Revoking an agent's authority mid-session already shipped (`agent-custody revoke`, example 27); example 31 shows the enterprise sign-in and the roles.
- The [state review console](../state/README.md#explain-one-action): search receipts by transaction, customer, agent or time, read the ten answers, and hand over a portable HTML/JSON case whose signatures, authorizations and inclusion proofs can be verified offline.
- A log outage after an ordinary call (issue #149): the signed receipt waits in `receipts/outbox/` and the gateway appends it when the log is back, the agent gets the real outcome marked `log-pending`, `GET /health` counts the pending receipts, and `requirePrecommit` refuses a remote log with an empty `precommit`. The [failure table](docs/usage.md#when-the-log-fails) gives each case.
- The anchor (issue #176): `agent-custody anchor` proves each new checkpoint extends the last one it anchored, then commits a Merkle root over them in one transaction from its address to itself, on Ethereum by default or on Base, Arbitrum, Optimism, Polygon, or any EVM chain by id (`--chain`), with a fee cap sized per chain. It publishes each log's record and inclusion proof, sends nothing for an idle log, skips a run above a fee cap, and never has two transactions in flight. Every transaction covers every watched log, and a transaction counts only once its block is finalized, following reorgs. `log-check --anchor-url` checks the record against one or more JSON-RPC endpoints, requires the log id the verifier pinned and the address's newest transaction, and checks the log's head against the anchored checkpoint, so a rewritten or rolled-back tree is caught from the chain alone ([anchoring](docs/anchoring.md), example 33).
- Completeness from the provider's side (issue #178): `agent-custody completeness` lists Stripe's refunds, payouts, or transfers over a window with the auditor's own read-only key, and matches each to a verified receipt by the provider's object id. It reports actions with no receipt, receipts the provider does not have, amount, currency, and beneficiary mismatches, calls forwarded without an outcome receipt, and receipts it cannot match ([completeness](docs/completeness.md), example 35).

**Next, in the order it pays off**

The first three close the gap between a log the operator cannot rewrite and a record the operator cannot shape.

1. Run the anchor for log.agent-custody.dev on mainnet: a funded key held only by the anchor service on the host, its records served beside the checkpoints, its address and each tenant's log id published in the welcome sheet and on the security page, and the monitor checking it. The code is done. [Issue #176](https://github.com/svayatta/agent-custody/issues/176).
2. Completeness beyond Stripe: the same check over GitHub's actions, and over on-chain transfers out of an agent's wallet, where the chain itself lists every transfer. [Issue #178](https://github.com/svayatta/agent-custody/issues/178).
3. A TEE gateway: a confidential container with a reproducible, attested build, the signing key generated and kept in the enclave, TLS ending inside it, and both verifiers checking the path from the receipt key, through the attestation, to the release. It replaces the TEE-hosted signer planned before. [Issue #179](https://github.com/svayatta/agent-custody/issues/179).
4. Run the witness for log.agent-custody.dev on a machine and under an account that is not ours, and require it in the welcome sheet. The code is done; what it needs is a second operator. [Issue #116](https://github.com/svayatta/agent-custody/issues/116).
5. Post-quantum signatures: ML-DSA beside Ed25519 in the same DSSE envelope, hybrid by default when a PQ key is present, in every signed artefact and in the browser verifier. [Issue #11](https://github.com/svayatta/agent-custody/issues/11).
6. Receiver attestation for agent-to-agent calls: the delegate signs its answer for the receipt, as a signing upstream does today.
7. SD-JWT redaction, then ZK proofs of policy compliance. Not before.
