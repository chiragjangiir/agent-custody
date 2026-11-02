# The TypeScript SDK

The receipt issuer inside the agent's own process, for tools that are plain functions rather than MCP servers. Every field it records is `claimed`: the SDK is the agent's own report, not evidence against the agent. Use it to record everything; use the [gateway](./gateway) to enforce the calls that matter.

```ts
import { createSdkIssuer, loadSdkConfig } from "@agent-custody/receipts";
const issuer = createSdkIssuer(loadSdkConfig("sdk.json"));
```

## The config file

`sdk.json`, paths relative to the file.

```json
{
  "agentId": "support-agent",
  "principalId": "user_456",
  "identity": { "keyFile": "keys/app.key" },
  "policyFile": "policy.cedar",
  "receiptsDir": "receipts",
  "log": { "url": "https://log.agent-custody.dev/t/acme/", "tokenEnv": "AGENT_CUSTODY_LOG_TOKEN", "hashOnly": true },
  "framework": "openai-agents",
  "otel": { "url": "http://localhost:4318" }
}
```

| field | meaning |
| --- | --- |
| `agentId` | recorded on every receipt as the agent, `claimed` |
| `principalId` | *optional*, recorded as the principal, `claimed` |
| `identity.keyFile` | the application's Ed25519 key; signs receipts |
| `policyFile` | *optional* Cedar policy; with it, `decide` and `wrap` can deny |
| `mode` | *optional* `"enforce"` (default) or `"observe"`: in observe mode `decide` returns the decision with `enforced: false`, `wrap` runs the function on a deny and records it, and every hook adapter returns no block |
| `receiptsDir` | where bundles are written |
| `logFile` or `log` | exactly one: a local Merkle log, or a remote one as in the [gateway config](./gateway#the-config-file) |
| `framework` | *optional* free-text label, recorded on `issuer.framework` |
| `otel`, `splunk` | *optional* [exporters](./gateway#exporters) |
| `capture`, `captureKeyEnv` | *optional* [private evidence](./gateway#private-evidence), as for the gateway: what the receipt file carries of each tool's arguments and result, and the environment variable holding the key that encrypts withheld fields |

## `SdkIssuer`

```ts
interface SdkIssuer {
  agentId: string;
  keyid: string;
  log: LogSink;                                             // { kind: "file" | "http", where, append(leaf) }
  ruleReasons: readonly (string | null)[];                  // the @reason of each policy in the file, in order, or null
  decide(ev: ToolEvent): PolicyDecision | null;
  record(ev: ToolEvent, outcome: Outcome, policy?: PolicyDecision | null): Promise<ReceiptBundle>;
  wrap<A, R>(tool: string, fn: (args: A) => R | Promise<R>, meta?: { model?, session? }): (args: A) => Promise<R>;
}
interface ToolEvent { tool: string; args: Record<string, unknown>; model?: string | null; session?: { id?: string | null; toolUseId?: string | null } }
type Outcome = { status: "executed" | "failed"; result: unknown } | { status: "denied"; reason: string } | { status: "error"; error: string };
interface PolicyDecision { decision: "allow" | "deny"; reasons: string[]; errors: string[]; policyDigest: string }
```

### `decide(event)`

Evaluates the policy for a call, records nothing. `null` when no policy is configured.

```ts
issuer.decide({ tool: "stripe.refund", args: { customer_id: "cust_123", amount: 5_000_000 } });
// → { decision: "deny", reasons: [], errors: [], policyDigest: "0e56…" }
```

Over the SDK the Cedar context has `args` and `facts: {}`; there is no gateway to fetch facts and no signed grant to supply `context.grant`.

### `record(event, outcome, policy?)`

Issues one receipt: signs it, appends its hash to the log, writes `receipts/<id>.json`, tells the exporters. Rejects if the log refuses; then no bundle is written.

```ts
const bundle = await issuer.record({ tool: "crm.lookup", args: { id: 1 } }, { status: "executed", result: { plan: "pro" } }, issuer.decide(ev));
bundle.inclusion.leafIndex;                                    // 0
receiptIdOf(bundle);                                           // "c92e582b-…"
```

The bundle is the same [receipt bundle](./gateway#the-receipt-bundle) the gateway writes, with `issuer.kind: "sdk"`, `principal.provenance: "claimed"`, and no `delegation`.

### `wrap(tool, fn, meta?)`

Decide, run, record. Throws `PolicyDeniedError` (`.tool`, `.reason`, `.receiptId`) on deny, after issuing the denial receipt; a thrown `fn` is recorded as `error` and re-thrown.

```ts
const refund = issuer.wrap("stripe.refund", async (args: { customer_id: string; amount: number }) => stripe.refunds.create(args));
await refund({ customer_id: "cust_123", amount: 2500 });     // executed, recorded
```

## Simulating a policy

Exported from `@agent-custody/receipts`:

```ts
import { simulatePolicy, formatSimulation } from "@agent-custody/receipts";
// predicates are the recorded statements from bundles you have verified with verifyBundle.
const report = simulatePolicy(proposedCedar, predicates);
console.log(formatSimulation(report));
```

`simulatePolicy(policyText: string, receipts: Iterable<ReceiptPredicate>, options?: SimulationOptions): SimulationReport` is a pure replay of the recorded policy inputs: `args`, each fact's `value`, and, for gateway receipts, `grant: { principal, scopes }` from the embedded delegation. It neither verifies signatures nor executes tools; use `verifyBundle` first, or the [CLI](./cli). It compares `policy.decision` even in observe mode, rather than the execution status.

| report field | meaning |
| --- | --- |
| `runId`, `timestamp` | a UUID for this run and its ISO timestamp |
| `policyDigest`, `previousPolicyDigests` | sha256 of the proposed text and the sorted distinct original digests |
| `total`, `evaluated`, `unchanged` | supplied calls, replayed calls, and calls whose decision stayed the same |
| `reconciliations` | reconciliation receipts: provider reads with no policy decision. A replay counts them here, not in `evaluated` or `skipped`, and they do not make the report incomplete, unless the original receipt of the call is missing: then the call is in `skipped`. Call `verifyBundle` first: the replay trusts a reconciliation by its shape and its link only |
| `changes` | `{ receiptId, tool, previous, proposed }[]`: both decisions for every changed call |
| `groups` | `{ tool, reason, receiptIds }[]`: changed calls grouped by the proposed reasons or errors |
| `skipped` | `{ receiptId, tool, reason }[]`: unavailable inputs, missing baseline, or calls stopped before policy evaluation |
| `complete` | false when any receipt was skipped |

`formatSimulation(report): string` prints the digests, grouped receipt ids and decision changes, counts, and any incomplete calls. `options` takes `captureKey` (a 32-byte `Buffer`) to decrypt withheld inputs, `disclosures` (a `Map` from receipt id to a disclosure file's contents), and `unreplayable` (`SimulationSkip[]`: calls that have no receipt; each counts in `total` and `skipped`). The function reads `receipts` once, so a generator that verifies one bundle at a time keeps memory flat. Types: `SimulationReport`, `SimulationOptions`, `SimulationChange`, `SimulationSkip`, `SimulationGroup`. Withheld arguments or fact values are reported as incomplete; withheld results do not affect replay. Grant restrictions cannot be widened by Cedar. See the [policy guide](https://agent-custody.dev/receipts/policies#simulating-a-policy-against-recorded-history) and [tutorial 28](https://github.com/svayatta/agent-custody/blob/main/packages/receipts/examples/28-policy-simulation.ts).

## Adapters

Each records the framework's tool calls through the issuer. Enforce or observe, never both on one tool.

| import | function | what it does |
| --- | --- | --- |
| `@agent-custody/receipts/sdk/vercel-ai` | `wrapTools(issuer, tools)` | returns the same tool map with each `execute` wrapped: decide, run, record; a denial returns the denial text as the tool result |
| `@agent-custody/receipts/sdk/openai-agents` | `wrapTools(issuer, tools)` | the same for OpenAI Agents SDK function tools (`invoke` wrapped) |
| `@agent-custody/receipts/sdk/openai-agents` | `observeRunner(issuer, runner)` | record-only: listens to a runner's tool events; evaluates no policy |
| `@agent-custody/receipts/sdk/langchain` | `receiptCallbacks(issuer)` → `{ callbacks }` | record-only callback handler for LangChain and LangGraph; pass it in the run config |
| `@agent-custody/receipts/sdk/claude` | `handleHookEvent(issuer, input)` | Claude Code and Claude Agent SDK hooks; see [Claude Code](./claude-code) |
| `@agent-custody/receipts/sdk/claude` | `claudeAgentHooks(issuer, matcher?)` | the in-process hooks object for the Claude Agent SDK, built on `handleHookEvent` |
| `@agent-custody/receipts/sdk/openclaw` | `openclawHooks(issuer)` → `{ before_tool_call, after_tool_call }` | OpenClaw plugin hooks: `before_tool_call(event, ctx)` returns `{ block: true, blockReason }` on a policy deny after issuing the denial receipt, nothing otherwise; `after_tool_call(event, ctx)` records the executed or failed call. `event` is OpenClaw's `{ toolName, params, toolCallId?, result?, error? }`, `ctx` its `{ sessionId?, sessionKey? }` |
| `@agent-custody/receipts/sdk/openclaw` | `registerOpenClaw(api, issuer)` | calls `api.on` for both hooks, for a plugin's `register(api)` |
| `@agent-custody/receipts/sdk/deepseek-harness` | the module itself: `name`, `inject`, `Config`, `apply(ctx, { config? })` | a DeepSeek Harness plugin, listed by this path with the SDK config file as its setting (or `AGENT_CUSTODY_CONFIG`); registers `tools/pre-execute` and `tools/post-execute` |
| `@agent-custody/receipts/sdk/deepseek-harness` | `deepseekHarnessHooks(issuer)` → `{ preExecute, postExecute }` | `preExecute(exec, next)` returns `{ kind: "deny", reason }` on an enforced policy deny after issuing the denial receipt, else `next()`; `postExecute(exec, result, next)` records the executed (`content`/`value`) or failed (`error`) call, then `next()`. `exec` is the harness's `{ name, arguments, callId, agent }` |
| `@agent-custody/receipts/sdk/deepseek-harness` | `registerDeepSeekHarness(ctx, issuer)` | calls `ctx.on` for both events |

## Agents over A2A

Exported from `@agent-custody/receipts` beside the gateway. They belong to the gateway, not the in-process issuer, and are listed here with the other exports; the behaviour is on the [gateway](./gateway#an-a2a-agent-as-an-upstream) page.

| export | signature | what it does |
| --- | --- | --- |
| `a2aUpstream` | `(name, cfg: A2aUpstreamConfig, { fetch?, env? }?)` → upstream client with `resolved(): Promise<ResolvedCard>` | a remote agent as an upstream: `<prefix>.send` delegates a task, `<prefix>.card` reads its card |
| `fetchAgentCard` | `(url, headers, fetch, timeoutMs): Promise<ResolvedCard>` | fetches the card from a base URL or a card URL; `ResolvedCard` is `{ card: AgentCard, cardUrl, endpoint, legacy }`, `legacy` true for a 0.3 card |
| `serveA2a` | `(host: GatewayHost, cfg: A2aUpstreamConfig, { port, host?, grant?, log? }: A2aServerOptions): Promise<RunningA2aServer>` | the gateway as an A2A agent; `RunningA2aServer` is `{ url, close() }` |
| `textOf` | `(message) => string` | a message's text parts joined, what a policy reads as `context.args.text` |
| `A2A_CARD_PATH`, `A2A_RECEIPT_METADATA_KEY`, `A2A_STREAM_META_KEY` | `"/.well-known/agent-card.json"`, `"agent-custody/receipt"`, `"agent-custody/a2a-stream"` | the card path, the metadata key an answered task or message names its receipt under, and the `_meta` key a `.send` result carries a relayed stream's events under |

Types: `AgentCard`, `ResolvedCard`, `A2aServerOptions`, `RunningA2aServer`.

## Human approvals

Exported from `@agent-custody/receipts` for signing and verifying exact actions at the [gateway](./gateway#human-approvals). The SDK issuer does not enforce these gateway rules.

```ts
interface ApprovalBinding {
  principal: string;
  agent: string;
  tool: string;
  args: Record<string, unknown>;
  fields?: { amount?: string; currency?: string; beneficiary?: string };
}
type ApprovalVerifyResult =
  | { ok: true; approval: Approval; approverKeyids: string[] }
  | { ok: false; error: string };
```

| export | signature | behaviour |
| --- | --- | --- |
| `createApproval` | `(key: KeyPair, input: ApprovalBinding & { approvalId?: string; issuedAt?: string; expiresAt: string }): Envelope` | signs a v0.1 approval; defaults to a UUID id and current issuance time; requires expiry after issuance. The digest covers every JSON argument. Present action fields are copied by the configured top-level names; defaults are `amount`, `currency`, `beneficiary`. Amount is a safe integer in minor units; the other two are nonempty strings |
| `verifyApproval` | `(envelope: unknown, trusted: PublicKeyRef[], binding: ApprovalBinding, { at?: string, minApprovers?: 1 \| 2, maxLifetimeSeconds?: number }?): ApprovalVerifyResult` | checks the envelope/schema, distinct trusted signatures, complete binding, the lifetime cap when given (`expiresAt` minus `issuedAt`), and half-open validity window `[issuedAt, expiresAt)`; current time, one approver, and no cap by default. Returns a failure for untrusted input; does not consume |
| `verifyApprovalStatement` | `(envelope: unknown, trusted: PublicKeyRef[], minApprovers: 1 \| 2 = 1): ApprovalVerifyResult` | checks only the schema and distinct trusted signatures. Does not establish action binding or time validity; use `verifyApproval` at an enforcement boundary |
| `consumeApproval` | `(usedDir: string, approvalId: string, receiptId: string, at: string): void` | exclusively creates a persistent consumption marker before a side effect; throws on replay or storage failure; does not undo a marker after later failures |
| `ApprovalSchema` | Zod schema | strict payload schema for `Approval`, with `version: "0.1"`, UUID `approvalId`, principal, agent, tool, `argsDigest`, optional action fields, `issuedAt`, `expiresAt` |
| `APPROVAL_TYPE`, `APPROVAL_META_KEY` | `"application/vnd.agent-custody.approval+json"`, `"agent-custody/approval"` | signed payload type and caller `_meta` key |

Types: `Approval`, `ApprovalBinding`, `ApprovalRecord`, `ApprovalVerifyResult`. `ApprovalRecord` is the gateway's observed check, embedded in receipts and pre-commit authorizations; it carries the envelope when its statement has a trusted signature and valid schema, threshold, optional field mapping, times, status, optional reason and signer keyids.

For two approvers, `dsseCountersign(createApproval(firstKey, action), secondKey)` adds a signature to the same payload. Distinct trusted keyids count once each; distinct human identities are an operational assumption. Keep private keys with the people reviewing the complete action. [Tutorial 28](/receipts/tutorials) runs the gateway, refusals, two signatures, consumption and offline verification.

## Private evidence

Exported from `@agent-custody/receipts`. `createIssuer(key, receiptsDir, log, { capture: { rules, key } })` applies the rule to every statement it signs (`issue(predicate, ctx?, retainPrepared?)`, `authorize(predicate, ctx?)`), which is how the gateway and `createSdkIssuer` get it, and the verifier uses `restorePaths` to put the values back; the behaviour is on the [gateway](./gateway#private-evidence) and [verify](./verify#reveal) pages.

The optional synchronous `retainPrepared(candidate): PreparedReceipt` callback durably chooses the signed view before a log append. `PreparedReceipt` contains `{ envelope, view: { predicate, salts } }`; it is private recovery data, including commitment salts, and must never be exported or handed to a verifier. Returning the stored winner lets restarted/concurrent reconciliation attempts append identical bytes and retain the same salts. The issuer checks its signature, statement and receipt id before appending. Ordinary callers omit this callback.

| export | signature | what it does |
| --- | --- | --- |
| `privateView` | `(predicate, rule: CaptureRule \| undefined, key?: Buffer, ctx?: CaptureContext) => { predicate, salts }` | the statement a receipt carries under a rule: every non-structural value withheld as the rule says, the digests salted from the field salts, the `capture` note set; and the salts by `pathKey`, which the issuer keeps in `receipts/salts/<id>.json` and never signs. The predicate itself and no salts under a clear rule. `ctx.clearFactArgs` names the fact arguments that may stay in clear, `ctx.factResults` the lookup results behind the fact digests |
| `restorePaths` | `(predicate, note: CaptureNote \| undefined, disclosed?, key?: Buffer) => Restoration` | the statement with every restorable path put back: `{ predicate, restored: Map<pathKey, "disclosed" \| "decrypted">, salts: Map<pathKey, string>, missing: Path[], problems: { path, error }[] }`; a path the note names that holds no commitment, a disclosed value without its salt, or a disclosure that contradicts a commitment, is a problem, never a throw. `digestSaltFor(restoration, note, prefix)` is the salt of the digest over a part once its values are back |
| `withhold` | `(value, key?: Buffer) => { commitment, salt }` | a commitment over a random salt and the canonical value, and the salt, which the receipt never carries; with a key, the value and the salt under AES-256-GCM inside the commitment |
| `checkCommitment` | `(c: Commitment, value, salt) => boolean` | true when `value` under `salt` is what the commitment was made over |
| `reveal` | `(c: Commitment, key: Buffer) => { value, salt }` | the value and the salt behind an encrypted commitment, checked against it; throws for a `withheld` commitment or a key that is not the one it was encrypted under |
| `isCommitment`, `isDisclosed`, `digestSalt` | `(v) => boolean`, `(v) => boolean`, `(salts: string[]) => string \| undefined` | whether a value is a well-formed commitment; whether it is a disclosed value `{ $custody: "disclosed", salt, value? }`; the salt of a digest over values with these salts, none when there are none |
| `ruleMode`, `ruleFor` | `(rule) => CaptureMode`, `(capture: CaptureConfig \| undefined, tool) => CaptureRule \| undefined` | the one mode a rule withholds in (`encrypted` when any side is, `digest` when any side is private, else `clear`); the tool's rule, or the `"*"` rule |
| `REST` | `"$rest"` | the slot in a captured side's view that holds the commitment over every field not kept in clear |
| `getAt`, `setAt`, `pathKey`, `pathText`, `under` | `(root, path: Path)`, `(root, path, value) => root'`, `(path) => string`, `(path) => string`, `(path, prefix) => boolean` | own-property reads and copying writes at a path (a field named `__proto__` stays a field); a path as a map key, as text, and whether it lies under a prefix |
| `captureKeyFrom`, `captureKeyId` | `(text) => Buffer`, `(key) => string` | the 32-byte key from its hex or base64 form; the sha256 of a key, which an encrypted commitment carries as `keyid` |

Types: `CaptureMode`, `CaptureSide`, `CaptureRule`, `CaptureConfig`, `CaptureNote` (`{ mode, withheld: Path[] }`), `Path`, `CaptureContext`, `PrivateView`, `Restoration`, `How`, `Withheld`, `Encrypted`, `Commitment`, `Disclosed`.

## The log client

`httpLog(url, { token?, hashOnly?, retries? = 3, timeoutMs? = 10000, fetch? })` is what the gateway and SDK use for a remote log: `POST <url>append` with `{ leaf }` or `{ leafHash }`, retrying 429 and 5xx with backoff and honouring `Retry-After`. `fileLog(path, key)` is the local one. Both are `LogSink`s: `append(leaf): Promise<{ inclusion, treeHead }>`. `openLog(config, key)` picks from a config.

## Verifying in code

```ts
import { verifyBundle, formatReport, loadPublicKey } from "@agent-custody/receipts";
const r = verifyBundle(bundle, { issuerKeys: [loadPublicKey("keys/app.pub")], principalKeys: [] });
r.ok; r.checks;                                                // [{ name, ok, detail? }]
console.log(formatReport(r));
```

Every option and check is on the [verify](./verify) page.

## Keys

`generateKeyPair(): KeyPair`, `writeKeyPair(kp, dir, name)` → `{ keyFile, pubFile }`, `loadPrivateKey(path)`, `loadPublicKey(path): PublicKeyRef` (`{ publicKey, keyid }`), `publicKeyFromPem(pem)`, `publicKeyToPem(publicKey)`. Keys are Ed25519; a keyid is the SHA-256 of the SPKI DER. `dsseSign(payloadType, payload, keyPair): Envelope`, `dsseCountersign(envelope, keyPair): Envelope`, and `dsseVerify(envelope, trustedKeys)` are the primitives every signed artefact uses.
