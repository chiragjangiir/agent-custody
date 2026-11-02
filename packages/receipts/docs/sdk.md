# The interceptor SDK

The gateway sees only MCP traffic. The SDK sees whatever the agent framework lets it hook, from inside the agent's own process. It issues the same receipt format, verified by the same command, with one difference a verifier cannot miss: the receipt names its issuer as `sdk`, and every field is `claimed`.

| | gateway | SDK |
| --- | --- | --- |
| runs | as a separate process between agent and tools | inside the agent's process |
| sees | MCP tool calls only | whatever the framework's hooks expose |
| can enforce | yes, the call never reaches upstream on deny | only where the hook can block, and only if nobody bypasses the hook |
| facts | fetched by the gateway itself, `observed` | none; policies see `context.args` only |
| delegation | required, signed by the principal | none; principal is a config string, `claimed` |
| a verifier learns | the agent could not have skipped or forged this | the agent's process reported this, and it has not changed since |
| install | change one line in the host's MCP config | add a hook or wrap a tool function |

Use the SDK for reach. Use the gateway for anything that moves money, touches production, or handles personal data. Both write to the same receipt directory and log if you point them there.

## Configuration

```json
{
  "agentId": "billing-bot",
  "principalId": "user_456",
  "identity": { "keyFile": "keys/app.key" },
  "policyFile": "policy.cedar",
  "receiptsDir": "receipts",
  "logFile": "log.jsonl",
  "framework": "claude-code"
}
```

`policyFile` and `principalId` are optional. Without a policy the SDK records and never denies. Paths resolve relative to the config file. Instead of `logFile`, `"log": { "url": "https://log.example.com/", "tokenEnv": "AGENT_CUSTODY_LOG_TOKEN" }` sends every leaf to a log run by someone else, whose key then signs the tree heads; see [usage.md](usage.md) for what that changes and [verification.md](verification.md) for what it proves. Generate the key with `node src/cli.ts keygen --dir keys --name app`.

`"otel": { "url": "http://localhost:4318" }` additionally exports every receipt as one span to that OTLP/HTTP collector, after the receipt is written, with the receipt id as the trace id; see the [usage guide](usage.md#setup-step-by-step) for the fields. Export never blocks or fails a receipt. `"splunk": { "url": ..., "tokenEnv": "HEC_TOKEN" }` does the same to a Splunk HTTP Event Collector, one event per receipt with the receipt id and log position as fields; both blocks may be set together.

Policies see `context.args` and an empty `context.facts`. A policy that reads `context.facts` or `context.grant` errors, which is a deny. That is intended: an SDK policy cannot pretend it checked something outside the agent's process.

`"mode": "observe"` in the SDK config records the policy's decision without acting on it: `decide` returns it with `enforced: false`, `wrap` runs the function on a deny and records it as executed, and every hook adapter below returns no block. Run a policy that way first, read the receipts that say "would have been denied", then remove the line.

## Claude Code

Register the hook command in `.claude/settings.json`. The same command handles all three events.

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "mcp__.*|Bash|Write|Edit", "hooks": [{ "type": "command", "command": "node /abs/path/agent-custody/packages/receipts/src/cli.ts hook --config /abs/path/sdk.json" }] }
    ],
    "PostToolUse": [
      { "hooks": [{ "type": "command", "command": "node /abs/path/agent-custody/packages/receipts/src/cli.ts hook --config /abs/path/sdk.json" }] }
    ],
    "PostToolUseFailure": [
      { "hooks": [{ "type": "command", "command": "node /abs/path/agent-custody/packages/receipts/src/cli.ts hook --config /abs/path/sdk.json" }] }
    ]
  }
}
```

`AGENT_CUSTODY_CONFIG` works instead of `--config`. Behaviour per event:

- **PreToolUse.** Evaluates the policy. On deny, issues a denial receipt and returns `permissionDecision: "deny"` with the receipt id in the reason. If the log does not take the receipt, the hook still denies the call, and the reason says `no receipt` and why. On allow, or with no policy, returns no decision, so Claude Code's own permission prompts still apply. The hook never auto-approves.
- **PostToolUse.** Issues an executed receipt carrying `tool_response`.
- **PostToolUseFailure.** Issues a failed receipt.

Session and tool-use ids from the event are recorded so a receipt can be matched to the transcript. If the user declines a call at the permission prompt, no PostToolUse fires and no receipt is issued for it. Claude Code records that in its own transcript, not here.

## Claude Agent SDK, in-process

```ts
import { query } from "@anthropic-ai/claude-agent-sdk";
import { loadSdkConfig } from "@agent-custody/receipts";
import { claudeAgentHooks, createSdkIssuer } from "@agent-custody/receipts/sdk/claude";

const issuer = createSdkIssuer(loadSdkConfig("./sdk.json"));

for await (const msg of query({
  prompt: "Refund the customer",
  options: { hooks: claudeAgentHooks(issuer) },
})) {
  // ...
}
```

`claudeAgentHooks(issuer, matcher?)` returns entries for `PreToolUse`, `PostToolUse`, and `PostToolUseFailure` with the same behaviour as the command hook. The hook callback receives the same JSON fields, so the handler is shared. This adapter is typed loosely and does not import the SDK package; it has been exercised against the documented hook contract, not against a live `query()` run.

## OpenAI Agents SDK (JS)

Two adapters in [src/sdk/openai-agents.ts](../src/sdk/openai-agents.ts). Both are tested against the real package with a scripted model and a real `Runner`, no network.

```ts
import { Agent, Runner } from "@openai/agents";
import { wrapTools, observeRunner } from "@agent-custody/receipts/sdk/openai-agents";

// enforcement + receipts: wrap the tools you hand to the agent
const agent = new Agent({ name: "billing", tools: wrapTools(issuer, [refundTool, lookupTool]) });

// receipts only: attach to the runner's lifecycle events, nothing to wrap, no policy evaluated
const runner = new Runner();
observeRunner(issuer, runner);
```

`wrapTools` wraps each tool's `invoke`. On a policy deny the tool never runs; the model receives the denial text as the tool result, with the receipt id, and the run continues. That matches what a model sees when a human declines a tool. `observeRunner` listens to `agent_tool_start` and `agent_tool_end`, pairs them by call id, and records executed receipts with no policy. Use one or the other for a given tool, not both.

## Vercel AI SDK

[src/sdk/vercel-ai.ts](../src/sdk/vercel-ai.ts), tested with a real `generateText` loop over a mock model.

```ts
import { generateText } from "ai";
import { wrapTools } from "@agent-custody/receipts/sdk/vercel-ai";

const result = await generateText({ model, prompt, tools: wrapTools(issuer, tools) });
```

`wrapTools` returns a new tool set with every `execute` wrapped. Tools without `execute` pass through untouched. On deny it throws `PolicyDeniedError`, which the AI SDK turns into a `tool-error` part that the model sees; the loop continues. The receipt records the `toolCallId`.

## LangChain / LangGraph (JS)

[src/sdk/langchain.ts](../src/sdk/langchain.ts), tested against real `StructuredTool` invocations.

```ts
import { tool } from "@langchain/core/tools";
import { receiptCallbacks, ReceiptCallbackHandler } from "@agent-custody/receipts/sdk/langchain";

// receipts only: a callback handler, attach per call or on the whole graph
await refund.invoke({ customer_id, amount }, receiptCallbacks(issuer));
const graph = workflow.compile().withConfig({ callbacks: [new ReceiptCallbackHandler(issuer)] });

// enforcement: build the tool from issuer.wrap()
const refund = tool(issuer.wrap("stripe.refund", fn), { name: "stripe.refund", schema });
```

[Example 23](../examples/23-langchain-kb-agent.ts) is a whole agent on `createAgent`, a docs agent over a knowledge base with a policy that allows writes under `notes/` only, with every receipt verified at the end; it runs with no API key. A 22-second film of it: [agent-custody.dev/demo-langchain-kb.mp4](https://agent-custody.dev/demo-langchain-kb.mp4).

LangChain callbacks cannot block a tool, so the handler evaluates no policy; it records what happened, including the `tool_call_id` when one is present, and unwraps `ToolMessage` outputs. For enforcement wrap the function at construction. Do not do both on one tool or it will be recorded twice.

## OpenClaw

[src/sdk/openclaw.ts](../src/sdk/openclaw.ts). OpenClaw runs plugins in the agent's process and awaits two tool hooks: `before_tool_call`, which can block a call with a reason the model sees, and `after_tool_call`, which carries the result or the error. A plugin is three files: `package.json` with `"openclaw": { "extensions": ["./index.ts"] }`, `openclaw.plugin.json`, and the entry:

```ts
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-sdk";
import { createSdkIssuer, loadSdkConfig } from "@agent-custody/receipts";
import { registerOpenClaw } from "@agent-custody/receipts/sdk/openclaw";

export default definePluginEntry({
  id: "agent-custody",
  name: "agent-custody",
  description: "A signed receipt for every tool call; a policy can deny one before it runs",
  register(api) {
    registerOpenClaw(api, createSdkIssuer(loadSdkConfig(process.env.AGENT_CUSTODY_CONFIG ?? "./sdk.json")));
  },
});
```

```json
{ "id": "agent-custody", "name": "agent-custody", "activation": { "onStartup": true }, "configSchema": { "type": "object", "additionalProperties": false } }
```

Then `openclaw plugins install --link ./agent-custody-plugin && openclaw plugins enable agent-custody`. `before_tool_call` evaluates the policy: on deny it issues a denial receipt and returns `{ block: true, blockReason: "agent-custody: … (receipt <id>)" }`; on allow, or with no policy, it returns nothing, so OpenClaw's own approvals and other plugins still apply. It never auto-approves, and if the denial receipt cannot be issued the call is blocked all the same. `after_tool_call` issues the receipt for the executed or failed call, with OpenClaw's `sessionId` and `toolCallId` as the receipt's session. `openclawHooks(issuer)` returns the two handlers for a plugin that registers them itself. Typed loosely on purpose, mirroring OpenClaw's `hook-types.ts`, so the package does not depend on `openclaw`; exercised against that contract in [example 21](../examples/21-openclaw.ts) and the test.

## DeepSeek Harness

[src/sdk/deepseek-harness.ts](../src/sdk/deepseek-harness.ts). DeepSeek Harness (dsh) is Node, everything in it is a plugin, and it runs two awaited waterfalls around every tool call: `tools/pre-execute`, whose handler returns `{ kind: "deny", reason }` (the reason reaches the model) or delegates with `next()`, and `tools/post-execute`, which sees the result. This module is a harness plugin itself: it exports `name`, `inject`, `Config`, and `apply`, so it is listed by its package path with the SDK config file as its one setting:

```yaml
# cordis.yml overlay (dsh web --patch ./cordis.yml), or the plugin list the dsh CLI manages
- insert:
    - id: agent-custody
      name: "@agent-custody/receipts/sdk/deepseek-harness"
      config:
        config: /abs/path/sdk.json
```

`AGENT_CUSTODY_CONFIG` in the environment works instead of the setting. `tools/pre-execute` evaluates the policy: on an enforced deny it issues the denial receipt and denies with `agent-custody: … (receipt <id>)`; otherwise it delegates, so the harness's own approvals and other plugins still apply, and it never decides `allow` itself. `tools/post-execute` records the executed or failed call with the harness's session and call ids and delegates. `deepseekHarnessHooks(issuer)` returns the two handlers, `registerDeepSeekHarness(ctx, issuer)` registers them, for a plugin of your own. Typed loosely from the harness's `packages/core/tools/src/index.ts`, no dependency on `@deepseek-ai/dsh-tools`; driven with the harness's event shapes in [example 22](../examples/22-deepseek-harness.ts) and the test.

The harness also ships `@deepseek-ai/dsh-hooks-claude-code`, a bridge that runs a Claude Code `hooks.json` on the same seams. The [`agent-custody hook`](#claude-code) command works through it unchanged, one process per call; this plugin is the in-process path.

## Hermes Agent

[packages/python/agent_custody/hermes.py](../../python/agent_custody/hermes.py), through the sidecar like every Python adapter. Hermes runs Python plugins in the agent's process and fires `pre_tool_call(tool_name, args, task_id, **kwargs)`, which may return `{"action": "block", "message": …}`, and `post_tool_call(tool_name, args, result, task_id, duration_ms, **kwargs)`. The plugin is the directory [packages/python/hermes-plugin](../../python/hermes-plugin/): a `plugin.yaml` declaring both hooks and a `sidecar_url` setting, and an `__init__.py` that is one line, `from agent_custody.hermes import register`. Copy it to `~/.hermes/plugins/agent-custody/`, `pip install agent-custody`, start the sidecar, `hermes plugins enable agent-custody`. A denied call is blocked before it runs with the receipt id in the message; an allowed one gets no action, so Hermes's own guardrails and approvals still apply; every completed call is recorded with the Hermes `task_id` as the receipt's session. `hermes_hooks(client)` returns the two callables; `register_hermes(ctx, client)` registers them on a plugin context.

## Google ADK

[packages/python/agent_custody/adk.py](../../python/agent_custody/adk.py), through the sidecar like every Python adapter. ADK runs `before_tool_callback(tool, args, tool_context)` before every tool call, and a dict returned there skips the tool and becomes its result; `after_tool_callback(tool, args, tool_context, tool_response)` runs after the tool and may replace the response. `adk_callbacks(client)` returns both, keyed by the `LlmAgent` fields they go in:

```python
from google.adk.agents import LlmAgent
from agent_custody import Client
from agent_custody.adk import adk_callbacks

agent = LlmAgent(name="billing", model="gemini-2.5-flash", tools=[...], **adk_callbacks(Client()))
```

`pip install "agent-custody[adk]"` brings in `google-adk[a2a]`. The before callback evaluates the policy: on an enforced deny it records the denial receipt and returns `{"error": "agent-custody: <reason> (receipt <id>)", "agent-custody/receipt": "<id>"}`, so ADK skips the tool and the model sees the receipt as the tool's result; on allow, or with no policy, it returns `None` and the tool runs. If the denial receipt cannot be recorded the call is still skipped. The after callback records the executed call, the result as JSON when it is JSON and as text otherwise, and returns `None`, leaving the response as it was; it recognises the denial dict by its receipt key and does not record it a second time. ADK's `invocation_id` and `function_call_id` are the receipt's session. In observe mode a deny is recorded and the tool runs, as with every adapter. Tested in `tests/test_adk.py` against ADK's own runner with a scripted model and a tool named `stripe.refund`.

A delegation an ADK agent makes to another agent over A2A, through `RemoteA2aAgent`, is not a tool call and does not pass through these callbacks. Point the `RemoteA2aAgent` at the gateway's A2A front instead, `agent-custody gateway --a2a`, in [usage.md](usage.md#the-gateway-as-an-a2a-agent): every delegation is then a receipted, policy-checked call, and a refused one never reaches the remote agent. `tests/test_adk_a2a.py` runs that with ADK's own `to_a2a` on the remote side.

## Any other framework: wrap the function

Every agent framework ends up calling a function. Wrap it.

```ts
import { loadSdkConfig } from "@agent-custody/receipts";
import { createSdkIssuer, PolicyDeniedError } from "@agent-custody/receipts";

const issuer = createSdkIssuer(loadSdkConfig("./sdk.json"));

const refund = issuer.wrap("stripe.refund", async (args: { customer_id: string; amount: number }) => {
  return stripe.refunds.create({ customer: args.customer_id, amount: args.amount });
});

try {
  await refund({ customer_id: "cust_123", amount: 50000 });   // executed receipt
} catch (e) {
  if (e instanceof PolicyDeniedError) console.log(e.receiptId); // denial receipt, tool never ran
  throw e;                                                       // any other error: error receipt, rethrown
}
```

For finer control use the two primitives `wrap` is built from:

```ts
const decision = issuer.decide({ tool, args });                       // PolicyDecision | null
const bundle = await issuer.record({ tool, args, model, session }, { status: "executed", result }, decision);
```

`record` returns a promise because the log may be remote. It rejects, and writes no bundle, if the log refuses the leaf. `handleHookEvent` is asynchronous for the same reason. The record-only adapters that cannot await, such as `observeRunner`, report a refused leaf on stderr.

## Which adapter enforces

| framework | enforce + record | record only |
| --- | --- | --- |
| Claude Code | `hook` command, PreToolUse deny | PostToolUse |
| Claude Agent SDK | `claudeAgentHooks` | same |
| OpenAI Agents SDK | `wrapTools` | `observeRunner` |
| Vercel AI SDK | `wrapTools` | wrap with a policy-less issuer |
| LangChain / LangGraph | `tool(issuer.wrap(...))` | `ReceiptCallbackHandler` |
| Google ADK (Python) | `adk_callbacks`: `before_tool_callback` skips the tool | `after_tool_callback` |
| anything else | `issuer.wrap` | `issuer.record` |

Record-only adapters evaluate no policy on purpose. A receipt that said "policy: deny" next to "execution: executed" would fail verification, and the verifier would be right: that is not a receipt, that is a finding. Enforce, or observe, but do not pretend.

The three framework packages are optional peer dependencies. Each adapter imports only from its own package, so installing none of them costs nothing.

## What an SDK receipt is worth

A verified SDK receipt establishes that a process holding the application key reported this call, at this time, with these arguments and this result, and that the record has not changed since. It does not establish that the process reported every call, that the arguments are what the tool really received, or that anyone outside the process checked anything. The verifier prints exactly that sentence under `ISSUER`. Keep it in the dashboard too.

## Other languages: the sidecar

The interceptor above is TypeScript. Agents in any other language get the same receipts through the sidecar: the SDK issuer behind a local HTTP API, started from the same config file.

```bash
agent-custody serve --config sdk.json          # 127.0.0.1:8788 by default; --port and --host to change
```

| | |
| --- | --- |
| `GET /health` | `{ agentId, keyid, log: { kind, where } }` |
| `POST /decide` with a `ToolEvent` `{ tool, args, model?, session? }` | the `PolicyDecision`, or `null` when no policy is configured |
| `POST /record` with `{ event, outcome, policy? }` | the `ReceiptBundle`; `outcome` is `{ status: "executed" \| "failed", result }`, `{ status: "denied", reason }`, or `{ status: "error", error }` |

The client's loop is decide, run the tool, record. A malformed body gets a 400 and nothing is written; a log that refuses the leaf gets a 502 and nothing is written. Bind the sidecar to loopback: it is a per-host companion holding the signing key, not a shared service, and everything it records is `claimed` exactly as with the in-process SDK, because it trusts what the client reports.

**Python** has a real package, [packages/python](../../python/README.md): `pip install agent-custody`, a standard-library client with `decide`, `record`, and `wrap`, and adapters for LangChain callbacks, OpenAI Agents function tools, and Claude Agent SDK hooks, each tested against the real package with receipts checked by this verifier.

**Go, Java, Rust, and Python without the package** each have a complete client in [examples/languages](../examples/languages): one file, standard library where the language has an HTTP client, decide then record. The test suite runs every one of them against a live sidecar. Any language with an HTTP client is the same forty lines.

The gateway needs none of this. It is an MCP server, so a Python or Go agent host that speaks MCP puts it in front of its tools with a config change; [usage.md](usage.md) shows the Python hosts.

