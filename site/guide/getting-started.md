# Getting started

Two paths. The **SDK path** records what the agent's own process reports: the quickest way to a receipt, and every field in it is the agent's word (`claimed`). The **gateway path** puts a process the agent does not control between it and the tools, so a call can be denied before it runs and a stranger can accept the record. Start with the SDK to see a receipt today; move a tool to the gateway when its call moves money or touches production. Either path runs in observe mode first, `"mode": "observe"` in the config, recording what the policy would deny without blocking anything, until the policy is right.

## Claude Code in one command

For your own Claude Code sessions, one command does the setup and prints each step: an agent key, a config in observe mode, a starter deny policy (force push, `rm -rf` on `/`, `~`, and `$HOME`, `terraform destroy`, `drop database`), and the three hooks.

```bash
npx @agent-custody/receipts init claude-code
```

Work in Claude Code as usual. Nothing is blocked, and the receipts stay on your machine. Then read what the policy would have denied:

```bash
agent-custody report --config ~/.config/agent-custody/sdk.json
```

`init` prints this command with absolute paths. To enforce the policy, remove the `"mode": "observe"` line from `sdk.json`. The options are on [the Claude Code page](/reference/claude-code#one-command).

## Pick your stack

Install the package, make a key and a config once, then add the lines for your framework: Claude Code, the Claude Agent SDK, the OpenAI Agents SDK, LangChain, Vercel AI, OpenClaw, DeepSeek Harness, Hermes, Google ADK, or plain Python. Each produces a receipt in `receipts/` that [the browser verifier](/verify) checks with the `.pub` file.

```bash
npm install @agent-custody/receipts && npx @agent-custody/receipts keygen --dir keys --name app
```

::: code-group

```json [Claude Code]
// .claude/settings.json: one hook command records every tool call and can deny one before it runs
{ "hooks": {
  "PreToolUse":  [{ "matcher": "Bash|Write|Edit|mcp__.*", "hooks": [{ "type": "command", "command": "agent-custody hook --config /abs/path/sdk.json" }] }],
  "PostToolUse": [{ "matcher": "Bash|Write|Edit|mcp__.*", "hooks": [{ "type": "command", "command": "agent-custody hook --config /abs/path/sdk.json" }] }]
} }
```

```ts [Claude Agent SDK]
import { query } from "@anthropic-ai/claude-agent-sdk";
import { loadSdkConfig } from "@agent-custody/receipts";
import { claudeAgentHooks, createSdkIssuer } from "@agent-custody/receipts/sdk/claude";

const issuer = createSdkIssuer(loadSdkConfig("./sdk.json"));
for await (const msg of query({ prompt: "Refund the customer", options: { hooks: claudeAgentHooks(issuer) } })) { /* … */ }
```

```ts [OpenAI Agents SDK]
import { Agent } from "@openai/agents";
import { loadSdkConfig, createSdkIssuer } from "@agent-custody/receipts";
import { wrapTools } from "@agent-custody/receipts/sdk/openai-agents";

const issuer = createSdkIssuer(loadSdkConfig("./sdk.json"));
const agent = new Agent({ name: "billing", tools: wrapTools(issuer, [refundTool, lookupTool]) });   // a denied call never runs; the model sees why
```

```ts [LangChain]
import { tool } from "@langchain/core/tools";
import { loadSdkConfig, createSdkIssuer } from "@agent-custody/receipts";
import { receiptCallbacks } from "@agent-custody/receipts/sdk/langchain";

const issuer = createSdkIssuer(loadSdkConfig("./sdk.json"));
await refund.invoke({ customer_id, amount }, receiptCallbacks(issuer));                              // record what happened
const enforced = tool(issuer.wrap("stripe.refund", fn), { name: "stripe.refund", schema });         // or deny before it runs
```

```ts [Vercel AI]
import { generateText } from "ai";
import { loadSdkConfig, createSdkIssuer } from "@agent-custody/receipts";
import { wrapTools } from "@agent-custody/receipts/sdk/vercel-ai";

const issuer = createSdkIssuer(loadSdkConfig("./sdk.json"));
const result = await generateText({ model, prompt, tools: wrapTools(issuer, tools) });
```

```ts [OpenClaw]
// an OpenClaw plugin entry: every tool call the agent makes, a denied one blocked before it runs
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-sdk";
import { createSdkIssuer, loadSdkConfig } from "@agent-custody/receipts";
import { registerOpenClaw } from "@agent-custody/receipts/sdk/openclaw";

export default definePluginEntry({ id: "agent-custody", name: "agent-custody", description: "A receipt for every tool call",
  register(api) { registerOpenClaw(api, createSdkIssuer(loadSdkConfig("./sdk.json"))); } });
```

```yaml [DeepSeek Harness]
# the module is the plugin: list it in cordis.yml (dsh web --patch ./cordis.yml) with the SDK config as its setting
- insert:
    - id: agent-custody
      name: "@agent-custody/receipts/sdk/deepseek-harness"
      config:
        config: /abs/path/sdk.json
```

```yaml [Hermes]
# ~/.hermes/plugins/agent-custody/plugin.yaml, beside an __init__.py that reads: from agent_custody.hermes import register
name: agent-custody
version: 1.0.0
provides_hooks: [pre_tool_call, post_tool_call]
config_schema:
  sidecar_url: { type: str, default: "http://127.0.0.1:8788" }
# then: pip install agent-custody && hermes plugins enable agent-custody
```

```python [Google ADK]
# pip install "agent-custody[adk]"; the sidecar is `npx @agent-custody/receipts serve --config sdk.json`
from google.adk.agents import LlmAgent
from agent_custody import Client
from agent_custody.adk import adk_callbacks

agent = LlmAgent(name="billing", model="gemini-2.5-flash", tools=[refund, lookup], **adk_callbacks(Client()))   # a denied call is skipped; the model sees the receipt
```

```python [Python]
# pip install agent-custody; the sidecar is `npx @agent-custody/receipts serve --config sdk.json`
from agent_custody import Client, PolicyDeniedError

client = Client("http://127.0.0.1:8788")
refund = client.wrap("stripe.refund", lambda args: stripe.refund(**args))
refund({"amount": 5000})   # decide, run, record; raises PolicyDeniedError on deny
```

:::

Then verify the receipt in the shell, or drop it on [/verify](/verify):

```bash
npx @agent-custody/receipts verify receipts/<id>.json --issuer-key keys/app.pub --log log.jsonl
```

Every adapter is on [the SDK page](/receipts/sdk) with what it enforces and what it only records. **To make a receipt evidence** a customer or auditor accepts, put [the gateway](/receipts/usage) in front of the tool and log to [a log run by someone else](/early-access): the receipt then carries a signed grant, a policy decision made outside the agent, and a tree head signed by a key you do not hold.

<Flow />

## The whole loop, in one file

<!--@include: ../../README.md#getting-started-->

**Where to go next**

- Enforce instead of record: put the gateway between the agent and its MCP tools. [The gateway](/receipts/usage)
- Hook an existing framework, or another language. [The interceptor SDK](/receipts/sdk)
- Write policies, for tools and for memory, with tested examples. [Policies](/receipts/policies), and what a verified receipt proves: [Verification](/receipts/verification)
- Put beliefs in the ledger. [State](/state/)
