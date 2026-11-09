---
title: Advanced
description: "Everything beyond the Claude Code hook: the gateway, grants and Cedar policy, the transparency log, the state package, the hosted log, and the other frameworks and languages."
---

<script setup>
import Demo from './.vitepress/theme/Demo.vue'
</script>

# Advanced

The front page covers one job: stop a coding agent such as Claude Code from running destructive commands, and keep a signed record that a reviewer can check. This page holds the rest of the product. Each section says what the part does and links to the page that explains it.

## Contents

- [The two ways to record a call](#the-two-ways-to-record-a-call)
- [Product overview film](#product-overview-film)
- [The problem](#the-problem)
- [The refund demo](#the-refund-demo)
- [How it works](#how-it-works)
- [Policies](#policies)
- [Receipts compared with logs and traces](#receipts-compared-with-logs-and-traces)
- [Use cases](#use-cases)
- [Parts, one by one](#parts-one-by-one)
- [Other frameworks and languages](#other-frameworks-and-languages)
- [Hosted log, trust, and the specification](#hosted-log-trust-and-the-specification)

## The two ways to record a call

The Claude Code hook runs in the agent's own process. It can deny a call that the agent makes through its tools, and it writes a receipt. The receipt is the agent's own report: every field is `claimed`.

The gateway is a separate process between the agent and its tools. It checks a grant that a person signed, evaluates a policy on facts that it fetches itself, forwards or denies the call, and issues a signed receipt either way. The agent cannot skip it for the tools behind it. A credential in the agent's own environment still goes around it. The [threat model](/receipts/threat-model) lists what each part defends.

- [What each piece is for, and when you need it](/guide/pieces): the table of parts, with the failure that each one prevents.
- [Getting started](/guide/getting-started): the SDK path and the gateway path.
- [The gateway](/receipts/usage) and [configuring the gateway](/receipts/configuration).
- [Architecture](/guide/architecture) and [deployment](/guide/deployment).

## Product overview film

A 30-second narrated film with captions. Priya, an AML lead, tells the story. The AML alert and the policy in the film are illustrative.

<video controls playsinline preload="none" poster="/promo-poster.jpg" width="1080" height="1080" style="display: block; width: 100%; max-width: 640px; height: auto; aspect-ratio: 1 / 1; margin: 0 auto; border-radius: 12px;" aria-label="A 30-second narrated film: an AI agent clears an AML alert and its own log can be edited. Replayed through agent-custody, the same call is denied, the refusal is signed, and an auditor verifies it offline.">
  <source src="/promo.mp4" type="video/mp4" />
  <track kind="captions" src="/promo.vtt" srclang="en" label="English" />
</video>

| time | chapter | what it shows |
| --- | --- | --- |
| 0:00 | Tuesday | An AI agent clears an AML alert. The auditor asks why. |
| 0:06 | The log | The only record is the agent's own log, and anyone can edit it. |
| 0:12 | Tuesday, replayed | The policy checks the same call before it runs. The call is denied, and the refusal is signed and logged. |
| 0:19 | The audit | The auditor verifies the receipt offline, with public keys. A changed word makes the check fail. |
| 0:25 | The close | "Now I don't explain what our agents did. I prove it." |

## The problem

The record of an agent's actions is the log that its own process wrote. Nobody outside the team can check it.

- **Made-up authority.** The agent refunds £50,000. Its log says the customer asked. Nobody signed anything that allowed it.
- **A log that can be edited.** The team that ran the agent holds the log. After the incident, the entry that matters is gone or different.
- **Evidence nobody else can check.** Traces sit in a vendor account. The auditor gets a screenshot and a promise.

## The refund demo

`bun run demo` runs a support agent against a test Stripe server. Each call writes a signed receipt to your disk. Then the demo verifies the receipts and edits one.

```bash
git clone https://github.com/svayatta/agent-custody && cd agent-custody && bun install && bun run demo
```

It needs Node 22 and Bun. It runs four calls through the gateway, three refunds and a payout, and verifies each receipt.

<Demo />

## How it works

Every call through the gateway goes through the same five steps.

1. **Authorize.** A person signs a grant: which agent, which tools, for how long.
2. **Gate.** The gateway fetches the facts itself, evaluates the policy, and forwards or denies.
3. **Record.** One signed receipt per call: who authorized it, what was asked, what was checked, what happened.
4. **Log.** The receipt's hash goes to a Merkle log with signed heads. A rewrite is detectable by anyone who kept a checkpoint.
5. **Verify.** Anyone with the public keys checks a receipt, in the shell or the browser, offline.

<Flow />

## Policies

Policies are written in Cedar and evaluated on facts that the gateway fetches itself. Each receipt records the policy digest. Nine more policies, each run by the test suite, are in [Writing policies](/receipts/policies).

**Limits.** A ceiling per call, in minor units. No floats, no rounding.

```cedar
permit(principal, action == Action::"stripe.refund", resource)
when { context.args.amount <= 100000 };
```

**Facts, not claims.** The gateway looks the customer up itself before it decides. The agent's own arguments are never enough.

```cedar
permit(principal, action == Action::"stripe.refund", resource)
when { context.facts.customer.verified
    && context.args.customer_id == context.facts.customer.id };
```

**Allowed targets.** A short list of accounts, hosts, and paths. Anything else is refused before it leaves.

```cedar
permit(principal, action == Action::"payout.send", resource)
when { ["acct_treasury", "acct_payroll"].contains(context.args.to) };
```

**Human approval.** A larger change needs a person that the gateway can see approved it, in the system of record.

```cedar
permit(principal, action == Action::"pr.merge", resource)
when { context.facts.checks.all_green
    && context.facts.reviews.human_count >= 1 };
```

**Boundaries.** Where an agent may write, and what it must say when it does.

```cedar
permit(principal, action == Action::"kb.write", resource)
when { context.args.path like "notes/*"
    && context.args has source };
```

**Evidence before effect.** Name a tool as consequential, and the authorization is logged before the call is forwarded. If the log refuses, nothing happens.

```json
"precommit": ["stripe.refund", "pr.merge", "deploy.promote"]
```

## Receipts compared with logs and traces

Receipts export to OpenTelemetry and Splunk, so you keep your current tools. The exports are in [the SDK reference](/reference/sdk-typescript) and [the gateway reference](/reference/gateway). Tutorials 18 and 19 run them.

| | Application log | Trace | Gateway receipt |
| --- | --- | --- | --- |
| Written by | the agent's process | the agent's process | a gateway, with its own key |
| Allowed or denied before the tool ran | no | no | yes, and a denial is a receipt |
| Who authorized it | not recorded | not recorded | the grant a person signed |
| A rewrite is detectable | no | no | yes, by anyone who kept a checkpoint |
| Who can check it | log access holders | the tracing account | anyone with the public keys |

Measured on a laptop (lower is better):

| what | median |
| --- | --- |
| a policy decision | 0.10 ms |
| a full gateway call | 0.52 ms |
| verifying a receipt | 0.14 ms |
| a receipt (the log gets 32 bytes) | 5.7 KB |

Medians, Apple silicon, Node 22, from [scripts/bench.ts](https://github.com/svayatta/agent-custody/blob/main/packages/receipts/scripts/bench.ts). You can run it.

## Use cases

Each use case has a runnable example, or says that it has none.

- **Payments and refunds.** A refund within a limit, for a customer that the gateway verified. [The refund demo](#the-refund-demo), and [example 17: a REST upstream](https://github.com/svayatta/agent-custody/blob/main/packages/receipts/examples/17-rest-upstream.ts).
- **Agents that write code.** Risk-tiered merges, and change-management evidence for SOC 2 and ISO 27001. [Risk-tiered merges, with evidence](/blog/risk-tiered-merges-with-evidence), and [example 24: the merge gate](https://github.com/svayatta/agent-custody/blob/main/packages/receipts/examples/24-agentic-cicd-merge-gate.ts).
- **Knowledge bases.** Read anything, and write just under `notes/`, with a source. [A 22-second film](/demo-langchain-kb.mp4), and [example 23: LangChain](https://github.com/svayatta/agent-custody/blob/main/packages/receipts/examples/23-langchain-kb-agent.ts).
- **Your own repository.** Every Claude Code shell command, file edit, and MCP tool call as a receipt. [This repository](/custody), and [the hook](/reference/claude-code).

More, by kind of team, each with its policy: [Use cases](/use-cases).

## Parts, one by one

| part | what it does | page |
| --- | --- | --- |
| The table of pieces | For each part, the failure it prevents and when you need it | [What each piece is for](/guide/pieces) |
| Tutorials | One runnable example for each aspect of the code, run by the test suite | [Tutorials](/receipts/tutorials) |
| The state package | A fact ledger: every belief of an agent cites the receipt that caused it, and a wrong belief is retracted, not deleted | [The fact ledger](/state/) |
| Blast radius | From a bad belief to every call and later belief that came from it | [The fact ledger](/state/) |
| Quarantine, certified forget, retention, legal hold | Governed memory for personal data | [The fact ledger](/state/) |
| Extra memory adapters | Write-through to Mem0 and Zep, so the ledger sits under a store that you already run | [The fact ledger](/state/) |
| Single sign-on and roles | An enterprise tenant signs in through its own identity provider, with roles (`owner`, `admin`, `reviewer`, `readonly`) | [Hosted log and portal](/reference/hosted), [tutorial 31](/receipts/tutorials) |
| The consoles | The gateway console (config, tools, receipts with a verdict each, policy replay, grant revocation) and the state review console | [The gateway console](/receipts/console), [Explain, review, packs](/reference/state-tools) |
| Payload-bound approvals | One or two approvers' keys sign the exact action before it runs | [Approvals](/receipts/approvals) |
| Financial operations | Durable operation ids, provider idempotency keys, budget reservations, and reconciliation | [Financial operations](/receipts/financial-operations) |
| Completeness | Match the provider's own records against verified receipts, to find actions taken outside the gateway | [Completeness](/receipts/completeness) |
| The chain anchor | Commits the log's checkpoints to Ethereum from a published address. It has not run on mainnet for the hosted log yet | [Anchoring](/receipts/anchoring) |
| The witness | A second signer that countersigns the log's checkpoints. The code exists. No independent witness runs yet | [Verifying a receipt](/receipts/verification), [the hosted log](/early-access) |
| Splunk and OpenTelemetry exports | One event or span for each receipt, and the collector is never on the evidence path | [Tutorial 18 and 19](/receipts/tutorials), [the SDK reference](/reference/sdk-typescript) |
| What the evidence satisfies | Which artifact answers which SOC 2, ISO 27001, EU AI Act, and UK GDPR requirement | [Compliance](/receipts/compliance) |

## Other frameworks and languages

The Claude Code hook has the same input and output as the Claude Agent SDK, so one handler serves both. These frameworks have an adapter:

| framework | how | where |
| --- | --- | --- |
| Any MCP host | the gateway as an MCP server | [The gateway](/receipts/usage) |
| OpenAI Agents SDK | `wrapTools` | [Getting started](/guide/getting-started) |
| LangChain, LangGraph | `issuer.wrap` and a callback handler | [Getting started](/guide/getting-started) |
| Vercel AI SDK | `wrapTools` | [Getting started](/guide/getting-started) |
| Google ADK | tool callbacks | [Getting started](/guide/getting-started) |
| OpenClaw | the `before_tool_call` hook | [The SDK page](/receipts/sdk) |
| DeepSeek Harness, Hermes, CrewAI | a plugin or an adapter | [The SDK page](/receipts/sdk), [the Python client](/python/) |
| Python | the Python client of the sidecar | [The Python client](/python/) |
| Go, Java, Rust | the HTTP sidecar | [The sidecar](/receipts/sdk#other-languages-the-sidecar), [the client examples](https://github.com/svayatta/agent-custody/tree/main/packages/receipts/examples/languages) |

## Hosted log, trust, and the specification

- [Pricing](/pricing), [the hosted log](/early-access), and [the security questionnaire](/security).
- [FAQ: where the data goes](/faq), [privacy](/privacy), [terms](/terms), and [contact](/contact).
- [Verify a receipt in the browser](/verify). Nothing is uploaded.
- [Receipt v0.2](/receipt/v0.2) and [the conformance vectors](/receipt/vectors).
- [Threat model](/receipts/threat-model) and [what the evidence satisfies](/receipts/compliance).
- [Writing](/blog/) and [the changelog](/changelog).
- [Agent sessions in this repository](/custody).
