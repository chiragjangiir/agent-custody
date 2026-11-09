---
title: FAQ
description: Where the gateway sits, what a receipt contains, what reaches the hosted log, and how secrets and personal data are handled.
---

# Frequently asked questions

Answers about where the data goes. Everything here is checkable against the code and the [threat model](/receipts/threat-model); where something is not built yet, it says so.

## Is agent-custody a proxy between the LLM and my tools?

Between the agent and its tools, yes. Between the agent and the model, no.

The gateway is an MCP server that stands in front of your real tools. The agent's framework sends it tool calls; it checks the grant and the policy, forwards or denies, and issues a receipt. Prompts, completions, and the model's reasoning never pass through it, because the model traffic is not routed through the gateway at all. It sees a tool call only when the agent makes one.

The gateway runs on your machines. Nothing in it phones home.

The egress witness is a proxy too, for the connections a locked-down agent makes that are not tool calls. It relays them without TLS interception, so it records the destination, the times, and the byte counts, never what was sent. It sees nothing when lockdown is off, and it relays only HTTP. [Credential custody and egress lockdown](/guide/credential-custody) has the table of what it sees.

## What does a receipt contain? Is there personal data in it?

A receipt records the call as the tool saw it: the tool name, the arguments the agent sent, the facts the gateway fetched itself, the policy decision with the policy's hash, the grant that authorized the agent, and, for a call that ran, the result the tool returned. Every field is labelled `attested`, `observed`, or `claimed`.

So yes: if the agent passes a customer's email as an argument, or the tool returns an account record, that is in the receipt. A receipt is evidence of what happened, and the arguments and the result are what happened. Treat the receipts directory the way you treat the tool's own logs: it lives on your infrastructure, under your retention rules, and it never leaves unless you send it.

## What reaches the hosted log?

For each receipt, thirty-two bytes: the SHA-256 of the signed envelope. With it, the time it arrived, your tenant id, and the hash of the API key that sent it. The log stores that, signs tree heads over it, and publishes checkpoints.

This is enforced on the server, not left to configuration. The hosted log runs in hash-only mode and refuses a full receipt at append with a 400. The [security questionnaire](/security) says so, and the [privacy page](/privacy) lists everything the service holds. A hash of a signed receipt reveals nothing about its contents and cannot be linked to a person without the receipt itself.

The same hash is what a verifier checks: the inclusion proof ties the receipt you hold to the leaf the log holds. The log never needs the receipt to prove it was there.

## Does the gateway see my API keys and secrets?

It holds the credentials it needs to reach your tools, the same way any process that calls them does, and it reads them from the environment at startup: an upstream's header token, the log's API key, a webhook secret. They are never written into the configuration file, never written into a receipt, and never sent anywhere but to the service they belong to.

What a receipt does record is what the agent sent as arguments. If an agent passes a secret as a tool argument, it is in the receipt, exactly as it would be in any log of that call. The fix is the same as for any logging: do not hand secrets to agents as arguments; give the tool its credentials and let the agent ask for the action.

## Can I keep arguments and results out of receipts and track actions only?

Yes, per tool and per field. A `capture` rule in the gateway or SDK config says what the receipt file carries of each tool's arguments, result, and facts: `clear` records the value, `digest` withholds every field not listed as clear and leaves a salted sha256 commitment in its place, the salt kept by the issuer and never in the receipt, and `encrypted` does the same and carries the value and the salt encrypted under a 32-byte key you hold. The rule is applied by the issuer to the whole signed statement: once a side is private, everything the receipt carries that is not structural (the other sides, policy error messages, a thrown message, the result's metadata, a provider delivery's body, an upstream's signed envelope) is withheld too, and the digests over withheld values are salted from their salts, so nobody can confirm a guess of a withheld value from the receipt. The policy still decides on the real values and the signature and digests are still over the whole call; a reviewer verifies the receipt as committed without the key, and in full once you reveal the values with `agent-custody reveal` or give the verifier the key. The [usage guide](/receipts/usage#private-evidence) has the rule and its limits.

What already sends actions only: the exporters. The OpenTelemetry and Splunk exporters emit one span or event per receipt with the receipt id, tool, agent, principal, decision, policy digest, argument digest, and log position. No arguments, no results. A trace backend or a SIEM sees that a refund was denied and which policy denied it, not the customer's details.

## What does an integration look like, concretely?

For an in-process framework, three things: a key and a config file for the agent's process, a Cedar policy, and the adapter for your framework. A LangChain agent on `createAgent` with two tools and a policy that allows writes under `notes/` only is [example 23](https://github.com/svayatta/agent-custody/blob/main/packages/receipts/examples/23-langchain-kb-agent.ts), about a hundred lines including the knowledge base it writes to; a [22-second film](/demo-langchain-kb.mp4) shows it run, refuse a runbook edit, and verify every receipt. For evidence a stranger accepts, the gateway goes in front of the tool instead, with no change to the agent: it is an MCP server.

## Our agents open more pull requests than humans can review. Does this help?

Yes, in the way SOC 2 and ISO 27001 allow. Neither standard says a human must read every change; they say changes must be authorized, tested, and approved under a defined process, with evidence. Risk-tiered review is such a process, if the tier decision is itself evidence rather than a pipeline's own say-so. With the gateway in front of the git host, the tier is a policy evaluated on facts the gateway fetches itself, the diff, the gate results, who approved, and every merge and refusal is a signed receipt pre-committed to the log. Low-risk changes merge on the agent's authority with a receipt; medium ones need an approval the gateway can see; high-risk ones are refused for any agent. The receipts are the change-management evidence, per change, verifiable without us. [Example 24](https://github.com/svayatta/agent-custody/blob/main/packages/receipts/examples/24-agentic-cicd-merge-gate.ts) runs the whole gate against a stand-in git host with no API key; the [compliance mapping](/receipts/compliance#agent-made-changes-the-merge-gate) says which controls it answers.

## Does it cover agents that delegate to other agents?

Yes, over A2A. The gateway speaks the protocol itself: `agent-custody gateway --a2a` serves the remote agent's card at its own address, so a Google ADK `RemoteA2aAgent`, or any A2A client, is pointed at the gateway and every delegation becomes a policy-checked call with a receipt, a refused one coming back as a rejected task that the remote agent never saw. The remote agent's card is a fact the gateway fetches itself, so the policy decides on the agent it is actually talking to, not on the one the caller claims; [example 25](https://github.com/svayatta/agent-custody/blob/main/packages/receipts/examples/25-a2a-delegation.ts) runs it against a stand-in agent.

## Can I run it without it blocking anything?

Yes. Set `"mode": "observe"` in the gateway or SDK config. Every call the grant allows goes through, and each receipt records the decision the policy would have made, marked `enforced: false`. You run it against real traffic, read the receipts that say "would have been denied", fix the policy, and switch to enforce. The verifier accepts an observe-mode receipt and says so in its report; a receipt that claims a deny was enforced beside a call that ran fails verification, so the mode cannot be hidden after the fact.

## Why trust the enforcer?

Three reasons, none of them "trust us". The gateway and the verifier are open source under Apache-2.0; read them. Policies are Cedar, the authorization language AWS built and formally verified, evaluated by its own engine, or Rego, compiled by Open Policy Agent's own `opa build` or answered by an OPA server you run; we do not interpret policies ourselves. And every receipt decided by a policy file carries the SHA-256 of the policy text that decided it, so a verifier knows exactly which rules were in force (an OPA server's receipt names the bundle revisions the server reported instead), and the receipt format is published with [conformance vectors](/receipt/vectors) any second implementation must pass. The verifier's report also says what a receipt does not prove: an SDK receipt is the agent's own word, tamper-evident after issue, and the report prints that sentence.

## How fast is it?

Medians measured on an Apple-silicon laptop under Node 22, with [the script in the repository](https://github.com/svayatta/agent-custody/blob/main/packages/receipts/scripts/bench.ts), 6 October 2026: a policy decision 0.10 ms; a full gateway call, including the fact lookup, the decision, a stand-in upstream on the same machine, and the receipt signed and logged, 0.52 ms; verifying a receipt 0.14 ms. A receipt is about 5.7 KB of JSON; the hosted log receives 32 bytes of it. Your network adds whatever it adds, and the hosted log is on the path only for consequential calls, where a refusal withholds the call rather than losing the evidence.

## What stays private?

The receipt, which holds the arguments and the result, never leaves your machines unless you send it. The hosted log holds a hash per receipt and refuses anything more. The policy text stays with you; the log sees its digest, and you choose whether to publish named versions. A verifier you hand a receipt to sees everything in that receipt and nothing else: there is no account, no query to us, and no other tenant's data in the proof.

## Does the gateway call any AI service?

No. Policy evaluation is Cedar, or Rego compiled from a file, evaluated in the gateway's process. The only network calls it makes are the ones you configure: to your own tools, to the log you name, to an OPA server if you choose one, and to the exporters you turn on. It runs offline against local tools and a local log file.

## What about prompt injection?

The gateway does not read prompts, so it cannot detect an injection. It does not need to. An injection that succeeds makes the agent call a tool it should not; the gateway evaluates that call against the policy and the facts it fetched itself, and denies it before the tool hears anything. The denial is a receipt with the arguments the agent tried, which is what your investigation wants. The film on the home page shows exactly this case.

## Who can read the portal and the admin page?

The portal at app.agent-custody.dev holds your account, your tenant, hashed API keys, usage counts, and the policy versions you chose to publish. The admin page is ours, behind one secret, and shows tenants, usage, and the contact details people gave at registration. Neither holds a receipt. The [privacy page](/privacy) is the full list.

## Can I run all of it myself?

Yes. The gateway, the SDKs, the ledger, and the verifier are Apache-2.0 and need no account. The log server is the same container we run, with a compose file and Kubernetes manifests in the [deploy directory](https://github.com/svayatta/agent-custody/tree/main/deploy). What you cannot run for yourself is a log operated by someone who is not you; that is the only thing the hosted service is.

## How do I delete what you hold?

Your tenant's leaf hashes, on written request; it is irreversible and breaks the inclusion proofs in your own receipts, which the runbook explains. Your account and contact details, on request. Receipts you never sent us, so there is nothing of them to delete here. For beliefs an agent recorded in the ledger, the state package's certified forget removes a value and issues a receipt saying what each store answered.
