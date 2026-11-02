---
title: Use cases
description: "Where a receipt earns its keep, by the kind of team running the agent: the call that matters, the policy that governs it, what the receipt proves, and who verifies it."
---

# Use cases

Every entry here follows the same shape, because the product does: the call that matters, a policy the gateway evaluates on facts it fetched itself, what the receipt proves, and who outside the team can verify it. Every policy below is checked against the evaluator by the test suite's rules, and four of the eight have a runnable example behind them. Where there is no example yet, it says so.

The pattern is the same everywhere. The gateway sits between the agent and the tool, in your infrastructure. Nothing about the agent changes. What changes is that the decision is made outside it, and that the record of the decision is signed by a key the agent does not hold and its hash goes to a tamper-evident log, where anyone who kept a checkpoint can detect a rewrite. See [what a receipt proves](/receipts/#what-a-receipt-proves-and-what-it-does-not) for the exact claims.

## Crypto wallets and on-chain agents

**The call.** An agent holding a session key signs a transaction: a swap, a transfer, a contract call. Once broadcast it cannot be withdrawn, and a wrong destination or a bad quote is money gone.

**The policy.** Only these contracts, under this amount, at a slippage the gateway checked itself against a quote the agent did not supply.

```cedar
permit(principal, action == Action::"wallet.send", resource)
when { ["0x7a25…router", "0xa0b8…usdc"].contains(context.args.to)
    && context.args.amount_usdc <= 250000000
    && context.facts.quote.slippage_bps <= 50 };
```

**What the receipt proves.** Which key authorized the agent and for how long, the exact call data the agent asked to sign, the quote the gateway fetched before deciding, and that the signature was issued only after the authorization was in the log. A refused transaction is a receipt too, with the reason.

**Who verifies.** The wallet's owner, a fund's administrator, an auditor, or a counterparty, with the public keys. The session key itself proves nothing about intent; the receipt does.

No runnable example yet; the gateway's REST upstream fronts a signing service the same way it fronts a payments API in [example 17](https://github.com/svayatta/agent-custody/blob/main/packages/receipts/examples/17-rest-upstream.ts).

## Exchanges and payment providers

**The call.** Withdrawals, payouts, refunds, limit changes: anything that moves customer money on an agent's say-so.

**The policy.** The customer's KYC state and remaining daily limit are fetched by the gateway, not asserted by the agent. The destination must be on the allow-list. Anything above a threshold has no permit for an agent at all and goes to two people.

```cedar
permit(principal, action == Action::"withdrawal.create", resource)
when { context.facts.customer.kyc == "verified"
    && context.facts.destination.allowlisted
    && context.args.amount <= context.facts.customer.daily_remaining };
```

**What the receipt proves.** That the withdrawal was within the customer's limit as the system of record stated it at that moment, to an allow-listed destination, authorized under a grant a named person signed, and committed to the log before the money moved. For the refused ones: that the agent tried, what it asked, and why it was stopped.

**Who verifies.** The compliance officer, the external auditor, the regulator, the customer disputing a payout. The [compliance mapping](/receipts/compliance) says which SOC 2, ISO 27001, and EU AI Act provisions each receipt answers.

Runnable: the home page's receipt is this case, a £50,000 refund refused before the provider, and [example 16](https://github.com/svayatta/agent-custody/blob/main/packages/receipts/examples/16-precommit.ts) shows the authorization logged before a refund is forwarded.

## E-commerce and marketplaces

**The call.** Refunds against orders, price changes on the catalogue, purchase orders to suppliers, inventory writes. Each is small; the volume is what makes a mistake expensive.

**The policy.** A refund only against a delivered order and never above its total. A price change inside a band. A supplier order only with a human approval the gateway can see.

```cedar
permit(principal, action == Action::"order.refund", resource)
when { context.facts.order.status == "delivered"
    && context.args.amount <= context.facts.order.total };
permit(principal, action == Action::"catalog.price_update", resource)
when { context.args.change_pct >= -10 && context.args.change_pct <= 10 };
permit(principal, action == Action::"supplier.order", resource)
when { context.facts.approvals.human_count >= 1 };
```

**What the receipt proves.** For every refund, the order state the gateway saw; for every price change, the band it stayed in; for every purchase order, who approved it. A month of agent activity becomes a ledger a finance team can sample and an auditor can verify, rather than a log the operations team keeps.

**Who verifies.** Finance, internal audit, a marketplace operator checking a seller's agent, a supplier disputing an order.

No runnable example yet; the shape is [example 17](https://github.com/svayatta/agent-custody/blob/main/packages/receipts/examples/17-rest-upstream.ts) with an order API as the upstream.

## Legal technology

**The call.** An agent reads documents across matters, drafts, and in some products files. Privilege, matter boundaries, and the duty to supervise what an AI did on a client's behalf are the whole job.

**The policy.** Read only within the matter the task names, and never a document marked privileged. Write only under drafts, and only citing the sources used. Filing has no permit for an agent: a lawyer does it, and the agent's draft receipts are attached.

```cedar
permit(principal, action == Action::"docs.read", resource)
when { context.facts.document.matter == context.args.matter
    && !context.facts.document.privileged };
permit(principal, action == Action::"draft.write", resource)
when { context.args.path like "drafts/*" && context.args has sources };
```

**What the receipt proves.** Exactly which documents the agent read for a draft and which it was refused, with the privilege flag as the document system reported it; which sources a draft cites; and which named lawyer's grant authorized the agent, for how long. That is the supervision record a regulator or an opposing party would ask for, produced by a key the agent does not hold.

**Who verifies.** The supervising partner, the client, the court, the regulator, opposing counsel in a dispute over what the AI saw.

No runnable example yet; the knowledge-base agent in [example 23](https://github.com/svayatta/agent-custody/blob/main/packages/receipts/examples/23-langchain-kb-agent.ts) is the same shape with a document store as the upstream.

## Agents that write code

**The call.** Merging a pull request and promoting a release. See [risk-tiered merges, with evidence](/blog/risk-tiered-merges-with-evidence) for the full case: low merges alone, medium needs a human the gateway can see, high is refused for any agent. Runnable in [example 24](https://github.com/svayatta/agent-custody/blob/main/packages/receipts/examples/24-agentic-cicd-merge-gate.ts).

## Knowledge bases and runbooks

**The call.** Reading and writing a shared knowledge base, wiki, or git-backed document store. Writes only under notes, citing a source; runbook edits refused. Runnable in [example 23](https://github.com/svayatta/agent-custody/blob/main/packages/receipts/examples/23-langchain-kb-agent.ts), with a [22-second film](/demo-langchain-kb.mp4).

## Customer support agents

**The call.** Refunds, credits, account changes on a customer's behalf. The policy limits the amount and requires the customer record the gateway fetched. The home page's receipt and [example 05](https://github.com/svayatta/agent-custody/blob/main/packages/receipts/examples/05-gateway.ts) are this case.

## Coding agents on your own repository

**The call.** Every shell command, file write, and tool call a Claude Code session makes. See [agent sessions in this repository](/custody).

## What every case has in common

The agent is unchanged. The gateway holds the credentials, fetches the facts, decides, and signs. The log holds hashes only. The verifier needs public keys and nothing else. And every policy above can run in observe mode first, recording what it would have refused without refusing anything, until the team is ready to turn it on.

The same gateway sits between agents that delegate to each other over A2A: it serves the remote agent's card at its own address, and every delegation is a receipted, policy-checked call that a refused task never reaches, as in [example 25](https://github.com/svayatta/agent-custody/blob/main/packages/receipts/examples/25-a2a-delegation.ts).

If your case is not here, the [FAQ](/faq) says what an integration looks like, and the quickest way to find out is a twenty-minute call: [contact](/contact).
