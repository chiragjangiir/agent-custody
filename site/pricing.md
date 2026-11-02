---
title: Pricing
---

# Pricing

Everything you run yourself, the gateway, the SDK, the ledger, the verifier, is open source under Apache-2.0 and costs nothing. What is priced is the hosted log: a transparency log run by someone who is not you, so your receipts can be accepted by people who do not trust you. It holds hashes, never receipts. The unit is appends, counted per calendar month.

| | Free | Team | Enterprise |
| --- | --- | --- | --- |
| **Price** | $0 | **$50 a month** | by conversation |
| **Appends a month** | 10,000 | 1,000,000 | no allowance |
| **Tenants** | one | one | as many as you need |
| **Log** | shared service, your own tenant, your own log id | the same | a dedicated log instance, your own signing key, your region |
| **Keys** | as many as you mint, revocable one by one | the same | the same, plus keys managed by your own operators |
| **Export** | everything, any time, with your key | the same | the same |
| **Audit trail** | every action on your tenant, visible in your export | the same | the same |
| **Support** | community, on GitHub | email, answer within two working days | a named contact, a stated response time |
| **Terms** | [early-access terms](/terms) | the same, plus payment terms | a signed agreement and a data processing agreement |
| **Witness** | none yet | none yet | run your own, or we help you find an independent operator |
| **Get it** | [register](https://app.agent-custody.dev/#register) | [register](https://app.agent-custody.dev/#register), then upgrade from the billing page | [write to us](/contact) |

## What 10,000 appends is

One append per receipt, one receipt per tool call, allowed or denied. An allowed call to a tool in `precommit` (every tool, in strict mode), or to a financial operation, uses two appends: the signed authorization before the call and the receipt after it. A worked week, with round numbers and one append per call:

| who | tool calls | appends a day | appends a month | plan |
| --- | --- | --- | --- | --- |
| one support agent | 40 tasks a day, 6 tool calls each, five days a week | 240 | about 5,000 | Free, with room: a pilot, not a toy |
| a fleet of ten of those | the same, ten agents | 2,400 | about 50,000 | Free runs out on Friday of week one; Team |
| a coding agent under the Claude Code hook | 300 tool calls a working day | 300 | about 6,500 | Free |
| a hundred agents at 240 a day | production | 24,000 | about 500,000 | Team, half used |
| more than a million a month | | | | Enterprise, or a dedicated log |

An append is a hash and a timestamp; the log never receives the receipt, so the count is the only thing that grows with you. The [portal](https://app.agent-custody.dev/) shows appends against the allowance by month.

## What is and is not promised

No plan carries an availability commitment yet. The log runs on one machine with no failover, and the design fails closed: when it is unreachable, a gateway withholds pre-committed calls rather than acting without evidence. That is stated on the [security questionnaire](/security) and will not change until the failover work is done, at which point the Team and Enterprise plans get a service level. Nobody on any plan is certified against SOC 2 or ISO 27001 by using this; the [compliance mapping](/receipts/compliance) says which of your controls the artefacts are evidence for.

## What happens at the allowance

An append past the month's allowance is refused with a clear message and the date it resets. The gateway behind it withholds pre-committed calls and financial operations, so they do not run. An ordinary tool call still runs, and its receipt waits in the gateway's outbox until the log takes it. Upgrade from the billing page and the next append lands. Nothing already logged is affected.

## Paying

Team is billed monthly by card through Stripe, from the [portal](https://app.agent-custody.dev/), and cancelled there too; the plan drops to Free at the end of the paid period and your log stays exactly where it was. We never see the card. Enterprise is invoiced.

## Why this price

Fifty dollars is what a design partner pays for a service whose operator is honest about its stage: real, running, monitored from outside, not yet redundant. It is not the enterprise price, which is a conversation about a dedicated log, a region, a witness, and a signed agreement.
