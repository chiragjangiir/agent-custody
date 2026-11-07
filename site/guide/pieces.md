# What each piece is for, and when you need it

<!--@include: ../../README.md#pieces-->

## What you are trusting

| setup | the record is | who could still rewrite it |
| --- | --- | --- |
| SDK in the agent's process | self-reported, every field `claimed` | the agent's own process |
| gateway, local log | observed outside the agent, tamper-evident to anyone holding a copy | the operator, who holds the key and the file |
| door in front of your own site or API | observed outside the arrival; who the arrival was is attested only when it presented a grant, else claimed | the operator, as for the gateway; the log choices below apply the same way |
| gateway, log run by someone else | tree heads signed by a key the operator does not hold | the log's operator, with yours |
| the same, with a witness | checkpoints countersigned by a second signer nobody in the chain controls | both operators and the witness, together |
| the same, anchored on a chain | checkpoints committed to Ethereum, or another EVM chain, from a published address | the log's operator, only for what no anchor covers yet |

The full list of claims, who can check each, and against whom, is the [proof table](/receipts/#what-a-receipt-proves-and-what-it-does-not). What the gateway does not cover is on the [deployment page](/guide/deployment#what-the-gateway-does-not-cover). A hosted log is [running and taking tenants](/early-access).
