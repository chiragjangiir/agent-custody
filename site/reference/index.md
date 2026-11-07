# Reference

Every feature of agent-custody, how to use it, and the exact request and response of every function and endpoint. The narrative guides on [agent-custody.dev](https://agent-custody.dev/guide/getting-started) explain why; these pages say what goes in and what comes out.

## The pieces

| piece | package | what it is | reference |
| --- | --- | --- | --- |
| Gateway | `@agent-custody/receipts` | a process between the agent and its tools: checks the grant and the policy, forwards or denies, issues a receipt | [gateway](./gateway) |
| Door | `@agent-custody/receipts` | a reverse proxy in front of your own site or API: classifies every arrival, decides by policy per route, relays or refuses, issues a receipt | [door](./door) |
| SDK | `@agent-custody/receipts` | the same issuer inside the agent's process, for tools that are plain functions; adapters for the frameworks | [TypeScript SDK](./sdk-typescript) |
| Sidecar | `@agent-custody/receipts` | the SDK as a local HTTP API, for agents in any language | [sidecar](./sidecar) |
| Python | `agent-custody` on PyPI | the sidecar client, framework adapters, and the memory client | [Python](./python) |
| Claude Code | `@agent-custody/receipts` | a hook that records every tool call of a session | [Claude Code](./claude-code) |
| Log | `@agent-custody/receipts` | the transparency log: a file, or a server, or the hosted one; the client the gateway uses | [log API](./log-api) |
| Verifier | `@agent-custody/receipts` | checks a receipt, audits a log, monitors a log, exports a tenant | [verify and audit](./verify) |
| Hosted log | log.agent-custody.dev | tenants, plans, the portal, the API keys | [hosted](./hosted) |
| Memory | `@agent-custody/state` | the fact ledger and the memory server behind the gateway; write-through stores | [memory](./memory) |
| Explain, review, pack | `@agent-custody/state` | one action explained, a review page, a fact's custody pack, blast radius, evals, retention | [explain and packs](./state-tools) |
| Command line | both packages | every command and flag | [CLI](./cli) |

## Install

```bash
npm install @agent-custody/receipts @agent-custody/state
pip install agent-custody
```

The packages run on Node 22 or later and Python 3.10 or later. Nothing phones home; the only network calls are the ones you configure.

## Conventions on these pages

- **Request** and **Response** blocks are JSON exactly as sent and received. Fields marked *optional* may be omitted; fields marked *env* name an environment variable and never carry the secret itself.
- Every signed object is a [DSSE](https://github.com/secure-systems-lab/dsse) envelope: `{ "payloadType", "payload" (base64), "signatures": [{ "keyid", "sig" }] }`. The `keyid` is the SHA-256 of the signer's public key in SPKI DER, so a verifier matches keys without being told which is which.
- `provenance` on a receipt field is one of `attested` (signed by a key other than the issuer's), `observed` (the issuer saw it itself), or `claimed` (the agent said so). The [proof table](https://agent-custody.dev/receipts/#what-a-receipt-proves-and-what-it-does-not) says what each is worth.
- Money is integer minor units everywhere. Timestamps are ISO 8601, UTC.
