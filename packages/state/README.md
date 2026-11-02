# @agent-custody/state

Governed memory for AI agents. Not a vector store: a ledger of facts where every write cites the receipt that caused it, carries valid time and transaction time, and can be superseded or retracted without losing what the agent believed at any earlier moment.

Retrieval stays with whatever store you already use. This package owns provenance, time, and undo.

## Getting started

```bash
npm install @agent-custody/state           # or bun add, pnpm add
```

Published on npm as [`@agent-custody/state`](https://www.npmjs.com/package/@agent-custody/state): compiled JavaScript with type declarations, Node 22 or later, Apache-2.0.

```ts
import { Ledger } from "@agent-custody/state";

// a JSONL file, a .sqlite path, or "postgres://…" with the pg package installed; the ledger is asynchronous
const ledger = new Ledger("./state/ledger.jsonl");
const a = await ledger.assert({ subject: "acct:42", predicate: "plan", value: "pro", space: "org", actor: "agent:support", source: { receiptId } });
await ledger.assert({ subject: "acct:42", predicate: "plan", value: "enterprise", space: "org", actor: "agent:sales", supersedes: a.fact.factId });
await ledger.retract({ factId: a.fact.factId, actor: "user:admin", reason: "poisoned by a tool result" });
await ledger.asOf({ validAt: "2026-09-01T00:00:00Z", txAt: "2026-09-01T00:00:00Z" });
```

Runnable examples, all executed by the test suite. [10-support-recovery.ts](examples/10-support-recovery.ts) corrects stale benefits and compensates a simulated credit after a wrong-plan incident, with verified evidence. [09-repair.ts](examples/09-repair.ts) loses a ledger append after a store took the write, then finds and removes the orphan entry with `memory.repair`. [08-review-console.ts](examples/08-review-console.ts) makes a refund through the gateway, finds it by transaction and customer, and exports an offline case file that verifies independently. [07-incomplete-evidence.ts](examples/07-incomplete-evidence.ts) makes the refund of example 06 private under a capture rule: blast radius without the customer's key lists the refund as INCOMPLETE rather than leaving it out, and with the key finds it. [06-actions-on-beliefs.ts](examples/06-actions-on-beliefs.ts) puts memory and a payments API behind one gateway and finds the refund in a belief's blast radius. [05-blast-radius.ts](examples/05-blast-radius.ts) walks from a retracted belief to everything that relied on it. [04-evals.ts](examples/04-evals.ts) scores the ledger and a naive store on the same memory incidents. [03-memory-behind-the-gateway.ts](examples/03-memory-behind-the-gateway.ts) runs the memory server as the gateway's upstream. [01-ledger.ts](examples/01-ledger.ts) walks through a wrong write and its undo. [02-receipt-to-belief.ts](examples/02-receipt-to-belief.ts) runs the whole loop with the receipts package: a tool call gets a signed receipt, the receipt is verified, the belief taken from it is recorded citing the receipt, and later retracted. Run them with `node examples/<file>` from this directory, after `bun run build` at the repository root.

For a real model choosing its own tools, run the opt-in [Codex support recovery demo](../receipts/docs/codex-recovery.md). Headless Codex handles a support request against incorrect CRM memory; an operator then reviews and approves recovery. It uses your Codex login and simulated billing. The regular test suite stays offline.

## The memory server

The ledger as MCP tools, meant to run as the upstream of the receipts gateway. Behind the gateway, every write and read is checked by the Cedar policy and gets a signed receipt, and two things reach this server in the call's `_meta` that no caller can supply: the receipt id, which becomes the fact's `source`, and the agent from the signed delegation grant, which becomes the fact's `actor`. A caller's own claims about either are ignored.

```bash
agent-custody-memory serve --ledger ./ledger.jsonl        # over stdio; refuses calls that did not come through the gateway
```

In the gateway's config, the memory server is the upstream, and the grant names the memory tools as scopes:

```json
{ "upstream": { "command": "agent-custody-memory", "args": ["serve", "--ledger", "/abs/path/ledger.jsonl"] }, ... }
```

| tool | does | policy sees |
| --- | --- | --- |
| `memory.write` | records a belief in a space, optionally superseding an earlier fact | `context.args.space`, `subject`, `predicate`, `value` |
| `memory.read` | the facts believed at a moment, by space, subject, predicate, valid time, transaction time | the query |
| `memory.confirm` | lifts a quarantined fact to attested; accepted only through the gateway | `factId` |
| `memory.retract` | undoes a belief, keeping it visible to questions about the past | `factId`, `reason` |
| `memory.forget` | erases the value from the ledger and every store, keeping the digest; the receipt is the certificate | `factId`, `reason` |
| `pack` (CLI) | one fact's history, receipts, holds, blast radius, and forget certificate as one signed artefact, verifiable offline | |
| `memory.hold`, `memory.release` | legal hold: while it stands the fact cannot be forgotten by request or sweep | `factId`, `reason` |
| `memory.sweep` | retention: forget what was learned before an instant, in a space or all, skipping held facts, reaching every store | `before`, `space`, `reason` |
| `memory.repair` | finds the store entries that the ledger has no fact for, stored before a cutoff, and removes them once they are older than a cutoff; see [Write order and repair](#write-order-and-repair) | `reason`, `before` (earlier cutoff only) |
| `memory.get` | one fact by id in any state, for the gateway's policy lookups | `factId` |
| `memory.history` | every event that touched a fact, a repair of an orphan entry included | `factId` |

**Quarantine.** Every fact carries a provenance: `claimed`, `attested`, or `verified`. A write that came through the gateway is `attested`: its actor is the agent named in a human-signed grant and its receipt exists. A write that arrived any other way is `claimed`, and claimed facts are quarantined: `memory.read` leaves them out unless the caller asks for `includeClaimed`, and the policy can refuse that. `memory.confirm`, accepted only through the gateway, lifts a claimed fact to attested with its own receipt and transaction time, so "was this fact still in quarantine on Tuesday" is answerable. A tool result an SDK-only agent wrote down cannot become something the rest of the fleet believes until an attested party says so. Over stdio the server has one client; shared over HTTP, below, gateways and direct writers feed one ledger and quarantine does its job.

**Value-level quarantine.** An attested write still carries whatever value the agent chose to write. When the agent can say where a value came from, the gateway's own observation decides. A `memory.write` may name `evidence: { fact, path }`, a fact the gateway fetched itself for this call through its fact-lookup mechanism (a CRM record, say) and optionally a field in it. The memory server compares the value with the observation: equal, and the fact is written as `verified`, the third provenance level, where both the actor and the value are vouched for by something other than the agent; different, and the write is refused. A policy can require evidence for a space (`context.args has evidence`), and `memory.read` with `requireVerified` returns only verified facts. The test suite runs this with a CRM lookup behind the same gateway as the memory server.

**Policy over the fact being changed.** The gateway can look up the fact a write supersedes or a retraction targets before deciding, through its fact-lookup mechanism and the `memory.get` tool, and the policy then sees that fact's space, actor, and provenance as observed facts. This is the second half of trust tiers: a self-reported note in the org space can be superseded by anyone the grant allows, while an attested org fact cannot be displaced or retracted except by whoever the policy names. In the gateway config:

```json
"facts": [
  { "name": "target", "tool": "memory.get", "args": { "factId": "$args.supersedes" }, "forTools": ["memory.write"], "optional": true },
  { "name": "target", "tool": "memory.get", "args": { "factId": "$args.factId" }, "forTools": ["memory.retract"] }
]
```

```cedar
forbid(principal, action in [Action::"memory.write", Action::"memory.retract"], resource)
when { context.facts has target && context.facts.target.space == "org" && context.facts.target.provenance == "attested" };
```

The lookup for writes is optional, so a write that supersedes nothing needs no lookup; the one for retractions is required. The denial receipt records the fact the policy saw, observed by the gateway. The test suite runs exactly this configuration.

**Attested executions.** Started with `--key memory.key`, the server signs every result for the receipt the gateway is issuing. A verifier given `memory.pub` then reports the execution of each memory call as attested by the memory server, not only observed by the gateway; the test suite verifies a write this way.

**Shared over HTTP.** `agent-custody-memory serve --ledger ./ledger.jsonl --http --port 8790 --token-env MEMORY_TOKEN --allow-direct --direct-token-env MEMORY_DIRECT_TOKEN` serves the same tools over Streamable HTTP, so several gateways, one per agent host, and, with `--allow-direct`, SDK-only agents share one ledger. The two kinds of caller hold different tokens, and the token decides what the server believes: a gateway's call carries the receipt id, the agent, and the facts the gateway observed in its `_meta`, and that is what makes a write attested or verified; a direct writer's `_meta` is dropped before the server reads it, so it can claim a fact and never attest one, whatever its call says. Never give a direct writer the gateway's token. That is the deployment quarantine was built for: writes arriving through a gateway are attested, writes arriving directly are claimed and hidden until a gateway confirms them, and the ledger tells them apart. A gateway reaches it with `"upstream": { "url": "http://127.0.0.1:8790/mcp", "tokenEnv": "MEMORY_TOKEN" }` in its config. The server does not start over HTTP without the gateway token, because without it any caller that reaches the port could pass as a gateway. The test suite runs exactly this: one gateway writer, one direct writer, one ledger. SIGINT or SIGTERM closes the server and the ledger, so a container runtime or systemd stops it cleanly; the review console does the same. The server stops listening, closes idle connections at once, and lets a request in flight finish. After 3 seconds it cuts the connections that remain, for example a request whose body never arrives. The server opens no GET stream (it answers GET with 405, which the gateway's client accepts), so a connected gateway does not hold the stop.

[Writing policies](../receipts/docs/policies.md#policies-for-memory) in the receipts guide has six tested policies for the memory tools, from confining an agent to its team's space to a complete support-agent policy. Trust tiers are Cedar policies over the space and, through `includeClaimed`, over quarantine: `permit(principal, action == Action::"memory.write", resource) when { context.args.space == "team:support" };` lets this agent write team memory and nothing else. A read's receipt carries, as `observed`, the exact facts returned, so the ids the agent relied on are already on the record.

`--allow-direct` lets the server take calls without a gateway; then `source.receiptId` is null, `actor` is whatever the caller said, recorded as such, and anything the caller puts in `_meta` is ignored. Over stdio the one client is either the gateway or a direct writer, and `--allow-direct` says which: a gateway must never spawn the server with `--allow-direct`. [examples/03-memory-behind-the-gateway.ts](examples/03-memory-behind-the-gateway.ts) runs the whole loop, including a denied write and a retraction that cites its own receipt.

## Certified forget

"Certified" means the receipt certifies what was done, not that the value exists nowhere. What forget reaches is the ledger and the stores with adapters, and it reports what each of them answered. It does not reach caches, a model's context window, application logs, replicas, backups, warehouses fed by export, or any store without an adapter. On Postgres the erased row image stays in the table until the store's `VACUUM FULL` runs, which it does after each forget unless told not to ([the ledger](#the-ledger)). Say all of that plainly to whoever is relying on it, and read the per-store status in the result before calling anything gone.

A deletion demand is different from a correction. Retract keeps the record; forget erases the value. `memory.forget` removes the fact's value from the ledger file itself, stops believing the fact, and removes it from every store behind the server. What it keeps in place of the value is a choice, recorded on the event as `digestKind`: a plain `sha256` of the value, which lets the ledger prove what it erased but is guessable for short values such as an email by anyone holding the file; an `hmac-sha256` under a forget key the server holds outside the file (`serve --forget-key-env NAME`), which proves the same to anyone shown the key and nothing to anyone else; or `none`, with `keepDigest: false`, for the case where counsel wants nothing derived from the value retained. Use the keyed form unless you have a reason not to. The result says exactly what happened: erased from the ledger, removed from which stores, still held by which, with the digest, the actor, and the reason.

**Retention and legal hold.** `memory.sweep` forgets every fact the ledger learned of before an instant, in one space or all, and removes each from every store; it is retention as a receipted call, with the receipt as the record of what was erased. Retention windows live in the server: `serve --retention 'org=P365D,team:*=P90D,user:*=P30D'`, ISO 8601 durations by space pattern, and a sweep with no `before` uses them per space. To run it on a schedule without a daemon, `agent-custody-memory sweep --via retention-gateway.json --reason "quarterly retention"` spawns that gateway and calls `memory.sweep` through it, so the sweep runs as the principal named in the gateway's grant, a retention job with the single scope `memory.sweep`, and its receipt records when retention ran, by whom, what it erased, and what a hold kept. Any cron, systemd timer, or CI schedule drives that one command. `memory.hold` puts a legal hold on a fact: while it stands, neither a deletion request nor a sweep can forget it, and `memory.release` lifts it. Holds and releases are events with actor, reason, and receipt, so the history of a fact shows the hold as plainly as the write. `agent-custody-memory sweep --ledger ... --before ... --reason ...` runs retention on the ledger file alone, for ledgers with no stores behind them.

**Removal is verified, not assumed.** A delete by id and a search index catching up are different moments. After every retraction, forget, or sweep, the server asks each store's own search whether the fact still surfaces, a few times with backoff, and records the outcome per store in the result and so in the receipt: `verified` (the store's search no longer finds it), `stillIndexed` (it still does, after the retries), `unverified` (the store cannot be asked, or the adapter has no search), or `failed` (the removal itself failed). Mem0 and Zep both verify through their search APIs; the tests drive the real clients against indexes that lag by a configurable number of searches. A certificate that says `stillIndexed` is an honest certificate; run forget again later, or read it as the store's problem to fix.

**The pack.** `agent-custody-memory pack --ledger ... --receipts ... --fact <id> --out pack.json --sign keys/pack.key` gathers everything about one fact into one signed artefact: its history with the receipt that produced each event, its holds and releases, its blast radius with every downstream receipt, and, if it was forgotten, the forget certificate with what each store answered. `pack --verify pack.json --key keys/pack.pub --issuer-key keys/gateway.pub --principal-key keys/principal.pub` checks the pack's signature and digest, every receipt inside it against the gateway's keys, that every event's receipt is present, and that the forget receipt names this fact and records the erasure. Touch one receipt inside and the whole pack fails. It is the artefact counsel attaches to a ticket; the reviewer needs the two public keys and nothing from you.

The certificate is the receipt. Through the gateway, `memory.forget` is a receipted call whose result the gateway observed, so the signed, logged receipt records that the erasure happened, who asked for it, and what the stores answered. Hand that receipt to whoever demanded the deletion; anyone with the gateway's public key can verify it.

Receipts are the other place a value lives: the receipt that recorded the write carries it in its request arguments, and the receipts of reads carry it in their results, signed and in a Merkle log. The receipts package's `prune` command is retention for the log: it replaces older leaves with their hashes, so every root and every proof still verifies while the content is gone, and removes the pruned receipts' bundle files. Run it on the same schedule as the sweep.

## Blast radius

When a belief turns out wrong, the next question is what relied on it. Two records answer it together. Every gateway receipt carries `consumed`: the fact ids the agent had been shown, through the gateway, before that call, which the memory server declares on each read. Every fact in the ledger carries the receipt that wrote it. Walking forward from a fact through those two links gives every later call and every belief written in those calls, transitively, and whether the root was retracted and which derived beliefs are still believed.

```bash
agent-custody-memory blast --ledger ./ledger.jsonl --receipts ./receipts --fact <factId> [--capture-key-env NAME]
```

A receipt issued under a private capture rule withholds what the agent had been shown. The query never counts such a call as having relied on nothing: it lists every one made since the ledger learned the fact (by transaction time: a fact valid from tomorrow is readable today) under `INCOMPLETE`, and the capture key, for receipts in mode `encrypted`, lets it see through.

```
fact 3f2a…: acct:42 plan = "enterprise" (space team:support, by support-agent, attested)
retracted at 2026-09-07T10:12:04.118Z by support-agent: CRM sync bug: account is on the free plan
3 call(s) made after the agent was shown it:
  2026-09-07T10:12:03.902Z  memory.write       executed  receipt 7c1e…
  ...
2 belief(s) written in those calls, 2 still believed:
  acct:42 discount = "20%"  fact 9b04…  STILL BELIEVED
  acct:42 support_tier = "priority"  fact e77d…  STILL BELIEVED
```

With the gateway fronting several upstreams, memory and the tools the agent acts with, the radius reaches the actions too: a refund issued after the agent read a belief carries that belief's id and is listed. [examples/06-actions-on-beliefs.ts](examples/06-actions-on-beliefs.ts) shows it.

It is an upper bound by design: a call made after the agent had seen the fact is in the radius whether or not the agent used it, because no receipt can prove what a model attended to. What it never misses is the thing that matters, a downstream action or belief that did depend on the fact. [examples/05-blast-radius.ts](examples/05-blast-radius.ts) runs the whole loop.

## Explain one action

The question a security owner asks first is not about a fact but about an action: *what is refund 183722, and can I trust the answer?* `agent-custody-memory explain --receipts receipts --receipt <id> --ledger ledger.sqlite --issuer-key keys/gateway.pub --principal-key keys/principal.pub` answers it in the order it is asked:

```
WHO                          support-agent (attested, named in a signed grant)
WHO AUTHORIZED IT            user_456, grant signed by key bfa1c0d2e3f4, valid 2026-09-08T08:00:00.000Z to 2026-09-08T16:00:00.000Z
WHAT WAS ALLOWED             tools customer.lookup, stripe.refund
                             policy 9c1d2e3f4a5b decided allow
WHAT THE AGENT SAW           customer = {"verified":true,"plan":"pro"} (fetched by the gateway via customer.lookup)
                             1 belief(s) shown before this call:
                               acct:42 plan = "enterprise" [0b83d822]
WHAT IT DID                  stripe.refund {"customer_id":"cust_123","amount":845000} -> executed
WHY                          the policy permitted it
WHAT EVIDENCE                receipt 7f2e…, leaf 41 of a log whose head is signed by 3a9b0c1d2e3f
                             authorization committed as leaf 40, before the call was forwarded
CAN I VERIFY IT              VERIFIED, 23 checks
DID ANYTHING DEPEND ON THIS  1 belief(s) written in this call, 3 later call(s) made after seeing them, 2 belief(s) derived
WHAT NEEDS REVERSAL          2 belief(s) still believed, and 3 later call(s) to review
```

The first eight lines come from the receipt alone and work without a ledger; the last two are answered from the ledger, and without one they say `unknown without a ledger` rather than pretending nothing depended on the call. `--out action.json --sign keys/pack.key` writes the same answers as one signed action pack with the receipt and every downstream receipt inside it, and `explain --verify action.json --key keys/pack.pub --issuer-key ... --principal-key ...` checks the pack's signature and digest, the receipt, every downstream receipt, and that the written beliefs cite this receipt. Touch one receipt inside and the pack fails. The custody pack below is the same artefact seen from a fact instead of an action.

**The review console.** `agent-custody-memory review --receipts receipts --ledger ledger.sqlite --issuer-key keys/gateway.pub --principal-key keys/principal.pub` serves the same answers as pages on loopback: an index with transaction and customer ids, when, tool, outcome, agent, principal, producer, and its verdict. Search by transaction, customer, agent, or an inclusive time range; each receipt opens the ten answers, the verification report, the issued bundle, and a portable case download. It runs where the receipts are, because nobody else holds them; it has no login of its own, so expose it only behind one you already have.

```bash
agent-custody-memory review --receipts receipts --issuer-key keys/gateway.pub --principal-key keys/principal.pub --transaction re_123 --customer cust_123 --agent support-agent --from 2026-10-01T00:00:00Z --to 2026-10-31T23:59:59Z
agent-custody-memory review --receipts receipts --issuer-key keys/gateway.pub --principal-key keys/principal.pub --out review-site/
agent-custody-memory review --receipts receipts --issuer-key keys/gateway.pub --principal-key keys/principal.pub --case <receiptId> --out refund.case.html
agent-custody-memory review --receipts receipts --issuer-key keys/gateway.pub --principal-key keys/principal.pub --case <receiptId> --out refund.case.json
agent-custody-memory review --verify-case refund.case.json --issuer-key keys/gateway.pub --principal-key keys/principal.pub --json
agent-custody-memory review --verify-case refund.case.html --issuer-key keys/gateway.pub --principal-key keys/principal.pub
```

Filters combine with AND, match exact case-sensitive ids, and search only public arguments, results, and gateway facts. Times must be ISO 8601 date-times with `Z` or a UTC offset. An identifier withheld by a capture rule cannot be searched. A record that lacks a part the pages read (it fails the verifier's structural check) is shown as NOT VERIFIED with the reason, and it does not stop an export. A ledger or file error is not a defect of the record: it fails the export, and the live page answers 500. Search stops at 64 levels of nesting and ignores JSON text longer than 64 KiB, so one hostile argument cannot stall the index. A receipt with a value that search skipped is marked "partially indexed", and an id filter keeps it in the list, because the id may be in the skipped value. The index never drops a record: a file whose receipt id differs from its name is listed as NOT VERIFIED ("file name does not match receipt id"), and the header counts the files that could not be read. `--out <dir>` writes an index, receipt pages and bundles, and each receipt's `.case.html` and `.case.json`; its browser search covers only the receipts included in that export. Add `--approval-key` (once for each human approver) when the receipts are for calls that a human approved: without those keys such a receipt is NOT VERIFIED. Add `--log-key`, `--log-id`, and `--upstream-key` when those signatures need independent keys.

A portable HTML case contains the signed receipts, embedded signed authorizations, inclusion proofs, signed log heads, public keys (issuer, principal, approval, log, and upstream) and their fingerprints, the ten answers, and any ledger snapshot. Open it locally: its embedded WebCrypto verifier runs fresh checks on the signed evidence without external requests. That result is not independent, because the script is in the same file as the data: whoever edits the file can edit the script too, and the page does not compare the ten answers with the receipts. `review --verify-case` is the independent check. It takes the format from the file name: a name that ends in `.json` is read as JSON, and every other name as a page. Content that does not match the name fails. It reads the file, rebuilds the ten answers from the signed receipt and prints them (a saved answer that differs fails the check "ten answers match the signed receipt and the unsigned ledger snapshot"), and exits 1 on failed verification. For a `.case.html` it also fails unless the page is exactly what its data renders, so a changed visible answer or a second copy of the data fails. Trust the answers that the command prints, not the page. The check covers the answers that come from the signed receipt. The belief, dependency, and reversal lines come from the ledger snapshot in the file, which nobody signs, so a forged snapshot with matching answers passes: those lines are not attested. Without key flags it uses the bundled keys; supplied public keys replace the entire bundled trust set. Confirm bundled fingerprints through a trusted source. The explanation and ledger snapshot are unsigned exporter assertions; verification establishes the recorded gateway decision and detects receipt tampering, not that an external payment occurred. Without a ledger, belief dependencies remain `unknown without a ledger`. Capture keys, private keys, salts, and restored withheld values are never added to a case file.

## Write-through to the stores you already use

The ledger is not a retrieval store, and it does not try to be. `src/stores.ts` puts it under the ones teams already run: a fact written through the memory server also lands in every configured store, with its custody metadata (fact id, space, actor, provenance, receipt id), the store's own id is recorded on the fact, and a retraction reaches the store by that id. Certified forget will be built on this: a deletion is only real once it has reached the stores that serve recall. For teams whose recall is a pgvector table, `pgvectorStore` writes the fact's text, its embedding from the function you already use, and its custody metadata as one row keyed by the fact id, and verifies a removal with the same nearest-neighbour query a retrieval call runs. Three more, each with its own limitation stated: `lettaStore` writes a passage to an agent's archival memory with the custody as tags, since Letta passages carry no free metadata, and verifies removal through archival search; `langgraphStore` writes one item per fact into a LangGraph store, which is where LangMem keeps its memories, keyed by the fact id under the namespace you give, and verifies removal with `get` and a filtered `search`; `cogneeStore` speaks Cognee's REST API directly, because Cognee has no JavaScript client, adding the text with the custody as external metadata and finding the data id by listing the dataset, since Cognee's add returns a pipeline run rather than an id; it was built against Cognee's routers and tested against a stand-in of them, not a running Cognee.

```ts
import { MemoryClient } from "mem0ai";
import { ZepClient } from "@getzep/zep-cloud";
import { Letta } from "@letta-ai/letta-client";
import { InMemoryStore } from "@langchain/langgraph";
import { Ledger, cogneeStore, createMemoryServer, langgraphStore, lettaStore, mem0Store, pgvectorStore, zepStore } from "@agent-custody/state";

const stores = [
  mem0Store(new MemoryClient({ apiKey: process.env.MEM0_API_KEY! }), { userId: "user_42" }),   // infer is off: the memory is the fact, verbatim
  zepStore(new ZepClient({ apiKey: process.env.ZEP_API_KEY! }), { userId: "user_42" }),         // or { graphId } for a shared graph
  pgvectorStore(pool, { embed, dimensions: 1536, table: "agent_memories" }),                    // your Postgres, your embedding function
  lettaStore(new Letta({ apiKey: process.env.LETTA_API_KEY! }), { agentId: "agent-…" }),            // archival memory of one agent, custody as tags
  langgraphStore(new InMemoryStore(), { namespace: ["memories", "user_42"] }),                    // or any BaseStore: LangMem's memories live here
  cogneeStore({ url: "http://localhost:8000", datasetId: "…", apiKeyEnv: "COGNEE_API_KEY" }),    // Cognee's REST API, no client package exists
];
createMemoryServer(new Ledger("./ledger.jsonl"), { stores });
```

The `Store` interface is small. A custom store implements `name`, `put`, and `delete`, and can add `verifyDeleted` and `list`:

```ts
interface StoreEntry { externalId: string; factId: string; text: string; storedAt?: string }   // one entry a store holds for a fact; storedAt is the ISO time of the store write
interface Store {
  name: string;
  put(fact): Promise<string>;                          // writes the fact, returns the store's own id
  delete(entry: StoreEntry): Promise<void>;
  verifyDeleted?(entry: StoreEntry): Promise<boolean>; // optional; without it a removal is "unverified"
  list?(): Promise<StoreEntry[]>;                      // optional; every entry with custody metadata, for memory.repair
}
```

**Breaking change for custom stores.** `remove(externalId, fact)` is now `delete(entry)`, and `verifyRemoved(externalId, fact)` is now `verifyDeleted(entry)`. Each takes one `StoreEntry`. Change `remove(id, fact)` to `delete({ externalId, factId, text })`. The names changed with the arguments: `createMemoryServer` refuses a store that has no `delete`, so a store written for the earlier interface fails at startup. It is never called with the wrong arguments, and its old check can never report an entry as verified. The `text` field is the text that `factText(fact)` returns, so a store no longer needs the whole fact. The `entryOf(fact, externalId)` function builds an entry from a fact. The adapters in this package use the new signature already. Every adapter implements `list`: pgvector and Cognee always, LangGraph when the store has `search`, and Mem0, Zep, and Letta when their client has a method that lists entries.

The adapters are typed structurally and carry no runtime dependency on either vendor; the tests drive the real `mem0ai` and `@getzep/zep-cloud` clients against fake endpoints, offline.

### Write order and repair

The write order is fixed: validate, stores, ledger.

1. The ledger's checks run first. A write that the ledger refuses never reaches a store.
2. The stores are written next. The server needs the store ids to record them on the fact.
3. The ledger appends last.

A store that refuses the write fails the write, and nothing is recorded anywhere. A write whose stores take more than five minutes is refused before its ledger append; see the repair sweep below. The retraction order is the reverse: ledger, then stores. Custody must not depend on a store being up. A store that fails to remove is named in the error, so the caller knows that recall can still serve the value.

The order has one cost. If the ledger append fails after the stores took the write, a store keeps an entry that the ledger has no fact for. That entry is an orphan: recall can serve it, and no event explains it. The repair sweep removes orphans.

A write that is in progress looks like an orphan too: its entries are in the stores and not yet in the ledger. Two rules keep the sweep away from it. Each entry records `storedAt`, the time of its store write. The sweep removes only entries stored before a cutoff, which is ten minutes ago (the exported `REPAIR_MIN_AGE_MS`). And a write whose stores take more than five minutes, half of `REPAIR_MIN_AGE_MS`, is refused before its ledger append. So the entries of a write in progress are never older than the cutoff. This holds across server processes that share the stores. If a ledger append stalls for longer than that, the repair event decides: whichever record of the fact id reaches the ledger first wins, and the other fails with an error. In one server process, the ledger makes the check and the append of the two records one step. For servers in different processes, the window is the time between the check and the commit of one append. To close it, the check and the append must be one transaction in the shared ledger store, for example with a per-fact-id advisory lock. This version does not do that. A unique constraint on `fact_id` does not work: retract, confirm, hold, release, and forget events share the fact id of the fact, and an orphan in two stores has one repair event for each store.

`memory.repair { reason, before? }` runs the sweep. The CLI runs it through a gateway, so the sweep has a receipt and runs as the principal in the gateway's grant:

```bash
agent-custody-memory repair --via repair-gateway.json --reason "ledger outage on 14 October" [--before <ISO instant>]
```

The cutoff is the earlier of `before` and ten minutes ago. `before` can move the cutoff earlier only, never later.

For each store that has `list`, the sweep reads every entry with custody metadata. It removes an entry once only, if a listing holds it twice. It skips an entry whose fact id the ledger knows. It skips an entry that was not stored before the cutoff. For each other entry, the sweep first appends a `repair` event, as a retraction does with its ledger event. The event has the fact id from the entry's metadata, the actor, the reason, the receipt id, the store, and the store's id for the entry. Then the sweep removes the entry and asks the store's search whether the entry is gone (the same retries and outcomes as a forget). The outcome is in the result and in the receipt of the call: `verified`, `stillIndexed`, `unverified`, or `failed`. `memory.history` of the orphan's fact id shows the event. The first record of a fact id wins. The ledger refuses a repair for a fact id that it knows, and it refuses an assert for a fact id that has a repair event, so a late write fails with an error and the ledger never believes a fact that no store holds. In one server process, a repair of an entry that already has a repair event adds no second event: a retry after a failed removal uses the first event. One sweep runs at a time in a server process. If a store fails a delete and its listing then no longer holds the entry, the sweep treats the delete as done and verifies the entry as usual, so the outcome is `verified`, `stillIndexed`, or `unverified` by the same rules.

The result is `{ before, repaired, unlisted, stillHeld, unrecorded }`:

- `before` is the cutoff that the sweep used, as an ISO instant.
- `repaired` is `[{ store, externalId, factId, outcome, eventId }]`.
- `unlisted` is the names of the stores that have no `list`.
- `stillHeld` is the errors of removals that failed. It also holds `<store>: cannot list: <error>` for a store whose listing failed. The sweep goes on with the other stores.
- `unrecorded` is `[{ store, externalId, factId, error }]`: the entries that the sweep did not remove, because the ledger did not take the repair event. The next sweep tries them again.

The result is an error when `stillHeld` or `unrecorded` is not empty. Run the sweep again after you fix the store or the ledger.

Limits:

- An entry whose `storedAt` is missing or does not parse counts as young. The sweep never removes it. When the metadata has no `storedAt`, the adapters fall back to the creation time of the store: the `created_at` column for pgvector, and the creation time that the client reports for Mem0, Zep, Letta, and LangGraph. Cognee has a fallback only if its listing has a creation time. Letta records `storedAt` in the tag `stored:<iso>`.
- One store scope belongs to one ledger. A store scope is a pgvector table, a Mem0 user, a Zep user or graph, a Letta agent with its exact tag set, a LangGraph namespace, or a Cognee dataset. Two ledgers that share a scope already leak recall between them, and a repair on one ledger removes the entries of the other.
- A change to the tag set of a Letta store strands the passages that the store wrote under the old tags. The exact tag set is the scope, as the namespace is for LangGraph. The new store does not list the old passages, and `memory.repair` cannot remove the orphans among them. `lettaStore` throws on a tag that is `agent-custody` or starts with `fact:`, `space:`, `stored:`, or `receipt:`.
- The clocks of the memory servers must agree to within a few minutes. `storedAt` comes from the clock of the writer, and the cutoff comes from the clock of the repairer.
- A store without `list` is reported in `unlisted` and is not swept. Mem0, Zep, and Letta get `list` when their client has a method to list entries.
- The sweep finds only entries that carry custody metadata (`source: "agent-custody"` and a fact id). It does not touch other entries in the store.
- The Cognee data listing carries no text, so its entries have empty `text`. The adapter verifies by id, so this does not matter for the sweep.

## Scoring memory mutations

`src/evals.ts` is a harness that scores a memory system on what goes wrong after writes, not on recall. A scenario is a script of writes, reads, supersessions, and retractions with the value a correct system returns at each read. The score counts stale reads (a value served after a correction was known), contradictions (two values for one subject and predicate at once), blast radius (reads that served a write the scenario marks as bad), and correct reads. Any system behind the small `MemoryUnderTest` interface can be scored; this ledger and a naive overwrite store ship as the two reference points, and [examples/04-evals.ts](examples/04-evals.ts) prints both reports side by side.

```ts
import { Ledger, ledgerUnderTest, runAll, SCENARIOS, formatReport } from "@agent-custody/state";
console.log(formatReport(await runAll(ledgerUnderTest(new Ledger("./ledger.jsonl")), SCENARIOS)));
```

From the shell, on a schedule:

```bash
agent-custody-memory eval --baseline                                     # built-in scenarios, ledger and a naive store side by side
agent-custody-memory eval --scenarios incidents.json --sign keys/eval.key --out report.json   # your own incidents, signed report
agent-custody-memory eval --verify report.json --key keys/eval.pub       # what a reviewer runs
```

A scenario file is `{ "version": "0.1", "scenarios": [{ "name", "ops": [...] }] }` with the same write, read, and retract ops as the built-ins; every read carries `expect`, null meaning nothing. The file is validated and a bad one names the offending op. The signed report is an in-toto statement over the scores, bound to a digest of the scenarios it ran, in the same envelope format as receipts; `eval --verify` checks the signature and the digest. `eval` exits non-zero when the ledger scores below perfect on the scenarios it was given, so a cron job that runs it fails loudly when a change regresses memory behaviour.

## The ledger

`src/ledger.ts` keeps an append-only log of events. It holds none of them itself: every question is a query to a store, so the store decides how large a ledger can be and who shares it. A store answers four questions, everything in order (export, audits), everything about the facts matching a filter (a bitemporal read), everything that touched one fact (its history and its checks), and which spaces exist (retention), and it does three things: append, replace one assert in place (forget), and compact after erasures. Three stores ship, and the whole ledger suite runs against each of them, so they answer identically.

**JSONL** is the default: one event per line, readable by anyone, the file you copy for an audit. It answers from memory, which is fine to tens of thousands of events. **SQLite**, chosen by a path ending in `.sqlite` or `.db`, is for durability on one machine: transactional writes with write-ahead logging, an in-place forget that overwrites the erased value (secure delete, then a truncating checkpoint so nothing lingers in the write-ahead log), and every query answered by an index on fact, time, space, subject, predicate, and supersession. Node ships the SQLite module, so there is no native dependency; a ledger written by an earlier version gets the index columns filled from its JSON the first time it is opened. Measured on a million-event ledger: open in 0.2 s, a subject read in about 1 ms, a fact's history in well under a millisecond, the spaces for a sweep in 2 ms. **Postgres**, chosen by a `postgres://` URL, is for a shared ledger: several memory servers on one table, in the database your security team has already approved, the same queries pushed down as SQL. It needs the `pg` package installed beside this one; `?table=custody.events` names the table and `?vacuum=false` skips the vacuum described below. In code, pass a `PostgresStore` around your own `pg` Pool, with whatever TLS and credentials you already use. The adapter is tested against the real Postgres engine in-process through PGlite, including that a forgotten value is absent from the database files, and checked by hand against Postgres 16.

Forget on Postgres is an `UPDATE`, and MVCC keeps the old row image in the table until vacuum. So after a forget or a sweep the store runs `VACUUM FULL` on the table, which rewrites it without the old image. That takes an exclusive lock for the rewrite; a very large ledger may set `vacuum: false` and run its own schedule, and the forget certificate then rests on that schedule. The write-ahead log, replicas, and backups keep their own copies for as long as their retention says; that is true of every database, and the honest reading of a forget certificate is that the live ledger no longer holds the value.

Choose JSONL for one server process and for anything an auditor should read with `cat`. Choose SQLite when one machine serves the ledger over HTTP, when a crash between two writes must not cost you an event, or when a deletion demand must leave no trace of the value in the file. Choose Postgres when more than one server must share the ledger, or when the ledger belongs in the database you already operate. Warehouses are not stores: Snowflake and Databricks keep deleted rows for days by default and are built for scans, not one small write per agent call. Feed them with `agent-custody-memory export --ledger postgres://… --out ledger.jsonl`, which writes the auditable JSONL from any store, and query the ledger where your compliance team already works.

The log holds these kinds of event.

- **assert** creates a fact: subject, predicate, value, the space it lives in (a person, a team, an org), the actor that wrote it, the source receipt id if the write went through a receipts producer, and the valid-time interval. An assert may **supersede** an earlier fact, which ends that fact's validity where the new one begins.
- **retract** says a fact should never have been believed. This is the undo. The record stays, so queries about earlier moments still see the fact, and anything the retracted fact had superseded is believed again.

Two clocks, kept apart on purpose:

| | question it answers | set by |
| --- | --- | --- |
| valid time | was this true in the world at T | the writer, defaults to now |
| transaction time | did the ledger know it at T | the ledger, never the writer |

`asOf({ validAt, txAt, space, subject, predicate })` returns the facts believed at a moment. Setting both times to the same instant answers "what did the agent believe on Tuesday", including beliefs later retracted. `history(factId)` returns every event that touched a fact.

The ledger refuses to supersede a fact that is unknown, already superseded, or retracted, and refuses a replacement whose validity starts before the fact it replaces.

## Layout

```
src/ledger.ts   the fact record, the event kinds, as-of queries, supersession, retraction, forget, holds, sweeps, repairs
src/storage.ts  the store interface and its three stores: JSONL (default, auditable), SQLite (indexed, one machine), Postgres (shared); chosen by path or URL
src/server.ts   the ledger as MCP tools; source and actor taken from the gateway's _meta
src/http.ts     the memory server over Streamable HTTP with bearer auth, for a shared ledger
src/explain.ts  one action explained: the ten answers from a receipt and the ledger, and the signed action pack
src/review.ts   the searchable review console: explain pages and portable case downloads, served on loopback or written as files
src/search.ts   exact transaction, customer, agent and time filters over the public receipt view
src/case-file.ts  portable HTML/JSON evidence with public keys, fresh offline verification and the ten answers
src/verify-web.ts  the browser verifier embedded in portable HTML case files
src/pack.ts     the custody pack: build, sign, verify, format
src/cli.ts      agent-custody-memory serve (stdio or --http, with --retention and --forget-key-env), sweep (ledger-only or --via a gateway), repair (--via a gateway), eval, explain, review, pack, export, blast
src/blast.ts    blast radius: from receipts' consumed facts and the ledger's source receipts, forward
src/stores.ts   write-through adapters: Mem0, Zep, pgvector, Letta, a LangGraph store (LangMem), and Cognee, and the Store interface (put, delete, verifyDeleted, list) for others
src/evals.ts    the memory-mutation harness: scenarios, scoring, report
src/evals-ledger.ts  the ledger and a naive overwrite store behind the harness interface
src/evals-file.ts    scenario files, validated; signed eval reports and their verification
src/index.ts    public surface
examples/       runnable walkthroughs, each ends with OK and is run by the test suite
test/           one test per question a platform owner asks after a memory incident
tsconfig.build.json  emits dist/ for consumers; the repo itself runs the .ts directly
```

## Plan

**Done**

- Bitemporal fact ledger with supersession, retraction, as-of and history queries, persisted as JSONL, SQLite, or Postgres behind one store interface that answers every query from an index, with export back to JSONL.
- The memory server: the ledger as MCP tools behind the receipts gateway, with the source receipt id and the attested actor supplied by the gateway, policy over spaces, and a denial receipt for every refused write.
- Forget digests are keyed under a server-held secret, or absent on request, so an erased value cannot be guessed back from the file.
- Retention windows per space in the server, sweeps that default to them, and a `sweep --via` trigger that runs retention through a gateway as a named principal, on any timer.
- The review console: search public receipt fields by transaction, customer, agent or time, inspect the ten answers and verification report, and export a portable HTML/JSON case with fresh offline verification; served on loopback or written as static files.
- Explain one action: from a receipt id, who, who authorized it, what was allowed, what the agent saw, what it did, why, the evidence, whether it verifies, what depended on it, and what needs reversal; the same as a signed action pack that carries every downstream receipt.
- The custody pack: a fact's history with receipts, holds, blast radius, and forget certificate as one signed artefact, verified as a whole.
- Removal verification: after a retraction, forget, or sweep the server asks each store's search whether the value still surfaces and records verified, stillIndexed, unverified, or failed per store, in the receipt.
- Repair of a failed ledger append: `memory.repair` and `repair --via` find the store entries that the ledger has no fact for, remove and verify them, and record a `repair` event under the entry's fact id. The Store interface takes a `StoreEntry` and has an optional `list`.
- Retention and legal hold: a receipted sweep forgets what was learned before an instant and reaches the stores; a hold refuses forget and sweep until released, as events on the fact's history.
- Value-level quarantine: a write may cite a fact the gateway fetched itself; the value must match it and the fact is then `verified`, the provenance level above attested, or the write is refused.
- Attested executions: with a key, the memory server signs its results for the gateway's receipt, so a verifier holding its public key sees memory calls as attested.
- The memory server over HTTP: one ledger shared by several gateways and direct writers, a token per kind of caller so only a gateway is believed about receipts and agents, quarantine live.
- Certified forget: `memory.forget` erases a value from the ledger file keeping its digest, stops believing it, removes it from every store, and reports exactly what happened; the gateway's receipt of that call is the certificate.
- Policy over provenance: the gateway looks up the fact a write supersedes or a retraction targets, so policy decides on its space, actor, and provenance; a claimed fact can be displaced, an attested org fact cannot.
- Consumed facts and blast radius: the memory server declares the facts it serves, the gateway records them on every later receipt, and `blast` walks from a fact to every downstream call and derived belief, transitively, with its retraction status.
- Write-through to pgvector: the fact's text, embedding, and custody metadata as one row in the Postgres a team already runs, keyed by the fact id; removal verified by the same nearest-neighbour query recall runs; tested against Postgres with the extension in Docker.
- Write-through adapters for Letta (archival passages, custody as tags), a LangGraph store where LangMem keeps its memories (one item per fact under a namespace), and Cognee (its REST API, the data id found by listing the dataset); each verifies its own removals, each states its limitation.
- Write-through adapters for Mem0 and Zep: every write lands in the store with custody metadata, the store id is recorded on the fact, retractions reach the store, and failures are ordered so nothing is half-recorded.
- The eval CLI: built-in or custom scenario files, the naive baseline beside the ledger, a signed report a reviewer verifies, and a non-zero exit on regression, for cron.
- The memory-mutation eval harness: stale reads, contradictions, blast radius, and correct reads over scripted incidents, scored the same way for the ledger and for anything behind the same interface.
- Quarantine: facts carry `attested` or `claimed` provenance; claimed facts are hidden from reads by default and a gateway-only `memory.confirm` lifts them, as a recorded event.

**Next, in the order it pays off**

1. The hosted plane, behind early access: tenanted log, then memory, then reports and a control plane, with SSO, SCIM, residency, and SIEM export. [Issue #6](https://github.com/svayatta/agent-custody/issues/6).

