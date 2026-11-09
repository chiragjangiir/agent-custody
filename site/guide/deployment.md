# Deployment

The [architecture page](/guide/architecture) has the diagrams: what runs on the customer's side, what is hosted, and the sequence of a call. Nobody's agent calls agent-custody. The agent never learns it exists. There are three places the layer can sit, and a deployment uses whichever of them the job needs.

```
agent host  (Claude Code, LangGraph, the OpenAI Agents SDK, your own loop)
   │  MCP, unchanged: the host is pointed at the gateway instead of at the tool
   ▼
agent-custody gateway          → one signed receipt per call → the local log, or a log run by someone else
   │  MCP, unchanged
   ▼
the tool servers the agent already used: Stripe, GitHub, the memory server, several at once under one grant
```

## The gateway: outside the agent, in front of the tools

The gateway is an MCP server because MCP is what the host already speaks to its tools. It is a transparent proxy in that protocol, the way an API gateway sits in front of an HTTP service. The only change on the agent's side is one line of host config: where it named the Stripe MCP server, it now names the gateway, and the gateway forwards. The agent still believes it is talking to Stripe.

Being outside the agent's process is what lets the gateway do two things a log collector cannot: refuse a call before the tool runs, and sign the record with a key the agent never holds. One gateway runs per agent session, on stdio, as MCP hosts run their servers; it fronts several upstreams under one human-signed grant. [Setting it up](/receipts/usage).

For every agent on a host or cluster, run one shared gateway as a service instead: `ghcr.io/svayatta/agent-custody-gateway` (amd64 and arm64), with a compose file, Kubernetes manifests and a systemd unit. Each agent connects over HTTP and presents its own grant, and the tool credentials live in the gateway. [Running the gateway as a service](../../deploy/gateway/README.md) has the steps and the limits: a grant is a bearer credential, the transport is plain HTTP, and one replica is the supported shape.

## The SDK: inside the agent, for tools that are not MCP servers

For tools that are plain functions, the SDK hooks the framework the agent already uses: a Claude Code hook, a LangChain callback, a wrapped OpenAI Agents or Vercel AI tool. No new server, no change to the tool. The record is self-reported, since it comes from inside the process it describes, and every receipt says so with the `claimed` label. Agents in other languages get the same through the sidecar, a local HTTP process holding the key, with a Python package and Go, Java, and Rust clients. [The interceptor SDK](/receipts/sdk).

## The memory server: the belief ledger, behind the gateway

The memory server is not for logging. It is the belief ledger's interface, exposed as MCP tools because that is how agents use memory, and it runs as one of the gateway's upstreams so that every write and read inherits the policy check and the receipt. Over stdio it serves one gateway; over HTTP with a bearer token it is one shared ledger for many gateways and, if allowed, direct writers, which is when quarantine does its work. Teams that only want receipts for actions never run it. [The memory server](/state/#the-memory-server).

## What the gateway does not cover

Everything the gateway proves holds for calls that go through it. These do not, and no receipt says otherwise:

- **An API key in the agent's environment.** If the agent process holds a Stripe key, it can call Stripe directly and the gateway does not see it. The fix is a deployment decision: the key lives in the gateway's environment (`upstream.env`, or `headerEnv` on a REST upstream) and not in the agent's. Under egress lockdown, such a direct call is refused or relayed by the egress witness, which receipts the connection but not its content (below).
- **Another MCP server in the host config.** A host that names the gateway and also names the tool server directly gives the agent both routes. Remove the direct one.
- **SDK-only wraps and the sidecar.** They run inside the agent's process and record what that process tells them. Every such receipt is `claimed`, and the report says so on the `ISSUER` line.
- **Subprocesses, databases, queues, and other agents** reached without MCP or the REST connector. Same as the first point: if the agent holds the credential, the agent decides.

## Where interception stops

If agent code calls an HTTP API directly, outside MCP and outside a wrapped function, the gateway does not see it. The answer built for that is the REST connector: describe the API's endpoints as tools in the gateway config, with the credential read from the environment, and the agent calls them through the gateway instead of holding the API key itself. Scope, policy on the gateway's own lookups, pre-commit, and receipts then apply to REST calls exactly as to MCP calls, and a REST upstream sits beside MCP upstreams behind one grant. What remains outside is code that keeps its own credentials and calls out on its own. Taking those away from the agent is a deployment decision: [credential custody and egress lockdown](/guide/credential-custody). Under lockdown, the [egress witness](/receipts/egress) receipts each direct connection, and decides it by policy, with the agent, the destination, and the byte counts. It never records the payload: there is no TLS interception. Without lockdown, an agent can ignore the proxy, and the witness sees nothing. It relays only HTTP; under lockdown, other protocols cannot leave at all.

## Observability you already have

Receipts are not a dashboard. With `otel` in a gateway or SDK config, each receipt is also exported as one span to the OTLP collector the team already runs, Datadog, Grafana, or whatever sits behind it, with the receipt id as the trace id. With `splunk` in the same config, each receipt is one event at a Splunk HTTP Event Collector, the token read from the environment, with the receipt id, tool, agent, principal, status, decision, and log position as plain fields for the searches the security team already writes. Both can be on at once. Nothing is replaced: the traces the agent framework already emits stay as they are, and the receipt sits beside them, pointing at the evidence. Exports run after the receipt and never block or fail it.

## What a remote log costs per call

A remote log puts one HTTP round trip on the path of every call, and two on a call named in `precommit`: the authorization append before the upstream is called, and the receipt append after it returns. The request is small, a leaf hash and a bearer token, so the cost is network distance plus the log's own work. Measured on 2026-09-09 against the log at log.agent-custody.dev, a Hetzner machine in Helsinki running the shipped image with Postgres and the separate signer:

| Where measured | What | Median | p90 |
| --- | --- | --- | --- |
| On the log's own host, loopback | hash-only append, Postgres, remote signer | 5.4 ms | 7.3 ms |
| On the log's own host, loopback | hash-only append, Postgres, in-process signer | 3.3 ms | 4.3 ms |
| On the log's own host, loopback | tree-head read | 4.3 ms | 5.4 ms |
| A client 160 ms away (network round trip by ping) | any request, connection reused | 170 ms | 190 ms |
| The same client, new TLS connection | first request of a process | 500 ms | 550 ms |

So a call costs the network round trip plus about five milliseconds, and a pre-committed call costs twice that. From the same region as the log that is a few tens of milliseconds per call; from another continent it is the numbers above. The gateway keeps its connection open, so the TLS handshake is paid once per process, not per call. A local log file appends in well under a millisecond, which is why the default is local and the remote log is recommended once a receipt has an audience outside the team. A log that answers 429 or a server error is retried three times with backoff starting at 200 ms, so a log outage costs a pre-committed call about 1.4 seconds before it is withheld. The script that produced the append numbers ran fifty appends into a throwaway database on the same Postgres and is the `httpLog` client the gateway itself uses.

## What you are trusting, by setup

Each setup, from the SDK alone to a log anchored on a chain, rests on different parties. The table is on [what each piece is for](/guide/pieces#what-you-are-trusting), with the status of the anchor and the witness for our hosted log.

## Sizing

One gateway process per agent session is far more than one session needs; the gateway's overhead per call is small next to the tool calls it forwards, and the Merkle log's append cost does not grow with the log. The shared pieces, the remote log server and the HTTP memory server, are single processes. Indexed queries for large ledgers are in place for SQLite and Postgres. The receipts package README records the measurements and the script that produced them, for anyone sizing a deployment.
