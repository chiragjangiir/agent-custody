# The egress witness: receipts for calls that go around the gateway

The gateway holds an agent's tool credentials and receipts every call made through it. An agent that has a credential of its own, or that calls a public API with none, can go around it. The egress witness is for those connections. It is an HTTP forward proxy in the agent's network path, the [door](door.md) turned around to face outbound traffic. For each connection that does not go to the gateway, it:

- identifies the agent by a proxy credential it checks;
- lets a Cedar or Rego policy decide per destination (host and port);
- relays the connection or refuses it;
- signs a receipt either way, with `issuer.kind: "egress"`. The receipt goes to the log like any other.

**It needs lockdown.** A proxy alone is advice: an agent can ignore `HTTPS_PROXY` and connect directly. The witness means something only when the agent's network reaches nothing but the gateway and the witness. The witness runs anywhere Node 22 runs, but the lockdown belongs to the platform the agent runs on. `deploy/gateway/lockdown` ships it for Kubernetes (a NetworkPolicy), docker compose (an internal network), and a Linux VM or bare metal (`lockdown/vm`: an nftables rule on the agent's Unix user, a systemd drop-in for the agent's unit, a unit for the witness, and a script that runs the lockdown checks). On a cloud task or a laptop, you build the default-deny egress with that platform's own firewall. [Credential custody and lockdown](../../../site/guide/credential-custody.md) explains each.

**What it cannot see.** Every page about the witness repeats this list:

- **Payloads.** CONNECT is relayed as an opaque tunnel, with no TLS interception. The witness records where traffic went, when, and how many bytes went each way. It never records what was sent or received. For plain HTTP it records the method, host, and port, not the path, the headers, or the body.
- **Traffic that skips it.** With lockdown off, an agent that ignores `HTTPS_PROXY` leaves no receipt at all. With lockdown on Kubernetes, DNS to the cluster resolver stays open, and a resolver that forwards to the internet can still carry data in its queries. The VM recipe closes DNS to the agent.
- **Protocols other than HTTP.** The witness relays HTTP requests and CONNECT tunnels. Under lockdown, other protocols cannot leave. Without lockdown they are invisible to it.

Each receipt is an **observed bypass**: evidence that the agent connected to a destination around the gateway. It is not a record of what the agent did there.

## The config file

`egress.json`, paths relative to the file:

```json
{
  "identity": { "keyFile": "keys/egress.key" },
  "agents": [{ "id": "research-agent", "secretEnv": "EGRESS_SECRET_RESEARCH_AGENT" }],
  "policyFile": "egress-policy.cedar",
  "mode": "enforce",
  "connectTimeoutMs": 10000,
  "idleTimeoutMs": 300000,
  "maxInFlight": 256,
  "receiptsDir": "receipts",
  "logFile": "log.jsonl"
}
```

- `policyFile`: a Cedar file, or a Rego file when the name ends in `.rego` (see [the same policy in Rego](#the-same-policy-in-rego)). The witness re-reads it when it changes. A file that does not parse or compile is not loaded, and the policy in force stays.
- `agents`: each agent the witness knows, and the environment variable that holds its proxy secret. The secret is never in the file. An agent id has no colon or whitespace, because Basic credentials split at the first colon. The witness refuses to start if a variable is unset.
- `mode`: `enforce` (the default) refuses what the policy denies. `observe` relays every connection from a known agent and records the decision with `enforced: false`, so you can see what your agents call before you block anything. A connection without a valid credential is refused in both modes.
- `connectTimeoutMs`: how long the witness waits for the destination to accept the connection. `idleTimeoutMs`: a relayed connection with no bytes in either direction for this long is closed.
- `maxInFlight`: connections handled at once. Past this, the next one gets 503 and is not decided, relayed, or receipted. The door has the same rule.
- `log`, `otel`, `splunk`: as for the gateway.

Run it with `agent-custody egress --config egress.json [--port 8791] [--host 127.0.0.1]`.

## How an agent uses it

The agent sets `HTTPS_PROXY` and `HTTP_PROXY` to `http://<agent id>:<secret>@<witness>:8791`, and `NO_PROXY` to the gateway's host, because the gateway receipts its own calls. Most HTTP clients send the credential from the URL as `Proxy-Authorization: Basic`. Node's `fetch` reads these variables when `NODE_USE_ENV_PROXY=1` is set, on versions that support it. Other clients need their own proxy setting.

## How the witness knows the agent

Only from the proxy credential. The witness compares a sha256 of the presented secret with the one it holds for that id, in constant time. An id that is not known is compared against a stand-in, so the answer time does not reveal which ids exist.

- **Verified:** the agent is that id, with provenance `observed`. This means the witness checked a secret it holds. Anyone who has the secret can act as that agent, so give each agent its own secret and keep it in that agent's environment only.
- **Invalid or absent:** the agent is `unknown`, with provenance `claimed`. An id that came with a wrong secret stays in the destination fact as `declared`, a claim. The connection is refused with `407 Proxy Authentication Required`, whatever the policy says.

Nothing the agent writes in a header names it. The connection's source address is the socket's own. A forward proxy has nothing in front of it, so the witness never reads `X-Forwarded-For` (the door's `trustProxy` rule, with nothing to trust).

## How a connection becomes a Cedar request

- **Principal:** `Agent::"<id>"` when the credential verified, otherwise `Agent::"unknown"`.
- **Action:** the destination as `host:port`, for example `Action::"api.stripe.com:443"`. An IPv6 address is in brackets. Host names are lowercase, without a final dot. A CONNECT host goes through the same URL parser as a plain request's. So an IPv4 address written another way is decided on as the address it names: `2130706433` and `0x7f.1` become `127.0.0.1`, and `010.0.0.1` becomes `8.0.0.1`, the address `getaddrinfo` would dial. A rule on an address cannot be dodged by spelling it differently.
- **Resource:** the same as the action.
- **Context:** `context.args` holds `{ method, host, port }` as the agent asked for them. `context.facts.destination` holds the witness's own observation: `host`, `port`, `scheme` (`connect` or `http`), `credential` (`verified`, `invalid`, or `absent`), `remote` (the socket's address), and, after a failed credential, `declared`.

```cedar
// The research agent may read the package registry over TLS.
permit(principal == Agent::"research-agent", action == Action::"registry.npmjs.org:443", resource);

// Any known agent may reach hosts under example.com on 443.
permit(principal, action, resource)
when { context.facts.destination.credential == "verified" && context.facts.destination.port == 443 && context.facts.destination.host like "*.example.com" };
```

### The same policy in Rego

Give `policyFile` a name ending in `.rego`, and the witness compiles it with `opa build`, exactly as the gateway does ([Rego](policies.md#rego)). The policy declares `package agentcustody`, with an `allow` boolean and a `deny` set of strings. The input is the Cedar request above with plain strings: `input.principal` is the agent id, or `"unknown"` when the credential did not verify, `input.action` and `input.resource` are `host:port`, and `input.context` holds `args` and `facts.destination`. The `opa` binary must be on `PATH` when the policy loads or changes. The witness notices a change on the first connection after it and compiles the file then, synchronously: the whole witness waits for `opa build`, typically a few hundred milliseconds, so every other connection waits too. The compile has no deadline, so an `opa` that hangs stalls the witness until it exits or the process is killed. A file that does not compile is compiled once, not again on each connection, until it changes. The gateway image includes `opa`.

This is `deploy/gateway/lockdown/config/egress-policy.cedar` in Rego:

```rego
package agentcustody

# The research agent may read the package registry and the public docs over TLS.
allow if {
	input.principal == "research-agent"
	input.action in {"registry.npmjs.org:443", "docs.python.org:443"}
}

# Any known agent may reach hosts under example.com on 443; context.facts.destination is the witness's own observation.
allow if {
	d := input.context.facts.destination
	d.credential == "verified"
	d.port == 443
	endswith(d.host, ".example.com")
}
```

`endswith(d.host, ".example.com")` is Cedar's `like "*.example.com"`. A `deny` entry wins over `allow`, as a `forbid` wins over a `permit`, and its strings are the reason in the 403 and in the receipt. The receipt's `policyDigest` is the sha256 of the file's text, as for Cedar.

An OPA server (`opa: { url }`) is not supported here yet. The gateway can ask one, but the witness decides each connection synchronously, before it relays a byte. An HTTP query per connection would need that decision to wait, and fail closed, on a server outside the witness. Use a `.rego` file.

[Writing egress policies](../../../site/guide/egress-policies.md) is the guide to these rules: allow lists, wildcard hosts, ports, IP literals, `forbid`, and rolling out from observe mode. Every example in it is tested.

Do not permit a provider whose calls belong in the gateway. The point of the gateway is that it holds the provider's key and decides each call on its arguments. The witness sees only a host name.

**Internal addresses.** The policy decides on a host name, and the witness then resolves it. A name the agent chose, or a DNS answer someone else chose, could point a permit for a public host at the metadata service or the private network. So the witness drops every internal address from the answer before it connects: loopback, private and shared ranges, link-local (the cloud metadata address `169.254.169.254`), `192.0.0.0/24` (Oracle's metadata at `192.0.0.192`), multicast, reserved space, and their IPv6 forms. That includes IPv4-mapped and NAT64 (`64:ff9b::/96`) addresses, which are judged by the IPv4 address they carry, since a DNS64 answer can wrap an internal one. A name with nothing left fails with an `error` receipt, and no connection is made. The check is in the resolver the socket connects with, so there is no second lookup to rebind. An IP literal is not looked up: it is the Cedar action itself, so it is dialled only when a rule names that address. On Kubernetes, `deploy/gateway/lockdown/k8s/egress-networkpolicy.yaml` refuses the same ranges a second time, at the network.

`agent-custody policy simulate` replays egress receipts like any other.

## Drafting a policy from observe mode

```bash
agent-custody egress draft-policy --receipts receipts --issuer-key keys/egress.pub [--log-key <pub>]... [--log log.jsonl] > egress-policy.draft.cedar
```

It reads every regular file `*.json` in the directory, never through a symlink, and verifies each one. A symlink, a special file such as a fifo, and a receipt that does not verify are skipped; a receipt that does not verify is named on stderr. It keeps the egress receipts whose agent is `observed` (a verified proxy credential) and whose connection was relayed (`executed`). It prints one `permit` per agent and scheme over the `host:port` destinations that agent used, sorted, with no duplicates. A plain request and a tunnel to the same `host:port` are the same Cedar action, so each permit also names the scheme it saw (`context.facts.destination.scheme`): an observed plain GET never becomes a permitted CONNECT tunnel. Each permit and each destination carries a comment with its count and its first and last time. A destination that is an IP literal in an internal range is marked `INTERNAL ADDRESS`, because the witness dials a literal that a rule names. The output starts with a warning: the draft permits whatever the agents did in the window, bad destinations included, and a person must review it before it is enforced. It exits 1 when there is nothing to permit.

An observe-mode witness writes the receipt of a 407 with the policy's unenforced decision beside a `denied` status, and that receipt does not verify (`policy decision consistent with execution`). `draft-policy` skips it like any receipt that does not verify. `policy simulate` stops on it.

Tutorial: [42-egress-draft.ts](../examples/42-egress-draft.ts).

## What the agent gets back

| case | answer | receipt |
| --- | --- | --- |
| allowed, CONNECT | `200 Connection Established`, then the tunnel | `executed` when the tunnel closes |
| allowed, plain HTTP | the destination's answer, without hop-by-hop headers | `executed` when the answer ends |
| policy refuses | `403`, JSON with the reason | `denied` |
| no valid credential | `407`, with `Proxy-Authenticate: Basic realm="agent-custody egress"` | `denied` |
| destination unreachable, or a host name that resolves only to internal addresses | `502` (plain HTTP: `504` if the request may have arrived) | `error` |
| the log will not commit the connection first | `503` | `withheld` |
| the witness stops before the connection opens | `503` | `error` |
| past `maxInFlight` | `503`, `Retry-After: 1` | none |
| malformed target, or `https://` in a plain request | `400` | none |

Every answer that has a receipt carries `x-agent-custody-receipt`. A plain HTTP request is relayed without `Proxy-Authorization`, so the agent's secret never reaches the destination. The `Host` header is set to the destination the policy decided on, whatever the agent wrote. A request in origin form (`GET /…`) is for the witness itself: `GET /.well-known/agent-custody-egress` answers the key id, the policy digest, and the number of receipts waiting for the log.

## The receipt

The same in-toto statement and v0.2 predicate as every other receipt, signed by the witness's key:

- `issuer`: `{ kind: "egress", framework: "connect" | "http" }`.
- `principal`: `null`, claimed. The witness checks no grant.
- `agent`: as above.
- `tool`: `{ name: "host:port", provenance: "observed" }`.
- `request.args`: `{ method, host, port }`, claimed, as the agent asked.
- `facts.destination`: the observation the policy decided on, observed.
- `execution`:
  - for a relayed connection, `executed` with `result`: `peer`, `openedAt`, `closedAt`, `bytesUp`, `bytesDown`, `end`, and for plain HTTP `status`. `peer` is the address the witness connected to. `end` is `closed`, `reset`, `idle-timeout`, or `witness-stopped`.
  - otherwise `denied` with the reason, or `error`.

For a tunnel, the bytes are the tunnel's payload, which is ciphertext for HTTPS. For plain HTTP, they are the request body and the response body.

**Committed before relaying.** Before any byte of the agent's moves, the witness commits the connection to the log as an authorization: the agent, the destination, and the decision. This is what the door does for a request that can change something. If the log will not take it, nothing is relayed and the agent gets 503. Observe mode is the exception, as at the door: it relays and prints the gap, and that receipt then fails `egress open committed before relaying`, because nothing was committed first. The receipt, written when the connection ends, embeds that authorization and adds the times, the byte counts, and how it ended. So the bypass is on record before it happens, even if the closing receipt is never written. A witness that is stopped normally closes its open connections, including those still connecting, and receipts each one. A witness that is killed leaves the committed authorization in the log, but not the closing receipt with the byte counts.

## What a verifier checks

[Verifying a receipt](verification.md) lists the common checks. On an egress receipt, all three verifiers (TypeScript, the browser page, Python) also run these:

- `egress receipt carries a policy decision`: the witness decides every connection.
- `egress destination observed`: the tool name is observed, and it equals the host and port in the observed destination fact.
- `egress relayed only for a checked agent`: a connection that was relayed (`executed`, `failed`, or `error`) has an agent with provenance `observed`.
- `egress open committed before relaying`: a relayed connection carries the authorization the witness committed before any byte moved. The usual authorization checks then confirm that it names this call and that it sits in the log before the receipt.
- `egress peer matches the destination`: for an IP literal, the recorded `peer` is that very address, since the policy named it. For a host name, the `peer` is a public address.

Vectors `egress-*` and `resigned-egress-*` in `vectors/receipts.json` cover them.

## What it does not do yet

- Record the byte counts of a connection open when the witness is killed: the committed authorization is in the log, the closing receipt is not.
- Identify an agent by its source address or by a signed grant. Today only per-agent proxy credentials identify an agent.
- `agent-custody check` does not read an egress config yet.
- Ask an OPA server for the decision. A `.rego` file works; `opa: { url }` does not, because the decision is made synchronously before the relay.

Tutorials: [41-egress.ts](../examples/41-egress.ts), and [44-egress-rego.ts](../examples/44-egress-rego.ts) for a Rego policy.
