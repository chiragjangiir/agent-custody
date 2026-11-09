# The egress witness

An HTTP forward proxy for a locked-down agent's connections that do not go to the [gateway](./gateway). It relays CONNECT and plain HTTP, with no TLS interception. Each connection is tied to an agent by the proxy credential the witness checked, decided by a Cedar or Rego policy per destination, and receipted either way with `issuer.kind: "egress"`. The guide is [the egress witness](/receipts/egress), and [credential custody and lockdown](/guide/credential-custody) covers the deployment; this page is the exact contract.

It sees the destination, the times, and the byte counts. It never sees payloads. It sees nothing that skips it, which happens whenever lockdown is off, and it relays no protocol other than HTTP. Each receipt is an observed bypass, not a record of what was done.

## Config

`egress.json`, paths relative to the file. `loadEgressConfig(path)`; schema `EgressConfigSchema`.

| key | type | default | meaning |
| --- | --- | --- | --- |
| `identity.keyFile` | path | required | the witness's signing key |
| `agents` | `{ id, secretEnv }[]` | required, at least one | each agent and the environment variable holding its proxy secret; ids are unique, with no colon or whitespace |
| `policyFile` | path | required | Cedar, or Rego when the name ends in `.rego` (compiled by `opa build`, which must be on `PATH` when it loads); re-read when it changes, and a file that does not parse or compile leaves the policy in force |
| `mode` | `enforce` \| `observe` | `enforce` | `observe` relays every connection from a verified agent and records `enforced: false`; it also relays when the log refuses the commit, and that receipt fails `egress open committed before relaying` |
| `connectTimeoutMs` | integer | 10000 | wait for the destination to accept |
| `idleTimeoutMs` | integer | 300000 | close a relayed connection idle this long |
| `maxInFlight` | integer | 256 | connections at once; past it, 503 with no receipt |
| `receiptsDir` | path | required | |
| `logFile` or `log` | | exactly one | as for the gateway |
| `otel`, `splunk` | | optional | as for the gateway |

## Running it

```bash
agent-custody egress --config egress.json [--port 8791] [--host 127.0.0.1]
```

In code:

```ts
import { createEgressHost, serveEgress, loadEgressConfig } from "@agent-custody/receipts";
const host = await createEgressHost(loadEgressConfig("egress.json"), { autoFlush: true });
const running = await serveEgress(host, { port: 8791, host: "0.0.0.0" });
// on shutdown: host.close() receipts each open connection as witness-stopped, then running.close()
```

`createEgressHost(cfg, { log?, exporter?, autoFlush?, lookup? })` returns `{ keyid, policyDigest(), handleRequest(req, res), handleConnect(req, socket, head), flushOutbox(), pendingReceipts(), close() }`. `draftEgressPolicy(receiptsDir, { issuerKeys, logKeys?, logFile? })` returns `{ policy, agents, read, used, skipped }`: the draft text that `agent-custody egress draft-policy` prints, each agent with its destinations (`name`, `scheme`, `count`, `first`, `last`, `internal`), and each skipped file with its `kind` (`not-a-file`, `unverified`, `not-egress`, `no-agent`, `not-relayed`, `unsafe-name`) and reason. `DRAFT_WARNING` holds the lines the draft starts with. The guide is [writing egress policies](/guide/egress-policies).

Also exported: `checkProxyCredential(header, agents)`, `parseAuthority(authority)`, `normalizeHost(host)`, `destinationName(host, port)`, `DESTINATION_FACT`, `EGRESS_VERSION`, `PROXY_REALM`.

## Requests

- `CONNECT host:port`: a tunnel. The port is required. A host is a DNS name or an IP address, and an IPv6 address is in brackets. The host is made canonical by the URL parser, as a plain request's is, so `2130706433:443` is decided on as `127.0.0.1:443`. A name whose last label is all digits or starts with `0x`, and an IPv4 part with a leading zero in the verifiers, is never treated as a name for an address.
- A plain request in absolute form, `GET http://host[:port]/path`. It is relayed without hop-by-hop headers, `Proxy-Authorization`, or `Expect`, and with `Host` set to the target. An `https://` URL, or credentials in the URL, gets 400.
- A request in origin form is for the witness itself. `GET /.well-known/agent-custody-egress` answers `{ keyid, policyDigest, version, pendingReceipts }`. Any other path gets 404.
- `Proxy-Authorization: Basic base64(id:secret)` identifies the agent. Nothing else does.

## The Cedar request

- **Principal:** `Agent::"<id>"` if the credential verified, otherwise `Agent::"unknown"`.
- **Action and resource:** `"host:port"`.
- **Context:** `args: { method, host, port }`, and `facts.destination: { host, port, scheme, credential, declared?, remote }`.

Without a verified credential, the connection is refused with 407 in every mode.

## The Rego input

For a `.rego` policy file, the same request with plain strings, under `package agentcustody` with `allow` (a boolean) and `deny` (a set of strings), as in the gateway's [Rego contract](/receipts/policies#rego):

| Rego | value |
| --- | --- |
| `input.principal` | the agent id if the credential verified, otherwise `"unknown"` |
| `input.action`, `input.resource` | `"host:port"` |
| `input.context.args` | `{ method, host, port }`. **Provenance: claimed.** |
| `input.context.facts.destination` | `{ host, port, scheme, credential, declared?, remote }`. **Provenance: observed.** |

`deploy/gateway/lockdown/config/egress-policy.cedar` in Rego:

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

The receipt's `policyDigest` is the sha256 of the file's text, as for Cedar. An OPA server (`opa: { url }`) is not supported: the witness decides each connection synchronously before it relays, and a query to a server would put a network round trip outside the witness in front of every connection.

## Responses

| status | when | receipt |
| --- | --- | --- |
| 200 | CONNECT allowed (`Connection Established`, then the tunnel) | `executed` at close |
| the destination's | plain HTTP allowed | `executed` at the end |
| 400 | malformed target | none |
| 403 | the policy refused | `denied` |
| 407 | no valid credential (`Proxy-Authenticate: Basic realm="agent-custody egress"`) | `denied` |
| 500 | the receipt of a refusal could not be written; nothing was relayed | none |
| 502 | the destination could not be reached, or a host name resolved only to internal addresses | `error` |
| 503 | the log would not commit the connection first | `withheld` |
| 503 | the witness stopped before the connection opened | `error` |
| 503 | past `maxInFlight`, or the witness is stopping when the request arrives | none |
| 504 | plain HTTP: the request may have reached the destination and no answer came | `error` |

Answers with a receipt carry `x-agent-custody-receipt`. If the log did not take the receipt yet, the answer also carries `x-agent-custody-log-pending: true`.

## The receipt

- `issuer: { kind: "egress", keyid, version, framework: "connect" | "http" }`
- `principal: { id: null, provenance: "claimed" }`
- `agent`: `{ id, provenance: "observed" }` when verified, otherwise `{ id: "unknown", provenance: "claimed" }`
- `tool: { name: "host:port", provenance: "observed" }`
- `request.args: { method, host, port }`, claimed
- `facts.destination`, observed
- `execution`:
  - `executed`, with `result: { peer, openedAt, closedAt, bytesUp, bytesDown, end, status? }`; `end` is `closed`, `reset`, `idle-timeout`, or `witness-stopped`
  - `denied`, with `reason`
  - `error`, with `error`

- `authorization`: on every relayed connection, the statement committed to the log before any byte moved

The verifier checks are `egress receipt carries a policy decision`, `egress destination observed`, `egress relayed only for a checked agent`, `egress open committed before relaying`, and `egress peer matches the destination`.

A host name is never dialled at an internal address: the resolver drops loopback, private, shared, link-local, metadata, multicast, and reserved addresses, and IPv4-mapped or NAT64 addresses that carry one, before the connection is made. An IP literal is dialled only when the policy names it. `publicOnlyLookup(resolve?)`, `internalAddress(ip)`, `sameAddress(a, b)`, and `isAddressLiteral(host)` are exported.

## Not yet

- The byte counts of a connection open when the witness is killed: the committed authorization is in the log, the closing receipt is not.
- Agent identity by source address or by signed grant.
- `agent-custody check` for an egress config.
- A decision from an OPA server. A `.rego` file works.
