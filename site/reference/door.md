# The door

A reverse proxy in front of your own website, API, or forms. Where the [gateway](./gateway) sits between an agent and its tools, the door sits between the world and your HTTP surface. Every arrival is classified by what it presented, decided by a Cedar policy for the route it hit, relayed to your origin or refused, and receipted either way with the same signed, logged receipt, `issuer.kind: "door"`. The guide is [the door](/receipts/door); this page is the exact contract.

## Config

`door.json`, paths relative to the file. `loadDoorConfig(path)`; schema `DoorConfigSchema`.

```json
{
  "identity": { "keyFile": "keys/door.key" },
  "origin": { "url": "http://127.0.0.1:3000", "headers": { "x-via": "door" }, "headerEnv": { "x-door-secret": "DOOR_SECRET" }, "timeoutMs": 30000 },
  "routes": [
    { "name": "catalogue", "methods": ["GET"], "path": "/catalogue/*" },
    { "name": "refund", "methods": ["POST"], "path": "/refunds" },
    { "name": "api", "path": "/api/*" }
  ],
  "unmatchedRoute": "other",
  "trustedPrincipalKeys": ["keys/principal.pub"],
  "policyFile": "policy.cedar",
  "mode": "enforce",
  "trustProxy": false,
  "maxBodyBytes": 1048576,
  "maxResponseBytes": 33554432,
  "maxInFlight": 256,
  "receiptsDir": "receipts",
  "logFile": "log.jsonl"
}
```

| field | type | meaning |
| --- | --- | --- |
| `identity.keyFile` | path | the door's Ed25519 private key; signs every receipt |
| `origin.url` | URL | where allowed arrivals are relayed; a path in it is kept as the prefix of every relayed path |
| `origin.headers`, `origin.headerEnv` | maps, optional | headers added to every relayed request; `headerEnv` maps a header name to an environment variable, read at startup, missing is a startup error |
| `origin.timeoutMs` | integer, default 30000 | one relayed request's budget |
| `routes[]` | `{ name, methods?, path }` | the action per arrival. `path`: exact (`/refunds`), prefix (`/api/*`, which also matches `/api`), or `*`. `methods`: a subset of GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS; default all. First match wins, on the path percent-decoded once with empty segments merged (`normalizePath`: `//admin/x` and `/admin//x` are `/admin/x`); a trailing slash matches as none (`/refunds/` matches `/refunds`). The origin is sent that form encoded once, trailing slash kept. Names are unique |
| `unmatchedRoute` | string, default `other` | the action for an arrival no route matches |
| `trustedPrincipalKeys` | paths, default `[]` | principals whose grants are passports |
| `policyFile` | path | Cedar; re-read on change; a file that does not parse is refused and the policy in force stays |
| `mode` | `enforce` (default) or `observe` | observe relays everything and records `enforced: false` |
| `trustProxy` | boolean, optional | one trusted proxy in front: the arrival's address is the last in `X-Forwarded-For`; the proxy's `X-Forwarded-*`, `Forwarded`, `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP`, `X-Client-IP`, `X-Cluster-Client-IP`, and `Fastly-Client-IP` are kept on the relay. Without it the door drops all of these and sets its own |
| `maxBodyBytes` | integer, default 1 MiB | a larger request body the policy allowed is refused with 413 and receipted as `withheld`; one the policy refuses is `denied` as any other |
| `maxResponseBytes` | integer, default 32 MiB | a larger origin response is not relayed: 502, and the receipt records the origin's act by size |
| `maxInFlight` | integer, default 256 | arrivals handled at once; past it, 503 with `Retry-After: 1` before the body is read, no receipt |
| `precommit` | strings, default `[]` | route names whose arrivals are committed to the log before they are relayed whatever their method, or `["*"]`. Every arrival whose method is not GET, HEAD, or OPTIONS is committed regardless |
| `receiptsDir`, `logFile` or `log`, `otel`, `splunk`, `capture`, `captureKeyEnv` | | as for the [gateway](./gateway#the-config-file). Capture rules are keyed by route name. Without a rule for the route and without a `"*"` rule, the door applies `DOOR_DEFAULT_CAPTURE`: `args` in digest mode with `method`, `path`, `headers`, `bodyBytes`, `bodyOversized` in clear; the query, the body, and `bodyDigest` are withheld as `request.args.$rest`; `facts` and `result` clear. A remote `log` needs `log.keys` |

## Running it

```bash
agent-custody check --config door.json
agent-custody door --config door.json [--port 8780] [--host 127.0.0.1]
```

Plain HTTP; bind to loopback or put TLS in front. `check` on a door config reports unknown keys, the key, the principal keys, the policy (and warns on a permit that names an agent without requiring `context.facts.arrival.class == "verified"`), the routes, what is precommitted, the origin's scheme, every credential variable the door reads at startup (origin headers, log, Splunk, OTel, capture key), and the paths; exit 1 on an error.

In code: `createDoorHost(cfg, { log?, exporter?, fetch?, autoFlush? })` returns a `DoorHost` with `keyid`, `policyDigest()`, `handle(req, res)`, `flushOutbox()`, `pendingReceipts()`, `close()`. `serveDoor(host, { port, host?, log? })` returns `{ url, close() }`. `normalizePath(pathname)`, `matchRoute(routes, unmatched, method, path)`, `classifyArrival(req, trustedKeys, route, trustProxy, atIso)`, `cedarArgs(args)`, and `DOOR_DEFAULT_CAPTURE` are exported for embedding the door in a server of your own.

## What an arrival presents

| header | effect |
| --- | --- |
| `Authorization: Bearer <base64url DSSE envelope>` or `X-Agent-Custody-Grant: <same>` | a grant, as to the HTTP gateway. Signed by a trusted principal, inside its window, with the route among its scopes: the arrival is `verified`. Otherwise `claimed`, with the reason in the arrival fact. Stripped before relaying. Bearer-grade: the door does not check that the sender holds the agent's key, and a verified receipt carries the grant in `delegation`, so whoever reads the receipt can present the grant until it expires. Keep door grants short-lived |
| `X-Agent-Custody-Agent: <name>` | a declared name; `claimed`, never checked. Stripped before relaying |
| `Signature-Input` (RFC 9421) | noted as `signature: true`; not checked yet; `claimed` |
| nothing of the above | `unknown` |

## The arrival fact

Recorded as `facts.arrival` (observed) and given to the policy as `context.facts.arrival`:

```json
{ "class": "verified", "subject": "shopping-agent", "grant": "verified", "signature": false, "remote": "203.0.113.9", "method": "POST", "path": "/refunds", "route": "refund" }
```

`class`: `verified` | `claimed` | `unknown`. `grant`: `verified` | `out-of-scope` | `invalid` | `absent`, with `grantError` when not verified. `declared` when the agent header was sent. There is no `human` class. `subject` reaches the Cedar principal only when `class` is `verified`.

## The Cedar request

`principal` `Agent::"<agent>"` for a verified arrival's agent, `Agent::"unknown"` otherwise; `action` and `resource` the route name. `context.args`: `{ method, path, query, headers, body?, bodyBytes, bodyDigest }`, where `path` is normalised as above, `query` maps names to a string or an array of strings (own properties: `?constructor=x` and `?__proto__=x` are parameters), `headers` carries `user-agent`, `content-type`, `accept`, `host` only, and `body` is present for a JSON body of at most 64 KiB. A body above `maxBodyBytes` gives `bodyBytes` (read so far) and `bodyOversized: true`, no `body`, no `bodyDigest`. The policy reads `cedarArgs(args)`: `null` members dropped, numbers that are not safe integers as strings, since Cedar refuses both; the receipt keeps the body as sent. `context.facts.arrival` as above. `context.grant` `{ principal, scopes }` only when verified.

## Before relaying

An arrival whose method is not GET, HEAD, or OPTIONS, or whose route is in `precommit`, is committed to the log as an authorization statement before it is relayed, as the [gateway's precommit](./gateway#the-config-file) does; `receipts/<receiptId>.authorization.json`, embedded in the receipt as `authorization`. A refusal by the log: 503, `withheld`, nothing relayed; in observe mode relayed, and printed.

## Responses

| outcome | status | body | headers | receipt `execution` |
| --- | --- | --- | --- | --- |
| relayed | the origin's | the origin's | the origin's, minus hop-by-hop, plus the door's; a `Location` on the origin's host, on any scheme or port, becomes a path on the door: under the origin's path it loses that prefix, and any other path is kept as it is | `executed`; `failed` on an origin 5xx. `result` is `{ status, contentType?, bodyBytes, bodyDigest }` |
| denied, whatever the body's size | 403 | `{ "error": "refused by the door's policy", "reason", "receipt" }` | the door's | `denied` |
| origin unreachable (connection refused, host not resolved) | 502 | `{ "error": "the origin could not be reached", "detail", "receipt" }` | the door's | `error` |
| outcome unknown (timeout, reset, body stopped after the headers) | 504 | `{ "error": "the origin may have acted on the request; its answer did not arrive. Do not retry", "detail", "receipt" }` | the door's | `error`; `error` says the origin may have acted |
| allowed, body too large | 413 | `{ "error": "not relayed", "reason", "receipt" }` | the door's | `withheld` |
| allowed, log refused the authorization | 503 | `{ "error": "not relayed", "reason", "receipt" }` | the door's | `withheld` |
| allowed, a path segment does not decode or decodes to a slash | 400 | `{ "error": "not relayed", "reason", "receipt" }` | the door's | `withheld`, under `unmatchedRoute` |
| allowed, origin's response above `maxResponseBytes` | 502 | `{ "error", "receipt" }` | the door's | `executed` or `failed`; `result` is `{ status, contentType?, bodyBytes, bodyOversized: true }` |
| receipt could not be written | 500 | `{ "error", "outcome", "receipt" }` | `X-Agent-Custody-Receipt`, `-Class` | none; `outcome` says whether the origin acted |
| more than `maxInFlight` at once | 503 | `{ "error" }` | `Retry-After: 1` | none |

The door's headers on every answer: `X-Agent-Custody-Receipt` (receipt id), `X-Agent-Custody-Class`, and `X-Agent-Custody-Log-Pending: true` when the receipt waits in the outbox. On the relayed request: the same two, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto` (the socket's address, the `Host`, and `http`; with `trustProxy` the proxy's values, the address appended), `X-Real-IP` (the socket's address, without `trustProxy`), and `Accept-Encoding: identity`; `Expect` is not relayed. Every `Set-Cookie` from the origin is relayed.

`GET /.well-known/agent-custody-door` → `{ "keyid", "policyDigest", "version", "pendingReceipts" }`.

## The receipt

Receipt v0.2 with `issuer: { kind: "door", keyid, version, framework: "http" }`. `tool.name` is the route, observed. `request.args` as the Cedar request's `args`, claimed. For a verified arrival `principal` and `agent` are attested and `delegation` carries the grant; otherwise `principal` is `{ id: null, provenance: "claimed" }` and `agent.id` is the subject, claimed. `authorization` is present when the request was committed before relaying. Verification runs `door receipt carries a policy decision` and otherwise the gateway's checks, the authorization checks included; vectors `door-*`. See the [specification](/receipt/v0.2).

## Not yet

Agent detection in web or API traffic, RFC 9421 and Web Bot Auth verification (so a grant is not yet bound to its sender), AP2 mandates, a challenge branch, grant revocation lists, streamed request bodies, and streamed responses or responses above `maxResponseBytes` (a larger response is cut at the limit: 502 to the client, `executed` with `bodyOversized` in the receipt).
