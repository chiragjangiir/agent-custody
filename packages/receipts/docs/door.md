# The door: a receipted reverse proxy in front of your own site or API

The gateway stands between an agent and the tools it uses. The door stands between the world and your own HTTP surface: a website, an API, a form. Every arrival, a browser, an API client, a crawler, or an agent acting for someone, is classified by what it presented, decided by a Cedar policy for the route it hit, relayed to your origin or refused, and receipted either way. The receipt is the same signed, logged, independently verifiable receipt the gateway issues, with `issuer.kind: "door"`.

This is the first piece of the agent front door. It answers "what may this arrival do here" and "what did it do, provably". It does not yet answer "is this an agent" for web traffic: that is detection, and the door records only what it can check. Read [what the door knows](#what-the-door-knows-about-an-arrival) before writing a policy.

```bash
agent-custody keygen --dir keys --name door
agent-custody check --config door.json
agent-custody door --config door.json --port 8780
```

## The config file

`door.json`, paths relative to the file. Loaded with `loadDoorConfig(path)`.

```json
{
  "identity": { "keyFile": "keys/door.key" },
  "origin": { "url": "http://127.0.0.1:3000", "timeoutMs": 30000 },
  "routes": [
    { "name": "catalogue", "methods": ["GET"], "path": "/catalogue/*" },
    { "name": "refund", "methods": ["POST"], "path": "/refunds" },
    { "name": "api", "path": "/api/*" }
  ],
  "unmatchedRoute": "other",
  "trustedPrincipalKeys": ["keys/principal.pub"],
  "policyFile": "policy.cedar",
  "receiptsDir": "receipts",
  "logFile": "log.jsonl"
}
```

| field | meaning |
| --- | --- |
| `identity.keyFile` | the door's Ed25519 key; signs every receipt. From `agent-custody keygen` |
| `origin.url` | where allowed arrivals are relayed: the site or API behind the door. `headers` and `headerEnv` add headers to every relayed request, the latter from the environment, so the origin can require a secret only the door holds. `timeoutMs` bounds one relayed request, default 30 s. A path in the URL (`https://host/api/v1`) is kept: the arrival's path goes under it, and a redirect from the origin to a place under it comes back as a door path |
| `routes` | what the policy sees as the action. `path` is exact (`/refunds`), a prefix (`/api/*`), or `*`; `methods` narrows it, default every method. The first route that matches wins; an arrival no route matches is the action `unmatchedRoute`, default `other`. The match reads the path as the origin will: percent-decoded once, so `/%61dmin` falls under `/admin/*`, and with empty segments merged, so `//admin/users` and `/admin//users` fall under it too (nginx, Apache, and many frameworks merge them). A trailing slash matches as none: `/refunds/` falls under `/refunds`. The origin is sent that merged, decoded form, trailing slash kept, so the door and the origin read one path. A path with a segment that does not decode, or decodes to a slash or a backslash, falls under `unmatchedRoute` and is never relayed |
| `trustedPrincipalKeys` | public keys of principals whose signed grants the door accepts as a passport. Without any, no arrival can be `verified` |
| `policyFile` | the Cedar policy, re-read when the file changes; one that does not parse is refused and the policy in force stays |
| `mode` | `enforce` (default) refuses what the policy denies. `observe` relays everything and records the decision with `enforced: false` |
| `trustProxy` | behind one reverse proxy you run: the arrival's address is the last in `X-Forwarded-For`, the one your proxy appended; everything before it is what the client sent. The proxy's `X-Forwarded-For`, `-Proto`, and `-Host` are kept on the relay, with the door's own socket address appended, and the other client-address headers (`Forwarded`, `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP`, every `X-Forwarded-*`) are relayed as the proxy sent them. Without `trustProxy` the client wrote all of these: the door drops them and sets `X-Forwarded-For`, `-Host`, `-Proto`, and `X-Real-IP` itself |
| `maxBodyBytes` | the largest request body the door relays; a larger one gets 413 and a `withheld` receipt once the policy has allowed it. Default 1 MiB |
| `maxResponseBytes` | the largest origin response the door relays; see [what the arrival gets back](#what-the-arrival-gets-back). Default 32 MiB |
| `maxInFlight` | arrivals handled at once. Each holds its body and the origin's answer in memory until it is answered, so this bounds the door's memory at about `maxInFlight × (maxBodyBytes + maxResponseBytes)`. Past it the next arrival gets 503 with `Retry-After: 1` before its body is read: it is not decided, relayed, or receipted. Default 256 |
| `precommit` | route names whose arrivals are committed to the log before they are relayed whatever their method, or `["*"]`. Every arrival whose method is not GET, HEAD, or OPTIONS is committed regardless; see [before the origin hears of it](#before-the-origin-hears-of-it). Default `[]` |
| `challenge` | the human branch: `{ provider: "turnstile" or "hcaptcha", siteKey, secretEnv, hostnames, action?, header?, timeoutMs?, maxInFlight? }`. `hostnames` lists the hosts of the pages that render the widget, `action` (Turnstile only) the widget's action, and `maxInFlight` (default 64) how many checks may wait on the provider at once. A token an arrival sends in `header` (default `x-agent-custody-challenge`) is verified with the provider, and the outcome is the arrival's `challenge` signal; see [challenging a human](#challenging-a-human). The secret comes from the environment variable, read at startup; missing is a startup error |
| `receiptsDir`, `logFile` or `log`, `otel`, `splunk`, `capture`, `captureKeyEnv` | as for the [gateway](configuration.md): where receipts and the log go, exporters, and private evidence per route. A remote `log` needs `log.keys`, because its answer is checked before a request is relayed. Unlike the gateway, the door withholds by default: see [what a receipt records](#what-a-receipt-records-of-the-query-and-the-body) |

`agent-custody check --config door.json` reads a door config the way the door would: unknown keys, the key, the principal keys, the policy (including a permit that names an agent without requiring a verified arrival, see below), the routes, what is precommitted, the challenge provider or its absence, the origin's scheme, every credential variable the door reads at startup (origin headers, the log, Splunk, OTel, the capture key, the challenge secret), and the paths. It exits 1 on an error.

## What the door knows about an arrival

The door records one fact for every arrival, `arrival`, observed by the door itself, and the policy reads it as `context.facts.arrival`:

| field | values | meaning |
| --- | --- | --- |
| `class` | `verified`, `claimed`, `unknown` | `verified`: a grant signed by a trusted principal, inside its window, naming this route among its scopes. `claimed`: something was asserted that the door could not accept: a grant from a stranger, an expired one, one for other routes, a declared agent name, or an HTTP signature header. `unknown`: nothing was presented |
| `subject` | string | the agent named in a verified grant; else the declared name or the agent a rejected grant named; else `unknown`. Only a verified subject reaches the Cedar `principal` |
| `grant` | `verified`, `out-of-scope`, `invalid`, `absent` | what became of the grant header, with `grantError` when it was not accepted |
| `signature` | boolean | an RFC 9421 `Signature-Input` header was present. **Not checked yet.** It is a claim |
| `declared` | string | the `x-agent-custody-agent` header, when sent. A claim |
| `remote` | string | the arrival's address |
| `challenge` | `{ provider, outcome, error? }` | only when `challenge` is configured. `passed`: the provider confirmed the token the arrival sent. `failed`: the provider refused the token (`invalid-input-response`, `timeout-or-duplicate`, `expired-input-response`, `already-seen-response`, `missing-input-response`, with the codes in `error`), it confirmed a token issued on another hostname or for another action, or the token was longer than 4096 characters, which is refused without calling the provider. `unavailable`: the provider did not answer in time, answered a non-200, a redirect, or something that is not JSON, answered a code that is its own or the operator's fault (`internal-error`, `bad-request`, `missing-input-secret`, `invalid-input-secret`, `sitekey-secret-mismatch`, `invalid-sitekey`, `missing-sitekey`, `invalid-remoteip`: a rotated secret gives every person one of these), or `maxInFlight` checks were already waiting. `absent`: no token. A passed challenge leaves `class` as it was: it says a provider's test was passed in front of this arrival, not who the arrival is |
| `rate` | `{ by, burst, minute }` | arrivals from the same source in the last 10 and 60 seconds, this one included, whatever was decided about them, counted by this door process alone. `by` is `agent` for a verified arrival (counted by the agent's name across addresses) or `remote` (by address). A pace, not a verdict |
| `method`, `path`, `route` | strings | what arrived, and the route it fell under |

[Door signals](door-signals.md) says, for each field, what it establishes and what it does not, and how a policy should read it.

There is no `human` class. The door cannot tell a person from a program that presents nothing, and it does not pretend to. With `challenge` configured, a policy can require a passed challenge on a route instead; without it, a policy that lets `unknown` through on a route is letting everything through on that route, and should say so.

**Presenting a passport.** An agent presents its grant exactly as it does to the HTTP gateway: the DSSE envelope as base64url in `Authorization: Bearer <value>` or in `X-Agent-Custody-Grant`. The scopes of the grant are route names. A grant that travelled in `Authorization` is stripped before the request is relayed, so the origin never sees it; one in the custom header is stripped too. The door's own headers are added to the relayed request: `X-Agent-Custody-Receipt` (the receipt id), `X-Agent-Custody-Class`, and `X-Forwarded-For`, `-Host`, `-Proto`, with `X-Real-IP` when `trustProxy` is off.

**A verified arrival is bearer-grade.** The door checks the grant's signature, window, and scope. It does not check that the sender holds the agent's key: there is no request signature yet (RFC 9421 is [future work](#what-it-does-not-do-yet)). Anyone who holds the grant's bytes is that agent until the grant expires, and every verified receipt carries the grant in `delegation`, so a person who can read one receipt can replay its grant. Issue door grants with short lifetimes (minutes, not days), scope them to the routes they need, bound what a route allows per call in the policy, and treat receipt files and logs as holding live credentials until those grants expire.

**Challenging a human.** The door builds no CAPTCHA. With `challenge` configured, a page in front of a protected route renders the provider's widget (Cloudflare Turnstile or hCaptcha) with `siteKey`, and sends the token the widget produced in the `challenge.header` header of its request. The door posts the token and the secret from `secretEnv` to the provider's `siteverify` endpoint, with a timeout, and records the answer as `challenge.outcome`. It adds the arrival's address as `remoteip` only with `trustProxy`, where that address is the client's; without it the socket's address may be a proxy's, and the provider would refuse a token the client solved. It never follows a redirect, which would resend the secret and the token elsewhere. To hCaptcha it also sends `siteKey` as `sitekey`: an hCaptcha secret belongs to the account, and without it a token solved on the account's easiest widget would pass on the hardest. A Turnstile secret belongs to one widget already. `success` alone does not pass: the token must have been issued on one of `hostnames`, and for `action` when one is set, or a token solved on another site that uses this site key, or for another widget, would count. At most `maxInFlight` checks wait on the provider at once; an arrival past that is `unavailable`. The token is stripped before the request is relayed, and neither the token nor the secret is recorded. A policy admits a person on a form route with

```cedar
permit(principal, action == Action::"refund", resource)
when { context.facts.arrival.challenge.outcome == "passed" };
```

and a refused arrival that has not passed is told how in the 403 body: `challenge: { provider, siteKey, header }`, so a page can render the widget and try again.

**A token serves one request.** Turnstile and hCaptcha refuse a token they have seen (`timeout-or-duplicate`, `already-seen-response`), and the door keeps no pass between requests: it does not set a cookie or remember an address. So the page must take a new token for every request it sends to a challenged route, and for every retry: call `turnstile.reset()` or `hcaptcha.reset()` after each request, and wait for the new token before the next. The door checks the token before it reads the body, so a request refused for its size (413), its path (400), or by the policy has used its token too. A second request that sends the same token is `failed`, and the person sees another 403. The outcome is a signal, not a class: a `verified` agent that also passes a challenge is still the agent its grant names, and an `unknown` arrival that passes is still `unknown`, with `challenge.outcome: "passed"` beside it. What the provider's pass means, and what it does not, is in [door signals](door-signals.md). Passkeys are not a provider here: a passkey proves possession of a credential the site registered, which is a login, not a challenge, and belongs to the origin.

### A run against Turnstile's test keys

The tests stub `siteverify`. This run calls the real one once. Cloudflare publishes [test keys](https://developers.cloudflare.com/turnstile/troubleshooting/testing/) that need no account: the site key `1x00000000000000000000AA`, the secret `1x0000000000000000000000000000000AA` (validation always succeeds), the secret `2x0000000000000000000000000000000AA` (validation always fails), and the dummy token `XXXX.DUMMY.TOKEN.XXXX`. The test secrets accept only the dummy token. Cloudflare answers a test key with the hostname `example.com`, so the config names that hostname. These secrets are public. A real secret still goes only into the environment, never into the config or a flag.

The run used the CLI from this repository on 2026-11-10. `policy.cedar`:

```cedar
// The form is for an arrival that has passed the challenge.
permit(principal, action == Action::"form", resource)
when { context.facts.arrival.challenge.outcome == "passed" };
```

`door.json`:

```json
{
  "identity": { "keyFile": "keys/door.key" },
  "origin": { "url": "http://127.0.0.1:3000" },
  "routes": [{ "name": "form", "methods": ["POST"], "path": "/form" }],
  "policyFile": "policy.cedar",
  "receiptsDir": "receipts",
  "logFile": "log.jsonl",
  "challenge": {
    "provider": "turnstile",
    "siteKey": "1x00000000000000000000AA",
    "secretEnv": "TURNSTILE_SECRET",
    "hostnames": ["example.com"]
  }
}
```

A stand-in origin answers every request with `{"ok":true}`:

```bash
agent-custody keygen --dir keys --name door
node -e 'require("http").createServer((q,s)=>{s.setHeader("content-type","application/json");s.end(JSON.stringify({ok:true}))}).listen(3000,"127.0.0.1")' &
```

**The pass run.** Start the door with the secret that always succeeds, and send the dummy token:

```bash
TURNSTILE_SECRET=1x0000000000000000000000000000000AA agent-custody door --config door.json --port 8780 &
curl -sS -i -X POST http://127.0.0.1:8780/form -H 'content-type: application/json' \
  -H 'x-agent-custody-challenge: XXXX.DUMMY.TOKEN.XXXX' -d '{"name":"test"}'
```

```text
HTTP/1.1 200 OK
x-agent-custody-receipt: 74c1e645-3b3e-4306-a70c-057ea0e61d41
content-type: application/json
date: Tue, 10 Nov 2026 02:24:05 GMT
x-agent-custody-class: unknown
Connection: keep-alive
Keep-Alive: timeout=5
Transfer-Encoding: chunked

{"ok":true}
```

**The fail run.** Stop the door. Start it again with the secret that always fails, and send the same request:

```bash
TURNSTILE_SECRET=2x0000000000000000000000000000000AA agent-custody door --config door.json --port 8780 &
curl -sS -i -X POST http://127.0.0.1:8780/form -H 'content-type: application/json' \
  -H 'x-agent-custody-challenge: XXXX.DUMMY.TOKEN.XXXX' -d '{"name":"test"}'
```

```text
HTTP/1.1 403 Forbidden
x-agent-custody-receipt: 01b840df-6a79-408a-9d3b-32dac88787d8
content-type: application/json
cache-control: no-store
x-agent-custody-class: unknown
Date: Tue, 10 Nov 2026 02:24:13 GMT
Connection: keep-alive
Keep-Alive: timeout=5
Transfer-Encoding: chunked

{"error":"refused by the door's policy","reason":"no permit policy matched","receipt":"01b840df-6a79-408a-9d3b-32dac88787d8","challenge":{"provider":"turnstile","siteKey":"1x00000000000000000000AA","header":"x-agent-custody-challenge"}}
```

**Verify both receipts.** Both exit 0:

```bash
agent-custody verify receipts/74c1e645-3b3e-4306-a70c-057ea0e61d41.json --issuer-key keys/door.pub --log log.jsonl
```

```text
PASS  receipt signature (issuer key)  (keyid e316d40ebc50)
PASS  receipt payload type
PASS  structural parts in clear
PASS  issuer kind is known  (door / http)
PASS  issuer keyid matches signer
PASS  door receipt carries a policy decision
PASS  principal is claimed, not attested  (no signed delegation in this receipt)
PASS  request args digest  (committed, not recomputed: 1 value(s) withheld; disclose them to recompute)
PASS  execution result digest
PASS  withheld facts.arrival.resultDigest  (committed, not recomputed: 1 value(s) withheld; disclose them to recompute)
PASS  policy decision consistent with execution  (allow -> executed)
PASS  no policy errors on an allow
PASS  authorization signature (issuer key)  (keyid e316d40ebc50)
PASS  authorization names this call  (form for receipt 74c1e645-3b3)
PASS  authorization tree head signature  (keyid e316d40ebc50)
PASS  authorization log inclusion proof  (leaf 0 of 1)
PASS  authorization logged before execution  (authorization leaf 0, receipt leaf 1)
PASS  tree head signature  (issuer key e316d40ebc50)
PASS  tree head matches inclusion proof size
PASS  log inclusion proof  (leaf 1 of 2, root 67f4115b31c2)
PASS  log file root matches tree head  (recomputed 67f4115b31c2)

RESULT: VERIFIED

ISSUER: door (http), unknown issuer kind

field           provenance  value
principal       claimed     (none)
agent           claimed     unknown
model           claimed     (none supplied)
tool            observed    form
args            claimed     {"$rest":{"$custody":"withheld","sha256":"8f41daf2…"},"bodyBytes":15,"headers":{"accept":"*/*","content-type":"application/json","host":"127.0.0.1:8780","user-agent":"curl/8.7.1"},"method":"POST","path":"/form"}
fact.arrival    observed    {"challenge":{"outcome":"passed","provider":"turnstile"},"class":"unknown","grant":"absent","method":"POST","path":"/form","rate":{"burst":1,"by":"remote","minute":1},"remote":"127.0.0.1","route":"form","signature":false,"subject":"unknown"}
policy          observed    allow [policy0] policy 71e3eefa3599
authorization   observed    committed to the log as leaf 0, before the call was forwarded
execution       observed    executed
```

```bash
agent-custody verify receipts/01b840df-6a79-408a-9d3b-32dac88787d8.json --issuer-key keys/door.pub --log log.jsonl
```

```text
PASS  receipt signature (issuer key)  (keyid e316d40ebc50)
PASS  receipt payload type
PASS  structural parts in clear
PASS  issuer kind is known  (door / http)
PASS  issuer keyid matches signer
PASS  door receipt carries a policy decision
PASS  principal is claimed, not attested  (no signed delegation in this receipt)
PASS  request args digest  (committed, not recomputed: 1 value(s) withheld; disclose them to recompute)
PASS  withheld facts.arrival.resultDigest  (committed, not recomputed: 1 value(s) withheld; disclose them to recompute)
PASS  withheld execution.reason  (committed, not recomputed: 1 value(s) withheld; disclose them to recompute)
PASS  policy decision consistent with execution  (deny -> denied)
PASS  no policy errors on an allow
PASS  tree head signature  (issuer key e316d40ebc50)
PASS  tree head matches inclusion proof size
PASS  log inclusion proof  (leaf 2 of 3, root 54a065656fa2)
PASS  log file root matches tree head  (recomputed 54a065656fa2)

RESULT: VERIFIED

ISSUER: door (http), unknown issuer kind

field           provenance  value
principal       claimed     (none)
agent           claimed     unknown
model           claimed     (none supplied)
tool            observed    form
args            claimed     {"$rest":{"$custody":"withheld","sha256":"255b518c…"},"bodyBytes":15,"headers":{"accept":"*/*","content-type":"application/json","host":"127.0.0.1:8780","user-agent":"curl/8.7.1"},"method":"POST","path":"/form"}
fact.arrival    observed    {"challenge":{"error":"invalid-input-response","outcome":"failed","provider":"turnstile"},"class":"unknown","grant":"absent","method":"POST","path":"/form","rate":{"burst":1,"by":"remote","minute":1},"remote":"127.0.0.1","route":"form","signature":false,"subject":"unknown"}
policy          observed    deny [] policy 71e3eefa3599
execution       observed    denied: (reason withheld under the capture rule)
```

The pass run's receipt records `challenge.outcome: "passed"`, and the door relayed the request. The fail run's receipt records `challenge.outcome: "failed"` with Cloudflare's code `invalid-input-response`, and the policy refused the request. The token does not appear in either receipt.

**What this run shows, and what it does not.** Test keys prove the wire path, not bot detection. The door reaches the real `siteverify`, sends the secret and the token, and records the answer. A test secret gives a fixed answer and no widget runs, so the run says nothing about how well Turnstile tells a person from a bot. The run did not exercise the `unavailable` outcome, a hostname mismatch, an action mismatch, the `timeout-or-duplicate` code, or `remoteip` (the config sets no `trustProxy`, so the door sent none). `test/door.test.ts` covers those against a stubbed `siteverify`. In the output above, the two `sha256` digests are shortened to eight characters and `…`. Nothing else is changed. The CLI was `agent-custody` 0.16.2, run from this repository at commit `64285ef`.

## How an arrival becomes a Cedar request

| Cedar slot | value |
| --- | --- |
| `principal` | `Agent::"<agent>"` for the agent a verified grant names; `Agent::"unknown"` for every other arrival. A declared name and the agent a rejected grant names stay in the arrival fact: a permit on `principal == Agent::"shopping-agent"` cannot be satisfied by sending a header |
| `action` | `Action::"<route>"` |
| `resource` | `Tool::"<route>"` |
| `context.args` | `{ method, path, query, headers, body?, bodyBytes, bodyDigest }`. `query` holds every parameter by name, as own properties, so `?constructor=x` is a parameter. `headers` carries `user-agent`, `content-type`, `accept`, and `host` only. `body` is present for a JSON body of at most 64 KiB; every body the door read is recorded by `bodyDigest` (sha256 of the raw bytes) and `bodyBytes`. A body above `maxBodyBytes` is dropped as it passes the limit and recorded as `bodyBytes` read so far and `bodyOversized: true`, with no digest and no `body`. The policy reads a copy that Cedar accepts: Cedar has no `null` and no non-integer number, and refuses the whole request on either, so in the copy a `null` member is dropped and a number that is not a safe integer becomes its string (`9.99` becomes `"9.99"`). A rule that compares such a value as a number then errors, and that rule's deny is the answer. The receipt keeps the body as it arrived. **Provenance: claimed** |
| `context.facts.arrival` | the fact above. **Provenance: observed** |
| `context.grant` | `{ principal, scopes }`, present only when the arrival is `verified`. **Provenance: attested** |

Every rule the gateway's policies obey applies: default deny, `forbid` wins, an evaluation error is a deny, the policy digest is in the receipt. A policy for the shop in the tutorial:

```cedar
// The catalogue is public: humans, agents, anyone.
permit(principal, action == Action::"catalogue", resource);

// Refunds: a verified agent, in its grant's scope, for a positive amount of at most £50.
permit(principal, action == Action::"refund", resource)
when {
  context.facts.arrival.class == "verified" &&
  context.args.body.amount > 0 &&
  context.args.body.amount <= 5000
};

// Everything else on the API is for verified agents.
permit(principal, action == Action::"api", resource)
when { context.facts.arrival.class == "verified" };
```

A refund without a JSON body, with no `amount`, or with an `amount` that is not an integer (`45.5` reaches the policy as `"45.5"`), is an evaluation error and a deny. That is the behaviour you want in front of a payments route. The bound has two ends on purpose: `amount <= 5000` alone admits `{"amount": -1}`, and the door relays the body as it came.

A permit that names an agent, `permit(principal == Agent::"shopping-agent", action == Action::"refund", resource)`, admits only an arrival whose verified grant names that agent, since nothing else reaches the principal slot. `agent-custody check` still warns on such a permit when it does not also require `context.facts.arrival.class == "verified"`: the same text in a gateway policy reads differently, and the condition says what the permit relies on.

## Before the origin hears of it

A request that can change something at the origin, any method but GET, HEAD, and OPTIONS, and any arrival at a route named in `precommit`, is committed to the log before it is relayed, exactly as the gateway's precommit does for a consequential tool call: the door signs an authorization statement (the receipt without its outcome), appends it, writes it as `receipts/<receiptId>.authorization.json`, and only then relays. The receipt embeds it as `authorization`, and the verifier checks that it names this receipt and sits in the log before it. A door that dies between the relay and the receipt leaves the authorization behind, so the side effect has a record and a retry can be told from a first attempt. If the log will not take the authorization, the request is not relayed: 503 and a `withheld` receipt. In observe mode it is relayed and the missing authorization is printed.

## What the arrival gets back

| the door's decision | HTTP | body | receipt `execution.status` |
| --- | --- | --- | --- |
| policy allows, origin answered | the origin's status and body, plus the door's headers | the origin's | `executed`, or `failed` when the origin answered 5xx |
| policy denies, whatever the body's size | 403 | `{ error, reason, receipt }`, plus `challenge: { provider, siteKey, header }` when a challenge is configured and this arrival has not passed it | `denied` |
| origin unreachable: the connection was refused or the host did not resolve | 502 | `{ error, detail, receipt }`, "the origin could not be reached" | `error`; the request never left the door |
| the request left, and its answer did not arrive: a timeout, a reset, or a body that stopped after the headers | 504 | `{ error, detail, receipt }`, "the origin may have acted on the request ... Do not retry" | `error`, and `execution.error` says the origin may have acted. Find out from the origin before retrying a refund |
| policy allows, body above `maxBodyBytes` | 413 | `{ error, reason, receipt }` | `withheld`; nothing was relayed |
| policy allows, the log refused the authorization | 503 | `{ error, reason, receipt }` | `withheld`; nothing was relayed |
| policy allows, the path does not decode cleanly | 400 | `{ error, reason, receipt }` | `withheld`; nothing was relayed |
| policy allows, the origin's response above `maxResponseBytes` | 502 | `{ error, receipt }`, and "do not retry" | `executed` or `failed`: the origin acted; `result` carries the status and `bodyOversized: true`, no digest |
| the receipt could not be written | 500 | `{ error, outcome, receipt }` | none on disk; `outcome` says whether the origin acted, so that a refund is not retried on the strength of a 500 |
| more than `maxInFlight` arrivals at once | 503, `Retry-After: 1` | `{ error }` | none: the arrival was not read, decided, or relayed |

A redirect from the origin to its own host, on any scheme or port, is rewritten to a path, so the client's next request comes back through the door and is classified again. A path under the origin's path loses that prefix; any other path, including one that `..` takes out of it, is kept as it is. A redirect to another host is relayed as sent. Every `Set-Cookie` the origin sent reaches the client. An `Expect: 100-continue` is the client's conversation with the door, which answers it; the origin does not see the header.

Every answer carries `X-Agent-Custody-Receipt` and `X-Agent-Custody-Class`. When the log did not take the receipt, it waits in `receipts/outbox/` and the answer also carries `X-Agent-Custody-Log-Pending: true`; a serving door appends the outbox every 30 seconds, as the gateway does.

`GET /.well-known/agent-custody-door` answers the door's key id, the policy digest in force, the version, and the count of pending receipts.

## What a receipt records of the query and the body

A query can carry an API key (`?api_key=sk_live_...`) and a JSON body a password. When the config gives a route no `capture` rule, and has no `"*"` rule, the door applies its own private rule to it: `method`, `path`, `headers` (the four above), `bodyBytes`, and `bodyOversized` stay in clear, and the query, the body, and `bodyDigest` leave one salted commitment, `request.args.$rest`, in their place. The policy still decides on the real values, because the rule is applied after the decision, and the receipt still verifies. As under any private rule, the denial reason and the policy's error messages are withheld too; the client's 403 still carries the reason. The facts (the arrival) and the result (the origin's status and digest) stay in clear.

To record more in clear, give the route a rule of its own, as for the gateway ([private evidence](configuration.md)): `{ "capture": { "refund": { "args": { "mode": "digest", "clear": ["method", "path", "body"] } } } }` keeps a refund's body in clear, and `{ "capture": { "*": { "args": { "mode": "clear" } } } }` keeps every route's arguments in clear, as before.

## The receipt

A door receipt is a v0.2 receipt with `issuer.kind: "door"` and `issuer.framework: "http"`. The route is the tool, observed. `request.args` is the arrival as the table above describes it, claimed. `facts.arrival` is the door's observation. When the arrival was verified, `principal` and `agent` are attested and `delegation` carries the grant; otherwise `principal` is `{ id: null, provenance: "claimed" }` and `agent` is the subject, claimed. `execution.result` for a relayed call is `{ status, contentType?, bodyBytes, bodyDigest }`: the origin's body is never copied into the receipt, only committed to.

The verifier runs `door receipt carries a policy decision` in place of the gateway's two checks, and otherwise the same checks: a verified arrival's receipt passes `delegation binds principal and agent` and `executed tool within delegated scope`; an unknown arrival's passes `principal is claimed, not attested`; a receipt that carries an `authorization` passes the authorization checks, including `authorization logged before execution`. Both verifiers, the Python verifier, and `policy simulate` accept door receipts; the conformance vectors `door-unknown-executed`, `door-unknown-denied`, and `door-verified-executed` pin them.

## What it does not do yet

- Detect agents in web or API traffic. The only signals are the ones in the arrival fact: `signature` and `declared` are claims, and `rate` is a pace ([door signals](door-signals.md)).
- Check RFC 9421 HTTP message signatures, Web Bot Auth directories, or AP2 mandates. The grant is the only passport today.
- Challenge an arrival with a passkey. Turnstile and hCaptcha are the providers; see [challenging a human](#challenging-a-human).
- Revoke a grant by a revocation list; a grant stands until it expires.
- Bind a grant to its sender. A verified arrival is bearer-grade: see [presenting a passport](#what-the-door-knows-about-an-arrival).
- Stream a request body: the body is read whole, up to `maxBodyBytes`, so that the policy can read it and the receipt can commit to it.
- Relay a response larger than `maxResponseBytes`, or stream one: the body is relayed whole so that its digest can be recorded. A larger one is not held: reading stops at the limit, the client gets 502, and the receipt records that the origin answered.

Tutorial: [40-door.ts](../examples/40-door.ts).
