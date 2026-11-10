# Put the door in front of a site

This page is for someone who runs a website or an API. In about fifteen minutes you run the door in front of a small stand-in site, write one policy for a sign-up form, and watch four arrivals: a bot that is refused and told how to pass the challenge, a bot that only claims to be an agent, a person who passes the challenge, and an agent that shows a passport. Then you verify the receipts with public keys only.

You need Node 22 or later and `curl`. The person in step 6 passes Cloudflare Turnstile with its public test keys, which needs no account but does call Cloudflare once. Everything else runs on your machine.

The door does not have its own container yet ([#258](https://github.com/svayatta/agent-custody/issues/258)), so this page runs the CLI from npm:

```bash
alias agent-custody='npx -y -p @agent-custody/receipts@0.16.4 agent-custody'
mkdir door-quickstart && cd door-quickstart
```

## 1. Keys

The door signs every receipt with its own key. The principal key belongs to whoever vouches for an agent: it signs the agent's passport, and the door trusts the passports it signs.

```bash
agent-custody keygen --dir keys --name door
agent-custody keygen --dir keys --name principal
```

## 2. A stand-in site

Your real site goes here later. This one answers a page on `GET /` and accepts a sign-up on `POST /form`:

```bash
node -e 'require("http").createServer((q,s)=>{s.setHeader("content-type","text/plain");s.end(q.method==="GET"?"the sign-up page\n":"thanks, you are signed up\n")}).listen(3000,"127.0.0.1")' &
```

## 3. The policy

The door names each request by the route it falls under, and the policy decides per route. Anything the policy does not permit is refused. `policy.cedar`:

```cedar
// The page is public.
permit(principal, action == Action::"page", resource);

// The form takes a person who has passed the challenge...
permit(principal, action == Action::"form", resource)
when { context.facts.arrival.challenge.outcome == "passed" };

// ...or an agent whose passport covers the form.
permit(principal, action == Action::"form", resource)
when { context.facts.arrival.class == "verified" };
```

## 4. The door's config

`door.json`:

```json
{
  "identity": { "keyFile": "keys/door.key" },
  "origin": { "url": "http://127.0.0.1:3000" },
  "routes": [
    { "name": "page", "methods": ["GET"], "path": "/" },
    { "name": "form", "methods": ["POST"], "path": "/form" }
  ],
  "trustedPrincipalKeys": ["keys/principal.pub"],
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

`1x00000000000000000000AA` and the secret below are Cloudflare's [test keys](https://developers.cloudflare.com/turnstile/troubleshooting/testing/): every token passes, and the answer names the host `example.com`. Check the config before you start the door; it should end with `no errors, 0 warnings`:

```bash
export TURNSTILE_SECRET=1x0000000000000000000000000000000AA
agent-custody check --config door.json
```

## 5. Start the door

```bash
agent-custody door --config door.json --port 8780 &
curl -s http://127.0.0.1:8780/
```

```text
the sign-up page
```

The page went through the door, so it already has a receipt.

## 6. Four arrivals at the form

**A bot.** It presents nothing. The policy refuses it, and the 403 says how to pass the challenge, so your page can show the widget and try again:

```bash
curl -si -X POST http://127.0.0.1:8780/form -H 'content-type: application/json' -d '{"email":"a@example.com"}'
```

```text
HTTP/1.1 403 Forbidden
x-agent-custody-receipt: 454a8bef-8044-4cc7-9806-b421918507d2
x-agent-custody-class: unknown

{"error":"refused by the door's policy","reason":"no permit policy matched","receipt":"454a8bef-8044-4cc7-9806-b421918507d2","challenge":{"provider":"turnstile","siteKey":"1x00000000000000000000AA","header":"x-agent-custody-challenge"}}
```

**A bot that says it is an agent.** A name in a header is a claim, and the door records it as one: the class is `claimed`, and no permit reads a claim:

```bash
curl -si -X POST http://127.0.0.1:8780/form -H 'content-type: application/json' -H 'x-agent-custody-agent: shopping-agent' -d '{"email":"a@example.com"}'
```

```text
HTTP/1.1 403 Forbidden
x-agent-custody-class: claimed
```

**A person.** On a real page the Turnstile widget produces a token, and the page sends it in `x-agent-custody-challenge`. The door asks Cloudflare whether it is good. With the test secret any token passes:

```bash
curl -si -X POST http://127.0.0.1:8780/form -H 'content-type: application/json' -H 'x-agent-custody-challenge: XXXX.DUMMY.TOKEN.XXXX' -d '{"email":"a@example.com"}'
```

```text
HTTP/1.1 200 OK
x-agent-custody-class: unknown

thanks, you are signed up
```

The class stays `unknown`: a passed challenge says the arrival solved a challenge, not who it is.

**An agent with a passport.** The principal signs a grant that names the agent and the routes it may use. The agent sends it, base64url-encoded, in `x-agent-custody-grant` (or as `Authorization: Bearer`):

```bash
agent-custody grant --key keys/principal.key --principal agent-co --agent shopping-agent --scopes form --out grant.json
PASSPORT=$(node -e 'process.stdout.write(Buffer.from(require("fs").readFileSync("grant.json","utf8")).toString("base64url"))')
curl -si -X POST http://127.0.0.1:8780/form -H 'content-type: application/json' -H "x-agent-custody-grant: $PASSPORT" -d '{"email":"agent@example.com"}'
```

```text
HTTP/1.1 200 OK
x-agent-custody-receipt: 3e30a694-f144-4b78-9b57-a906c8777803
x-agent-custody-class: verified

thanks, you are signed up
```

## 7. Verify the receipts

Every arrival left a receipt in `receipts/`, refused or not, and every one is in the log. A sign-up has two: the door commits it to the log before your site hears of it, then receipts the outcome. Your receipt ids differ from the ones here; take them from the `x-agent-custody-receipt` headers.

The refused bot, checked with the door's public key and the log:

```bash
agent-custody verify receipts/454a8bef-8044-4cc7-9806-b421918507d2.json --issuer-key keys/door.pub --log log.jsonl
```

```text
PASS  policy decision consistent with execution  (deny -> denied)
PASS  log inclusion proof  (leaf 2 of 3, root c1b6db0a0f60)

RESULT: VERIFIED

ISSUER: door (http), enforced in front of the business's own HTTP surface; the arriving party could not forge this receipt and is attested only when it presented a grant, and a request that reached the origin some other way leaves no receipt
```

The agent, with the principal's key as well, so the passport is checked too:

```bash
agent-custody verify receipts/3e30a694-f144-4b78-9b57-a906c8777803.json --issuer-key keys/door.pub --principal-key keys/principal.pub --log log.jsonl
```

```text
PASS  delegation signature (principal key)  (signed by 9ebc1bcd4701)
PASS  executed tool within delegated scope  (form)
PASS  authorization logged before execution  (authorization leaf 6, receipt leaf 7)

RESULT: VERIFIED

principal       attested    agent-co
agent           attested    shopping-agent
policy          observed    allow [policy2] policy fbb0e37266c4
```

The output above is cut to the lines that matter; the full report lists every check. The request body is not in either receipt, only its digest: the door withholds by default ([what a receipt records](door.md#what-a-receipt-records-of-the-query-and-the-body)).

Stop the door and the stand-in site with `kill %1 %2`.

## Before you put it in front of your own site

- **Use your own Turnstile keys.** Put the widget on the page that posts the form, set `siteKey`, the secret in `TURNSTILE_SECRET`, and `hostnames` to your site's hosts. A token serves one request, so the page takes a new one for each submit ([challenging a human](door.md#what-the-door-knows-about-an-arrival)).
- **Make the door the only way in.** A request that reaches your site some other way leaves no receipt. Bind the site to a private address, or have it require a header that only the door adds (`origin.headerEnv`).
- **Behind your own TLS proxy,** set `trustProxy` so the door reads the client's address, not the proxy's.
- **A passport is bearer-grade.** The door checks its signature, window, and scope, not that the sender holds the agent's key. Keep the time to live short.
- **Read [the door](door.md)** for every field of the config, and [door signals](door-signals.md) for what each fact about an arrival does and does not establish, before you write a policy for a route that matters.
