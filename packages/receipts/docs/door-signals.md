# Door signals: what each one does and does not mean

The door records one fact for every arrival, `arrival`, and gives it to the policy as `context.facts.arrival`. Every field in it is a signal: something the door observed, labelled by how far it was checked. None of them is a verdict. This page says, for each signal, what it establishes, what it does not, and how a policy should read it. The door's guide is [the door](door.md); the contract is the [reference](https://agent-custody.dev/reference/door).

Three labels run through the table:

- **Checked.** The door verified it against a key it trusts or computed it itself. A policy may rely on it.
- **Observed.** The door saw it on the wire. It is true that it was sent; nothing about the sender follows.
- **A claim.** The caller asserted it and the door could not check it. A policy that relies on it relies on the caller.

## The signals

| signal | label | what it means | what it does not mean |
| --- | --- | --- | --- |
| `class: "verified"` | checked | A grant signed by a principal in `trustedPrincipalKeys`, inside its validity window, names this agent and lists this arrival's route among its scopes. The Cedar `principal` is that agent | That the agent is well-behaved, that the principal is who they say they are beyond holding the key, or that the request body is what the principal intended. The grant has no revocation list: it stands until it expires |
| `class: "claimed"` | a claim | Something was asserted that the door could not accept: a grant from a key it does not trust, an expired one, one for other routes, a declared agent name, or an HTTP signature header. `grant` and `grantError` say which | That the arrival is an agent, or that it is hostile. A misconfigured client, a grant for the wrong route, and an impostor all look the same here |
| `class: "unknown"` | observed | Nothing was presented | That the arrival is a person. A browser, a crawler, and a script that sends no headers are all `unknown`. There is no `human` class, and a policy that admits `unknown` on a route admits everything on that route |
| `grant: "verified"` | checked | As `class: "verified"` | |
| `grant: "out-of-scope"` | checked | The grant verified and is valid, but this route is not among its scopes. `subject` is the agent it names | That the agent may do anything here. The principal did not grant this route |
| `grant: "invalid"` | checked | The grant did not verify against a trusted key, did not decode, or is outside its window. `grantError` says which | Who signed it. A grant from an untrusted principal is `invalid` even when it is genuine |
| `grant: "absent"` | observed | No grant header | |
| `subject` | checked only when `class` is `verified` | The agent a verified grant names; else the declared name or the agent a rejected grant named; else `unknown` | For a `claimed` arrival, anything. It is recorded so the receipt shows what was asserted; the Cedar `principal` is `Agent::"unknown"` for it |
| `declared` | a claim | The `x-agent-custody-agent` header, as sent, cut at 200 characters | That the agent is that agent. Anyone can send the header. A permit on a declared name admits whoever types it |
| `signature: true` | a claim | An RFC 9421 `Signature-Input` header was present, so the arrival asserts a signature | That the signature is valid, or who signed. **The door does not check it yet.** It is recorded so that a later verifier, or a reader of the receipt, knows a signature travelled with the request |
| `remote` | observed | The socket's address, or with `trustProxy` the last address in `X-Forwarded-For`, the one your proxy appended | Who the person or program is. One address serves a whole office, a mobile carrier, or a cloud region; one program can use many |
| `challenge.outcome` | checked, against the provider | Only when `challenge` is configured. `passed`: Turnstile or hCaptcha confirmed the token this arrival sent, so the provider judged a person present when the token was made. `failed`: the provider refused the token itself (bad, expired, or already used; `error` carries the codes), the token was issued on a hostname not in `hostnames` or for another action, or it was too long to be a token. `unavailable`: the provider did not answer in time, answered a non-200, a redirect, or something that is not JSON, reported a fault of its own or of the operator's (a wrong or rotated secret, a site key that does not match it), or too many checks were already waiting, which is the provider's or the door's state, not the arrival's. `absent`: no token | That the arrival is a person now, or that the person is who they say: a token is made once and sent by whatever holds it, and the provider's own error rate applies. It does not change `class`. `unavailable` is not `failed`: a policy that treats it as one locks everyone out when the provider is down, and one that treats it as a pass admits everyone; say which, on purpose |
| `rate.burst`, `rate.minute` | checked | Arrivals from the same source in the last 10 and 60 seconds, this one included, whatever the policy decided about them, counted by this door process on a monotonic clock, so a step of the wall clock does not move the windows. `rate.by` says what the source is: `agent`, the verified agent's name, or `remote`, the address | That the source is a program, or that it is abusive. Twenty arrivals a minute is one page load for a site that fans out to its API, and one agent on a job. The count is one process's memory: it starts at one when the door starts, two doors do not share it, and an address shared by many people counts them together. It keeps at most 10,000 sources and forgets the least recently seen first, so a client that sends from many new addresses can make another source's count start again |
| `method`, `path`, `route` | observed | What arrived, the path percent-decoded once, and the route it fell under | |

## Reading them in a policy

The signals are attributes of `context.facts.arrival`. A permit for an agent requires the arrival to be verified, or the permit admits nothing but a header:

```cedar
permit(principal == Agent::"shopping-agent", action == Action::"api", resource)
when { context.facts.arrival.class == "verified" };
```

`agent-custody check` warns about a permit that names an agent without that condition.

Rate is a reason to slow a route down or to ask for more, not a reason to decide what the arrival is. A forbid on it refuses the arrivals past the limit and receipts each refusal, so the receipts show how often the limit was hit and by what:

```cedar
forbid(principal, action == Action::"refund", resource)
when { context.facts.arrival.rate.minute > 30 };
```

A limit by `remote` reaches everyone behind one address. Put it high enough that a shared address is not refused for one user's pace, or scope it to routes where a person's pace is slow in any case, as a refund form is. For a verified agent the count is by agent name across every address it uses, so a limit on a verified agent is a limit on the agent.

An `unknown` arrival that comes fast is still unknown. The honest policy for a route that should not take bursts from strangers is to refuse them and say why, and to route the agents you want through a grant, which makes them `verified` and counted by name.

A challenge is the way a person gets through a route that refuses `unknown`. The permit names the outcome, not the class, and a second permit lets the agents you trust through without the widget:

```cedar
permit(principal, action == Action::"refund", resource)
when { context.facts.arrival.challenge.outcome == "passed" };

permit(principal == Agent::"shopping-agent", action == Action::"refund", resource)
when { context.facts.arrival.class == "verified" };
```

Decide what `unavailable` means for each route before the provider has its first outage: a forbid on `outcome != "passed"` closes the route then, and the receipts show that the provider, not the arrivals, was the reason.

## What is not a signal yet

Nothing in the arrival fact says whether the arrival is a program. Behavioural and fingerprint signals, HTTP message signature verification, and Web Bot Auth directory lookups are not built; when they are, each will arrive with a measured error rate beside it, and this page will say what it means. Until then a policy has the grant, the claims, the address, and the pace, and the receipt records which of them it used.
