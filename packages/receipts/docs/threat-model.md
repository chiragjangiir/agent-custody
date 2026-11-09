# Threat model

What agent-custody is built to withstand, what it is not, and who has to be trusted in each setup. Written for the security reviewer who has to decide whether the evidence this produces would hold in a dispute, and for us, since every design decision in the packages traces to a row here. Read [verification.md](verification.md) for what each check proves and [compliance.md](compliance.md) for which control each artefact satisfies; this page is about attackers.

## The claim being defended

A receipt is a signed statement that a named agent, acting for a named principal under a specific grant and policy, asked for a specific tool call at a specific time, and that the call was allowed, denied, withheld, executed, or failed, with the arguments and the result digested. The remote log commits to the receipt's existence before or shortly after the action, in a tree whose heads are signed by a key the agent's operator does not hold. The claim under attack is therefore: **this receipt describes what actually happened, and it was not written, altered, or dropped after the fact.**

Everything below asks who could make that claim false, and what stops them.

## Parties

| party | holds | wants, if hostile |
| --- | --- | --- |
| **the agent** (the model and its process) | its own arguments, whatever credentials are in its environment | to act outside its grant, to hide an action, to make a denied action look allowed |
| **the operator** (the team running the agent and the gateway) | the gateway key, the receipts directory, the local log, the policy | to rewrite history after an incident, to produce receipts for actions that did not happen, to drop receipts for ones that did |
| **the principal** (whoever the agent acts for) | their signing key | to disown a grant they signed, or to claim a grant they never gave |
| **the upstream** (the tool, API, or MCP server) | its own key if it signs results, its own records | to deny it served a result, or to claim it served a different one |
| **the log operator** (us, for the hosted log) | the log's signing key, every tenant's leaf hashes, token hashes | to rewrite a tenant's tree, to show different histories to different verifiers, to read receipt contents |
| **the witness** (a second operator) | its own key | to countersign a rewritten history, or to refuse a true one |
| **a network attacker** | the wire between any two of the above | to replay, drop, or alter appends and results |
| **a verifier** (auditor, counsel, regulator) | public keys and receipts they were handed | to be misled by any of the above |

## What the design assumes

- Ed25519 signatures and SHA-256 are sound. Post-quantum signatures are [issue #11](https://github.com/svayatta/agent-custody/issues/11), not present.
- Private keys stay private to their holder. Key custody is the holder's problem; the packages read keys from files or a signer process and never transmit them.
- The gateway runs where the agent cannot read its key or its receipts directory. A gateway in the agent's own container, with the key readable by the agent, is an SDK with extra steps and the receipts it produces are worth exactly that.
- Clocks are roughly right. Timestamps in receipts are the producer's; the log's checkpoint times and the witness's countersignature times are the only times a verifier can hold anyone to.
- A verifier obtains public keys from somewhere the attacker does not control: the log's key document over TLS, or a key file handed over out of band.

## Attacks and what stops them

Each row names the attacker, the move, the defence, and whether the defence is a property of the evidence (holds against anyone later) or a property of the deployment (holds only if the deployment is as described).

### By the agent

| attack | defence | kind |
| --- | --- | --- |
| Call a tool the grant does not allow | The gateway evaluates the policy against the grant the principal signed; the agent never sees the policy or the key. A denied call never reaches the upstream and still produces a receipt. | deployment: only calls through the gateway are covered |
| Feed the policy lies in the arguments | `context.args` is `claimed`; policies that matter read `context.facts`, which the gateway fetched itself and marks `observed`. A policy that decides on args alone is the operator's choice and the receipt shows it. Arguments are passed to Cedar as data only: a value shaped as a Cedar entity or extension (`__entity`, `__extn`) is a deny before evaluation, so an argument cannot satisfy a comparison by its shape. | evidence: provenance is in the receipt |
| Make the gateway run a fact lookup on the way to a denial | A fact lookup runs before the policy decides, because the policy decides on it, and only after the tool is in the grant's scope. It is therefore a read the gateway makes on the agent's request: a fact tool named in `precommit` is refused at startup, so no consequential call can be reached through a lookup, and every lookup is on the receipt with its arguments. | deployment: fact tools must be reads |
| Read the gateway's secrets from a tool process | A stdio upstream is started with a minimal environment (the path, home, and temp directories, plus what its own config names), never the gateway's, so the tokens other upstreams and the log are given do not reach it. | deployment |
| Bypass the gateway with a credential in its own environment | The gateway covers only the tools behind it. Two deployment steps narrow this route: credential custody, where tool credentials live only in the gateway, and egress lockdown, where the agent's network reaches only the gateway and the [egress witness](egress.md) (`deploy/gateway/lockdown`). Under lockdown, a direct call has to pass through the witness. The witness identifies the agent by the proxy credential it checked, lets the Cedar policy refuse or allow the destination, and receipts the connection either way. That receipt is an observed bypass: it records the destination, the times, and the byte counts, never the payload, because there is no TLS interception. The witness sees nothing when lockdown is off, since an agent can ignore `HTTPS_PROXY`, and it relays no protocol other than HTTP. `completeness` still catches a bypass after the fact, for Stripe. | deployment: custody and lockdown; detected and receipted by the egress witness, never its payload |
| Skip an in-process hook or SDK wrapper | Same: an SDK receipt is the agent's own report, and every field in it is `claimed`. | not covered; use the gateway for anything consequential |
| Write memory the fleet will trust | Writes not made through the gateway are `claimed` and quarantined until a gateway confirms them; reads leave them out unless asked for. | deployment |
| Exhaust the log so its own calls are withheld rather than recorded | A withheld call shows `allow` next to `withheld` and nothing happened upstream; there is no state in which an action occurs without a receipt when `precommit` names the tool. | evidence |

### By the operator

| attack | defence | kind |
| --- | --- | --- |
| Rewrite a receipt after the fact | The receipt's envelope is signed by the gateway key, which the operator holds, so the signature alone does not stop this. What stops it is the log: the leaf hash of the original envelope is in a tree whose head the log signed, and a rewritten receipt has a different hash with no inclusion proof. | evidence, with a remote log; deployment, with a local log the operator can rewrite |
| Drop a receipt | The log's tree only grows, and consistency proofs between any two heads show nothing was removed. A receipt the operator never logged never existed as evidence, which is the point of `precommit` for consequential calls: the authorization leaf goes in before the action. [Strict mode](usage.md#strict-mode) does that for every call, with a remote hash-only log and no outbox, and its receipts say so, so a verifier can require it; a modified gateway can still claim strict mode. | evidence for logged receipts; withheld calls for pre-committed tools, and for every call under strict mode |
| Forge a receipt for an action that never happened | Nothing in the log stops the operator logging a fabricated receipt; the log commits to existence, not truth. What limits it: the upstream's signature over the result when the upstream signs, provider attestations where the provider delivers them, and the principal's signature on the grant. A forged receipt for a signing upstream fails its `upstream` checks. | evidence, where the upstream signs; otherwise the operator's word |
| Act outside the gateway with the provider's own credentials | Nothing on the gateway's side sees it. `agent-custody completeness` lists the provider's objects with the auditor's own read-only key and reports each one that no verified receipt names; a forged receipt file fails verification and cannot cover for it. | evidence, for a provider that lists its objects (Stripe today) |
| Replace the policy and claim a different one decided | The receipt carries the sha256 of the policy text; a verifier with the policy file can check it, and a policy change is a different digest in every later receipt. | evidence |
| Produce a second, cleaner history | With a remote log, both histories would need heads signed by the log's key at the same size with different roots; the checkpoints host and the witness make that detectable. With a local log, a copy taken earlier by someone else is the only defence. | evidence with a witnessed remote log |
| Erase what an agent believed | `forget` erases the value and leaves a digest keyed by a forget key held outside the ledger, so the erasure is provable without the value. A forget with `none` leaves nothing and the custody pack says so. | evidence |

### By the principal

| attack | defence | kind |
| --- | --- | --- |
| Disown a grant | The grant is signed with the principal's key and embedded in every receipt issued under it; the verifier checks the signature against the principal's public key. | evidence |
| Claim a grant they never gave | Nobody else holds their key. A leaked principal key is the principal's problem and the reason grants carry expiry. | assumption |

### By the upstream

| attack | defence | kind |
| --- | --- | --- |
| Deny it served a result | When the upstream signs `{ receiptId, tool, contentDigest }` the receipt carries its signature. When it does not sign, the receipt carries the gateway's digest of what the gateway saw, which is the operator's word against the upstream's. | evidence, where the upstream signs |
| Serve a different result to the gateway than it records | Same signature. Providers that deliver attestations (Stripe, GitHub webhooks) are checked against the provider's secret. | evidence, where available |

### By the log operator

| attack | defence | kind |
| --- | --- | --- |
| Read receipt contents | The hosted log runs with `--hash-only` and refuses a full leaf at append, so no receipt reaches the log process even from a misconfigured gateway or a stolen token; the tenant's `hashOnly` setting keeps the receipt from ever leaving their machine. A log an operator runs for themselves may accept full leaves. | evidence: the server refuses; deployment on the tenant's side |
| Rewrite a tenant's tree | Every head is signed and published as a checkpoint on a second host; a rewrite means two signed heads at one size with different roots, or a later head that does not extend an earlier one. Anyone holding an earlier head detects it with `audit`; the monitor does it every ten minutes; the witness countersigns only heads that extend the last it signed; the anchor commits each checkpoint to Ethereum, and `log-check --anchor-url` fails a head that does not extend the anchored one. | evidence, given a witness or an earlier head held elsewhere |
| Show different histories to different verifiers | Same: checkpoints are public and the witness sees one history. Without a witness, two verifiers who compare heads detect it, and nobody else does. | evidence with a witness; otherwise detection needs comparison |
| Mint a token for a tenant and append noise | Appends are hashes with no content; the tenant's export and usage show leaves and live tokens they did not make, and the audit trail, which the tenant's export carries, records who minted what and from where. | deployment |
| Sign with a key not in the key document | Verifiers pin by keyid from the published document; a head signed by an unpublished key fails. Retired keys stay published so old heads keep verifying, and a rotation is announced with its date. | evidence |
| Disappear | The tenant's export carries every leaf hash, the signed head, the keys, and the checkpoints; `verify --log` and `audit --log` work against it with no server. | evidence |

### By the witness

| attack | defence | kind |
| --- | --- | --- |
| Countersign a rewritten history | It cannot without also holding the log's key; a countersignature is over the log's own signed head. A witness that countersigns two heads at one size has published its own dishonesty. | evidence |
| Refuse a true history | An alarm with no consistency failure behind it is a false alarm; the log's consistency proof settles it in public. Verifiers who require a witness signature see a gap, which is the correct outcome for a disputed period. | evidence |
| Collude with the log operator | Two independent operators are the assumption. A witness on the log operator's machine proves nothing, and the deployment guide says so. | assumption |

### By the anchor

| attack | defence | kind |
| --- | --- | --- |
| Publish a record for a checkpoint it never anchored | The record is checked against the chain: the transaction must come from the pinned address to itself, succeed, and carry exactly the root the record's inclusion proof leads to, from a checkpoint the log's keys signed. | evidence |
| Anchor a rewritten history | The anchor proves each checkpoint extends the last one it anchored, and refuses with an alarm otherwise. An anchor that skipped the proof would still leave two anchored roots that cannot both extend the earlier one, in public. | evidence |
| Serve an older, genuine record as the current one | Every anchor transaction covers every watched log, and the verifier requires the record's transaction to be the newest from the address, by the address's transaction count on the chain. | evidence |
| Serve another tenant's record for this log | Tenant logs share the log's keys and the anchor's address, so the verifier pins each log's id; the anchored checkpoint and the current head must both name it. | evidence, given the pinned id |
| Stop anchoring | A head ahead of its newest anchor fails once that anchor's block, timed by the chain, is older than `--max-anchor-lag`. Between anchors, a rewrite is caught only once a later anchor or another holder of a head disagrees. | detection |
| Count an anchor a reorg removed | The anchor holds a transaction until its block is finalized, writes its records again if a reorg moves it, and sends the same root again if a reorg drops it. A verifier reports whether the record's block is finalized. | evidence once finalized |
| Leak its key | Someone else can spend the funds and post transactions from the address. A root that no checkpoint leads to proves nothing, so a leaked key cannot make a false record check out. | evidence |
| Anchor on a chain a few parties control | The installation chooses the chain, and the record names it. On an L2 a sequencer can delay or refuse an anchor, which shows as an anchor that does not keep up. A finalized block is as hard to rewrite as that chain makes it, which differs by chain (`docs/anchoring.md` lists what each rests on). | assumption: the chain's own guarantees |
| Lie through a JSON-RPC endpoint | Give `log-check` several endpoints from different providers: they must agree on the transaction and its block, and a block counts as finalized only when every endpoint says so. | assumption: not every endpoint lies the same way |

### On the network

| attack | defence | kind |
| --- | --- | --- |
| Replay an append | Appends are idempotent in effect: the same leaf hash appended twice is two leaves, both true. Nothing an attacker replays creates a receipt the gateway did not sign. | evidence |
| Alter an append in flight | TLS between gateway and log; the leaf hash is over a signed envelope, so an altered hash simply fails inclusion for the real receipt. | evidence |
| Drop the log's answer | The gateway retries, then errors or withholds; no receipt is handed out without an inclusion proof. Timeouts bound the wait. | evidence |
| Steal a tenant token | Tokens are bearer secrets; a stolen one appends noise to that tenant's log until revoked. Rate limits bound the damage per second; the tenant's usage shows it. | deployment |
| Escape a per-address limit by forging `X-Forwarded-For` | Behind the proxy the deployment runs, the limiter keys on the address the proxy appended, the rightmost entry, never on one the client supplied. | deployment |

### On the portal accounts

The portal is not part of the evidence: it publishes policy names and mints log tokens. A stolen account can mint a token, so the portal limits who may.

| attack | defence | kind |
| --- | --- | --- |
| Guess or steal a member's password | Optional TOTP MFA on the account. A code works once, wrong codes are throttled per address and per account, and the half-signed-in cookie is never a session. A GitHub or Google sign-in goes through the same code step. | deployment |
| A member acts beyond their job | Four roles: `readonly` reads, `reviewer` also publishes policy versions, `admin` also manages keys and members below owner, `owner` also manages billing and owners. A new write route needs `admin` unless it is listed. The last owner cannot be removed or demoted. | deployment |
| Claim an invited address to join a tenant | An invite is accepted only by an account with a verified address, and an account belongs to one tenant. | deployment |
| Sign in through an IdP the tenant does not own | The operator sets single sign-on, never the tenant. An IdP is trusted only for the email domains of its tenant, and a domain belongs to one tenant. The portal checks the OIDC `id_token` signature against the IdP's key set, or the signed SAML assertion through a maintained library, and ties the sign-in to the request that started it. | deployment |
| Lock a member out of their SSO tenant by registering their address first | The IdP proves the address, so it wins over an account that never verified it. The sign-in deletes that account with its password, sessions, memberships, and linked providers. A tenant that the account created stays, for the operator to deal with. Registering with a tenant, or linking a provider, does not change this. The one limit: an account in another tenant that has other members is refused, so that tenant keeps its members. | deployment |
| Keep access after leaving the company | With enforcement on, members sign in only through the IdP, so removal at the IdP ends access at the next sign-in. Sessions that began earlier end when enforcement is turned on. A member removed in the portal loses access at once, also in an SSO tenant: the IdP sign-in joins them again only after an admin invites the address again, also when they never verified their address. An API key that the member minted stays valid until an admin revokes it. | deployment |

## What is not defended

Stated plainly, because a security review that finds these itself will not believe the rest.

- **Actions outside the gateway.** A credential the agent holds directly is used directly. The gateway is a choke point only for what goes through it.
- **Truth of SDK receipts.** An in-process receipt is the process's own report. It is history, not evidence against that process.
- **Truth of what the upstream did** when the upstream does not sign. The receipt proves what the gateway sent and what it got back, on the gateway's word.
- **The operator's key custody.** A stolen gateway key signs receipts the verifier cannot tell from real ones; the log still bounds when they were created.
- **Availability.** A log that is down withholds pre-committed calls. That is the designed behaviour and it is a denial of service on the agent. Run the log with the runbook's monitoring, and expect a tenant to ask for the SLA.
- **Post-quantum adversaries.** Issue #11.
- **A dishonest log operator with a dishonest witness.** Two colluding parties can present a consistent false history. The defence is choosing them independently.

## How the hosted log is run against this model

The deployment in [deploy/](../../deploy/README.md) and its [runbook](../../deploy/RUNBOOK.md): the signer alone holds the key and is reachable only inside the compose network; the log process facing the internet holds no key; tenant tokens are hashed at rest and shown once; every admin action requires the admin token and is throttled; checkpoints are published on a second host; the monitor runs from machines that are not ours every ten minutes; backups are nightly, with an off-machine mirror the runbook installs once a destination is configured; the key rotates yearly and on suspicion, with retired keys published; the witness runs on another operator's machine, or the site says it does not yet.
