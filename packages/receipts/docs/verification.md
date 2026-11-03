# Verifying a receipt

A verifier needs three things and no network access:

1. the receipt bundle, one JSON file
2. the issuer's public key: the gateway key, or the application key for SDK receipts
3. the principal's public key, for gateway receipts, which carry a signed delegation

A receipt carrying approval evidence for a forwarded call also needs the human approvers' public keys, trusted separately from issuer and principal keys.

A copy of the log file is optional. It lets the verifier confirm the receipt sits in a log whose root the verifier recomputed, not one the issuer merely asserted.

When the issuer logs to a remote log, the tree head is signed by the log's key rather than the issuer's. The verifier then needs that public key too, and the report says which key signed the tree head. That is the point of a remote log: a tree head signed by a party that is not the operator says the receipt was in a log the operator could not rewrite. A tree head signed by the issuer's own key says only that the issuer has not changed its story since.

## From the command line

```bash
node src/cli.ts verify receipts/<id>.json \
  --issuer-key keys/gateway.pub \
  --principal-key keys/principal.pub \
  --approval-key keys/approver.pub \
  --log-key keys/log.pub \
  --upstream-key keys/upstream.pub \
  --log log.jsonl
```

`--approval-key` is needed for forwarded calls carrying human approvals (not for a refusal), `--log-key` for a remote log, and `--upstream-key` when checking a signed upstream result. `--log` is optional. `--require-strict` refuses a receipt that a gateway in [strict mode](usage.md#strict-mode) did not issue, and a forwarded call without its precommitted authorization.

Exit code 0 when every check passes, 1 otherwise. Add `--json` for machine-readable output. `--issuer-key`, `--principal-key`, and `--approval-key` can be repeated to accept rotated keys; signatures are matched by keyid. `--gateway-key` is an alias for `--issuer-key`. `--principal-key` may be omitted for SDK receipts, which carry no delegation.

When a receipt was issued under a capture rule ([private evidence](usage.md#private-evidence)), some of its arguments, result, or facts are commitments rather than values. `--capture-key-env NAME` names the environment variable holding the customer's capture key: the verifier decrypts every encrypted field, checks it against its commitment, and recomputes the digests from the real values. `--disclose disclosure.json` does the same from a file holding the withheld values, `{ "receiptId", "args"?, "result"? }`, as `agent-custody reveal` writes it or as the party that holds them hands it over. Without either, the receipt digest checks pass as committed and the report says so. For a forwarded call carrying approval evidence, the separate approval payload binding check fails while any argument remains withheld.

A real report, produced by `node scripts/demo.ts`:

```
PASS  receipt signature (issuer key)  (keyid f2f53b689a84)
PASS  receipt payload type
PASS  issuer kind is known  (gateway)
PASS  issuer keyid matches signer
PASS  gateway receipt carries a delegation
PASS  gateway receipt carries a policy decision
PASS  delegation signature (principal key)  (signed by bfa1a505f55b)
PASS  delegation binds principal and agent
PASS  delegation valid at receipt time  (2026-09-04T13:06:20.074Z .. 2026-09-04T14:06:21.074Z)
PASS  executed tool within delegated scope  (stripe.refund)
PASS  request args digest
PASS  execution result digest
PASS  policy decision consistent with execution  (allow -> executed)
PASS  no policy errors on an allow
PASS  tree head signature
PASS  tree head matches inclusion proof size
PASS  log inclusion proof  (leaf 0 of 1, root 4efaea879930)
PASS  log file root matches tree head  (recomputed 4efaea879930)

RESULT: VERIFIED

ISSUER: gateway, enforced outside the agent's process; the agent could neither skip nor forge this receipt

field           provenance  value
principal       attested    user_456
agent           attested    support-agent
model           claimed     claude-fable-5-1
tool            observed    stripe.refund
args            claimed     {"amount":50000,"customer_id":"cust_123"}
fact.customer   observed    {"email":"alex@example.com","id":"cust_123","verified":true}
policy          observed    allow [policy1] policy ba4e4461ffc4
execution       observed    executed
```

A refused call's `execution` row carries the reason the receipt records, for example `denied: delegation grant has been revoked`, and so does a `withheld` one. Under a capture rule the reason is a commitment, and the row says `(reason withheld under the capture rule)` rather than printing it.

## What each check means

| check | what it establishes | what a failure usually means |
| --- | --- | --- |
| receipt signature (issuer key) | the bundle's envelope was signed by a key you trust as an issuer and has not changed since | edited receipt, or an issuer key you do not trust |
| receipt payload type | the payload is an in-toto Statement with this project's predicate type | wrong file, or a different envelope replayed as a receipt |
| issuer kind is known | the receipt says whether a gateway or an SDK produced it; the detail shows which, and the framework | a predicate this verifier does not understand |
| issuer keyid matches signer | the receipt's own claim of who signed it matches the actual signature | mixed-up or forged predicate |
| gateway receipt carries a delegation | gateway receipts always embed the signed grant they enforced | an SDK receipt relabelled as gateway |
| gateway receipt carries a policy decision | gateway receipts always record the Cedar decision | same |
| delegation signature (principal key) | the embedded grant was signed by a key you trust as a principal | a grant the principal never issued |
| delegation chain to the principal | only when the grant embeds a parent: every link is signed by the key its parent names, holds no scope its parent lacks, sits inside its parent's window, and names the same principal, up to three delegations deep | a sub-agent given more than its delegator had, a link signed by the wrong key, a chain that never reaches a trusted principal |
| delegation binds principal and agent | the grant names the same principal and agent the receipt names, and the principal keyid matches | a valid grant for someone else, spliced in |
| delegation valid at receipt time | the receipt's timestamp is inside the grant's window; a call the gateway refused after the grant ran out passes with a note, since only an executed call must sit inside the window | expired or not-yet-valid authority behind an executed call |
| executed tool within delegated scope | if the tool ran, the grant covered it. Denied calls pass this check by construction | a gateway that forwarded out of scope |
| principal is claimed, not attested | SDK receipts only: there is no delegation, so the principal is a config string and is labelled as such | an SDK receipt pretending to an attested principal |
| approval signatures (human keys) | for a forwarded call carrying an approval record, enough distinct human approval keys signed the embedded envelope; issuer and principal keys never substitute. Under a private rule the envelope is a commitment: the check passes as committed until it is disclosed or decrypted. It fails when the envelope is withheld beside arguments in clear | missing approval keys, untrusted signer, or insufficient threshold |
| approval payload binding | the signed approval names the same principal, agent, tool, complete arguments, and configured amount/currency/beneficiary | changed arguments or a spliced approval. Arguments that are still withheld pass as committed, as `request args digest` does; disclose them or provide the capture key to check the full binding |
| approval valid at forward time | the approval was valid at the recorded check and consumption times (forwarded calls only) | expiry or a future issuance time behind a forwarded call |
| approval consistent with execution | forwarded calls with approval evidence have an approved, consumed record with matching signer observations; denied or withheld calls verify as evidence of refusal without endorsing the rejected approval | an execution without the recorded approval consumption, or inconsistent observed signer ids |
| request args digest | the args in the predicate hash to the digest in the subject. Recomputed when the arguments are in clear, disclosed with `--disclose`, or decrypted with `--capture-key-env`; when fields are withheld and neither is given, it passes as committed, the detail saying "committed, not recomputed" and how many fields are withheld | edited arguments, or a disclosure that contradicts a commitment |
| execution result digest | executed and failed calls: the result in the predicate hashes to `execution.resultDigest`, under the same rules as the arguments; a provider delivery withheld with the result is restored first, since the digest covered it | an edited result, or a disclosure or key that does not match the commitment, or a capture note naming a field that is not a commitment |
| fact `<name>` value, fact `<name>` args | only for a captured fact: its commitments hold against the disclosed or decrypted value, or pass as committed when neither is given | a disclosure that lies about a fact the policy decided on |
| upstream signature not checked | only when the result is withheld and an upstream key or provider secret was given: the signature cannot be checked against a result the verifier cannot see, so the line passes with a note in place of the signature check; disclose the result or give the key to run it | nothing; it is a note |
| policy decision consistent with execution | allow went with executed or failed; an enforced deny went with denied; a deny carrying `enforced: false` (observe mode) went with anything but denied, and the detail says "observe mode, not enforced". Skipped when no policy was evaluated | an issuer that executed after a deny |
| no policy errors on an allow | an allow was not produced while Cedar reported errors | broken fail-closed behaviour |
| authorization signature (issuer key) | pre-commit receipts only: the embedded authorization statement was signed by the same issuer key as the receipt | an authorization from another gateway, or none the issuer signed |
| authorization names this call | the committed authorization names this receipt id, tool, argument digest, agent, and principal, and recorded an allow | an authorization spliced in from a different call |
| authorization carries this approval | when present, the human approval envelope, signature threshold, and field mapping match the final receipt | a different approval substituted after the precommit |
| authorization approval was valid | for a forwarded call, the precommit recorded an approved statement, distinct trusted signer observations, and a check inside the signed window. Under a private rule only the status, the times, and the signer count are checked until the envelope is restored | an invalid initial approval hidden by a valid final receipt |
| authorization tree head signature | the authorization's own tree head is signed by a trusted log or issuer key | a fabricated log position for the authorization |
| authorization log inclusion proof | the authorization statement is a leaf of that tree | an authorization that was never logged |
| authorization logged before execution | the authorization's leaf precedes the receipt's leaf, at a tree size no larger than the receipt's | evidence written after the side effect, dressed up as before |
| tree head signature | the tree head was signed by a trusted issuer key | forged log position |
| strict mode in force | with `--require-strict`: a gateway receipt whose issuer says `strict: true`. It is the gateway's own statement, signed with its key, so it binds the operator to a mode it can be held to; it does not prove the gateway's code | an ordinary receipt presented where strict ones are required |
| strict: call precommitted before forwarding | with `--require-strict`: a call that was executed, failed, or errored carries its authorization, which the `authorization …` checks then place in the log before the receipt. A reconciliation receipt is a provider read and needs none | a strict claim on a call that went out before any log entry |
| tree head names the expected log | with `--log-id`: the tree head carries that log id, so a head from another tenant's log on the same server cannot be presented as this one's | a receipt logged to a different log than claimed |
| tree head matches inclusion proof size | the proof and the tree head describe the same tree | mismatched bundle parts |
| log inclusion proof | this exact envelope is a leaf of the tree with that root | receipt never logged, or logged then changed |
| log file root matches tree head | recomputing the root from your copy of the log at that size gives the same value | your log copy and the issuer's history diverge: deletion, reordering, or edit |

Approval-bearing forwarded calls add four approval checks. A refused call runs only `approval consistent with execution`, so it verifies without approval keys, with a valid approval or with the invalid approval that caused its refusal. Gateway receipts otherwise run seventeen checks, eighteen with a log file, one more (`execution result digest`) when the call was executed or failed, and five more when the tool was committed before it ran (`precommit` in the gateway config). `--require-strict` adds two. SDK receipts run fewer, because there is no delegation to check, and the report says so on the `principal is claimed` line. A receipt issued to a sub-agent under a delegation chain runs one more, `delegation chain to the principal`.

Financial receipts add `operation …` checks and `authorization names this operation` for the durable id (absent under a private capture rule; the provider key then links the receipts), provider key, precommitted lookup, and budget. Reconciliation receipts embed their original receipt or authorization and run its checks under `reconciliation original …`, reject nested reconciliation evidence, preserve identity at `reconciliation links the original operation`, and check the configured mapping and provider record at `reconciliation lookup matches authorization`, `reconciliation lookup args match request`, and `reconciliation provider status`. The provider's terminal state must agree with the financial outcome and its record must echo the idempotency key. `reconciliation logged after original` checks ordering. These observations do not independently prove settlement without trusting the gateway and provider; private provider results verify as committed until disclosed or decrypted. See [financial operations](financial-operations.md).

## What a verified receipt lets you conclude

Read the `ISSUER` line first, then the provenance column. For the executed refund above, a gateway receipt, a verified result supports exactly this statement:

> The gateway holding key `f2f5…` observed that the agent `support-agent`, acting under a grant signed by the holder of principal key `bfa1…` for `user_456`, requested `stripe.refund` with these arguments; the gateway itself looked up the customer and got `verified: true`; policy with digest `ba4e…` allowed it; the upstream server returned a result with this digest; and the gateway committed all of that to position 0 of a log whose root is `4efa…`.

For an SDK receipt the statement is shorter: a process holding the application key reported this call, with these arguments and this result, and the record has not changed since. Nothing in it was checked outside that process. The report prints this under `ISSUER` so nobody has to remember it.

A gateway receipt does **not** support:

- that Stripe really executed the refund. The upstream result is `observed`, not signed by Stripe. That is the first roadmap item.
- that the side effect exists because the receipt does, unless the receipt carries an authorization. Without one, the call was forwarded first and logged second. With one, the `authorization` checks establish that the gateway had committed the call to the log before it went out, including the human approval when required, and a `withheld` execution establishes that it never went out.
- that the arguments were correct. They are `claimed`: they are what the agent asked for, which is what a receipt should record.
- that a receipt issued under a capture rule shows everything the call carried. The `capture` note says which fields are withheld; the verifier establishes that every value shown, disclosed, or decrypted is the one the signed digest was made over, and nothing about the ones it was not shown.
- that a human approval was not used by another gateway. The signature establishes the exact action and window; single use depends on the gateway's persistent consumption store shared across every process that accepts the approval.
- that a human approval is valid, for a reviewer who holds neither the capture key nor a disclosure: under a private rule the receipt withholds the approval envelope, because it carries the action fields and an unsalted digest of all arguments. The approval checks then pass as committed. See [approval privacy limits](approvals.md#privacy-limits).
- that the model named in `model` produced the call. No hosted provider signs model identity.
- that the gateway operator is honest. The operator holds the gateway key. Against a dishonest operator you need a log copy taken out of their control, or a signer they do not control. See the threat model table in the README.

## In the browser

[agent-custody.dev/verify](https://agent-custody.dev/verify) runs the same checks in the page over WebCrypto, nothing uploaded. It is a second implementation of this verifier, and it passes every published [conformance vector](https://agent-custody.dev/receipt/vectors).

## Programmatic verification

```ts
import { readFileSync } from "node:fs";
import { loadPublicKey } from "../src/crypto.ts";
import { verifyBundle, formatReport } from "../src/verify.ts";

const bundle = JSON.parse(readFileSync("receipts/<id>.json", "utf8"));
const result = verifyBundle(bundle, {
  issuerKeys: [loadPublicKey("keys/gateway.pub")],   // gateway keys and SDK application keys
  principalKeys: [loadPublicKey("keys/principal.pub")],
  approvalKeys: [loadPublicKey("keys/approver.pub")], // separately trusted human keys; repeat for a two-key rule
  logKeys: [loadPublicKey("keys/log.pub")],           // only for receipts logged to a remote log
  upstreamKeys: [loadPublicKey("keys/upstream.pub")], // only when the upstream signed its result
  logFile: "log.jsonl",           // optional
});

result.ok                          // every check passed
result.checks                      // [{ name, ok, detail? }]
result.statement?.predicate        // the decoded receipt, only when the signature verified
console.log(formatReport(result));
```

`verifyBundle` is pure and synchronous. It reads the log file only when `logFile` is given. `disclosed: { args?, result? }` hands it the withheld values of a receipt issued under a capture rule and `captureKey: Buffer` the customer's key (`captureKeyFrom(text)` parses the hex or base64 form); the digests are then recomputed instead of passing as committed.

## Verifying without this codebase

The formats are standard on purpose, so a verifier in another language needs no code from here:

- **Envelope:** [DSSE](https://github.com/secure-systems-lab/dsse). Signature is Ed25519 over `"DSSEv1 " + len(payloadType) + " " + payloadType + " " + len(payload) + " " + payload`.
- **Payload:** [in-toto Statement v1](https://github.com/in-toto/attestation), canonical JSON with sorted keys and no whitespace.
- **keyid:** sha256 of the SPKI DER encoding of the public key, hex.
- **Log:** RFC 6962 hashing (`0x00` prefix for leaves, `0x01` for nodes) and the RFC 9162 inclusion-proof algorithm. Leaves are the canonical JSON of the envelope. The log file is one JSON string per line.

## Auditing a log copy

Take copies of `log.jsonl` on a schedule and keep them where the operator cannot write. A remote log serves `GET /root?size=N` so an auditor can compare a tree head with the log's own root without a copy; example 13 does this. Then for any receipt:

```bash
node src/cli.ts verify receipts/<id>.json --issuer-key ... --principal-key ... --log /audit/copies/log-2026-09-04.jsonl
```

The last check recomputes the root at the receipt's tree size from your copy. If the operator later deletes, reorders, or edits a line before that position, the recomputed root changes and the check fails.

Today a copy must be at least as long as the receipt's tree size. Consistency proofs between two tree heads, which would let you check that a newer log extends an older copy without holding the whole file, are on the roadmap.

## Proving history was not rewritten

An inclusion proof says a receipt was in the log at one moment. It does not say the log still contains, unchanged, everything it contained earlier. That is what a consistency proof is for: given two tree heads, it proves the larger tree extends the smaller one, so nothing before the older head was rewritten. Keep the tree head from any receipt; it is the older head in every later audit.

```bash
node src/cli.ts audit --older receipts/<earlier>.json --newer receipts/<later>.json --log log.jsonl --issuer-key keys/gateway.pub
node src/cli.ts audit --older receipts/<earlier>.json --newer receipts/<later>.json --log-url https://log.example.com/t/acme/ --log-id acme

A witness that countersigns the log's checkpoints from a machine the operator does not control is required with `--witness-url https://witness.example.org/` or `--witness-key witness.pub`: the check `newer tree head countersigned by a witness` then has to pass, and `--newer` may be a checkpoint file from the witness's host. `--log-url` also fetches the log's published keys from `/.well-known/agent-custody-log.json` and pins them by keyid, so no key file changes hands; `--log-key` still works for a key you were handed. The same flag on `verify` does the same for a receipt.
```

Both tree heads must be signed by a trusted key. With `--log` the proof is computed from a copy of the log; with `--log-url` it is fetched from the log's `GET /consistency?old=M&new=N`. Exit code 0 means the newer log extends the older one. A failure means either history was rewritten between the two heads or the proof belongs to other tree heads; example 14 shows a rewritten log failing this way while every individual receipt still verifies.

Programmatically, `auditExtends(older.treeHead, newer.treeHead, proof, keys)` returns the same checks. The proof algorithm is RFC 9162 section 2.1.4, so any log implementing it can answer, and any verifier implementing it can check.

The remote log also serves `GET /head`, its current tree head signed with the log's key, so an auditor can record heads on a schedule and later audit any two of them without holding a receipt for each.

## Conformance vectors

`vectors/` in the package holds fixed receipts, keys, logs, proofs, and the verdicts this verifier produces for them, generated by `bun run vectors` and checked by the test suite on every run. A verifier written elsewhere proves it agrees by reproducing every verdict. They are published at [agent-custody.dev/receipt/vectors](https://agent-custody.dev/receipt/vectors).

## Attested execution

On a gateway receipt the execution is `observed`: the gateway saw what the upstream returned. An upstream that holds a key can do better and sign its result for the receipt being issued; the gateway embeds the signature, and a verifier given the upstream's public key checks it and reports the execution as `attested` by that key. The check binds the signature to the receipt id, the tool, and the digest of the result content, so a signature cannot be moved between receipts.

For upstream authors, `signResult(result, key, receiptId, tool)` from `@agent-custody/receipts` does the signing; the receipt id arrives in the call's `_meta["agent-custody/receipt"]`. The memory server in `@agent-custody/state` signs when started with `--key`, and the demo's fake upstream does too.

### Provider-native deliveries

Real providers do not sign per receipt. Stripe signs webhooks and GitHub signs deliveries with an HMAC over the raw body under a shared secret, unbound to any receipt. An MCP server wrapping such a provider can attach the delivery that corresponds to the call, with `attachProviderAttestation(result, { provider: "stripe-webhook", rawBody, signature, bind: "data.object.id" })`, and the gateway embeds it as `execution.upstream`. A verifier given the secret recomputes the HMAC, checks Stripe's timestamp against the receipt's within five minutes, and checks that the value at `bind` in the delivery appears in the receipt's result, which is what ties a delivery to this call.

```bash
STRIPE_WEBHOOK_SECRET=whsec_... node src/cli.ts verify receipts/<id>.json --issuer-key keys/gateway.pub --principal-key keys/principal.pub --stripe-secret-env STRIPE_WEBHOOK_SECRET
```

The report then says `attested (shared secret)`, deliberately distinct from `attested`: anyone holding the secret could forge a delivery, so this is the provider's word as far as the secret is trusted, not a signature only the provider could make. Without the secret the delivery is carried and not checked, and the report says so. The demo's fake Stripe attaches webhooks when started with `--webhook-secret`; the conformance vectors include a receipt verified with and without the secret.

## Retention on the log

Receipts hold values: request arguments, results, facts. The log is append-only and hashed, so nothing can simply be deleted from it. `prune` is how retention reaches it without breaking a proof:

```bash
node src/cli.ts prune --log log.jsonl --before 2026-06-01T00:00:00Z --receipts receipts
```

Every leaf whose receipt is older than the cutoff is replaced in the file by its leaf hash, and the receipt's bundle file is deleted. The Merkle tree is built from leaf hashes, so every root, every inclusion proof, and every consistency proof for the remaining leaves is unchanged, and `--log` verification of later receipts still passes. Someone who kept a pruned receipt's bundle can still prove it was in the log; nobody holding only the log can recover what it said. `prune` holds the log lock (`<log>.lock`) while it rewrites the file, so a process that appends at the same time waits, and its leaf is kept. `prune` waits up to 20 seconds for the lock. Run it on the same schedule as memory retention.

