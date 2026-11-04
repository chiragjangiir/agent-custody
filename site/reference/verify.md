# Verify, audit, export

A receipt is verified with public keys alone: no server, no account, no trust in whoever handed it over. The [verification guide](https://agent-custody.dev/receipts/verification) explains what each check proves; this page is the interface.

## `verify`

```bash
agent-custody verify receipts/<id>.json --issuer-key keys/gateway.pub --principal-key keys/principal.pub [--approval-key approver.pub] [--log-key log.pub | --log-url https://log.example.com/] [--log-id acme] [--require-strict] [--upstream-key upstream.pub] [--stripe-secret-env NAME] [--github-secret-env NAME] [--log log.jsonl] [--disclose disclosure.json] [--capture-key-env NAME] [--json] [--markdown]
```

| option | meaning |
| --- | --- |
| `--issuer-key` (repeatable) | keys trusted to issue receipts: gateway keys, SDK application keys. `--gateway-key` is an alias |
| `--principal-key` (repeatable) | keys whose grants are accepted; may be omitted for SDK receipts |
| `--approval-key` (repeatable) | human keys trusted to sign exact-action approvals; required to validate a forwarded call carrying approval evidence; a refusal needs none. Never falls back to issuer or principal keys |
| `--log-key` / `--log-url` | the key of a log run by someone else, given as a file or fetched from the log's key document and pinned by keyid |
| `--log-id` | every tree head must name this log |
| `--require-strict` | the receipt must come from a gateway in strict mode (`issuer.strict: true`), and a call it forwarded must carry the authorization committed before it: the checks `strict mode in force` and `strict: call precommitted before forwarding` |
| `--upstream-key` | an upstream that signs its results; the execution then verifies as attested |
| `--stripe-secret-env`, `--github-secret-env` | shared secrets for provider deliveries carried in the receipt |
| `--log` | a copy of the log file; the root is recomputed at the receipt's tree size and compared |
| `--disclose` | a disclosure file: `{ "receiptId", … }` with `{ "$custody": "disclosed", "salt", "value" }` at the paths a capture rule withheld (`request.args.$rest`, `execution.result.$rest`, `execution.error`, `execution.upstream.rawBody`, `execution.upstream.signature`, `execution.upstream.bind`, `execution.upstream.envelope`, `policy.errors`, `facts.<name>.value.$rest`, `facts.<name>.args.<field>`, `facts.<name>.resultDigest`, `consumed.factIds`, `model.id`, `session.id`), any part of them, as `reveal` writes it or as the party that holds the values and the salts hands it over; each value is checked against its commitment under its salt and the digests are recomputed; a value without its salt, or a file for another receipt, is refused |
| `--capture-key-env` | the environment variable holding the customer's capture key; encrypted fields are decrypted, checked against their commitments, and the digests recomputed; a key that is not theirs fails the checks, naming the key id |
| `--json` | machine-readable output |
| `--markdown` | the arguments are directories of bundles (or bundle files), and the output is one Markdown table instead of a report; see [verify --markdown](#verify-markdown). It does not combine with `--json` or `--disclose` |

Exit 0 when every check passes, 1 otherwise. The text report is one line per check, `PASS`/`FAIL`, the name, and a detail, ending in `RESULT: VERIFIED` or `RESULT: NOT VERIFIED`. The JSON:

```json
{ "ok": true, "checks": [{ "name": "receipt signature (issuer key)", "ok": true, "detail": "keyid 9d442884f3d4" }, { "name": "delegation signature (principal key)", "ok": true, "detail": "signed by 19b2d2a2a213" }, …], "statement": { "…": "the decoded statement" } }
```

In code: `verifyBundle(bundle, { issuerKeys, principalKeys, approvalKeys?, logKeys?, upstreamKeys?, providerSecrets?, logFile?, logId?, requireStrict?, disclosed?, captureKey? }): { ok, checks, statement }` and `formatReport(result): string`. Keys are `PublicKeyRef`s from `loadPublicKey(path)` or `publicKeyFromPem(pem)`; `fetchLogKeys(url)` returns `{ doc, keys }` from a key document.

An approval record makes its checks mandatory for a forwarded call, even when `approvalKeys` is empty. A refusal receipt, such as a Cedar denial after a valid approval, runs only `approval consistent with execution` and verifies without approval keys. The browser verifier takes a separate human approval key input and cannot restore hidden values; use the Node verifier with `--disclose` or `--capture-key-env` for those. Under a private capture rule the receipt withholds the signed envelope, which contains action fields plus an unsalted argument digest, so the approval checks pass as committed until it is restored. See [human approvals](/receipts/approvals). Offline verification cannot prove that the approval was never used elsewhere; single use relies on the gateway's persistent shared consumption store.

### The checks

| check | proves |
| --- | --- |
| receipt signature (issuer key) | the bundle was signed by a trusted issuer key; nothing else is decided if this fails |
| receipt payload type | it is an in-toto statement with the receipt predicate type |
| structural parts in clear | the capture note, if any, is well formed and names no structural part (ids, the tool, the grant, the status, the decision, the digests, a fact's tool, a provider's name), and those parts are present and of the right type: an attested principal's key id, the status, the decision and the policy digest, an authorization's tree head and proof, and an approval record; nothing else is decided if this fails |
| issuer kind is known, issuer keyid matches signer | the receipt says who issued it and the signature agrees |
| strict mode in force, strict: call precommitted before forwarding | only with `--require-strict`: a gateway receipt that says `issuer.strict: true`, and, for a call that was executed, failed, or errored, an embedded authorization; a reconciliation receipt is a provider read and needs none |
| gateway receipt carries a delegation, carries a policy decision | gateway receipts embed both |
| delegation signature (principal key) | the grant was signed by a trusted principal key |
| delegation chain to the principal | only for chained grants: every link signed by the key its parent names, no scope escalation, nested windows, one principal |
| delegation binds principal and agent, valid at receipt time | the grant is for this principal and agent and the receipt's time is inside its window |
| executed tool within delegated scope | if the tool ran, the grant covered it |
| principal is claimed, not attested | SDK receipts: the principal is a config string and labelled so |
| disclosure names this receipt | only with `--disclose`: the file's `receiptId` is this receipt's |
| approval signatures (human keys) | a forwarded call carrying an approval record has the required number of distinct signatures from separately trusted `approvalKeys`. A withheld envelope passes as committed until it is disclosed or decrypted, unless nothing under `request.args` is withheld: then it fails |
| approval payload binding | that approval names this principal, agent, tool, complete arguments, and mapped amount/currency/beneficiary. If any argument remains withheld, this passes as committed until the arguments are disclosed or decrypted, as `request args digest` does |
| approval valid at forward time | the recorded check and consumption occurred inside the approval validity window |
| approval consistent with execution | forwarded calls carrying approval evidence have an approved, consumed record with matching signer observations; denied or withheld calls can verify as authentic refusals despite an invalid approval |
| request args digest | the arguments match their digest (salted from the field salts when any argument is withheld) and the statement's subject: recomputed when they are in clear, disclosed with `--disclose`, or decrypted with `--capture-key-env`; when values are withheld and neither is given it passes as committed, the detail saying "committed, not recomputed" and how many values are withheld; a path the note names that holds no commitment, or a disclosure that contradicts a commitment, fails it with the path named |
| execution result digest | executed and failed calls: the result matches `execution.resultDigest` (salted from the field salts when any part is withheld), under the same rules |
| fact `<name>` value, fact `<name>` args | a captured fact's commitments hold against the disclosed or decrypted value, or pass as committed when neither is given |
| withheld `<path>` | every other path the capture note names (`execution.error`, `execution.reason`, `policy.errors`, `execution.upstream.rawBody`, a part added later): it holds a commitment, which holds against the disclosed or decrypted value when one is given |
| upstream signature (upstream key), upstream signature (provider secret) | the upstream's signature over the result verifies when a key is given; a Stripe or GitHub delivery verifies when its secret is given |
| upstream signature (upstream key) | the upstream's signature over the result verifies when a key is given; a withheld envelope beside a result in clear fails it rather than skipping it, since the issuer keeps a plain attestation in clear beside a clear result; a result whose only withheld part is `_meta` counts as in clear here, since the signature covers the content and `isError`, never `_meta` |
| upstream signature not checked | only when the result, the delivery body, its signature or bind, or (with the result withheld) the upstream's signed envelope is withheld and a key or secret was given: the signature cannot be checked against a result the verifier cannot see, so this passes with a note in place of the signature check |
| policy decision consistent with execution | an enforced `deny` never sits beside `executed`; a `deny` with `enforced: false` (observe mode) may, and the detail says so |
| authorization … (five checks) | pre-committed calls: the authorization verifies, names this call, was allowed, is included in the log, and precedes the receipt leaf |
| authorization carries this approval | the precommit and receipt carry the same human approval envelope, threshold, and field mapping |
| authorization approval was valid | for a forwarded call, the precommit itself recorded an approved statement, distinct trusted signer observations, and a check inside the signed approval window |
| operation …; authorization names this operation | financial evidence is gateway-observed, identifies the original receipt, and carries the committed operation id, provider key, lookup digest, and budget; terminal outcomes need reconciliation unless the call was withheld; a retry of an existing operation is a `withheld` receipt that names the original, and a private receipt withholds the operation id and links by key |
| reconciliation original …; reconciliation original evidence verifies | the embedded original receipt or crash-surviving authorization verifies with its own signature, grant, commitments and inclusion proof; nested reconciliations are refused |
| reconciliation links the original operation; reconciliation lookup matches authorization; reconciliation lookup args match request | the original identity and budget are preserved, and the provider lookup and arguments match the mapping committed before forwarding |
| reconciliation logged after original; reconciliation records a terminal provider outcome; reconciliation provider status | log order holds and the provider record's terminal state and idempotency key match the financial outcome; a withheld result passes as committed until restored |
| tree head signature, tree head names the expected log | the head was signed by an issuer or log key, and by the log the verifier expected |
| log inclusion proof | the leaf is in the tree the head describes |
| log file root matches | with `--log`, the copy's root at that size equals the head's |

### `verify --markdown`

```bash
agent-custody verify --markdown .custody/receipts --issuer-key keys/agent.pub [--principal-key keys/principal.pub] [--log-url https://log.example.com/] [--log-id acme]
```

The command verifies each `<id>.json` in the directory, except `<id>.authorization.json` files, subdirectories, and symbolic links, with the same keys and options as `verify`. `verify --markdown` follows a symbolic link when the link is the file argument or the directory argument itself, but not a link inside the directory. The table shows only fixed error text or verified fields, so a followed link shows no text from its target. It prints this, and nothing else, on stdout:

```
<!-- agent-custody -->
## agent-custody receipts

**Not verified.** 1 of 2 receipts do not verify.

| Receipt | Tool | Status | Result |
| --- | --- | --- | --- |
| `981d2afd-63f2-49ed-854a-83fc1bf1c035` | - | - | `receipt signature (issuer key)` |
| `6e2de8f3-4e51-43e5-af8b-a2b283dd7709` | `stripe.refund` | executed | verified |
```

The failed rows come first, and the table has 200 rows at most. `Status` is the execution status in the signed receipt, or `-` when the signature does not verify. A file whose name is not its receipt id fails with `file name matches receipt id`. Text from a receipt is sanitized, so it cannot break the table or add Markdown or HTML. A file that is not valid JSON shows `not a JSON file`, and a file with the wrong shape shows `not a receipt bundle`; the table never quotes the file. Exit 1 when one receipt does not verify, when the directory holds no receipt, and when the path does not exist.

In code: `summarizeReceipts(receiptFiles(dir), options): { ok, rows, problem? }` and `formatSummaryMarkdown(summary): string`. The first line of the output is `SUMMARY_MARKER`.

The [GitHub Action](/receipts/github-action) in this repository runs this command and posts the table on a pull request. Its inputs are `path`, `issuer-key`, `principal-key`, `log-url`, `log-id`, `version`, `github-token`, and `comment-author`.

### `export`

```bash
agent-custody export --receipts ~/.config/agent-custody/receipts --out .custody/receipts --issuer-key keys/agent.pub [--issuer-key keys/other.pub] [--principal-key keys/principal.pub] [--approval-key keys/approver.pub] [--since 2026-11-02T09:00:00Z] [--allow-clear]
```

The command puts receipts into a directory that goes into a pull request. For each `<id>.json` at the top level of `--receipts`, it does these steps in order.

1. It verifies the receipt with the issuer keys. It refuses a receipt that does not verify, and a receipt whose file name is not its signed receipt id (`file name matches receipt id`). `--issuer-key` is required, because the privacy check trusts the signed capture note.
2. It skips a receipt issued before `--since`. `--since` takes an ISO time that starts with a date, for example `2026-11-02` or `2026-11-02T09:00:00Z`. A receipt issued at that time is kept.
3. It refuses a receipt when a side that holds data has no withheld path under it in the signed capture note. The sides are `args` (`request.args`), `result` (`execution.result`, the error message, and the denial reason), and `facts` (the value of each fact). A field that a rule lists in its `clear` list is allowed when the rule withholds the other fields of that side. `--allow-clear` turns the check off; the command then marks the receipt `(plain values: ...)` and prints a warning on standard error.
4. It copies the file byte for byte, and writes nothing for a refused or skipped receipt. The command creates `--out` when it copies a receipt.

The command never reads or copies `salts/`, `outbox/`, `*.authorization.json`, a subdirectory, a symbolic link, or a file that does not end in `.json`. A `.json` file that is not a receipt bundle is refused.

It prints one line for each receipt (`copied`, `refused` with the reason, or `skipped`), then `<n> copied, <n> refused, <n> skipped`. Exit 1 when it refuses a receipt, and when it copies none. The receipts that pass are copied even when the exit code is 1.

A side whose every field is on the `clear` list has no commitment, and the check cannot tell it from a side in mode `clear`. The command refuses it. [Receipts on a pull request](/receipts/github-action#how-receipts-get-into-the-pull-request) has the capture rules that keep receipts safe to commit, and their limits.

In code: `exportReceipts({ receiptsDir, outDir, verify, since?, allowClear? }): ReceiptExportResult` (`{ lines, copied, refused, skipped, problem? }`), `formatReceiptExport(result): string[]`, and `clearSides(predicate): string[]`.

## `reveal`

The values a receipt withheld under a capture rule in mode `encrypted`, as a disclosure file for `verify --disclose`. Needs the customer's capture key.

```bash
agent-custody reveal receipts/<id>.json --capture-key-env AGENT_CUSTODY_CAPTURE_KEY --issuer-key keys/gateway.pub [--out disclosure.json] [--include-salts]
```

| option | meaning |
| --- | --- |
| `--capture-key-env` | the environment variable holding the 32-byte key, 64 hex characters or 44 of base64; never the key itself |
| `--issuer-key` | the issuer's public key; the bundle must verify against it, or nothing is revealed (repeatable) |
| `--out` | where to write the disclosure; without it, stdout |
| `--include-salts` | also write the salt of every value the key cannot reveal, from the salts file beside the receipt, for the holder of the values to complete |

Output: `{ "receiptId", … }` with every encrypted value decrypted, checked against its commitment, and written at its own path with the salt the commitment was made with:

```json
{ "receiptId": "36c85dc9-…", "request": { "args": { "$rest": { "$custody": "disclosed", "salt": "9f3a…", "value": { "reason": "customer called from +44 20 7946 0000 about the card ending 4242" } } } }, "facts": { "customer": { "value": { "$rest": { "$custody": "disclosed", "salt": "…", "value": { "id": "cust_123", "email": "alex@example.com", "verified": true } } } } } }
```

A value withheld as a digest only carries nothing to reveal, and the command says which paths (`Not revealed, withheld without a value: execution.result.$rest, execution.upstream.envelope; only the party that holds them can disclose them; --include-salts writes their salts from receipts/salts/<id>.json for the holder to complete`). A key other than the one the values were encrypted under is reported as such (`Encrypted under key <keyid>…, not the one given`), and the command fails when that is all it found. With `--include-salts` and the issuer's salts file beside the receipt, it writes `{ "$custody": "disclosed", "salt" }` at each such path for the holder to add `value` to; a file carrying a salt without a value fails verification, so it cannot be handed over unfinished. A key other than the one a value was encrypted under reveals nothing of it, and the path is listed the same way; a decrypted value that does not match its commitment is an error. Exit 0; with `--out` the command prints where the file went and the `verify --disclose` option that reads it. In code: `restorePaths(predicate, note, disclosed?, key?)` and `reveal(commitment, key)`, on the [SDK](./sdk-typescript#private-evidence) page.

## `audit`

Proves that nothing between two receipts was rewritten: the newer receipt's tree head extends the older one's.

```bash
agent-custody audit --older receipts/<earlier>.json --newer receipts/<later>.json (--log log.jsonl | --log-url <url>) [--issuer-key <pub>] [--log-key <pub>] [--log-id <id>] [--witness-key <pub> | --witness-url <url>] [--json]
```

`--older` and `--newer` accept receipt bundles or checkpoint files. With `--log-url` the consistency proof is fetched from `GET /consistency` and the keys from the key document; with `--log` both come from the file. With a witness key or URL the newer head must also carry the witness's countersignature. JSON: `{ "ok", "checks", "older": <tree head>, "newer": <tree head> }`. In code: `auditExtends(olderEnvelope, newerEnvelope, proofHashes, keys, logId?, { witnessKeys? })`.

## In the browser

[agent-custody.dev/verify](https://agent-custody.dev/verify) runs the same checks in the page with the Web Crypto API; a receipt dropped on it never leaves the browser. `/verify?sample=<vector name>` loads that conformance vector with its keys and verifies it on arrival; `/verify?receipt=<id>` opens one of the site's own receipts from `/custody/<id>.json` with the agent's key and the log's key and verifies it at once; only that path on that origin is ever fetched. It passes every published [conformance vector](https://agent-custody.dev/receipt/vectors), as the package does.

## `log-check`

The outside monitor, on the [log API page](./log-api#monitoring).

## `log-export`

A tenant's own log, with their token, self-checked:

```bash
agent-custody log-export --log-url https://log.example.com/ --tenant acme --token-env AGENT_CUSTODY_LOG_TOKEN --out custody-export/ [--month 2026-09]… [--json]
```

| file | contents |
| --- | --- |
| `log.jsonl` | every leaf hash as `{"hash":"…"}` lines: a log copy `verify --log` and `audit --log` read with no server |
| `head.json` | the signed head and its decoded fields |
| `keys.json` | the log's key document at export time |
| `checkpoints.json` | every published checkpoint for the tenant |
| `usage.json` | appends per month, plan, quota, live keys |
| `audit.json` | every administrative action on the tenant |
| `policies.json` | the policy versions the tenant published, each with its name, text, and the digest receipts carry |
| `export.json` | the summary: `{ "exportedAt", "logUrl", "tenant", "logId", "treeSize", "rootHash", "keyid", "checkpoints", "audit", "usage", "problems": [] }` |

Before writing, the export checks that the head verifies against the published keys, that the leaves fetched hash to the head's root, and that every checkpoint verifies and matches the leaves at its size. Anything that does not add up is listed under `problems`, the command exits 1, and the report ends `RESULT: EXPORT DOES NOT ADD UP`. In code: `exportLog({ logUrl, tenant?, token, outDir, months?, fetch? }): Promise<ExportResult>` and `formatExport(result)`.
