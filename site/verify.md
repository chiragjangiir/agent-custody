# Verify a receipt

Paste a receipt bundle and the public keys it should verify against. The report is the one the CLI prints: every check, then every field with its provenance, so you know what was proven and what was merely claimed. Nothing leaves your browser.

<ClientOnly><Verifier /></ClientOnly>

## What to paste

- **The bundle** is the file the gateway or SDK wrote to `receipts/<id>.json`: the signed statement, the signed tree head, and the inclusion proof.
- **Issuer keys** are the gateway's `.pub` file for gateway receipts, the door's for door receipts, or the application's `.pub` for SDK receipts. Paste more than one to accept rotated keys; signatures match by keyid.
- **Principal keys** are needed for gateway receipts, which carry a delegation grant signed by the principal, and for door receipts of an arrival that presented one.
- **Log keys** are needed only when the receipt was logged to a remote log, whose key signs the tree head.
- **A copy of the log** is optional. With it, the verifier recomputes the root at the tree head's size and compares.

The same checks from the shell: `npx @agent-custody/receipts verify receipts/<id>.json --issuer-key keys/app.pub --log log.jsonl`. [Verifying a receipt](/receipts/verification) explains each check and what a verified receipt does and does not prove.
