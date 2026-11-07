# The log API

The transparency log is an RFC 6962 Merkle tree of receipt leaf hashes whose heads are signed. It exists in three forms with one contract: a local file (`logFile`), a server you run (`agent-custody log`), and the hosted one. The gateway and SDK append to it; verifiers read from it.

## Files

A log file is one JSON value per line: a leaf string, `{"hash":"<64 hex>"}` for a leaf appended by hash, or `{"pruned":"<64 hex>"}` for a leaf whose content was removed by retention. The tree is rebuilt from the file on open. `MerkleLog` in `@agent-custody/receipts`: `append(leaf)`, `appendHash(hex)`, `root(size?)`, `inclusionProof(leafIndex, treeSize?)`, `consistencyProof(oldSize, newSize?)`, `leafHashes(from, to)`; `leafHash(data)`, `rootOf(hashes, size?)`, `verifyInclusion(leaf, proof, root)`, `verifyConsistency(oldSize, oldRoot, newSize, newRoot, proof)` are the primitives. They refuse, before any hashing, a proof hash or a root that is not a string of 64 lowercase hex digits, a leaf that is not 32 bytes, and an index or a size that is not a non-negative integer; a head of size 0 passes only with the empty tree's root, `sha256("")`, and an empty proof.

## The server

```bash
agent-custody log --db-env DATABASE_URL --signer-url http://signer:8790/ --signer-token-env SIGNER_TOKEN --log-id log.example.com --checkpoint-dir /checkpoints --admin-token-env ADMIN_TOKEN --public-url https://log.example.com/ --checkpoints-url https://checkpoints.example.com/ --trust-proxy --port 8787
```

Or `--file log.jsonl --key log.key [--token-env NAME] [--tenants tenants.json]` for one file log and no database. The root paths serve the tenant `default`; every other tenant is under `/t/<tenant>/`. Bearer tokens are `Authorization: Bearer <token>`.

### Public routes

| route | response |
| --- | --- |
| `GET /health` | `{ "ok": true, "keyid": "6ddd…", "checkpoints": true }`; `503` when the signer or the default log does not answer |
| `GET /.well-known/agent-custody-log.json` | the key document, below |
| `GET /head`, `GET /t/<tenant>/head` | `{ "treeHead": <signed envelope> }`, the current head, signed on request |
| `GET /root?size=N` | `{ "treeSize": N, "rootHash": "<hex>" }`; `400` if `size` is not in `0..current` |
| `GET /consistency?old=M&new=N` | `{ "oldSize": M, "newSize": N, "hashes": ["<hex>", …] }`, the RFC 6962 consistency proof; `new` defaults to the current size |
| `GET /checkpoints?since=S` | `{ "checkpoints": [{ "treeSize", "rootHash", "signedAt", "treeHead": <signed envelope> }, …] }` with `treeSize > S` |

The key document:

```json
{ "log": "log.example.com", "keys": [
  { "keyid": "6ddde646…", "alg": "ed25519", "publicKeyPem": "-----BEGIN PUBLIC KEY-----…", "validFrom": "2026-09-08T00:00:00.000Z" },
  { "keyid": "a1b2…", "alg": "ed25519", "publicKeyPem": "…", "validFrom": "1970-01-01T00:00:00.000Z", "validTo": "2026-09-08T00:00:00.000Z" }
] }
```

Current key first, retired keys after it, so heads they signed keep verifying. A tree head payload is `{ "treeSize": 5, "rootHash": "<hex>", "timestamp": "…", "log": "log.example.com" }` in an envelope of type `application/vnd.agent-custody.treehead+json`.

### Appending

`POST /append` or `POST /t/<tenant>/append`, token required when the log has one.

**Request** `{ "leaf": "<the canonical receipt envelope>" }` or, with `hashOnly`, `{ "leafHash": "<64 hex>" }`. Body at most 64 KB.

**Response** `200`

```json
{ "inclusion": { "leafIndex": 6, "treeSize": 7, "hashes": ["<hex>", "<hex>"] }, "treeHead": { "payloadType": "application/vnd.agent-custody.treehead+json", "payload": "…", "signatures": [{ "keyid": "6ddd…", "sig": "…" }] } }
```

| status | meaning |
| --- | --- |
| `401 { "error": "unauthorized" }` | no token, or not this tenant's |
| `413` | body over the cap |
| `429 { "error": "too many appends; retry shortly" }` with `Retry-After: 1` | rate limit: 50 a second, burst 100, per token |
| `429 { "error": "monthly quota reached: …" }` with `Retry-After: <seconds to month end>` | the tenant's [plan allowance](./hosted#plans) is used |
| `503 { "error": "log unavailable: …" }` | the store or the signer did not answer |

The client retries 429 and 5xx three times with backoff and then fails the call; nothing is issued for a leaf the log did not take.

### A tenant's own routes

Token required. What the [export](./verify#log-export) fetches.

| route | response |
| --- | --- |
| `GET /t/<tenant>/leaves?since=N&limit=M` | `{ "since": N, "size": <tree size>, "leaves": ["<hex>", …] }`, at most 10,000 per page |
| `GET /t/<tenant>/usage?month=YYYY-MM` | `{ "month", "appends", "totalLeaves", "liveTokens", "plan", "quota" }` |
| `GET /t/<tenant>/policies` | `{ "policies": [{ "id", "name", "digest", "bytes", "createdAt", "createdBy", "text" }] }`, the versions the tenant published through the portal, with the tenant token |
| `GET /t/<tenant>/audit?limit=N` | `{ "entries": [{ "id", "at", "actor", "action", "tenantId", "detail" }, …] }`, newest first |

### Checkpoints

Every `--checkpoint-every` seconds (default 300) the server signs the head of each log that has grown, and every `--checkpoint-heartbeat` seconds (default 21600) re-signs a quiet log's head so a checkpoint is never stale. Checkpoints are written as `<dir>/<tenant>/<treeSize>.json` and `latest.json`, each `{ "tenant", "logId", "treeSize", "rootHash", "signedAt", "envelope": <signed tree head> }`, served from a second host so the record of what the log signed does not depend on the log's API. A [witness](#the-witness) countersigns them.

### The signer

`agent-custody signer --key log.key --port 8790 --token-env SIGNER_TOKEN [--retired-key old.pub]…` is the one process that holds the key. `POST /sign` `{ "payloadType", "payload" }` with the shared token → the signed envelope; `GET /keys` → the key document. The log runs with `--signer-url` and never holds the key.

### The admin API

Behind `--admin-token-env`, token as `Authorization: Bearer` or as the password of HTTP Basic. `GET /admin` is the page. `GET /admin/tenants`, `POST /admin/tenants { id, logId? }`, `POST /admin/tenants/<id>/disable`, `POST /admin/tenants/<id>/plan { plan }`, `GET /admin/tenants/<id>/tokens`, `POST /admin/tenants/<id>/tokens { label }` → `{ token, tokenHash, welcome }`, `POST /admin/tenants/<id>/tokens/<hash prefix>/revoke` → `{ revoked }`, `GET /admin/usage?month=` and `/admin/usage.csv`, `GET /admin/registrations?month=` → `{ month, rows: [{ tenant, logId, plan, email, name, company, role, phone, telegram, registeredAt, billing, appends, quota, totalLeaves, liveTokens, disabled }], totals: { tenants, registered, appends, totalLeaves } }` (the contact fields, registeredAt, and billing are null for a tenant onboarded by script rather than through the portal; the month defaults to the current one) and `/admin/registrations.csv`, `GET /admin/audit?tenant=&limit=`, `GET /admin/info`. Wrong tokens from one address are throttled.

## The witness

`agent-custody witness --key witness.key --log-url <url> --checkpoints-url <url> --out <dir> [--tenant <name>]… [--every 300] [--once]` runs on a machine the log's operator does not control. Each cycle, per watched log: fetch `latest.json`, verify it against the log's published keys, prove with `GET /consistency` that it extends the last head this witness signed, countersign it into `<dir>/<tenant>/<treeSize>.json` and `latest.json` (the same checkpoint, one more signature). A checkpoint that does not extend, a second history at the same size, or a signature by an unpublished key gets `<dir>/<tenant>/ALARM.json` and `ALARM-<time>.json` instead. The witness's key document is `<dir>/.well-known/agent-custody-witness.json`; verifiers give `audit --witness-url` and the newer head must then carry the witness's signature.

## The anchor

`agent-custody anchor --log-url <url> --checkpoints-url <url> --out <dir> --rpc-url-env NAME --key-env NAME [--tenant <name>]… [--chain ethereum] [--max-fee-gwei <gwei>] [--every 21600] [--once]` commits the log's checkpoints to a chain: Ethereum mainnet by default, or `base`, `arbitrum`, `optimism`, `polygon`, or any EVM chain id, with a default fee cap per named chain (required for a bare id). Each run, per watched log, it fetches `latest.json`, verifies it against the log's published keys, and proves with `GET /consistency` that it extends the last checkpoint it anchored. A checkpoint that does not extend, a second history at the same size, or a signature by an unpublished key gets `<dir>/<tenant>/ALARM.json` and `ALARM-<time>.json`.

When any log moved, every watched log's checkpoint (the new one, or the last one anchored) becomes a leaf of one Merkle tree, and one zero-value transaction from the anchor's address to itself carries its root as calldata (`0x` + hex(`agent-custody/anchor/1:`) + root). Once it is in a block, each log gets `<dir>/<tenant>/<treeSize>.json` and `latest.json`, written again if a reorg moves the transaction; it stays pending, and nothing new is sent, until its block is finalized, and a transaction a reorg drops is sent again after 30 minutes. A record is `{ tenant, logId, treeSize, rootHash, checkpoint, anchor: { chainId, address, txHash, blockNumber, root, proof, sentAt } }`.

`<dir>/.well-known/agent-custody-anchor.json` names the chain and address for discovery; verifiers pin the address from elsewhere, and the address must send nothing but anchors.

The key and the endpoint come from the environment. The command needs the optional package `viem`. In code: `new Anchor(options)`, `evmChain(options)`, `resolveAnchorChain(name)`, and `checkAnchorRecord(record, options)`; [anchoring](https://github.com/svayatta/agent-custody/blob/main/packages/receipts/docs/anchoring.md) is the guide.

## Monitoring

`agent-custody log-check --log-url <url> [--checkpoints-url <url>] [--witness-url <url>] [--tenant <name>]… [--max-lag 900] [--anchor-url <url> --anchor-address <0x…> --anchor-rpc-env NAME… --anchor-log-id <tenant>=<id>…] [--json]` is the outside probe: key document served; per tenant, head verifies against the published keys, latest checkpoint verifies, checkpoint keeps up with the head (within `--max-lag` when the tree grew, within a day when it did not), head extends the checkpoint; with a witness, witness countersigned, keeps up, and raised no alarm; with `--anchor-url <url> --anchor-address <0x…> --anchor-rpc-env NAME… --anchor-log-id <tenant>=<id>… [--anchor-chain ethereum] [--max-anchor-lag 46800]`, anchor verifies on chain (against every endpoint, which must agree), anchor and head name the pinned log, anchor is the newest from its address (by the address's transaction count), head extends the anchored checkpoint, and anchor keeps up with the log (a head ahead of an anchor whose block is older than the lag fails). `--json` prints `{ "ok": boolean, "checks": [{ "tenant", "name", "ok", "detail"? }] }`; exit 1 on any failure. `checkLog(options): Promise<LogCheckResult>` in code.
