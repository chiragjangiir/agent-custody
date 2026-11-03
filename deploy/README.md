# Deploying the log

This directory runs the log server as a container: on one VM with docker compose, or on Kubernetes with the manifests in `k8s/`. Both use the same image and the same environment variables, so a deployment moves between them by changing where it runs, not what it is.

What it deploys is the log service from `@agent-custody/receipts` as it runs at log.agent-custody.dev: tenants with their own logs and bearer tokens (hashed at rest) in Postgres, hash-only leaves, a separate signer process that alone holds the key, signed checkpoints published on a second host, the key document at `/.well-known/agent-custody-log.json`, the operator's page at `/admin`, and per-tenant usage for invoicing. The witness is a separate stack for a machine the operator does not control. The single-file server is still there behind `--profile file` for a second machine of your own. Day-two operations, restore, key rotation, token and tenant lifecycle, incidents, are in [RUNBOOK.md](RUNBOOK.md).

Operators who log here should set `"hashOnly": true` in their `log` config, so the server commits to receipts without ever holding them; the log file then contains hashes only. Without it, the server stores whole receipt envelopes, arguments and results included, which is fine for your own second machine and not for other people's receipts.

The gateway has its own image and recipes in [gateway/](gateway/README.md): one shared gateway for every agent on a host or cluster. This page is about the log.

## The image

`ghcr.io/svayatta/agent-custody-log:<version>`, built for amd64 and arm64 by the `image` workflow from `deploy/Dockerfile` and the published npm package of that version. The compose file builds the same image locally if the registry has no such tag yet, so nothing waits on the registry. To publish a version by hand: `gh workflow run image.yml -f version=0.3.0`; a `v0.3.0` tag does the same. The first push creates the package as private; make it public once in the package settings on GitHub so `docker pull` needs no login.

### Verifying an image

Each pushed image is signed by the workflow that built it (cosign, keyless) and carries a provenance attestation and an SBOM. Pin the digest rather than a tag, and check the signature before you run it. The signature is a Sigstore bundle that the registry keeps as an OCI 1.1 referrer of the image. Use cosign 3 or later to verify it: cosign 2 does not find it.

```bash
cosign verify ghcr.io/svayatta/agent-custody-log:0.8.0 \
  --certificate-identity-regexp '^https://github.com/svayatta/agent-custody/\.github/workflows/image\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
docker buildx imagetools inspect ghcr.io/svayatta/agent-custody-log:0.8.0 --format '{{ json .SBOM }}'
docker buildx imagetools inspect ghcr.io/svayatta/agent-custody-log:0.8.0 --format '{{ json .Provenance }}'
```

The identity is pinned to the `image` workflow on main (a release build runs as the default branch), and the workflow refuses to point a version tag or `latest` at anything but the tagged release commit. If a verify fails on a genuine image, print the certificate with `cosign verify ... | jq '.[0].optional'` and compare its identity before relaxing the check. The workflow's step summary lists each release's digest. Base images in every Dockerfile and compose file are pinned by digest, and Dependabot proposes the updates. A pull request that touches `deploy/` builds the image from the workspace package and starts it (`smoke-log.sh`), and checks the compose files, the manifests, the shell scripts, and `upgrade.sh` (`test-upgrade.sh`), so a broken image or script is found before the release.

If a pull or an inspect fails with `pull access denied` or `insufficient_scope` on an image that is public, docker is probably sending a stored ghcr.io login that has expired or lacks access, and the registry rejects the login although an anonymous request would succeed. Run `docker logout ghcr.io` and try again: a public image needs no login. (The same applies to `docker buildx imagetools inspect`.)

## The contract

| variable | meaning | default |
| --- | --- | --- |
| `AGENT_CUSTODY_LOG_FILE` | the Merkle log, one leaf per line | `/data/log.jsonl` |
| `AGENT_CUSTODY_LOG_KEY` | the signing key; generated on first start if absent, public half printed to the container log | `/data/keys/log.key` |
| `AGENT_CUSTODY_LOG_PORT` | listen port inside the container | `8787` |
| `AGENT_CUSTODY_LOG_TOKEN` | bearer token required on append; without it the log accepts appends from anyone who can reach it | unset |
| `AGENT_CUSTODY_LOG_ID` | the id written into every tree head, checked by verifiers with `--log-id`; use the public host | unset |
| `AGENT_CUSTODY_LOG_TENANTS` | path to a tenants file inside the container, for several file logs at `/t/<tenant>/` | unset |
| `DATABASE_URL` | with it, leaves, tenants, tokens, and checkpoints live in Postgres and the file is not used; the compose file sets it | unset |
| `ROLE` | `signer` runs the signer instead of the log | `log` |
| `AGENT_CUSTODY_SIGNER_URL`, `SIGNER_TOKEN` | the log signs through this signer with this shared secret instead of holding a key; the compose file sets them | unset |
| `AGENT_CUSTODY_HASH_ONLY` | `1` refuses `{ leaf }` on append and accepts only `{ leafHash }`, so the log process never receives a receipt; the compose file sets it for the tenanted log and not for the single-file `--profile file` server | unset (the compose file: 1) |
| `TRUST_PROXY` | `1` when a reverse proxy you run is the only way in, so per-address limits key on `X-Forwarded-For`; the compose file sets it for Caddy | unset |
| `ADMIN_TOKEN` | turns on the operator's page at `/admin` and its API, behind this token; `LOG_HOST` and `CHECKPOINTS_HOST` fill the welcome sheet | unset |
| `ADMIN_HOST` | the operator's page on its own host in the public profile (A record to this VM): Caddy maps its root to the log service's `/admin`; the token is still required on every request | unset |
| `DOCS_HOST` | the documentation site, the `docs` service in the public profile: built from this checkout by `deploy/docs.Dockerfile`, rebuilt with `update-docs.sh` after a pull | unset |
| `ROLE=portal` with `PORTAL_SECRET`, `PORTAL_HOST`, and optionally `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_TEAM` (the last two written by `stripe-setup.sh`), `MAIL_API_KEY`, `MAIL_FROM`, `MAIL_NOTIFY`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | the tenant portal: registration, first key, usage against plan, keys, billing, export; the compose file runs it as the `portal` service and Caddy serves it at `PORTAL_HOST`. The image installs `pg` and `@node-saml/node-saml` (SAML sign-in) beside the CLI, as optional peers | unset |
| `AGENT_CUSTODY_CHECKPOINT_DIR`, `AGENT_CUSTODY_CHECKPOINT_EVERY`, `AGENT_CUSTODY_CHECKPOINT_HEARTBEAT` | where signed checkpoints are written, how often the publisher looks for growth, and how often a quiet log's head is re-signed anyway so the checkpoint stays fresh; the compose file serves the directory from `CHECKPOINTS_HOST` | unset, 300, 21600 |

The volume at `/data` is the whole state: the log and the key. Back it up; a lost key means every tree head it signed is still verifiable, but new heads will be signed by a different key, which verifiers must be told about.

## Checking a change to deploy/

- `docker-compose.yaml` and `k8s/` share the variables in the table above.
- The profiles `public` (Caddy TLS and the docs site) and `file` (the file-backed log, no Postgres) are off by default. Their variables must stay optional, so that `docker compose config` passes without them.
- Check with `docker compose -f deploy/docker-compose.yaml config -q` and `kubectl kustomize deploy/k8s`. CI runs both, `shellcheck deploy/*.sh`, `test-upgrade.sh`, and the image smoke test on every pull request that touches `deploy/`. The gateway's files in `deploy/gateway` are checked the same way by the `gateway-image` workflow.
- `.github/workflows/image.yml` pushes the image to ghcr.io on a `v*` tag or by hand (`gh workflow run image.yml -f version=X`). It uses `GITHUB_TOKEN`, never a personal token. It builds each architecture on a native runner (`ubuntu-24.04-arm` for arm64), then merges the digests into one tag. Do not merge these into one multi-arch job: npm under QEMU emulation dies with SIGILL.
- The site build excludes `deploy/**`.

## Deploying from GitHub Actions

`.github/workflows/deploy.yml` deploys the host over SSH, by hand from the Actions tab. With a version it runs `deploy/upgrade.sh <version>` on the host and then `agent-custody log-check` from outside. Run it with a version once `image.yml` has built that image, which happens after the release workflow publishes. With `docs` it runs `deploy/upgrade.sh docs`. It does nothing until the repository variable `DEPLOY_HOST` is set.

`deploy/upgrade.sh` is also the command an operator runs by hand on the host: `./upgrade.sh docs`, or `./upgrade.sh 0.8.0`.
- **`docs`:** brings the checkout to main (and recreates Caddy if the Caddyfile changed) and rebuilds the docs site.
- **A version:** does the same, and also:
  - backs up the log;
  - sets `AGENT_CUSTODY_VERSION` in `.env`;
  - pulls and restarts log, signer, and portal;
  - waits up to two minutes for all three to be healthy. If they are not, it puts the previous version back and exits 1.

Postgres and Caddy keep running.

Setup, once:

1. Make a key for the workflow alone, on a machine you trust: `ssh-keygen -t ed25519 -N '' -C deploy@github -f deploy_key`.
2. On the host, add its public half to `/root/.ssh/authorized_keys` with a forced command, so the key can run `upgrade.sh` and nothing else:
   `command="/opt/agent-custody/deploy/upgrade.sh",restrict ssh-ed25519 AAAA… deploy@github`. The script reads the target from `SSH_ORIGINAL_COMMAND` and refuses anything but `docs` or a version.
3. Record the host key: `ssh-keyscan -t ed25519 <host>`, and compare its fingerprint with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the host.
4. In the repository settings, create the environment `production`. Add required reviewers to it if a release should wait for a person.
   - **Environment secrets:** `DEPLOY_SSH_KEY` (the private key file) and `DEPLOY_KNOWN_HOSTS` (the `ssh-keyscan` line).
   - **Repository variables:** `DEPLOY_HOST`, `LOG_URL`, and `CHECKPOINTS_URL`. Set `DEPLOY_USER` if the key is not root's.
5. Delete the local copy of the private key.

The images come from the published npm package, so the order is: push the tag, `release.yml` publishes, `image.yml` builds, then run this workflow with the version. Anything that runs `docker compose` on the host can take root, which is why the key is pinned to the one script rather than given a user of its own.

## One VM, docker compose

Any Linux VM with Docker works. A Hetzner CX22 (2 vCPU, 4 GB, about 4 EUR a month) is more than the first tenants need; the log does a hash and a signature per append.

```bash
# on the VM
git clone https://github.com/svayatta/agent-custody.git && cd agent-custody/deploy
cp .env.example .env
sed -i "s/^AGENT_CUSTODY_LOG_TOKEN=.*/AGENT_CUSTODY_LOG_TOKEN=$(openssl rand -hex 32)/" .env
sed -i "s/^SIGNER_TOKEN=.*/SIGNER_TOKEN=$(openssl rand -hex 32)/; s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(openssl rand -hex 24)/" .env
sed -i "s/^LOG_HOST=.*/LOG_HOST=log.example.com/; s/^CHECKPOINTS_HOST=.*/CHECKPOINTS_HOST=checkpoints.example.com/" .env   # A records for both hosts must point at the VM
docker compose --profile public up -d
docker compose logs log | grep -A3 "public key"                # hand this to verifiers as --log-key
```

Caddy obtains the certificate and forwards to the log. Without `--profile public` the log listens on the VM's loopback only, for a VPN or your own reverse proxy.

The operator's side is one config line, with the token in their environment:

```json
"log": { "url": "https://log.example.com/", "tokenEnv": "AGENT_CUSTODY_LOG_TOKEN", "hashOnly": true }
```

Verifiers add `--log-url https://log.example.com/ --log-id log.example.com`, which fetches and pins the published keys, and, to prove history was not rewritten between two receipts, `agent-custody audit` against `GET /consistency`.

**Tenants.** `docker compose exec log agent-custody log-admin --db-env DATABASE_URL tenant add acme --log-id acme-eu`, then `token add acme --label support-fleet`; the token prints once. The tenant appends at `https://log.example.com/t/acme/` and verifies with `--log-id acme-eu`. A file log from before Postgres comes in with `log-admin --db-env DATABASE_URL import --file /data/log.jsonl`, which adds its hashes to the default tenant and is safe to run twice.

**Onboarding a tenant.** Open `https://admin.example.com/` (`ADMIN_HOST`), or `https://log.example.com/admin`; the browser asks for a user name (anything) and a password, which is `ADMIN_TOKEN` from `.env`. Create the tenant, mint a token: the token is shown once beside the welcome sheet, ready to copy. Nothing under `/admin` answers without the token, wrong attempts are throttled, and tenants never see the page. The same from the server: `./onboard-tenant.sh acme --log-id acme-eu --label "support fleet"` creates the tenant and its first token, keeps the token in `/root/agent-custody-tenants/acme.token`, and prints the welcome sheet: their URL, log id, checkpoints URL, the one config line, and the two verifier commands. Hand the token over once by a channel you trust; the server keeps only its hash. Revoke with `log-admin token revoke acme <hash-prefix>`, disable with `log-admin tenant disable acme`.

**Backups.** A nightly cron job tars the data volume (the key) and `pg_dump`s the database (leaves, tenants, token hashes, checkpoints) into `/var/backups/agent-custody`, keeping thirty days; the script is in the runbook. That directory is on the same disk as the data, so `backup-offsite.sh`, installed as a second nightly job, mirrors it with rclone to the remote named by `BACKUP_REMOTE` in `.env`; restore from it once a quarter the way the runbook describes, since a backup that has never been restored is a hope. Keep at least one signed tree head somewhere the VM cannot touch; that is what an auditor compares against, and the witness does it continuously.

**Upgrades.** Bump `AGENT_CUSTODY_VERSION` in `.env`, then `docker compose --profile public pull && docker compose --profile public up -d`. The log format and the endpoints are stable within a major version; rolling back is the same two commands with the previous version.

## Kubernetes

```bash
kubectl create namespace agent-custody
kubectl -n agent-custody create secret generic agent-custody-log --from-literal=AGENT_CUSTODY_LOG_TOKEN="$(openssl rand -hex 32)"
# edit k8s/ingress.yaml: your host and cluster issuer
kubectl apply -k k8s
kubectl -n agent-custody logs deploy/agent-custody-log | grep -A3 "public key"
```

One replica, `Recreate` strategy, a `ReadWriteOnce` volume: a log has one writer, and this keeps it that way. With `DATABASE_URL` in the secret the leaves live in Postgres and the volume holds only the key.

## Monitoring and metering

`.github/workflows/monitor.yml` runs `agent-custody log-check` against the log every ten minutes from GitHub's machines, which are not ours, and a failing run emails the workflow's owner; the workflow badge is the status page. The same probe runs from any cron: `agent-custody log-check --log-url https://log.example.com/ --checkpoints-url https://checkpoints.example.com/ --tenant default --max-lag 900`, exit code 1 on trouble. `GET /health` is the liveness check for a load balancer or the container. Usage per tenant per month is on the admin page and at `/admin/usage.csv?month=YYYY-MM` for invoicing; the Registrations section at the top of the page, and `/admin/registrations.csv?month=YYYY-MM`, lists who registered each tenant through the portal, its plan and billing state, appends that month, and leaves in total, with totals.

## The witness, on someone else's machine

`deploy/witness/` is a separate compose stack: the same image with `ROLE=witness`, and a Caddy serving what it signs. It belongs on a machine and under an account that the log's operator does not control; run on the log's own machine it proves nothing. It needs the log's API URL, the checkpoints URL, and the tenants to watch, generates its own key on first start, and publishes that key at `/.well-known/agent-custody-witness.json` on its host. Every five minutes it fetches each watched log's latest checkpoint, proves it extends the last head it signed with the log's own consistency proof, and countersigns it; a checkpoint that does not extend, or a second history at the same size, gets an `ALARM.json` on the host instead of a signature. Verifiers add `--witness-url https://witness.example.org/` to `audit` and the newer head must then carry the witness's signature. `audit --older` and `--newer` accept checkpoint files from either host as well as receipt bundles.

**Alarm notice.** The witness writes `ALARM.json` and sends no message. Anyone can poll for it from any host with the public URLs, so no token is needed. `log-check` fails the check "witness has raised no alarm" when `<tenant>/ALARM.json` exists on the witness host, and the command then exits 1. The check runs only when `--checkpoints-url` and `--witness-url` are both set. Put this line in the crontab of a machine that is not the log's, and set `MAILTO` so that cron mails the output:

```
*/10 * * * * out=$(agent-custody log-check --log-url https://log.example.com/ --checkpoints-url https://checkpoints.example.com/ --witness-url https://witness.example.org/ --tenant default --max-lag 900 2>&1) || printf '%s\n' "$out"
```

The line prints only when a check fails. The witness never deletes `ALARM.json`, so the line keeps failing until the witness operator removes the file after the cause is understood.

**Rotating the witness key.** Run these steps in `deploy/witness/` on the witness host. Keep the `witnessed` volume: it holds `state.json`, the last head the witness signed.

```bash
docker compose cp witness:/data/keys/witness.pub ./witness-old.pub
docker compose exec witness sh -c 'mkdir -p /data/keys/retired && mv /data/keys/witness.key /data/keys/retired/$(date +%F).key && mv /data/keys/witness.pub /data/keys/retired/$(date +%F).pub'
docker compose restart witness
curl -s https://witness.example.org/.well-known/agent-custody-witness.json      # the new key only
```

Send `witness-old.pub` and the new key id to every verifier, and keep the old private key offline or destroy it. The next countersignature carries the new key, and the consistency check against the last head continues unchanged.

What the code does not do:

- The key document lists only the current key. The witness writes it again at every start, and it has no retired-key option, unlike the signer. A verifier that reads the key by `--witness-url` cannot verify a countersignature that the old key made.
- The witness does not sign again at a tree size that it already signed. Until the log grows, `latest.json` keeps the old signature. In that time `log-check --witness-url` fails "witness has countersigned", and `audit --witness-url` fails "newer tree head countersigned by a witness" for that checkpoint.
- Nothing links the new key to the old one. A verifier cannot tell a rotation from a takeover of the witness host. Confirm the new key id through a second channel.
- The witness has no revocation list. After a leak, the old key must not stay in any verifier's key list for heads newer than the rotation, and a countersignature carries no signed time that separates the good ones from the forged ones.

What a verifier does after a rotation:

- To check a checkpoint that the old key countersigned, add `--witness-key witness-old.pub`. The option repeats, and it combines with `--witness-url`. One valid signature from any listed key is enough.
- To check a checkpoint that the new key countersigned, keep `--witness-url`. For a log that stays quiet, wait for the first countersignature at a larger tree size.
- Remove the old key from the list when it is not needed any more.

## Hetzner now, AWS later

Yes, and it is the right order. Nothing here depends on a cloud provider: a container, a database, a volume, a hostname, and a certificate. A Hetzner VM runs the compose file as written. Moving to AWS later, when a tenant's procurement asks for it or an integration needs it, is:

1. Run the same image on ECS or EKS (the `k8s/` manifests apply to EKS unchanged apart from the ingress class and the storage class).
2. Copy the volume: the key. `tar` out, `tar` in, start. The key moves with it, so verifiers notice nothing; if you prefer a fresh key in AWS's secret store, rotate as the runbook describes and keep the old public key published.
3. `pg_dump` from Hetzner to RDS.
4. Point the DNS record at the new address. The gateway's config does not change.

Migration is a volume copy and a DNS change because the design keeps the state in one place and the trust in the key.

## What issue #6 delivered, phase by phase

| phase | what lands in the packages | what changes in this directory |
| --- | --- | --- |
| 1 | hash-only appends, tenant-scoped paths, `log` id in tree heads | done: `AGENT_CUSTODY_LOG_ID` and `AGENT_CUSTODY_LOG_TENANTS` in the contract |
| 2 | Postgres store, tokens table, rate limits | done: Postgres is in the default profile; `DATABASE_URL` in the contract; `--profile file` keeps the old single-file server |
| 3 | signer process, well-known keys, checkpoint publisher | done: the `signer` service holds the key; the log publishes checkpoints to a volume Caddy serves at `CHECKPOINTS_HOST`; verifiers use `--log-url` |
| 4 | | this is the deployment, running at log.agent-custody.dev |
| 5 | | `onboard-tenant.sh` creates a tenant and prints the welcome sheet |
| 6 | witness | done: `deploy/witness/` is its own compose stack for a machine the operator does not control; `ROLE=witness` in the same image |
