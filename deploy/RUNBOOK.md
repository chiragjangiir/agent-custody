# Running the log: the runbook

Day-two procedures for the deployment in this directory, written against the live one at log.agent-custody.dev. Every command runs on the log's host in `deploy/` unless it says otherwise. Nothing here prints a token; tokens live in `.env` and in `/root/agent-custody-tenants/<tenant>.token`, and are handed over once by a channel you trust.

What the pieces hold, so the blast radius of each procedure is clear:

| piece | holds | if lost | if leaked |
| --- | --- | --- | --- |
| `signer` (volume `/data/keys/log.key`) | the private key that signs every tree head and checkpoint | new heads are signed by a new key; old heads keep verifying if the old public key stays published | an attacker can sign a false head; rotate, publish the old key as retired, tell tenants the date |
| `postgres` | leaf hashes per tenant, tenants, token **hashes**, checkpoints | restore from backup; leaves appended since the backup are gone and their receipts no longer verify inclusion | hashes only; nothing to replay, no receipt content |
| `.env` | `ADMIN_TOKEN`, `SIGNER_TOKEN`, `POSTGRES_PASSWORD`, `AGENT_CUSTODY_LOG_TOKEN` | regenerate | rotate the leaked one, below |
| `/checkpoints` volume | signed checkpoints the second host serves | regenerated from Postgres on the next publish | public data |
| a tenant's token (their side) | the right to append to their log | mint another | revoke, mint another; appends made with it in between are in their log and visible in usage |

## Routine

**Upgrade.** Run the `deploy` workflow from the Actions tab with the version once its image is built (`.github/workflows/deploy.yml`, set up in `deploy/README.md`), or `./upgrade.sh <version>` on the host. Either one does: backup, check out the release tag `v<version>` (so the compose file, the Caddyfile, and the scripts are the released ones and not main's), version, pull, restart, health, and the previous version and its checkout back if the new one is not healthy. A version deploy leaves the checkout on the tag; `docs` returns it to main. Without the script, bump `AGENT_CUSTODY_VERSION` in `.env`, then:

```bash
docker compose --profile public pull && docker compose --profile public up -d
docker compose --profile public ps
```

Both `log` and `signer` restart on the new image; Postgres and Caddy do not. Roll back by setting the previous version and running the same two commands. Then confirm from outside: `agent-custody log-check --log-url https://log.example.com/ --checkpoints-url https://checkpoints.example.com/ --tenant default`.

**Docs.** `docs.<domain>` is the site built from the checkout on this host. Rebuild it with the `deploy` workflow and `docs`, or `./upgrade.sh docs` on the host, or after `git pull`, `./update-docs.sh`. Nothing else changes.

**Caddyfile changes.** The `caddy` service mounts `./Caddyfile` as a single file, and `git pull` replaces that file rather than editing it, so the running container keeps the old one: `caddy reload` then re-reads the old config and reports success. After a pull that touches the Caddyfile, recreate the container instead, which drops every host for a second or two:

```bash
docker compose --profile public up -d --force-recreate --no-deps caddy
docker compose exec -T caddy grep -c '<a line you changed>' /etc/caddy/Caddyfile
```

The second command proves the container sees the new file; a count of 0 means it is still on the old one.

**Backups.** `/etc/cron.daily/agent-custody-log-backup` runs nightly:

```bash
cd /opt/agent-custody/deploy
docker run --rm -v agent-custody_logdata:/data:ro -v /var/backups/agent-custody:/backup alpine tar czf "/backup/log-$(date +%F).tgz" -C / data
docker compose exec -T postgres pg_dump -U custody custody_log | gzip > "/var/backups/agent-custody/db-$(date +%F).sql.gz"
find /var/backups/agent-custody -name 'log-*.tgz' -mtime +30 -delete
find /var/backups/agent-custody -name 'db-*.sql.gz' -mtime +30 -delete
```

The tarball is the key; the dump is everything else. Both land on the same disk as the data, so `backup-offsite.sh` copies the directory off the machine with rclone every night, an hour after the dump; `BACKUP_REMOTE` in `.env` names the destination (`hetzner:agent-custody-backups`, `s3:bucket/prefix`, or an sftp storage box) and the script refuses to run without it, so a missing destination is loud. Install: `cp backup-offsite.sh /etc/cron.daily/agent-custody-backup-offsite` after `rclone config` on the host. Check the directory has yesterday's two files whenever you log in, and that the remote listing matches.

**Restore drill, quarterly.** `./restore-drill.sh [YYYY-MM-DD]` on the log's host restores that night's dump and key tarball into a second compose project on its own volumes, with no ports and no Caddy, starts postgres, signer, and log there, checks the restored log's head against its own key document, requires the restored key id to equal the live log's, prints the leaf and tenant counts, and tears the project down. It touches nothing in the live project. Exit 0 is a pass; record the date and result below. To rebuild on a fresh VM for real, the same steps by hand: clone, `.env` with the same secrets, `up -d postgres`, pipe the dump into `psql`, untar the key into the `logdata` volume, `up -d`.

Drills: 2026-09-09, backups of 2026-09-08, PASS (first drill).

**Disk and certificates.** Caddy renews certificates itself; `docker compose logs caddy | grep -i error` if a host stops answering on 443. Postgres grows by roughly a hundred bytes per leaf; `df -h /` is the check, and the nightly dumps are the first thing to prune if it fills.

## Tenants and tokens

**Onboard.** `./onboard-tenant.sh <id> --log-id <id> --label "<team>"` creates the tenant and its first token, keeps the token in `/root/agent-custody-tenants/<id>.token`, and prints the welcome sheet to hand over. Or the admin page, at `https://<ADMIN_HOST>/` or `/admin` on the log host; its Registrations section is where to see who has signed up, on what plan, whether they pay, and how much they have logged this month and in total.

**Change a tenant's plan.** `docker compose exec log agent-custody log-admin --db-env DATABASE_URL tenant plan <id> team`, or the plan column on the admin page. The new allowance applies from the next append; the change is in the audit trail. Free allows ten thousand appends a month, team a million, enterprise has no allowance.

**Rotate a tenant's token.** Mint the new one first, hand it over, let them switch, then revoke the old:

```bash
docker compose exec log agent-custody log-admin --db-env DATABASE_URL token add <id> --label "<team> 2026-10"
docker compose exec log agent-custody log-admin --db-env DATABASE_URL token revoke <id> <old hash prefix>
```

Every one of these commands is recorded in the audit trail with your user and host. Hash prefixes are on the admin page and in `log-admin token list <id>` (the first eight characters of the stored hash; the plaintext is not recoverable). A revoked token gets 401 on its next append; the gateway behind it withholds pre-committed calls and errors on the rest, which is the tenant's signal that the switch missed a machine.

**Export, theirs to run.** A tenant takes their own log with `agent-custody log-export --log-url https://log.example.com/ --tenant <id> --token-env AGENT_CUSTODY_LOG_TOKEN --out <dir>`: every leaf hash as a log file the verifier reads, the signed head, the keys, the checkpoints, their usage, self-checked. Put it in the welcome sheet and in the offboarding email; a tenant who runs it monthly never depends on this machine for their evidence.

**Offboard.** `tenant disable <id>` refuses new appends and keeps the log readable, so receipts the tenant already holds keep verifying inclusion and their auditors can still fetch consistency proofs; this is the default and the honest one. The leaves themselves are hashes and stay: removing them would change every later root in that tenant's tree and break their own evidence. If a contract requires the tenant's log gone entirely, `DELETE FROM log_leaves WHERE tenant_id = '<id>'` and the rows in `log_heads`, `log_tokens`, and `log_tenants` for it, after telling them in writing that their receipts will no longer prove inclusion; take a dump first.

## The portal and billing

**What it is.** `app.<your domain>`, the `portal` service: a team registers with an email, a password, and a tenant id, and gets the tenant and its first key at once; the dashboard shows appends against the plan, the tree size, the latest checkpoint, keys, and the audit rows; keys are minted and revoked there, and the team plan is bought there through Stripe Checkout. Every action the portal takes on a tenant is in the audit trail as `portal:<email>`, and every plan change by Stripe as `stripe:<event>`.

**Stripe setup, once.** Put the secret key in `.env` without it touching a terminal history or a transcript: `read -s k && printf 'STRIPE_SECRET_KEY=%s\n' "$k" >> .env && unset k`. Then `./stripe-setup.sh`: it creates the product "agent-custody Team" with a recurring monthly price of $50 and the webhook endpoint at `https://<PORTAL_HOST>/stripe/webhook` for `checkout.session.completed`, `customer.subscription.updated`, and `customer.subscription.deleted`, reusing any that exist, and writes `STRIPE_PRICE_TEAM` and `STRIPE_WEBHOOK_SECRET` into `.env` (the signing secret is only returned when the endpoint is created; for an endpoint made by hand, paste its secret from the dashboard). Enable the customer portal under Settings, Billing, so "Manage billing" works. Then `docker compose --profile public up -d portal`. Test mode first: the same three variables from the test dashboard, a checkout with card 4242 4242 4242 4242, the tenant's plan moving to team on the admin page and in the audit trail, then swap to live keys.

**A tenant says they paid and are still on free.** The webhook did not arrive or was refused: check Stripe's webhook log for the endpoint and the portal's log for `bad signature`; a wrong `STRIPE_WEBHOOK_SECRET` is the usual cause. Move the plan by hand (`tenant plan <id> team`) and fix the secret.

**Mail setup, once.** Registration sends the person a welcome (the setup sheet, never the key) and, with `MAIL_NOTIFY`, sends you a note with their contact details. Create a Resend account, add the domain and its DNS records there, make an API key, then put `MAIL_API_KEY`, `MAIL_FROM` (an address on that domain, no display name) and `MAIL_NOTIFY` in `.env` and `docker compose --profile public up -d portal`. A provider failure is logged by the portal and never fails a registration.

**Sign-in providers, once.** GitHub: Settings, Developer settings, OAuth Apps, New OAuth App, with the callback `https://<PORTAL_HOST>/auth/github/callback`; Google: a project in the Google Cloud console, OAuth consent screen (external, the email scope only), then Credentials, OAuth client ID, web application, with the same shape of redirect URI at `/auth/google/callback`. Put the ids and secrets in `.env` as `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, then `docker compose --profile public up -d portal`. A provider sign-in links to the account with the same verified email, or creates one; the person then sets up their tenant on the next screen.

**The founder's note, hourly.** About an hour after someone registers, `followup.sh` sends them a personal note from `MAIL_FROM` (who they are, which stack, an offer to do the integration, start in observe mode), once each, to registrations up to a week old; accounts on your own mail domains are skipped. The script reads `.env` beside itself, so cron must run it in place, not a copy. Install it once as a wrapper:

```bash
printf '#!/bin/sh\nexec /opt/agent-custody/deploy/followup.sh >> /var/log/agent-custody-followup.log 2>&1\n' > /etc/cron.hourly/agent-custody-followup && chmod +x /etc/cron.hourly/agent-custody-followup
```

It runs `agent-custody portal-followup` inside the portal container and logs one line per run to `/var/log/agent-custody-followup.log`; `./followup.sh --dry-run` shows who would get it. A provider failure leaves the person pending for the next hour. The text is `founderNote` in `portal.ts`; change it there.

**A lost password.** There is no reset flow until an email provider is configured for it. Verify the person by another channel, then `docker compose exec portal agent-custody log-admin --db-env DATABASE_URL audit --tenant <id>` shows which email registered the tenant; a new password is set by deleting the row in `portal_users` for that email and letting them register the same email again against the existing tenant is not supported, so instead update `password_hash` with a hash from `PortalStore.hashPassword` in a node one-liner inside the container. Write down that you did it.

**Single sign-on for a tenant.** The operator does this, never the tenant. Get from the tenant's IT team: for OIDC, the issuer URL, a client id, and a client secret, with the redirect URI `https://<PORTAL_HOST>/auth/sso/<tenant>/callback` registered at their IdP; for SAML, the IdP's sign-in URL and its signing certificate as a PEM file, and give them the metadata from `https://<PORTAL_HOST>/auth/sso/<tenant>/saml`. Put the OIDC secret in the environment of the command, not in the command line: `read -s s && ACME_OIDC_SECRET=$s docker compose exec -e ACME_OIDC_SECRET portal agent-custody log-admin --db-env DATABASE_URL sso set <tenant> --oidc-issuer <url> --oidc-client-id <id> --oidc-secret-env ACME_OIDC_SECRET --domains acme.com --default-role readonly; unset s`. For SAML use `--saml-entry-point <url> --saml-cert <pem file> --domains acme.com` instead. A domain belongs to one tenant. Test with `sso show <tenant>` and one real sign-in from a test member, then run `sso set` again with all its flags and `--enforce` once the tenant's owners have signed in through the IdP: an owner whose address is not verified is locked out when enforcement is on, because the IdP sign-in is refused (`409`) and the password sign-in is refused (`403`), so each owner must verify the address, or sign in through the IdP, first. With it on, members cannot use a password, GitHub, or Google, and their older sessions end. `sso remove <tenant>` turns single sign-on off for the tenant. `sso set`, `sso remove`, and `user mfa-reset` are in the audit trail like the other commands, with your user and host and never a secret.

**A member lost their authenticator.** Verify the person by another channel, then `docker compose exec portal agent-custody log-admin --db-env DATABASE_URL user mfa-reset <email>`. The account has MFA off until the person sets it up again. A member who signs in through single sign-on has no portal MFA to reset: their IdP owns it.

**Sign everyone out.** Rotate `PORTAL_SECRET` and restart the portal.

## Keys and secrets

**Rotating the signing key.** Heads signed by the old key must keep verifying, so the old public key stays published as retired. The entrypoint lists every `.pub` in `/data/keys/retired/` in the key document.

```bash
docker compose exec signer sh -c 'mkdir -p /data/keys/retired && cp /data/keys/log.pub /data/keys/retired/$(date +%F).pub && mv /data/keys/log.key /data/keys/retired/$(date +%F).key.retired && agent-custody keygen --dir /data/keys --name log'
docker compose --profile public restart signer log
curl -s https://log.example.com/.well-known/agent-custody-log.json      # the new keyid first, the old one after it
```

Then tell tenants the new key id and the date; verifiers that pin by `--log-url` pick it up on their next fetch, and verifiers holding a `--log-key` file need the new one. Gateways that pin the key in `log.keys` (required with `precommit`) refuse every append signed by the new key, so tell tenants before the switch to add the new `.pub` beside the old one; a gateway that fetched the keys on first use needs a restart. Keep the retired private key offline or destroy it; nothing needs it again. Rotate on a schedule you state in your terms (yearly is reasonable), and immediately on any suspicion of the host.

The witness has its own key, and its rotation is different: see "The witness, on someone else's machine" in [README.md](README.md).

**A leaked admin token.** Set a new `ADMIN_TOKEN` in `.env`, `docker compose --profile public up -d log`. Then read the Activity list on the admin page, or `log-admin audit`: every tenant and token change carries who made it and from which address, so anything you did not do stands out; revoke it and disable the tenant. Appends made through a token the attacker minted are hashes in that tenant's log, worthless to them and harmless to others.

**A leaked signer token.** Same with `SIGNER_TOKEN`, restarting both `signer` and `log`. The signer is reachable only inside the compose network, so a leaked token alone signs nothing from outside; treat it as a sign the host may be compromised and rotate the key as well.

**A compromised host.** Assume the private key was read. Rotate the key as above with the old one retired, rotate every secret in `.env`, revoke every tenant token and mint new ones, rebuild the VM from a clean image, and restore Postgres from the last backup you trust. Tell tenants the window between the last checkpoint the witness countersigned and the rotation; heads signed inside it are the ones a verifier should treat as unwitnessed. This is the case the witness exists for: with one running, `audit --witness-url` proves any head from the window that the attacker did not manage to get countersigned.

## Incidents a monitor failure means

The `monitor` workflow, or your own cron running `log-check`, fails for one of these:

| check that failed | likely cause | do |
| --- | --- | --- |
| key document served | log down, Caddy down, certificate | `docker compose --profile public ps`, `logs log`, `logs caddy`; a Caddy that restarts with `server block without any key` means a host variable the Caddyfile names is not in the caddy service's environment |
| head verifies against the published keys | the signer restarted with a key not in the document | check `/data/keys`; a rotation done without copying the `.pub` into `retired/` looks like this |
| latest checkpoint verifies | the checkpoints volume was edited or served stale | `docker compose restart log` republishes; compare with Postgres `log_heads` |
| checkpoint keeps up with the head | the publisher stopped, or `--max-lag` is shorter than `AGENT_CUSTODY_CHECKPOINT_EVERY` | `logs log \| grep checkpoint` |
| head extends the checkpoint | **the log's history changed.** | stop the log, keep every file, page whoever is on call, and do not restart until the cause is known; a consistency failure is the one alarm that must never be cleared by a restart |
| witness countersigned / no alarm | the witness's view of the log disagrees with the log's | read the witness's `ALARM.json`; it names the two heads |

Write down, for each incident: when it was noticed, what failed, what was done, and when it cleared. Tenants whose logs were affected get that record.

## Contacts and cadence

- Security reports: see [SECURITY.md](../SECURITY.md).
- Weekly: `df -h`, yesterday's backup files present, the monitor badge green, Dependabot pull requests reviewed.
- Quarterly: restore drill; review the tenant list and revoke tokens with no appends in the quarter.
- Yearly: key rotation.
