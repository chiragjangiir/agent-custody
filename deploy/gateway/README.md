# Running the gateway as a service

One shared agent-custody gateway for every agent on a host or cluster. All their tool calls go through it, each agent connection presents its own signed grant, and the tool credentials live in the gateway and never in an agent. This is the long-running way to run the gateway (`agent-custody gateway --http`); for a single agent session the host can spawn the gateway on stdio and there is nothing to operate (see [the gateway guide](../../packages/receipts/docs/usage.md)).

```
agent A ─┐                                          ┌─ Stripe (REST)
agent B ─┼─ MCP over HTTP, own grant ─▶ gateway ────┼─ GitHub (MCP)
agent C ─┘      (this image)             │          └─ another agent (A2A)
                                         └─ signed receipts ─▶ /data, and the log
```

## The image

`ghcr.io/svayatta/agent-custody-gateway`, for linux/amd64 and linux/arm64, built by the `gateway-image` workflow:

| tag | built when | from |
| --- | --- | --- |
| `edge`, `sha-<short>` | every merge to main that touches the receipts package or `deploy/gateway` | the source of that commit |
| `<version>`, `<major>.<minor>`, `latest` | every release | the published npm package of that version |

Run a version, or better its digest, in production. `latest` moves on every release, and `edge` on every merge, so neither is a default anywhere in these files. The first release that carries the gateway image publishes its version tag; until then use `edge` to try it, not in production. Every build starts the image and runs [smoke.sh](smoke.sh) before it is pushed: healthy, a connection with no grant refused, a demo grant accepted, and `docker stop` closing the gateway cleanly. The first push creates the package as private; make it public once in the package's settings so `docker pull` needs no login.

Every pushed image is signed by the workflow that built it (cosign, keyless) and carries a provenance attestation and an SBOM. Check one before you run it, and pin the digest in production. The signature is a Sigstore bundle that the registry keeps as an OCI 1.1 referrer of the image. Use cosign 3 or later to verify it: cosign 2 does not find it.

```bash
cosign verify ghcr.io/svayatta/agent-custody-gateway:0.8.0 \
  --certificate-identity-regexp '^https://github.com/svayatta/agent-custody/\.github/workflows/gateway-image\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
docker buildx imagetools inspect ghcr.io/svayatta/agent-custody-gateway:0.8.0 --format '{{ json .SBOM }}'
```

The identity is pinned to this workflow on main: a release build (`workflow_run`) and a push to main both sign as the default branch, and a build of any other ref does not verify. The workflow refuses to point a version tag or `latest` at anything but the tagged release commit, and `edge` at anything but main. If a verify fails on a genuine image, print the certificate with `cosign verify ... | jq '.[0].optional'` and compare its identity before relaxing the check. The `gateway-image` workflow's step summary lists the digest of each build.

If a pull or an inspect fails with `pull access denied` or `insufficient_scope` on an image that is public, docker is probably sending a stored ghcr.io login that has expired or lacks access, and the registry rejects the login although an anonymous request would succeed. Run `docker logout ghcr.io` and try again: a public image needs no login. (The same applies to `docker buildx imagetools inspect`.)

## Start one

```bash
mkdir config
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD/config:/config" ghcr.io/svayatta/agent-custody-gateway:<version> init
echo 'AGENT_CUSTODY_GATEWAY_VERSION=<version>' > .env
docker compose up -d        # or: docker run -d -v "$PWD/config:/config:ro" -v gateway-data:/data -p 127.0.0.1:8790:8790 <image>
curl http://127.0.0.1:8790/health
```

`init` writes a starter `gateway.json`, an example `policy.cedar`, the public half of a demo principal key, and a demo 24-hour grant under `config/demo/`. Edit the upstream, then restart; a policy edit applies from the next call. **Delete `config/demo/` before production:** the principal's private key must never sit on the gateway host. Issue real grants on the principal's own machine with `agent-custody grant --key principal.key ...`, and put only `principal.pub` in the config.

An agent connects to `http://<gateway>:8790/mcp` and presents its grant as the base64url of the grant file, in `Authorization: Bearer <value>` or `X-Agent-Custody-Grant`. `base64 < grant.json | tr -d '\n=' | tr '+/' '-_'` makes the value. From JavaScript, `grantHeader(envelope)` does. One gateway serves every grant that is signed by a key in `trustedPrincipalKeys`.

[example/](example/README.md) is a complete config directory you can copy: a REST API, a policy, a fact lookup, and the steps to make the principal's key, issue grants, and run it. Who may use which tools, where the tools live, and the principal's key are in [configuring the gateway](../../packages/receipts/docs/configuration.md). Check a config before you start it, in the same container image, with the same mounts and environment:

```bash
docker run --rm -v "$PWD/config:/config:ro" -v gateway-data:/data --env-file .env <image> check --config /config/gateway.json --connect
```

The container runs the same check, without `--connect`, each time it starts, and **does not start if it finds an error**: a mistyped key, a policy that does not parse, a missing credential variable, a path the gateway cannot write. Set `GATEWAY_CHECK=advisory` to print the findings and start anyway, or `GATEWAY_CHECK=off` to skip it.

## What goes where

| path in the container | holds | mounted |
| --- | --- | --- |
| `/config` | `gateway.json`, `policy.cedar` (or `policy.rego`, which the image's `opa` compiles), the principals' public keys | read-only, from your repository or a ConfigMap |
| `/data` | the gateway's key (created on first start), receipts, the local log, `revoked.json`, the operations store | a named volume or a persistent volume claim |
| environment | the credentials the upstreams read (`headerEnv`, `tokenEnv` in `gateway.json`), the log's token | `.env`, a Secret |

Paths in `gateway.json` are relative to `/config`; give absolute `/data/...` paths for anything the gateway writes. The gateway key is created once and printed (public half) in the container log; verifiers check receipts against it, so back the `/data/keys` directory up and keep it. Do not put tool credentials in an agent's environment: an agent that holds a Stripe key can call Stripe directly and nothing here sees it.

For evidence a customer or auditor will accept, point `log` in `gateway.json` at a log run by someone else (`"log": { "url": ..., "tokenEnv": ..., "hashOnly": true, "keys": [...] }`; [usage.md](../../packages/receipts/docs/usage.md), "Logging to a remote log"). `init` configures a local file log and `"precommit": ["*"]`, so every agent call is authorized in the log before it is forwarded; name only the consequential tools once you know them.

## Running it

| task | how |
| --- | --- |
| revoke a grant | `docker compose exec gateway agent-custody revoke --config /config/gateway.json --grant /path/in/container/grant.json`. The next call of every session under that grant, and every grant delegated from it, is refused; no restart. |
| change the policy | save it through `agent-custody console`, or write `config/policy.cedar` by rename (write a temporary file, then `mv` it over). The gateway applies it from the next call with no restart, and records the change in `receipts/policy-reloads.jsonl`. A file that does not parse is refused and the old policy stays. A `policy.rego` is applied and refused the same way; the console edits Cedar only. With `opa` in the config the policy lives on your OPA server instead. |
| upgrade | set `AGENT_CUSTODY_GATEWAY_VERSION` and `docker compose pull && docker compose up -d`. |
| stop | `docker compose stop`. The gateway closes on SIGTERM; `stop_grace_period` is 30 s. |
| other commands | anything after the image name runs through the `agent-custody` CLI: `docker compose run --rm gateway verify ...`. |
| plain VM | [agent-custody-gateway.service](agent-custody-gateway.service) runs the same command under systemd. |
| Kubernetes | `kubectl apply -k deploy/gateway/k8s`; the header of [k8s/kustomization.yaml](k8s/kustomization.yaml) lists the steps. |
| TLS | `docker compose --profile tls up -d` puts Caddy in front on `GATEWAY_HOST`. |
| the console | `docker compose --profile console up -d` runs the [admin console](../../packages/receipts/docs/console.md) from the same image on `127.0.0.1:8795`: config, tools, receipts with a verdict each, a policy editor that replays recorded calls, and grant revocation. Its token is a Docker secret that only the console service reads: `openssl rand -hex 32 > console-token && chmod 600 console-token` (or `CONSOLE_TOKEN_FILE` in `.env`). It does not go in `.env`, which the gateway reads. The console mounts `./config` read-write, because it edits the policy file, and runs as the same user as the gateway (`GATEWAY_UID` and `GATEWAY_GID`, default 10001), so `sudo chown 10001:10001 config`, or set your own ids and `GATEWAY_DATA=./data` to a directory you own. Keep it on loopback or a private network. |

## What a shared gateway means, and its limits

- **A grant is a bearer credential.** The gateway does not check that the connecting party holds the agent's key, so whoever has a grant can connect as that agent until it expires or is revoked. Use short grant lifetimes, keep the port on a private network or behind mutual TLS, and revoke at once on a leak.
- **The transport is plain HTTP.** The compose file publishes on 127.0.0.1 by default. Put TLS in front before it crosses a network.
- **One process holds every agent's tool credentials.** That is the point, and also the blast radius. One policy and one gateway key apply to all agents on it; run one gateway per team where that is not acceptable.
- **One replica.** Sessions live in memory and the local log has one writer, so run a single instance (the Kubernetes manifest uses `Recreate`). A second replica needs sticky routing and shared state that is not built.
- **Availability.** A stopped gateway is every agent stopped, and a log that is down withholds the `precommit` calls of every agent.
- **Policy edits apply from the next call,** like grants and revocations, with no restart. Write the policy by rename: an editor saving in place can be read half-written.
- **Stdio upstreams need their tool inside the image.** REST and A2A upstreams work out of the box. For an MCP server that is a command, build on this image (`FROM ghcr.io/svayatta/agent-custody-gateway`, then install the tool) or reach it over HTTP.

## Building it yourself

```bash
cd packages/receipts && bun run build && bun pm pack --destination ../../deploy/gateway/pkg   # from the workspace
cd ../../deploy/gateway && docker build -t agent-custody-gateway:local .
# or, from a published version: docker build --build-arg AGENT_CUSTODY_VERSION=0.8.0 -t agent-custody-gateway:local .
./smoke.sh agent-custody-gateway:local
```
