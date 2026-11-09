#!/bin/sh
# Smoke test for the gateway image: init writes a config, the container becomes healthy, a connection with no grant is
# refused and one with the demo grant gets a session, and `docker stop` closes the gateway (exit 0, not SIGKILL). Then the
# same image in egress mode: the witness creates its key, becomes healthy, refuses a connection with no proxy credential
# (407) and one its policy does not permit (403) before connecting anywhere, and stops with exit 0.
# Usage: ./smoke.sh <image>        needs docker, curl, and free ports 18790 and 18791
set -eu
image="${1:?usage: smoke.sh <image>}"
port=18790
work=$(mktemp -d)
name="gateway-smoke-$$"
eport=18791
ename="egress-smoke-$$"
cleanup() { docker rm -f "$name" "$ename" > /dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
fail() { echo "smoke: $*" >&2; docker logs "$name" >&2 2>&1 || true; docker logs "$ename" >&2 2>&1 || true; exit 1; }

mkdir "$work/config"
docker run --rm -u "$(id -u):$(id -g)" -v "$work/config:/config" "$image" init > /dev/null 2>&1 || fail "init failed"
[ -f "$work/config/gateway.json" ] || fail "init wrote no config"
[ -f "$work/config/demo/grant.json" ] || fail "init wrote no demo grant"

docker run -d --name "$name" -v "$work/config:/config:ro" -p "127.0.0.1:$port:8790" "$image" > /dev/null
i=0
until [ "$(docker inspect -f '{{.State.Health.Status}}' "$name")" = healthy ]; do
  i=$((i + 1)); [ "$i" -le 30 ] || fail "not healthy after 60 s"
  sleep 2
done

curl -fsS "http://127.0.0.1:$port/health" | grep -q '"ok":true' || fail "/health did not answer ok"
init='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}'
post() { curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$port/mcp" -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' "$@" -d "$init"; }
[ "$(post)" = 403 ] || fail "a connection with no grant was not refused"
grant=$(base64 < "$work/config/demo/grant.json" | tr -d '\n=' | tr '+/' '-_')
[ "$(post -H "authorization: Bearer $grant")" = 200 ] || fail "the demo grant did not open a session"

start=$(date +%s)
docker stop "$name" > /dev/null
elapsed=$(( $(date +%s) - start ))
code=$(docker inspect -f '{{.State.ExitCode}}' "$name")
[ "$code" = 0 ] || fail "stopped with exit code $code, not 0 (SIGKILL is 137)"
[ "$elapsed" -le 8 ] || fail "docker stop took ${elapsed}s: the gateway ignored SIGTERM"
echo "smoke: ok (healthy, no-grant refused, demo grant accepted, stopped in ${elapsed}s with exit 0)"

mkdir "$work/egress"
cat > "$work/egress/egress.json" <<'JSON'
{ "identity": { "keyFile": "/data/keys/egress.key" }, "agents": [{ "id": "smoke-agent", "secretEnv": "EGRESS_SECRET_SMOKE" }],
  "policyFile": "policy.cedar", "receiptsDir": "/data/receipts", "logFile": "/data/log.jsonl" }
JSON
printf 'permit(principal == Agent::"smoke-agent", action == Action::"example.invalid:443", resource);\n' > "$work/egress/policy.cedar"
secret=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
docker run -d --name "$ename" -v "$work/egress:/egress:ro" -e EGRESS_CONFIG=/egress/egress.json -e EGRESS_SECRET_SMOKE="$secret" \
  -p "127.0.0.1:$eport:8791" "$image" egress > /dev/null
i=0
until [ "$(docker inspect -f '{{.State.Health.Status}}' "$ename")" = healthy ]; do
  i=$((i + 1)); [ "$i" -le 30 ] || fail "the egress witness was not healthy after 60 s"
  sleep 2
done
docker logs "$ename" 2>&1 | grep -q "created the egress witness key" || fail "egress mode did not create the witness key"
curl -fsS "http://127.0.0.1:$eport/.well-known/agent-custody-egress" | grep -q '"keyid"' || fail "the witness did not answer its well-known route"
# both refusals happen before the witness connects anywhere: nothing leaves the runner
via() { curl -s -o /dev/null -w '%{http_connect}' -x "http://127.0.0.1:$eport" "$@" https://api.stripe.com/ || true; }
[ "$(via)" = 407 ] || fail "a connection with no proxy credential was not refused with 407"
[ "$(via -U "smoke-agent:$secret")" = 403 ] || fail "a destination the policy does not permit was not refused with 403"
docker stop "$ename" > /dev/null
code=$(docker inspect -f '{{.State.ExitCode}}' "$ename")
[ "$code" = 0 ] || fail "the witness stopped with exit code $code, not 0"
echo "smoke: ok (egress mode: key created, healthy, 407 without a credential, 403 for a refused destination, stopped with exit 0)"
