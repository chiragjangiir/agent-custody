#!/bin/sh
# Smoke test for the gateway image: init writes a config, the gateway and a CLI command refuse to run with a witness
# proxy secret in their environment (without logging the value), the container becomes healthy, a connection with no grant is
# refused and one with the demo grant gets a session, and `docker stop` closes the gateway (exit 0, not SIGKILL). Then the
# same image in egress mode: the witness creates its key, becomes healthy, refuses a connection with no proxy credential
# (407) and one its policy does not permit (403) before connecting anywhere, relays one its policy permits (to a listener
# in a container beside it), writes a receipt for the refusal and the relay, and stops with exit 0.
# Usage: ./smoke.sh <image>        needs docker, curl, and free ports 18790 and 18791
set -eu
image="${1:?usage: smoke.sh <image>}"
port=18790
work=$(mktemp -d)
name="gateway-smoke-$$"
eport=18791
ename="egress-smoke-$$"
uname="egress-upstream-$$"
net="egress-smoke-$$"
lname="gateway-leftover-$$"
cleanup() { docker rm -f "$name" "$ename" "$uname" "$lname" > /dev/null 2>&1 || true; docker network rm "$net" > /dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
fail() { echo "smoke: $*" >&2; docker logs "$name" >&2 2>&1 || true; docker logs "$ename" >&2 2>&1 || true; exit 1; }

mkdir "$work/config"
docker run --rm -u "$(id -u):$(id -g)" -v "$work/config:/config" "$image" init > /dev/null 2>&1 || fail "init failed"
[ -f "$work/config/gateway.json" ] || fail "init wrote no config"
[ -f "$work/config/demo/grant.json" ] || fail "init wrote no demo grant"
# a witness proxy secret left in the gateway's environment stops the gateway, and its value is not logged
docker run -d --name "$lname" -v "$work/config:/config:ro" -e EGRESS_SECRET_SMOKE_LEFTOVER=leftover-value "$image" > /dev/null
i=0
while [ "$(docker inspect -f '{{.State.Running}}' "$lname")" = true ]; do
  i=$((i + 1)); [ "$i" -le 15 ] || fail "the gateway started with an EGRESS_SECRET_ variable in its environment"
  sleep 1
done
[ "$(docker inspect -f '{{.State.ExitCode}}' "$lname")" != 0 ] || fail "the gateway exited 0 with an EGRESS_SECRET_ variable in its environment"
leftover=$(docker logs "$lname" 2>&1)
echo "$leftover" | grep -q "EGRESS_SECRET_SMOKE_LEFTOVER is in this container's environment, so 'serve' is not running" || fail "a leftover proxy secret did not stop the gateway: $leftover"
# the same for a command passed through to the CLI: every command but egress refuses
cli=$(docker run --rm -v "$work/config:/config:ro" -e EGRESS_SECRET_SMOKE_LEFTOVER=leftover-value "$image" check --config /config/gateway.json 2>&1) && fail "a CLI command ran with an EGRESS_SECRET_ variable"
echo "$cli" | grep -q "so 'check' is not running" || fail "a leftover proxy secret did not stop a CLI command: $cli"
echo "$leftover" | grep -q "leftover-value" && fail "the gateway logged the value of a leftover proxy secret"

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
echo "smoke: ok (a leftover proxy secret refused, healthy, no-grant refused, demo grant accepted, stopped in ${elapsed}s with exit 0)"

mkdir "$work/egress"
# the permitted destination: a TCP listener in a container on a network of its own, named by its address, because the
# witness refuses a host name that resolves to a private address and dials an address only when the policy names it
docker network create "$net" > /dev/null
docker run -d --name "$uname" --network "$net" --entrypoint node "$image" \
  -e "require('net').createServer((s) => s.end('ok')).listen(9443)" > /dev/null
upstream="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$uname"):9443"
cat > "$work/egress/egress.json" <<'JSON'
{ "identity": { "keyFile": "/data/keys/egress.key" }, "agents": [{ "id": "smoke-agent", "secretEnv": "EGRESS_SECRET_SMOKE" }],
  "policyFile": "policy.cedar", "receiptsDir": "/data/receipts", "logFile": "/data/log.jsonl" }
JSON
printf 'permit(principal == Agent::"smoke-agent", action == Action::"%s", resource);\n' "$upstream" > "$work/egress/policy.cedar"
secret=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
docker run -d --name "$ename" --network "$net" -v "$work/egress:/egress:ro" -e EGRESS_CONFIG=/egress/egress.json -e EGRESS_SECRET_SMOKE="$secret" \
  -p "127.0.0.1:$eport:8791" "$image" egress > /dev/null
i=0
until [ "$(docker inspect -f '{{.State.Health.Status}}' "$ename")" = healthy ]; do
  i=$((i + 1)); [ "$i" -le 30 ] || fail "the egress witness was not healthy after 60 s"
  sleep 2
done
docker logs "$ename" 2>&1 | grep -q "created the egress witness key" || fail "egress mode did not create the witness key"
curl -fsS "http://127.0.0.1:$eport/.well-known/agent-custody-egress" | grep -q '"keyid"' || fail "the witness did not answer its well-known route"
# both refusals happen before the witness connects anywhere: nothing leaves the runner
via() { target="$1"; shift; curl -s -m 10 -o /dev/null -w '%{http_connect}' -x "http://127.0.0.1:$eport" "$@" "https://$target/" || true; }
[ "$(via api.stripe.com)" = 407 ] || fail "a connection with no proxy credential was not refused with 407"
[ "$(via api.stripe.com -U "smoke-agent:$secret")" = 403 ] || fail "a destination the policy does not permit was not refused with 403"
# the tunnel opens (200) and the listener closes it; curl's TLS handshake then fails, which is not part of the test
[ "$(via "$upstream" -U "smoke-agent:$secret")" = 200 ] || fail "the destination the policy permits ($upstream) was not relayed with 200"
# Each receipt as "<destination> <status>[ <reason>]". The relay is receipted when its tunnel closes, so wait for it.
receipts() {
  docker exec "$ename" node -e '
    const fs = require("fs"), dir = "/data/receipts";
    for (const f of fs.readdirSync(dir).filter((f) => f.endsWith(".json") && !f.endsWith(".authorization.json"))) {
      const b = JSON.parse(fs.readFileSync(`${dir}/${f}`, "utf8"));
      const p = JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()).predicate;
      console.log([p.tool.name, p.execution.status, p.execution.reason].filter(Boolean).join(" "));
    }'
}
i=0
until receipts | grep -qx "$upstream executed"; do
  i=$((i + 1)); [ "$i" -le 10 ] || fail "no executed receipt for $upstream; receipts: $(receipts | tr '\n' ',')"
  sleep 1
done
# the 407 is receipted as denied too, so require the 403's own reason
receipts | grep -qx "api.stripe.com:443 denied no permit policy matched" || fail "no receipt of the policy refusing api.stripe.com:443; receipts: $(receipts | tr '\n' ',')"
docker stop "$ename" > /dev/null
code=$(docker inspect -f '{{.State.ExitCode}}' "$ename")
[ "$code" = 0 ] || fail "the witness stopped with exit code $code, not 0"
echo "smoke: ok (egress mode: key created, healthy, 407 without a credential, 403 and a policy-refusal receipt for a refused destination, 200 and an executed receipt for a permitted one, stopped with exit 0)"
