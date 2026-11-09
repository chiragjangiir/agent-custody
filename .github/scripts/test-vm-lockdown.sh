#!/bin/sh
# End-to-end test of the VM egress lockdown (deploy/gateway/lockdown/vm) on a throwaway Linux host with systemd: installs
# the gateway, the witness, a stand-in upstream, and a stand-in agent as the file headers describe, then runs
# check-lockdown.sh with no lockdown (which must fail), with the whole recipe, and with the systemd drop-in alone. It also
# checks that loading the table leaves another table alone, that a reload or a start of nftables.service (which flushes
# the ruleset) is followed by the table, that the agent stays down when the table fails to load, that the agent gets no
# answer from the DNS resolver, that the agent's unit refuses vsock, and that the witness refuses a private address its
# policy permits.
# It starts nftables.service, which flushes the host's ruleset (docker's included): run it on a throwaway host only.
# Usage: sudo test-vm-lockdown.sh <@agent-custody/receipts tarball>     needs node 22, nft, curl, python3, openssl
set -eu
pkg="${1:?usage: test-vm-lockdown.sh <package tarball>}"
here=$(cd "$(dirname "$0")/../.." && pwd)
gw="$here/deploy/gateway"
vm="$gw/lockdown/vm"
fail() { echo "test-vm-lockdown: FAIL: $*" >&2; journalctl -u agent-custody-gateway -u agent-custody-egress --no-pager -n 40 >&2 || true; exit 1; }

# into /usr/local, where the units find it on systemd's PATH
npm install -g --silent --prefix /usr/local "$pkg"
[ -x /usr/local/bin/agent-custody ] || fail "npm install -g put no agent-custody in /usr/local/bin"

# the gateway, with one REST tool whose upstream is a stand-in on loopback
id custody > /dev/null 2>&1 || useradd --system --home /var/lib/agent-custody --create-home custody
install -d -o custody -g custody /var/lib/agent-custody/keys
runuser -u custody -- agent-custody keygen --dir /var/lib/agent-custody/keys --name gateway > /dev/null
install -d /etc/agent-custody/keys
work=$(mktemp -d)
agent-custody keygen --dir "$work" --name principal > /dev/null
cp "$work/principal.pub" /etc/agent-custody/keys/principal.pub
echo 'permit(principal, action == Action::"example.lookup", resource);' > /etc/agent-custody/policy.cedar
cat > /etc/agent-custody/gateway.json << 'CONFIG'
{
  "identity": { "keyFile": "/var/lib/agent-custody/keys/gateway.key" },
  "upstream": { "rest": { "baseUrl": "http://127.0.0.1:9000", "tools": [{ "name": "example.lookup", "method": "GET", "path": "/v1/items/{id}", "inputSchema": { "type": "object", "properties": { "id": { "type": "string" } }, "required": ["id"] } }] } },
  "trustedPrincipalKeys": ["keys/principal.pub"],
  "policyFile": "policy.cedar",
  "receiptsDir": "/var/lib/agent-custody/receipts",
  "logFile": "/var/lib/agent-custody/log.jsonl"
}
CONFIG
install -m 0600 /dev/null /etc/agent-custody/gateway.env
cp "$gw/agent-custody-gateway.service" /etc/systemd/system/
mkdir -p /srv/upstream/v1/items
echo '{"id":"1"}' > /srv/upstream/v1/items/1
systemd-run --quiet --unit upstream-demo -p User=nobody python3 -m http.server 9000 --bind 127.0.0.1 --directory /srv/upstream

# the witness, with the shipped starter config
id custody-egress > /dev/null 2>&1 || useradd --system --home /var/lib/agent-custody-egress --create-home --shell /usr/sbin/nologin custody-egress
install -d /etc/agent-custody/egress
cp "$gw/lockdown/config/egress.json" "$gw/lockdown/config/egress-policy.cedar" /etc/agent-custody/egress/
secret=$(openssl rand -hex 32)
install -m 0600 /dev/null /etc/agent-custody/egress.env
echo "EGRESS_SECRET_RESEARCH_AGENT=$secret" > /etc/agent-custody/egress.env
install -d -o custody-egress -g custody-egress /var/lib/agent-custody-egress/keys
runuser -u custody-egress -- agent-custody keygen --dir /var/lib/agent-custody-egress/keys --name egress > /dev/null
cp "$vm/agent-custody-egress.service" /etc/systemd/system/
# the witness's unit denies the private ranges; a resolver off loopback (OrbStack's is in 0.0.0.0/8) needs its allow
resolver=$(awk '/^nameserver/ { print $2; exit }' /etc/resolv.conf)
case "$resolver" in
  127.*) ;;
  *) install -d /etc/systemd/system/agent-custody-egress.service.d
     printf '[Service]\nIPAddressAllow=%s\n' "$resolver" > /etc/systemd/system/agent-custody-egress.service.d/resolver.conf ;;
esac
systemctl daemon-reload
systemctl start agent-custody-gateway agent-custody-egress

# the agent: its user, the nftables rule as shipped, and a service with the drop-in
id agent > /dev/null 2>&1 || useradd --system --home /var/lib/agent --create-home --shell /usr/sbin/nologin agent
install -m 0644 "$vm/agent-lockdown.nft" /etc/agent-custody/agent-lockdown.nft
nft -c -f /etc/agent-custody/agent-lockdown.nft
printf '[Service]\nExecStart=/bin/sleep infinity\n' > /etc/systemd/system/demo-agent.service
install -d /etc/systemd/system/demo-agent.service.d
cp "$vm/agent-lockdown.conf" /etc/systemd/system/demo-agent.service.d/lockdown.conf
# the agent's settings, as the drop-in's header lists them; check-lockdown.sh reads the proxy secret from here
install -m 0600 /dev/null /etc/agent-custody/agent.env
cat > /etc/agent-custody/agent.env << ENV
HTTPS_PROXY=http://research-agent:$secret@127.0.0.1:8791
HTTP_PROXY=http://research-agent:$secret@127.0.0.1:8791
NO_PROXY=127.0.0.1
NODE_USE_ENV_PROXY=1
AGENT_CUSTODY_GATEWAY_URL=http://127.0.0.1:8790/mcp
ENV
cp "$vm/agent-custody-lockdown.service" /etc/systemd/system/
install -D -m 0644 "$vm/nftables-lockdown.conf" /etc/systemd/system/nftables.service.d/agent-custody-lockdown.conf
systemctl daemon-reload

i=0
until curl -fsS http://127.0.0.1:8790/health > /dev/null 2>&1 && curl -fsS http://127.0.0.1:8791/.well-known/agent-custody-egress > /dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -le 30 ] || fail "the gateway or the witness did not come up"
  sleep 1
done

echo "== no lockdown: the checks must fail"
if "$vm/check-lockdown.sh"; then fail "check-lockdown.sh passed with no lockdown in place"; fi
echo "== the whole recipe: starting the agent loads the table, and leaves another table alone"
nft add table inet another_firewall
systemctl start demo-agent
systemctl is-active --quiet agent-custody-lockdown || fail "starting the agent did not start agent-custody-lockdown"
nft list table inet another_firewall > /dev/null || fail "loading the lockdown deleted another table"
"$vm/check-lockdown.sh"
"$vm/check-lockdown.sh" --unit demo-agent.service
echo "== the systemd drop-in alone"
nft delete table inet agent_custody_lockdown
if "$vm/check-lockdown.sh" --unit demo-agent.service; then fail "check-lockdown.sh passed with the table missing"; fi
printf '%s\n' "$secret" > "$work/secret"
PROBE_PORT='' EGRESS_SECRET_FILE="$work/secret" "$vm/check-lockdown.sh" --unit demo-agent.service
systemctl restart agent-custody-lockdown

table() { nft list table inet agent_custody_lockdown > /dev/null 2>&1; }
echo "== nftables.service: a start from inactive and a reload flush the ruleset; the table must come back"
systemctl is-active --quiet nftables && systemctl stop nftables
systemctl start demo-agent
systemctl start nftables
table || fail "a start of nftables.service left the table missing"
systemctl reload nftables
table || fail "a reload of nftables.service left the table missing"
systemctl is-active --quiet demo-agent || fail "the agent stopped across a reload of nftables.service"
"$vm/check-lockdown.sh"
echo "test-vm-lockdown: the table survived a start and a reload of nftables.service"

echo "== a table that fails to load keeps the agent down, at its start and at a reload of nftables.service"
cp /etc/agent-custody/agent-lockdown.nft "$work/agent-lockdown.nft"
sed -i 's/^define AGENT_USERS = { agent }/define AGENT_USERS = { no-such-user }/' /etc/agent-custody/agent-lockdown.nft
systemctl reload nftables
i=0
while systemctl is-active --quiet demo-agent; do
  i=$((i + 1)); [ "$i" -le 10 ] || fail "the agent kept running after a reload of nftables.service could not load its table"
  sleep 1
done
systemctl reset-failed agent-custody-lockdown 2> /dev/null || true
if systemctl start demo-agent 2> /dev/null; then fail "the agent started although its firewall table did not load"; fi
systemctl is-active --quiet demo-agent && fail "the agent is running although its firewall table did not load"
echo "test-vm-lockdown: the agent stayed down when the table failed to load"
cp "$work/agent-lockdown.nft" /etc/agent-custody/agent-lockdown.nft
systemctl reset-failed agent-custody-lockdown 2> /dev/null || true
systemctl start demo-agent
"$vm/check-lockdown.sh" --unit demo-agent.service

echo "== DNS over IP is closed to the agent: a query to this host's resolver gets no answer"
dns='import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5); s.connect((sys.argv[1], 53))
s.send(bytes.fromhex("123401000001000000000000076578616d706c6503636f6d0000010001")); s.recv(512)'
python3 -c "$dns" "$resolver" || fail "cannot tell: root gets no answer from the resolver $resolver either"
if runuser -u agent -- python3 -c "$dns" "$resolver" 2> /dev/null; then fail "the agent got an answer from the resolver $resolver"; fi
echo "test-vm-lockdown: the resolver $resolver answered root and not the agent"

echo "== the agent's unit refuses vsock"
families=$(systemctl show -P RestrictAddressFamilies demo-agent)
vsock="import socket; socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)"
if runuser -u agent -- python3 -c "$vsock" 2> /dev/null; then
  if systemd-run --quiet --wait --pipe --collect --uid=agent -p "RestrictAddressFamilies=$families" python3 -c "$vsock" 2> /dev/null; then
    fail "the agent's unit can open a vsock socket"
  fi
  echo "test-vm-lockdown: vsock opens for the agent user, and not in the agent's unit"
else
  echo "test-vm-lockdown: skipped vsock: this kernel has no vsock for the agent user to open"
fi

echo "== the witness refuses a private address that its policy permits"
ip addr add 10.255.255.1/32 dev lo
mkdir -p /srv/private
echo ok > /srv/private/index.html
systemd-run --quiet --unit private-demo -p User=nobody python3 -m http.server 8080 --bind 10.255.255.1 --directory /srv/private
echo 'permit(principal == Agent::"research-agent", action == Action::"10.255.255.1:8080", resource);' >> /etc/agent-custody/egress/egress-policy.cedar
private() {
  printf 'proxy-user = "research-agent:%s"\n' "$secret" \
    | runuser -u agent -- curl -s -m 15 -o /dev/null -w '%{http_code}' -K - -x http://127.0.0.1:8791 http://10.255.255.1:8080/
}
witness_up() {
  i=0
  until curl -fsS http://127.0.0.1:8791/.well-known/agent-custody-egress > /dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -le 30 ] || fail "the witness did not come back"
    sleep 1
  done
}
systemctl restart agent-custody-egress
witness_up
[ "$(curl -s -m 5 http://10.255.255.1:8080/)" = ok ] || fail "cannot tell: root cannot reach the private listener"
code=$(private)
[ "$code" != 200 ] || fail "the witness relayed to 10.255.255.1:8080 although its unit denies 10.0.0.0/8"
# the control: without the unit's deny list the same permit is relayed, so the deny list is what refused it
install -d /etc/systemd/system/agent-custody-egress.service.d
printf '[Service]\nIPAddressDeny=\n' > /etc/systemd/system/agent-custody-egress.service.d/zz-no-deny.conf
systemctl daemon-reload
systemctl restart agent-custody-egress
witness_up
[ "$(private)" = 200 ] || fail "cannot tell: the witness did not relay to the private listener even without the deny list"
echo "test-vm-lockdown: the witness answered $code for a permitted 10.255.255.1:8080 under its unit, 200 without the deny list"
echo "test-vm-lockdown: ok"
