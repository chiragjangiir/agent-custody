#!/bin/sh
# The three lockdown checks from the guide, for an agent on a VM or bare metal, and a fourth for this recipe. Run it on
# the agent's host, as root, once the gateway, the witness, and agent-lockdown.nft are in place. Each probe runs as the
# agent user. With --unit it runs in a transient unit with the IP filter of the agent's service, so it also tests
# agent-lockdown.conf.
#
#   1. a direct connection that ignores the proxy fails to connect, where the same connection made as root succeeds;
#   2. a connection through the witness to a host the policy does not permit gets 403, and the witness writes a receipt
#      that names that host and says denied;
#   3. the gateway answers the agent;
#   4. another port on loopback, over IPv4 and IPv6, is closed to the agent, where root reaches it. The script opens that
#      port itself. The drop-in alone passes 1 to 3 but fails this, since it allows every port on 127.0.0.1.
#
# Usage: sudo ./check-lockdown.sh [--unit <agent>.service]
# The agent's proxy id and secret come from HTTPS_PROXY in AGENT_ENV (/etc/agent-custody/agent.env, the file the drop-in
# loads), or the secret from the first line of EGRESS_SECRET_FILE. Do not pass it as EGRESS_SECRET=... on the command
# line: ps and the shell history show it there. EGRESS_SECRET in the environment is still read first.
# Settings (environment): AGENT_USER (agent), AGENT_ID (the id in HTTPS_PROXY, else research-agent),
# GATEWAY (127.0.0.1:8790), WITNESS (127.0.0.1:8791), RECEIPTS_DIR (/var/lib/agent-custody-egress/receipts),
# REFUSED_HOST (example.net, a host the policy must not permit), DIRECT_HOST (example.com, a host root can reach),
# PROBE_PORT (18799, a free port; set it empty only to test the drop-in alone). Needs curl, getent, base64, python3,
# runuser, and systemd-run with --unit.
set -eu

fail() { echo "check-lockdown: FAIL: $*" >&2; exit 1; }
: "${AGENT_ENV:=/etc/agent-custody/agent.env}"
if [ -z "${EGRESS_SECRET:-}" ]; then
  if [ -n "${EGRESS_SECRET_FILE:-}" ]; then
    EGRESS_SECRET=$(head -n 1 "$EGRESS_SECRET_FILE" | tr -d '\r\n') || fail "cannot read $EGRESS_SECRET_FILE"
  elif [ -r "$AGENT_ENV" ]; then
    # HTTPS_PROXY=http://<id>:<secret>@host:port, quoted or not
    proxy=$(sed -n 's/^[[:space:]]*HTTPS_PROXY=//p' "$AGENT_ENV" | head -n 1 | tr -d "\"'")
    case "$proxy" in
      *://*:*@*)
        userinfo=${proxy#*://}
        userinfo=${userinfo%@*}
        EGRESS_SECRET=${userinfo#*:}
        : "${AGENT_ID:=${userinfo%%:*}}" ;;
    esac
  fi
fi
[ -n "${EGRESS_SECRET:-}" ] || fail "no proxy secret: put HTTPS_PROXY=http://<id>:<secret>@<witness> in $AGENT_ENV, or set EGRESS_SECRET_FILE"
: "${AGENT_USER:=agent}"
: "${AGENT_ID:=research-agent}"
: "${GATEWAY:=127.0.0.1:8790}"
: "${WITNESS:=127.0.0.1:8791}"
: "${RECEIPTS_DIR:=/var/lib/agent-custody-egress/receipts}"
: "${REFUSED_HOST:=example.net}"
: "${DIRECT_HOST:=example.com}"
PROBE_PORT="${PROBE_PORT-18799}"

unit=""
if [ "${1:-}" = --unit ]; then unit="${2:?--unit needs the agent service name}"; fi

work=$(mktemp -d)
listener=""
cleanup() { [ -z "$listener" ] || kill "$listener" 2> /dev/null || true; rm -rf "$work"; }
trap cleanup EXIT
[ "$(id -u)" = 0 ] || fail "run as root, so the probes can run as $AGENT_USER"
id "$AGENT_USER" > /dev/null 2>&1 || fail "no user $AGENT_USER"

# as_agent <command...>: runs the command as the agent user, inside the agent unit's IP filter when --unit is given
if [ -n "$unit" ]; then
  deny=$(systemctl show -P IPAddressDeny "$unit")
  allow=$(systemctl show -P IPAddressAllow "$unit")
  families=$(systemctl show -P RestrictAddressFamilies "$unit")
  [ -n "$deny" ] || fail "$unit has no IPAddressDeny; is the drop-in installed and systemd reloaded?"
  as_agent() {
    systemd-run --quiet --wait --pipe --collect --uid="$AGENT_USER" -p NoNewPrivileges=true -p "IPAddressDeny=$deny" \
      -p "IPAddressAllow=$allow" ${families:+-p "RestrictAddressFamilies=$families"} "$@"
  }
else
  as_agent() { runuser -u "$AGENT_USER" -- "$@"; }
fi

# 1. Direct. The address is looked up here, as root, so a refused DNS query cannot pass for a refused connection.
addr=$(getent ahostsv4 "$DIRECT_HOST" | awk 'NR == 1 { print $1 }')
[ -n "$addr" ] || fail "could not resolve $DIRECT_HOST on this host"
# The control, as root: on a host with no route out, the agent's probe fails whether or not it is locked down.
out=$(env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy \
  curl -sS -m 10 -o /dev/null --noproxy '*' --resolve "$DIRECT_HOST:443:$addr" "https://$DIRECT_HOST/" 2>&1) || fail "cannot tell: root cannot reach $DIRECT_HOST ($addr:443) directly either ($out). Set DIRECT_HOST to a host this machine reaches"
set +e
out=$(as_agent env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy \
  curl -sS -m 10 -o /dev/null --noproxy '*' --resolve "$DIRECT_HOST:443:$addr" "https://$DIRECT_HOST/" 2>&1)
code=$?
set -e
# 7 is curl's "could not connect": refused by the firewall. 28, a timeout, means a drop somewhere, still no connection.
case "$code" in
  7 | 28) echo "check-lockdown: ok 1/4: a direct connection to $DIRECT_HOST ($addr:443) failed for $AGENT_USER and succeeded for root: $out" ;;
  0) fail "a direct connection to $DIRECT_HOST ($addr:443) succeeded: the agent is not locked down" ;;
  *) fail "a direct connection to $DIRECT_HOST failed with curl exit $code, not a refused connection: $out" ;;
esac

# 2. Through the witness. The proxy credential goes to curl on stdin, never on a command line that ps shows.
touch "$work/before"
set +e
connect=$(printf 'proxy-user = "%s:%s"\n' "$AGENT_ID" "$EGRESS_SECRET" \
  | as_agent curl -s -m 15 -o /dev/null -w '%{http_connect}' -K - -x "http://$WITNESS" "https://$REFUSED_HOST/")
set -e
[ "$connect" = 403 ] || fail "the witness answered CONNECT $REFUSED_HOST:443 with '$connect', not 403 (407 is a wrong secret; 000 is no answer)"
# The witness signs the receipt as it refuses. Find the new one that names the refused host and says denied.
receipt=""
i=0
while [ -z "$receipt" ]; do
  find "$RECEIPTS_DIR" -maxdepth 1 -name '*.json' -newer "$work/before" > "$work/new" 2> /dev/null || true
  while IFS= read -r f; do
    statement=$(sed -n 's/.*"payload": *"\([^"]*\)".*/\1/p' "$f" | base64 -d 2> /dev/null) || continue
    case "$statement" in
      *"\"tool\":{\"name\":\"$REFUSED_HOST:443\""*) ;;
      *) continue ;;
    esac
    case "$statement" in
      *'"status":"denied"'*) receipt="$f"; break ;;
      *) fail "the receipt $f for $REFUSED_HOST:443 does not say denied" ;;
    esac
  done < "$work/new"
  [ -n "$receipt" ] && break
  i=$((i + 1)); [ "$i" -le 5 ] || fail "the witness refused $REFUSED_HOST but wrote no receipt naming $REFUSED_HOST:443 in $RECEIPTS_DIR"
  sleep 1
done
echo "check-lockdown: ok 2/4: CONNECT $REFUSED_HOST:443 through the witness got 403 and a receipt for it, status denied ($receipt)"

# 3. The gateway.
health=$(as_agent curl -sS -m 10 "http://$GATEWAY/health" 2>&1) || fail "the agent cannot reach the gateway at $GATEWAY: $health"
case "$health" in
  *'"ok":true'*) echo "check-lockdown: ok 3/4: the gateway at $GATEWAY answered the agent: $health" ;;
  *) fail "the gateway at $GATEWAY did not answer ok: $health" ;;
esac

# 4. Loopback beyond the gateway and the witness. A listener of our own on PROBE_PORT, on both 127.0.0.1 and ::1.
if [ -z "$PROBE_PORT" ]; then
  echo "check-lockdown: skipped 4/4: PROBE_PORT is empty, so other ports on loopback were not probed"
  exit 0
fi
runuser -u nobody -- python3 -m http.server "$PROBE_PORT" --bind :: --directory "$work" > /dev/null 2>&1 &
listener=$!
i=0
until curl -s -o /dev/null --noproxy '*' "http://127.0.0.1:$PROBE_PORT/"; do
  i=$((i + 1)); [ "$i" -le 10 ] || fail "cannot tell: no listener came up on 127.0.0.1:$PROBE_PORT (is the port free, is python3 installed?)"
  sleep 1
done
probed="127.0.0.1"
targets="127.0.0.1"
if curl -s -o /dev/null --noproxy '*' "http://[::1]:$PROBE_PORT/"; then targets="$targets [::1]"; probed="127.0.0.1 and ::1"; fi
for host in $targets; do
  set +e
  out=$(as_agent curl -sS -m 10 -o /dev/null --noproxy '*' "http://$host:$PROBE_PORT/" 2>&1)
  code=$?
  set -e
  case "$code" in
    7 | 28) ;;
    0) fail "the agent reached $host:$PROBE_PORT, a loopback port other than the gateway and the witness: the nftables table is missing or too wide" ;;
    *) fail "the probe of $host:$PROBE_PORT failed with curl exit $code, not a refused connection: $out" ;;
  esac
done
case "$probed" in *::1*) ;; *) probed="$probed (root cannot reach ::1, so IPv6 loopback was not probed)" ;; esac
echo "check-lockdown: ok 4/4: port $PROBE_PORT on $probed refused the agent and answered root"
