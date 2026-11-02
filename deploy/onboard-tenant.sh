#!/bin/sh
# Onboards one tenant on this log server: creates the tenant and its first token, writes the token to a file only
# root can read, and prints the welcome sheet to hand to the tenant. Run on the server, in deploy/.
#
#   ./onboard-tenant.sh <tenant-id> [--log-id <id>] [--label <fleet name>]
#
# The tenant id is what appears in their URL, /t/<tenant-id>/. The log id is what their tree heads name and what
# their verifiers pass as --log-id; it defaults to the tenant id. The label names the fleet the token is for.
set -eu

tenant=""; log_id=""; label="first fleet"
while [ $# -gt 0 ]; do
  case "$1" in
    --log-id) log_id="$2"; shift 2 ;;
    --label) label="$2"; shift 2 ;;
    -*) echo "unknown option $1" >&2; exit 2 ;;
    *) tenant="$1"; shift ;;
  esac
done
[ -n "$tenant" ] || { echo "usage: $0 <tenant-id> [--log-id <id>] [--label <fleet name>]" >&2; exit 2; }
[ -n "$log_id" ] || log_id="$tenant"

env_file="$(dirname "$0")/.env"
log_host=$(grep '^LOG_HOST=' "$env_file" | cut -d= -f2)
cp_host=$(grep '^CHECKPOINTS_HOST=' "$env_file" | cut -d= -f2)
[ -n "$log_host" ] || { echo "LOG_HOST is not set in $env_file" >&2; exit 1; }

admin() { docker compose -f "$(dirname "$0")/docker-compose.yaml" exec -T log agent-custody log-admin --db-env DATABASE_URL "$@"; }

admin tenant add "$tenant" --log-id "$log_id" >&2
token=$(admin token add "$tenant" --label "$label" 2>/dev/null)
[ -n "$token" ] || { echo "token was not created" >&2; exit 1; }

store="/root/agent-custody-tenants"
mkdir -p "$store"; chmod 700 "$store"
umask 077
printf '%s\n' "$token" > "$store/$tenant.token"
keys=$(curl -sf "https://$log_host/.well-known/agent-custody-log.json" || echo '{}')
keyid=$(printf '%s' "$keys" | sed -n 's/.*"keyid":"\([0-9a-f]*\)".*/\1/p' | head -1)

cat <<EOF

================================================================================
agent-custody log: welcome sheet for tenant "$tenant"
================================================================================

Your log            https://$log_host/t/$tenant/
Your log id         $log_id
Your checkpoints    https://$cp_host/$tenant/latest.json
The log's keys      https://$log_host/.well-known/agent-custody-log.json  (current keyid ${keyid:-see the document})

Your token is in $store/$tenant.token on this server. Hand it over once, by a channel you trust; it is stored here
only as a hash and cannot be recovered, only replaced (log-admin token add / token revoke).

--- In your gateway or SDK config ---------------------------------------------

  "log": { "url": "https://$log_host/t/$tenant/", "tokenEnv": "AGENT_CUSTODY_LOG_TOKEN", "hashOnly": true }

hashOnly means this log never receives your receipts, only their hashes. Your receipts stay in your receiptsDir.

--- For whoever verifies your receipts ----------------------------------------

  npx @agent-custody/receipts verify receipts/<id>.json --issuer-key <your gateway.pub> --principal-key <your principal.pub> \\
      --log-url https://$log_host/t/$tenant/ --log-id $log_id

  npx @agent-custody/receipts audit --older receipts/<earlier>.json --newer receipts/<later>.json \\
      --log-url https://$log_host/t/$tenant/ --log-id $log_id

--log-url fetches this log's published keys and pins them; --log-id makes sure the tree heads are this log's.
An auditor who keeps any signed tree head can later fetch a newer checkpoint from your checkpoints URL and audit
between the two, which proves nothing before it was rewritten.

--- What this log does not do -------------------------------------------------

It holds no receipt contents, only hashes. It cannot forge a receipt: those are signed by your gateway key.
It is one signer today; a second, independent witness is the next step. Ask for the proof table at
https://agent-custody.dev/receipts/#what-a-receipt-proves-and-what-it-does-not before repeating any claim.
================================================================================
EOF
