#!/bin/sh
# serve (default): starts the shared gateway on 0.0.0.0, creating the gateway key on first start.
# console: starts the admin console for that gateway (token from CONSOLE_TOKEN), as a separate container of this image.
# egress: starts the egress witness on 0.0.0.0, creating its key on first start; extra arguments replace the defaults.
# init: writes a starter config, an example policy, and a demo principal key and grant into /config.
# Anything else is passed to the agent-custody CLI, so `docker exec <container> revoke --config ... --grant ...` works.
# Every command but egress refuses to run with an EGRESS_SECRET_* variable in its environment (below).
set -eu

: "${DATA_DIR:=/data}"
: "${GATEWAY_CONFIG:=/config/gateway.json}"
: "${GATEWAY_KEY:=$DATA_DIR/keys/gateway.key}"
: "${GATEWAY_PORT:=8790}"
: "${GATEWAY_IDLE_MINUTES:=30}"
: "${EGRESS_CONFIG:=/config/egress.json}"
: "${EGRESS_KEY:=$DATA_DIR/keys/egress.key}"
: "${EGRESS_PORT:=8791}"
config_dir=$(dirname "$GATEWAY_CONFIG")

# An agent's proxy secret for the egress witness (left in .env, which the gateway, the console and init load) would let
# that process connect through the witness as the agent. Every command but egress, the one that must hold the secrets,
# refuses to run with one. Names only: the value never goes to the log. `docker exec` does not pass through here; in a
# running gateway container, serve has already refused.
if [ "${1:-serve}" != egress ]; then
  leftover=$(env | sed -n 's/^\(EGRESS_SECRET_[A-Za-z0-9_]*\)=.*/\1/p' | tr '\n' ' ')
  if [ -n "$leftover" ]; then
    echo "gateway: ${leftover}is in this container's environment, so '${1:-serve}' is not running. A proxy secret belongs only to the egress witness and its agent: move it from .env to lockdown/agents/<agent>.env" >&2
    exit 1
  fi
fi

case "${1:-serve}" in
  serve)
    if [ ! -f "$GATEWAY_CONFIG" ]; then
      echo "gateway: $GATEWAY_CONFIG not found. Mount your config at $config_dir, or write a starter one with: init" >&2
      exit 1
    fi
    if [ ! -f "$GATEWAY_KEY" ]; then
      key_dir=$(dirname "$GATEWAY_KEY"); key_name=$(basename "$GATEWAY_KEY" .key)
      mkdir -p "$key_dir"
      agent-custody keygen --dir "$key_dir" --name "$key_name" >&2
      echo "gateway: created the gateway key. Verifiers check receipts with its public key:" >&2
      cat "$key_dir/$key_name.pub" >&2
    fi
    # GATEWAY_CHECK=strict (the default) refuses to start on a config the check calls an error, advisory prints the findings
    # and starts anyway, off skips the check
    case "${GATEWAY_CHECK:-strict}" in
      off) ;;
      advisory) agent-custody check --config "$GATEWAY_CONFIG" >&2 || echo "gateway: the config check found errors; starting anyway (GATEWAY_CHECK=advisory)" >&2 ;;
      strict) agent-custody check --config "$GATEWAY_CONFIG" >&2 || { echo "gateway: the config check found errors, so the gateway is not starting. Fix them, or set GATEWAY_CHECK=advisory to start anyway" >&2; exit 1; } ;;
      *) echo "gateway: GATEWAY_CHECK must be strict, advisory, or off" >&2; exit 1 ;;
    esac
    exec agent-custody gateway --config "$GATEWAY_CONFIG" --http --host 0.0.0.0 --port "$GATEWAY_PORT" --idle-minutes "$GATEWAY_IDLE_MINUTES"
    ;;
  egress)
    # the egress witness: the same image, a container of its own that holds only the agents' proxy secrets, never a tool
    # credential. Its key is not the gateway's: verifiers trust it separately. The key is created at EGRESS_KEY and the
    # healthcheck probes EGRESS_PORT, so a config whose identity.keyFile differs, or your own arguments, need both set to match.
    shift
    if [ "$#" -eq 0 ] && [ ! -f "$EGRESS_CONFIG" ]; then
      echo "gateway: $EGRESS_CONFIG not found. Mount the witness config there, or set EGRESS_CONFIG" >&2
      exit 1
    fi
    if [ ! -f "$EGRESS_KEY" ]; then
      key_dir=$(dirname "$EGRESS_KEY"); key_name=$(basename "$EGRESS_KEY" .key)
      mkdir -p "$key_dir"
      agent-custody keygen --dir "$key_dir" --name "$key_name" >&2
      echo "gateway: created the egress witness key. Verifiers check its receipts with its public key:" >&2
      cat "$key_dir/$key_name.pub" >&2
    fi
    if [ "$#" -gt 0 ]; then exec agent-custody egress "$@"; fi
    exec agent-custody egress --config "$EGRESS_CONFIG" --host 0.0.0.0 --port "$EGRESS_PORT"
    ;;
  console)
    # the admin console, as a service of its own: the same image, the same config and data, and a token kept in a file that
    # only this container is given (a container secret, /run/secrets/console_token) or, for a plain host, CONSOLE_TOKEN
    token_file="${CONSOLE_TOKEN_FILE:-/run/secrets/console_token}"
    if [ ! -f "$token_file" ] && [ -z "${CONSOLE_TOKEN:-}" ]; then
      echo "gateway: console needs a token: a file at $token_file (a container secret), or CONSOLE_TOKEN in the environment (openssl rand -hex 32)" >&2
      exit 1
    fi
    if [ ! -f "$GATEWAY_CONFIG" ]; then
      echo "gateway: $GATEWAY_CONFIG not found. The console reads the gateway's config; mount it at $config_dir" >&2
      exit 1
    fi
    if [ -f "$token_file" ]; then
      exec agent-custody console --config "$GATEWAY_CONFIG" --host 0.0.0.0 --port "${CONSOLE_PORT:-8795}" --token-file "$token_file" ${GATEWAY_URL:+--gateway-url "$GATEWAY_URL"}
    fi
    exec agent-custody console --config "$GATEWAY_CONFIG" --host 0.0.0.0 --port "${CONSOLE_PORT:-8795}" ${GATEWAY_URL:+--gateway-url "$GATEWAY_URL"}
    ;;
  init)
    if [ -e "$GATEWAY_CONFIG" ]; then
      echo "gateway: $GATEWAY_CONFIG already exists; init writes only into an empty config directory" >&2
      exit 1
    fi
    mkdir -p "$config_dir/keys" "$config_dir/demo"
    agent-custody keygen --dir "$config_dir/demo" --name principal >&2
    cp "$config_dir/demo/principal.pub" "$config_dir/keys/principal.pub"
    cat > "$config_dir/policy.cedar" <<'POLICY'
// Starter policy: the demo agent may read items. Everything else is denied (Cedar denies by default).
// Amounts are integer minor units; context.args is what the agent sent, context.facts is what the gateway fetched.
permit(principal, action == Action::"example.lookup", resource);
POLICY
    cat > "$GATEWAY_CONFIG" <<CONFIG
{
  "identity": { "keyFile": "$GATEWAY_KEY" },
  "upstream": {
    "rest": {
      "baseUrl": "https://api.example.com",
      "tools": [{ "name": "example.lookup", "method": "GET", "path": "/v1/items/{id}", "inputSchema": { "type": "object", "properties": { "id": { "type": "string" } }, "required": ["id"] } }]
    }
  },
  "trustedPrincipalKeys": ["keys/principal.pub"],
  "policyFile": "policy.cedar",
  "precommit": ["*"],
  "receiptsDir": "$DATA_DIR/receipts",
  "logFile": "$DATA_DIR/log.jsonl",
  "revokedGrants": "$DATA_DIR/revoked.json"
}
CONFIG
    agent-custody grant --key "$config_dir/demo/principal.key" --principal demo-admin --agent demo-agent --scopes example.lookup --ttl-hours 24 --out "$config_dir/demo/grant.json" >&2
    cat >&2 <<NEXT
gateway: wrote a starter config in $config_dir

  gateway.json         edit the upstream: your API's base URL and its tools. Add a credential with
                       "headerEnv": { "authorization": "MY_API_TOKEN" } and set MY_API_TOKEN in the gateway's environment
  policy.cedar         the rules; applied from the next call when written by rename
  keys/principal.pub   the public key the gateway trusts to sign grants
  demo/                a DEMO principal key and a 24-hour grant. Delete this directory in production: the principal's
                       private key must never sit on the gateway host. Issue real grants with agent-custody grant.

An agent presents its grant on connection, as the base64url of the grant file:

  Authorization: Bearer \$(base64 < demo/grant.json | tr -d '\n=' | tr '+/' '-_')

NEXT
    ;;
  *)
    exec agent-custody "$@"
    ;;
esac
