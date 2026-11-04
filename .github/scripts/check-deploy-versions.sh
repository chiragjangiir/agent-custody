#!/usr/bin/env bash
# Fails unless every version the deploy files and the monitor name is the given release version, so a release never
# ships a compose file, a manifest, or a monitor that still names the previous one. The action's default may name the
# next release, because the action is merged before the release that carries its commands, so it may not be older.
set -u

version=${1:?usage: check-deploy-versions.sh <version>}
status=0
expect() {
  local file=$1 pattern=$2 found
  found=$(grep -oE "$pattern" "$file" | sed -E 's/.*[:=@" -]([0-9]+\.[0-9]+\.[0-9]+)"?$/\1/' | sort -u)
  if [ -z "$found" ]; then echo "$file: no version found for $pattern"; status=1; return; fi
  for v in $found; do
    if [ "$v" != "$version" ]; then echo "$file names $v, the release is $version"; status=1; fi
  done
}

at_least() {
  local file=$1 pattern=$2 found v
  found=$(grep -oE "$pattern" "$file" | sed -E 's/.*[: ]([0-9]+\.[0-9]+\.[0-9]+)$/\1/' | sort -u)
  if [ -z "$found" ]; then echo "$file: no version found for $pattern"; status=1; return; fi
  for v in $found; do
    if [ "$(printf '%s\n%s\n' "$version" "$v" | sort -t. -k1,1n -k2,2n -k3,3n | head -n 1)" != "$version" ]; then
      echo "$file names $v, which is older than the release $version"; status=1
    fi
  done
}

expect deploy/docker-compose.yaml 'AGENT_CUSTODY_VERSION:-[0-9]+\.[0-9]+\.[0-9]+'
expect deploy/witness/docker-compose.yaml 'AGENT_CUSTODY_VERSION:-[0-9]+\.[0-9]+\.[0-9]+'
expect deploy/Dockerfile 'ARG AGENT_CUSTODY_VERSION=[0-9]+\.[0-9]+\.[0-9]+'
expect deploy/.env.example '^AGENT_CUSTODY_VERSION=[0-9]+\.[0-9]+\.[0-9]+'
expect deploy/witness/.env.example '^AGENT_CUSTODY_VERSION=[0-9]+\.[0-9]+\.[0-9]+'
expect deploy/k8s/kustomization.yaml 'newTag: "[0-9]+\.[0-9]+\.[0-9]+"'
expect .github/workflows/monitor.yml '@agent-custody/receipts@[0-9]+\.[0-9]+\.[0-9]+'
at_least action.yml '^    default: [0-9]+\.[0-9]+\.[0-9]+$'
# the gateway files have no default version: a moving tag there would ship whatever was built last
if grep -nE ':-latest|:-edge|newTag: "?(latest|edge)' deploy/gateway/docker-compose.yaml deploy/gateway/.env.example deploy/gateway/k8s/kustomization.yaml; then
  echo "deploy/gateway names a moving tag as its default"; status=1
fi
exit $status
