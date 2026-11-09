# The shared gateway as a container: `agent-custody gateway --http` on Node, one session per grant, for every agent
# on the host or cluster that points at it. Built two ways from the same file: a release installs the published npm
# package of AGENT_CUSTODY_VERSION; a build from main puts a tarball of the workspace package in pkg/ and installs
# that. Mounts: /config (read-only: gateway.json, policy.cedar or policy.rego, the principals' public keys) and /data (the gateway
# key, receipts, the local log, the revocation file). The opa binary is copied in from the official static image so a
# policy.rego compiles when the gateway loads it; Cedar policies and OPA servers do not use it.
FROM openpolicyagent/opa:1.22.0-static@sha256:906bfc9904b2693733e7959d71773dd073e6c135cf06f26d955abe94603e82b3 AS opa

FROM node:24-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53

COPY --from=opa /opa /usr/local/bin/opa

ARG AGENT_CUSTODY_VERSION
COPY pkg/ /tmp/pkg/
RUN if ls /tmp/pkg/*.tgz > /dev/null 2>&1; then npm install -g /tmp/pkg/*.tgz; else npm install -g "@agent-custody/receipts@${AGENT_CUSTODY_VERSION:?pass --build-arg AGENT_CUSTODY_VERSION=<version>, or put a tarball in pkg/}"; fi \
  && rm -rf /tmp/pkg \
  && adduser -D -u 10001 custody \
  && mkdir -p /config /data/keys \
  && chown -R custody:custody /data

COPY gateway-entrypoint.sh /usr/local/bin/gateway-entrypoint.sh
RUN chmod +x /usr/local/bin/gateway-entrypoint.sh

USER custody
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8790 8791

ENV DATA_DIR=/data \
    GATEWAY_CONFIG=/config/gateway.json \
    GATEWAY_PORT=8790 \
    EGRESS_PORT=8791

# healthy when the gateway answers, or the egress witness when the container runs in egress mode
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:${GATEWAY_PORT}/health" > /dev/null 2>&1 || wget -qO- "http://127.0.0.1:${EGRESS_PORT}/.well-known/agent-custody-egress" > /dev/null || exit 1

ENTRYPOINT ["gateway-entrypoint.sh"]
CMD ["serve"]
