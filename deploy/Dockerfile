# The log server as a container: the published @agent-custody/receipts CLI on Node 22, nothing else.
# Runs `agent-custody log` over a /data volume that holds the log file and the signing key. The same image serves
# docker compose, a single VM, and Kubernetes; only the environment differs.
FROM node:24-alpine@sha256:44fce696f38ba8c987c4db89954051000bbd05ffd8d8659ba15ed4a8602e937f

ARG AGENT_CUSTODY_VERSION=0.14.0
# A release installs the published package; a pull request check puts a tarball of the workspace package in pkg/.
COPY pkg/ /tmp/pkg/
RUN if ls /tmp/pkg/*.tgz > /dev/null 2>&1; then npm install -g /tmp/pkg/*.tgz pg@8 @node-saml/node-saml@5; else npm install -g "@agent-custody/receipts@${AGENT_CUSTODY_VERSION}" pg@8 @node-saml/node-saml@5; fi \
  && rm -rf /tmp/pkg \
  && adduser -D -u 10001 custody \
  && mkdir -p /data/keys /checkpoints /witnessed \
  && chown -R custody:custody /data /checkpoints /witnessed

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER custody
WORKDIR /data
VOLUME ["/data", "/checkpoints", "/witnessed"]
EXPOSE 8787

# Every setting is an environment variable, so compose and Kubernetes configure it the same way.
ENV AGENT_CUSTODY_LOG_FILE=/data/log.jsonl \
    AGENT_CUSTODY_LOG_KEY=/data/keys/log.key \
    AGENT_CUSTODY_LOG_PORT=8787

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:${AGENT_CUSTODY_LOG_PORT}/head" > /dev/null || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
