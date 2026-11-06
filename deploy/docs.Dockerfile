# docs.agent-custody.dev: the site built from this checkout and served as static files. Build context is the
# repository root (the compose file sets it); the image carries only the built pages and a Caddy serving them.
FROM oven/bun:1@sha256:ec06c3b6cea04192ae6770c434f668ca41d343ad19fa6472216c7b48be39c598 AS build
WORKDIR /src
COPY . .
RUN bun install --frozen-lockfile --ignore-scripts && bun run site:build

FROM caddy:2-alpine@sha256:e70b164da81ef698b3ad19af799ea6086ce6d9e48ed4079eb9fe26f6fbf14ee5
COPY --from=build /src/site/.vitepress/dist /srv
COPY deploy/docs.Caddyfile /etc/caddy/Caddyfile
