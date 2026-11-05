# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
ARG NODE_IMAGE=node:24.22.2-trixie-slim@sha256:54f84b4cf8432b21aaffd5d3ce8d41e12cea0d10d33c09d2f3c9879d49d6b446
ARG KUBECTL_IMAGE=cgr.dev/chainguard/kubectl@sha256:668d137910c3e949ac9ef48accd14063ee22bfe702141487d199e1bc9cfe39b7
FROM ${NODE_IMAGE} AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund

FROM dependencies AS test
COPY tsconfig.json ./
COPY src ./src
COPY tests ./tests
COPY web ./web
COPY scripts ./scripts
COPY Dockerfile compose.yaml ./
COPY deploy/k8s ./deploy/k8s
RUN npm run build && npm test

FROM dependencies AS build
COPY tsconfig.json ./
COPY src ./src
COPY web ./web
COPY scripts ./scripts
RUN npm run build && npm prune --omit=dev --ignore-scripts --no-audit --no-fund && node scripts/integrity.mjs create /app

FROM build AS signed-payload
ARG INTEGRITY_PUBLIC_KEY
# Missing signing material is an error for the default distribution target.
RUN --mount=type=secret,id=integrity_key,required=true test -n "$INTEGRITY_PUBLIC_KEY" \
    && MCP_SSH_INTEGRITY_SIGNING_KEY_FILE=/run/secrets/integrity_key node scripts/integrity.mjs create /app --signed \
    && MCP_SSH_INTEGRITY_PUBLIC_KEY="$INTEGRITY_PUBLIC_KEY" node scripts/integrity.mjs verify /app

FROM ${KUBECTL_IMAGE} AS kubectl

FROM ${NODE_IMAGE} AS runtime-tools
RUN apt-get update && apt-get install -y --no-install-recommends unzip \
    && mkdir -p /data && chmod 0700 /data \
    && mkdir -p /runtime-libs \
    && cp -L /lib/$(uname -m)-linux-gnu/libbz2.so.1.0 /runtime-libs/ \
    && dpkg-query -s unzip libbz2-1.0 > /runtime-tools.status

FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:b8cec4b2f2126ff7bd034ec9ac207ffb3272667dfdc48376e3b035d3270549ba AS runtime-upstream

# Node bundles its own zlib; neither Node nor unzip links this unused system
# library. Remove the vulnerable library itself and its package records, rather
# than suppressing CVE-2026-76844 in the scanner.
FROM ${NODE_IMAGE} AS runtime-trim
COPY --from=runtime-upstream / /rootfs/
RUN rm -f /rootfs/usr/lib/*-linux-gnu/libz.so.1 /rootfs/usr/lib/*-linux-gnu/libz.so.1.3.1 \
      /rootfs/var/lib/dpkg/status.d/zlib1g /rootfs/var/lib/dpkg/status.d/zlib1g.md5sums \
    && rm -rf /rootfs/usr/share/doc/zlib1g \
    && test -z "$(find /rootfs -name 'libz.so*' -print -quit)"

# No shell, package manager or npm in production; preserve the Linux tunnel archive extractor.
FROM scratch AS runtime-base
COPY --from=runtime-trim /rootfs/ /
ENV NODE_ENV=production MCP_SSH_DATA=/var/lib/mcp-ssh \
    GATEWAY_PORT=8080 GATEWAY_BIND=0.0.0.0 TMPDIR=/tmp HOME=/tmp \
    PATH=/nodejs/bin:/usr/local/bin:/usr/bin:/bin LD_LIBRARY_PATH=/opt/runtime-libs
COPY --from=runtime-tools --chown=1000:1000 /data /var/lib/mcp-ssh
COPY --from=runtime-tools /usr/bin/unzip /usr/bin/unzip
COPY --from=runtime-tools /runtime-libs /opt/runtime-libs
COPY --from=runtime-tools /runtime-tools.status /var/lib/dpkg/status.d/mcp-runtime-tools
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules
COPY --from=kubectl /usr/bin/kubectl /usr/local/bin/kubectl
COPY --from=build /app/package.json /app/package-lock.json ./
COPY LICENSE ./
COPY web ./web
COPY scripts/bootstrap.mjs scripts/healthcheck.mjs ./scripts/
COPY scripts/start.mjs scripts/integrity.mjs ./scripts/
COPY scripts/termius_dump.py ./scripts/termius_dump.py
USER 1000:1000
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD ["node", "scripts/healthcheck.mjs"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["/nodejs/bin/node"]
CMD ["scripts/start.mjs"]

# Explicit local development target. Never publish this as a release.
FROM runtime-base AS runtime-dev
ENV MCP_SSH_REQUIRE_SIGNED_INTEGRITY=0
COPY --from=build /app/integrity.json ./integrity.json

# Default: a signed production image shared by Docker and Kubernetes.
FROM runtime-base AS runtime
ARG INTEGRITY_PUBLIC_KEY
ARG APP_VERSION=0.2.0
ARG VCS_REF=unknown
ARG SOURCE_URL=""
ENV MCP_SSH_REQUIRE_SIGNED_INTEGRITY=1 MCP_SSH_INTEGRITY_PUBLIC_KEY=${INTEGRITY_PUBLIC_KEY}
LABEL org.opencontainers.image.title="MCP SSH K8s" \
    org.opencontainers.image.version=${APP_VERSION} \
    org.opencontainers.image.revision=${VCS_REF} \
    org.opencontainers.image.source=${SOURCE_URL}
COPY --from=signed-payload /app/integrity.* ./
