# Toolchain image for CodegenService project runs. The TypeScript toolchain is
# baked in (no network at runtime — the sandbox runs with --network none), so
# agents can typecheck, lint, and execute TS/JS without installing anything.
# The base is pinned by digest, so every build of this context starts from the same
# bytes: local builds once used whatever their cache held while CI pulled the tag fresh,
# both under one inputs label (review, 2026-10-23). The tag is for readers; the digest
# decides. To move it: docker pull the tag, then copy its RepoDigests entry here. With
# DOCKER_HUB_MIRROR set, make docker-images passes the same digest from the mirror.
ARG BASE_NODE=node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914
FROM ${BASE_NODE} AS runner-guard-build
RUN apk add --no-cache gcc musl-dev
COPY guard/runner.c /runner-guard.c
RUN cc -O2 -fPIC -shared -o /runner-guard.so /runner-guard.c

FROM ${BASE_NODE}

# Global, version-pinned dev toolchain. Versions are the single source of truth in
# ../toolchain.versions and are kept in lockstep with the e2b template
# (e2b/e2b.Dockerfile) by the internal/toolchain test. Installed at build time so
# runtime needs no egress.
RUN npm install -g --no-fund --no-audit \
      typescript@5.6.3 \
      tsx@4.19.2 \
      eslint@9.13.0 \
  && npm cache clean --force

# The in-sandbox runner (see sandbox/runner.mjs).
COPY runner.mjs /runner.mjs
COPY --from=runner-guard-build /runner-guard.so /usr/local/lib/plimsoll-runner-guard.so

# Drop to a non-root user; the host also enforces --user, --cap-drop, etc.
USER node

ENTRYPOINT ["sh", "-c", "export LD_PRELOAD=/usr/local/lib/plimsoll-runner-guard.so; exec node /runner.mjs"]
