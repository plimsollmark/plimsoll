# Toolchain image for CodegenService project runs. The TypeScript toolchain is
# baked in (no network at runtime — the sandbox runs with --network none), so
# agents can typecheck, lint, and execute TS/JS without installing anything.
FROM node:22-alpine AS runner-guard-build
RUN apk add --no-cache gcc musl-dev
COPY guard/runner.c /runner-guard.c
RUN cc -O2 -fPIC -shared -o /runner-guard.so /runner-guard.c

FROM node:22-alpine

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
