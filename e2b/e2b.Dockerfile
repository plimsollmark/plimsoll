# E2B sandbox template for plimsoll project runs. Mirrors docker/Dockerfile: the
# TypeScript toolchain is baked in so a sandbox needs NO network at runtime. That is
# what lets plimsoll run no-grant E2B sandboxes with internet fully disabled
# (network.denyOut) without breaking tsc/tsx/eslint project steps — the same posture
# as the docker provider's `--network none` image.
#
# Debian-slim (not alpine) because E2B's envd daemon, injected at build time, is
# glibc-based; slim keeps the rootfs small (~250 MB vs ~1.1 GB for full node:22), so
# the microVM's disk footprint and attack surface stay minimal — complementing the
# cpu_count/memory_mb caps in e2b.toml. tsc/tsx/eslint/node need no compiler at
# runtime, so slim is sufficient.
FROM node:22-slim

# Use Debian's current CA bundle for outbound HTTPS. Node's bundled CA set can
# lag OS trust updates; the E2B beta guard endpoint must validate public chains
# without disabling TLS verification.
ENV NODE_OPTIONS=--use-openssl-ca

# Global, version-pinned dev toolchain. Versions are the single source of truth in
# ../toolchain.versions and are kept in lockstep with docker/Dockerfile by the
# internal/toolchain test.
RUN npm install -g --no-fund --no-audit \
      typescript@5.6.3 \
      tsx@4.19.2 \
      eslint@9.13.0 \
  && npm cache clean --force
