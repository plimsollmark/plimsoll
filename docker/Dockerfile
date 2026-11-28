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
# The session init (docker/guard/session-init.c), PID 1 for a session provider whose
# runtime has no init option (the WSL containers provider). Static, so no variable in
# the image's environment can load code into it. guard/session-exec.c is built into no
# image: a session call's command and environment are its exec's own arguments.
COPY guard/session-init.c /
RUN cc -static -O2 -Wall -Wextra -Werror -o /plimsoll-session-init /session-init.c \
 && chmod 0755 /plimsoll-session-init

# The project runner: plimsoll's native helper (sandbox/internal/nativehelper), a static
# program with no outside package. Its bytes are the committed build at its pin, handed to
# this build as the named build context nativehelper (make docker-images passes
# --build-context nativehelper=sandbox/internal/nativehelper/program, and the inputs label
# covers both files), checked here against the pin, and checked again by plimsolld's
# startup test against the pin compiled into plimsolld. Only an x86-64 build is committed:
# on another machine the COPY finds no file and the build fails.
FROM ${BASE_NODE} AS native-helper
ARG TARGETARCH
COPY --from=nativehelper plimsoll-helper_${TARGETARCH} plimsoll-helper.sha256 /h/
RUN cd /h && pin="$(grep -x "[0-9a-f]\{64\}  plimsoll-helper_${TARGETARCH}" plimsoll-helper.sha256)" \
 && echo "$pin" | sha256sum -c - \
 && install -m 0711 plimsoll-helper_${TARGETARCH} /plimsoll-helper

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

# The project runner (the native helper's run-project mode), root's, mode 0711: the guest may
# run it and not read it, so the kernel makes it non-dumpable from its exec, before its first
# instruction (nativehelper.InstalledMode). The guard library stays: plimsoll loads it into every node program of its own
# beside guest code (a session's sweep, quiesce and relays, the granted-run forwarder).
COPY --from=native-helper /plimsoll-helper /usr/local/libexec/plimsoll-helper
COPY --from=runner-guard-build /runner-guard.so /usr/local/lib/plimsoll-runner-guard.so
COPY --from=runner-guard-build /plimsoll-session-init /usr/local/bin/

# Drop to a non-root user; the host also enforces --user, --cap-drop, etc.
USER node

# plimsoll names its own command for every container (--entrypoint); this one is for a reader.
ENTRYPOINT ["/usr/local/libexec/plimsoll-helper", "run-project"]
