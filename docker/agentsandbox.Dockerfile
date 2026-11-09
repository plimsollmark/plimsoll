# Agent-sandbox image: plimsoll's project image with sandboxd, the runtime daemon of
# Kubernetes agent-sandbox, built from source at v1.0.7 (the project publishes no released
# image of it, only a staging latest-main); plimsoll-sandboxd-tls, the TLS terminator in
# front of it (sandboxdtls/main.go: sandboxd serves no TLS); and util-linux setpriv, which
# the provider (sandbox/agentsandbox) uses to drop every command to the guest uid:
# BusyBox's setpriv, which the base carries, cannot change uid. The runner and its guard
# come from the base.
#
# A SandboxTemplate runs it as root with only CAP_SETUID and CAP_SETGID, with the command
# /usr/local/bin/plimsoll-sandboxd-tls and sandboxd's flags, among them
# --listen-host=127.0.0.1, --grpc-port=9091 and --auth-token-sha256, and the TLS Secret
# mounted at /etc/plimsoll/sandboxd-tls (docs/agentsandbox.md). Build with
#   docker build -f docker/agentsandbox.Dockerfile -t plimsoll/sandbox-agentsandbox docker
# Its context is docker/ filtered by agentsandbox.Dockerfile.dockerignore, which admits
# the terminator's source alone. The sandboxd build fetches the agent-sandbox source and
# its modules, so it needs network.
# The base is pinned by digest, so every build of this context starts from the same
# bytes: local builds once used whatever their cache held while CI pulled the tag fresh,
# both under one inputs label (review, 2026-10-23). The tag is for readers; the digest
# decides. To move it: docker pull the tag, then copy its RepoDigests entry here. With
# DOCKER_HUB_MIRROR set, make docker-images passes the same digest from the mirror.
# Its Go is 1.26.10, the canonical toolchain (AGENTS.md), which the terminator's TLS
# server is built with.
ARG BASE_GO=golang:1.26-alpine@sha256:27f2d3b83cfc5803c8078f8e730af0f7c431bf067afaec8f60a36fb763187cba
FROM ${BASE_GO} AS sandboxd
ARG AGENT_SANDBOX_COMMIT=807cc37107bd7c012115afac9fa9c3b77b8365c2
RUN apk add --no-cache git
RUN git clone --filter=blob:none https://github.com/kubernetes-sigs/agent-sandbox /src \
 && git -C /src checkout --detach "$AGENT_SANDBOX_COMMIT" \
 && test "$(git -C /src rev-parse HEAD)" = "$AGENT_SANDBOX_COMMIT"
WORKDIR /src
# The module asks for toolchain go1.27.1; its go line (1.26.0) is met by this image's Go,
# so no toolchain is downloaded.
RUN GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath -ldflags=-buildid= -o /sandboxd ./packages/sandboxd/cmd/sandboxd

# The terminator imports the standard library only, so a module of its own needs no
# download.
FROM ${BASE_GO} AS tls
WORKDIR /tls
COPY sandboxdtls/main.go ./
RUN printf 'module plimsoll-sandboxd-tls\n\ngo 1.26\n' > go.mod \
 && GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath -ldflags=-buildid= -o /plimsoll-sandboxd-tls .

FROM plimsoll/sandbox:latest
USER root
# /etc/plimsoll holds the TLS Secret's mount; root's and closed to every other user, so
# the guest cannot even reach the key file below it, whatever the Secret's own modes.
RUN apk add --no-cache setpriv && /bin/setpriv --version | grep -q util-linux \
 && install -d -o root -g root -m 0700 /etc/plimsoll /etc/plimsoll/sandboxd-tls
COPY --from=sandboxd /sandboxd /usr/local/bin/sandboxd
COPY --from=tls /plimsoll-sandboxd-tls /usr/local/bin/plimsoll-sandboxd-tls
ENTRYPOINT ["/usr/local/bin/plimsoll-sandboxd-tls"]
