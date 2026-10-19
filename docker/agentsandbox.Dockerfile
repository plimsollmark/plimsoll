# Agent-sandbox image: plimsoll's project image with sandboxd, the runtime daemon of
# Kubernetes agent-sandbox, built from source at v1.0.7 (the project publishes no released
# image of it, only a staging latest-main), and util-linux setpriv, which the provider
# (sandbox/agentsandbox) uses to drop every command to the guest uid: BusyBox's setpriv,
# which the base carries, cannot change uid. The runner and its guard come from the base.
#
# A SandboxTemplate runs it as root with only CAP_SETUID and CAP_SETGID and starts sandboxd
# with --auth-token-sha256 (docs/agentsandbox.md). Build with
#   docker build -f docker/agentsandbox.Dockerfile -t plimsoll/sandbox-agentsandbox docker
# The sandboxd build fetches the agent-sandbox source and its modules, so it needs network.
FROM golang:1.26-alpine AS sandboxd
ARG AGENT_SANDBOX_COMMIT=807cc37107bd7c012115afac9fa9c3b77b8365c2
RUN apk add --no-cache git
RUN git clone --filter=blob:none https://github.com/kubernetes-sigs/agent-sandbox /src \
 && git -C /src checkout --detach "$AGENT_SANDBOX_COMMIT" \
 && test "$(git -C /src rev-parse HEAD)" = "$AGENT_SANDBOX_COMMIT"
WORKDIR /src
# The module asks for toolchain go1.27.1; its go line (1.26.0) is met by this image's Go,
# so no toolchain is downloaded.
RUN GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath -ldflags=-buildid= -o /sandboxd ./packages/sandboxd/cmd/sandboxd

FROM plimsoll/sandbox:latest
USER root
RUN apk add --no-cache setpriv && /bin/setpriv --version | grep -q util-linux
COPY --from=sandboxd /sandboxd /usr/local/bin/sandboxd
ENTRYPOINT ["/usr/local/bin/sandboxd"]
