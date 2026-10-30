# The session image the verifiers attempt serves (plimsolld's SANDBOX_DOCKER_PROJECT_IMAGE):
# plimsoll's Python session image, plus bash, because the plimsoll-bash harness runs each bash
# tool call as `bash -c` the way verifiers' shipped bash harness does (the base has BusyBox sh
# only), and /workspace, a link to the session's work directory, for tasks written for that
# path (prime-envs uuid_ctf). The plimsoll runtime accepts a task's work directory when it
# resolves to the session's inside the sandbox, so the link is the whole adaptation.
# A test image: build it as plimsoll-wip/verifiers-agent:dev, never under a plimsoll/ name.
FROM plimsoll/sandbox-python:latest
USER root
RUN apk add --no-cache bash \
 && ln -s /work /workspace
USER node
