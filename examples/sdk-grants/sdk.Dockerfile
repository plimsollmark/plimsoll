# The project image of the sdk-grants example: plimsoll's Python image with the OpenAI
# and Anthropic client libraries added, unmodified, from the wheels requirements.txt pins
# by version and SHA-256. Building it uses the network (pip fetches the wheels); a run
# never does. Nothing under docker/ changes, so the shared images and their inputs label
# stay as they are.
#
#   docker build -f examples/sdk-grants/sdk.Dockerfile -t plimsoll-wip/sdk-grants:dev examples/sdk-grants
#
# The first stage adds pip (Alpine's py3-pip) to install the wheels into a directory of
# their own; the image the runs use copies that directory into the interpreter's
# site-packages and carries no pip, as plimsoll/sandbox-python carries none.
FROM plimsoll/sandbox-python:latest AS wheels
USER root
RUN apk add --no-cache py3-pip
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --no-deps --only-binary=:all: --require-hashes \
      --target /opt/sdk -r /tmp/requirements.txt \
 && rm -rf /opt/sdk/bin

FROM plimsoll/sandbox-python:latest
COPY --from=wheels /opt/sdk/ /usr/lib/python3.14/site-packages/
