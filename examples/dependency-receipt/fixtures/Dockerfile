# The image the fixture logs were captured in: node 22 on Alpine, the five fixture packages
# packed into /fixtures, and the driver.
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402
COPY packages /src
COPY driver.mjs /driver.mjs
RUN mkdir -p /fixtures /cache && for d in /src/*; do (cd "$d" && npm pack --pack-destination /fixtures >/dev/null 2>&1); done && rm -rf /root/.npm
ENV HOME=/tmp NPM_CONFIG_UPDATE_NOTIFIER=false
