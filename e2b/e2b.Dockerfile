# plimsoll's E2B template: the machine image E2B starts each of plimsoll's sandboxes from.
# Built with E2B's current build system (`e2b template create`, which reads this file;
# e2b/README.md has the steps). Two things need it:
#
# - Sessions. A session's own programs (its open, process lister, sweep, stager,
#   artifact reader, relays) start with node's --disable-sigusr1, so that the session's
#   code cannot open their debugger with a signal. Node accepts that option from v22.14.0
#   (v23.7.0 in the 23 line, every release from 24); E2B's own `base` template carried
#   node v20.9.0 when plimsoll last read it (2026-11-20), so a session there is refused.
#   A session also needs util-linux's setpriv (it runs the session's code as a user no
#   account has), mount (the open bind-mounts the work folder on itself, for file calls)
#   and, for Python cells, python3: sandbox/e2b_session.go's e2bRequiredBins and
#   e2b_session.js's pin list name what the open looks for.
# - Project runs with the network off. The TypeScript toolchain is baked in, as in
#   docker/Dockerfile, so a step needs no `npm install` at run time.
#
# Single runs (snippets, projects without the toolchain) work on E2B's `base` too.
#
# The base is pinned by digest, so every build starts from the same bytes; the tag is
# for readers. Debian, because E2B's agent inside the machine (envd) is a glibc program
# and E2B identifies the distribution from /etc/os-release. To move the pin: docker pull
# the tag, then copy its RepoDigests entry here.
FROM node:24-trixie-slim@sha256:43b9ba1142b8dcf33fa8f922ca1be85714adc444e0586c7cf7726daaeabc1bea

# python3 for Python cells and project steps; ca-certificates for Debian's trust store,
# which NODE_OPTIONS below points node at. The last line fails the build when any program
# a session pins is missing or node is too old for --disable-sigusr1.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && node --disable-sigusr1 -e 'process.stdout.write(process.version + "\n")' \
 && setpriv --version && mount --version && python3 --version && test -x /usr/bin/env && test -x /bin/sh

# Use Debian's current CA bundle for outbound HTTPS. Node's bundled CA set can
# lag OS trust updates; the E2B guard endpoint must validate public chains
# without disabling TLS verification. E2B's build turns ENV into the template's
# environment, which a run's processes get; plimsoll's own session programs start with
# an empty one.
ENV NODE_OPTIONS=--use-openssl-ca

# Global, version-pinned dev toolchain. Versions are the single source of truth in
# ../toolchain.versions and are kept in lockstep with docker/Dockerfile by the
# internal/toolchain test.
RUN npm install -g --no-fund --no-audit \
      typescript@5.6.3 \
      tsx@4.19.2 \
      eslint@9.13.0 \
  && npm cache clean --force

# A node of plimsoll's own, outside /usr/local. E2B's template build, after these steps,
# leaves /usr/local and everything in it writable by every user in the machine (mode 777;
# measured on 2026-11-20, on E2B's base template too), and this image's node is in
# /usr/local/bin. A session's code could replace a node there, so plimsoll's own programs
# in a session look for node only in /usr/sbin, /usr/bin, /sbin and /bin, and a session's
# open refuses a program a guest could change. A copy, not a link: a hard link would
# share the file E2B's build opens. Keep this the last step that touches node.
RUN cp /usr/local/bin/node /usr/bin/node && chmod 755 /usr/bin/node \
 && /usr/bin/node --disable-sigusr1 -e 'process.stdout.write(process.version + "\n")'

# No USER, WORKDIR, CMD or ENTRYPOINT: E2B's build makes `user` (home /home/user) the
# default user, which a single run starts as and reads its files as, and a template start
# command would run a process of the template's beside every session.
