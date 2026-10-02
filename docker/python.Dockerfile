# Python project-run image, derived from the Node toolchain image. The runner and
# its contract (guarded node /runner.mjs entrypoint, USER node, no VOLUME, --network none at
# run time) come from the base; this layer only adds an interpreter and two
# packages, which is the whole recipe for any other runtime
# (docs/guest-dependencies.md, "Other runtimes: the same recipe").
#
# Build with `make docker-images`, which tags it plimsoll/sandbox-python:latest;
# point a daemon at it with SANDBOX_DOCKER_PROJECT_IMAGE. Steps then run
# `python3 main.py` through the same runner, with no API change.
FROM plimsoll/sandbox:latest

USER root

# Alpine packages, pinned to the upstream minor version. `~3.14` admits any 3.14.x
# and any Alpine packaging revision (-rN): Alpine drops a package from its index when
# it updates or rebuilds it, so a pin to a patch version turned Alpine's python3 3.14.8
# into a failed build that changed nothing we chose (2026-10-01, both hosted Docker jobs).
# What ran stays exact: the image's identity is stated on every run.
#
# The base tag floats: `make docker-images` pulls node:22-alpine, and that tag
# tracks Alpine's current release (3.23 on 2026-09-18 in the morning, 3.24 by the
# first build of this file that afternoon, which changed all three versions). So
# an "unable to select packages ... breaks: world[python3~3.x]" failure here means
# the base moved to a newer Alpine release and the pins need a deliberate bump to what
# `apk search -x python3 py3-numpy py3-scipy` reports inside plimsoll/sandbox.
#
# NumPy is here as the proof that a native extension loads under the seccomp
# profile and noexec writable mounts; SciPy rides along because the same proof
# covers its LAPACK bindings. No pip: a run never installs anything.
RUN apk add --no-cache \
      "python3~3.14" \
      "py3-numpy~2.4" \
      "py3-scipy~1.17"

# One BLAS thread. Alpine's OpenBLAS is the pthreads build (MAX_THREADS=256) and
# sizes its pool from the host's core count, not the run's CPU quota, so without
# this a run would spin up a thread per host core inside a 1-CPU, 256-pid cgroup.
# One thread also makes reductions deterministic across runs, which a migration
# harness comparing results needs. OMP_NUM_THREADS covers anything built against
# OpenMP instead.
ENV OPENBLAS_NUM_THREADS=1 \
    OMP_NUM_THREADS=1

USER node
