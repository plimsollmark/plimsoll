#!/bin/bash
# A stand-in for wslc.exe that answers through this machine's docker (`make
# wslc-docker-check`, which make audit runs with DOCKER=1): the wslc provider's real run path, plimsoll's runner and
# the smoke test's probe, against a real container (runc under a Linux dockerd). It checks
# plimsoll's side of the path: the probe's JavaScript, the runner's report and the checks
# on real values. It is not WSLC and proves nothing about WSLC, interop or wslc.exe: the
# docker CLI here accepts the flags the provider sends whether or not wslc does.
# It answers the shared mode only. The per-run mode opens Hyper-V sessions from a Windows
# path and a VHDX, which docker cannot stand in for, so `make wslc-docker-check` skips the
# per-run tests; `make wslc-suite` on a real WSLC is their only run.
if [ "$1" = "--session" ]; then shift 2; fi   # one stand-in session: this machine
case "$1 $2" in
  "system info") echo '{"Server":{"Sessions":[{"Name":"wslc-cli-standin"}]}}' ;;
  "version --format") echo '{"Client":{"Version":"3.0.5.0"}}' ;;
  "image inspect") exec docker image inspect "$3" ;;
  "system session")
    shift 3
    case "$*" in
      "uname -r") uname -r ;;
      "cat /proc/sys/kernel/random/boot_id") cat /proc/sys/kernel/random/boot_id ;;
      "ls -l /dev/dxg") exec ls -l /dev/dxg ;;
      "cat /proc/self/mounts") exec cat /proc/self/mounts ;;
      "dockerd --version") docker version --format 'Docker version {{.Server.Version}}' ;;
      *) echo "unknown session command: $*" >&2; exit 2 ;;
    esac ;;
  "container run") shift 2; exec docker run "$@" ;;
  "container remove") shift 2; exec docker rm "$@" ;;
  *) echo "unknown: $*" >&2; exit 2 ;;
esac
