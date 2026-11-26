#!/bin/sh
# setup.sh: the build tools and the kernel history witness.py needs, inside a Debian container (run as root).
# Fetches only public trees: Linus's (from GitHub) and the ext4 tree's dev branch (from git.kernel.org).
# A second run finds the checkout already there and only reinstalls the tools.
set -eu
WORK="${WITNESS_WORK:-/root}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q --no-install-recommends build-essential flex bison bc libelf-dev libssl-dev \
  python3 git ca-certificates ccache rsync kmod cpio xz-utils
git config --global --add safe.directory '*'
mkdir -p "$WORK/linux"
cd "$WORK/linux"
if [ ! -f "$WORK/.setup-ok" ]; then
  git init -q
  git remote add origin https://github.com/torvalds/linux.git 2>/dev/null || true
  # Everything committed since 2026-11-01: the pull's 94 commits (Nov 18 to 23), their base v7.4-rc2, and Linus's
  # side up to the merge 4dce97c6c265, with file contents (the builds need them).
  git fetch -q --shallow-since=2026-11-01 origin 4dce97c6c265544342e716e62fd24bbb232590c5
  for c in 4dce97c6c265^2 bae28a1b11f4 05f2b6927ab5 9627baed418b; do git rev-parse --verify -q "$c^{commit}"; done
  git checkout -q bae28a1b11f4
  git config user.email witness@example.invalid
  git config user.name witness
  # The ext4 tree's dev branch: the merge, then Ted Ts'o's two KUnit fixes (97f29574e12e, ad592b92d677). Two commits
  # deep, which is all the configuration check needs. By commit first; if the server refuses that, the branch (deeper,
  # in case it has moved on since 2026-11-26).
  EXT4=https://git.kernel.org/pub/scm/linux/kernel/git/tytso/ext4.git
  git fetch -q --depth=2 "$EXT4" ad592b92d6774cb520d1492bf17685fb5eede99d || git fetch -q --depth=50 "$EXT4" dev
  git rev-parse --verify -q 'ad592b92d6774cb520d1492bf17685fb5eede99d^{commit}'
  touch "$WORK/.setup-ok"
fi
git rev-parse --short=12 HEAD
