#!/usr/bin/env bash
# buildvcs.sh DIR         prints "true" when plimsolld built from the plimsoll checkout DIR (go -C DIR build) may carry
#                         Go's version control stamp, "false" otherwise.
# buildvcs.sh DIR BINARY  exits 0 when BINARY, built from DIR, carries no stamp or exactly the release the first form
#                         finds; otherwise it says why and exits 1, and receipt.sh builds again without the stamp.
#
# The daemon states its version on every answer, from the build information Go writes into the binary. Built with the
# stamp from a checkout of a release (v0.28.0), it states that release, so a receipt names the plimsoll release that
# made it. Anywhere else the stamp is a version nobody published (a pseudo-version for a commit no release names, a
# +dirty one for a changed tree, the version of another checkout), so the build leaves it out and the daemon states
# (devel).
#
# The first form answers true only when Go, building from DIR, stamps exactly the release tag it found, which with Go
# 1.26.11 is when all of these hold (buildvcs_test.go builds each case and reads the stamp back):
# - git is installed, and no GIT_ variable is set: git reads its repository, work tree, index, objects and settings
#   from them, and Go runs git in the same environment (receipt.sh removes them all before both).
# - DIR/.git is a directory and git names DIR as the top of its work tree. Go takes the nearest directory at or above
#   the build that holds a .git directory as the repository, so from a worktree or a submodule (whose .git is a file)
#   it stamps the checkout around it, and for a module in a subdirectory it reads that repository's tags. The recipe
#   builds the root of plimsoll's own repository; anything else answers false.
# - The tree is unchanged, untracked files included whatever git's settings say (an untracked file in a package
#   directory is compiled, and Go sees it only when git status lists it). A file git ignores is not checked.
# - DIR/go.mod names a module path with no major version suffix (plimsoll's has none), so Go reads tags v0 and v1
#   and ignores v2 and later; a path ending /v2 answers false.
# - A release tag names HEAD: vMAJOR.MINOR.PATCH, each number 0 or without a leading zero, from v0.2.0 on
#   (plimsoll's public releases start there; the v0.1.x tags are spent) and below v2.
# - No tag naming HEAD reads as a higher version, since Go stamps the highest version among the tags on the commit,
#   a pre-release included (v0.29.0-rc.1 over v0.28.0). A tag that only looks like one (v0.29.0+build) answers false
#   too, the safe side. Tags that are no version (latest, clients/mcp/v0.29.0) change nothing.
#
# A tag shows only that the checkout's repository names HEAD with that release; in a fork, the fork's own tags count
# the same way. Some of what Go reads cannot be seen from here (with GOPROXY=off, a pseudo-version Go's module cache
# remembers for the commit; a later git or Go that reads tags otherwise), which is why receipt.sh checks the binary
# with the second form.
set -u
dir="${1:?the plimsoll checkout}"
binary="${2:-}"

# above A B: whole number A (digits, leading zeros allowed) is greater than B.
above() {
  local a="${1#"${1%%[!0]*}"}" b="${2#"${2%%[!0]*}"}"
  if [ "${#a}" -ne "${#b}" ]; then [ "${#a}" -gt "${#b}" ]; return; fi
  [[ "$a" > "$b" ]]
}

# newer A B: version triple A (MAJOR.MINOR.PATCH) is above triple B.
newer() {
  local -a x y
  IFS=. read -r -a x <<< "$1"
  IFS=. read -r -a y <<< "$2"
  local i
  for i in 0 1 2; do
    if above "${x[$i]}" "${y[$i]}"; then return 0; fi
    if above "${y[$i]}" "${x[$i]}"; then return 1; fi
  done
  return 1
}

# release prints the release tag Go stamps building from DIR, or nothing.
release() {
  command -v git > /dev/null 2>&1 || return 0
  local name
  for name in $(compgen -e); do
    case "$name" in GIT_*) return 0 ;; esac
  done
  [ -d "$dir/.git" ] || return 0
  local top here
  top="$(git -C "$dir" rev-parse --show-toplevel 2> /dev/null)" || return 0
  here="$(CDPATH='' cd -- "$dir" && pwd -P)" || return 0
  [ "$top" = "$here" ] || return 0
  [ -f "$dir/go.mod" ] || return 0
  local line modpath=''
  while IFS= read -r line; do
    if [[ "$line" =~ ^[[:space:]]*module[[:space:]]+\"?([^\"[:space:]]+) ]]; then
      modpath="${BASH_REMATCH[1]}"
      break
    fi
  done < "$dir/go.mod"
  if [ -z "$modpath" ] || [[ "$modpath" =~ [/.]v[0-9]+$ ]]; then return 0; fi
  local changed
  changed="$(git -C "$dir" status --porcelain --untracked-files=normal 2> /dev/null)" || return 0
  [ -z "$changed" ] || return 0
  local tags
  tags="$(git -C "$dir" tag --points-at HEAD 2> /dev/null)" || return 0
  local num='(0|[1-9][0-9]*)'
  local rel="^v(0\.([2-9]|[1-9][0-9]+)|1\.$num)\.$num\$"
  local tag best='' bestv=''
  while IFS= read -r tag; do
    if [[ "$tag" =~ $rel ]] && { [ -z "$best" ] || newer "${tag#v}" "$bestv"; }; then
      best="$tag" bestv="${tag#v}"
    fi
  done <<< "$tags"
  [ -n "$best" ] || return 0
  while IFS= read -r tag; do
    if [[ "$tag" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+) ]] && ! above "${BASH_REMATCH[1]}" 1 &&
      newer "${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}" "$bestv"; then
      return 0
    fi
  done <<< "$tags"
  printf '%s\n' "$best"
}

tag="$(release)"
if [ -z "$binary" ]; then
  if [ -n "$tag" ]; then echo true; else echo false; fi
  exit 0
fi

# The second form: what Go wrote into BINARY.
info="$(go version -m "$binary" 2> /dev/null)" || { echo "buildvcs.sh: go version -m cannot read $binary" >&2; exit 1; }
# Lines are a tab, a kind and its fields: "mod PATH VERSION", "build vcs.revision=..." (read strips the first tab).
version='' revision='' modified='' stamped=0
while IFS=$'\t' read -r kind first second _; do
  case "$kind" in
    mod) version="$second" ;;
    build)
      case "$first" in vcs=* | vcs.*) stamped=1 ;; esac
      case "$first" in
        vcs.revision=*) revision="${first#vcs.revision=}" ;;
        vcs.modified=*) modified="${first#vcs.modified=}" ;;
      esac
      ;;
  esac
done <<< "$info"
if [ "$stamped" = 0 ] && [ "$version" = '(devel)' ]; then exit 0; fi
if [ -n "$tag" ] && [ "$version" = "$tag" ] && [ "$modified" = false ] &&
  [ "$revision" = "$(git -C "$dir" rev-parse HEAD 2> /dev/null)" ]; then
  exit 0
fi
echo "buildvcs.sh: the build states $version at commit ${revision:-none}, not the release ${tag:-(none)} at this checkout's HEAD" >&2
exit 1
