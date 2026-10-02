# Starts a session's interpreter (argv: its command; it gets the directory as its last
# argument), with its stdout and stderr on two FIFOs it holds open read-write, in its
# own session, in the work directory. Prints the identity the sweep keeps it by:
# pid:starttime:cmdline-hex. Runs before the cell's code is sent, but not always
# right after a sweep (a cell that finds its interpreter gone starts it again), so the
# session's other interpreters, and what they started, can have written anything here. So the identity is the process this launcher started, $child (setsid
# execs without forking, as a background job is not a process group leader), and
# never a PID read from a file: the ready file says only that the interpreter
# listens, and only once it names $child.
set -eu
d="$PLIMSOLL_INTERP_DIR"
mkdir -p "$PLIMSOLL_WORK"
rm -rf "$d"
mkdir -p "$d"
chmod 700 "$d"
mkfifo "$d/out" "$d/err"
cd "$PLIMSOLL_WORK"
setsid "$@" "$d" </dev/null 1<>"$d/out" 2<>"$d/err" &
child=$!
# ready names $child once the interpreter listens. Any process of the session can put
# something else at that path; a FIFO there blocked a reader until the cell's deadline.
# So the file is opened read-write, which never blocks, and read only when what was
# opened is a regular file: the check and the read are of one open file, so swapping
# the path between them gains nothing. Anything else ends the launch at once.
ready() {
  [ -e "$d/ready" ] || return 1
  command exec 3<>"$d/ready" 2>/dev/null || return 1
  if [ ! -f "/proc/$$/fd/3" ]; then
    echo "the interpreter's ready file is not a regular file" >&2
    exit 3
  fi
  r=$(head -c 64 <&3)
  exec 3>&-
  [ "$r" = "$child" ]
}
i=0
while ! ready; do
  if ! kill -0 "$child" 2>/dev/null; then echo "the interpreter exited at start" >&2; exit 3; fi
  i=$((i + 1))
  if [ "$i" -gt 400 ]; then echo "the interpreter did not start within 20 seconds" >&2; exit 3; fi
  sleep 0.05
done
# One read gives the parent and the start time together. The parent is this shell
# until it exits, so a process that took $child's PID after the interpreter died
# fails here instead of being kept.
stat=$(sed 's/.*) //' "/proc/$child/stat")
ppid=$(echo "$stat" | cut -d' ' -f2)
start=$(echo "$stat" | cut -d' ' -f20)
if [ "$ppid" != "$$" ]; then echo "process $child is not the interpreter this launcher started" >&2; exit 3; fi
cmd=$(od -An -tx1 -v "/proc/$child/cmdline" | tr -d ' \n')
printf '%s:%s:%s' "$child" "$start" "$cmd"
