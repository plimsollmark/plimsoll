# Starts a session's interpreter (argv: its command; it gets the directory as its last
# argument), with its stdout and stderr on two FIFOs it holds open read-write, in its
# own session, in the work directory. Prints the identity the sweep keeps it by:
# pid:starttime:cmdline-hex. Runs only where no call's code can have run since the
# last clean sweep, except other interpreters of the session.
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
i=0
while [ ! -s "$d/ready" ]; do
  if ! kill -0 "$child" 2>/dev/null; then echo "the interpreter exited at start" >&2; exit 3; fi
  i=$((i + 1))
  if [ "$i" -gt 400 ]; then echo "the interpreter did not start within 20 seconds" >&2; exit 3; fi
  sleep 0.05
done
pid=$(cat "$d/ready")
start=$(sed 's/.*) //' "/proc/$pid/stat" | cut -d' ' -f20)
cmd=$(od -An -tx1 -v "/proc/$pid/cmdline" | tr -d ' \n')
printf '%s:%s:%s' "$pid" "$start" "$cmd"
