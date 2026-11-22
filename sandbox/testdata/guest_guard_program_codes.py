"""Each failure of the guest guard program, reached once, and what it passes through when it works.

TestDockerGuestGuardProgram (sandbox/guestguard_program_docker_test.go) runs this without the guard,
in a container docker starts without no-new-privileges (so the guard's own setting can be seen),
after guest_guard_attempts.py with MODES = ["control"]. It prepends PRCTL_NR, prctl's request
number on this machine. A run that needs the guard's prctl answered otherwise installs a filter of
its own first, in the child, before it starts the guard: refusing PR_SET_NO_NEW_PRIVS, refusing
PR_SET_SECCOMP, or answering PR_SET_SECCOMP with 0 without doing it, which is what a runtime that
ignores filters looks like to the guard. One JSON line per run: {"run", "exit", "stdout", "stderr"}.
"""
import ctypes
import json
import os
import subprocess

libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.restype = ctypes.c_int
u = ctypes.c_ulong

GUARD = GUEST_GUARD  # noqa: F821 (prepended by the test: where the provider mounts the guard)
PR_SET_SECCOMP, PR_SET_NO_NEW_PRIVS, PR_GET_NO_NEW_PRIVS = 22, 38, 39
SECCOMP_MODE_FILTER = 2
RET_ALLOW, RET_ERRNO = 0x7FFF0000, 0x00050000
EPERM = 1


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


def answer_prctl(option, ret, refuse_unshare=False):
    """A filter that answers prctl(option, ...) with ret and allows everything else; with
    refuse_unshare, it also refuses unshare with EPERM whatever its flags, as plimsoll's shipped
    profile does (finding guest-guard-13: a self-check that asks only for that refusal passes)."""
    ins = [
        (0x20, 0, 0, 0),  # A = nr
        (0x15, 0, 3, PRCTL_NR),  # noqa: F821 (prepended by the test): not prctl, go on
        (0x20, 0, 0, 16),  # A = low 32 bits of the first argument
        (0x15, 0, 3, option),
        (0x06, 0, 0, ret),
        (0x15, 0, 1, UNSHARE_NR if refuse_unshare else 0xFFFFFFFF),  # noqa: F821 (prepended): unshare?
        (0x06, 0, 0, RET_ERRNO | EPERM),
        (0x06, 0, 0, RET_ALLOW),
    ]
    raw = b"".join(c.to_bytes(2, "little") + bytes([jt, jf]) + k.to_bytes(4, "little") for c, jt, jf, k in ins)
    buf = ctypes.create_string_buffer(raw, len(raw))

    def install():
        if libc.prctl(ctypes.c_int(PR_SET_NO_NEW_PRIVS), u(1), u(0), u(0), u(0)) != 0:
            os._exit(90)
        prog = SockFprog(len(ins), ctypes.cast(buf, ctypes.c_void_p))
        if libc.prctl(ctypes.c_int(PR_SET_SECCOMP), u(SECCOMP_MODE_FILTER), ctypes.byref(prog), u(0), u(0)) != 0:
            os._exit(91)

    return install


def run(name, argv, preexec=None, env=None):
    p = subprocess.run(argv, capture_output=True, text=True, preexec_fn=preexec, env=env if env is not None else {})
    print(json.dumps({"run": name, "exit": p.returncode, "stdout": p.stdout, "stderr": p.stderr}), flush=True)


print(json.dumps({"run": "no-new-privileges without the guard",
                  "exit": libc.prctl(ctypes.c_int(PR_GET_NO_NEW_PRIVS), u(0), u(0), u(0), u(0)),
                  "stdout": "", "stderr": ""}), flush=True)
NNP = 'import ctypes; l = ctypes.CDLL(None); print(l.prctl(39, 0, 0, 0, 0), l.prctl(21, 0, 0, 0, 0))'
run("no-new-privileges and the filter behind the guard", [GUARD, "--", "/usr/bin/env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin", "python3", "-I", "-c", NNP])
run("environment and arguments pass through", [GUARD, "--", "/bin/sh", "-c", 'printf "%s|" "$0" "$@" "$A"', "zero", "a b", ""], env={"A": "1"})
run("environment passes through whole", [GUARD, "--", "/usr/bin/env"], env={"A": "1", "B": "two words"})
run("usage: nothing", [GUARD])
run("usage: no --", [GUARD, "/bin/echo", "RAN"])
run("usage: nothing after --", [GUARD, "--"])
# The process-1 mode (finding guest-guard-10): only process 1 may stay to collect; here python is
# process 1 and the guard its child.
run("usage: --pid1 not as process 1", [GUARD, "--pid1", "--", "/bin/echo", "RAN"])
run("usage: --pid1 with no --", [GUARD, "--pid1", "/bin/echo", "RAN"])
run("usage: --pid1 twice", [GUARD, "--pid1", "--pid1", "--", "/bin/echo", "RAN"])
run("exec: a missing program", [GUARD, "--", "/nonexistent/program"])
run("exec: a name, not a path", [GUARD, "--", "echo", "RAN"], env={"PATH": "/bin:/usr/bin"})
run("no_new_privs: refused", [GUARD, "--", "/bin/echo", "RAN"], preexec=answer_prctl(PR_SET_NO_NEW_PRIVS, RET_ERRNO | EPERM))
run("install: refused", [GUARD, "--", "/bin/echo", "RAN"], preexec=answer_prctl(PR_SET_SECCOMP, RET_ERRNO | EPERM))
run("self-check: the filter ignored", [GUARD, "--", "/bin/echo", "RAN"], preexec=answer_prctl(PR_SET_SECCOMP, RET_ERRNO | 0))
run("self-check: the filter ignored under a profile that refuses unshare", [GUARD, "--", "/bin/echo", "RAN"],
    preexec=answer_prctl(PR_SET_SECCOMP, RET_ERRNO | 0, refuse_unshare=True))
