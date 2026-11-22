"""Does a real kernel take the guest guard's filter, and answer as its table says? Run as the guest.

The Go test (TestDockerGuestGuardFilterInstalls, sandbox/guestguard_docker_test.go) prepends two
lines to this file: FILTER, the committed bytes of sandbox/internal/guestguard's filter for this
machine, and CASES, the requests to try. Each case runs twice, each time in a child process of its
own so a kill ends only that child: once as it is ("control"), and once after the child installs
the filter with prctl(PR_SET_NO_NEW_PRIVS) and prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER), the
two calls the guard will make ("guarded"). One JSON line per run: {"case", "mode", "exit", "ret"},
where exit is the child's exit status (negative: the signal that ended it, -31 for SIGSYS, which
is how seccomp kills) and ret is what the request returned (minus the errno when refused), absent
when the child was killed. A child that could not install the filter exits 4 with the reason in
"error".

TestDockerGuestGuardProgram (sandbox/guestguard_program_docker_test.go) prepends MODES too: "control"
alone in a container without the guard, "behind" alone when this file runs behind the guard program,
where the child installs nothing because the guard already has.
"""
import ctypes
import json
import os

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
libc.prctl.restype = ctypes.c_int

PR_SET_NO_NEW_PRIVS, PR_SET_SECCOMP, SECCOMP_MODE_FILTER = 38, 22, 2


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


program = ctypes.create_string_buffer(FILTER, len(FILTER))  # noqa: F821 (prepended by the test)
fprog = SockFprog(len(FILTER) // 8, ctypes.cast(program, ctypes.c_void_p))  # noqa: F821


def install():
    u = ctypes.c_ulong
    if libc.prctl(ctypes.c_int(PR_SET_NO_NEW_PRIVS), u(1), u(0), u(0), u(0)) != 0:
        return "PR_SET_NO_NEW_PRIVS: errno %d" % ctypes.get_errno()
    if libc.prctl(ctypes.c_int(PR_SET_SECCOMP), u(SECCOMP_MODE_FILTER), ctypes.byref(fprog), u(0), u(0)) != 0:
        return "PR_SET_SECCOMP: errno %d" % ctypes.get_errno()
    return None


def attempt(case, mode):
    guarded = mode == "guarded"
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        try:
            if guarded:
                err = install()
                if err:
                    os.write(w, json.dumps({"error": err}).encode())
                    os._exit(4)
            args = [ctypes.c_long(case["nr"])] + [ctypes.c_long(a) for a in case["args"]]
            ret = libc.syscall(*args)
            errno = ctypes.get_errno()
            if case.get("forks") and ret == 0:
                os._exit(0)  # the copy a clone that was let through made: end it at once
            if case.get("forks") and ret > 0:
                os.waitpid(ret, 0)
            os.write(w, json.dumps({"ret": ret if ret >= 0 else -errno}).encode())
        except BaseException as e:  # report, never let the child run on into the parent's loop
            os.write(w, json.dumps({"error": repr(e)}).encode())
            os._exit(3)
        os._exit(0)
    os.close(w)
    out = b""
    while True:
        chunk = os.read(r, 4096)
        if not chunk:
            break
        out += chunk
    os.close(r)
    _, status = os.waitpid(pid, 0)
    row = {"case": case["name"], "mode": mode, "exit": os.waitstatus_to_exitcode(status)}
    if out:
        row.update(json.loads(out))
    print(json.dumps(row), flush=True)


for case in CASES:  # noqa: F821 (prepended by the test)
    for mode in globals().get("MODES", ("control", "guarded")):
        attempt(case, mode)
