"""Behind the guest guard program: does ordinary work go on, and does the filter stay?

TestDockerGuestGuardProgram (sandbox/guestguard_program_docker_test.go) appends this file to
guest_guard_attempts.py and runs both behind the guard, which docker starts first. Each check
prints one JSON line {"check": name, ...} with what it saw; the Go test decides. A check that
could change this process (a filter added, a namespace made if the guard failed) runs in a child.
"""
import ctypes
import json
import os
import subprocess
import sys
import threading

libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.restype = ctypes.c_int
libc.unshare.restype = ctypes.c_int
libc.ptrace.restype = ctypes.c_long
u = ctypes.c_ulong

PR_GET_SECCOMP, PR_SET_SECCOMP, PR_SET_NO_NEW_PRIVS, PR_GET_NO_NEW_PRIVS = 21, 22, 38, 39
SECCOMP_MODE_DISABLED, SECCOMP_MODE_FILTER = 0, 2
CLONE_NEWUSER = 0x10000000
GUARD = GUEST_GUARD  # noqa: F821 (prepended by the test: where the provider mounts the guard)

STATE = r'''
import ctypes, json
libc = ctypes.CDLL(None, use_errno=True)
u = ctypes.c_ulong
def call(r):
    return r if r >= 0 else -ctypes.get_errno()
print(json.dumps({
    "seccomp": call(libc.prctl(ctypes.c_int(21), u(0), u(0), u(0), u(0))),
    "nnp": call(libc.prctl(ctypes.c_int(39), u(0), u(0), u(0), u(0))),
    "unshare": call(libc.unshare(ctypes.c_int(0x10000000))),
    "ptrace": call(libc.ptrace(ctypes.c_long(0), 0, 0, 0)),
    "self_check": call(libc.unshare(ctypes.c_int(-1))),
}))
'''


def call(r):
    return r if r >= 0 else -ctypes.get_errno()


def state():
    """What this process sees: its filter mode, no-new-privileges, and two refused requests (the
    same reads as STATE, which a started program runs)."""
    return {
        "seccomp": call(libc.prctl(ctypes.c_int(PR_GET_SECCOMP), u(0), u(0), u(0), u(0))),
        "nnp": call(libc.prctl(ctypes.c_int(PR_GET_NO_NEW_PRIVS), u(0), u(0), u(0), u(0))),
        "unshare": call(libc.unshare(ctypes.c_int(CLONE_NEWUSER))),
        "ptrace": call(libc.ptrace(ctypes.c_long(0), 0, 0, 0)),
        # unshare with every low flag bit set: EHWPOISON (133) comes from the guard's filter alone.
        "self_check": call(libc.unshare(ctypes.c_int(-1))),
    }


def report(name, **seen):
    print(json.dumps(dict(check=name, **seen)), flush=True)


def in_child(fn):
    """Runs fn in a forked child and returns what it returned (a dict), or how the child died."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        try:
            os.write(w, json.dumps(fn()).encode())
        except BaseException as e:
            os.write(w, json.dumps({"error": repr(e)}).encode())
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
    res = json.loads(out) if out else {}
    res["child_exit"] = os.waitstatus_to_exitcode(status)
    return res


report("state", **state())

box = {}
t = threading.Thread(target=lambda: box.update(state()))
t.start()
t.join()
report("thread", **box)

r, w = os.pipe()
os.write(w, b"through a pipe")
os.close(w)
piped = os.read(r, 64).decode()
os.close(r)
sh = subprocess.run(["/bin/sh", "-c", "echo through | cat"], capture_output=True, text=True)
report("pipe and child", pipe=piped, shell_out=sh.stdout, shell_exit=sh.returncode)

started = subprocess.run([sys.executable, "-I", "-c", STATE], capture_output=True, text=True)
report("started program", exit=started.returncode, stderr=started.stderr, **json.loads(started.stdout or "{}"))
nested = subprocess.run(["/bin/sh", "-c", '"$0" -I -c "$1"', sys.executable, STATE], capture_output=True, text=True)
report("program started by a started program", exit=nested.returncode, stderr=nested.stderr, **json.loads(nested.stdout or "{}"))


def weaker():
    allow_all = (ctypes.c_ubyte * 8)(0x06, 0, 0, 0, 0x00, 0x00, 0xFF, 0x7F)  # ret SECCOMP_RET_ALLOW

    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]

    prog = SockFprog(1, ctypes.cast(allow_all, ctypes.c_void_p))
    installed = call(libc.prctl(ctypes.c_int(PR_SET_SECCOMP), u(SECCOMP_MODE_FILTER), ctypes.byref(prog), u(0), u(0)))
    return dict(installed=installed, **state())


report("a weaker filter added", **in_child(weaker))


def take_off():
    disable = call(libc.prctl(ctypes.c_int(PR_SET_SECCOMP), u(SECCOMP_MODE_DISABLED), u(0), u(0), u(0)))
    clear_nnp = call(libc.prctl(ctypes.c_int(PR_SET_NO_NEW_PRIVS), u(0), u(0), u(0), u(0)))
    return dict(disable=disable, clear_nnp=clear_nnp, **state())


report("taking the filter off", **in_child(take_off))


def write_guard():
    seen = {}
    try:
        os.close(os.open(GUARD, os.O_WRONLY))
        seen["open_for_write"] = 0
    except OSError as e:
        seen["open_for_write"] = -e.errno
    try:
        os.chmod(GUARD, 0o777)
        seen["chmod"] = 0
    except OSError as e:
        seen["chmod"] = -e.errno
    return seen


report("the guard file", **in_child(write_guard))
