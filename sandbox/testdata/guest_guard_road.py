"""The road of finding noexec-setting-3, run as the guest: make a private view of the system (a user and a mount
namespace of the code's own), mount a folder of its own there (a tmpfs, which carries no no-execute mark), write a
program into it and start it. Under gVisor without the guest guard every step succeeds (the design's measurement);
behind the guard the first step is refused, under every runtime. One JSON line: {"road": {step: result}}, each result 0
for done or minus the errno, "ran" the started program's output; the road stops at the first step that fails.
"""
import ctypes
import json
import os
import shutil
import subprocess

libc = ctypes.CDLL(None, use_errno=True)
libc.unshare.restype = ctypes.c_int
libc.mount.restype = ctypes.c_int
CLONE_NEWNS, CLONE_NEWUSER = 0x00020000, 0x10000000


def road():
    seen = {}
    uid, gid = os.getuid(), os.getgid()
    if libc.unshare(ctypes.c_int(CLONE_NEWUSER | CLONE_NEWNS)) != 0:
        seen["unshare"] = -ctypes.get_errno()
        return seen
    seen["unshare"] = 0
    try:
        with open("/proc/self/setgroups", "w") as f:
            f.write("deny")
        with open("/proc/self/uid_map", "w") as f:
            f.write("0 %d 1" % uid)
        with open("/proc/self/gid_map", "w") as f:
            f.write("0 %d 1" % gid)
        seen["map"] = 0
    except OSError as e:
        seen["map"] = -e.errno
        return seen
    folder = "/tmp/plimsoll-road"
    os.makedirs(folder, exist_ok=True)
    if libc.mount(b"none", folder.encode(), b"tmpfs", ctypes.c_ulong(0), None) != 0:
        seen["mount"] = -ctypes.get_errno()
        return seen
    seen["mount"] = 0
    prog = os.path.join(folder, "echo")
    shutil.copy("/bin/echo", prog)  # busybox's, on Alpine: run as "echo", it is echo
    os.chmod(prog, 0o755)
    try:
        p = subprocess.run([prog, "RAN"], capture_output=True, text=True)
        seen["ran"] = p.stdout.strip() or "exit %d" % p.returncode
    except OSError as e:
        seen["ran"] = -e.errno
    return seen


print(json.dumps({"road": road()}), flush=True)
