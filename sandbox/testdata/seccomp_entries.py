"""Which system call entries does the seccomp profile let through? Run as the guest, on x86-64.

The kernel takes system calls through three entries on x86-64: the native one (the syscall
instruction with a 64-bit number), the 32-bit one (int 0x80 with i386 numbers, which has
socketcall and ipc, the two calls that hide their arguments in memory) and x32 (the syscall
instruction with the number's bit 30 set). A filter that lists only x86-64 kills a call through
either of the other two; a filter that lists them evaluates the call there, and libseccomp
rewrites a rule on socket into a socketcall rule that no longer reads the address family
(docs/seccomp.md, "Architectures").

Each case runs in a child process of its own, so a kill ends only that child. One JSON line per
case: {"case", "entry", "exit", "ret"}, where exit is the child's exit status (negative: the signal
that ended it, -31 for SIGSYS, which is how seccomp kills) and ret is what the call returned (a
descriptor or a count when it was let through, minus the errno when it was refused), absent when
the child was killed. A socket that was created also reports its family (SO_DOMAIN).
"""
import json
import subprocess
import sys

CHILD = r'''
import ctypes, json, struct, sys

libc = ctypes.CDLL(None, use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
PROT_RWX, MAP_PRIVATE, MAP_ANON, MAP_32BIT = 7, 0x02, 0x20, 0x40
# Below 4 GiB, so a 32-bit call can address it: code first, then the data a call points at.
page = libc.mmap(None, 8192, PROT_RWX, MAP_PRIVATE | MAP_ANON | MAP_32BIT, -1, 0)
if page in (None, ctypes.c_void_p(-1).value):
    print(json.dumps({"error": "mmap"}))
    sys.exit(3)
data = page + 4096

def imm(v):
    return struct.pack("<I", v & 0xFFFFFFFF)

def put(blob):
    ctypes.memmove(data, blob, len(blob))
    return data

# In a child made by clone (its return value 0), end it at once with the native exit_group, so
# the copy never returns into this program.
CHILD_EXIT = b"\x85\xc0\x75\x09\xb8\xe7\x00\x00\x00\x31\xff\x0f\x05"

def i386(nr, a, child_exit):
    # push rbx; eax = nr; ebx, ecx, edx, esi = the arguments; int 0x80; pop rbx; ret
    code = b"\x53\xb8" + imm(nr) + b"\xbb" + imm(a[0]) + b"\xb9" + imm(a[1]) + b"\xba" + imm(a[2]) + b"\xbe" + imm(a[3]) + b"\xcd\x80"
    return code + (CHILD_EXIT if child_exit else b"") + b"\x5b\xc3"

def x86_64(nr, a, child_exit):
    # eax = nr; edi, esi, edx, r10d = the arguments; syscall; ret
    code = b"\xb8" + imm(nr) + b"\xbf" + imm(a[0]) + b"\xbe" + imm(a[1]) + b"\xba" + imm(a[2]) + b"\x41\xba" + imm(a[3]) + b"\x0f\x05"
    return code + (CHILD_EXIT if child_exit else b"") + b"\xc3"

X32 = 0x40000000
AT_FDCWD = -100
AF_UNIX, AF_INET, AF_NETLINK, AF_ALG, AF_VSOCK = 1, 2, 16, 38, 40
SOCK_STREAM, SOCK_RAW, SOCK_SEQPACKET = 1, 3, 5
SYS_SOCKET = 1  # socketcall's call number for socket
SHMGET = 23     # ipc's call number for shmget
IPC_CREAT = 0o1000
CLONE_NEWUSER, SIGCHLD = 0x10000000, 17
READ_IMPLIES_EXEC = 0x0400000
S_IFREG, S_IFIFO = 0o100000, 0o010000

def sockargs(family, kind):
    return put(struct.pack("<III", family, kind, 0))

def path(name):
    return put(name.encode() + b"\0")

name = sys.argv[1]
cases = {
    # The 32-bit entry, i386 numbers.
    "i386 getpid":                         lambda: (i386, 20, [0, 0, 0, 0]),
    "i386 socketcall socket AF_UNIX":      lambda: (i386, 102, [SYS_SOCKET, sockargs(AF_UNIX, SOCK_STREAM), 0, 0]),
    "i386 socketcall socket AF_INET":      lambda: (i386, 102, [SYS_SOCKET, sockargs(AF_INET, SOCK_STREAM), 0, 0]),
    "i386 socketcall socket AF_NETLINK":   lambda: (i386, 102, [SYS_SOCKET, sockargs(AF_NETLINK, SOCK_RAW), 0, 0]),
    "i386 socketcall socket AF_ALG":       lambda: (i386, 102, [SYS_SOCKET, sockargs(AF_ALG, SOCK_SEQPACKET), 0, 0]),
    "i386 socketcall socket AF_VSOCK":     lambda: (i386, 102, [SYS_SOCKET, sockargs(AF_VSOCK, SOCK_STREAM), 0, 0]),
    "i386 socket AF_UNIX":                 lambda: (i386, 359, [AF_UNIX, SOCK_STREAM, 0, 0]),
    "i386 socket AF_VSOCK":                lambda: (i386, 359, [AF_VSOCK, SOCK_STREAM, 0, 0]),
    "i386 ipc shmget":                     lambda: (i386, 117, [SHMGET, 0, 4096, IPC_CREAT | 0o600]),
    "i386 shmget":                         lambda: (i386, 395, [0, 4096, IPC_CREAT | 0o600, 0]),
    "i386 clone CLONE_NEWUSER":            lambda: (i386, 120, [CLONE_NEWUSER | SIGCHLD, 0, 0, 0]),
    "i386 personality READ_IMPLIES_EXEC":  lambda: (i386, 136, [READ_IMPLIES_EXEC, 0, 0, 0]),
    "i386 mknodat FIFO":                   lambda: (i386, 297, [AT_FDCWD, path("/tmp/entries-i386-fifo"), S_IFIFO | 0o600, 0]),
    "i386 mknodat regular file":           lambda: (i386, 297, [AT_FDCWD, path("/tmp/entries-i386-file"), S_IFREG | 0o600, 0]),
    "i386 mknod regular file":             lambda: (i386, 14, [path("/tmp/entries-i386-mknod"), S_IFREG | 0o600, 0, 0]),
    # The x32 entry: x86-64 numbers with bit 30 set (x32's own numbers start at 512).
    "x32 getpid":                          lambda: (x86_64, X32 | 39, [0, 0, 0, 0]),
    "x32 socket AF_UNIX":                  lambda: (x86_64, X32 | 41, [AF_UNIX, SOCK_STREAM, 0, 0]),
    "x32 socket AF_VSOCK":                 lambda: (x86_64, X32 | 41, [AF_VSOCK, SOCK_STREAM, 0, 0]),
    "x32 shmget":                          lambda: (x86_64, X32 | 29, [0, 4096, IPC_CREAT | 0o600, 0]),
    "x32 clone CLONE_NEWUSER":             lambda: (x86_64, X32 | 56, [CLONE_NEWUSER | SIGCHLD, 0, 0, 0]),
    "x32 personality READ_IMPLIES_EXEC":   lambda: (x86_64, X32 | 135, [READ_IMPLIES_EXEC, 0, 0, 0]),
    "x32 mknodat regular file":            lambda: (x86_64, X32 | 259, [AT_FDCWD, path("/tmp/entries-x32-file"), S_IFREG | 0o600, 0]),
    # The native entry, for comparison: the profile's rules as written.
    "x86_64 socket AF_UNIX":               lambda: (x86_64, 41, [AF_UNIX, SOCK_STREAM, 0, 0]),
    "x86_64 socket AF_INET":               lambda: (x86_64, 41, [AF_INET, SOCK_STREAM, 0, 0]),
    "x86_64 socket AF_NETLINK":            lambda: (x86_64, 41, [AF_NETLINK, SOCK_RAW, 0, 0]),
    "x86_64 socket AF_ALG":                lambda: (x86_64, 41, [AF_ALG, SOCK_SEQPACKET, 0, 0]),
    "x86_64 socket AF_VSOCK":              lambda: (x86_64, 41, [AF_VSOCK, SOCK_STREAM, 0, 0]),
    "x86_64 mknodat regular file":         lambda: (x86_64, 259, [AT_FDCWD, path("/tmp/entries-x86_64-file"), S_IFREG | 0o600, 0]),
}
if name == "--list":
    print(json.dumps(list(cases)))
    sys.exit(0)
gen, nr, args = cases[name]()
code = gen(nr, args, "clone" in name)
ctypes.memmove(page, code, len(code))
r = ctypes.CFUNCTYPE(ctypes.c_int)(page)()
out = {"ret": r}
if r >= 0 and "socket" in name:
    # Read through the C library (Python's socket object refuses some families, AF_ALG among
    # them): SO_DOMAIN, or the family getsockname reports where a profile refuses that option.
    family, size = ctypes.c_int(-1), ctypes.c_uint(4)
    if libc.getsockopt(r, 1, 39, ctypes.byref(family), ctypes.byref(size)) != 0:  # SOL_SOCKET, SO_DOMAIN
        addr, size = ctypes.create_string_buffer(128), ctypes.c_uint(128)
        if libc.getsockname(r, addr, ctypes.byref(size)) == 0 and size.value >= 2:
            family = ctypes.c_int(struct.unpack("<H", addr.raw[:2])[0])
    out["family"] = family.value
    libc.close(r)
print(json.dumps(out))
'''


def main():
    listed = subprocess.run([sys.executable, "-I", "-c", CHILD, "--list"], capture_output=True, timeout=20, check=True)
    for name in json.loads(listed.stdout):
        p = subprocess.run([sys.executable, "-I", "-c", CHILD, name], capture_output=True, timeout=20)
        row = {"case": name, "entry": name.split(" ", 1)[0], "exit": p.returncode}
        try:
            row.update(json.loads(p.stdout.decode().strip().splitlines()[-1]))
        except (ValueError, IndexError):
            if p.returncode >= 0:
                row["stderr"] = p.stderr.decode(errors="replace")[-300:]
        print(json.dumps(row), flush=True)


main()
