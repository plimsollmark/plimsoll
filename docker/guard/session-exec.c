// plimsoll-session-exec: kept in the repository, built into no image and on no path. The
// WSL containers provider now runs a session call as its exec's own arguments,
// `/usr/bin/env -i -- NAME=value ... COMMAND ARG...` (sandbox/wslc/sessionexec.go), which
// needs no program of plimsoll's in the container. What follows describes the helper as
// it was last written, should a provider need it again: it must then be installed
// root:root mode 0711, which gVisor release-20260907.0 does not run.
//
// It runs one command of a session call, given as its own arguments, with exactly the
// call's environment, started as
//
//   wslc container exec --user G:G --workdir /work -e PLSMENV_0 ... -e PLSMENV_<N-1> C
//       /usr/local/bin/plimsoll-session-exec N /ABSOLUTE/COMMAND [ARG...]
//
// where each PLSMENV_<i> holds one NAME=value of the call's environment (the provider
// passes the values in wslc.exe's own environment through WSLENV, so none is on the
// Windows command line). The container's own variables (the image's) are dropped: the
// command gets the N strings and nothing else. Standard input is left alone: it is the
// call's payload and nothing of the helper's.
//
// Why the command does not travel on standard input (as it did until 2026-11-21): the
// exec's input pipe belongs to the guest's uid, so a process an earlier call left
// behind could open it through /proc/PID/fd/0 and write a command of its own ahead of
// the real one (measured on WSL under runc, 1 exec in 60). Arguments and the environment
// are fixed by the exec itself before this program starts; no other process can change
// them.
//
// Why it must be installed root:root, mode 0711 (execute, not read): the kernel then
// makes the process non-dumpable at execve (fs/exec.c, would_dump), so from its first
// instruction no other process of the guest's uid can open its /proc/PID/fd entries,
// read its memory or attach to it. It checks this and refuses to run if it started
// dumpable (a readable install), so a wrong install fails every call instead of quietly
// reopening the window. Once it replaces itself with the command, the command is
// dumpable again, as every exec's command is (runc, E2B and docker do the same).
//
// It is statically linked (no dynamic loader, so no variable can load code into it),
// searches no PATH, opens no file and reads no input.
//
// Refused, exit 125, nothing run: the process started dumpable or could not be made
// non-dumpable; N not a decimal number from 0 to 4096 written without leading zeros; no
// command, or a command that is not an absolute path; a PLSMENV_<i> for some i below N
// missing or given twice; a PLSMENV_ variable whose index is not one of 0 to N-1 (written
// without leading zeros); a value with no '=' or starting with one.
// Exit 126: the command could not be executed. Otherwise the command's own exit status.
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#define MAX_ENVS 4096u
#define PREFIX "PLSMENV_"
#define PREFIX_LEN (sizeof(PREFIX) - 1)

extern char **environ;

// The command's environment, NULL-terminated; entries point into this process's own.
static char *envs[MAX_ENVS + 1];

// fail writes one line to standard error and exits. Ignoring SIGPIPE first keeps the
// exit status the caller reads from becoming a signal death when standard error is a
// closed pipe; the process is about to exit, so nothing inherits it.
static _Noreturn void fail(const char *line, size_t len, int status) {
    signal(SIGPIPE, SIG_IGN);
    while (len > 0) {
        ssize_t n = write(STDERR_FILENO, line, len);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            break;
        }
        line += n;
        len -= (size_t)n;
    }
    _exit(status);
}

static _Noreturn void refuse(void) {
    static const char line[] = "plimsoll-session-exec: refused\n";
    fail(line, sizeof(line) - 1, 125);
}

// parse_index reads a decimal number from s up to the character end (exclusive):
// digits only, no leading zero unless it is "0", at most max. It returns -1 for
// anything else.
static long parse_index(const char *s, const char *end, unsigned long max) {
    if (s == end || (s[0] == '0' && end - s > 1)) {
        return -1;
    }
    unsigned long v = 0;
    for (const char *p = s; p < end; p++) {
        if (*p < '0' || *p > '9') {
            return -1;
        }
        v = v * 10u + (unsigned long)(*p - '0');
        if (v > max) {
            return -1;
        }
    }
    return (long)v;
}

int main(int argc, char **argv) {
    // 1 is SUID_DUMP_USER: a readable install. Anything else (0, or 2 when the system
    // dumps setuid programs) means the kernel made this process non-dumpable at execve.
    if (prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 1) {
        static const char line[] = "plimsoll-session-exec: started dumpable (is it installed mode 0711?)\n";
        fail(line, sizeof(line) - 1, 125);
    }
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 || prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0) {
        static const char line[] = "plimsoll-session-exec: cannot set non-dumpable state\n";
        fail(line, sizeof(line) - 1, 125);
    }

    if (argc < 3 || argv[2][0] != '/') {
        refuse();
    }
    long n = parse_index(argv[1], argv[1] + strlen(argv[1]), MAX_ENVS);
    if (n < 0) {
        refuse();
    }

    for (char **e = environ; *e != NULL; e++) {
        if (strncmp(*e, PREFIX, PREFIX_LEN) != 0) {
            continue; // the container's own variable: dropped
        }
        const char *digits = *e + PREFIX_LEN;
        const char *eq = strchr(digits, '=');
        if (eq == NULL) {
            refuse();
        }
        long i = parse_index(digits, eq, MAX_ENVS);
        if (i < 0 || i >= n || envs[i] != NULL) {
            refuse();
        }
        char *value = (char *)eq + 1; // NAME=value, the call's string
        if (value[0] == '=' || strchr(value, '=') == NULL) {
            refuse();
        }
        envs[i] = value;
    }
    for (long i = 0; i < n; i++) {
        if (envs[i] == NULL) {
            refuse();
        }
    }
    envs[n] = NULL;

    execve(argv[2], &argv[2], envs);

    // "plimsoll-session-exec: exec failed " and the errno number, in decimal.
    int err = errno;
    char line[64] = "plimsoll-session-exec: exec failed ";
    size_t len = strlen(line);
    char digits[16];
    size_t nd = 0;
    unsigned int v = err < 0 ? 0u : (unsigned int)err;
    do {
        digits[nd++] = (char)('0' + v % 10u);
        v /= 10u;
    } while (v > 0 && nd < sizeof(digits));
    while (nd > 0) {
        line[len++] = digits[--nd];
    }
    line[len++] = '\n';
    fail(line, len, 126);
}
