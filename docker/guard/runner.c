// Loaded only into the project runner before Node reads its plan. A step runs
// under the same uid, so the runner must deny ptrace-style access to its /proc
// descriptors and memory regardless of the host's Yama setting.
#define _GNU_SOURCE
#include <sys/prctl.h>
#include <unistd.h>

__attribute__((constructor)) static void protect_runner(void) {
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 ||
        prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0) {
        static const char message[] = "plimsoll runner: cannot set non-dumpable state\n";
        ssize_t written = write(STDERR_FILENO, message, sizeof(message) - 1);
        (void)written;
        _exit(125);
    }
}
