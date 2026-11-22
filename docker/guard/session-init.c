// plimsoll-session-init: PID 1 of a session container on a provider whose container
// runtime offers no init of its own (`wslc container run` has no --init). It starts
// the session's main process, reaps every orphan the kernel hands to PID 1, and exits
// with the main process's status. The container then has the shape docker's --init
// gives a docker session: PID 1 and one main process, and no dead entries left behind
// by the processes the cleanup after each call kills (a dead process stays listed until
// its parent collects its exit status, and an orphan's parent is PID 1).
//
// Usage, as the container's command: plimsoll-session-init /ABSOLUTE/PATH [ARG...]
//
// Exit 2: not PID 1, or no absolute command path (nothing started). Exit 1: the main
// process could not be started, or no child is left to wait for. Exit 127: the main
// process could not be executed. Otherwise the main process's exit status, or 128 plus
// the number of the signal that ended it.
//
// It installs no signal handler, and it reads no environment variable. Under runc, no
// process in the container can signal it (the kernel drops a signal to a namespace's
// PID 1 that has no handler for it). Under gVisor that does not hold: a signal sent to
// it from inside the container or by docker ends it (measured 2026-11-21),
// which opens nothing on docker, since the guest can already
// end its session by ending the main process, which runs as the same user.
#define _GNU_SOURCE
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (getpid() != 1 || argc < 2 || argv[1][0] != '/') {
        return 2;
    }
    pid_t child = fork();
    if (child < 0) {
        return 1;
    }
    if (child == 0) {
        execv(argv[1], &argv[1]);
        _exit(127);
    }
    for (;;) {
        int status = 0;
        pid_t pid = waitpid(-1, &status, 0);
        if (pid < 0) {
            if (errno == EINTR) {
                continue;
            }
            return 1; // ECHILD: no child left to wait for
        }
        if (pid != child) {
            continue; // an orphan, now reaped
        }
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        }
        if (WIFSIGNALED(status)) {
            return 128 + WTERMSIG(status);
        }
    }
}
