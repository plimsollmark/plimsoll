/* The guest guard: puts the filter of guest_filter.h on itself, proves it is in force, then
 * becomes the program named after "--", with the arguments and environment it was given.
 *
 *     guard -- PROGRAM [ARG...]          PROGRAM is a path: it is not looked up in PATH
 *     guard --pid1 -- PROGRAM [ARG...]   the same, as process 1 of a container (below)
 *
 * It reads no setting and opens no file; "--pid1" is its one option. Built statically against
 * musl by build.sh beside it. Every failure starts nothing and exits with its own code, after one
 * line on standard error, "plimsoll guest guard: STEP: DETAIL":
 *
 *     120  usage         the arguments are not "[--pid1] -- PROGRAM [ARG...]", or --pid1 is
 *                        given to a process that is not process 1
 *     121  no_new_privs  prctl(PR_SET_NO_NEW_PRIVS) failed, or did not hold
 *     122  install       prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) refused the filter
 *     123  self-check    the filter is not in force: the self-check request of guest_filter.h
 *                        (unshare with every low flag bit set) was not answered with the errno
 *                        only this filter gives (EHWPOISON), or unshare(0) was not refused
 *                        with EPERM
 *     124  exec          execve of PROGRAM failed (missing, not runnable); with --pid1 also
 *                        when the signal mask could not be set or the fork failed
 *
 * (The codes avoid 125 to 127, which docker run and shells use for their own failures.)
 *
 * With --pid1 (a docker session's container, finding guest-guard-10) the guard does not become
 * PROGRAM: process 1 must collect every process that ends in the container (an orphan is handed
 * to it), and a program that does not would fill the container's process limit with zombies.
 * Behind its own filter, so nothing in the container runs outside it, it blocks every signal
 * the C library's sigfillset names (musl's leaves out 32 to 34, the three it keeps for itself,
 * and no program can block SIGKILL or SIGSTOP), starts PROGRAM as its one child (the mask put
 * back, so the child gets what process 1 was given) and then only waits for signals:
 *
 *   - SIGCHLD: it collects every process that has ended; when the child itself has ended, it
 *     exits with the child's status (128 plus the signal for a child a signal ended), which ends
 *     the container.
 *   - A signal whose default would end a process and whose record names no sender (si_pid 0)
 *     with the code of kill or of the kernel: it exits with 128 plus the signal, and the kernel
 *     ends every other process of the container, as docker's kill would after its wait. A
 *     signal from outside the container carries that record (the kernel names no sender inside
 *     it), the one docker stop sends among them; so do some a process of the container can
 *     cause, such as the I/O signal of a descriptor it makes process 1 the owner of, or SIGXCPU
 *     after it sets process 1's CPU limit (finding guest-guard-34).
 *   - Any other signal it takes: nothing. It passes no signal on to any process and writes
 *     nothing.
 *
 * So code of the container can end its own session through process 1, as it always could by
 * ending PROGRAM. Process 1 does not promise more: under gVisor a SIGSTOP, a SIGKILL or signal
 * 32 or 33 from inside the container stops or ends it (finding guest-guard-35), and while code
 * keeps a SIGTERM of its own pending, the one docker stop sends is dropped against it, so docker
 * stop waits its whole timeout (finding guest-guard-36).
 *
 * Its error output stays docker's, written to only on the failures above. */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <signal.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "guest_filter.h"

static void fail(int code, const char *step, int err) {
	char line[96] = "plimsoll guest guard: ";
	char num[12];
	int n = sizeof num;
	strcat(line, step);
	strcat(line, ": errno ");
	num[--n] = '\0';
	do {
		num[--n] = (char)('0' + err % 10);
		err /= 10;
	} while (err > 0 && n > 0);
	strcat(line, num + n);
	strcat(line, "\n");
	ssize_t w = write(STDERR_FILENO, line, strlen(line));
	(void)w;
	_exit(code);
}

/* ends_a_process: whether sig's default action ends a process (every signal but those whose
 * default is to be ignored, to stop or to continue). */
static int ends_a_process(int sig) {
	switch (sig) {
	case SIGCHLD:
	case SIGCONT:
	case SIGTSTP:
	case SIGTTIN:
	case SIGTTOU:
	case SIGURG:
	case SIGWINCH:
		return 0;
	}
	return 1;
}

/* status_of: the exit code that passes on a child's wait status. */
static int status_of(int st) {
	return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

/* be_pid1: process 1's loop (--pid1, above). Never returns. */
static void be_pid1(char **prog, char **envp) {
	sigset_t all, given;
	sigfillset(&all);
	if (sigprocmask(SIG_SETMASK, &all, &given) != 0)
		fail(124, "exec: the signal mask", errno);
	pid_t child = fork();
	if (child < 0)
		fail(124, "exec: fork", errno);
	if (child == 0) {
		sigprocmask(SIG_SETMASK, &given, 0);
		execve(prog[0], prog, envp);
		fail(124, "exec", errno);
	}
	for (;;) {
		siginfo_t si;
		int sig = sigwaitinfo(&all, &si);
		if (sig == SIGCHLD) {
			int st;
			pid_t ended;
			while ((ended = waitpid(-1, &st, WNOHANG)) > 0)
				if (ended == child)
					_exit(status_of(st));
		} else if (sig > 0 && si.si_pid == 0 && (si.si_code == SI_USER || si.si_code == SI_KERNEL) && ends_a_process(sig)) {
			_exit(128 + sig);
		}
	}
}

int main(int argc, char **argv, char **envp) {
	int pid1 = argc >= 2 && strcmp(argv[1], "--pid1") == 0;
	int sep = pid1 ? 2 : 1;
	if (argc < sep + 2 || strcmp(argv[sep], "--") != 0)
		fail(120, "usage: guard [--pid1] -- PROGRAM [ARG...]", EINVAL);
	if (pid1 && getpid() != 1)
		fail(120, "usage: --pid1 is for process 1 only", EINVAL);
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
		fail(121, "no_new_privs", errno);
	if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
		fail(121, "no_new_privs: not set after setting it", EPERM);
	struct sock_fprog prog = {
		.len = GUEST_FILTER_LEN,
		.filter = (struct sock_filter *)guest_filter,
	};
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0)
		fail(122, "install", errno);
	/* A refusal by another filter is not proof: plimsoll's shipped profile refuses unshare
	 * too, so a guard whose install did nothing would pass a check that only asks for a
	 * refusal (finding guest-guard-13). This answer is the guard's filter's alone. */
	errno = 0;
	if (syscall(GUEST_SELF_CHECK_NR, GUEST_SELF_CHECK_ARG0, 0UL, 0UL, 0UL, 0UL, 0UL) != -1 || errno != GUEST_SELF_CHECK_ERRNO)
		fail(123, "self-check: the guard's own answer did not come back", errno);
	errno = 0;
	if (unshare(0) != -1 || errno != EPERM)
		fail(123, "self-check: unshare(0) was not refused", errno);
	if (pid1)
		be_pid1(argv + sep + 1, envp);
	execve(argv[sep + 1], argv + sep + 1, envp);
	fail(124, "exec", errno);
}
