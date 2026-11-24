/* Safe tracee spawner for the dishonest-execution-substrate supervisor.
 *
 * We do fork()/PTRACE_TRACEME/raise(SIGSTOP)/execv entirely in C so that no
 * Haskell RTS code runs in the forked child before execv (running the GHC
 * runtime between fork and exec can deadlock the allocator). The parent gets
 * the tracee pid back and drives it with ptrace from Haskell.
 *
 * On success the child is stopped (SIGSTOP) just before execv; the parent
 * waits for that stop, sets ptrace options, then resumes it into execv.
 */
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>

pid_t spawn_tracee(char *const argv[]) {
    pid_t pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        execv(argv[0], argv);
        _exit(127);
    }
    return pid;
}
