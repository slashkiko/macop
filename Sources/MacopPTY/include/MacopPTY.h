#include <sys/types.h>
#include <sys/ioctl.h>

int macop_forkpty_exec(const char *path, char *const argv[], char *const envp[],
                       struct winsize *size, int *master, pid_t *pid);

/* Installs async-signal-safe SIGINT/SIGTERM handlers that write the signal
 * number to a CLOEXEC nonblocking pipe. Returns the read descriptor or -1.
 * macop_signal_pipe_restore restores handlers and closes both descriptors. */
int macop_signal_pipe_install(void);
void macop_signal_pipe_restore(void);
