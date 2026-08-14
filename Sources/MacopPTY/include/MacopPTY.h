#include <sys/types.h>
#include <sys/ioctl.h>

int macop_forkpty_exec(const char *path, char *const argv[], char *const envp[],
                       struct winsize *size, int *master, pid_t *pid);
