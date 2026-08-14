#include "MacopPTY.h"
#include <stdlib.h>
#include <unistd.h>
#include <util.h>

int macop_forkpty_exec(const char *path, char *const argv[], char *const envp[],
                       struct winsize *size, int *master, pid_t *pid) {
    int local_master = -1;
    pid_t child = forkpty(&local_master, NULL, NULL, size);
    if (child < 0) return -1;
    if (child == 0) {
        execve(path, argv, envp);
        _exit(127);
    }
    *master = local_master;
    *pid = child;
    return 0;
}
