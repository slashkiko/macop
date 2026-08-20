#include "MacopPTY.h"
#include <stdlib.h>
#include <unistd.h>
#include <util.h>
#include <fcntl.h>
#include <signal.h>

static int macop_signal_pipe[2] = { -1, -1 };
static struct sigaction macop_old_int;
static struct sigaction macop_old_term;
static int macop_signal_installed = 0;

static void macop_signal_handler(int signal_number) {
    unsigned char value = (unsigned char)signal_number;
    if (macop_signal_pipe[1] != -1) {
        (void)write(macop_signal_pipe[1], &value, sizeof(value));
    }
}

int macop_signal_pipe_install(void) {
    if (macop_signal_installed) return macop_signal_pipe[0];
    if (pipe(macop_signal_pipe) != 0) return -1;
    if (fcntl(macop_signal_pipe[0], F_SETFD, FD_CLOEXEC) == -1 ||
        fcntl(macop_signal_pipe[1], F_SETFD, FD_CLOEXEC) == -1 ||
        fcntl(macop_signal_pipe[0], F_SETFL, O_NONBLOCK) == -1 ||
        fcntl(macop_signal_pipe[1], F_SETFL, O_NONBLOCK) == -1) {
        close(macop_signal_pipe[0]); close(macop_signal_pipe[1]);
        macop_signal_pipe[0] = macop_signal_pipe[1] = -1;
        return -1;
    }
    struct sigaction action;
    action.sa_handler = macop_signal_handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    if (sigaction(SIGINT, &action, &macop_old_int) != 0) {
        if (macop_signal_pipe[0] != -1) close(macop_signal_pipe[0]);
        if (macop_signal_pipe[1] != -1) close(macop_signal_pipe[1]);
        macop_signal_pipe[0] = macop_signal_pipe[1] = -1;
        return -1;
    }
    if (sigaction(SIGTERM, &action, &macop_old_term) != 0) {
        (void)sigaction(SIGINT, &macop_old_int, NULL);
        if (macop_signal_pipe[0] != -1) close(macop_signal_pipe[0]);
        if (macop_signal_pipe[1] != -1) close(macop_signal_pipe[1]);
        macop_signal_pipe[0] = macop_signal_pipe[1] = -1;
        return -1;
    }
    macop_signal_installed = 1;
    return macop_signal_pipe[0];
}

void macop_signal_pipe_restore(void) {
    if (!macop_signal_installed) return;
    (void)sigaction(SIGINT, &macop_old_int, NULL);
    (void)sigaction(SIGTERM, &macop_old_term, NULL);
    close(macop_signal_pipe[0]); close(macop_signal_pipe[1]);
    macop_signal_pipe[0] = macop_signal_pipe[1] = -1;
    macop_signal_installed = 0;
}

int macop_forkpty_exec(const char *path, char *const argv[], char *const envp[],
                       struct winsize *size, int *master, pid_t *pid) {
    int local_master = -1;
    pid_t child = forkpty(&local_master, NULL, NULL, size);
    if (child < 0) return -1;
    if (child == 0) {
        long maximum_fd = sysconf(_SC_OPEN_MAX);
        if (maximum_fd < 4) maximum_fd = 1024;
        for (int fd = 3; fd < maximum_fd; fd++) (void)close(fd);
        execve(path, argv, envp);
        _exit(127);
    }
    *master = local_master;
    *pid = child;
    return 0;
}
