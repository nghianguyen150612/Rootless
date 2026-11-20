/* SPDX-License-Identifier: GPL-3.0-only */
#define _GNU_SOURCE
#include "rootless/native.h"
#include <assert.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static void check_results(rl_capability *p) {
    for (int i = 0; i < RL_NATIVE_PROBE_COUNT; ++i) {
        assert(p[i].name && p[i].detail);
        assert(p[i].status >= RL_SUPPORTED && p[i].status <= RL_NOT_TESTED);
        if (p[i].status == RL_SUPPORTED) assert(p[i].error_number == 0);
        if (i >= 3 && p[i-1].status == RL_NOT_TESTED) assert(p[i].status == RL_NOT_TESTED);
    }
}
int main(void) {
    assert(rl_select_engine(0, 0) == RL_ENGINE_NATIVE_DIRECT);
    assert(rl_select_engine(0, 1) == RL_ENGINE_UNSUPPORTED);
    assert(rl_select_engine(EACCES, 0) == RL_ENGINE_UNSUPPORTED);
    assert(rl_select_engine(ENOEXEC, 0) == RL_ENGINE_UNSUPPORTED);
    rl_capability p[RL_NATIVE_PROBE_COUNT];
    char cwd[4096], after[4096];
    assert(getcwd(cwd, sizeof(cwd)));
    assert(rl_native_probes(p) == 0);
    check_results(p);
    assert(getcwd(after, sizeof(after)));
    assert(!strcmp(cwd, after));
    assert(access(cwd, F_OK) == 0);
    /* Force a real namespace permission failure in an isolated test child.
       No filters are installed in CTest or in the ordinary probe caller. */
    const int blocked[] = { SYS_unshare, SYS_chroot, SYS_mount };
    for (unsigned trial = 0; trial < sizeof(blocked)/sizeof(blocked[0]); ++trial) {
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        struct sock_filter ins[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, blocked[trial], 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
        };
        struct sock_fprog prog = { .len = 4, .filter = ins };
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
            prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) _exit(77);
        assert(rl_native_probes(p) == 0);
        int step = trial == 0 ? 1 : trial == 1 ? 8 : 6;
        if (p[step].status == RL_NOT_TESTED) _exit(77);
        assert(p[step].status == RL_PERMISSION_DENIED && p[step].error_number == EPERM);
        for (int i = step + 1; i < RL_NATIVE_PROBE_COUNT; ++i) assert(p[i].status == RL_NOT_TESTED);
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status));
    if (WEXITSTATUS(status) == 77) printf("injected denial syscall %d: NOT_RUN (prerequisite denied)\n", blocked[trial]);
    else assert(WEXITSTATUS(status) == 0);
    }
    puts("native engine selection and isolated feasibility: PASS");
    return 0;
}
