/* SPDX-License-Identifier: GPL-3.0-only */
#define _GNU_SOURCE
#include "rootless/probe.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/filter.h>
#include <linux/seccomp.h>
#if defined(__has_include)
# if __has_include(<linux/openat2.h>)
#  include <linux/openat2.h>
#  define RL_HAS_OPEN_HOW 1
# endif
#endif
#endif

#if !defined(RL_HAS_OPEN_HOW)
struct rl_open_how { uint64_t flags, mode, resolve; };
#define RL_OPEN_HOW struct rl_open_how
#else
#define RL_OPEN_HOW struct open_how
#endif
#ifndef RESOLVE_IN_ROOT
#define RESOLVE_IN_ROOT 0x10
#endif

const char *rl_status_name(rl_status status) {
    switch (status) {
    case RL_SUPPORTED: return "supported";
    case RL_UNSUPPORTED: return "unsupported";
    case RL_PERMISSION_DENIED: return "permission_denied";
    case RL_UNKNOWN: return "unknown";
    case RL_NOT_TESTED: return "not_tested";
    }
    return "unknown";
}

rl_status rl_status_from_errno(int number) {
    if (number == 0) return RL_SUPPORTED;
    if (number == EPERM || number == EACCES) return RL_PERMISSION_DENIED;
    if (number == ENOSYS || number == EINVAL || number == EOPNOTSUPP)
        return RL_UNSUPPORTED;
    return RL_UNKNOWN;
}

typedef int (*probe_attempt)(void);

/* Child reports errno; parent never installs filters, unshares or changes memory. */
static int isolated(probe_attempt attempt, rl_status *status) {
    int ends[2];
    if (pipe(ends) != 0) {
        *status = RL_UNKNOWN;
        return errno;
    }
    pid_t pid = fork();
    if (pid == -1) {
        const int saved = errno;
        close(ends[0]);
        close(ends[1]);
        *status = RL_UNKNOWN;
        return saved;
    }
    if (pid == 0) {
        close(ends[0]);
        int number = attempt();
        ssize_t n;
        do { n = write(ends[1], &number, sizeof(number)); } while (n == -1 && errno == EINTR);
        close(ends[1]);
        _exit(n == (ssize_t)sizeof(number) ? 0 : 1);
    }
    close(ends[1]);
    int number = 0;
    ssize_t n;
    do { n = read(ends[0], &number, sizeof(number)); } while (n == -1 && errno == EINTR);
    close(ends[0]);
    int wstatus = 0;
    pid_t waited;
    do { waited = waitpid(pid, &wstatus, 0); } while (waited == -1 && errno == EINTR);
    if (waited != pid || n != (ssize_t)sizeof(number) ||
        !WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0 || number < 0) {
        *status = RL_UNKNOWN;
        return EPROTO;
    }
    *status = rl_status_from_errno(number);
    return number;
}

static int attempt_userns(void) {
#ifdef CLONE_NEWUSER
    return unshare(CLONE_NEWUSER) == 0 ? 0 : errno;
#else
    return ENOSYS;
#endif
}

static int attempt_mountns(void) {
#if defined(CLONE_NEWUSER) && defined(CLONE_NEWNS)
    if (unshare(CLONE_NEWUSER) != 0) return errno;
    return unshare(CLONE_NEWNS) == 0 ? 0 : errno;
#else
    return ENOSYS;
#endif
}

static int attempt_openat2(void) {
#if defined(SYS_openat2) && defined(O_PATH)
    RL_OPEN_HOW how = { .flags = (uint64_t)(O_PATH | O_CLOEXEC),
                         .mode = 0, .resolve = RESOLVE_IN_ROOT };
    int fd = (int)syscall(SYS_openat2, AT_FDCWD, ".", &how, sizeof(how));
    if (fd < 0) return errno;
    close(fd);
    return 0;
#else
    return ENOSYS;
#endif
}

static int seccomp_install(const struct sock_fprog *program) {
#if defined(SYS_seccomp) && defined(SECCOMP_SET_MODE_FILTER)
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) return errno;
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, program) == -1) return errno;
    return 0;
#else
    (void)program;
    return ENOSYS;
#endif
}

static int attempt_seccomp_filter(void) {
    struct sock_filter instructions[] = { BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW) };
    struct sock_fprog program = { .len = 1, .filter = instructions };
    return seccomp_install(&program);
}

static volatile sig_atomic_t saw_sigsys;
static void sigsys_handler(int signum, siginfo_t *info, void *context) {
    (void)context;
    if (signum == SIGSYS && info != NULL) saw_sigsys = 1;
}

static int attempt_seccomp_trap(void) {
#if defined(SYS_getpid) && defined(SECCOMP_RET_TRAP)
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsys_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSYS, &sa, NULL) != 0) return errno;
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getpid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program = { .len = 4, .filter = instructions };
    int result = seccomp_install(&program);
    if (result != 0) return result;
    saw_sigsys = 0;
    errno = 0;
    long value = syscall(SYS_getpid);
    (void)value; /* SIGSYS return register state is architecture-dependent. */
    return saw_sigsys == 1 ? 0 : EPROTO;
#else
    return ENOSYS;
#endif
}

static int attempt_ptrace(void) {
    return ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0 ? 0 : errno;
}

static int attempt_rw_rx(void) {
    void *region = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (region == MAP_FAILED) return errno;
    int number = mprotect(region, 4096, PROT_READ | PROT_EXEC) == 0 ? 0 : errno;
    munmap(region, 4096);
    return number;
}

static rl_capability capability(const char *name, rl_status status, int number,
                                const char *detail) {
    rl_capability item = { name, status, number, detail };
    return item;
}

static rl_capability isolated_capability(const char *name, probe_attempt fn,
                                         const char *detail) {
    rl_status status;
    int number = isolated(fn, &status);
    return capability(name, status, number, detail);
}

size_t rl_collect_probes(rl_capability *out, size_t capacity) {
    if (out == NULL || capacity < RL_PROBE_COUNT) return RL_PROBE_COUNT;
    struct utsname u;
    if (uname(&u) != 0)
        out[0] = capability("host.aarch64", RL_UNKNOWN, errno, "uname failed");
    else
        out[0] = capability("host.aarch64", !strcmp(u.machine, "aarch64") ?
                            RL_SUPPORTED : RL_UNSUPPORTED, 0, "host ISA, not guest execution");
    const char *prefix = getenv("PREFIX");
    out[1] = capability("host.termux_prefix",
        (prefix != NULL && strstr(prefix, "/files/usr") != NULL) ?
            RL_SUPPORTED : RL_UNSUPPORTED, 0, "heuristic; does not validate filesystem access");
    out[2] = isolated_capability("kernel.user_namespace", attempt_userns,
                                  "unshare(CLONE_NEWUSER) in a child");
    out[3] = isolated_capability("kernel.mountns_with_userns", attempt_mountns,
                                  "unshare(CLONE_NEWUSER), then CLONE_NEWNS");
    out[4] = isolated_capability("kernel.openat2_in_root", attempt_openat2,
                                  "openat2('.', RESOLVE_IN_ROOT); not full VFS");
    out[5] = isolated_capability("kernel.seccomp_filter", attempt_seccomp_filter,
                                  "install allow-all filter in a child only");
    out[6] = isolated_capability("kernel.seccomp_trap", attempt_seccomp_trap,
                                  "SIGSYS on getpid; return register is unspecified");
    out[7] = isolated_capability("kernel.ptrace_traceme", attempt_ptrace,
                                  "TRACEME only; not full tracing compatibility");
    out[8] = isolated_capability("memory.rw_to_rx", attempt_rw_rx,
                                  "mprotect permission only; no file execution");
    out[9] = capability("kernel.real_chroot", RL_NOT_TESTED, 0,
                         "requires P1 namespace/capability validation");
    out[10] = capability("android.app_data_exec", RL_NOT_TESTED, 0,
                          "requires real Android/Termux execution test");
    FILE *f = fopen("/proc/self/attr/current", "r");
    if (f == NULL) {
        out[11] = capability("android.selinux_context", rl_status_from_errno(errno),
                              errno, "could not read /proc/self/attr/current");
    } else {
        char c;
        const int n = fscanf(f, "%c", &c);
        fclose(f);
        out[11] = capability("android.selinux_context", n == 1 ? RL_SUPPORTED : RL_UNKNOWN,
                              0, "readable (context value not exposed in P0)");
    }
    return RL_PROBE_COUNT;
}
