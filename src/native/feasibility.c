/* SPDX-License-Identifier: GPL-3.0-only */
#define _GNU_SOURCE
#include "rootless/native.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int map_file(const char *path, const char *value) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return errno;
    size_t len = strlen(value);
    ssize_t n = write(fd, value, len);
    int error = n < 0 ? errno : (size_t)n == len ? 0 : EIO;
    close(fd);
    return error;
}
static int chroot_cap(void) {
#ifdef SYS_capget
    struct __user_cap_header_struct h = { .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0 };
    struct __user_cap_data_struct d[2] = {{0}};
    if (syscall(SYS_capget, &h, d) != 0) return errno;
    return (d[CAP_SYS_CHROOT / 32].effective & (1U << (CAP_SYS_CHROOT % 32))) ? 0 : EPERM;
#else
    return ENOSYS;
#endif
}
static void result(rl_capability *p, int error) {
    p->error_number = error;
    p->status = rl_status_from_errno(error);
}

int rl_native_probes(rl_capability out[RL_NATIVE_PROBE_COUNT]) {
    static const char *names[] = {"current.cap_sys_chroot", "namespace.user",
        "namespace.setgroups_deny", "namespace.uid_map", "namespace.gid_map",
        "namespace.mount", "namespace.mount_private", "namespace.cap_sys_chroot", "namespace.chroot"};
    static const char *details[] = {"capget effective capability in child", "unshare(CLONE_NEWUSER)",
        "write deny to /proc/self/setgroups", "map namespace uid 0 to caller uid",
        "map namespace gid 0 to caller gid", "unshare(CLONE_NEWNS) after mapping",
        "mount MS_REC|MS_PRIVATE on /", "capget effective capability after mapping",
        "chroot(empty temporary directory), chdir(/) in isolated child; no guest launched"};
    for (int i = 0; i < RL_NATIVE_PROBE_COUNT; ++i)
        out[i] = (rl_capability){names[i], RL_NOT_TESTED, 0, details[i]};
    char dir[] = "/tmp/rl-chroot-XXXXXX";
    /* Termux has no /tmp. Respect TMPDIR for the disposable probe directory. */
    char *root = NULL;
    const char *tmp = getenv("TMPDIR");
    if (tmp == NULL) tmp = "/tmp";
    size_t len = strlen(tmp) + sizeof(dir);
    root = malloc(len);
    if (!root) return ENOMEM;
    snprintf(root, len, "%s/rl-chroot-XXXXXX", tmp);
    if (!mkdtemp(root)) { int e = errno; free(root); return e; }
    int ends[2];
    if (pipe2(ends, O_CLOEXEC) != 0) { int e = errno; rmdir(root); free(root); return e; }
    uid_t uid = getuid();
    gid_t gid = getgid();
    pid_t pid = fork();
    if (pid == 0) {
        close(ends[0]);
        result(&out[0], chroot_cap());
        result(&out[1], unshare(CLONE_NEWUSER) == 0 ? 0 : errno);
        if (out[1].error_number) goto done;
        result(&out[2], map_file("/proc/self/setgroups", "deny"));
        /* Older kernels lack setgroups control; absence is recorded but mapping is valid. */
        if (out[2].error_number && out[2].error_number != ENOENT) goto done;
        char mapping[80];
        snprintf(mapping, sizeof(mapping), "0 %lu 1\n", (unsigned long)uid);
        result(&out[3], map_file("/proc/self/uid_map", mapping));
        if (out[3].error_number) goto done;
        snprintf(mapping, sizeof(mapping), "0 %lu 1\n", (unsigned long)gid);
        result(&out[4], map_file("/proc/self/gid_map", mapping));
        if (out[4].error_number) goto done;
        result(&out[5], unshare(CLONE_NEWNS) == 0 ? 0 : errno);
        if (out[5].error_number) goto done;
        result(&out[6], mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0 ? 0 : errno);
        if (out[6].error_number) goto done;
        result(&out[7], chroot_cap());
        if (out[7].error_number) goto done;
        result(&out[8], chroot(root) == 0 ? 0 : errno);
        if (!out[8].error_number && chdir("/") != 0) result(&out[8], errno);
    done:;
        /* Only scalar results cross the pipe; no child pointer values. */
        int values[RL_NATIVE_PROBE_COUNT * 2];
        for (int i = 0; i < RL_NATIVE_PROBE_COUNT; ++i) {
            values[2*i] = out[i].status; values[2*i+1] = out[i].error_number;
        }
        _exit(write(ends[1], values, sizeof(values)) == sizeof(values) ? 0 : 1);
    }
    int error = pid < 0 ? errno : 0;
    close(ends[1]);
    if (pid > 0) {
        int values[RL_NATIVE_PROBE_COUNT * 2], status;
        ssize_t n;
        do { n = read(ends[0], values, sizeof(values)); } while (n < 0 && errno == EINTR);
        pid_t waited;
        do { waited = waitpid(pid, &status, 0); } while (waited < 0 && errno == EINTR);
        if (n != sizeof(values) || waited != pid || !WIFEXITED(status) || WEXITSTATUS(status)) error = EPROTO;
        else for (int i = 0; i < RL_NATIVE_PROBE_COUNT; ++i) {
            out[i].status = (rl_status)values[2*i]; out[i].error_number = values[2*i+1];
        }
    }
    close(ends[0]);
    rmdir(root);
    free(root);
    return error;
}
