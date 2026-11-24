/* SPDX-License-Identifier: GPL-3.0-only */
#define _GNU_SOURCE
#include "rootless/native.h"
#include "namespace.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <sched.h>
#include <stdio.h>
#include <sys/mount.h>
#include <unistd.h>

static int enter_user_namespace(const char **operation) {
    uid_t uid = geteuid();
    gid_t gid = getegid();
    *operation = "unshare(CLONE_NEWUSER)";
    if (unshare(CLONE_NEWUSER) != 0) {
        int error = errno;
        /* Existing capabilities can suffice on hosts that disable user namespaces. */
        if (!rl_effective_capability(CAP_SYS_ADMIN) &&
            !rl_effective_capability(CAP_SYS_CHROOT))
            return 0;
        return error;
    }

    *operation = "deny setgroups";
    int error = rl_write_namespace_map("/proc/self/setgroups", "deny");
    if (error && error != ENOENT) return error;

    char mapping[80];
    *operation = "write uid_map";
    snprintf(mapping, sizeof(mapping), "0 %lu 1\n", (unsigned long)uid);
    error = rl_write_namespace_map("/proc/self/uid_map", mapping);
    if (error) return error;

    *operation = "write gid_map";
    snprintf(mapping, sizeof(mapping), "0 %lu 1\n", (unsigned long)gid);
    return rl_write_namespace_map("/proc/self/gid_map", mapping);
}

static int enter_root(int rootfd, const char **operation) {
    int error = enter_user_namespace(operation);
    if (error) return error;

    *operation = "unshare(CLONE_NEWNS)";
    if (unshare(CLONE_NEWNS) != 0) return errno;
    *operation = "make mount propagation private";
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) return errno;

    *operation = "fchdir(rootfs)";
    if (fchdir(rootfd) != 0) return errno;
    *operation = "chroot";
    if (chroot(".") != 0) return errno;
    *operation = "chdir(/)";
    if (chdir("/") != 0) return errno;

    return 0;
}

int rl_exec_rootfs(const char *root, const char *path, char *const argv[],
                   char *const envp[], const char **operation) {
    *operation = "open rootfs";
    int rootfd = open(root, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (rootfd < 0) return errno;

    int error = enter_root(rootfd, operation);
    close(rootfd);
    if (error) return error;

    /* The kernel resolves the executable and its PT_INTERP against the new root. */
    *operation = "execve in rootfs";
    execve(path, argv, envp);
    return errno;
}
