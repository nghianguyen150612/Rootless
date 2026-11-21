/* SPDX-License-Identifier: GPL-3.0-only */
#define _GNU_SOURCE
#include "rootless/native.h"
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

static int write_map(const char *path, const char *value) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return errno;
    size_t len = strlen(value);
    ssize_t n = write(fd, value, len);
    int e = n < 0 ? errno : (size_t)n == len ? 0 : EIO;
    close(fd);
    return e;
}

/* Called only by the standalone launcher. Successful exec replaces it, retaining
   the terminal, process group, PID and inherited descriptors. */
int rl_exec_rootfs(const char *root, const char *path, char *const argv[], char *const envp[]) {
    uid_t uid = getuid();
    gid_t gid = getgid();
    int rootfd = open(root, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (rootfd < 0) return errno;
    if (unshare(CLONE_NEWUSER) == 0) {
        char map[80];
        int e = write_map("/proc/self/setgroups", "deny");
        if (e && e != ENOENT) { close(rootfd); return e; }
        snprintf(map, sizeof(map), "0 %lu 1\n", (unsigned long)uid);
        e = write_map("/proc/self/uid_map", map);
        if (e) { close(rootfd); return e; }
        snprintf(map, sizeof(map), "0 %lu 1\n", (unsigned long)gid);
        e = write_map("/proc/self/gid_map", map);
        if (e) { close(rootfd); return e; }
    }
    /* A caller with existing capabilities may succeed even if user namespaces
       are disabled. Mount namespace and private propagation are mandatory. */
    if (unshare(CLONE_NEWNS) || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) ||
        fchdir(rootfd) || chroot(".") || chdir("/")) {
        int e = errno; close(rootfd); return e;
    }
    close(rootfd);
    execve(path, argv, envp);
    return errno;
}
