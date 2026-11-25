/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef ROOTLESS_VFS_H
#define ROOTLESS_VFS_H

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#define RL_VFS_FILTER_CAPACITY 96

struct rl_vfs {
    int rootfd;
    int cwdfd;
    int tracee_fds;
    int execfd;
    pid_t guest;
    bool launch_pending;
};

int rl_vfs_probe(int rootfd);
int rl_vfs_open_executable(int rootfd, const char *path);
int rl_vfs_start(struct rl_vfs *vfs, int rootfd, int execfd, pid_t guest);
void rl_vfs_stop(struct rl_vfs *vfs);
size_t rl_vfs_filter(struct sock_filter *code);
int rl_vfs_dispatch(struct rl_vfs *vfs, int listener, const struct seccomp_notif *request);

#endif
