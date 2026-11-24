/* SPDX-License-Identifier: GPL-3.0-only */
#define _GNU_SOURCE
#include "namespace.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int rl_write_namespace_map(const char *path, const char *value) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return errno;
    size_t len = strlen(value);
    ssize_t n;
    do n = write(fd, value, len); while (n < 0 && errno == EINTR);
    int error = n < 0 ? errno : (size_t)n == len ? 0 : EIO;
    close(fd);
    return error;
}
int rl_effective_capability(unsigned int capability) {
#ifdef SYS_capget
    if (capability >= 64) return EINVAL;
    struct __user_cap_header_struct h = { .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0 };
    struct __user_cap_data_struct d[2] = {{0}};
    if (syscall(SYS_capget, &h, d) != 0) return errno;
    return (d[capability / 32].effective & (1U << (capability % 32))) ? 0 : EPERM;
#else
    (void)capability;
    return ENOSYS;
#endif
}
