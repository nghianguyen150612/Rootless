/* SPDX-License-Identifier: GPL-3.0-only */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--missing") == 0) {
        errno = 0;
        int fd = openat(AT_FDCWD, "/missing.txt", O_RDONLY);
        int saved = errno;
        if (fd >= 0) {
            close(fd);
            return 10;
        }
        if (saved != ENOENT) return 11;
        printf("missing errno=%d getpid=%ld\n", saved, (long)getpid());
        return 0;
    }

    char buffer[64] = {0};
    int fd = openat(AT_FDCWD, "/marker.txt", O_RDONLY);
    if (fd < 0) return 20;
    ssize_t n = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (n < 0) return 21;
    int relative = openat(AT_FDCWD, "relative.txt", O_RDONLY);
    if (relative < 0) return 22;
    char relative_buffer[64] = {0};
    ssize_t rn = read(relative, relative_buffer, sizeof(relative_buffer) - 1);
    close(relative);
    if (rn < 0) return 23;
    printf("absolute=%s relative=%s getpid=%ld\n", buffer,
           relative_buffer, (long)getpid());
    return 0;
}
