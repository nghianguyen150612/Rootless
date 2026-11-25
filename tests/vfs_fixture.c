/* SPDX-License-Identifier: GPL-3.0-only */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "VFS fixture line %d: %s (errno=%d %s)\n", \
                __LINE__, #condition, errno, strerror(errno)); \
        exit(1); \
    } \
} while (0)

#define FAILS(expression, error) CHECK((expression) == -1 && errno == (error))

static void check_read(int fd) {
    CHECK(fd >= 0);
    char buffer[16] = {0};
    CHECK(read(fd, buffer, sizeof(buffer)) == 7);
    CHECK(!strcmp(buffer, "marker\n"));
    CHECK(close(fd) == 0);
}

static void check_cwd(const char *expected) {
    char path[64];
    CHECK(syscall(SYS_getcwd, path, sizeof(path)) == (long)strlen(expected) + 1);
    CHECK(!strcmp(path, expected));
}

int main(int argc, char **argv, char **envp) {
    CHECK(argc == 2);
    if (!strcmp(argv[1], "signal")) {
        raise(SIGTERM);
        return 120;
    }
    if (!strcmp(argv[1], "child")) {
        check_cwd("/a");
        check_read(open("marker", O_RDONLY));
        return 42;
    }
    int reference = !strcmp(argv[1], "reference");
    check_cwd("/");
    CHECK(chdir("/a") == 0);
    check_cwd("/a");
    check_read(open("./marker", O_RDONLY));
    check_read(open("../../abs-link", O_RDONLY));
    FAILS(syscall(SYS_getcwd, argv, 1), ERANGE);

    int dir = open("/a/b", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(dir >= 0 && fcntl(dir, F_GETFD) == FD_CLOEXEC);
    int duplicate = dup(dir);
    CHECK(duplicate >= 0 && fcntl(duplicate, F_GETFD) == 0);
    CHECK(close(dir) == 0);
    check_read(openat(duplicate, "../marker", O_RDONLY));
    check_read(openat(duplicate, "jump/marker", O_RDONLY));
    CHECK(fchdir(duplicate) == 0);
    check_cwd("/a/b");
    CHECK(chdir("..") == 0);
    check_cwd("/a");
    int raw = openat(duplicate, "jump/marker", O_RDONLY | O_CLOEXEC);
    CHECK(raw >= 0 && fcntl(raw, F_GETFD) == FD_CLOEXEC);

    struct open_how how = { .flags = O_RDONLY };
    check_read((int)syscall(SYS_openat2, duplicate, "../marker", &how, sizeof(how)));
    how.resolve = RESOLVE_NO_SYMLINKS;
    FAILS(syscall(SYS_openat2, duplicate, "jump/marker", &how, sizeof(how)), ELOOP);
    FAILS(syscall(SYS_openat2, duplicate, "../marker", &how, 8), EINVAL);
    struct { struct open_how how; unsigned long extension; } extended = { .extension = 1 };
    FAILS(syscall(SYS_openat2, duplicate, "../marker", &extended, sizeof(extended)), E2BIG);

    struct stat st;
    CHECK(fstatat(duplicate, "../marker", &st, 0) == 0 && S_ISREG(st.st_mode) && st.st_size == 7);
    CHECK(fstatat(raw, "", &st, AT_EMPTY_PATH) == 0 && S_ISREG(st.st_mode));
    CHECK(fstatat(duplicate, "jump", &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(st.st_mode));
    CHECK(fstatat(duplicate, "jump", &st, 0) == 0 && S_ISDIR(st.st_mode));
    struct statx sx;
    CHECK(statx(duplicate, "../marker", 0, STATX_TYPE | STATX_SIZE, &sx) == 0);
    CHECK(S_ISREG(sx.stx_mode) && sx.stx_size == 7);
    CHECK(syscall(SYS_faccessat, duplicate, "../marker", F_OK) == 0);
    CHECK(syscall(SYS_faccessat2, duplicate, "../marker", R_OK, AT_EACCESS) == 0);
    FAILS(syscall(SYS_faccessat2, duplicate, "missing", F_OK, 0), ENOENT);
    char target[8] = {0};
    CHECK(readlinkat(duplicate, "jump", target, sizeof(target)) == 2 && !strcmp(target, "/a"));
    char truncated[2] = {0, 'x'};
    FAILS(readlinkat(duplicate, "../marker", target, sizeof(target)), EINVAL);
    CHECK(readlinkat(duplicate, "jump", truncated, 1) == 1 &&
          truncated[0] == '/' && truncated[1] == 'x');

    check_read(openat(-1, "/a/marker", O_RDONLY));
    FAILS(openat(-1, "marker", O_RDONLY), EBADF);
    FAILS(openat(raw, "marker", O_RDONLY), ENOTDIR);
    FAILS(fchdir(raw), ENOTDIR);
    FAILS(open("absent", O_RDONLY), ENOENT);
    FAILS(open("", O_RDONLY), ENOENT);
    FAILS(open("/abs-link", O_RDONLY | O_NOFOLLOW), ELOOP);
    FAILS(syscall(SYS_openat, AT_FDCWD, 1L, O_RDONLY, 0), EFAULT);
    FAILS(syscall(SYS_newfstatat, AT_FDCWD, "marker", 1L, 0), EFAULT);
    char too_long[4097];
    memset(too_long, 'x', sizeof(too_long) - 1);
    too_long[sizeof(too_long) - 1] = '\0';
    FAILS(open(too_long, O_RDONLY), ENAMETOOLONG);
    CHECK(close(raw) == 0 && close(duplicate) == 0);

    puts("cwd=/a dirfd=ok metadata=ok links=ok errno=ok");
    char *child_argv[] = { "/fixture", "child", NULL };
    if (reference) {
        pid_t child = fork();
        CHECK(child >= 0);
        if (!child) {
            execve("/fixture", child_argv, envp);
            _exit(120);
        }
        int status;
        CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 42);
        puts("child=42");
    } else {
        FAILS(open("marker", O_WRONLY | O_TRUNC), EROFS);
        FAILS(mkdirat(AT_FDCWD, "should-not-exist", 0755), EROFS);
        FAILS(unlinkat(AT_FDCWD, "marker", 0), EROFS);
        FAILS(open("/regular-fifo", O_RDONLY), EOPNOTSUPP);
        FAILS(open("/a", O_PATH | O_DIRECTORY), EOPNOTSUPP);
        const char *external_fd = getenv("RL_P4_EXTERNAL_FD");
        const char *internal_fd = getenv("RL_P4_INTERNAL_FD");
        CHECK(external_fd && internal_fd);
        int internal = atoi(internal_fd);
        check_read(openat(internal, "marker", O_RDONLY));
        CHECK(fchdir(internal) == 0);
        check_cwd("/a");
        int external = atoi(external_fd);
        FAILS(openat(external, "anything", O_RDONLY), EXDEV);
        FAILS(fchdir(external), EXDEV);
        FAILS(fork(), EOPNOTSUPP);
        FAILS(execve("/fixture", child_argv, envp), EOPNOTSUPP);
        how.resolve = RESOLVE_BENEATH;
        FAILS(syscall(SYS_openat2, AT_FDCWD, "marker", &how, sizeof(how)), EOPNOTSUPP);
        puts("readonly=ok inherited-dirfd=ok external-dirfd=blocked fork/exec=unsupported");
    }
    return 23;
}
