/* SPDX-License-Identifier: GPL-3.0-only */
#define _GNU_SOURCE
#include "vfs.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/openat2.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#if (defined(__aarch64__) || defined(__x86_64__)) && defined(SYS_openat2) && \
    defined(SYS_faccessat2) && defined(SYS_statx) && defined(STATX_MNT_ID) && \
    defined(SYS_execveat)

#ifndef SECCOMP_ADDFD_FLAG_SEND
#define SECCOMP_ADDFD_FLAG_SEND (1UL << 1)
#endif

/* Kernel open flags on LP64. glibc defines O_LARGEFILE as zero on LP64. */
#if defined(__aarch64__)
#define RL_O_LARGEFILE (1U << 17)
#else
#define RL_O_LARGEFILE (1U << 15)
#endif

#ifndef SYS_clone3
#define SYS_clone3 435
#endif
#ifndef RESOLVE_CACHED
#define RESOLVE_CACHED 0x20
#endif

enum operation {
    OPEN, OPENAT, OPENAT2, STAT, LSTAT, FSTATAT, STATX, ACCESS, FACCESSAT,
    FACCESSAT2, READLINK, READLINKAT, CHDIR, FCHDIR, GETCWD, EXECVEAT,
    PROCESS_UNSUPPORTED, MUTATION_UNSUPPORTED
};

static const struct {
    int number;
    enum operation operation;
} intercepted[] = {
    { SYS_openat, OPENAT },
    { SYS_openat2, OPENAT2 },
    { SYS_newfstatat, FSTATAT },
    { SYS_statx, STATX },
    { SYS_faccessat, FACCESSAT },
    { SYS_faccessat2, FACCESSAT2 },
    { SYS_readlinkat, READLINKAT },
    { SYS_chdir, CHDIR },
    { SYS_fchdir, FCHDIR },
    { SYS_getcwd, GETCWD },
    { SYS_execveat, EXECVEAT },
    { SYS_execve, PROCESS_UNSUPPORTED },
    { SYS_clone, PROCESS_UNSUPPORTED },
    { SYS_clone3, PROCESS_UNSUPPORTED },
    { SYS_mkdirat, MUTATION_UNSUPPORTED },
    { SYS_unlinkat, MUTATION_UNSUPPORTED },
    { SYS_renameat2, MUTATION_UNSUPPORTED },
    { SYS_linkat, MUTATION_UNSUPPORTED },
    { SYS_symlinkat, MUTATION_UNSUPPORTED },
    { SYS_mknodat, MUTATION_UNSUPPORTED },
    { SYS_truncate, MUTATION_UNSUPPORTED },
#ifdef SYS_renameat
    { SYS_renameat, MUTATION_UNSUPPORTED },
#endif
#ifdef SYS_open
    { SYS_open, OPEN },
    { SYS_stat, STAT },
    { SYS_lstat, LSTAT },
    { SYS_access, ACCESS },
    { SYS_readlink, READLINK },
    { SYS_fork, PROCESS_UNSUPPORTED },
    { SYS_vfork, PROCESS_UNSUPPORTED },
    { SYS_mkdir, MUTATION_UNSUPPORTED },
    { SYS_rmdir, MUTATION_UNSUPPORTED },
    { SYS_unlink, MUTATION_UNSUPPORTED },
    { SYS_rename, MUTATION_UNSUPPORTED },
    { SYS_link, MUTATION_UNSUPPORTED },
    { SYS_symlink, MUTATION_UNSUPPORTED },
    { SYS_creat, MUTATION_UNSUPPORTED },
    { SYS_mknod, MUTATION_UNSUPPORTED },
#endif
};

_Static_assert(2 * (sizeof(intercepted) / sizeof(intercepted[0])) <= RL_VFS_FILTER_CAPACITY,
               "VFS syscall table exceeds filter storage");

size_t rl_vfs_filter(struct sock_filter *code) {
    size_t n = 0;
    for (size_t i = 0; i < sizeof(intercepted) / sizeof(intercepted[0]); ++i) {
        code[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                  intercepted[i].number, 0, 1);
        code[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);
    }
    return n;
}

static int rooted_open(int rootfd, const char *path, uint64_t flags, uint64_t resolve) {
    struct open_how how = {
        .flags = flags | O_CLOEXEC,
        .resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV | resolve
    };
    int fd = (int)syscall(SYS_openat2, rootfd, path, &how, sizeof(how));
    return fd < 0 ? -errno : fd;
}

static int identity(int fd, struct statx *st) {
    if (syscall(SYS_statx, fd, "", AT_EMPTY_PATH, STATX_INO | STATX_MNT_ID, st) < 0)
        return errno;
    if ((st->stx_mask & (STATX_INO | STATX_MNT_ID)) != (STATX_INO | STATX_MNT_ID))
        return EOPNOTSUPP;
    return 0;
}

static int same_directory(int a, int b) {
    struct statx left, right;
    int error = identity(a, &left);
    if (!error) error = identity(b, &right);
    if (error) return error;
    return left.stx_ino == right.stx_ino && left.stx_mnt_id == right.stx_mnt_id
        && left.stx_dev_major == right.stx_dev_major && left.stx_dev_minor == right.stx_dev_minor
        ? 0 : ESTALE;
}

static void proc_fd_name(int fd, char path[64]) {
    snprintf(path, 64, "/proc/self/fd/%d", fd);
}

static int directory_name(int fd, char path[PATH_MAX]) {
    char proc[64];
    proc_fd_name(fd, proc);
    ssize_t n = readlink(proc, path, PATH_MAX);
    if (n < 0) return errno;
    if (n == PATH_MAX) return ENAMETOOLONG;
    if (!n || path[0] != '/') return EXDEV;
    path[n] = '\0';
    return 0;
}

int rl_vfs_probe(int rootfd) {
    int fd = rooted_open(rootfd, ".", O_PATH | O_DIRECTORY, 0);
    if (fd < 0) return -fd;
    struct statx st;
    int error = identity(fd, &st);
    if (!error && syscall(SYS_faccessat2, fd, "", X_OK, AT_EMPTY_PATH | AT_EACCESS) < 0)
        error = errno;
    char path[PATH_MAX];
    if (!error) error = directory_name(fd, path);
    close(fd);
    return error;
}

/* Reopen a pinned inode without following a guest-selected pathname again. */
static int reopen_regular_or_directory(int pinned, uint64_t flags, bool executable) {
    struct stat st;
    if (fstat(pinned, &st) < 0) return -errno;
    if (S_ISLNK(st.st_mode)) return -ELOOP;
    if (executable && !S_ISREG(st.st_mode)) return -EACCES;
    if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) return -EOPNOTSUPP;

    char proc[64];
    proc_fd_name(pinned, proc);
    int fd = open(proc, (int)(flags & ~O_NOFOLLOW) | O_CLOEXEC);
    return fd < 0 ? -errno : fd;
}

int rl_vfs_open_executable(int rootfd, const char *path) {
    if (path[0] != '/') return -EINVAL;
    int pinned = rooted_open(rootfd, path, O_PATH, 0);
    if (pinned < 0) return pinned;
    int fd = reopen_regular_or_directory(pinned, O_RDONLY | O_NONBLOCK, true);
    close(pinned);
    return fd;
}

int rl_vfs_start(struct rl_vfs *vfs, int rootfd, int execfd, pid_t guest) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/fd", (long)guest);
    int tracee_fds = open(path, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (tracee_fds < 0) return errno;
    int cwdfd = fcntl(rootfd, F_DUPFD_CLOEXEC, 0);
    if (cwdfd < 0) {
        int error = errno;
        close(tracee_fds);
        return error;
    }
    *vfs = (struct rl_vfs){ rootfd, cwdfd, tracee_fds, execfd, guest, true };
    return 0;
}

void rl_vfs_stop(struct rl_vfs *vfs) {
    close(vfs->tracee_fds);
    close(vfs->cwdfd);
}

static int pin_fd(const struct rl_vfs *vfs, int fd) {
    if (fd == AT_FDCWD) {
        int dup = fcntl(vfs->cwdfd, F_DUPFD_CLOEXEC, 0);
        return dup < 0 ? -errno : dup;
    }
    if (fd < 0) return -EBADF;
    char name[32];
    snprintf(name, sizeof(name), "%d", fd);
    int pinned = openat(vfs->tracee_fds, name, O_PATH | O_CLOEXEC);
    return pinned < 0 ? -(errno == ENOENT ? EBADF : errno) : pinned;
}

/* Derive a name from a pinned directory. A textual prefix alone is insufficient:
   reopen that name inside the pinned root and compare inode and mount identity. */
static int guest_directory(const struct rl_vfs *vfs, int fd, char guest[PATH_MAX]) {
    struct stat st;
    if (fstat(fd, &st) != 0) return errno;
    if (!S_ISDIR(st.st_mode)) return ENOTDIR;

    char root[PATH_MAX], directory[PATH_MAX];
    int error = directory_name(vfs->rootfd, root);
    if (!error) error = directory_name(fd, directory);
    if (error) return error;

    size_t length = strlen(root);
    const char *relative = directory;
    if (strcmp(root, "/")) {
        if (strncmp(root, directory, length) || (directory[length] && directory[length] != '/'))
            return EXDEV;
        relative += length;
    }
    if (!*relative) relative = "/";
    int check = rooted_open(vfs->rootfd, relative, O_PATH | O_DIRECTORY, RESOLVE_NO_SYMLINKS);
    if (check < 0) return -check;
    error = same_directory(fd, check);
    close(check);
    if (!error) strcpy(guest, relative);
    return error;
}

static int pin_path(const struct rl_vfs *vfs, int dirfd, const char *path,
                    uint64_t flags, uint64_t resolve) {
    if (path[0] == '/') return rooted_open(vfs->rootfd, path, flags, resolve);
    if (!path[0]) return -ENOENT;

    int base = pin_fd(vfs, dirfd);
    if (base < 0) return base;
    char directory[PATH_MAX], joined[PATH_MAX];
    int error = guest_directory(vfs, base, directory);
    if (error) {
        close(base);
        return -error;
    }

    int n = snprintf(joined, sizeof(joined), "%s%s%s", directory,
                     strcmp(directory, "/") ? "/" : "", path);
    int fd = n < 0 || n >= (int)sizeof(joined)
        ? -ENAMETOOLONG : rooted_open(vfs->rootfd, joined, flags, resolve);

    /* Catch observed base movement around lookup. This is a read-only lookup;
       a rename away and back can still evade the two checks. */
    char after[PATH_MAX];
    error = guest_directory(vfs, base, after);
    close(base);
    if (error || strcmp(directory, after)) {
        if (fd >= 0) close(fd);
        return -ESTALE;
    }
    return fd;
}

static int validity(int listener, uint64_t id) {
    return ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) < 0 ? errno : 0;
}

static int send_result(int listener, uint64_t id, int result, uint32_t flags) {
    struct seccomp_notif_resp response = {
        .id = id, .val = result >= 0 ? result : 0,
        .error = result < 0 ? result : 0, .flags = flags
    };
    return ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &response) < 0 ? errno : 0;
}

static ssize_t read_memory(pid_t pid, uint64_t address, void *buffer, size_t length) {
    if (!address) return -EFAULT;
    struct iovec local = { .iov_base = buffer, .iov_len = length };
    struct iovec remote = { .iov_base = (void *)(uintptr_t)address, .iov_len = length };
    ssize_t got;
    do got = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    while (got < 0 && errno == EINTR);
    return got < 0 ? -errno : got;
}

static int read_path(pid_t pid, uint64_t address, char path[PATH_MAX]) {
    ssize_t n = read_memory(pid, address, path, PATH_MAX);
    if (n < 0) return (int)n;
    if (memchr(path, '\0', (size_t)n)) return 0;
    return n == PATH_MAX ? -ENAMETOOLONG : -EFAULT;
}

static int write_memory(int listener, const struct seccomp_notif *request,
                        uint64_t address, void *buffer, size_t length) {
    int error = validity(listener, request->id);
    if (error) return -error;
    if (!address) return -EFAULT;
    struct iovec local = { .iov_base = buffer, .iov_len = length };
    struct iovec remote = { .iov_base = (void *)(uintptr_t)address, .iov_len = length };
    ssize_t n;
    do n = process_vm_writev((pid_t)request->pid, &local, 1, &remote, 1, 0);
    while (n < 0 && errno == EINTR);
    if (n < 0) return -errno;
    return (size_t)n == length ? 0 : -EFAULT;
}

static int get_open_how(const struct seccomp_notif *request, struct open_how *how) {
    size_t size = (size_t)request->data.args[3];
    if (size < sizeof(*how)) return -EINVAL;
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size < 0 || size > (size_t)page_size) return -E2BIG;

    unsigned char buffer[64];
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = size - offset;
        if (chunk > sizeof(buffer)) chunk = sizeof(buffer);
        uint64_t address = request->data.args[2] + offset;
        if (address < request->data.args[2]) return -EFAULT;
        ssize_t got = read_memory((pid_t)request->pid, address, buffer, chunk);
        if (got < 0) return (int)got;
        if ((size_t)got != chunk) return -EFAULT;
        size_t i = 0;
        if (!offset) {
            memcpy(how, buffer, sizeof(*how));
            i = sizeof(*how);
        }
        for (; i < chunk; ++i)
            if (buffer[i]) return -E2BIG;
        offset += chunk;
    }
    return 0;
}

/* A lookup returning an O_PATH fd cannot open a FIFO/device or truncate a file.
   Reopen that exact inode only after confirming it is a regular file or directory. */
static int open_readonly(const struct rl_vfs *vfs, int dirfd, const char *path,
                         struct open_how how, bool strict) {
    uint64_t path_flags = O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW | O_PATH;
    uint64_t read_flags = path_flags | O_NONBLOCK | O_NOCTTY | O_NOATIME | RL_O_LARGEFILE;
    if (strict && (how.flags & O_PATH) && (how.flags & ~path_flags))
        return -EINVAL;
    if (!strict && (how.flags & O_PATH)) how.flags &= path_flags;
    bool creates = (how.flags & O_CREAT) || (how.flags & O_TMPFILE) == O_TMPFILE;
    if (strict && (how.mode & ~07777ULL || (how.mode && !creates))) return -EINVAL;
    if ((how.flags & O_ACCMODE) == O_ACCMODE) return -EINVAL;
    if ((how.flags & (O_ACCMODE | O_TRUNC)) || creates) return -EROFS;
    if (how.flags & ~read_flags) return -EOPNOTSUPP;

    uint64_t supported = RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS;
    uint64_t unsupported = RESOLVE_BENEATH | RESOLVE_IN_ROOT | RESOLVE_CACHED;
    if (how.resolve & ~(supported | unsupported)) return -EINVAL;
    if ((how.resolve & (RESOLVE_BENEATH | RESOLVE_IN_ROOT)) ==
        (RESOLVE_BENEATH | RESOLVE_IN_ROOT)) return -EINVAL;
    /* The notification injection API rejects O_PATH source descriptors. */
    if ((how.resolve & unsupported) || (how.flags & O_PATH)) return -EOPNOTSUPP;

    int pinned = pin_path(vfs, dirfd, path, O_PATH | (how.flags & (O_DIRECTORY | O_NOFOLLOW)),
                          how.resolve);
    if (pinned < 0) return pinned;
    int result = reopen_regular_or_directory(pinned, how.flags, false);
    close(pinned);
    return result;
}

static int inject_fd(int listener, const struct seccomp_notif *request, int fd,
                     uint64_t flags) {
    struct seccomp_notif_addfd addfd = {
        .id = request->id, .srcfd = (uint32_t)fd, .flags = SECCOMP_ADDFD_FLAG_SEND,
        .newfd_flags = (uint32_t)(flags & O_CLOEXEC)
    };
    int error = ioctl(listener, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd) < 0 ? errno : 0;
    close(fd);
    if (!error || error == ENOENT) return 0;
    return send_result(listener, request->id, -(error == EINVAL ? EOPNOTSUPP : error), 0);
}

static int metadata(const struct rl_vfs *vfs, int listener,
                    const struct seccomp_notif *request, enum operation op,
                    int dirfd, const char *path, int flags, uint64_t argument, uint64_t output) {
    int supported_flags = AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH;
    if (op == STATX) supported_flags |= AT_STATX_SYNC_TYPE;
    if (op == FACCESSAT2) {
        supported_flags = AT_SYMLINK_NOFOLLOW | AT_EACCESS | AT_EMPTY_PATH;
        if (argument & ~(uint64_t)(R_OK | W_OK | X_OK)) return -EINVAL;
    }
    if ((flags & ~supported_flags) ||
        (op == STATX && (flags & AT_STATX_SYNC_TYPE) == AT_STATX_SYNC_TYPE))
        return -EINVAL;
    if (op == READLINKAT && (int)argument <= 0) return -EINVAL;

    bool empty = !*path && ((flags & AT_EMPTY_PATH) || op == READLINKAT);
    uint64_t nofollow = (flags & AT_SYMLINK_NOFOLLOW) || op == READLINKAT ? O_NOFOLLOW : 0;
    int fd = empty ? pin_fd(vfs, dirfd) : pin_path(vfs, dirfd, path, O_PATH | nofollow, 0);
    if (fd < 0) return fd;
    int result = 0;
    if (op == FACCESSAT2) {
        if (syscall(SYS_faccessat2, fd, "", (int)argument,
                    AT_EMPTY_PATH | (flags & AT_EACCESS)) < 0) result = -errno;
    } else if (op == STATX) {
        struct statx st = {0};
        if (syscall(SYS_statx, fd, "", AT_EMPTY_PATH | (flags & AT_STATX_SYNC_TYPE),
                    (unsigned int)argument, &st) < 0) result = -errno;
        else result = write_memory(listener, request, output, &st, sizeof(st));
    } else if (op == READLINKAT) {
        char target[PATH_MAX];
        size_t length = (unsigned int)argument;
        if (length > sizeof(target)) length = sizeof(target);
        ssize_t n = readlinkat(fd, "", target, length);
        if (n < 0) result = -(errno == ENOENT && !empty ? EINVAL : errno);
        else {
            result = write_memory(listener, request, output, target, (size_t)n);
            if (!result) result = (int)n;
        }
    } else {
        /* Both supported native LP64 ABIs use the kernel stat layout. */
        struct stat st = {0};
        if (syscall(SYS_newfstatat, fd, "", &st, AT_EMPTY_PATH) < 0) result = -errno;
        else result = write_memory(listener, request, output, &st, sizeof(st));
    }
    close(fd);
    return result;
}

static int change_cwd(struct rl_vfs *vfs, int listener, const struct seccomp_notif *request,
                      int fd) {
    if (fd < 0) return send_result(listener, request->id, fd, 0);
    char name[PATH_MAX];
    int error = guest_directory(vfs, fd, name);
    if (!error && syscall(SYS_faccessat2, fd, "", X_OK, AT_EMPTY_PATH | AT_EACCESS) < 0)
        error = errno;
    int sent = send_result(listener, request->id, -error, 0);
    if (!sent && !error) {
        close(vfs->cwdfd);
        vfs->cwdfd = fd;
    } else close(fd);
    return sent;
}

int rl_vfs_dispatch(struct rl_vfs *vfs, int listener, const struct seccomp_notif *request) {
    if ((pid_t)request->pid != vfs->guest)
        return send_result(listener, request->id, -EOPNOTSUPP, 0);
    enum operation op = PROCESS_UNSUPPORTED;
    for (size_t i = 0; i < sizeof(intercepted) / sizeof(intercepted[0]); ++i) {
        if (intercepted[i].number == request->data.nr) {
            op = intercepted[i].operation;
            break;
        }
    }

    const __u64 *args = request->data.args;
    int dirfd = AT_FDCWD;
    uint64_t pointer = args[0], argument = 0, output = 0;
    struct open_how how = {0};
    char path[PATH_MAX];
    int flags = 0, result = 0;
    switch (op) {
    case MUTATION_UNSUPPORTED: result = -EROFS; break;
    case PROCESS_UNSUPPORTED: result = -EOPNOTSUPP; break;
    case EXECVEAT:
        result = -EOPNOTSUPP;
        if (vfs->launch_pending && (int)args[0] == vfs->execfd && (int)args[4] == AT_EMPTY_PATH) {
            result = read_path(vfs->guest, args[1], path);
            if (!result && !*path) {
                /* Probe both directions against the blocked bootstrap's
                   writable empty string before continuing the first exec. */
                result = write_memory(listener, request, args[1], path, 1);
                if (result) return -result;
                /* Invalid source fd checks ioctl support without injecting a file. */
                struct seccomp_notif_addfd probe = {
                    .id = request->id, .flags = SECCOMP_ADDFD_FLAG_SEND,
                    .srcfd = UINT32_MAX
                };
                if (ioctl(listener, SECCOMP_IOCTL_NOTIF_ADDFD, &probe) >= 0) return EPROTO;
                if (errno != EBADF) return errno == EINVAL ? EOPNOTSUPP : errno;
                int sent = send_result(listener, request->id, 0, SECCOMP_USER_NOTIF_FLAG_CONTINUE);
                if (!sent) vfs->launch_pending = false;
                return sent;
            }
            if (result) return -result;
            result = -EOPNOTSUPP;
        }
        break;
    case FCHDIR:
        if ((int)args[0] == AT_FDCWD) return send_result(listener, request->id, -EBADF, 0);
        return change_cwd(vfs, listener, request, pin_fd(vfs, (int)args[0]));
    case GETCWD:
        result = -guest_directory(vfs, vfs->cwdfd, path);
        if (!result) {
            size_t size = strlen(path) + 1;
            if (args[1] < size) result = -ERANGE;
            else {
                result = write_memory(listener, request, args[0], path, size);
                if (!result) result = (int)size;
            }
        }
        break;
    case OPENAT2:
        result = get_open_how(request, &how);
        dirfd = (int)args[0];
        pointer = args[1];
        break;
    case OPENAT:
        dirfd = (int)args[0];
        pointer = args[1];
        how.flags = (uint32_t)args[2];
        break;
    case OPEN:
        how.flags = (uint32_t)args[1];
        break;
    case STATX:
        argument = args[3];
        output = args[4];
        flags = (int)args[2];
        dirfd = (int)args[0];
        pointer = args[1];
        break;
    case FSTATAT:
        output = args[2];
        flags = (int)args[3];
        dirfd = (int)args[0];
        pointer = args[1];
        break;
    case STAT: case LSTAT:
        output = args[1];
        if (op == LSTAT) flags = AT_SYMLINK_NOFOLLOW;
        op = FSTATAT;
        break;
    case FACCESSAT: case FACCESSAT2:
        if (op == FACCESSAT2) flags = (int)args[3];
        argument = args[2];
        dirfd = (int)args[0];
        pointer = args[1];
        op = FACCESSAT2;
        break;
    case ACCESS:
        argument = args[1];
        op = FACCESSAT2;
        break;
    case READLINKAT:
        dirfd = (int)args[0];
        pointer = args[1];
        output = args[2];
        argument = args[3];
        break;
    case READLINK:
        output = args[1];
        argument = args[2];
        op = READLINKAT;
        break;
    case CHDIR: break;
    }

    if (result || op == GETCWD) return send_result(listener, request->id, result, 0);
    result = read_path(vfs->guest, pointer, path);
    if (result) return send_result(listener, request->id, result, 0);
    result = validity(listener, request->id);
    if (result) return result;

    if (op == OPEN || op == OPENAT || op == OPENAT2) {
        result = open_readonly(vfs, dirfd, path, how, op == OPENAT2);
        if (result >= 0) return inject_fd(listener, request, result, how.flags);
    } else if (op == CHDIR) {
        return change_cwd(vfs, listener, request, pin_path(vfs, AT_FDCWD, path,
                                                           O_PATH | O_DIRECTORY, 0));
    } else {
        result = metadata(vfs, listener, request, op, dirfd, path, flags, argument, output);
    }
    return send_result(listener, request->id, result, 0);
}

#else

int rl_vfs_probe(int rootfd) {
    (void)rootfd;
    return EOPNOTSUPP;
}

int rl_vfs_open_executable(int rootfd, const char *path) {
    (void)rootfd;
    (void)path;
    return -EOPNOTSUPP;
}

int rl_vfs_start(struct rl_vfs *vfs, int rootfd, int execfd, pid_t guest) {
    (void)vfs;
    (void)rootfd;
    (void)execfd;
    (void)guest;
    return EOPNOTSUPP;
}

void rl_vfs_stop(struct rl_vfs *vfs) {
    (void)vfs;
}

size_t rl_vfs_filter(struct sock_filter *code) {
    (void)code;
    return 0;
}

int rl_vfs_dispatch(struct rl_vfs *vfs, int listener, const struct seccomp_notif *request) {
    (void)vfs;
    (void)listener;
    (void)request;
    return EOPNOTSUPP;
}

#endif
