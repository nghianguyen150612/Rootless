/* SPDX-License-Identifier: GPL-3.0-only */
#define _GNU_SOURCE
#include "rootless/intercept.h"
#include "rootless/native.h"
#include "vfs.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/openat2.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <stddef.h>
#include <stdbool.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif
#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE 1
#endif

#ifndef SECCOMP_ADDFD_FLAG_SEND
#define SECCOMP_ADDFD_FLAG_SEND (1UL << 1)
#endif

enum intercept_mode { P2_REDIRECT, P3_ALPINE, P4_VFS };

struct result_message {
    int error;
    int exit_status;
};

static int send_listener(int sock, int listener) {
    char marker = 'L';
    struct iovec iov = { .iov_base = &marker, .iov_len = sizeof(marker) };
    union {
        struct cmsghdr align;
        char bytes[CMSG_SPACE(sizeof(int))];
    } control;
    memset(&control, 0, sizeof(control));
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = control.bytes,
        .msg_controllen = sizeof(control.bytes)
    };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &listener, sizeof(listener));
    ssize_t sent;
    do sent = sendmsg(sock, &msg, 0); while (sent < 0 && errno == EINTR);
    if (sent != 1) return sent < 0 ? errno : EIO;
    return 0;
}

static void send_setup_error(int sock, int error) {
    struct { char marker; int error; } packet = { .marker = 'E', .error = error };
    (void)send(sock, &packet, sizeof(packet), MSG_NOSIGNAL);
}

static int receive_listener(int sock) {
    struct { char marker; int error; } packet = {0};
    struct iovec iov = { .iov_base = &packet, .iov_len = sizeof(packet) };
    union {
        struct cmsghdr align;
        char bytes[CMSG_SPACE(sizeof(int))];
    } control;
    memset(&control, 0, sizeof(control));
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = control.bytes,
        .msg_controllen = sizeof(control.bytes)
    };
    ssize_t got;
    do got = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC); while (got < 0 && errno == EINTR);
    if (got < 0) return -errno;
    if (msg.msg_flags & MSG_CTRUNC) return -EPROTO;
    if (got == sizeof(packet) && packet.marker == 'E' && packet.error > 0)
        return -packet.error;
    if (got != 1 || packet.marker != 'L') return -EPROTO;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg || cmsg->cmsg_level != SOL_SOCKET ||
        cmsg->cmsg_type != SCM_RIGHTS || cmsg->cmsg_len != CMSG_LEN(sizeof(int)))
        return -EPROTO;
    int fd;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
    return fd;
}

static int install_filter(enum intercept_mode mode) {
#if !defined(SYS_seccomp) || !defined(SYS_openat)
    return -ENOTSUP;
#elif defined(__aarch64__)
    const uint32_t native_arch = AUDIT_ARCH_AARCH64;
#elif defined(__x86_64__)
    const uint32_t native_arch = AUDIT_ARCH_X86_64;
#else
    return -ENOTSUP;
#endif
#if defined(SYS_seccomp) && defined(SYS_openat) && \
    (defined(__aarch64__) || defined(__x86_64__))
    struct sock_filter code[4 + 2 + RL_VFS_FILTER_CAPACITY + 1] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, native_arch, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, nr))
    };
    size_t n = 4;
    if (mode == P4_VFS) {
        code[2].k = SECCOMP_RET_KILL_PROCESS;
#if defined(__x86_64__)
        /* x32 shares AUDIT_ARCH_X86_64 but uses a different syscall ABI. */
        code[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K,
                                                 0x40000000U, 0, 1);
        code[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
#endif
        size_t added = rl_vfs_filter(code + n);
        if (!added) return -EOPNOTSUPP;
        n += added;
    } else {
        code[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat, 0, 1);
        code[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF);
    }
    code[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    struct sock_fprog program = { .len = (unsigned short)n, .filter = code };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -errno;
    long fd = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                      SECCOMP_FILTER_FLAG_NEW_LISTENER, &program);
    return fd < 0 ? -errno : (int)fd;
#endif
}

static int bind_to_parent(pid_t parent) {
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0) return errno;
    return getppid() == parent ? 0 : ESRCH;
}

static void guest_child(int sock, int rootfd, int execfd,
                        char *const argv[], char *const envp[],
                        enum intercept_mode mode, pid_t supervisor) {
    int error = mode == P4_VFS ? bind_to_parent(supervisor) : 0;
    if (error) {
        send_setup_error(sock, error);
        _exit(125);
    }
    if (fchdir(rootfd) != 0) {
        send_setup_error(sock, errno);
        _exit(125);
    }
    int listener = install_filter(mode);
    if (listener < 0) {
        send_setup_error(sock, -listener);
        _exit(125);
    }
    error = send_listener(sock, listener);
    close(listener);
    close(sock);
    if (error) _exit(125);
#ifdef SYS_execveat
    char exec_path[] = "";
    syscall(SYS_execveat, execfd, exec_path, argv, envp, AT_EMPTY_PATH);
    error = errno;
#else
    error = ENOSYS;
#endif
    dprintf(STDERR_FILENO, "rl dev-intercept: exec failed: errno=%d (%s)\n",
            error, strerror(error));
    _exit(error == ENOENT ? 127 : 126);
}

static int read_tracee_path(pid_t pid, uintptr_t address, char path[PATH_MAX]) {
    struct iovec local = { .iov_base = path, .iov_len = PATH_MAX };
    struct iovec remote = { .iov_base = (void *)address, .iov_len = PATH_MAX };
    ssize_t count;
    do count = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    while (count < 0 && errno == EINTR);
    if (count < 0 && (errno == ENOSYS || errno == EPERM || errno == EACCES)) {
        /* Some Android/container policies disable process_vm_readv while
           allowing the same parent-child read through procfs. */
        char mem_path[64];
        int length = snprintf(mem_path, sizeof(mem_path), "/proc/%ld/mem", (long)pid);
        if (length < 0 || (size_t)length >= sizeof(mem_path)) return EOVERFLOW;
        int memfd = open(mem_path, O_RDONLY | O_CLOEXEC);
        if (memfd < 0) return errno;
        if ((uintmax_t)address > (uintmax_t)INT64_MAX) {
            close(memfd);
            return EFAULT;
        }
        do count = pread(memfd, path, PATH_MAX, (off_t)address);
        while (count < 0 && errno == EINTR);
        int error = count < 0 ? errno : 0;
        close(memfd);
        if (error) return error;
    } else if (count < 0) {
        return errno;
    }
    if (count == 0) return EFAULT;
    if (!memchr(path, '\0', (size_t)count))
        return count == PATH_MAX ? ENAMETOOLONG : EFAULT;
    return 0;
}

static int send_response(int listener, uint64_t id, int error, int value,
                         uint32_t flags) {
    struct seccomp_notif_resp response = {
        .id = id,
        .val = value,
        .error = error ? -error : 0,
        .flags = flags
    };
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &response) == 0) return 0;
    if (errno == ENOENT) return 0; /* The notified task exited. */
    return errno;
}

static int handle_notification(int listener, int rootfd, enum intercept_mode mode,
                               struct rl_vfs *vfs) {
    struct seccomp_notif_sizes sizes;
    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) != 0)
        return errno;
    if (sizes.seccomp_notif > sizeof(struct seccomp_notif) ||
        sizes.seccomp_notif_resp > sizeof(struct seccomp_notif_resp) ||
        sizes.seccomp_data > sizeof(((struct seccomp_notif *)0)->data))
        return EOVERFLOW;
    struct seccomp_notif request;
    memset(&request, 0, sizeof(request));
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &request) != 0)
        return errno == ENOENT || errno == EINTR ? 0 : errno;
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &request.id) != 0)
        return errno == ENOENT ? 0 : errno;

    if (mode == P4_VFS) {
        int error = rl_vfs_dispatch(vfs, listener, &request);
        return error == ENOENT ? 0 : error;
    }

    /* Relative paths retain normal openat semantics. Only absolute paths are
       redirected; this interface does not claim to confine filesystem access. */
    char path[PATH_MAX];
    int error = read_tracee_path((pid_t)request.pid,
                                 (uintptr_t)request.data.args[1], path);
    if (error) return send_response(listener, request.id, error, 0, 0);
    if (path[0] != '/')
        return send_response(listener, request.id, 0, 0,
                             SECCOMP_USER_NOTIF_FLAG_CONTINUE);

#if !defined(SYS_openat2)
    return send_response(listener, request.id, ENOTSUP, 0, 0);
#else
    /* The openat ABI takes int flags and ignores mode for ordinary opens.
       openat2 validates both fields even when neither creates a file. */
    uint64_t flags = (uint32_t)request.data.args[2];
    if (flags & O_PATH) flags &= O_PATH | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW;
    bool creates = (flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE;
    struct open_how how = {
        .flags = flags,
        .mode = creates ? request.data.args[3] & 07777 : 0,
        .resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS
    };
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &request.id) != 0)
        return errno == ENOENT ? 0 : errno;
    int opened = (int)syscall(SYS_openat2, rootfd, path, &how, sizeof(how));
    if (opened < 0)
        return send_response(listener, request.id, errno, 0, 0);
    struct seccomp_notif_addfd addfd = {
        .id = request.id,
        .srcfd = (uint32_t)opened,
        .flags = SECCOMP_ADDFD_FLAG_SEND,
        .newfd_flags = flags & O_CLOEXEC
    };
    int targetfd = ioctl(listener, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
    if (targetfd < 0 && errno == EINVAL && mode == P2_REDIRECT) {
        /* Keep the P2 fixture usable on kernels predating atomic add-and-reply. */
        addfd.flags = 0;
        targetfd = ioctl(listener, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd);
        error = targetfd < 0 ? errno : 0;
        close(opened);
        return send_response(listener, request.id, error,
                             error ? 0 : targetfd, 0);
    }
    error = targetfd < 0 ? errno : 0;
    close(opened);
    if (!error || error == ENOENT) return 0;
    return send_response(listener, request.id, error, 0, 0);
#endif
}

static int reap_available(pid_t primary, int *primary_status, int *primary_seen) {
    for (;;) {
        int status;
        pid_t child = waitpid(-1, &status, WNOHANG);
        if (child > 0) {
            if (child == primary) {
                *primary_status = status;
                *primary_seen = 1;
            }
            continue;
        }
        if (child == 0) return 0;
        if (errno == EINTR) continue;
        if (errno == ECHILD) return ECHILD;
        return errno;
    }
}

static int supervise_guest(int rootfd, int execfd, char *const argv[],
                           char *const envp[], enum intercept_mode mode, int *exit_status) {
    if (mode == P4_VFS) {
        struct sigaction action = { .sa_handler = SIG_DFL };
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGCHLD, &action, NULL) != 0) return errno;
    }
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0) return errno;
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) != 0)
        return errno;
    pid_t supervisor = getpid();
    pid_t guest = fork();
    if (guest < 0) {
        int error = errno;
        close(sockets[0]);
        close(sockets[1]);
        return error;
    }
    if (guest == 0) {
        close(sockets[0]);
        guest_child(sockets[1], rootfd, execfd, argv, envp, mode, supervisor);
        _exit(125);
    }
    close(sockets[1]);
    int listener = receive_listener(sockets[0]);
    close(sockets[0]);
    if (listener < 0) {
        if (mode == P4_VFS) (void)kill(guest, SIGKILL);
        int ignored;
        while (waitpid(guest, &ignored, 0) < 0 && errno == EINTR) {}
        return -listener;
    }

    int primary_status = 0;
    int primary_seen = 0;
    struct rl_vfs vfs;
    int error = mode == P4_VFS ? rl_vfs_start(&vfs, rootfd, execfd, guest) : 0;
    bool have_vfs = mode == P4_VFS && !error;
    while (!error) {
        int reap_error = reap_available(guest, &primary_status, &primary_seen);
        if (reap_error == ECHILD) break;
        if (reap_error) { error = reap_error; break; }
        struct pollfd pfd = { .fd = listener, .events = POLLIN };
        int ready;
        do ready = poll(&pfd, 1, 100); while (ready < 0 && errno == EINTR);
        if (ready < 0) { error = errno; break; }
        if (ready > 0 && (pfd.revents & POLLIN)) {
            error = handle_notification(listener, rootfd, mode, &vfs);
            if (error) break;
        }
        if (ready > 0 && (pfd.revents & (POLLERR | POLLNVAL))) {
            error = EIO;
            break;
        }
    }
    close(listener);
    if (have_vfs) rl_vfs_stop(&vfs);
    if (error) {
        if (mode == P4_VFS && !primary_seen) {
            (void)kill(guest, SIGKILL);
            while (waitpid(guest, NULL, 0) < 0 && errno == EINTR) {}
        }
        return error;
    }
    if (!primary_seen) return ECHILD;
    if (WIFEXITED(primary_status)) *exit_status = WEXITSTATUS(primary_status);
    else if (WIFSIGNALED(primary_status)) *exit_status = 128 + WTERMSIG(primary_status);
    else *exit_status = 125;
    return 0;
}

static void supervisor_process(int result_fd, int rootfd, int execfd,
                               char *const argv[], char *const envp[],
                               enum intercept_mode mode, pid_t launcher) {
    int status = 125;
    int error = mode == P4_VFS ? bind_to_parent(launcher) : 0;
    if (!error) error = supervise_guest(rootfd, execfd, argv, envp, mode, &status);
    struct result_message result = { .error = error, .exit_status = status };
    const char *p = (const char *)&result;
    size_t remaining = sizeof(result);
    while (remaining) {
        ssize_t n = write(result_fd, p, remaining);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        p += n;
        remaining -= (size_t)n;
    }
    close(result_fd);
    close(rootfd);
    close(execfd);
    _exit(remaining ? 1 : 0);
}

static int run_intercepted(const char *root_directory, const char *executable,
                           char *const argv[], char *const envp[],
                           enum intercept_mode mode, int *exit_status) {
    if (!root_directory || !executable || !argv || !argv[0] || !envp ||
        !exit_status) return EINVAL;
    int error;
    int rootfd = open(root_directory, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (rootfd < 0) return errno;
#if defined(SYS_openat2)
    struct open_how feature_probe = {
        .flags = O_PATH | O_CLOEXEC,
        .resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS
    };
    int probe_fd = (int)syscall(SYS_openat2, rootfd, ".", &feature_probe,
                                sizeof(feature_probe));
    if (probe_fd < 0) {
        error = errno;
        close(rootfd);
        return error == ENOSYS ? ENOTSUP : error;
    }
    close(probe_fd);
    int execfd;
    if (mode == P4_VFS) {
        error = rl_vfs_probe(rootfd);
        if (error) {
            close(rootfd);
            return error;
        }
        execfd = rl_vfs_open_executable(rootfd, executable);
        if (execfd < 0) {
            close(rootfd);
            return -execfd;
        }
    } else if (mode == P3_ALPINE) {
        struct open_how how = {
            .flags = O_RDONLY | O_CLOEXEC | O_NONBLOCK,
            .resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS
        };
        execfd = (int)syscall(SYS_openat2, rootfd, executable, &how, sizeof(how));
    } else {
        execfd = open(executable, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    }
#else
    int execfd = -1;
    close(rootfd);
    return ENOTSUP;
#endif
    if (execfd < 0) {
        int error = errno;
        close(rootfd);
        return error;
    }
    error = mode == P3_ALPINE ? rl_check_native_linker(execfd) : rl_check_native(execfd);
    if (error) {
        close(execfd);
        close(rootfd);
        return error;
    }
    int result_pipe[2];
    if (pipe2(result_pipe, O_CLOEXEC) != 0) {
        error = errno;
        close(execfd);
        close(rootfd);
        return error;
    }
    pid_t launcher = getpid();
    pid_t supervisor = fork();
    if (supervisor < 0) {
        error = errno;
        close(result_pipe[0]);
        close(result_pipe[1]);
        close(execfd);
        close(rootfd);
        return error;
    }
    if (supervisor == 0) {
        close(result_pipe[0]);
        supervisor_process(result_pipe[1], rootfd, execfd, argv, envp, mode, launcher);
    }
    close(result_pipe[1]);
    close(execfd);
    close(rootfd);
    struct result_message result;
    char *p = (char *)&result;
    size_t received = 0;
    while (received < sizeof(result)) {
        ssize_t n = read(result_pipe[0], p + received, sizeof(result) - received);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        received += (size_t)n;
    }
    close(result_pipe[0]);
    int wait_status;
    while (waitpid(supervisor, &wait_status, 0) < 0) {
        if (errno != EINTR) return errno;
    }
    if (received != sizeof(result) || !WIFEXITED(wait_status) ||
        WEXITSTATUS(wait_status) != 0) return EIO;
    *exit_status = result.exit_status;
    return result.error;
}

int rl_experimental_intercept_run(const char *root_directory,
                                  const char *executable, char *const argv[],
                                  char *const envp[], int *exit_status) {
    return run_intercepted(root_directory, executable, argv, envp, P2_REDIRECT, exit_status);
}

int rl_experimental_alpine_shell(const char *root_directory, char *const argv[],
                                 char *const envp[], int *exit_status) {
#if defined(__aarch64__)
    if (!argv || !argv[0] || strcmp(argv[0], "/bin/sh")) return EINVAL;
    char linker[] = "/lib/ld-musl-aarch64.so.1";
    size_t argc = 0;
    while (argv[argc]) ++argc;
    char **linker_argv = calloc(argc + 5, sizeof(*linker_argv));
    if (!linker_argv) return ENOMEM;
    linker_argv[0] = linker;
    linker_argv[1] = "--argv0";
    linker_argv[2] = argv[0];
    linker_argv[3] = "--";
    memcpy(linker_argv + 4, argv, (argc + 1) * sizeof(*argv));
    int error = run_intercepted(root_directory, linker, linker_argv, envp,
                                P3_ALPINE, exit_status);
    free(linker_argv);
    return error;
#else
    (void)root_directory;
    (void)argv;
    (void)envp;
    (void)exit_status;
    return ENOTSUP;
#endif
}

int rl_experimental_vfs_run(const char *root_directory, char *const argv[],
                            char *const envp[], int *exit_status) {
    if (!argv || !argv[0]) return EINVAL;
    return run_intercepted(root_directory, argv[0], argv, envp, P4_VFS, exit_status);
}
