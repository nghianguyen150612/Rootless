/* SPDX-License-Identifier: GPL-3.0-only */
#define _GNU_SOURCE
#include "rootless/native.h"
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

rl_engine rl_select_engine(int error, int requires_root) {
    return error == 0 && !requires_root ? RL_ENGINE_NATIVE_DIRECT : RL_ENGINE_UNSUPPORTED;
}

int rl_check_native(int fd) {
    Elf64_Ehdr h;
    struct stat st;
    if (fstat(fd, &st) != 0) return errno;
    if (!S_ISREG(st.st_mode)) return EACCES;
    ssize_t n = pread(fd, &h, sizeof(h), 0);
    if (n < 0) return errno;
    if (n != sizeof(h) || memcmp(h.e_ident, ELFMAG, SELFMAG) ||
        h.e_ident[EI_CLASS] != ELFCLASS64 || h.e_ident[EI_DATA] != ELFDATA2LSB ||
        h.e_ident[EI_VERSION] != EV_CURRENT || h.e_version != EV_CURRENT ||
        h.e_ehsize != sizeof(h) || h.e_type != ET_EXEC ||
        h.e_phentsize != sizeof(Elf64_Phdr) || h.e_phnum == 0 || h.e_phnum == PN_XNUM)
        return ENOEXEC;
#if defined(__aarch64__)
    if (h.e_machine != EM_AARCH64) return ENOEXEC;
#elif defined(__x86_64__)
    if (h.e_machine != EM_X86_64) return ENOEXEC;
#else
    return ENOTSUP;
#endif
    if (h.e_phoff > (uint64_t)st.st_size ||
        (uint64_t)h.e_phnum * sizeof(Elf64_Phdr) > (uint64_t)st.st_size - h.e_phoff)
        return ENOEXEC;
    int load = 0;
    for (unsigned i = 0; i < h.e_phnum; ++i) {
        Elf64_Phdr p;
        n = pread(fd, &p, sizeof(p), (off_t)(h.e_phoff + i * sizeof(p)));
        if (n < 0) return errno;
        if (n != sizeof(p)) return ENOEXEC;
        if (p.p_type == PT_INTERP || p.p_type == PT_DYNAMIC) return ENOTSUP;
        if (p.p_type == PT_LOAD) {
            if (p.p_filesz > p.p_memsz || p.p_offset > (uint64_t)st.st_size ||
                p.p_filesz > (uint64_t)st.st_size - p.p_offset) return ENOEXEC;
            load = 1;
        }
    }
    return load ? 0 : ENOEXEC;
}

int rl_exec_native(const char *path, char *const argv[], char *const envp[]) {
    /* Pin the checked inode. CLOEXEC closes only our validation descriptor.
       Kernel permission/noexec/LSM checks remain authoritative at exec time. */
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return errno;
    int error = rl_check_native(fd);
    if (rl_select_engine(error, 0) == RL_ENGINE_NATIVE_DIRECT) {
        fexecve(fd, argv, envp);
        error = errno;
    }
    close(fd);
    return error;
}
