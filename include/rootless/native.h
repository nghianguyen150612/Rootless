/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef ROOTLESS_NATIVE_H
#define ROOTLESS_NATIVE_H
#include "rootless/probe.h"

typedef enum { RL_ENGINE_UNSUPPORTED, RL_ENGINE_NATIVE_DIRECT } rl_engine;
/* Root-directory semantics are deliberately unavailable in P1. */
rl_engine rl_select_engine(int executable_error, int requires_root);
/* Returns an errno value, zero for a supported static native ELF. */
int rl_check_native(int fd);
/* Checks native ET_DYN without PT_INTERP for direct linker invocation. */
int rl_check_native_linker(int fd);
/* On success replaces the process; on failure returns errno. No PATH search. */
int rl_exec_native(const char *path, char *const argv[], char *const envp[]);
/* Standalone launcher only. Failure returns errno and a stage and can leave the
   calling process in a new namespace or root. Its parent is unaffected. */
int rl_exec_rootfs(const char *root, const char *path, char *const argv[],
                   char *const envp[], const char **operation);
#define RL_NATIVE_PROBE_COUNT 9
/* Child-only mutations; dependent steps remain NOT_TESTED after a failure. */
int rl_native_probes(rl_capability out[RL_NATIVE_PROBE_COUNT]);
#endif
