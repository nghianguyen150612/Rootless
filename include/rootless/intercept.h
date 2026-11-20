/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef ROOTLESS_INTERCEPT_H
#define ROOTLESS_INTERCEPT_H

/*
 * Experimental P2 interface. Runs a checked static native ELF under a
 * child-only seccomp user-notification filter. Absolute openat paths are
 * resolved beneath root_directory. This is a controlled proof of concept,
 * not filesystem isolation.
 *
 * Returns an errno value for setup/supervision failures. On success, stores
 * the guest's shell-style exit status (128 + signal when signalled).
 */
int rl_experimental_intercept_run(const char *root_directory,
                                  const char *executable,
                                  char *const argv[],
                                  char *const envp[],
                                  int *exit_status);

#endif
