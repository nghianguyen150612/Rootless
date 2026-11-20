/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef ROOTLESS_PROBE_H
#define ROOTLESS_PROBE_H

#include <stddef.h>

#define RL_PROBE_COUNT 13

typedef enum {
    RL_SUPPORTED = 0,
    RL_UNSUPPORTED,
    RL_PERMISSION_DENIED,
    RL_UNKNOWN,
    RL_NOT_TESTED
} rl_status;

typedef struct {
    const char *name;
    rl_status status;
    int error_number;
    const char *detail;
} rl_capability;

const char *rl_status_name(rl_status status);
rl_status rl_status_from_errno(int error_number);
/* Returns RL_PROBE_COUNT; does not write beyond capacity. */
size_t rl_collect_probes(rl_capability *out, size_t capacity);

#endif
