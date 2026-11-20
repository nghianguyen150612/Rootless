/* SPDX-License-Identifier: GPL-3.0-only */
#include "rootless/probe.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    assert(!strcmp(rl_status_name(RL_SUPPORTED), "supported"));
    assert(!strcmp(rl_status_name(RL_NOT_TESTED), "not_tested"));
    assert(rl_status_from_errno(0) == RL_SUPPORTED);
    assert(rl_status_from_errno(EPERM) == RL_PERMISSION_DENIED);
    assert(rl_status_from_errno(EACCES) == RL_PERMISSION_DENIED);
    assert(rl_status_from_errno(ENOSYS) == RL_UNSUPPORTED);
    assert(rl_status_from_errno(EINVAL) == RL_UNSUPPORTED);
    assert(rl_status_from_errno(EIO) == RL_UNKNOWN);

    rl_capability buffer[RL_PROBE_COUNT];
    assert(rl_collect_probes(NULL, 0) == RL_PROBE_COUNT);
    assert(rl_collect_probes(buffer, RL_PROBE_COUNT - 1) == RL_PROBE_COUNT);
    assert(rl_collect_probes(buffer, RL_PROBE_COUNT) == RL_PROBE_COUNT);
    for (size_t i = 0; i < RL_PROBE_COUNT; ++i) {
        assert(buffer[i].name != NULL && buffer[i].detail != NULL);
        assert(buffer[i].status >= RL_SUPPORTED && buffer[i].status <= RL_NOT_TESTED);
        for (size_t j = 0; j < i; ++j)
            assert(strcmp(buffer[i].name, buffer[j].name) != 0);
    }
    assert(!strcmp(buffer[9].name, "kernel.real_chroot"));
    assert(buffer[9].status == RL_NOT_TESTED);
    assert(!strcmp(buffer[10].name, "android.app_data_exec"));
    assert(buffer[10].status == RL_NOT_TESTED);
    puts("probe contract: PASS");
    return 0;
}
