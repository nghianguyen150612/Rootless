/* SPDX-License-Identifier: GPL-3.0-only */
#include "rootless/probe.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>

#define RL_VERSION "0.1.0-p0"
#define RL_EX_USAGE 64
#define RL_EX_UNAVAILABLE 69

static void usage(FILE *file) {
    fputs("Rootless — native-first Linux runtime for Android (P0 foundation)\n"
          "Usage: rl [--help | --version]\n"
          "       rl probe [--verbose]\n"
          "\n"
          "Commands:\n"
          "  probe       Inspect real host capabilities without modifying the caller\n"
          "  run         Not implemented (P1+); cannot launch a guest yet\n"
          "  doctor      Not implemented\n"
          "  info        Not implemented\n"
          "  benchmark   Not implemented\n"
          "\n"
          "Probe statuses: supported, unsupported, permission_denied, unknown, not_tested\n"
          "An ordinary probe report exits 0 even if capabilities are blocked.\n", file);
}

static int probe(bool verbose) {
    struct utsname u;
    if (uname(&u) != 0) {
        fprintf(stderr, "rl: uname failed: %s\n", strerror(errno));
        return 70;
    }
    rl_capability capabilities[RL_PROBE_COUNT];
    const size_t total = rl_collect_probes(capabilities, RL_PROBE_COUNT);
    if (total != RL_PROBE_COUNT) {
        fputs("rl: internal probe count mismatch\n", stderr);
        return 70;
    }
    printf("rl probe (P0, no root required)\n"
           "system=%s machine=%s kernel=%s\n", u.sysname, u.machine, u.release);
    for (size_t i = 0; i < total; ++i) {
        const rl_capability *p = &capabilities[i];
        printf("%-31s %-18s %s", p->name, rl_status_name(p->status), p->detail);
        if (verbose && p->error_number != 0)
            printf(" [errno=%d: %s]", p->error_number, strerror(p->error_number));
        putchar('\n');
    }
    fputs("Note: supported means this narrow probe passed; it does not prove guest compatibility.\n", stdout);
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))) {
        usage(stdout);
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "--version")) {
        printf("rl %s\n", RL_VERSION);
        return 0;
    }
    if (argc >= 2 && !strcmp(argv[1], "probe")) {
        if (argc == 2) return probe(false);
        if (argc == 3 && !strcmp(argv[2], "--verbose")) return probe(true);
        fputs("rl: usage: rl probe [--verbose]\n", stderr);
        return RL_EX_USAGE;
    }
    if (argc >= 2 && (!strcmp(argv[1], "run") || !strcmp(argv[1], "doctor") ||
                      !strcmp(argv[1], "info") || !strcmp(argv[1], "benchmark"))) {
        fprintf(stderr, "rl: %s is not implemented in P0\n", argv[1]);
        return RL_EX_UNAVAILABLE;
    }
    fputs("rl: unknown or missing command (try 'rl --help')\n", stderr);
    return RL_EX_USAGE;
}
