/* SPDX-License-Identifier: GPL-3.0-only */
#include "rootless/probe.h"
#include "rootless/native.h"
#include "rootless/intercept.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>

#define RL_VERSION "0.1.0-p2"
#define RL_EX_USAGE 64
#define RL_EX_UNAVAILABLE 69

static void usage(FILE *file) {
    fputs("Rootless — native-first Linux runtime for Android (P2 syscall prototype)\n"
          "Usage: rl [--help | --version]\n"
          "       rl probe [--verbose]\n"
          "\n"
          "Commands:\n"
          "  probe       Inspect real host capabilities without modifying the caller\n"
          "  run -- FILE [ARG...]  Direct native static ELF; no filesystem isolation\n"
          "  run -r DIR -- FILE [ARG...]  Kernel chroot backend when permitted\n"
          "  dev-intercept --root DIR -- FILE [ARG...]  Experimental P2 openat redirect\n"
          "  native-probe         Test namespace/mapping/chroot feasibility in children\n"
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
    if (argc == 2 && !strcmp(argv[1], "native-probe")) {
        rl_capability caps[RL_NATIVE_PROBE_COUNT];
        int error = rl_native_probes(caps);
        if (error) {
            fprintf(stderr, "rl: native-probe failed: errno=%d: %s\n", error, strerror(error));
            return 70;
        }
        for (int i = 0; i < RL_NATIVE_PROBE_COUNT; ++i)
            printf("%s %s errno=%d (%s): %s\n", caps[i].name,
                rl_status_name(caps[i].status), caps[i].error_number,
                strerror(caps[i].error_number), caps[i].detail);
        puts("Direct execution provides no filesystem isolation. Rootfs engine requires a private mount namespace and chroot permission.");
        return 0;
    }
    if (argc >= 2 && !strcmp(argv[1], "run")) {
        if (argc >= 3 && !strcmp(argv[2], "-r")) {
            if (argc < 6 || strcmp(argv[4], "--")) {
                fputs("rl: usage: rl run -r DIR -- FILE [ARG...]\n", stderr);
                return RL_EX_USAGE;
            }
            extern char **environ;
            const char *operation;
            int error = rl_exec_rootfs(argv[3], argv[5], &argv[5], environ,
                                       &operation);
            fprintf(stderr, "rl: rootfs execution failed at %s: errno=%d (%s)\n",
                    operation, error, strerror(error));
            return error == ENOENT ? 127 : 126;
        }
        if (argc < 4 || strcmp(argv[2], "--")) {
            fputs("rl: usage: rl run -- FILE [ARG...] (direct execution, no filesystem isolation)\n", stderr);
            return RL_EX_USAGE;
        }
        extern char **environ;
        int error = rl_exec_native(argv[3], &argv[3], environ);
        fprintf(stderr, "rl: native direct execution failed: %s: errno=%d: %s\n",
                argv[3], error, strerror(error));
        return error == ENOENT ? 127 : 126;
    }
    if (argc >= 2 && !strcmp(argv[1], "dev-intercept")) {
        if (argc < 6 || strcmp(argv[2], "--root") || strcmp(argv[4], "--")) {
            fputs("rl: usage: rl dev-intercept --root DIR -- FILE [ARG...]\n", stderr);
            return RL_EX_USAGE;
        }
        extern char **environ;
        int status = 125;
        int error = rl_experimental_intercept_run(argv[3], argv[5], &argv[5],
                                                   environ, &status);
        if (error) {
            fprintf(stderr, "rl: dev-intercept unavailable or failed: errno=%d: %s\n",
                    error, strerror(error));
            return error == ENOSYS || error == ENOTSUP || error == EOPNOTSUPP ||
                           error == ENOTTY || error == EINVAL
                       ? RL_EX_UNAVAILABLE : 70;
        }
        return status;
    }
    if (argc >= 2 && (!strcmp(argv[1], "doctor") ||
                      !strcmp(argv[1], "info") || !strcmp(argv[1], "benchmark"))) {
        fprintf(stderr, "rl: %s is not implemented in P0\n", argv[1]);
        return RL_EX_UNAVAILABLE;
    }
    fputs("rl: unknown or missing command (try 'rl --help')\n", stderr);
    return RL_EX_USAGE;
}
