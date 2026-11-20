/* SPDX-License-Identifier: GPL-3.0-only */
#define _POSIX_C_SOURCE 200809L
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "exit")) return atoi(argv[2]);
    if (argc > 1 && !strcmp(argv[1], "signal")) { raise(atoi(argv[2])); return 99; }
    if (argc > 1 && !strcmp(argv[1], "fd"))
        return write(atoi(argv[2]), "inherited", 9) == 9 ? 0 : 98;
    if (argc > 1 && !strcmp(argv[1], "pid")) { printf("%ld\n", (long)getpid()); return 0; }
    for (int i = 0; i < argc; ++i) printf("arg[%d]=%s\n", i, argv[i]);
    const char *value = getenv("RL_TEST_ENV");
    printf("env=%s\n", value ? value : "<absent>");
    return 0;
}
