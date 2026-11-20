# Compatibility report — P0

Only Linux x86_64 CI/local validation has been performed at initial authoring.
The GitHub Actions workflow also *requests* Linux arm64 validation; its result
must be checked after a run. Linux arm64 is **not** Android arm64.

| Feature | P0 status | Evidence needed for production |
| --- | --- | --- |
| Host architecture and kernel release | Reported by `uname` | Real Android details |
| Termux prefix | Heuristic only | Real `$PREFIX`, execution permissions |
| User namespace | Isolated unshare attempt | UID/GID map + caps + SELinux |
| Mount namespace | Isolated unshare after userns attempt | Mount tests and propagation |
| `openat2` | Single `RESOLVE_IN_ROOT` open | Path semantics differential tests |
| seccomp BPF | Install allow-all filter in child | Interception correctness and lifecycle |
| seccomp trap | SIGSYS on getpid in child | Architecture registers, signals, threads |
| ptrace | `PTRACE_TRACEME` in child | Full tracing tracee supervision |
| executable memory | RW→RX `mprotect` in child | File exec, memfd and actual ELF execution |
| real chroot in user namespace | NOT_TESTED | P1 on Android |
| Android app-data executable file | NOT_TESTED | P1 on Termux |
| BusyBox / Alpine / Debian / Python | NOT_TESTED | P3–P5 workload results |

Important: `permission_denied` may reflect kernel, seccomp, SELinux, or other
policy. P0 does not attribute the specific policy solely from `errno`.
