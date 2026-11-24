# P3 native Alpine shell — COMPLETE

P3 builds on `feat/p2-fast-syscall-engine` at
`35de45b5d88861dee7584a42893daf2c5790905d`. The rootfs acceptance path is the
kernel chroot backend.

```sh
rl run -r ./alpine -- /bin/sh
```

## Kernel backend

The launcher opens the host rootfs directory and makes it the launcher's CWD
before cloning the mount namespace, so the kernel remaps the CWD into the new
mount namespace. It uses the P1 mapping mechanism to map namespace UID and
GID 0 to the effective host UID and GID. It denies changes to supplementary
groups before writing the maps. If user namespace creation fails, it proceeds
only when the caller already has both CAP_SYS_ADMIN and CAP_SYS_CHROOT. A
private mount namespace and private recursive propagation are required in both
cases. The launcher calls `chroot(".")`, sets CWD to `/`, and invokes
`execve` with the original guest argv and environment.

The parent's root, CWD, credentials and namespaces remain intact. Successful
launch replaces the launcher, preserving its PID, terminal, process group
and inheritable descriptors. The command is resolved from the guest root,
with no PATH search. Failure identifies the operation and numeric errno.
ENOENT returns 127 and other launch errors return 126. A shell that launches
returns its own exit status or terminates by signal normally.

The kernel resolves PT_INTERP after the root switch. Alpine BusyBox uses
`/lib/ld-musl-aarch64.so.1`, and musl's normal library lookup runs against the
guest filesystem. The kernel provides the normal ELF auxiliary vector,
including executable and interpreter addresses. Native static PIE and child
exec use the same kernel path. Static PIE was investigated at the mechanism
level and was outside this smoke test. Symlinks, traversal, descriptor-relative
operations, `openat2`, stat/access/readlink and CWD use Linux semantics inside
the changed root.

Use a trusted rootfs and program. Chroot changes pathname lookup but inherited
descriptors may still reference files or directories outside it. The launcher
provides no new mounts for `/proc` or `/dev`, PID or network namespace, or
environment filtering. Guest mounts and access remain subject to host policy.
When any required operation is refused, `run -r` fails at that step. Use
`rl native-probe` to inspect the namespace and chroot prerequisites. On the
Ubuntu 24.04 regression runners, the unprivileged probe stopped at the
`/proc/self/setgroups` write with EACCES (13). The Ubuntu 22.04 ARM64 smoke host
allowed the full sequence with host UID 1001.

## P2-based musl experiment

```sh
rl dev-intercept --root ./alpine --alpine-shell -- /bin/sh -c 'read v </etc/alpine-release; echo "$v"'
```

The kernel's internal PT_INTERP lookup does not issue a tracee `openat` and
does not trigger USER_NOTIF. The experiment pins the rootfs's standard
AArch64 musl interpreter through `openat2`, checks that it is native ET_DYN
without its own PT_INTERP, and starts it with `execveat`. Musl maps and
relocates `/bin/sh` itself and uses `--argv0` to set the shell's argv[0].
Musl gets the original environment and uses its own library search, including
`LD_LIBRARY_PATH` and the Alpine interpreter configuration. Absolute
`openat` calls made by musl and BusyBox go through the same pinned root
directory. The kernel exec image and auxiliary vector originate with the
loader, so executable identity such as `/proc/PID/exe` differs. Loading the
shell as a mapped program also differs from the kernel's per-file exec
checks. The development command has a separate launcher, supervisor and
guest PID. It sets `no_new_privs` and reports the shell-style guest exit
status. Musl's own program-load failures use musl's diagnostics and status.

The supervisor copies the tracee's path and checks notification validity again
before the open. It resolves absolute paths with
`RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS`, returns kernel open errors as
negative errno, and injects successful descriptors with atomic
`SECCOMP_ADDFD_FLAG_SEND`, preserving `O_CLOEXEC`. The original P2 fixture
retains the legacy injection path on kernels without atomic reply support.
The experiment needs `openat2`, seccomp USER_NOTIF with atomic injection, and
permission to read tracee memory via `process_vm_readv` or `/proc/PID/mem`.

This is selective redirection for controlled programs. USER_NOTIF provides
no security boundary. The following operations retain their host behavior.

- Relative `openat` keeps the tracee's real CWD and dirfd. Initial CWD is the
  host rootfs directory. `cd etc` from there works, while absolute `cd`,
  `fchdir`, `getcwd`, and relative traversal or symlinks can expose host
  paths. Inherited descriptors keep their original targets.
- Tracee `openat2`, stat/access/readlink and mutations such as rename and
  unlink bypass redirection. Absolute redirected opens run under supervisor
  credentials, and `openat2` accepts a narrower set of flags than `openat`.
- Child fork/wait stay native. A child inherits the filter, while a child
  exec path and its kernel interpreter lookup still use the host root.
  Guest child exec and interactive terminal behavior are outside the
  experiment's support.
- Tracee memory can change during copying or before a continued syscall.
  Validity checks and atomic injection handle stale notifications but
  cannot undo open side effects or eliminate path-memory races. A blocking
  open can stall the serial supervisor. The worker reaps descendants and
  can therefore outlive the primary shell. Signals sent only to the launcher
  are not forwarded.

These limits keep the experiment behind the explicit development command.
`rl run -r` selects chroot only.

## Native validation

The [GitHub Actions run](https://github.com/nghianguyen150612/Rootless/actions/runs/45513866224)
validated runtime commit `41e354ab24732fae94f420de6c233a899daf3a1a`. GCC 13.3.0
and Clang 18.1.3 built on x86_64 and native AArch64 Ubuntu 24.04. Each
configuration passed all nine P0–P2 CTest cases, including static native
execution and selective interception. Local x86_64 GCC 14.2.0 also passed
the nine cases.

The [Alpine smoke job](https://github.com/nghianguyen150612/Rootless/actions/runs/45513866224/job/138868156684)
built with GCC 11.4.0 on Ubuntu 22.04 ARM64, kernel `6.8.0-1070-azure`.
It verified the SHA-256 of the official Alpine 3.23.8 AArch64 minirootfs and
inspected BusyBox's AArch64 ELF header and musl PT_INTERP.

| Check | Observed result |
| --- | --- |
| Kernel chroot `/bin/sh` | Same PID as the launcher, argv and environment checks passed |
| Rootfs access | `cwd=/etc marker=alpine-rootfs child=alpine-rootfs Alpine=3.23.8`, exit 23 |
| Path behavior | Root-clamped `..`, relative read, absolute symlink and BusyBox child exec passed |
| Failed launch | Missing executable and missing PT_INTERP returned ENOENT (2), exit 127. Non-executable file returned EACCES (13), exit 126 |
| Interactive PTY | Shell detected the terminal, foreground `sleep` received Ctrl-C, prompt returned, explicit exit returned 37 |
| Musl experiment | `musl direct invocation marker=alpine-rootfs`, exit 29 |

Android/Termux is **NOT_RUN**. Terminal evidence covers the PTY sequence
above. Broad job control, filesystem differential coverage, stress and
performance remain later checkpoints.

## Next checkpoint

On a real AArch64 Android/Termux device, capture the exact outcomes of
`rl native-probe` and the musl experiment. Use P4 to compare CWD, dirfd,
metadata and child exec semantics against kernel chroot before expanding
userspace workload coverage.
