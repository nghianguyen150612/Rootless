# P2 native fast syscall engine

P2 adds an isolated, development-only selective syscall experiment on top of
the P1 base `feat/p1-native-execution` at
`1a4a3d19ea18a01ce329ccc821aabf9ee78bcc6e`. Pull request #2 is the P1 change
at that same commit. The ordinary `rl run -- FILE [ARG...]` implementation is
unchanged: it validates and directly `execveat`s the native ELF without
installing a filter or starting a supervisor.

## Selected mechanism

`rl dev-intercept --root DIR -- FILE [ARG...]` is an explicit P2-only entry
point. The prototype accepts the same bounded static ET_EXEC formats as P1.
It forks a private supervisor worker, then forks the guest. The guest changes
its working directory to `DIR`, sets `no_new_privs`, installs a seccomp-BPF
filter, passes the `SECCOMP_FILTER_FLAG_NEW_LISTENER` descriptor to the worker
over a Unix socket, and executes the already checked executable descriptor.
The filter selects only the host-native `openat` syscall number. Every other
syscall goes through the kernel unchanged. Relative `openat` paths use the
guest's root directory as its current directory and are continued in the
kernel. Absolute `openat` paths are copied by the supervisor and opened using
`openat2` with `RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS`; the resulting file
descriptor is injected into the guest with `SECCOMP_IOCTL_NOTIF_ADDFD`. Open
errors are returned as negative errno values in the notification response,
which preserves the usual libc `-1`/`errno` behavior. No SIGSYS handler is
used. The supervisor does not execute inside a signal handler, so its path
resolution cannot recurse through the guest's filter.

The supervisor runs in a separate child process and enables
`PR_SET_CHILD_SUBREAPER` only there. It stays alive while the guest or adopted
descendants remain, handles notifications serially, and propagates the primary
guest's exit status. Closing the worker process or pipe cannot mutate the
caller's current directory or install a filter in the caller. If the kernel
does not support a required seccomp notification or `openat2` operation, the
command reports an errno and exits unavailable/failure; there is no silent
fallback to P1 or to unsafe path walking. Some environments block
`process_vm_readv`; in that case the prototype tries the parent-child
`/proc/PID/mem` interface. Procfs and ptrace access policy can also reject
that read.

## Mechanism comparison

| Mechanism | Arbitrary native AArch64 compatibility | P2 decision |
| --- | --- | --- |
| Selective seccomp-BPF with default ALLOW | Good fast path for unrelated syscalls; selected native syscall ABI numbers/arguments are exposed by the kernel. It does not provide syscall emulation by itself. | Use as the filter front end. This build checks AArch64 and x86_64 native syscall ABIs. |
| `SECCOMP_RET_TRAP` / SIGSYS | A caught syscall is not resumed as a normal syscall. A handler must decode/replace registers, reproduce kernel errno conventions, and deal with async-signal-safety, recursion, threads and signal delivery. Caught handlers reset on exec, while the filter remains. | Rejected for path work in a handler. |
| `SECCOMP_RET_USER_NOTIF` | Kernel mediates selected calls in an ordinary supervisor context. Filter is inherited across fork and exec; the listener descriptor can be held outside the guest. Requires `no_new_privs` or privilege, notification support (Linux 5.0+), and descriptor injection support (Linux 5.9+ for `ADDFD`). It serializes selected operations and supervisor availability becomes part of guest liveness. | Selected for the proof of concept because unrelated calls remain native and path resolution happens in a regular process context. |
| ptrace | Offers broad register and syscall control, but requires tracing permission and stop/resume coordination around syscalls, signals, fork/exec and threads. It has higher context-switch overhead and more opportunities for semantic races. | Keep as a possible later fallback if user notification or descriptor injection is unavailable. Not implemented. |

On AArch64, the raw syscall number is in `x8`, arguments are in `x0`–`x5`,
and the raw result is in `x0`; kernel errors use the negative errno range.
The seccomp notification ABI supplies the syscall number and arguments, and
the supervisor returns the injected descriptor or a negative errno through
the notification response. The normal libc wrapper presents `-1` and sets
`errno`. This avoids signal-handler register rewriting. The syscall number
comes from the build's native headers, so this is not a cross-ABI translator.

## Explicit limits and blockers

This is path-redirection evidence for a controlled fixture, not a rootfs
runtime or filesystem isolation. Only absolute `openat` is redirected.
Relative `openat` is continued; `open`, `openat2`, stat/access/readlink,
rename/link/unlink, exec paths, dirfd semantics, inherited descriptors, and
many other filesystem syscalls remain native and can reach the host. A target
can bypass the experiment by selecting an unfiltered syscall. The worker
applies `no_new_privs` to the guest, which changes set-ID exec semantics.
Changing CWD and using procfs for tracee memory also differ from transparent
P1 direct execution. Therefore do not use this command as a security boundary
or claim transparent filesystem behavior across `execve`.

The seccomp filter is inherited across `execve` and fork. A SIGSYS handler is
not involved; caught handlers would be reset by exec, but user notification
continues because the filter is inherited and the worker retains the listener.
The worker subreaper keeps supervising adopted descendants after the main
guest exits. Multi-threaded notifications are serialized; path memory is
copied from a tracee and then resolved from that stable copy. This does not
provide a complete synchronization model for every concurrent filesystem
operation.

Android/Termux kernel versions, seccomp policy, SELinux access to procfs and
`process_vm_readv`, and notification ioctls vary by device. Linux AArch64 CI is
not Android validation. Android/Termux remains **NOT_RUN** pending execution on
a real device. Required notification features failing there are a documented
compatibility blocker, not grounds to bypass SELinux or switch silently to
ptrace.

## P2 evidence and deferred work

The smoke fixture checks that an absolute path reads a file from a disposable
temporary root, a relative `openat` continues normally, `getpid` remains
operational, missing files preserve `ENOENT`, and the caller's CWD is
unchanged. P1's direct execution regressions remain in the same CTest suite.
On Linux x86_64 kernel 6.18.57 with GCC 14.2.0, warning-enabled direct GCC
builds passed for `rl`, the P0 probe tests, and static native fixtures. The P0
probe contract, P1 `native_test.py` regression suite, new interception smoke
test, `rl probe --verbose`, `rl native-probe`, and the Termux packaging script
syntax check passed. CMake and Clang were not installed in this local
environment.

The CI matrix requests native Linux x86_64 and AArch64 with GCC and Clang.
Workflow job results must be inspected before claiming CI pass evidence.
Android is **NOT_RUN**.

Comprehensive filesystem differential tests, directory-FD and CWD semantics,
all path operations, dynamic ELF and loader lifecycle, stress/race testing,
performance measurements, and Android device validation are deferred to P4–P6.

