# P1 native execution foundation

Based on P0 branch `feat/p0-foundation-capability-probe`, commit
`467265200916ff66a63debc9237be75c8bb13982`. P0 probe source, public contract and
tests are unchanged. P0 architecture/compatibility documents remain historical.

## Execution semantics

`rl run -- FILE [ARG...]` opens FILE read-only with CLOEXEC and validates a
bounded ELF64 header/program-header table. It accepts static ET_EXEC and conservatively identified static PIE ET_DYN for the
compiler target (AArch64 or x86_64), with at least one PT_LOAD and no PT_INTERP
or PT_DYNAMIC. The kernel remains the ELF loader and final format validator.
The launcher uses `execveat(fd, "", argv, envp, AT_EMPTY_PATH)`, the kernel
descriptor form of execve, to pin the checked
inode instead of reopening a replaceable pathname. It adds no supervisor:
PID, exit status, terminating signals, argv, environment, current directory and
non-CLOEXEC descriptors retain exec semantics. Only the launcher's validation
FD is added and closed at exec. Existing CLOEXEC descriptors close normally.
A successful exec is the final proof that the kernel permits this file.
Preflight alone cannot prove execution permission.

There is no PATH search, environment editing, signal translation, CPU emulation,
interpreter lookup, syscall interception or custom loader. The launcher requires
read permission in addition to kernel execute permission. Executable content
must not be concurrently modified; pinning an inode does not freeze its bytes.
This is ordinary trusted-program execution, not a security boundary. The raw
execveat syscall avoids an Android API-level dependency on libc fexecve and
requires kernel execveat support. ENOSYS or policy denials are reported exactly;
there is no /proc fallback or alternate runtime backend.

On launch failure the CLI returns 127 for ENOENT and 126 otherwise, with exact
numeric errno and strerror. Usage errors return 64. Root-directory execution
returns 69. A guest may itself return any of these values; a launch diagnostic
distinguishes an error. Dynamic ELF, unsupported PIE forms, ELF32, scripts, big-endian ELF
and foreign machines are deliberately rejected. Android's Bionic launcher
cannot establish glibc compatibility; static native execution still depends on
kernel ABI and app/SELinux/seccomp execution policy.

## Feasibility and engine selection

`rl native-probe` creates an empty temporary directory under TMPDIR (or /tmp),
forks a child and performs these operations in sequence:

1. Read existing effective CAP_SYS_CHROOT using capget (absence is EPERM).
2. unshare(CLONE_NEWUSER).
3. Deny supplementary-group changes, then map namespace UID/GID 0 to the
   caller's single UID/GID through /proc/self/{uid,gid}_map. No helper or
   subordinate IDs are used. Missing setgroups control on older kernels is
   reported but permits attempting the mapping.
4. unshare(CLONE_NEWNS), then make / recursively private before any root change.
5. Check effective CAP_SYS_CHROOT in the new namespace.
6. Actually chroot into the empty directory and chdir to / in that child only.

The child exits; the parent removes the temporary directory. A chroot syscall
is never attempted unless mapping, mount isolation, propagation and scoped
capability checks pass. Failures record the exact operation and errno;
dependent operations remain not_tested (errno 0 here means no attempt).
Infrastructure errors fail the report with errno and exit 70. Namespace-local
capabilities do not grant host root. No privilege helpers, SELinux bypasses,
mounts of guest filesystems, daemons or host configuration changes are used.

The only selectable engine is kernel-native **direct** execution for a
supported native file. Invalid/unsupported files and requests for root-directory
semantics select unsupported. Kernel refusal at exec is terminal; no incomplete
virtualization fallback exists. Even if the probe passes, P1 supplies no chroot
execution backend. Chroot alone would also not establish a secure sandbox,
particularly with inherited descriptors and namespace capabilities.

`rl probe [--verbose]` intentionally retains all 13 P0 entries, including
kernel.real_chroot=not_tested. Use the separate P1 report for real chroot checks.
Neither namespace availability nor Android compatibility is inferred from ISA.

## Validation evidence

Local host: Linux x86_64 kernel 6.18.57, uid/gid 1000, GCC 14.2, Debug build.
All 8 CTest cases passed, including all 5 P0 cases. Native static ET_EXEC was
actually executed. Tests verify argv including empty/space arguments, environment,
PID replacement, inherited descriptors, exit values 0/1/69/126/127/255,
SIGINT/SIGTERM/SIGKILL, missing and non-executable files, directories, scripts,
truncated/malformed headers, unsupported machine/class/endian/type, dynamic
headers, root-directory rejection and engine selection.

Real local feasibility: existing CAP_SYS_CHROOT absent (EPERM=1); user namespace,
setgroups deny, UID/GID maps, mount namespace, private propagation, scoped
CAP_SYS_CHROOT and actual chroot/chdir all succeeded. Tests also install
child-only seccomp filters to force EPERM for unshare, mount and chroot,
verify exact failures/skipped dependencies, and verify parent CWD is unchanged.
If a host blocks the injected test's prerequisites, that injection is explicitly
NOT_RUN; it is never reported as exercised. Errors do not identify which host
policy caused a denial solely from errno.

The [GitHub Actions run 44671402861](https://github.com/nghianguyen150612/Rootless/actions/runs/44671402861)
completed successfully for runtime commit
`37de4330bbcc51d7b4e2ce98c57ab0ca51121f1f`:

| Native Linux runner | Compiler | Build, P0 regressions and native execution |
| --- | --- | --- |
| ubuntu-24.04 x86_64 | GCC 13.3.0 | PASS, 8/8 CTest cases |
| ubuntu-24.04 x86_64 | Clang 18.1.3 | PASS, 8/8 CTest cases |
| ubuntu-24.04-arm AArch64 | GCC 13.3.0 | PASS, 8/8 CTest cases |
| ubuntu-24.04-arm AArch64 | Clang 18.1.3 | PASS, 8/8 CTest cases |

All four logs confirm actual static execution, argument/environment propagation,
PID/descriptor preservation, exit/signal behavior and execution errors. No QEMU
or cross-execution is used. The existing P0 source and tests have no diff against
the required base commit. Local GCC build and all eight tests were also rerun
successfully during recovery.

CI feasibility is more restricted than the local host: all four runners report
existing CAP_SYS_CHROOT absent (EPERM=1), user namespace creation supported,
and setgroups denial failing with EACCES=13. UID/GID mapping, mount isolation,
scoped capability and chroot steps therefore remain NOT_TESTED on those runners.
The P0 combined user/mount namespace probe reports EPERM=1. These observed
capability failures do not fail a successfully generated report and do not
prevent direct static execution. A passing CI job is not evidence that chroot
worked there.

Static libc and Python3 are needed for execution tests; CMake warns NOT_RUN if
unavailable outside CI. No compatibility, stress, performance, filesystem
differential or cross-device test infrastructure is added in this recovery.

Android/Termux: **NOT_RUN**. On actual AArch64 hardware, build with CMake,
run CTest and both probe commands, and execute a native static ET_EXEC fixture
from an app-permitted path. Preserve exact device, kernel, policy, errno and
compiler results. The Termux packaging recipe is updated to P1 but only its
shell syntax is validated here. Linux ARM64 results do not establish Android
compatibility. No P2–P6 work or performance claims are included.


## Remaining scope and next checkpoint

P1 provides a working direct native backend and actual isolated namespace/chroot
feasibility checks. It does not provide a rootfs launch backend, and `run -r`
continues to return unsupported. No runtime implementation changes were needed
in this recovery; the runtime commit above remains the compiled CI evidence.

Next checkpoint: execute the existing build and static native smoke tests on
an actual Android AArch64/Termux device and capture namespace/mapping/chroot
results with exact errno values. Until then Android execution is NOT_RUN.
General workload compatibility, stress, differential filesystem behavior,
performance and broad cross-device evaluation remain NOT_TESTED and deferred
to the later roadmap, primarily P4–P6.
