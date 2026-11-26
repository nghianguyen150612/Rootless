# P5 checkpoint: partial

P5 is incomplete. No process creation or subsequent exec has been enabled.
The P4 userspace engine remains experimental, single-process and unsuitable
as an isolation boundary. Its lifecycle and syscall restrictions are described
in [P4](p4-filesystem-process-compat.md). Kernel chroot remains the ordinary
`rl run -r` backend and reference.

USER_NOTIF continuation cannot report the resulting child PID atomically or
serialize another thread's CLONE_FS/CLONE_FILES changes with virtual state.
Filter inheritance does not supply the missing fork/exec/exit events. A design
must associate state with process and thread lifetimes, handle PID reuse, clone
flags, exec ordering, exits and notification cancellation. Continuing clone
and reconstructing state later is unsafe. Ptrace fork/clone/exec/exit stops and
syscall control may supply the necessary ordering, but require careful signal,
thread and wait handling and device authorization; neither viability nor
necessity has been demonstrated. A cooperative runtime can synchronize known
calls but cannot cover arbitrary direct syscalls. No mandatory ptrace or
cooperative dependency is introduced. wait and signals remain native within
the existing single-process restrictions; launcher-only signal forwarding and
job control remain incomplete.

Later exec cannot be transparently redirected through USER_NOTIF: continuing it
uses the kernel's pathname and internal PT_INTERP lookup, while notification
cannot rewrite the syscall arguments. P3's explicit musl-loader invocation
changes executable identity and auxiliary-vector and permission behavior; it
is not equivalent to native exec. Fork, vfork, clone, clone3, execve and later
execveat remain rejected in VFS mode. Native reads, directory enumeration and
descriptor operations operate on real descriptors; selected path lookups and
metadata are translated, and selected mutations return EROFS. Other unhandled
syscalls and inherited descriptors may access the host. O_PATH injection is
still unsupported. See P4 for precise operation and error details.

The ARM CI job now obtains a checksum-pinned Alpine static BusyBox package and
runs pwd, echo, cat, readlink, ls and a missing-file check against a disposable
guest tree. The check is mandatory and does not substitute host commands. Its
result is evidence only after the job runs; the shell, apk and other workload
stages are not claimed. On the local x86_64 environment GCC built successfully;
nine CTest cases passed and the VFS case was skipped because bootstrap returned
ENOSYS. Static BusyBox locally hit the same blocker. Clang and P5 ARM CI results
must be recorded separately. P3 ARM Alpine coverage remains in CI.

Android/Termux: **NOT_RUN**. On a real AArch64 device build with Termux clang
and CMake in an executable app-permitted location, run `rl native-probe`, the
VFS fixture and the BusyBox smoke against a native static executable, and record
kernel version, Termux version, exit codes and errno. Verify USER_NOTIF and
atomic ADDFD, openat2, process_vm read/write, procfs visibility, executable
policy and SELinux behavior; ptrace requires separate authorization evaluation.
Do not infer these results from Linux CI or bypass device policy.

Next checkpoint: obtain native ARM results, fix only demonstrated workload
failures, then prototype and validate a lifecycle observation model before
relaxing any process-creation restriction.

## First native ARM CI result

[Run 45782216292](https://github.com/nghianguyen150612/Rootless/actions/runs/45782216292)
passed the GCC and Clang build/regression jobs on both x86_64 and native ARM64,
and the P3 Alpine shell and P4 ARM differential steps. The new BusyBox step
failed before guest execution: `pwd` returned 70, with ENOEXEC (8). The pinned
Alpine binary is an AArch64 static PIE (ET_DYN); P4 validates VFS guests as
static ET_EXEC. No BusyBox applet success is claimed. Supporting static PIE
requires validating its loader and execution properties without weakening the
existing executable checks, and remains future work. The overall CI run failed
on this new workload gate.
