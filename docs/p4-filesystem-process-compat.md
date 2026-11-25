# P4 filesystem and process compatibility

P4 builds on `feat/p3-alpine-shell` at
`31e5b4acaaf85b0a4a9eb9fba031f82271d3e505`. Kernel chroot remains the
default for `rl run -r` and the reference for filesystem behavior. The P1
direct static command, P2 open redirect and P3 Alpine musl experiment
remain available with their existing interfaces.

```sh
rl run -r ./alpine -- /bin/sh
rl dev-intercept --root ./rootfs --vfs -- /path/to/static-guest [ARG...]
```

The second command is an experimental, single-process, read-only pathname
mode for trusted native AArch64 or x86_64 static ET_EXEC guests. It opens the
executable under the selected root, checks it with the P1 ELF validator,
then runs it through the kernel. It uses no user or mount namespaces. It
never substitutes a host executable for the guest command. Setup diagnostics
include errno. Missing kernel support returns 69 for the recognized
unavailable errors. Other setup or supervisor errors return 70. Emulated
syscalls return Linux-style errno to the guest.

## Path model

The supervisor owns an `O_PATH` root descriptor and an `O_PATH` virtual
CWD descriptor. The CWD starts at `/`. An absolute pathname ignores the
tracee dirfd. A relative pathname starts at the virtual CWD for `AT_FDCWD`
or uses a pinned duplicate of the tracee's actual directory through
`/proc/PID/fd`. This accommodates descriptor numbers reused by the kernel and
inherited or duplicated directories. An invalid descriptor returns EBADF,
a file used as a directory returns ENOTDIR, and an out-of-root directory
returns EXDEV.

Linux `openat2` has a single dirfd for both starting directory and root.
To express a separate CWD or dirfd, P4 gets the kernel-reported path of the
pinned directory, reopens its root-relative name and compares device,
inode and mount ID. Only then does it pass the verified base plus the
original relative path to `openat2` under the pinned root. The original
components, including symlinks and `..`, are left for the kernel.
`RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV` rebases absolute
symlink targets, clamps `..` at the guest root and excludes nested mounts.
The base is checked again after lookup. Read opens reopen the selected
regular file or directory by descriptor, so a replacement of its name
after lookup cannot redirect that reopen.

Relative resolution requires a nameable directory. A moved or deleted base
may produce ESTALE, ENOENT or EXDEV, depending on when it is observed. The
before-and-after checks cannot detect a directory moved away and restored
during lookup. Concurrent directory renames are outside the supported
contract. This scheme also cannot reproduce lookup from an unlinked CWD,
or a valid relative pathname whose combination with the verified base
exceeds PATH_MAX. It may recheck ancestor search permissions that a kernel
dirfd walk would skip. These are explicit differences from kernel chroot.

## Syscall coverage

| Guest operation | P4 handling | Limits and observable differences |
| --- | --- | --- |
| `openat`, x86-64 `open` | Rooted lookup, pinned reopen and atomic descriptor injection. `O_CLOEXEC` is preserved on the guest FD. | Read-only regular files and directories. Write access, creation and truncation return EROFS. FIFO, device, socket and `O_PATH` opens return EOPNOTSUPP. The latter is an injection API limitation on the tested kernels. |
| `openat2` | Copies `open_how` and checks size and zero extension bytes. Uses the same descriptor path as `openat`. | Supports resolve 0, `NO_SYMLINKS`, `NO_MAGICLINKS` and `NO_XDEV`, with the engine's own rooted constraints. `BENEATH`, caller-defined `IN_ROOT` and `CACHED` return EOPNOTSUPP. |
| `newfstatat`, `statx`, x86-64 `stat` and `lstat` | Resolves or pins the object, then uses kernel descriptor metadata and writes the native structure into guest memory. | Supports no-follow and empty-string `AT_EMPTY_PATH`. The newer NULL-path form returns EFAULT. Ownership is from the caller's host user namespace. Lookup and reporting of mount-related details can differ. |
| `faccessat`, `faccessat2`, x86-64 `access` | Pins the object and calls kernel `faccessat2`, including `AT_EACCESS` when requested. | Runs with supervisor credentials. `W_OK` reports host permissions on the selected object. The open policy still rejects writes. |
| `readlinkat`, x86-64 `readlink` | Pins the final symlink without following it and writes the requested byte count into guest memory. | Returns the literal symlink payload, including any leading slash. No NUL is appended. |
| `chdir`, `fchdir`, `getcwd` | Checks directory type and search permission, then maintains an actual pinned directory as virtual CWD. `getcwd` returns its guest name. | Changes take effect for translated operations. The guest's real kernel CWD remains the host rootfs directory set at launch. |
| `mkdirat`, `unlinkat`, `renameat`, `renameat2`, `linkat`, `symlinkat`, `mknodat`, `truncate` and filtered legacy forms | Return EROFS. | Future mutation support needs stable parent FDs and final-component semantics, including rename flags, hard-link source policy and symlink payload handling. The current relative base verification is insufficient for safely replaying mutations. |
| `read`, `write`, `close`, `dup`, `fcntl`, `getdents64`, memory and ordinary signals | Native execution on actual guest descriptors and process state. | Inherited descriptors remain usable, including outside the selected root. Descriptor writes follow the descriptor's own permissions. |
| `fork`, `vfork`, `clone`, `clone3` | Return EOPNOTSUPP. | USER_NOTIF alone cannot atomically observe native CWD inheritance or maintain the virtual equivalent across `CLONE_FS`, regular fork and concurrent threads. |
| `execve`, `execveat` | Only the initial pinned static ELF `execveat` is continued. Later exec requests return EOPNOTSUPP. | USER_NOTIF cannot replace guest exec arguments or redirect the kernel's internal PT_INTERP lookup. P3's separate direct-musl mode changes executable identity. |
| Other syscalls | Native on the supported ABI. | Unhandled pathname calls such as `fchmodat` and `fchownat`, inherited descriptors and mechanisms such as `io_uring` can reach host resources. |

USER_NOTIF and this translation layer provide no security boundary. Use
trusted workloads and rootfs trees. Chroot is used as the behavioral
reference and inherits its own descriptor and namespace limitations.

## Notifications and process lifecycle

The worker verifies notification validity on receipt and before operating
on copied paths or writing to guest memory. The launch handshake checks
parent-to-child `process_vm_readv` and `process_vm_writev`, and probes
atomic descriptor injection. It does not use `/proc/PID/mem` for VFS
writes because that interface may override guest memory protections. There
is no guest pathname continuation. The only continuation is the controlled,
scoped launch from the checked FD. Atomic add-and-reply avoids leaving a
descriptor installed if a stale notification is rejected. CWD changes commit
only after a successful notification reply. A cancellation can still leave
bytes written into guest memory just before a signal arrived.

Only the primary guest PID is serviced. The supervisor retains its child
until it can reap it, avoiding PID reuse during a notification. P4 rejects
other execution ABIs and process creation, which removes guest-thread races
from the supported model. External rename, memory-map changes and policy can
still make operations fail. O_PATH lookups avoid opening special files and
ordinary I/O stays native. A filesystem or procfs operation can still block
the serial supervisor, so this mode has no bounded-latency guarantee.

The launcher remains a separate process. For the normal P4 process chain,
the worker is tied to the launcher and the guest to the worker via
`PR_SET_PDEATHSIG`. A worker-side fatal error closes the listener, kills
and reaps its primary guest and reports its error when the launcher is
alive. Guest normal exits propagate and signal exits become `128 + signal`.
Signals addressed only to the launcher are not transparently delivered to
the guest. Full foreground process-group handling, interactive PTY
behavior and job control are supported only to the extent demonstrated
for P3 kernel chroot.

A seccomp trap would need in-tracee register and memory handling and its
handler resets on exec. A cooperative launcher shim could coordinate guest
CWD and fork for applications that call through it, while direct syscalls
would require another mechanism. Ptrace fork/exec stops could provide the
events and register access USER_NOTIF lacks, with greater overhead and
different ptrace and Android policy dependencies. P4 introduces no such
backend and provides no automatic fallback.

## Android and Termux feasibility

**NOT_RUN** on real Android hardware. P4's static mode can operate without
user namespaces when the host permits all the following operations. Linux
version numbers refer to upstream introduction, since vendor kernels may
backport features or restrict them.

- USER_NOTIF appeared in Linux 5.0, ADDFD in 5.9, and atomic ADDFD with SEND
  in 5.14. An app needs permission to install a listener under
  `no_new_privs` and use the notification ioctls. AOSP Zygote installs app
  seccomp filters, and bionic's current common allowlist includes `seccomp`.
  A running device's inherited filter can still restrict the applicable
  syscalls. [Linux USER_NOTIF](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html) · [AOSP Zygote](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/jni/com_android_internal_os_Zygote.cpp) · [Bionic common allowlist](https://android.googlesource.com/platform/bionic/+/refs/heads/main/libc/SECCOMP_ALLOWLIST_COMMON.TXT)
- P4 needs `openat2` (Linux 5.6), `statx` mount IDs and `faccessat2` with
  `AT_EMPTY_PATH` (Linux 5.8). It needs access to the supervisor's procfd
  names and the guest's `/proc/PID/fd` entries. Kernel presence and NDK
  headers do not establish permission in an app domain. [openat2](https://man7.org/linux/man-pages/man2/openat2.2.html) · [statx](https://man7.org/linux/man-pages/man2/statx.2.html) · [faccessat2](https://man7.org/linux/man-pages/man2/faccessat.2.html)
- `process_vm_readv` and `process_vm_writev` both perform ptrace-style
  authorization. Same UID, parenthood and dumpability matter, and SELinux
  policy can still deny access. AOSP has a same-domain untrusted-app
  ptrace rule and restrictions on app-to-nonapp ptrace. Device policy
  and procfs visibility must be verified in the actual Termux process.
  [Linux process memory access](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html) · [AOSP untrusted-app policy](https://android.googlesource.com/platform/system/sepolicy/+/refs/heads/main/private/untrusted_app_all.te) · [AOSP app policy](https://android.googlesource.com/platform/system/sepolicy/+/refs/heads/main/private/app.te)
- Build `rl` for Android AArch64 using Termux's native toolchain and run it
  from an app-permitted executable location. The guest needs a permitted
  native static ELF. A glibc-linked Ubuntu `rl` is not a Termux binary.
  Android 10 applies writable app-home execution restrictions to apps
  targeting API 29 or newer. Termux variants and app install locations
  affect what the host permits. An ELF header check does not override
  execute permission, mount policy or SELinux. [Android 10 execution restrictions](https://developer.android.com/about/versions/10/behavior-changes-10#execute-permission) · [Termux and Android 10](https://github.com/termux/termux-packages/wiki/Termux-and-Android-10)

## Validation

**P4 COMPLETE for the controlled native Linux acceptance.** The
[validation run](https://github.com/nghianguyen150612/Rootless/actions/runs/45723575065)
at `870cff1f18628e82e315af2b4586ccaae7e2e78e` built GCC 13.3 and Clang
18.1 on x86_64 and native AArch64. All four configurations passed 10/10
CTest cases and the required VFS run. On Ubuntu 24.04 ARM64, the VFS
ran despite the chroot feasibility probe stopping at the setgroups
write with EACCES (13).

The [native ARM64 smoke job](https://github.com/nghianguyen150612/Rootless/actions/runs/45723575065/job/139587657543)
ran as UID 1001 on Ubuntu 22.04, Linux `6.8.0-1070-azure`. The same
static fixture under each backend verified virtual CWD, relative paths,
dirfds, `openat2`, metadata, symlinks, root-clamped traversal and representative
errno. Both exited 23. The kernel reference forked and exec'd a child that
inherited CWD and returned 42. Userspace verified that fork and later exec
returned EOPNOTSUPP, an inherited guest dirfd worked, an outside dirfd was
rejected and selected mutations left the fixture unchanged. A guest
SIGTERM remained a signal through chroot and returned 143 through
userspace. The P3 Alpine AArch64 chroot shell, child execution, PTY smoke
and direct-musl experiment also passed.

The [initial CI run](https://github.com/nghianguyen150612/Rootless/actions/runs/45723196903)
exposed EBADF from attempting to inject an O_PATH descriptor. P4 now
reports that form as unsupported and tests ordinary directory FDs,
including close-on-exec and duplication. Local GCC 14.2 built and passed
all nine P0–P3 CTest regressions. The local VFS test reported NOT_RUN after
the bootstrap `process_vm_readv` returned ENOSYS (38). Hosted CI required
the VFS smoke to execute.

## Next checkpoint

Run the P4 static fixture on a real Termux AArch64 device and record each
required primitive's errno and the applicable app policy. For P5, broaden
the differential workload on native Linux and evaluate how to represent
fork inheritance and child exec before enabling those operations.
