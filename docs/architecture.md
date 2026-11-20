# Architecture decision record — P0 (2026-11-20)

P0 builds only a CLI and a fact-finding layer. No runtime engine is selected
until the exact Android environment has been evaluated. All probe outcomes are
narrow operational evidence, not proof that a full engine will work.

| Candidate | Technical premise | Principal blocker | P0 decision |
| --- | --- | --- | --- |
| A: kernel-native | User+mount namespaces and CAP_SYS_CHROOT scoped to a user namespace, with real chroot | Android SELinux/seccomp policy and kernel configuration; mapping/mount restrictions | Probe namespace creation; do not attempt chroot yet |
| B: native fast | Intercept only path-sensitive syscalls; leave unaffected syscalls native | SIGSYS signal handler cannot safely perform arbitrary path resolution, reissue syscalls, or transparently continue the trapped syscall; exec/dynamic linker and threads complicate full coverage | Probe seccomp FILTER and TRAP in children; *no virtualization* |
| C: ptrace fallback | Tracer can supervise tracee syscall boundaries and signals | Tracing permission, context-switch overhead, races, process lifecycle | Probe PTRACE_TRACEME only; no fallback implementation |

## Security and semantics

- Native execution means no CPU instruction emulation. It does *not* imply zero
  syscall interception overhead or ABI compatibility between Android Bionic and
  an arbitrary guest glibc program.
- The kernel must actually permit creating a namespace. A user namespace
  grants capabilities **inside its scope**, not Android host root. UID/GID
  mappings, mount propagation, root switch and SELinux are separate checks.
- `SECCOMP_RET_TRAP` delivers SIGSYS; the filtered syscall is *not* resumed
  automatically after the handler returns; the apparent return value is
  architecture-dependent. Any syscall replacement must explicitly
  handle the register-level ABI, error codes, async-signal-safety, recursion,
  multithreading, signals and filter inheritance. Do not assume in-handler
  userspace path walking is safe.
- `openat2(RESOLVE_IN_ROOT)` constrains resolution **for that operation**; it
  does not virtualize `renameat2`, `readlinkat`, `execve`, dirfd-relative paths,
  inherited file descriptors or CWD semantics. `/proc` magic links need separate
  consideration. POSIX rename/link operations must be analyzed against a
  kernel-native chroot oracle with race/TOCTOU tests.
- Android app sandbox SELinux rules still apply even if namespace syscalls
  succeed. Never evade these policies or suggest bypassing SELinux.
- No rootfs, guest ELF, static/dynamic executable, shell or distro has passed
  tests at P0. A readable LSM label (which may be AppArmor, not SELinux) proves no
  capability to execute files under app-private paths.

## References

- Linux `seccomp(2)`: https://man7.org/linux/man-pages/man2/seccomp.2.html
- Linux `user_namespaces(7)`: https://man7.org/linux/man-pages/man7/user_namespaces.7.html
- Linux `chroot(2)`: https://man7.org/linux/man-pages/man2/chroot.2.html
- Linux `openat2(2)`: https://man7.org/linux/man-pages/man2/openat2.2.html
- Linux `ptrace(2)`: https://man7.org/linux/man-pages/man2/ptrace.2.html
- Android app sandbox: https://source.android.com/docs/security/app-sandbox
- Termux package guide: https://github.com/termux/termux-packages/wiki/Creating-new-package

Compatibility baseline for future phases: compare PRoot and fake-chroot-ng
by documented operations and direct measurements, not claimed speedups.
