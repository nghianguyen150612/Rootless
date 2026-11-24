# Development checkpoints

- **P0 — Complete**: C17 CLI, isolated capability checks, Linux build/tests,
  GitHub CI, Termux `.deb` local-build recipe. Acceptance: report accurately
  distinguishes supported, unsupported, permission_denied, unknown, not_tested.
  Real Android validation: **NOT_RUN**.
- **P1 — Complete**: native static ELF validation and direct `execveat`
  execution; isolated namespace/mapping/chroot feasibility probes. Rootfs
  execution remains unsupported.
- **P2 — Selective syscall prototype**: seccomp USER_NOTIF supervisor with an
  absolute-`openat` redirection fixture, P1 direct execution retained, and
  explicit limitations in `docs/p2-fast-syscall-engine.md`. Not a rootfs or
  filesystem isolation backend. Linux GCC/Clang and native ARM64 CI evidence
  requires successful workflow runs; Android/Termux: **NOT_RUN**.
- **P3 — Complete on native Linux ARM64**: Alpine musl shell through kernel
  chroot, with a separate direct-musl interception experiment. See
  [P3 validation](p3-alpine-shell.md). Android/Termux: **NOT_RUN**.
- **P4 — Pending**: dirfds, CWD, symlinks, openat2, rename/link/unlink and
  fork/exec semantics, tested against real chroot.
- **P5 — Pending**: progressive, evidenced compatibility (BusyBox, apk,
  Debian shell, Python, Git, OpenSSH, web server, database).
- **P6 — Pending**: reproducible benchmark host/chroot/PRoot on same device,
  memory footprint, Android compatibility matrix, packaging and release.

No phase is marked passed on inference alone. Do not auto-merge or release.
