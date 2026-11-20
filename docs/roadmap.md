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
- **P3 — Pending**: Alpine ARM64 shell, ELF `PT_INTERP` and dynamic linker
  lifecycle; do not add custom ELF loader without demonstrated need.
- **P4 — Pending**: dirfds, CWD, symlinks, openat2, rename/link/unlink and
  fork/exec semantics, tested against real chroot.
- **P5 — Pending**: progressive, evidenced compatibility (BusyBox, apk,
  Debian shell, Python, Git, OpenSSH, web server, database).
- **P6 — Pending**: reproducible benchmark host/chroot/PRoot on same device,
  memory footprint, Android compatibility matrix, packaging and release.

No phase is marked passed on inference alone. Do not auto-merge or release.
