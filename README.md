# Rootless

**As close to chroot as possible, without root.**

Rootless is an experimental, CLI-only, native-first Linux runtime project for
**Android AArch64**, developed for Termux. The command is `rl`. Rootless does
**not** require Magisk, `su`, a modified kernel, an unlocked bootloader or an APK.

## Current status: P0 foundation only

**Rootless cannot yet run a Linux root filesystem or replace PRoot/chroot.**
`rl probe` evaluates narrow host capabilities; it is not a compatibility
certification. `rl run`, `doctor`, `info` and `benchmark` are deliberately
unimplemented and return exit status 69. No daemon, telemetry, guest ELF loader,
path translation, or seccomp-based virtual filesystem exists yet.

### Build / test on Linux

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/rl --help
./build/rl --version
./build/rl probe --verbose
```

These commands work on ordinary Linux for CI validation; the production target
remains Android AArch64. Linux CI does not prove Android behavior.

### Build on Termux (requires an Android AArch64 device)

```sh
pkg install clang cmake make
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/rl probe --verbose
```

To create a local Termux `.deb` (requires `dpkg-deb`):

```sh
pkg install clang cmake make dpkg
sh packaging/termux/build-deb.sh
pkg install ./rootless_0.1.0~p0_aarch64.deb
rl probe
```

The script builds a Termux-prefix binary on-device; it has **not** been
validated on real Android in P0. Do not try to install a Linux/glibc CI build
into Termux. `pkg install rootless` will not work until a Termux package
repository publishes it.

### CLI contracts

| Command | P0 behavior |
| --- | --- |
| `rl --version`, `rl --help` | Implemented |
| `rl probe [--verbose]` | Executes isolated kernel feature probes |
| `rl run -r ROOTFS -- COMMAND` | Not implemented; exit 69 |
| `rl doctor`, `rl info`, `rl benchmark` | Not implemented; exit 69 |
| unknown argument / command | Usage failure; exit 64 |

`rl probe` exits 0 if it successfully produced a report, **including when
capabilities are blocked**. Each feature is `supported`, `unsupported`,
`permission_denied`, `unknown` or `not_tested`.

The seccomp filter, seccomp trap, namespace, ptrace and memory transition probes
run in isolated forked child processes. `rl` never installs a seccomp filter
in its caller. `openat2` reports only that the narrow feature invocation
worked; it is not a correctness or escape test. The seccomp trap test verifies
that `getpid` triggers SIGSYS without emulating a syscall. The apparent
syscall return value after the handler is architecture-dependent.

## Architecture and constraints

See [architecture](docs/architecture.md), [roadmap](docs/roadmap.md) and
[compatibility](docs/compatibility.md). Priority is native execution, accurate
filesystem/process behavior, and then performance. There is no claim that the
project is a sandbox or is faster than PRoot.

## License

GPL-3.0-only; see [LICENSE](LICENSE).
