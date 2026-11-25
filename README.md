# Rootless

**As close to chroot as possible, without root.**

Rootless is an experimental, CLI-only, native-first Linux runtime project for
**Android AArch64**, developed for Termux. The command is `rl`. Rootless does
**not** require Magisk, `su`, a modified kernel, an unlocked bootloader or an APK.

## P3 native Alpine shell

```sh
rl run -r ./alpine -- /bin/sh
```

This command launches a shell from an extracted Alpine rootfs when the host
permits private mount namespaces and chroot. Native Linux ARM64 validation
used Alpine 3.23.8 and demonstrated guest file reads, a BusyBox child command,
and terminal interaction through a PTY. The kernel resolves the guest musl
interpreter inside the rootfs. `rl native-probe` checks the prerequisites
in a disposable child. Android/Termux execution remains **NOT_RUN**.

`rl run -- ./static-program [ARG...]` remains the direct native ELF64 static
ET_EXEC path, using the caller's credentials, working directory, environment
and inheritable descriptors. Neither run mode searches PATH. Use trusted
guest programs and rootfs trees.

`rl dev-intercept --root DIR -- FILE [ARG...]` remains the development-only
P2 absolute `openat` experiment. Its explicit `--alpine-shell -- /bin/sh`
variant starts the Alpine AArch64 musl interpreter directly with selective
path redirection. Relative paths and unhandled syscalls can reach the host.
See [P3 implementation and validation](docs/p3-alpine-shell.md),
[P1 direct execution](docs/p1-native-execution.md) and
[P2 interception](docs/p2-fast-syscall-engine.md).

## P4 experimental filesystem compatibility

`rl dev-intercept --root DIR --vfs -- /FILE [ARG...]` adds virtual CWD,
directory-relative lookup, and metadata for a trusted, single-process
native static guest. It is read-only for translated operations and
requires no user namespace. It provides no filesystem isolation.
`rl run -r` continues to select kernel chroot. See the [syscall coverage
matrix and backend limits](docs/p4-filesystem-process-compat.md).

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
pkg install clang cmake make python
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/rl probe --verbose
```

To create a local Termux `.deb` (requires `dpkg-deb`):

```sh
pkg install clang cmake make python dpkg
sh packaging/termux/build-deb.sh
pkg install ./rootless_0.1.0~p2_aarch64.deb
rl probe
```

The script builds a Termux-prefix binary on-device; it has **not** been
validated on real Android in P2. Do not try to install a Linux/glibc CI build
into Termux. `pkg install rootless` will not work until a Termux package
repository publishes it.

### CLI contracts

| Command | Current behavior |
| --- | --- |
| `rl --version`, `rl --help` | Implemented |
| `rl probe [--verbose]` | Executes isolated kernel feature probes |
| `rl run -- FILE [ARG...]` | Native direct static ELF execution |
| `rl dev-intercept --root DIR -- FILE [ARG...]` | Experimental selected `openat` interception; not isolation |
| `rl dev-intercept --root DIR --vfs -- /FILE [ARG...]` | Experimental read-only VFS for a native static guest |
| `rl native-probe` | Isolated P1 namespace/mapping/chroot feasibility |
| `rl run -r ROOTFS -- COMMAND` | Kernel chroot with a private mount namespace |
| `rl dev-intercept --root DIR --alpine-shell -- /bin/sh [ARG...]` | AArch64 musl launch experiment with selected absolute `openat` redirection |
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
