#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise a disposable Alpine AArch64 minirootfs on native Linux."""
import errno
import os
from pathlib import Path
import platform
import pty
import select
import signal
import subprocess
import sys
import time


def run_pty(command, env):
    pid, terminal = pty.fork()
    if pid == 0:
        os.execve(command[0], command, env)

    def expect(marker):
        output = bytearray()
        deadline = time.monotonic() + 10
        while marker not in output:
            remaining = max(0, deadline - time.monotonic())
            if not select.select([terminal], [], [], remaining)[0]:
                raise AssertionError(f"PTY timeout waiting for {marker!r}: {output!r}")
            try:
                data = os.read(terminal, 4096)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                data = b""
            if not data:
                raise AssertionError(f"PTY closed before {marker!r}: {output!r}")
            output.extend(data)

    try:
        expect(b"rl-p3-shell> ")
        os.write(terminal, b'test -t 0 && test -t 1 && case $- in *i*) printf "term-%s\\n" ok;; esac\n')
        expect(b"term-ok\r\n")
        os.write(terminal, b'printf "sleep-%s\\n" start; /bin/sleep 30\n')
        expect(b"sleep-start\r\n")
        # Wait until the shell hands foreground control to the external command.
        deadline = time.monotonic() + 5
        while os.tcgetpgrp(terminal) in (0, pid):
            if time.monotonic() >= deadline:
                raise AssertionError("Alpine shell did not give sleep the foreground terminal")
            time.sleep(0.01)
        os.write(terminal, b"\x03")
        expect(b"rl-p3-shell> ")
        os.write(terminal, b'exit 37\n')
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            exited, status = os.waitpid(pid, os.WNOHANG)
            if exited:
                pid = 0
                assert os.waitstatus_to_exitcode(status) == 37, status
                return
            time.sleep(0.01)
        raise AssertionError("interactive shell did not exit")
    finally:
        os.close(terminal)
        if pid:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)


def main():
    rl, root = (Path(arg).resolve() for arg in sys.argv[1:])
    assert platform.system() == "Linux" and platform.machine() == "aarch64"
    assert os.geteuid() != 0, "rootless smoke must run with a non-root host UID"
    print(f"native host: {platform.system()} {platform.machine()} {platform.release()} uid={os.geteuid()}",
          flush=True)

    # Reject a foreign or static fixture before running the shell.
    elf = subprocess.check_output(["readelf", "-h", "-l", root / "bin/busybox"], text=True)
    loader_path = "/lib/ld-musl-aarch64.so.1"
    assert "AArch64" in elf and f"Requesting program interpreter: {loader_path}" in elf, elf
    print(f"Alpine BusyBox: AArch64 ELF, PT_INTERP={loader_path}", flush=True)

    (root / "etc/rl-p3-marker").write_text("alpine-rootfs\n")
    (root / "tmp/rl-absolute").symlink_to("/etc/rl-p3-marker")
    env = {**os.environ, "RL_P3_ENV": "preserved", "PS1": "rl-p3-shell> "}
    command = [str(rl), "run", "-r", sys.argv[2], "--"]
    cwd = os.getcwd()
    script = r'''
set -eu
[ "$0" = /bin/sh ] && [ "$1" = "two words" ] && [ "$2" = "" ]
[ "$RL_P3_ENV" = preserved ]
[ "$(pwd -P)" = / ]
cd ../../etc
[ "$(pwd -P)" = /etc ]
IFS= read -r local_marker < rl-p3-marker
IFS= read -r linked_marker < /tmp/rl-absolute
[ "$local_marker" = alpine-rootfs ] && [ "$linked_marker" = "$local_marker" ]
child=$(/bin/busybox cat /etc/rl-p3-marker)
[ "$child" = "$local_marker" ]
IFS= read -r release < /etc/alpine-release
printf 'pid=%s cwd=%s marker=%s child=%s Alpine=%s\n' "$$" "$(pwd -P)" "$local_marker" "$child" "$release"
exit 23
'''
    with subprocess.Popen([*command, "/bin/sh", "-c", script, "/bin/sh", "two words", ""],
                          env=env, stdout=subprocess.PIPE, text=True) as shell:
        output, _ = shell.communicate(timeout=15)
        assert shell.returncode == 23, (shell.returncode, output)
        assert output.startswith(f"pid={shell.pid} cwd=/etc marker=alpine-rootfs child=alpine-rootfs Alpine="), output
    assert os.getcwd() == cwd
    print(output.strip(), "exit=23", flush=True)

    def failure(path, status, error):
        result = subprocess.run([*command, path], capture_output=True, text=True, timeout=10)
        assert result.returncode == status and f"errno={error} (" in result.stderr, result
        assert "execve in rootfs" in result.stderr, result
        print(f"{path} exit={status} {result.stderr.strip()}", flush=True)

    failure("/bin/rl-p3-missing", 127, errno.ENOENT)
    nonexec = root / "tmp/rl-p3-noexec"
    nonexec.write_text("#!/bin/sh\nexit 0\n")
    nonexec.chmod(0o644)
    failure("/tmp/rl-p3-noexec", 126, errno.EACCES)
    loader = root / loader_path.lstrip("/")
    hidden = loader.with_name(loader.name + ".hidden")
    loader.rename(hidden)
    try:
        failure("/bin/sh", 127, errno.ENOENT)
    finally:
        hidden.rename(loader)

    run_pty([*command, "/bin/sh", "-i"], env)
    print("Alpine shell PTY, foreground child Ctrl-C, and exit=37: PASS", flush=True)

    experiment = [str(rl), "dev-intercept", "--root", sys.argv[2],
                  "--alpine-shell", "--", "/bin/sh"]
    script = r'''
set -eu
[ "$0" = /bin/sh ] && [ "$1" = "two words" ] && [ "$2" = "" ]
[ "$RL_P3_ENV" = preserved ]
IFS= read -r linked_marker < /tmp/rl-absolute
cd etc
IFS= read -r local_marker < rl-p3-marker
[ "$local_marker" = alpine-rootfs ] && [ "$linked_marker" = "$local_marker" ]
printf 'musl direct invocation marker=%s\n' "$local_marker"
exit 29
'''
    shell = subprocess.run([*experiment, "-c", script, "/bin/sh", "two words", ""],
                           env=env, capture_output=True, text=True, timeout=15)
    assert shell.returncode == 29 and shell.stdout == "musl direct invocation marker=alpine-rootfs\n", shell
    print(shell.stdout.strip(), "exit=29", flush=True)


if __name__ == "__main__":
    main()
