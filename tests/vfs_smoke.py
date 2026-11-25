#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Compare a narrow syscall contract using a disposable root."""
import errno
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tempfile


def main():
    rl, fixture = (str(Path(arg).resolve()) for arg in sys.argv[1:3])
    reference = "--arm64-reference" in sys.argv[3:]
    allow_unavailable = "--allow-unavailable" in sys.argv[3:]
    if reference:
        assert platform.system() == "Linux" and platform.machine() == "aarch64"
        assert os.geteuid() != 0

    with tempfile.TemporaryDirectory(prefix="rootless-p4-") as temp:
        root = Path(temp, "root")
        (root / "a/b").mkdir(parents=True)
        (root / "a/marker").write_text("marker\n")
        (root / "abs-link").symlink_to("/a/marker")
        (root / "a/b/jump").symlink_to("/a")
        os.mkfifo(root / "regular-fifo")
        shutil.copyfile(fixture, root / "fixture")
        (root / "fixture").chmod(0o755)

        # The sibling dirfd stays inherited and demonstrates out-of-root rejection.
        external = os.open(temp, os.O_RDONLY | os.O_DIRECTORY)
        internal = os.open(root / "a", os.O_RDONLY | os.O_DIRECTORY)
        env = {**os.environ, "RL_P4_EXTERNAL_FD": str(external),
               "RL_P4_INTERNAL_FD": str(internal)}
        vfs = [rl, "dev-intercept", "--root", str(root), "--vfs", "--"]
        try:
            userspace = subprocess.run([*vfs, "/fixture", "vfs"], env=env,
                                       pass_fds=(external, internal), capture_output=True,
                                       text=True, timeout=15)
        finally:
            os.close(internal)
            os.close(external)
        if allow_unavailable and userspace.returncode == 69 and (
            f"errno={errno.ENOSYS}:" in userspace.stderr
            or f"errno={errno.EOPNOTSUPP}:" in userspace.stderr
        ):
            print(f"userspace VFS unavailable: {userspace.stderr.strip()}")
            sys.exit(77)
        assert userspace.returncode == 23, userspace
        expected = "cwd=/a dirfd=ok metadata=ok links=ok errno=ok"
        assert userspace.stdout.splitlines() == [
            expected, "readonly=ok inherited-dirfd=ok external-dirfd=blocked fork/exec=unsupported"
        ], userspace
        assert not userspace.stderr, userspace
        assert (root / "a/marker").read_text() == "marker\n"
        assert not (root / "a/should-not-exist").exists()
        missing = subprocess.run([*vfs, "/missing"], capture_output=True, text=True, timeout=10)
        assert missing.returncode == 70 and f"errno={errno.ENOENT}:" in missing.stderr, missing
        signalled = subprocess.run([*vfs, "/fixture", "signal"], capture_output=True, timeout=10)
        assert signalled.returncode == 128 + signal.SIGTERM, signalled
        print("userspace", *userspace.stdout.splitlines(), "exit=23 SIGTERM=143", flush=True)
        if reference:
            chroot = [rl, "run", "-r", str(root), "--", "/fixture"]
            native = subprocess.run([*chroot, "reference"], capture_output=True,
                                    text=True, timeout=15)
            signalled = subprocess.run([*chroot, "signal"], capture_output=True, timeout=10)
            assert signalled.returncode == -signal.SIGTERM, signalled
            assert native.returncode == 23 and not native.stderr, native
            assert native.stdout.splitlines() == [expected, "child=42"], native
            print(f"native {platform.machine()} {platform.release()} uid={os.geteuid()}",
                  *native.stdout.splitlines(), "exit=23 SIGTERM=signal", flush=True)
            print("P4 controlled differential smoke: PASS", flush=True)


if __name__ == "__main__":
    main()
