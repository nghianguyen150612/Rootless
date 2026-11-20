#!/usr/bin/env python3
import os
import pathlib
import subprocess
import sys
import tempfile


def main():
    rl, fixture = sys.argv[1:]
    caller_cwd = os.getcwd()
    with tempfile.TemporaryDirectory(prefix="rootless-p2-") as temporary:
        root = pathlib.Path(temporary) / "root"
        root.mkdir()
        (root / "marker.txt").write_text("redirected-ok\n")
        (root / "relative.txt").write_text("relative-native-ok\n")

        result = subprocess.run(
            [rl, "dev-intercept", "--root", str(root), "--", fixture],
            text=True, capture_output=True, check=False
        )
        if result.returncode != 0:
            raise AssertionError(
                f"redirected fixture exited {result.returncode}: "
                f"stdout={result.stdout!r} stderr={result.stderr!r}"
            )
        if "absolute=redirected-ok" not in result.stdout:
            raise AssertionError(f"absolute path was not redirected: {result.stdout!r}")
        if "relative=relative-native-ok" not in result.stdout:
            raise AssertionError(f"relative path did not use root cwd: {result.stdout!r}")
        if "getpid=" not in result.stdout:
            raise AssertionError(f"unrelated getpid syscall failed: {result.stdout!r}")

        missing = subprocess.run(
            [rl, "dev-intercept", "--root", str(root), "--", fixture, "--missing"],
            text=True, capture_output=True, check=False
        )
        if missing.returncode != 0 or "missing errno=2" not in missing.stdout:
            raise AssertionError(
                f"ENOENT semantics failed: status={missing.returncode} "
                f"stdout={missing.stdout!r} stderr={missing.stderr!r}"
            )
        if os.getcwd() != caller_cwd:
            raise AssertionError("experimental child changed caller working directory")
    print("seccomp USER_NOTIF selective openat and path redirect: PASS")


if __name__ == "__main__":
    main()
