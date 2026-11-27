#!/usr/bin/env python3
"""Exercise real static BusyBox applets in a disposable guest tree."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

rl, busybox = (str(Path(p).resolve()) for p in sys.argv[1:3])
with tempfile.TemporaryDirectory(prefix="rootless-busybox-") as temp:
    root = Path(temp)
    (root / "bin").mkdir()
    (root / "data").mkdir()
    shutil.copyfile(busybox, root / "bin/busybox")
    (root / "bin/busybox").chmod(0o755)
    (root / "data/marker").write_text("guest-marker\n")
    (root / "data/link").symlink_to("/data/marker")
    prefix = [rl, "dev-intercept", "--root", temp, "--vfs", "--", "/bin/busybox"]
    for args, expected in [(["pwd"], "/\n"), (["echo", "hello"], "hello\n"),
                           (["cat", "/data/marker"], "guest-marker\n"),
                           (["readlink", "/data/link"], "/data/marker\n")]:
        result = subprocess.run(prefix + args, text=True, capture_output=True, timeout=15)
        print(f"{args}: status={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}", flush=True)
        if result.returncode != 0 or result.stdout != expected:
            sys.exit(1)
    result = subprocess.run(prefix + ["ls", "/data"], text=True, capture_output=True, timeout=15)
    print(f"ls: status={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}", flush=True)
    if result.returncode != 0 or set(result.stdout.split()) != {"link", "marker"}:
        sys.exit(1)
    result = subprocess.run(prefix + ["cat", "/data/missing"], text=True, capture_output=True, timeout=15)
    print(f"missing: status={result.returncode} stderr={result.stderr!r}", flush=True)
    if result.returncode == 0 or "No such file or directory" not in result.stderr:
        sys.exit(1)
