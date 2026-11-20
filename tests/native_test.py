# SPDX-License-Identifier: GPL-3.0-only
"""Real kernel execution; no emulation and no privileged test setup."""
import errno
import os
from pathlib import Path
import resource
import signal
import struct
import subprocess
import sys
import tempfile

rl, fixture, dynamic = map(os.path.abspath, sys.argv[1:])
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
def run(*args, **kw):
    return subprocess.run([rl, 'run', '--', *args], capture_output=True, **kw)
def failure(path, number, code=126):
    p = run(str(path))
    assert p.returncode == code, (path, p)
    assert f'errno={number}:'.encode() in p.stderr, p.stderr

p = run(fixture, 'space argument', '', 'literal $HOME', env={**os.environ, 'RL_TEST_ENV': 'value with spaces'})
assert p.returncode == 0, p.stderr
assert p.stdout.decode() == f'arg[0]={fixture}\narg[1]=space argument\narg[2]=\narg[3]=literal $HOME\nenv=value with spaces\n'
for code in (0, 1, 69, 126, 127, 255):
    assert run(fixture, 'exit', str(code)).returncode == code
for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGKILL):
    assert run(fixture, 'signal', str(sig)).returncode == -sig
p = subprocess.Popen([rl, 'run', '--', fixture, 'pid'], stdout=subprocess.PIPE)
assert int(p.communicate()[0]) == p.pid and p.returncode == 0
r, w = os.pipe()
p = run(fixture, 'fd', str(w), pass_fds=(w,))
os.close(w)
assert p.returncode == 0 and os.read(r, 100) == b'inherited'
os.close(r)
failure(dynamic, errno.ENOEXEC if struct.unpack_from('<H', Path(dynamic).read_bytes(), 16)[0] != 2 else errno.ENOTSUP)
with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    failure(root / 'missing', errno.ENOENT, 127)
    failure(root, errno.EACCES)
    f = root / 'fixture'
    data = bytearray(Path(fixture).read_bytes())
    f.write_bytes(data)
    f.chmod(0o600)
    failure(f, errno.EACCES)
    f.chmod(0o700)
    assert run(str(f), 'exit', '42').returncode == 42
    for content in (b'', b'#!/bin/sh\nexit 0\n', data[:32]):
        f.write_bytes(content)
        failure(f, errno.ENOEXEC)
    for offset, value in ((4, b'\x01'), (5, b'\x02'), (18, b'\xff\xff'), (16, b'\x01\x00'), (54, b'\x00\x00')):
        altered = data.copy()
        altered[offset:offset+len(value)] = value
        f.write_bytes(altered)
        failure(f, errno.ENOEXEC)
    # Header permits static ET_EXEC only; reject truncated program tables.
    altered = data.copy()
    struct.pack_into('<Q', altered, 32, len(data))
    f.write_bytes(altered)
    failure(f, errno.ENOEXEC)
    # Valid header with an interpreter is explicitly unsupported.
    altered = data.copy()
    phoff = struct.unpack_from('<Q', altered, 32)[0]
    struct.pack_into('<I', altered, phoff, 3)  # PT_INTERP
    f.write_bytes(altered)
    failure(f, errno.ENOTSUP)
    struct.pack_into('<I', altered, phoff, 2)  # PT_DYNAMIC
    f.write_bytes(altered)
    failure(f, errno.ENOTSUP)
p = subprocess.run([rl, 'run', '-r', '/', '--', fixture], capture_output=True)
assert p.returncode == 69 and b'unsupported' in p.stderr
assert subprocess.run([rl, 'run'], capture_output=True).returncode == 64
print('native static execution, arguments, environment, PID, FDs, exits/signals, errors: PASS')
