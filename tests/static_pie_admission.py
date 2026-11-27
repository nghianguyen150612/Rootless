# SPDX-License-Identifier: GPL-3.0-only
"""Reject malformed and dependent variants of a real native static PIE."""
import errno
import pathlib
import struct
import subprocess
import sys
import tempfile

rl, fixture = sys.argv[1:]
data = bytearray(pathlib.Path(fixture).read_bytes())
phoff = struct.unpack_from('<Q', data, 32)[0]
phnum = struct.unpack_from('<H', data, 56)[0]
phdrs = [phoff + 56 * i for i in range(phnum)]
dynph = next(p for p in phdrs if struct.unpack_from('<I', data, p)[0] == 2)
dynoff = struct.unpack_from('<Q', data, dynph + 8)[0]
with tempfile.TemporaryDirectory() as temp:
    path = pathlib.Path(temp) / 'guest'
    def reject(blob, error):
        path.write_bytes(blob)
        path.chmod(0o755)
        result = subprocess.run([rl, 'run', '--', str(path)], capture_output=True)
        assert result.returncode == 126 and f'errno={error}:'.encode() in result.stderr, result.stderr
    altered = data.copy()
    struct.pack_into('<q', altered, dynoff, 1)  # DT_NEEDED
    reject(altered, errno.ENOTSUP)
    altered = data.copy()
    struct.pack_into('<Q', altered, dynph + 8, len(data) + 1)
    reject(altered, errno.ENOEXEC)
    altered = data.copy()
    struct.pack_into('<I', altered, dynph, 3)  # PT_INTERP
    reject(altered, errno.ENOTSUP)
    altered = data.copy()
    struct.pack_into('<H', altered, 18, 0xffff)
    reject(altered, errno.ENOEXEC)
