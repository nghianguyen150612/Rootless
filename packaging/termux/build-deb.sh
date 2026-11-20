#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Run on Termux aarch64, from any working directory; no root needed.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
: "${PREFIX:?Termux PREFIX must be set}"
: "${TMPDIR:?Termux TMPDIR must be set}"
case "$PREFIX" in
    /data/data/*/files/usr) ;;
    *) echo "Expected Termux PREFIX under /data/data/*/files/usr" >&2; exit 1 ;;
esac
if [ "$(uname -m)" != "aarch64" ]; then
    echo "This package recipe builds on Android AArch64 only" >&2
    exit 1
fi
for tool in cmake dpkg-deb mktemp; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "Missing required tool: $tool" >&2; exit 1;
    }
done

work=$(mktemp -d "$TMPDIR/rootless-p2.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
cmake -S "$repo_dir" -B "$work/build" \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF -DCMAKE_INSTALL_PREFIX="$PREFIX"
cmake --build "$work/build" --parallel 2
mkdir -p "$work/pkg/DEBIAN"
DESTDIR="$work/pkg" cmake --install "$work/build"
cat > "$work/pkg/DEBIAN/control" <<'CONTROL'
Package: rootless
Version: 0.1.0~p2
Architecture: aarch64
Maintainer: Rootless contributors
Section: utils
Priority: optional
Description: Experimental rootless native-first Linux runtime (P2 syscall prototype)
 Direct static ELF execution only; no rootfs isolation.
CONTROL
out="$repo_dir/rootless_0.1.0~p2_aarch64.deb"
dpkg-deb --build --root-owner-group "$work/pkg" "$out"
printf 'Package created: %s\n' "$out"
