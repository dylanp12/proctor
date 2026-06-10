#!/usr/bin/env bash
# Idempotent dev setup: make `cargo build` able to link libseccomp without root.
# The libseccomp crate's -sys build script honors LIBSECCOMP_LIB_PATH (set in
# .cargo/config.toml to .dev/lib); we point a linker-name symlink at the
# runtime .so.2 when the distro dev package isn't installed.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .dev/lib
if [ ! -e .dev/lib/libseccomp.so ]; then
    so2="$(ldconfig -p | awk '/libseccomp\.so\.2/ {print $NF; exit}')"
    if [ -z "${so2}" ]; then
        echo "ERROR: libseccomp.so.2 not found; install libseccomp (>=2.5)" >&2
        exit 1
    fi
    ln -s "${so2}" .dev/lib/libseccomp.so
    echo "linked .dev/lib/libseccomp.so -> ${so2}"
fi
echo "dev setup OK"
