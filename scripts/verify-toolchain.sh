#!/bin/sh
set -eu
# Bootstrap validation, not a claim of a hermetic toolchain. See README.md.
clang++-21 --version | head -n 1 | grep -q '21.1.8' || {
    echo 'PeerFS requires Clang 21.1.8' >&2; exit 1;
}
command -v mold >/dev/null
command -v llvm-ar-21 >/dev/null
pkg-config --exact-version=0.9.0 yaml-cpp || {
    echo 'PeerFS bootstrap requires system yaml-cpp 0.9.0 (libstdc++ ABI)' >&2; exit 1;
}
