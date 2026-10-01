#!/usr/bin/env bash
# Run as the repository owner, not sudo. Does not replace curl's QUIC libraries.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION=1.16.0
SHA256=367cbcecaca539f76453c49454d8e7b38ecb162acf89cd571535ac4acf82a2b4
PREFIX="$ROOT/tools/ngtcp2-week8"
BUILD="$ROOT/build/week8"
if [[ -x "$PREFIX/bin/gtlsclient" ]]; then
    "$PREFIX/bin/gtlsclient" --help >/dev/null
    echo "Đã có gtlsclient: $PREFIX/bin/gtlsclient"
    exit 0
fi
for cmd in curl tar make g++ pkg-config; do
    command -v "$cmd" >/dev/null || { echo "Thiếu $cmd" >&2; exit 1; }
done
pkg-config --exists gnutls || { echo 'Cần libgnutls28-dev' >&2; exit 1; }
[[ -f /usr/include/ev.h ]] || { echo 'Cần libev-dev' >&2; exit 1; }
mkdir -p "$BUILD"
cd "$BUILD"
ARCHIVE="ngtcp2-$VERSION.tar.xz"
if [[ ! -f "$ARCHIVE" ]]; then
    curl --fail --location --max-time 120 -o "$ARCHIVE.part" \
      "https://github.com/ngtcp2/ngtcp2/releases/download/v$VERSION/$ARCHIVE"
    mv -- "$ARCHIVE.part" "$ARCHIVE"
fi
printf '%s  %s\n' "$SHA256" "$ARCHIVE" | sha256sum --check -
if [[ ! -d "ngtcp2-$VERSION" ]]; then
    tar -xf "$ARCHIVE"
fi
cd "ngtcp2-$VERSION"
PKG_CONFIG_PATH="$ROOT/tools/curl-h3/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}" \
    ./configure --prefix="$PREFIX" --with-gnutls > ../configure.log 2>&1
make -j2 > ../make.log 2>&1
make install > ../install.log 2>&1
mkdir -p "$PREFIX/bin"
./libtool --mode=install install examples/gtlsclient "$PREFIX/bin/gtlsclient"
"$PREFIX/bin/gtlsclient" --help >/dev/null
echo "Đã cài: $PREFIX/bin/gtlsclient"
