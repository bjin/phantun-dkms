#!/bin/sh
set -eu

VERSION=$(./dkms-version.sh)

if [ ! -f "configure" ] || [ ! -f "config.h.in" ] || ! grep -F "PACKAGE_VERSION='$VERSION'" -q -m1 configure; then
    ./autogen.sh
fi

TARBALL="phantun-dkms_${VERSION}.tar.gz"

tar czf "${TARBALL}" --owner=0 --group=0 \
    src/*.c \
    src/*.h \
    configure \
    config.h.in \
    dkms.conf \
    Kbuild \
    Makefile.in \
    LICENSE

printf "%s\n" "${TARBALL}"
