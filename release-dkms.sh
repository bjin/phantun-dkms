#!/bin/sh
set -e

if [ ! -f "configure" ] || [ ! -f "config.h.in" ]; then
    ./autogen.sh
fi

VERSION=$(./dkms-version.sh)

TARBALL="phantun-dkms_${VERSION}.tar.gz"

tar czf "${TARBALL}" \
    src/*.c \
    src/*.h \
    configure \
    config.h.in \
    dkms.conf \
    Kbuild \
    Makefile.in \
    LICENSE
