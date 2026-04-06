#!/bin/sh
set -e

if [ ! -f "configure" ] || [ ! -f "config.h.in" ]; then
    ./autogen.sh
fi

VERSION=$(grep '^PACKAGE_VERSION=' dkms.conf | cut -d'=' -f2 | tr -d "\"'" | xargs)

if [ -z "$VERSION" ]; then
    echo "Error: Could not extract PACKAGE_VERSION from dkms.conf" >&2
    exit 1
fi

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
