#!/bin/sh
set -eu

VERSION_LINE=$(grep '^PACKAGE_VERSION=' dkms.conf | head -n 1)
VERSION=${VERSION_LINE#*=}
VERSION=${VERSION#\"}
VERSION=${VERSION%\"}
VERSION=${VERSION#\'}
VERSION=${VERSION%\'}

if [ -z "$VERSION" ]; then
    echo "Error: Could not extract PACKAGE_VERSION from dkms.conf" >&2
    exit 1
fi

printf '%s\n' "$VERSION"
