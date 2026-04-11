#!/bin/sh
set -eu

PACKAGE_NAME=phantun-dkms
MODULE_NAME=phantun
PACKAGE_ARCH=all
SCRIPT_DIR=$(dirname -- "$(readlink -f -- "$0")")

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Error: Required command not found: $1" >&2
        exit 1
    fi
}

write_control_file() {
    cat >"$1" <<EOF
Package: ${PACKAGE_NAME}
Version: ${VERSION}
Section: kernel
Priority: optional
Architecture: ${PACKAGE_ARCH}
Maintainer: Bin Jin <bjin@protonmail.com>
Depends: dkms
Recommends: linux-headers-generic | linux-headers-virtual | linux-headers-amd64 | linux-headers
Homepage: https://github.com/bjin/phantun-dkms
Description: Kernel module re-implementation of phantun, transform UDP streams into fake-TCP streams
EOF
}

write_postinst() {
    cat >"$1" <<EOF
#!/bin/sh
set -e

MODULE_NAME="${MODULE_NAME}"
MODULE_VERSION="${VERSION}"

case "\$1" in
    configure)
        if [ ! -x /usr/lib/dkms/common.postinst ]; then
            echo "Error: /usr/lib/dkms/common.postinst is required" >&2
            exit 1
        fi

        autoinstall_all_kernels=yes
        export autoinstall_all_kernels
        /usr/lib/dkms/common.postinst "\$MODULE_NAME" "\$MODULE_VERSION" /usr/src "" "\${2-}"
        ;;
esac
EOF
}

write_prerm() {
    cat >"$1" <<EOF
#!/bin/sh
set -e

MODULE_NAME="${MODULE_NAME}"
MODULE_VERSION="${VERSION}"

case "\$1" in
    remove|upgrade|deconfigure)
        if dkms status -m "\$MODULE_NAME" -v "\$MODULE_VERSION" >/dev/null 2>&1; then
            dkms remove -m "\$MODULE_NAME" -v "\$MODULE_VERSION" --all
        fi
        ;;
esac
EOF
}

require_command dpkg-deb
require_command tar
require_command readlink
require_command dirname
require_command mktemp

VERSION=$("${SCRIPT_DIR}/dkms-version.sh")
TARBALL="${SCRIPT_DIR}/${PACKAGE_NAME}_${VERSION}.tar.gz"
PACKAGE_FILE="${SCRIPT_DIR}/${PACKAGE_NAME}_${VERSION}_${PACKAGE_ARCH}.deb"
WORK_DIR=$(mktemp -d "${SCRIPT_DIR}/.release-dkms-deb.XXXXXX")
trap 'rm -rf "$WORK_DIR"' EXIT HUP INT TERM

"${SCRIPT_DIR}/release-dkms.sh"

if [ ! -f "$TARBALL" ]; then
    echo "Error: Expected tarball not found: $TARBALL" >&2
    exit 1
fi

ROOTFS_DIR="${WORK_DIR}/rootfs"
CONTROL_DIR="${ROOTFS_DIR}/DEBIAN"
SOURCE_DIR="${ROOTFS_DIR}/usr/src/${MODULE_NAME}-${VERSION}"

mkdir -p "$CONTROL_DIR" "$SOURCE_DIR"
tar xzf "$TARBALL" -C "$SOURCE_DIR"

write_control_file "${CONTROL_DIR}/control"
write_postinst "${CONTROL_DIR}/postinst"
write_prerm "${CONTROL_DIR}/prerm"
chmod 0755 "${CONTROL_DIR}/postinst" "${CONTROL_DIR}/prerm"

rm -f -- "$PACKAGE_FILE"
dpkg-deb --root-owner-group --build "$ROOTFS_DIR" "$PACKAGE_FILE" >/dev/null
printf '%s\n' "$(basename -- "$PACKAGE_FILE")"
