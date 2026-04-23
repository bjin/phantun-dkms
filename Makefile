KVER ?= $(shell uname -r)
KDIR ?= $(firstword $(wildcard \
	/lib/modules/$(KVER)/build \
	/run/booted-system/kernel-modules/lib/modules/$(KVER)/build \
	/run/current-system/kernel-modules/lib/modules/$(KVER)/build))
PWD := $(CURDIR)

PACKAGE_NAME := phantun-dkms
MODULE_NAME := phantun
DEB_PACKAGE_ARCH := all
RPM_PACKAGE_ARCH := noarch
RPM_RELEASE := 1
PACKAGE_VERSION := $(subst ",,$(patsubst PACKAGE_VERSION=%,%,$(filter PACKAGE_VERSION=%,$(file < dkms.conf))))
DKMS_TARBALL := $(PACKAGE_NAME)_$(PACKAGE_VERSION).tar.gz
DKMS_DEB := $(PACKAGE_NAME)_$(PACKAGE_VERSION)_$(DEB_PACKAGE_ARCH).deb
DKMS_RPM := $(PACKAGE_NAME)-$(PACKAGE_VERSION)-$(RPM_RELEASE).$(RPM_PACKAGE_ARCH).rpm

DKMS_TARBALL_INPUTS := \
	$(wildcard src/*.c) \
	$(wildcard src/*.h) \
	configure \
	config.h.in \
	dkms.conf \
	Kbuild \
	Makefile \
	LICENSE

KDIR_STAMP_DIR := .build
KDIR_STAMP := $(KDIR_STAMP_DIR)/config$(subst /,_,$(KDIR)).stamp

.PHONY: all modules modules_install clean compile_commands dkms dkms-deb dkms-rpm

all: modules

configure config.h.in &: dkms.conf $(wildcard configure.ac)
	@set -eu; \
	need_autogen=no; \
	if [ ! -f configure ] || [ ! -f config.h.in ]; then \
		need_autogen=yes; \
	elif [ -f configure.ac ] && { [ configure.ac -nt configure ] || [ configure.ac -nt config.h.in ] || [ dkms.conf -nt configure ] || [ dkms.conf -nt config.h.in ]; }; then \
		need_autogen=yes; \
	fi; \
	if [ "$$need_autogen" = yes ]; then \
		if [ ! -f configure.ac ]; then \
			echo "Error: configure/config.h.in are missing or stale, but configure.ac is unavailable" >&2; \
			exit 1; \
		fi; \
		./autogen.sh; \
	fi

$(KDIR_STAMP): configure config.h.in
	@if [ -z "$(strip $(KDIR))" ]; then \
		echo "Unable to locate a kernel build tree; set KDIR=/path/to/kernel/build" >&2; \
		exit 1; \
	fi
	@mkdir -p '$(KDIR_STAMP_DIR)'
	./configure --with-kernel='$(KDIR)'
	@rm -f '$(KDIR_STAMP_DIR)'/config.*.stamp
	@printf '%s\n' '$(KDIR)' >'$@'

modules: $(KDIR_STAMP)
	$(MAKE) -C $(KDIR) M=$(PWD) modules

compile_commands: compile_commands.json

compile_commands.json: $(KDIR_STAMP)
	$(MAKE) -C $(KDIR) M=$(PWD) compile_commands.json

modules_install: modules
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

dkms: $(DKMS_TARBALL)
	@printf '%s\n' '$(DKMS_TARBALL)'

$(DKMS_TARBALL): $(DKMS_TARBALL_INPUTS)
	@rm -f -- '$@'
	@tar czf '$@' --owner=0 --group=0 $(DKMS_TARBALL_INPUTS)

dkms-deb: $(DKMS_DEB)
	@printf '%s\n' '$(DKMS_DEB)'

$(DKMS_DEB): $(DKMS_TARBALL)
	@set -eu; \
	work_dir=$$(mktemp -d '$(CURDIR)/.release-dkms-deb.XXXXXX'); \
	trap 'rm -rf "$$work_dir"' EXIT HUP INT TERM; \
	rootfs_dir="$$work_dir/rootfs"; \
	control_dir="$$rootfs_dir/DEBIAN"; \
	source_dir="$$rootfs_dir/usr/src/$(MODULE_NAME)-$(PACKAGE_VERSION)"; \
	mkdir -p "$$control_dir" "$$source_dir"; \
	tar xzf '$(DKMS_TARBALL)' -C "$$source_dir"; \
	printf '%s\n' \
		'Package: $(PACKAGE_NAME)' \
		'Version: $(PACKAGE_VERSION)' \
		'Section: kernel' \
		'Priority: optional' \
		'Architecture: $(DEB_PACKAGE_ARCH)' \
		'Maintainer: Bin Jin <bjin@protonmail.com>' \
		'Depends: dkms' \
		'Recommends: linux-headers-generic | linux-headers-virtual | linux-headers-amd64 | linux-headers' \
		'Homepage: https://github.com/bjin/phantun-dkms' \
		'Description: Kernel module re-implementation of phantun, transform UDP streams into fake-TCP streams' \
		>"$$control_dir/control"; \
	printf '%s\n' \
		'#!/bin/sh' \
		'set -e' \
		'' \
		'MODULE_NAME="$(MODULE_NAME)"' \
		'MODULE_VERSION="$(PACKAGE_VERSION)"' \
		'' \
		'case "$$1" in' \
		'    configure)' \
		'        if [ ! -x /usr/lib/dkms/common.postinst ]; then' \
		'            echo "Error: /usr/lib/dkms/common.postinst is required" >&2' \
		'            exit 1' \
		'        fi' \
		'' \
		'        autoinstall_all_kernels=yes' \
		'        export autoinstall_all_kernels' \
		'        /usr/lib/dkms/common.postinst "$$MODULE_NAME" "$$MODULE_VERSION" /usr/src "" "$${2-}"' \
		'        ;;' \
		'esac' \
		>"$$control_dir/postinst"; \
	printf '%s\n' \
		'#!/bin/sh' \
		'set -e' \
		'' \
		'MODULE_NAME="$(MODULE_NAME)"' \
		'MODULE_VERSION="$(PACKAGE_VERSION)"' \
		'' \
		'case "$$1" in' \
		'    remove|upgrade|deconfigure)' \
		'        if dkms status -m "$$MODULE_NAME" -v "$$MODULE_VERSION" >/dev/null 2>&1; then' \
		'            dkms remove -m "$$MODULE_NAME" -v "$$MODULE_VERSION" --all' \
		'        fi' \
		'        ;;' \
		'esac' \
		>"$$control_dir/prerm"; \
	chmod 0755 "$$control_dir/postinst" "$$control_dir/prerm"; \
	rm -f -- '$(DKMS_DEB)'; \
	dpkg-deb --root-owner-group --build "$$rootfs_dir" '$(DKMS_DEB)' >/dev/null

dkms-rpm: $(DKMS_RPM)
	@printf '%s\n' '$(DKMS_RPM)'

$(DKMS_RPM): $(DKMS_TARBALL)
	@set -eu; \
	if ! command -v rpmbuild >/dev/null 2>&1; then \
		echo "Error: rpmbuild is required; on Arch Linux install the rpm-tools package" >&2; \
		exit 1; \
	fi; \
	work_dir=$$(mktemp -d '$(CURDIR)/.release-dkms-rpm.XXXXXX'); \
	trap 'rm -rf "$$work_dir"' EXIT HUP INT TERM; \
	topdir="$$work_dir/rpmbuild"; \
	tmp_dir="$$work_dir/tmp"; \
	rpmdb_dir="$$work_dir/rpmdb"; \
	spec_dir="$$topdir/SPECS"; \
	source_dir="$$topdir/SOURCES"; \
	spec_path="$$spec_dir/$(PACKAGE_NAME).spec"; \
	rpm_path="$$topdir/RPMS/$(RPM_PACKAGE_ARCH)/$(DKMS_RPM)"; \
	mkdir -p "$$tmp_dir" "$$rpmdb_dir" "$$spec_dir" "$$source_dir" "$$topdir/BUILD" "$$topdir/RPMS" "$$topdir/SRPMS"; \
	rpmdb --initdb --dbpath "$$rpmdb_dir" >/dev/null; \
	cp '$(DKMS_TARBALL)' "$$source_dir/"; \
	printf '%s\n' \
		'%global debug_package %{nil}' \
		'Name: $(PACKAGE_NAME)' \
		'Version: $(PACKAGE_VERSION)' \
		'Release: $(RPM_RELEASE)%{?dist}' \
		'Summary: Kernel module re-implementation of phantun, transform UDP streams into fake-TCP streams' \
		'License: GPL-2.0-or-later' \
		'URL: https://github.com/bjin/phantun-dkms' \
		'Source0: $(DKMS_TARBALL)' \
		'BuildArch: $(RPM_PACKAGE_ARCH)' \
		'Requires: dkms' \
		'Recommends: kernel-devel' \
		'' \
		'%description' \
		'Kernel module re-implementation of phantun, transform UDP streams into fake-TCP streams.' \
		'' \
		'%install' \
		'rm -rf "%{buildroot}"' \
		'install -d "%{buildroot}/usr/src/$(MODULE_NAME)-%{version}"' \
		'tar xzf "%{SOURCE0}" -C "%{buildroot}/usr/src/$(MODULE_NAME)-%{version}"' \
		'' \
		'%post' \
		'if command -v dkms >/dev/null 2>&1; then' \
		'    if ! dkms add -m "$(MODULE_NAME)" -v "%{version}" >/dev/null 2>&1; then' \
		'        echo "Warning: dkms add for $(MODULE_NAME) %{version} failed; the source tree was still installed to /usr/src." >&2' \
		'    fi' \
		'    if ! dkms autoinstall -m "$(MODULE_NAME)" -v "%{version}"; then' \
		'        echo "Warning: dkms autoinstall for $(MODULE_NAME) %{version} failed; install matching kernel headers and rerun dkms autoinstall manually." >&2' \
		'    fi' \
		'else' \
		'    echo "Warning: dkms is unavailable; install dkms and run dkms add/autoinstall manually." >&2' \
		'fi' \
		'' \
		'%preun' \
		'if command -v dkms >/dev/null 2>&1 && dkms status -m "$(MODULE_NAME)" -v "%{version}" >/dev/null 2>&1; then' \
		'    dkms remove -m "$(MODULE_NAME)" -v "%{version}" --all || :' \
		'fi' \
		'' \
		'%files' \
		'/usr/src/$(MODULE_NAME)-%{version}' \
		>"$$spec_path"; \
	rm -f -- '$(DKMS_RPM)'; \
	rpmbuild -bb --define "_topdir $$topdir" --define "_tmppath $$tmp_dir" --define "_dbpath $$rpmdb_dir" "$$spec_path" >/dev/null; \
	cp "$$rpm_path" '$(DKMS_RPM)'

clean:
	@if [ -n "$(strip $(KDIR))" ]; then \
		$(MAKE) -C $(KDIR) M=$(PWD) clean; \
	fi
	@rm -rf '$(KDIR_STAMP_DIR)'
