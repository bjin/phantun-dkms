{
  lib,
  fetchFromGitHub,
  python3Packages,
  qemu_kvm,
  virtiofsd,
  file,
  kmod,
  busybox-static,
  openssh,
  zstd,
  xz,
}:

python3Packages.buildPythonApplication rec {
  pname = "virtme-ng";
  # Pinned past v1.41: main carries the NixOS guest support this flake
  # depends on (/run/current-system preservation across the /run tmpfs
  # mount and PATH defaults including /run/current-system/sw/bin).
  version = "1.41-unstable-2026-07-01";

  src = fetchFromGitHub {
    owner = "arighi";
    repo = "virtme-ng";
    rev = "bd434224876a071f9c0a4619c82c158ff9a07150";
    hash = "sha256-WX1Zp5XC6sEi5DxSnK8P4BOQqzxeLzO+04AP3OmNbmU=";
  };

  # Report the pinned version instead of shelling out to `git describe`.
  env.VNG_PACKAGE = "1";

  patches = [
    # Give guests booted from a /lib-less read-only root (NixOS hosts) a
    # writable overlay root, and make the auto-initramfs able to load
    # xz-compressed kernel modules.
    ./virtme-ng-nixos-guest-root.patch
  ];

  pyproject = true;
  build-system = with python3Packages; [
    setuptools
    argparse-manpage
  ];

  dependencies = with python3Packages; [
    argcomplete
    requests
  ];

  postPatch = ''
    # The guest scripts run inside the VM as PID 1 (or from it) where the
    # default PATH cannot resolve `env`/`bash` on NixOS; pin their shebangs
    # to store paths, which the guest sees through the host filesystem.
    patchShebangs virtme/guest bin vng virtme-run virtme-configkernel virtme-mkinitramfs

    # The guest sshd bootstrap hardcodes FHS paths that do not exist on
    # NixOS. Resolve sshd from PATH (virtme-init prepends
    # /run/current-system/sw/bin) and fall back to the sshd pinned here so
    # `vng --ssh` works even when the host profile lacks OpenSSH.
    substituteInPlace virtme/guest/virtme-sshd-script \
      --replace-fail 'if [[ ! -f /usr/sbin/sshd ]]; then' \
        'SSHD_BIN="$(command -v sshd || echo ${openssh}/bin/sshd)"
    if [[ ! -x "$SSHD_BIN" ]]; then' \
      --replace-fail '/usr/sbin/sshd -i' '"$SSHD_BIN" -i' \
      --replace-fail '/usr/sbin/sshd "''${ARGS[@]}"' '"$SSHD_BIN" "''${ARGS[@]}"' \
      --replace-fail 'if ! modprobe vsock &> /dev/null; then' \
        '# The booted kernel may not match the host userspace (prepared
    # foreign kernels), in which case host modprobe configuration points at
    # the wrong module tree. Load the vsock stack straight from the module
    # tree virtme selected; kmod insmod decompresses .ko.{xz,zst}.
    for _name in vsock vmw_vsock_virtio_transport_common vmw_vsock_virtio_transport; do
        for _mod in "''${virtme_link_mods:-/lib/modules/$(uname -r)}"/kernel/net/vmw_vsock/"$_name".ko*; do
            [[ -e "$_mod" ]] && insmod "$_mod" 2> /dev/null
        done
    done
    modprobe vmw_vsock_virtio_transport &> /dev/null
    if ! modprobe vsock &> /dev/null && [[ ! -e /dev/vsock ]]; then' \
      --replace-fail 'rm -f /var/run/nologin' \
        'rm -f /var/run/nologin

    # Hosts that never enabled OpenSSH lack the privilege separation user;
    # /etc is a writable overlay in the guest, so create what sshd needs.
    if ! grep -q "^sshd:" /etc/passwd 2> /dev/null; then
        echo "sshd:x:989:989:SSH privilege separation:/var/empty:/bin/false" >> /etc/passwd
    fi
    if ! grep -q "^sshd:" /etc/group 2> /dev/null; then
        echo "sshd:x:989:" >> /etc/group
    fi
    mkdir -p /var/empty' \
      --replace-fail 'UsePAM yes' \
        "\$([ -f /etc/pam.d/sshd ] && echo 'UsePAM yes' || echo 'UsePAM no')"

    # virtme-init generates a guest /etc/shadow with every account locked
    # ("!"). Ubuntu-style hosts never notice because UsePAM yes skips
    # sshd's locked-account check, but PAM-less guests (UsePAM no above)
    # reject pubkey logins for locked users. "*" equally prevents password
    # authentication without marking the account locked.
    substituteInPlace virtme/guest/virtme-init \
      --replace-fail "value='!'" "value='*'"

    # Device-driven module autoloading normally comes from udevd, which on
    # NixOS lives outside PATH; without it the vsock virtio transport never
    # loads and `vng --ssh` cannot reach the guest.
    substituteInPlace virtme/guest/virtme-init \
      --replace-fail 'if [[ -x /usr/lib/systemd/systemd-udevd ]]; then' \
        'if [[ -x /run/current-system/systemd/lib/systemd/systemd-udevd ]]; then
        udevd_ref=/run/current-system/systemd/lib/systemd/systemd-udevd
    elif [[ -x /usr/lib/systemd/systemd-udevd ]]; then'

    # Overlay mounts rely on kernel module autoloading, but the kernel's
    # default /sbin/modprobe does not exist on NixOS. Load overlayfs
    # explicitly from the module tree virtme selected before the first
    # overlay mount; kmod's insmod transparently decompresses .ko.{xz,zst}.
    substituteInPlace virtme/guest/virtme-init \
      --replace-fail 'mount_virtme_overlays() {' \
        'mount_virtme_overlays() {
    if ! grep -qw overlay /proc/filesystems; then
        local mod
        for mod in "''${virtme_link_mods:-/lib/modules/$(uname -r)}"/kernel/fs/overlayfs/overlay.ko*; do
            [[ -e "$mod" ]] && insmod "$mod" 2> /dev/null && break
        done
    fi'
  '';

  # Host-side helpers virtme-ng shells out to:
  # - qemu-system-* to boot the guest
  # - file(1) to detect the kernel version from an image
  # - depmod when a prepared module tree lacks modules.dep
  # - a *static* busybox for the auto-generated initramfs (virtio-fs/9p are
  #   modules in most distro kernels, so an initramfs is always needed)
  # - virtiofsd for the virtio-fs rootfs export (falls back to 9p without it)
  makeWrapperArgs = [
    "--prefix PATH : ${
      lib.makeBinPath [
        qemu_kvm
        virtiofsd
        file
        kmod
        busybox-static
        zstd
        xz
      ]
    }"
  ];

  # No tests that can run in the sandbox (they want /dev/kvm).
  doCheck = false;

  meta = {
    description = "Quickly run kernels inside a virtualized snapshot of your live system";
    homepage = "https://github.com/arighi/virtme-ng";
    license = lib.licenses.gpl2Only;
    mainProgram = "vng";
  };
}
