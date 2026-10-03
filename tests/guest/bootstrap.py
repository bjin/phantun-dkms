import os
import stat
from pathlib import Path


def repair_sshd_chroot():
    # virtme-ng creates Debian/Ubuntu's /run/sshd as guest root, but does not
    # prepare Arch's pre-auth chroot, /usr/share/empty.sshd.
    # Inherited metadata can fail OpenSSH's owner/mode checks even with
    # StrictModes disabled. Run via virtme-ng --exec, not SSH, and change
    # only the guest's COW filesystem.
    chroot = Path("/usr/share/empty.sshd")
    if not chroot.is_dir():
        return

    info = chroot.stat()
    if info.st_uid != 0 or info.st_gid != 0:
        os.chown(chroot, 0, 0)
    if info.st_mode & 0o022:
        chroot.chmod(stat.S_IMODE(info.st_mode) & ~0o022)


if __name__ == "__main__":
    repair_sshd_chroot()
