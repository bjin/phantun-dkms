#!/usr/bin/env python3
import os
import sys
import shutil
import subprocess
import urllib.request
import re
from pathlib import Path


def _iter_elf_host_tools(kernels_dir):
    for headers_dir in (kernels_dir / "usr" / "src").glob("linux-headers-*"):
        for sub in ("scripts", "tools", "arch"):
            root = headers_dir / sub
            if not root.is_dir():
                continue
            for path in root.rglob("*"):
                if path.is_symlink() or not path.is_file():
                    continue
                if not path.stat().st_mode & 0o111:
                    continue
                with open(path, "rb") as fh:
                    if fh.read(4) != b"\x7fELF":
                        continue
                yield path


def fixup_host_tools(kernels_dir):
    """Make the prebuilt kbuild host tools runnable on non-FHS hosts.

    Ubuntu's linux-headers packages ship dynamically linked binaries
    (fixdep, modpost, objtool, ...) that expect the FHS ELF interpreter
    /lib64/ld-linux-*.so. On hosts without a real loader there (e.g.
    NixOS, where that path is a stub), rewrite the interpreter and rpath.
    Gated on environment variables exported by the Nix devshell; a no-op
    everywhere else, so FHS hosts and CI are unaffected.
    """
    interp = os.environ.get("PHANTUN_PATCHELF_INTERP")
    rpath = os.environ.get("PHANTUN_PATCHELF_RPATH")
    if not interp or not rpath:
        return
    if shutil.which("patchelf") is None:
        print("Warning: patchelf not found; prebuilt kernel host tools were not fixed up")
        return

    patched = 0
    for path in _iter_elf_host_tools(kernels_dir):
        cur = subprocess.run(["patchelf", "--print-interpreter", str(path)], capture_output=True, text=True)
        if cur.returncode != 0:
            # Statically linked or no PT_INTERP; nothing to fix.
            continue
        if cur.stdout.strip() == interp:
            continue
        subprocess.run(
            ["patchelf", "--set-interpreter", interp, "--set-rpath", rpath, str(path)],
            check=True,
            capture_output=True,
        )
        patched += 1
    if patched:
        print(f"Patched {patched} prebuilt host tool(s) for this non-FHS host in {kernels_dir}")


def check_kernel_files(kernels_dir):
    # Check for vmlinuz
    vmlinuz = list(kernels_dir.glob("boot/vmlinuz-*"))
    if not vmlinuz:
        print(f"Missing vmlinuz in {kernels_dir}/boot")
        return False

    # Check for Makefile in headers
    kver = vmlinuz[0].name.replace("vmlinuz-", "")
    makefile = kernels_dir / "usr" / "src" / f"linux-headers-{kver}" / "Makefile"
    if not makefile.exists():
        print(f"Missing Makefile in {makefile.parent}")
        return False

    return True


def verify_kernel_dir(kernels_dir):
    extracted_flag = kernels_dir / ".extracted"
    if not extracted_flag.exists():
        return False
    if not check_kernel_files(kernels_dir):
        return False
    fixup_host_tools(kernels_dir)
    return True


def cleanup_kernel_dir(kernels_dir):
    if kernels_dir.exists():
        print(f"Cleaning up {kernels_dir} due to missing or corrupted files...")
        shutil.rmtree(kernels_dir)


def prepare_ubuntu_kernel(version):
    project_root = Path(__file__).parent
    kernels_dir = project_root / "kernels" / version

    if verify_kernel_dir(kernels_dir):
        print(f"Kernel {version} is already prepared and verified.")
        return kernels_dir

    cleanup_kernel_dir(kernels_dir)
    kernels_dir.mkdir(parents=True, exist_ok=True)

    base_url = f"https://kernel.ubuntu.com/mainline/{version}/amd64/"
    print(f"Fetching deb links from {base_url}...")
    try:
        with urllib.request.urlopen(base_url) as response:
            html = response.read().decode("utf-8")
    except Exception as e:
        print(f"Error: Failed to fetch {base_url}: {e}")
        sys.exit(1)

    deb_links = re.findall(r'href="([^"]+\.deb)"', html)
    debs_to_dl = [
        link
        for link in deb_links
        if any(x in link for x in ["linux-headers", "linux-image", "linux-modules"]) and "lowlatency" not in link
    ]

    if not debs_to_dl:
        print(f"Error: No relevant deb packages found for version {version}")
        sys.exit(1)

    (kernels_dir / "usr" / "lib").mkdir(parents=True, exist_ok=True)
    (kernels_dir / "lib").symlink_to("usr/lib")

    for deb in debs_to_dl:
        deb_url = base_url + deb
        deb_path = kernels_dir / deb
        print(f"Downloading {deb}...")
        urllib.request.urlretrieve(deb_url, deb_path)

        print(f"Extracting {deb}...")
        subprocess.run(
            f"dpkg-deb --fsys-tarfile {deb_path} | tar -x --keep-directory-symlink -C {kernels_dir}",
            shell=True,
            check=True,
        )
        deb_path.unlink()

    # Fix the build symlink and verify
    vmlinuz_paths = list(kernels_dir.glob("boot/vmlinuz-*"))
    if not vmlinuz_paths:
        print("Error: Extraction failed to produce vmlinuz")
        sys.exit(1)

    kver = vmlinuz_paths[0].name.replace("vmlinuz-", "")
    build_link = kernels_dir / "lib" / "modules" / kver / "build"
    headers_dir = kernels_dir / "usr" / "src" / f"linux-headers-{kver}"

    if build_link.exists() or build_link.is_symlink():
        build_link.unlink()
    if headers_dir.exists():
        build_link.symlink_to(headers_dir)
    else:
        print(f"Error: Headers directory {headers_dir} missing after extraction")
        sys.exit(1)

    if check_kernel_files(kernels_dir):
        fixup_host_tools(kernels_dir)
        kernels_dir.joinpath(".extracted").touch()
        print(f"Successfully prepared and verified kernel {version}")
    else:
        print(f"Error: Verification failed for {version} after extraction")
        sys.exit(1)

    return kernels_dir


def list_and_verify_kernels():
    project_root = Path(__file__).parent
    kernels_root = project_root / "kernels"

    if not kernels_root.exists():
        print("No kernels directory found. Nothing to verify.")
        return []

    prepared = []
    # Sort to ensure consistent output
    versions = sorted([d.name for d in kernels_root.iterdir() if d.is_dir()])

    for version in versions:
        kernels_dir = kernels_root / version
        if verify_kernel_dir(kernels_dir):
            prepared.append(version)
        else:
            # If directory exists but verification fails, clean it up
            # (verify_kernel_dir already prints why check_kernel_files failed if .extracted exists)
            cleanup_kernel_dir(kernels_dir)

    return prepared


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Process specific versions
        for ver in sys.argv[1:]:
            prepare_ubuntu_kernel(ver)
        sys.exit(0)

    # Final listing and verification of all cached kernels
    prepared_versions = list_and_verify_kernels()

    if prepared_versions:
        print("Prepared Ubuntu Kernel Versions:")
        for v in prepared_versions:
            print(f"- {v}")
    else:
        print("\nNo Ubuntu kernels are currently prepared.")
