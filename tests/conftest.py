import hashlib
import pytest
import subprocess
import tempfile
import time
import os
import signal
import shlex
import shutil
import json
from pathlib import Path
from datetime import datetime

# Guest commands run through a fresh SSH session whose PATH knows nothing
# about the environment pytest was started from. Re-export the host PATH
# (store paths stay valid inside the guest because the VM sees the host
# filesystem) so tools like dkms, nft or wg resolve to the same binaries on
# every distro, and keep the standard FHS directories behind it so guest-side
# distro binaries (e.g. the gcc-N compat symlinks in /usr/bin) stay
# reachable. MODULE_DIR pins kmod to the guest's /lib/modules tree even when
# the host's kmod was configured for another location (NixOS).
GUEST_PATH = os.environ.get("PATH", "") + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
GUEST_ENV_PREFIX = f"export PATH={shlex.quote(GUEST_PATH)} MODULE_DIR=/lib/modules; "


def pytest_addoption(parser):
    parser.addoption(
        "--kernel",
        action="append",
        default=[],
        help="Kernel version to test (e.g. host or v6.19.1). Can be specified multiple times.",
    )
    parser.addoption(
        "--all-kernels",
        action="store_true",
        default=False,
        help="Test against all prepared kernels in the kernels/ directory.",
    )


def pytest_generate_tests(metafunc):
    if "vm" in metafunc.fixturenames:
        kernels = metafunc.config.getoption("kernel")
        all_kernels_flag = metafunc.config.getoption("all_kernels")

        if all_kernels_flag:
            project_root = Path(__file__).parent.parent
            kernels_root = project_root / "kernels"
            if kernels_root.exists():
                # Find all subdirectories that have an .extracted file
                for d in sorted(kernels_root.iterdir()):
                    if d.is_dir() and (d / ".extracted").exists():
                        if d.name not in kernels:
                            kernels.append(d.name)

        if not kernels:
            metafunc.parametrize("vm", ["host"], indirect=True, scope="session")
        else:
            metafunc.parametrize("vm", kernels, indirect=True, scope="session")


class VM:
    def __init__(self, kernel_set_str, session_log_dir):
        self.kernel_set_str = kernel_set_str
        self.session_log_dir = Path(session_log_dir)
        self.proc = None
        self.dmesg_proc = None
        self.base_ssh_cmd = []
        self.temp_dir = None
        self.kernel_ver = None

    def run(self, cmd, check=True, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(shlex.quote(c) for c in cmd)
        else:
            cmd_str = cmd

        ssh_cmd = self.base_ssh_cmd + [f"bash -c {shlex.quote(GUEST_ENV_PREFIX + cmd_str)}"]
        res = subprocess.run(ssh_cmd, capture_output=True, text=True, **kwargs)
        if check and res.returncode != 0:
            print(f"SSH command failed: {ssh_cmd}")
            print(f"stdout: {res.stdout}")
            print(f"stderr: {res.stderr}")
            res.check_returncode()
        return res

    def _locate_nixos_kernel_build(self, kver):
        """Find (or fetch) the running kernel's build tree on a NixOS host.

        Never compiles a kernel: the dev output is either already on disk or
        substituted from a binary cache.
        """
        override = os.environ.get("PHANTUN_HOST_KDIR")
        if override:
            return Path(override)

        cand = Path(f"/run/current-system/kernel-modules/lib/modules/{kver}/build")
        if cand.exists():
            return cand.resolve()

        # Ask nix for the kernel derivation's dev output and substitute it.
        kernel_pkg = Path("/run/current-system/kernel").resolve().parent
        try:
            info = json.loads(
                subprocess.run(
                    ["nix", "path-info", "--json", str(kernel_pkg)],
                    capture_output=True,
                    text=True,
                    check=True,
                ).stdout
            )
            deriver = next(iter(info.values()))["deriver"]
            drv = json.loads(
                subprocess.run(
                    ["nix", "derivation", "show", deriver],
                    capture_output=True,
                    text=True,
                    check=True,
                ).stdout
            )
            drv_attrs = next(iter(drv.get("derivations", drv).values()))
            dev_path = drv_attrs["env"]["dev"]
            gcroot = Path(__file__).parent.parent / ".build" / "host-kernel-dev"
            gcroot.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["nix-store", "--realise", dev_path, "--add-root", str(gcroot)],
                capture_output=True,
                text=True,
                check=True,
            )
        except (subprocess.CalledProcessError, KeyError, StopIteration, json.JSONDecodeError) as exc:
            detail = getattr(exc, "stderr", "") or str(exc)
            pytest.exit(
                "Unable to obtain the host kernel's build tree for DKMS "
                f"(kernel {kver}): {detail.strip()}\n"
                "Set PHANTUN_HOST_KDIR=/path/to/kernel/build to override."
            )

        build = Path(dev_path) / "lib" / "modules" / kver / "build"
        if not build.exists():
            pytest.exit(f"Kernel dev output {dev_path} lacks lib/modules/{kver}/build")
        return build

    def _prepare_nixos_host_kernel(self):
        """Assemble a shadow root so virtme-ng can boot the NixOS host kernel.

        virtme-ng derives the module directory from the kernel image path
        (<root>/boot/vmlinuz-V -> <root>/lib/modules/V), so lay the running
        kernel out that way with symlinks. The guest sees this tree through
        virtme_link_mods; writes (dkms install, depmod) land in the guest's
        /tmp overlay because the shadow root lives under TMPDIR.
        """
        kver = self.kernel_ver
        kernel_img = Path("/run/current-system/kernel")
        mod_src = Path("/run/current-system/kernel-modules/lib/modules") / kver
        if not kernel_img.exists() or not mod_src.is_dir():
            pytest.exit(
                f"Host kernel {kver} not found under /lib/modules or "
                "/run/current-system; cannot run --kernel host here."
            )

        build = self._locate_nixos_kernel_build(kver)

        self.temp_dir = tempfile.mkdtemp(prefix="phantun-host-kernel-")
        shadow = Path(self.temp_dir)
        boot_dir = shadow / "boot"
        boot_dir.mkdir(parents=True)
        vmlinuz = boot_dir / f"vmlinuz-{kver}"
        vmlinuz.symlink_to(kernel_img.resolve())

        moddir = shadow / "lib" / "modules" / kver
        moddir.mkdir(parents=True)
        for entry in mod_src.iterdir():
            if entry.name == "build":
                continue
            (moddir / entry.name).symlink_to(entry)
        (moddir / "build").symlink_to(build)

        return str(vmlinuz)

    def _prepare_guest_environment(self):
        """One-time guest setup shared by all kernel flavors."""
        # DKMS refuses to run without its tree; distro packages normally
        # pre-create it.
        self.run("mkdir -p /var/lib/dkms /usr/src", check=False)

        # Kernel-initiated module autoloading (nft, tc netem, ...) execs
        # kernel.modprobe, whose default /sbin/modprobe may not exist in the
        # guest (NixOS). Install a shim that resolves modules from
        # /lib/modules regardless of how the host's kmod was configured.
        modprobe = shutil.which("modprobe")
        if modprobe:
            self.run(
                'test -x "$(cat /proc/sys/kernel/modprobe)" || { '
                "printf '#!/bin/sh\\nexport MODULE_DIR=/lib/modules\\nexec %s \"$@\"\\n' "
                f"{shlex.quote(modprobe)} > /run/phantun-modprobe && "
                "chmod +x /run/phantun-modprobe && "
                "echo /run/phantun-modprobe > /proc/sys/kernel/modprobe; }",
                check=False,
            )

        # The COW /etc exposes the host's modprobe.d; drop any phantun
        # options so module parameters only come from the tests.
        self.run(
            "grep -lsE '^[[:space:]]*(options|install|blacklist)[[:space:]]+phantun([[:space:]]|$)' "
            "/etc/modprobe.d/* 2>/dev/null | xargs -r rm -f",
            check=False,
        )

    def start(self):
        cmd = [
            "vng",
            "--ssh",
            "--user",
            "root",
            "--exec",
            "sleep 3600",
        ]

        self.ubuntu_kernel_dir = None

        if self.kernel_set_str == "host":
            self.kernel_ver = subprocess.run(["uname", "-r"], capture_output=True, text=True, check=True).stdout.strip()
            if os.path.exists(f"/lib/modules/{self.kernel_ver}"):
                # FHS host: default to the host kernel by using -r without argument
                cmd.extend(["-r"])
            else:
                # NixOS-style host: no /lib/modules. Build a shadow root that
                # lays the kernel image and module tree out the way virtme-ng
                # expects, including a build/ tree for DKMS.
                cmd.extend(["-r", self._prepare_nixos_host_kernel()])
        else:
            # Assume it is a pre-extracted ubuntu kernel
            self.kernel_ver = self.kernel_set_str
            project_root = Path(__file__).parent.parent
            kernels_dir = project_root / "kernels" / self.kernel_ver

            if not kernels_dir.exists() or not (kernels_dir / ".extracted").exists():
                pytest.exit(
                    f"Kernel {self.kernel_ver} not found or not extracted in {kernels_dir}. Please run ./prepare-kernels.py {self.kernel_ver} first."
                )

            self.ubuntu_kernel_dir = kernels_dir
            vmlinuz_paths = list(kernels_dir.glob("boot/vmlinuz-*"))
            if not vmlinuz_paths:
                raise Exception(f"No vmlinuz found in {kernels_dir}")

            vmlinuz = vmlinuz_paths[0]
            # Override kernel_ver with the actual full version string from vmlinuz
            self.kernel_ver = vmlinuz.name.replace("vmlinuz-", "")
            cmd.extend(["-r", str(vmlinuz)])
            # Module visibility needs no extra plumbing: virtme-ng finds
            # lib/modules/ next to the kernel image and symlinks it into the
            # guest, and DKMS writes land in the guest-side overlay of the
            # project directory.

        vng_log_path = self.session_log_dir / "vng.log"
        self.vng_log = open(vng_log_path, "w")
        # Keep virtme-ng and OpenSSH socket paths short even when TMPDIR points
        # at a long nested CI work directory.
        runtime_tmpdir = Path(os.environ.get("TMPDIR", "/tmp"))
        if len(str(runtime_tmpdir / "virtme-ng-sock")) > 80:
            runtime_tmpdir = Path("/tmp")

        runtime_env = os.environ.copy()
        runtime_env["TMPDIR"] = str(runtime_tmpdir)

        self.proc = subprocess.Popen(
            cmd,
            stdout=self.vng_log,
            stderr=subprocess.STDOUT,
            preexec_fn=os.setsid,
            env=runtime_env,
        )

        # Get SSH cmd
        res = subprocess.run(
            ["vng", "--ssh-client", "--dry-run"],
            capture_output=True,
            text=True,
            env=runtime_env,
        )
        if res.returncode != 0:
            raise Exception(f"Failed to get ssh client command: {res.stderr}")
        full_ssh_cmd = shlex.split(res.stdout.strip())
        if "--" in full_ssh_cmd:
            self.base_ssh_cmd = full_ssh_cmd[: full_ssh_cmd.index("--")]
        else:
            self.base_ssh_cmd = full_ssh_cmd
        try:
            l_index = self.base_ssh_cmd.index("-l")
            self.base_ssh_cmd[l_index + 1] = "root"
        except ValueError:
            self.base_ssh_cmd.extend(["-l", "root"])

        control_socket_hash = hashlib.sha256(f"{self.session_log_dir}:{self.kernel_ver}:{id(self)}".encode())
        control_socket_name = f"pht-ssh-{control_socket_hash.hexdigest()[:16]}"
        # Use the same socket-safe temp base for OpenSSH control sockets.
        control_socket_dir = runtime_tmpdir

        self.control_socket = control_socket_dir / control_socket_name
        self.base_ssh_cmd[1:1] = [
            "-o",
            "ControlMaster=auto",
            "-o",
            f"ControlPath={self.control_socket}",
            "-o",
            "ControlPersist=2m",
        ]

        # Wait for SSH
        success = False
        for _ in range(60):
            time.sleep(1)
            try:
                res = self.run(["uname", "-a"], check=False)
                if res.returncode == 0:
                    success = True
                    break
            except Exception:
                pass
            if self.proc.poll() is not None:
                self.vng_log.close()
                raise Exception(f"vng process died prematurely. Log: {vng_log_path.read_text()}")

        if not success:
            raise Exception("Timeout waiting for vng SSH to be available")

        if self.ubuntu_kernel_dir:
            self.run(["depmod", "-a", self.kernel_ver])

            gcc_target = "/usr/bin/gcc"
            for v in [16, 15, 14, 13]:
                if self.run(f"test -x /usr/bin/gcc-{v}", check=False).returncode == 0:
                    gcc_target = f"/usr/bin/gcc-{v}"
                    break
            else:
                # No distro compiler in the guest (NixOS host): use the
                # environment's gcc for the compatibility symlinks below.
                if self.run("test -x /usr/bin/gcc", check=False).returncode != 0:
                    res = self.run("command -v gcc", check=False)
                    if res.returncode == 0 and res.stdout.strip():
                        gcc_target = res.stdout.strip()

            # Symlink compilers that Ubuntu kernel Makefile might explicitly ask for
            for ver in [12, 13, 14, 15, 16]:
                self.run(f"test -e /usr/bin/gcc-{ver} || ln -sf {gcc_target} /usr/bin/gcc-{ver}", check=False)
                self.run(
                    f"test -e /usr/bin/x86_64-linux-gnu-gcc-{ver} || ln -sf {gcc_target} /usr/bin/x86_64-linux-gnu-gcc-{ver}",
                    check=False,
                )

        self._prepare_guest_environment()

        # Start dmesg collector
        self.dmesg_file_path = self.session_log_dir / "dmesg.log"
        self.dmesg_file = open(self.dmesg_file_path, "w")
        self.dmesg_proc = subprocess.Popen(
            self.base_ssh_cmd + ["dmesg", "-w"],
            stdout=self.dmesg_file,
            stderr=subprocess.STDOUT,
        )
        time.sleep(1)

    def stop(self):
        if self.dmesg_proc:
            self.dmesg_proc.terminate()
            self.dmesg_proc.wait()
            self.dmesg_file.close()

        if hasattr(self, "control_socket") and self.control_socket.exists():
            subprocess.run(self.base_ssh_cmd + ["-O", "exit"], check=False, capture_output=True)

        if hasattr(self, "vng_log") and not self.vng_log.closed:
            self.vng_log.close()
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.proc.wait()

        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)


@pytest.fixture(scope="session")
def session_log_dir():
    tmp_base = os.environ.get("TMPDIR", "/tmp")
    base_dir = Path(tmp_base) / "phantun-test-logs"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = base_dir / ts
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


class DmesgMonitor:
    def __init__(self, dmesg_file_path):
        self.dmesg_file_path = dmesg_file_path
        # Record starting offset
        if self.dmesg_file_path.exists():
            with open(self.dmesg_file_path, "r") as f:
                f.seek(0, 2)
                self.offset = f.tell()
        else:
            self.offset = 0
        self.pending_lines = []

    def get_new_lines(self):
        if not self.dmesg_file_path.exists():
            return []
        with open(self.dmesg_file_path, "r") as f:
            f.seek(self.offset)
            lines = f.read().splitlines()
            self.offset = f.tell()  # advance offset so we only read new lines each time
            return lines

    def clear(self):
        self.pending_lines = []

    def wait_for(self, substr, timeout=5):
        start_time = time.time()
        while time.time() - start_time < timeout:
            self.pending_lines.extend(self.get_new_lines())

            for i, line in enumerate(self.pending_lines):
                if substr in line:
                    del self.pending_lines[0:i]
                    return True

            time.sleep(0.5)
        return False


@pytest.fixture(scope="function")
def dmesg(vm):
    return DmesgMonitor(vm.dmesg_file_path)


@pytest.fixture(scope="session")
def project_info():
    test_dir = Path(__file__).parent
    proj_root = test_dir.parent
    dkms_conf = proj_root / "dkms.conf"

    version = "unknown"
    if dkms_conf.exists():
        for line in dkms_conf.read_text().splitlines():
            if line.startswith("PACKAGE_VERSION="):
                version = line.split("=")[1].strip('"').strip("'")
                break

    # Prepare tarball BEFORE VM starts because of COW filesystem.
    subprocess.run(["make", "dkms"], cwd=proj_root, check=True)
    tar_path = proj_root / f"phantun-dkms_{version}.tar.gz"

    return {"root": proj_root, "version": version, "tar_path": tar_path}


@pytest.fixture(scope="session")
def vm(request, session_log_dir):
    kernel_set_str = request.param
    vm_instance = VM(kernel_set_str, session_log_dir)
    try:
        vm_instance.start()
        yield vm_instance
    finally:
        vm_instance.stop()


class PhantunModule:
    def __init__(self, vm, project_info):
        self.vm = vm
        self.version = project_info["version"]
        self.root = project_info["root"]
        self.tar_path = project_info["tar_path"]
        self.dkms_name = f"phantun/{self.version}"
        self.mod_name = "phantun"

    def install(self):
        dkms_src = f"/usr/src/phantun-{self.version}"
        self.vm.run(f"mkdir -p {dkms_src} && tar xzf {self.tar_path} -C {dkms_src}")

        # Clean up existing entry if present (e.g. from host or failed run)
        self.vm.run(["dkms", "remove", self.dkms_name, "--all"], check=False)
        self.vm.run(["dkms", "add", self.dkms_name])
        try:
            self.vm.run(["dkms", "build", self.dkms_name])
        except subprocess.CalledProcessError:
            res_log = self.vm.run(
                f"cat /var/lib/dkms/{self.dkms_name}/build/make.log || true",
                check=False,
            )
            res_config_log = self.vm.run(
                f"cat /var/lib/dkms/{self.dkms_name}/build/config.log || true",
                check=False,
            )
            print("MAKE.LOG:\n", res_log.stdout)
            print("CONFIG.LOG:\n", res_config_log.stdout)
            raise
        self.vm.run(["dkms", "install", self.dkms_name])

    def uninstall(self):
        self.unload()
        self.vm.run(["dkms", "remove", self.dkms_name, "--all"], check=False)

    def load(self, **kwargs):
        self.unload()
        opts = [f"{k}={v}" for k, v in kwargs.items()]
        opts_str = " ".join(opts)

        if opts_str:
            self.vm.run(f"echo 'options {self.mod_name} {opts_str}' > /etc/modprobe.d/phantun.conf")
        else:
            self.vm.run(["rm", "-f", "/etc/modprobe.d/phantun.conf"])

        self.vm.run(["modprobe", "-v", self.mod_name])

    def unload(self):
        self.vm.run(["modprobe", "-r", self.mod_name], check=False)


@pytest.fixture(scope="session")
def phantun_module(vm, project_info):
    mod = PhantunModule(vm, project_info)
    try:
        mod.install()
        yield mod
    finally:
        mod.uninstall()
