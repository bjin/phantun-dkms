import pytest
import subprocess
import time
import os
import signal
import shlex
import shutil
import re
from pathlib import Path
from datetime import datetime


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

        ssh_cmd = self.base_ssh_cmd + [f"bash -c {shlex.quote(cmd_str)}"]
        res = subprocess.run(ssh_cmd, capture_output=True, text=True, **kwargs)
        if check and res.returncode != 0:
            print(f"SSH command failed: {ssh_cmd}")
            print(f"stdout: {res.stdout}")
            print(f"stderr: {res.stderr}")
            res.check_returncode()
        return res

    def start(self):
        cmd = [
            "vng",
            "--empty-passwords",
            "--ssh",
            "--user",
            "root",
            "--exec",
            "sleep 3600",
        ]

        self.ubuntu_kernel_dir = None

        if self.kernel_set_str == "host":
            self.kernel_ver = subprocess.run(["uname", "-r"], capture_output=True, text=True, check=True).stdout.strip()
            # Default to host kernel by using -r without argument
            cmd.extend(["-r"])
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

            # Map host kernel modules directory to guest with a COW overlay so DKMS can install into updates/ without modifying host cache
            host_mod_dir = str(self.ubuntu_kernel_dir / "lib" / "modules" / self.kernel_ver)
            cmd.append(f"--overlay-rwdir=/lib/modules/{self.kernel_ver}={host_mod_dir}")

        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )

        # Get SSH cmd
        res = subprocess.run(["vng", "--ssh-client", "--dry-run"], capture_output=True, text=True)
        if res.returncode != 0:
            raise Exception(f"Failed to get ssh client command: {res.stderr}")
        self.base_ssh_cmd = shlex.split(res.stdout.strip())
        try:
            l_index = self.base_ssh_cmd.index("-l")
            self.base_ssh_cmd[l_index + 1] = "root"
        except ValueError:
            self.base_ssh_cmd.extend(["-l", "root"])

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
                raise Exception("vng process died prematurely.")

        if not success:
            raise Exception("Timeout waiting for vng SSH to be available")

        if self.ubuntu_kernel_dir:
            self.run(["depmod", "-a", self.kernel_ver])

            # Symlink compilers that Ubuntu kernel Makefile might explicitly ask for
            for ver in [12, 13, 14, 15, 16]:
                self.run(["ln", "-sf", "/usr/bin/gcc", f"/usr/bin/gcc-{ver}"], check=False)
                self.run(
                    [
                        "ln",
                        "-sf",
                        "/usr/bin/gcc",
                        f"/usr/bin/x86_64-linux-gnu-gcc-{ver}",
                    ],
                    check=False,
                )

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

    def get_new_lines(self):
        if not self.dmesg_file_path.exists():
            return []
        with open(self.dmesg_file_path, "r") as f:
            f.seek(self.offset)
            lines = f.read().splitlines()
            self.offset = f.tell()  # advance offset so we only read new lines each time
            return lines

    def wait_for(self, pattern, timeout=5):
        start_time = time.time()
        while time.time() - start_time < timeout:
            lines = self.get_new_lines()
            for line in lines:
                if re.search(pattern, line):
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
    tar_path = proj_root / ".dkms_copy.tar"
    tar_path.unlink(missing_ok=True)
    dkms_files = list(
        filter(
            None,
            subprocess.check_output(
                ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                cwd=proj_root,
                text=True,
            ).split("\0"),
        )
    )
    extra_files = ["configure", "config.h.in"]
    for file in extra_files:
        if not (proj_root / file).exists():
            pytest.exit("Please run ./autogen.sh first before running tests")
    dkms_files.extend(extra_files)

    subprocess.run(
        ["tar", "--null", "-c", "-T", "-", "-f", str(tar_path)],
        cwd=proj_root,
        input="\0".join(dkms_files),
        text=True,
        check=True,
    )

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
        self.vm.run(f"mkdir -p {dkms_src} && tar xf {self.tar_path} -C {dkms_src}")

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
            print("MAKE.LOG:\n", res_log.stdout)
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

        self.vm.run(["modprobe", self.mod_name])

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
