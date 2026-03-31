import pytest
import subprocess
import time
import os
import signal

class VirtmeNGContext:
    def __init__(self):
        self.proc = None
        self.dmesg_proc = None

    def start(self):
        kernel_ver = subprocess.run(['uname', '-r'], capture_output=True, text=True).stdout.strip()
        cmd = [
            'vng', '-r', f'/usr/lib/modules/{kernel_ver}/vmlinuz',
            '--empty-passwords', '--ssh', '--user', 'root',
            '--exec', 'sleep 3600' # keep it alive
        ]

        self.log_file = open("vng.log", "w")
        self.proc = subprocess.Popen(
            cmd,
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
            preexec_fn=os.setsid
        )
        import shlex
        # Get raw ssh command from vng
        res = subprocess.run(['vng', '--ssh-client', '--dry-run'], capture_output=True, text=True)
        if res.returncode != 0:
            raise Exception(f"Failed to get ssh client command: {res.stderr}")
        self.base_ssh_cmd = shlex.split(res.stdout.strip())
        # Ensure we connect as root
        try:
            l_index = self.base_ssh_cmd.index('-l')
            self.base_ssh_cmd[l_index + 1] = 'root'
        except ValueError:
            self.base_ssh_cmd.extend(['-l', 'root'])

        # Also add options to disable host key checking in case vng didn't include them
        if '-o' not in self.base_ssh_cmd:
            self.base_ssh_cmd[1:1] = ['-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null']
        # Wait for SSH
        success = False
        for i in range(15):
            time.sleep(2)
            try:
                res = self.ssh_run(['uname', '-a'])
                if res.returncode == 0:
                    success = True
                    break
            except Exception:
                pass

            if self.proc.poll() is not None:
                raise Exception("vng process died prematurely.")

        if not success:
            raise Exception("Timeout waiting for vng SSH to be available")
        # Start dmesg collector
        self.dmesg_file = open("dmesg.log", "w")
        self.dmesg_proc = subprocess.Popen(
            self.base_ssh_cmd + ['dmesg', '-w'],
            stdout=self.dmesg_file,
            stderr=subprocess.STDOUT
        )

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
        if hasattr(self, 'log_file'):
            self.log_file.close()

    def ssh_run(self, cmd, check=False):
        if isinstance(cmd, list):
            import shlex
            cmd = ' '.join(shlex.quote(c) for c in cmd)
        ssh_cmd = self.base_ssh_cmd + [cmd]
        res = subprocess.run(ssh_cmd, capture_output=True, text=True)
        if check and res.returncode != 0:
            print(f"SSH command failed: {ssh_cmd}")
            print(f"stdout: {res.stdout}")
            print(f"stderr: {res.stderr}")
            res.check_returncode()
        return res

@pytest.fixture(scope="session")
def vng_vm():
    ctx = VirtmeNGContext()
    ctx.start()
    yield ctx
    ctx.stop()
