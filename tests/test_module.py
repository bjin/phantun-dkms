import subprocess

def test_kernel_version(vng_vm):
    res = vng_vm.ssh_run(['uname', '-r'], check=True)
    host_kernel_ver = subprocess.run(['uname', '-r'], capture_output=True, text=True).stdout.strip()
    assert host_kernel_ver in res.stdout

def test_module_compile_and_load(vng_vm):
    src_dir = '/home/bjin/src/phantun-kmod'
    clean_cmd = f"cd {src_dir} && make clean"
    vng_vm.ssh_run(['bash', '-c', clean_cmd], check=True)

    make_cmd = f"cd {src_dir} && make"
    vng_vm.ssh_run(['bash', '-c', make_cmd], check=True)

    insmod_cmd = f"cd {src_dir} && insmod phantun.ko managed_ports=1234 handshake_request=hello handshake_response=world"
    vng_vm.ssh_run(['bash', '-c', insmod_cmd], check=True)

    res = vng_vm.ssh_run(['lsmod'], check=True)
    assert 'phantun' in res.stdout

    res = vng_vm.ssh_run(['dmesg'], check=True)
    assert 'registered IPv4 LOCAL_OUT and PRE_ROUTING hooks' in res.stdout

    vng_vm.ssh_run(['rmmod', 'phantun'], check=True)

    res = vng_vm.ssh_run(['dmesg'], check=True)
    assert 'unregistered netfilter hooks' in res.stdout

def test_module_dkms(vng_vm):
    src_dir = '/home/bjin/src/phantun-kmod'
    dkms_src = '/usr/src/phantun-0.1.0'
    vng_vm.ssh_run(['bash', '-c', f'cp -r {src_dir} {dkms_src}'], check=True)

    vng_vm.ssh_run(['dkms', 'add', 'phantun/0.1.0'], check=True)
    vng_vm.ssh_run(['dkms', 'build', 'phantun/0.1.0'], check=True)
    vng_vm.ssh_run(['dkms', 'install', 'phantun/0.1.0'], check=True)

    modprobe_conf = "options phantun managed_ports=1234 handshake_request=hello handshake_response=world"
    vng_vm.ssh_run(['bash', '-c', f'echo "{modprobe_conf}" > /etc/modprobe.d/phantun.conf'], check=True)
    vng_vm.ssh_run(['modprobe', 'phantun'], check=True)

    res = vng_vm.ssh_run(['lsmod'], check=True)
    assert 'phantun' in res.stdout

    res = vng_vm.ssh_run(['dmesg'], check=True)
    assert 'registered IPv4 LOCAL_OUT and PRE_ROUTING hooks' in res.stdout

    vng_vm.ssh_run(['modprobe', '-r', 'phantun'], check=True)

    res = vng_vm.ssh_run(['dmesg'], check=True)
    assert 'unregistered netfilter hooks' in res.stdout

    vng_vm.ssh_run(['dkms', 'remove', 'phantun/0.1.0', '--all'], check=True)
