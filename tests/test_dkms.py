import pytest

def test_kernel_version(vm):
    """Sanity check that we are running the expected kernel."""
    res = vm.run(['uname', '-r'])
    if vm.kernel_ver not in res.stdout:
        pytest.fail(f"Expected kernel {vm.kernel_ver} not found in {res.stdout}")

def test_module_load_success(phantun_module, dmesg, vm):
    """Test that the module loads successfully via DKMS installed modprobe."""
    phantun_module.load(managed_ports="1234")

    res = vm.run(['lsmod'])
    if 'phantun' not in res.stdout:
        pytest.fail("phantun module is not loaded in lsmod")

    if not dmesg.wait_for(r'registered IPv4 LOCAL_OUT and PRE_ROUTING hooks', timeout=5):
        pytest.fail("Module did not log successful netfilter hook registration")

def test_module_unload_success(phantun_module, dmesg, vm):
    """Test that the module unloads cleanly."""
    phantun_module.load(managed_ports="4321")

    res = vm.run(['lsmod'])
    if 'phantun' not in res.stdout:
        pytest.fail("phantun module should be loaded before unload test")

    phantun_module.unload()

    res = vm.run(['lsmod'])
    if 'phantun' in res.stdout:
        pytest.fail("phantun module still loaded after rmmod")

    if not dmesg.wait_for(r'unregistered netfilter hooks', timeout=5):
        pytest.fail("Module did not log successful netfilter hook unregistration")

def test_module_reload_new_params(phantun_module, dmesg):
    """Test that the module can be reloaded with different parameters seamlessly."""
    phantun_module.load(managed_ports="1111")
    if not dmesg.wait_for(r'registered IPv4 LOCAL_OUT and PRE_ROUTING hooks', timeout=5):
        pytest.fail("First load failed")

    # .load() automatically unloads before loading new options
    phantun_module.load(managed_ports="2222")

    if not dmesg.wait_for(r'registered IPv4 LOCAL_OUT and PRE_ROUTING hooks', timeout=5):
        pytest.fail("Second load (reload) failed")
