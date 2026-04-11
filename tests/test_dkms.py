import re
import pytest


def assert_modprobe_rejected(result, context):
    if result.returncode == 0:
        pytest.fail(f"modprobe unexpectedly accepted {context}")

    # These tests run through virtme-ng's interactive guest shell; depending on
    # how that shell is attached, modprobe diagnostics may surface on either stream.
    output = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip())
    if "Invalid argument" not in output:
        pytest.fail(f"unexpected modprobe output for {context}: stdout={result.stdout!r}, stderr={result.stderr!r}")


def test_kernel_version(vm):
    """Sanity check that we are running the expected kernel."""
    res = vm.run(["uname", "-r"])
    if vm.kernel_ver not in res.stdout:
        pytest.fail(f"Expected kernel {vm.kernel_ver} not found in {res.stdout}")


def test_module_load_success(phantun_module, dmesg, vm):
    """Test that the module loads successfully via DKMS installed modprobe."""
    phantun_module.load(managed_local_ports="1234")

    res = vm.run(["lsmod"])
    if "phantun" not in res.stdout:
        pytest.fail("phantun module is not loaded in lsmod")
    if not dmesg.wait_for(rf"phantun {re.escape(phantun_module.version)} loaded", timeout=5):
        pytest.fail("Module did not log successful module initialization")
    if not dmesg.wait_for(r"registered IPv4 LOCAL_OUT/PRE_ROUTING hooks", timeout=5):
        pytest.fail("Module did not log successful netfilter hook registration")


def test_module_unload_success(phantun_module, dmesg, vm):
    """Test that the module unloads cleanly."""
    phantun_module.load(managed_local_ports="4321")

    res = vm.run(["lsmod"])
    if "phantun" not in res.stdout:
        pytest.fail("phantun module should be loaded before unload test")

    phantun_module.unload()

    res = vm.run(["lsmod"])
    if "phantun" in res.stdout:
        pytest.fail("phantun module still loaded after rmmod")

    if not dmesg.wait_for(r"unregistered netfilter hooks", timeout=5):
        pytest.fail("Module did not log successful netfilter hook unregistration")
    if not dmesg.wait_for(r"phantun unloaded", timeout=5):
        pytest.fail("Module did not log successful module unload")


def test_module_reload_new_params(phantun_module, dmesg):
    """Test that the module can be reloaded with different parameters seamlessly."""
    phantun_module.load(managed_local_ports="1111")
    if not dmesg.wait_for(r"registered IPv4 LOCAL_OUT/PRE_ROUTING hooks", timeout=5):
        pytest.fail("First load failed")

    # .load() automatically unloads before loading new options
    phantun_module.load(managed_local_ports="2222")

    if not dmesg.wait_for(r"registered IPv4 LOCAL_OUT/PRE_ROUTING hooks", timeout=5):
        pytest.fail("Second load (reload) failed")


def test_module_rejects_too_large_reopen_guard(phantun_module, vm):
    phantun_module.unload()
    vm.run(
        "echo 'options phantun managed_local_ports=1234 reopen_guard_bytes=2147483648' "
        "> /etc/modprobe.d/phantun.conf"
    )
    try:
        res = vm.run(["modprobe", "phantun"], check=False)
        assert_modprobe_rejected(res, "oversized reopen_guard_bytes")

        lsmod = vm.run(["lsmod"])
        if "phantun" in lsmod.stdout:
            pytest.fail("phantun module should not remain loaded after invalid reopen_guard_bytes")
    finally:
        vm.run(["rm", "-f", "/etc/modprobe.d/phantun.conf"])


def test_module_rejects_missing_selectors(phantun_module, vm):
    phantun_module.unload()
    vm.run(["rm", "-f", "/etc/modprobe.d/phantun.conf"])
    try:
        res = vm.run(["modprobe", "phantun"], check=False)
        assert_modprobe_rejected(res, "missing selectors")
    finally:
        vm.run(["rm", "-f", "/etc/modprobe.d/phantun.conf"])


def test_module_rejects_malformed_managed_remote_peer(phantun_module, vm):
    phantun_module.unload()
    vm.run("echo 'options phantun managed_remote_peers=not-a-peer' > /etc/modprobe.d/phantun.conf")
    try:
        res = vm.run(["modprobe", "phantun"], check=False)
        assert_modprobe_rejected(res, "malformed managed_remote_peers entry")
    finally:
        vm.run(["rm", "-f", "/etc/modprobe.d/phantun.conf"])
