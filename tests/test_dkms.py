import uuid

import pytest

from helpers import (
    assert_completed,
    kernel_has_base64_support,
    parse_guest_json,
    run_guest_scenario,
    spawn_guest_scenario,
    wait_for_guest_ready_file,
)


def assert_modprobe_rejected(result, context):
    if result.returncode == 0:
        pytest.fail(f"modprobe unexpectedly accepted {context}")

    # These tests run through virtme-ng's interactive guest shell; depending on
    # how that shell is attached, modprobe diagnostics may surface on either stream.
    output = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip())
    if "Invalid argument" not in output:
        pytest.fail(f"unexpected modprobe output for {context}: stdout={result.stdout!r}, stderr={result.stderr!r}")


def run_tcp_bind_probe(vm, bind_addr, bind_port):
    result = run_guest_scenario(
        vm,
        "tcp_bind_listen",
        {
            "bind_addr": bind_addr,
            "bind_port": bind_port,
        },
    )
    assert_completed(result, f"TCP bind probe {bind_addr}:{bind_port}")
    return parse_guest_json(result.stdout, f"tcp bind probe {bind_addr}:{bind_port} stdout")


def start_guest_tcp_listener(vm, bind_addr, bind_port):
    ready_file = f"/tmp/phantun-tcp-listener-{uuid.uuid4().hex}"
    stop_file = f"/tmp/phantun-tcp-listener-stop-{uuid.uuid4().hex}"
    listener = spawn_guest_scenario(
        vm,
        "hold_tcp_listener",
        {
            "bind_addr": bind_addr,
            "bind_port": bind_port,
            "ready_file": ready_file,
            "stop_file": stop_file,
        },
    )
    wait_for_guest_ready_file(vm, ready_file, timeout=5)
    return listener, stop_file


def test_kernel_version(vm):
    """Sanity check that we are running the expected kernel."""
    res = vm.run(["uname", "-r"])
    if vm.kernel_ver not in res.stdout:
        pytest.fail(f"Expected kernel {vm.kernel_ver} not found in {res.stdout}")


def test_module_load_success(phantun_module, dmesg, vm):
    """Test that the module loads successfully via DKMS installed modprobe."""
    dmesg.clear()
    phantun_module.load(managed_local_ports="1234")

    res = vm.run(["lsmod"])
    if "phantun" not in res.stdout:
        pytest.fail("phantun module is not loaded in lsmod")
    if not dmesg.wait_for(f"phantun {phantun_module.version} loaded", timeout=5):
        pytest.fail("Module did not log successful module initialization")
    if not dmesg.wait_for("registered IPv4 LOCAL_OUT/PRE_ROUTING hooks", timeout=5):
        pytest.fail("Module did not log successful netfilter hook registration")


def test_module_load_ignores_base64_prefix_without_kernel_support(phantun_module, dmesg, vm):
    if kernel_has_base64_support(vm):
        pytest.skip("kernel provides in-kernel base64 decode support")

    dmesg.clear()
    phantun_module.load(
        managed_local_ports="1234",
        handshake_request="base64:YWJj",
        handshake_response="base64:ZGVm",
    )

    res = vm.run(["lsmod"])
    if "phantun" not in res.stdout:
        pytest.fail("phantun module is not loaded in lsmod")
    if not dmesg.wait_for("base64 parameter is unsupported by this kernel, ignoring", timeout=5):
        pytest.fail("Module did not warn that base64-prefixed handshake payloads are unsupported")
    if not dmesg.wait_for("registered IPv4 LOCAL_OUT/PRE_ROUTING hooks", timeout=5):
        pytest.fail("Module did not log successful netfilter hook registration")


def test_module_unload_success(phantun_module, dmesg, vm):
    """Test that the module unloads cleanly."""
    dmesg.clear()
    phantun_module.load(managed_local_ports="4321")

    res = vm.run(["lsmod"])
    if "phantun" not in res.stdout:
        pytest.fail("phantun module should be loaded before unload test")

    phantun_module.unload()

    res = vm.run(["lsmod"])
    if "phantun" in res.stdout:
        pytest.fail("phantun module still loaded after rmmod")

    if not dmesg.wait_for("unregistered netfilter hooks", timeout=5):
        pytest.fail("Module did not log successful netfilter hook unregistration")
    if not dmesg.wait_for("phantun unloaded", timeout=5):
        pytest.fail("Module did not log successful module unload")


def test_module_reload_new_params(phantun_module, dmesg):
    """Test that the module can be reloaded with different parameters seamlessly."""
    dmesg.clear()
    phantun_module.load(managed_local_ports="1111")
    if not dmesg.wait_for("registered IPv4 LOCAL_OUT/PRE_ROUTING hooks", timeout=5):
        pytest.fail("First load failed")

    # .load() automatically unloads before loading new options
    dmesg.clear()
    phantun_module.load(managed_local_ports="2222")

    if not dmesg.wait_for("registered IPv4 LOCAL_OUT/PRE_ROUTING hooks", timeout=5):
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


def test_module_load_warns_when_reserved_tcp_port_is_already_occupied(phantun_module, dmesg, vm):
    managed_port = 45123
    listener, stop_file = start_guest_tcp_listener(vm, "0.0.0.0", managed_port)

    dmesg.clear()
    try:
        phantun_module.load(managed_local_ports=str(managed_port), reserved_local_ports="all")

        res = vm.run(["lsmod"])
        if "phantun" not in res.stdout:
            pytest.fail("phantun module is not loaded in lsmod after occupied-port warning test")
        if not dmesg.wait_for(f"local TCP port {managed_port} is already occupied", timeout=5):
            pytest.fail("Module did not log that reserved_local_ports encountered an already occupied TCP port")
    finally:
        vm.run(["touch", stop_file], check=False)
        try:
            listener.communicate(timeout=10)
        except Exception as exc:
            if listener.proc.poll() is None:
                listener.terminate()
            pytest.fail(f"held TCP listener did not terminate cleanly: {exc!r}")


def test_reserved_local_ports_is_ignored_outside_local_only_mode(phantun_module, dmesg, vm):
    managed_port = 45124

    dmesg.clear()
    phantun_module.load(
        managed_local_ports=str(managed_port),
        managed_remote_peers="198.51.100.20:51820",
        reserved_local_ports="all",
    )

    if not dmesg.wait_for("reserved_local_ports=all ignored because it only applies", timeout=5):
        pytest.fail("Module did not log that reserved_local_ports was ignored outside local-only mode")

    probe = run_tcp_bind_probe(vm, "0.0.0.0", managed_port)
    if not probe.get("ok"):
        pytest.fail(f"TCP bind unexpectedly failed while reserved_local_ports should be ignored: {probe!r}")
