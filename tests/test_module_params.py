"""Load-time module parameter parsing, validation, and derived settings."""

import pytest

from helpers import (
    MANAGED_LOCAL_PORTS,
    kernel_has_base64_support,
)


def assert_modprobe_rejected(result, context):
    if result.returncode == 0:
        pytest.fail(f"modprobe unexpectedly accepted {context}")

    # These tests run through virtme-ng's interactive guest shell; depending on
    # how that shell is attached, modprobe diagnostics may surface on either stream.
    output = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip())
    if "Invalid argument" not in output:
        pytest.fail(f"unexpected modprobe output for {context}: stdout={result.stdout!r}, stderr={result.stderr!r}")


def assert_modprobe_rejected_oversized_payload(result, context):
    if result.returncode == 0:
        pytest.fail(f"modprobe unexpectedly accepted {context}")

    output = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip())
    if "Invalid argument" not in output and "No space left on device" not in output:
        pytest.fail(f"unexpected modprobe output for {context}: stdout={result.stdout!r}, stderr={result.stderr!r}")


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


def test_module_rejects_invalid_hex_handshake_request_payload(phantun_module, vm):
    phantun_module.unload()
    vm.run("echo 'options phantun managed_local_ports=1234 handshake_request=hex:zz' > /etc/modprobe.d/phantun.conf")
    try:
        res = vm.run(["modprobe", "phantun"], check=False)
        assert_modprobe_rejected(res, "invalid hex handshake_request")

        lsmod = vm.run(["lsmod"])
        if "phantun" in lsmod.stdout:
            pytest.fail("phantun module should not remain loaded after invalid hex handshake_request")
    finally:
        vm.run(["rm", "-f", "/etc/modprobe.d/phantun.conf"])


def test_module_rejects_odd_hex_handshake_response_payload(phantun_module, vm):
    phantun_module.unload()
    vm.run(
        "echo 'options phantun managed_local_ports=1234 handshake_request=req handshake_response=hex:abc' "
        "> /etc/modprobe.d/phantun.conf"
    )
    try:
        res = vm.run(["modprobe", "phantun"], check=False)
        assert_modprobe_rejected(res, "odd hex handshake_response")

        lsmod = vm.run(["lsmod"])
        if "phantun" in lsmod.stdout:
            pytest.fail("phantun module should not remain loaded after odd hex handshake_response")
    finally:
        vm.run(["rm", "-f", "/etc/modprobe.d/phantun.conf"])


def test_module_rejects_invalid_base64_handshake_request_payload_when_kernel_supports_decode(phantun_module, vm):
    if not kernel_has_base64_support(vm):
        pytest.skip("kernel lacks in-kernel base64 decode support")

    phantun_module.unload()
    vm.run(
        "echo 'options phantun managed_local_ports=1234 handshake_request=base64:@@@@' "
        "> /etc/modprobe.d/phantun.conf"
    )
    try:
        res = vm.run(["modprobe", "phantun"], check=False)
        assert_modprobe_rejected(res, "invalid base64 handshake_request")

        lsmod = vm.run(["lsmod"])
        if "phantun" in lsmod.stdout:
            pytest.fail("phantun module should not remain loaded after invalid base64 handshake_request")
    finally:
        vm.run(["rm", "-f", "/etc/modprobe.d/phantun.conf"])


def test_module_rejects_oversized_handshake_request(phantun_module, vm):
    phantun_module.unload()
    payload = "A" * 1500
    vm.run(
        "echo 'options phantun managed_local_ports=1234 handshake_request="
        + payload
        + "' > /etc/modprobe.d/phantun.conf"
    )
    try:
        res = vm.run(["modprobe", "phantun"], check=False)
        assert_modprobe_rejected_oversized_payload(res, "oversized handshake_request")
    finally:
        vm.run(["rm", "-f", "/etc/modprobe.d/phantun.conf"])


def test_module_rejects_oversized_handshake_response(phantun_module, vm):
    phantun_module.unload()
    payload = "B" * 1500
    vm.run(
        "echo 'options phantun managed_local_ports=1234 handshake_request=req handshake_response="
        + payload
        + "' > /etc/modprobe.d/phantun.conf"
    )
    try:
        res = vm.run(["modprobe", "phantun"], check=False)
        assert_modprobe_rejected_oversized_payload(res, "oversized handshake_response")
    finally:
        vm.run(["rm", "-f", "/etc/modprobe.d/phantun.conf"])


def test_module_rejects_reopen_guard_at_cap(phantun_module, vm):
    phantun_module.unload()
    vm.run(
        "echo 'options phantun managed_local_ports=1234 reopen_guard_bytes=1073741824' "
        "> /etc/modprobe.d/phantun.conf"
    )
    try:
        res = vm.run(["modprobe", "phantun"], check=False)
        assert_modprobe_rejected(res, "reopen_guard_bytes at cap")

        lsmod = vm.run(["lsmod"])
        if "phantun" in lsmod.stdout:
            pytest.fail("phantun module should not remain loaded after invalid reopen_guard_bytes")
    finally:
        vm.run(["rm", "-f", "/etc/modprobe.d/phantun.conf"])


def test_module_accepts_reopen_guard_below_cap(phantun_module, vm):
    phantun_module.unload()
    vm.run(
        "echo 'options phantun managed_local_ports=1234 reopen_guard_bytes=1073741823' "
        "> /etc/modprobe.d/phantun.conf"
    )
    try:
        res = vm.run(["modprobe", "phantun"], check=False)
        if res.returncode != 0:
            pytest.fail(
                "modprobe rejected reopen_guard_bytes below cap: " f"stdout={res.stdout!r}, stderr={res.stderr!r}"
            )

        lsmod = vm.run(["lsmod"])
        if "phantun" not in lsmod.stdout:
            pytest.fail("phantun module is not loaded with reopen_guard_bytes below cap")
    finally:
        vm.run(["rm", "-f", "/etc/modprobe.d/phantun.conf"])


def test_module_rejects_oversized_second_timer_param(phantun_module, vm):
    phantun_module.unload()
    vm.run(
        "echo 'options phantun managed_local_ports=1234 keepalive_interval_sec=4294968' "
        "> /etc/modprobe.d/phantun.conf"
    )
    try:
        res = vm.run(["modprobe", "phantun"], check=False)
        assert_modprobe_rejected(res, "oversized keepalive_interval_sec")
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


def test_module_rejects_invalid_managed_netns(phantun_module, vm):
    phantun_module.unload()
    vm.run("echo 'options phantun managed_local_ports=1234 managed_netns=bogus' > /etc/modprobe.d/phantun.conf")
    try:
        res = vm.run(["modprobe", "phantun"], check=False)
        assert_modprobe_rejected(res, "invalid managed_netns")

        lsmod = vm.run(["lsmod"])
        if "phantun" in lsmod.stdout:
            pytest.fail("phantun module should not remain loaded after invalid managed_netns")
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


def test_replacement_protect_auto_config_logs_effective_window(phantun_module, dmesg, vm):
    dmesg.clear()
    phantun_module.load(
        managed_local_ports=MANAGED_LOCAL_PORTS,
        replacement_protect_ms=0,
        replacement_quarantine_ms=7000,
        handshake_timeout_ms=800,
        handshake_retries=3,
    )

    res = vm.run(["lsmod"])
    if "phantun" not in res.stdout:
        pytest.fail("phantun module is not loaded after replacement_protect_ms=0")
    if not dmesg.wait_for("replacement_protect_ms = 0 (auto effective 800)", timeout=5):
        pytest.fail("Module did not log replacement_protect_ms=0 auto effective window from handshake budget")
