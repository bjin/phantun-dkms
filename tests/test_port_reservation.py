"""reserved_local_ports TCP port reservation."""

import errno
import uuid

import pytest

from helpers import (
    PORTS_A,
    assert_completed,
    parse_guest_json,
    run_guest_scenario,
    run_in_netns,
    run_netns_scenario,
    spawn_guest_scenario,
    wait_for_guest_ready_file,
)


def run_tcp_bind_probe(vm, bind_addr, bind_port, namespace=None, v6only=None):
    config = {
        "bind_addr": bind_addr,
        "bind_port": bind_port,
        "v6only": v6only,
    }

    if namespace is None:
        result = run_guest_scenario(vm, "tcp_bind_listen", config)
        context = f"init-net TCP bind probe {bind_addr}:{bind_port}"
    else:
        result = run_netns_scenario(vm, namespace, "tcp_bind_listen", config)
        context = f"{namespace} TCP bind probe {bind_addr}:{bind_port}"

    assert_completed(result, context)
    return parse_guest_json(result.stdout, f"{context} stdout")


def assert_tcp_bind_ok(result, bind_addr, bind_port):
    if not result.get("ok"):
        pytest.fail(f"expected TCP bind to succeed on {bind_addr}:{bind_port}, got {result!r}")


def assert_tcp_bind_errno(result, expected_errno, bind_addr, bind_port):
    if result.get("ok"):
        pytest.fail(f"expected TCP bind on {bind_addr}:{bind_port} to fail with errno {expected_errno}, got {result!r}")
    if result.get("errno") != expected_errno:
        pytest.fail(
            f"unexpected errno for TCP bind on {bind_addr}:{bind_port}: expected {expected_errno}, got {result!r}"
        )


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


def test_default_local_only_mode_does_not_reserve_tcp_port(phantun_module, vm):
    managed_port = PORTS_A[0]

    phantun_module.load(managed_local_ports=str(managed_port))

    probe = run_tcp_bind_probe(vm, "0.0.0.0", managed_port)
    assert_tcp_bind_ok(probe, "0.0.0.0", managed_port)


def test_reserved_local_ports_off_keeps_local_only_mode_unreserved(phantun_module, vm):
    managed_port = PORTS_A[0]

    phantun_module.load(managed_local_ports=str(managed_port), reserved_local_ports="off")

    probe = run_tcp_bind_probe(vm, "0.0.0.0", managed_port)
    assert_tcp_bind_ok(probe, "0.0.0.0", managed_port)


def test_reserved_local_ports_all_blocks_init_netns_tcp_bind(phantun_module, vm):
    managed_port = PORTS_A[0]

    phantun_module.load(managed_local_ports=str(managed_port), reserved_local_ports="all")

    wildcard_probe = run_tcp_bind_probe(vm, "0.0.0.0", managed_port)
    loopback_probe = run_tcp_bind_probe(vm, "127.0.0.1", managed_port)

    assert_tcp_bind_errno(wildcard_probe, errno.EADDRINUSE, "0.0.0.0", managed_port)
    assert_tcp_bind_errno(loopback_probe, errno.EADDRINUSE, "127.0.0.1", managed_port)


def test_reserved_local_ports_filters_to_managed_local_ports_only(phantun_module, dmesg, vm):
    dmesg.clear()
    phantun_module.load(
        managed_local_ports="2222,3333",
        reserved_local_ports="2222,4444",
    )

    if not dmesg.wait_for(
        "reserved_local_ports[1]=4444 ignored because it is not present in managed_local_ports", timeout=5
    ):
        pytest.fail("Module did not log that non-managed reserved_local_ports entries were ignored")

    reserved_probe = run_tcp_bind_probe(vm, "0.0.0.0", 2222)
    unreserved_probe = run_tcp_bind_probe(vm, "0.0.0.0", 3333)

    assert_tcp_bind_errno(reserved_probe, errno.EADDRINUSE, "0.0.0.0", 2222)
    assert_tcp_bind_ok(unreserved_probe, "0.0.0.0", 3333)


def test_reserved_local_ports_default_init_mode_skips_new_netns(phantun_module, vm):
    managed_port = PORTS_A[0]
    namespace = "pht-reserve-after-load"

    phantun_module.load(managed_local_ports=str(managed_port), reserved_local_ports="all")
    vm.run(["ip", "netns", "del", namespace], check=False)
    vm.run(["ip", "netns", "add", namespace])

    try:
        run_in_netns(vm, namespace, ["ip", "link", "set", "lo", "up"])
        probe = run_tcp_bind_probe(vm, "0.0.0.0", managed_port, namespace=namespace)
        assert_tcp_bind_ok(probe, "0.0.0.0", managed_port)
    finally:
        vm.run(["ip", "netns", "del", namespace], check=False)


def test_reserved_local_ports_all_mode_applies_to_new_netns(phantun_module, vm):
    managed_port = PORTS_A[0]
    namespace = "pht-reserve-after-load"

    phantun_module.load(
        managed_netns="all",
        managed_local_ports=str(managed_port),
        reserved_local_ports="all",
    )
    vm.run(["ip", "netns", "del", namespace], check=False)
    vm.run(["ip", "netns", "add", namespace])

    try:
        run_in_netns(vm, namespace, ["ip", "link", "set", "lo", "up"])
        probe = run_tcp_bind_probe(vm, "0.0.0.0", managed_port, namespace=namespace)
        assert_tcp_bind_errno(probe, errno.EADDRINUSE, "0.0.0.0", managed_port)
    finally:
        vm.run(["ip", "netns", "del", namespace], check=False)


@pytest.mark.usefixtures("ipv6_runtime")
def test_reserved_local_ports_respect_ipv6_family_mode(phantun_module, vm):
    managed_port = PORTS_A[0]
    phantun_module.load(
        managed_local_ports=str(managed_port),
        reserved_local_ports="all",
        ip_families="ipv6",
    )

    ipv4_probe = run_tcp_bind_probe(vm, "0.0.0.0", managed_port)
    ipv6_probe = run_tcp_bind_probe(vm, "::", managed_port, v6only=True)
    assert ipv4_probe.get("ok")
    assert not ipv6_probe.get("ok") and ipv6_probe.get("errno") == errno.EADDRINUSE

    phantun_module.load(
        managed_local_ports=str(managed_port),
        reserved_local_ports="all",
        ip_families="both",
    )

    ipv4_probe = run_tcp_bind_probe(vm, "0.0.0.0", managed_port)
    ipv6_probe = run_tcp_bind_probe(vm, "::", managed_port, v6only=True)
    assert not ipv4_probe.get("ok") and ipv4_probe.get("errno") == errno.EADDRINUSE
    assert not ipv6_probe.get("ok") and ipv6_probe.get("errno") == errno.EADDRINUSE


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
