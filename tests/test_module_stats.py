"""sysfs stats counters and skb drop attribution."""

import time
import uuid

import pytest

from helpers import (
    MANAGED_LOCAL_PORTS,
    MODULE_STAT_NAMES,
    NS_A,
    NS_ADDR_A,
    NS_ADDR_B,
    NS_B,
    PORTS_A,
    PORTS_B,
    REQ,
    RESP,
    assert_completed,
    cleanup_netns_topology,
    ensure_netns_topology,
    parse_guest_json,
    read_module_stats,
    run_netns_scenario,
    spawn_netns_scenario,
    wait_for_guest_ready_file,
)


def _find_tracefs_root(vm):
    # A mounted-but-empty tracefs directory is common; probe the actual files.
    for root in ("/sys/kernel/tracing", "/sys/kernel/debug/tracing"):
        has_event = vm.run(["test", "-f", f"{root}/events/skb/kfree_skb/enable"], check=False)
        has_trace = vm.run(["test", "-f", f"{root}/trace"], check=False)
        if has_event.returncode == 0 and has_trace.returncode == 0:
            return root
    return None


@pytest.fixture(scope="session")
def symbolic_kfree_skb_tracefs(vm):
    tracefs = _find_tracefs_root(vm)
    if tracefs is None:
        pytest.skip("skb:kfree_skb tracepoint unavailable")

    event_format = vm.run(["cat", f"{tracefs}/events/skb/kfree_skb/format"]).stdout
    # A stack can include the hook as an ancestor of a later unrelated free.
    # Only a symbolized event location identifies the freeing call site.
    if "location=%pS" not in event_format:
        pytest.skip("skb:kfree_skb does not render call-site symbols")
    return tracefs


@pytest.fixture(scope="session")
def symbolic_kfree_skb_module(symbolic_kfree_skb_tracefs, request):
    # Bind this wrapper to the VM-parametrized capability check.
    return symbolic_kfree_skb_tracefs, request.getfixturevalue("phantun_module")


def test_sysfs_stats_exist_and_increment(phantun_module, vm):
    phantun_module.load(
        managed_netns="all",
        managed_local_ports=MANAGED_LOCAL_PORTS,
        handshake_request=REQ,
        handshake_response=RESP,
    )
    initial = read_module_stats(vm)
    missing = [name for name in MODULE_STAT_NAMES if name not in initial]
    if missing:
        pytest.fail(f"missing module stats: {missing!r}")
    if any(value != 0 for value in initial.values()):
        pytest.fail(f"expected fresh module stats to start at zero, got {initial!r}")

    ensure_netns_topology(vm)
    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    ready_file = f"/tmp/phantun-stats-server-{time.monotonic_ns()}"
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "recv_many_reply",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 2,
            "replies": ["reply-0", "reply-1"],
            "ready_file": ready_file,
        },
    )

    try:
        wait_for_guest_ready_file(vm, ready_file)
        client = run_netns_scenario(
            vm,
            NS_A,
            "send_many_recv",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["client-0", "client-1"],
                "recv_count": 2,
                "delay_ms": 100,
            },
            timeout=20,
        )
        server_result = server.communicate(timeout=20)
        assert_completed(client, "stats client")
        assert_completed(server_result, "stats server")

        client_data = parse_guest_json(client.stdout, "stats client stdout")
        server_data = parse_guest_json(server_result.stdout, "stats server stdout")
        if [entry["message"] for entry in server_data.get("received", [])] != [
            "client-0",
            "client-1",
        ]:
            pytest.fail(f"unexpected server payloads: {server_data!r}")
        if [entry["message"] for entry in client_data.get("replies", [])] != [
            "reply-0",
            "reply-1",
        ]:
            pytest.fail(f"unexpected client replies: {client_data!r}")
    finally:
        cleanup_netns_topology(vm)

    stats = read_module_stats(vm)
    expected = {
        "flows_created": 2,
        "flows_established": 2,
        "request_payloads_injected": 1,
        "response_payloads_injected": 1,
        "collisions_won": 0,
        "collisions_lost": 0,
        "rst_sent": 0,
        "udp_packets_dropped": 0,
    }
    for name, value in expected.items():
        if stats.get(name) != value:
            pytest.fail(f"unexpected {name}: expected {value}, got {stats.get(name)} in {stats!r}")
    if stats.get("udp_packets_queued", 0) < 1:
        pytest.fail(f"expected at least one queued UDP packet, got {stats!r}")
    if stats.get("shaping_payloads_dropped", 0) < 1:
        pytest.fail(f"expected at least one shaping payload drop, got {stats!r}")


def test_translated_udp_does_not_hit_kfree_skb_tracepoint(symbolic_kfree_skb_module, vm):
    tracefs, phantun_module = symbolic_kfree_skb_module

    phantun_module.load(managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    enable_path = f"{tracefs}/events/skb/kfree_skb/enable"
    tracing_on_path = f"{tracefs}/tracing_on"

    # Snapshot global tracing state so the suite never leaves it altered.
    saved_tracing_on = vm.run(["cat", tracing_on_path]).stdout.strip()
    saved_enable = vm.run(["cat", enable_path]).stdout.strip()

    try:
        vm.run(f"echo 1 > {enable_path}")
        vm.run(f"echo 1 > {tracing_on_path}")
        vm.run(f"echo > {tracefs}/trace")

        # Clean phase: a normally translated round trip. Both converted sites
        # (phantun_local_out established tail, phantun_flush_queued_udp tail)
        # must free the consumed skb via consume_skb, so neither location may
        # appear as a kfree_skb (drop) event.
        ready_file = f"/tmp/phantun-trace-echo-{uuid.uuid4().hex}"
        server = spawn_netns_scenario(
            vm,
            NS_B,
            "echo_server",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "count": 1,
                "timeout_sec": 15,
                "ready_file": ready_file,
            },
        )
        wait_for_guest_ready_file(vm, ready_file, timeout=10)
        client = run_netns_scenario(
            vm,
            NS_A,
            "echo_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["clean"],
                "timeout_sec": 15,
            },
        )
        assert_completed(client, "clean-phase echo client")
        server_result = server.communicate(timeout=20)
        assert_completed(server_result, "clean-phase echo server")

        trace = vm.run(["cat", f"{tracefs}/trace"]).stdout
        offending = [
            line for line in trace.splitlines() if "phantun_local_out" in line or "phantun_flush_queued_udp" in line
        ]
        if offending:
            pytest.fail("translated UDP hit the kfree_skb drop tracepoint:\n" + "\n".join(offending))

        # Drop phase: an oversized payload on the same tuple is a genuine drop
        # and must still be visible to drop monitors via kfree_skb.
        vm.run(f"echo > {tracefs}/trace")
        oversized = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["X" * 1470],
            },
        )
        assert_completed(oversized, "oversized drop-phase send")

        deadline = time.time() + 10
        while time.time() < deadline:
            trace = vm.run(["cat", f"{tracefs}/trace"]).stdout
            if any("phantun_local_out" in line for line in trace.splitlines()):
                break
            time.sleep(0.5)
        else:
            pytest.fail("oversized-drop kfree_skb event at phantun_local_out never appeared")
    finally:
        vm.run(f"echo {saved_tracing_on} > {tracing_on_path}", check=False)
        vm.run(f"echo {saved_enable} > {enable_path}", check=False)
        vm.run(f"echo > {tracefs}/trace", check=False)
        cleanup_netns_topology(vm)
