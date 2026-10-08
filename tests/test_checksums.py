"""Generated fake-TCP / reinjected UDP checksums and inbound checksum verification."""

import time
import uuid

import pytest

from helpers import (
    MANAGED_LOCAL_PORTS,
    NS6_ADDR_A,
    NS6_ADDR_B,
    NS_A,
    NS_ADDR_A,
    NS_ADDR_B,
    NS_B,
    PORTS_A,
    PORTS_B,
    VETH_B,
    assert_completed,
    cleanup_netns_topology,
    ensure_netns_topology,
    load_managed_module,
    make_netns_ingress_flag_drop_probe,
    make_netns_output_flag_probe,
    parse_guest_json,
    read_module_stat,
    read_module_stats,
    require_guest_command,
    run_netns_scenario,
    spawn_netns_scenario,
    spawn_ready_capture,
    wait_for_guest_ready_file,
)


def test_netns_generated_fake_tcp_checksum_state_is_valid_or_partial(phantun_module, vm):
    load_managed_module(phantun_module)
    ensure_netns_topology(vm)

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    payload = "checksum-v4"
    ready_file = f"/tmp/phantun_csum_v4_{uuid.uuid4().hex}"
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "recv_many",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 2,
            "timeout_sec": 20,
            "ready_file": ready_file,
        },
    )
    capture = None

    try:
        wait_for_guest_ready_file(vm, ready_file, timeout=5)
        warmup = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["warmup"],
            },
            timeout=10,
        )
        assert_completed(warmup, "checksum warm-up sender")

        deadline = time.time() + 5
        while read_module_stat(vm, "flows_established") == 0:
            if time.time() >= deadline:
                pytest.fail("checksum warm-up datagram did not establish the flow")
            time.sleep(0.1)

        capture = spawn_ready_capture(
            vm,
            NS_B,
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payload": payload,
                "timeout_sec": 20,
            },
        )
        sender = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": [payload],
            },
            timeout=10,
        )
        assert_completed(sender, "checksum payload sender")

        capture_result = capture.communicate(timeout=20)
        assert_completed(capture_result, "checksum capture")
        captured = parse_guest_json(capture_result.stdout, "checksum capture stdout")
        # Regression guard for the pseudo-header seed. Depending on the capture
        # point, the checksum may already be resolved or still CHECKSUM_PARTIAL.
        if captured.get("csum_state") not in ("valid", "partial_seed"):
            pytest.fail(f"generated fake-TCP checksum state is invalid: {captured!r}")

        server_result = server.communicate(timeout=20)
        assert_completed(server_result, "checksum receiver")
    finally:
        if capture is not None:
            capture.terminate()
        server.terminate()
        cleanup_netns_topology(vm)


@pytest.mark.usefixtures("ipv6_runtime")
def test_ipv6_generated_fake_tcp_checksum_state_is_valid_or_partial(phantun_module, vm):
    load_managed_module(phantun_module)
    ensure_netns_topology(vm, with_ipv6=True)

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    payload = "checksum-v6"
    ready_file = f"/tmp/phantun_csum_v6_{uuid.uuid4().hex}"
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "recv_many",
        {
            "bind_addr": NS6_ADDR_B,
            "bind_port": dst_port,
            "count": 2,
            "timeout_sec": 20,
            "ready_file": ready_file,
        },
    )
    capture = None

    try:
        wait_for_guest_ready_file(vm, ready_file, timeout=5)
        warmup = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS6_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS6_ADDR_B,
                "target_port": dst_port,
                "payloads": ["warmup"],
            },
            timeout=10,
        )
        assert_completed(warmup, "IPv6 checksum warm-up sender")

        deadline = time.time() + 5
        while read_module_stat(vm, "flows_established") == 0:
            if time.time() >= deadline:
                pytest.fail("IPv6 checksum warm-up datagram did not establish the flow")
            time.sleep(0.1)

        capture = spawn_ready_capture(
            vm,
            NS_B,
            {
                "bind_addr": NS6_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS6_ADDR_B,
                "target_port": dst_port,
                "payload": payload,
                "timeout_sec": 20,
            },
        )
        sender = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS6_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS6_ADDR_B,
                "target_port": dst_port,
                "payloads": [payload],
            },
            timeout=10,
        )
        assert_completed(sender, "IPv6 checksum payload sender")

        capture_result = capture.communicate(timeout=20)
        assert_completed(capture_result, "IPv6 checksum capture")
        captured = parse_guest_json(capture_result.stdout, "IPv6 checksum capture stdout")
        # Regression guard for the pseudo-header seed. Depending on the capture
        # point, the checksum may already be resolved or still CHECKSUM_PARTIAL.
        if captured.get("csum_state") not in ("valid", "partial_seed"):
            pytest.fail(f"IPv6 generated fake-TCP checksum state is invalid: {captured!r}")

        server_result = server.communicate(timeout=20)
        assert_completed(server_result, "IPv6 checksum receiver")
    finally:
        if capture is not None:
            capture.terminate()
        server.terminate()
        cleanup_netns_topology(vm)


@pytest.mark.parametrize("ipv6", [False, True], ids=["ipv4", "ipv6"])
@pytest.mark.parametrize("gso", [False, True], ids=["datagrams", "gso"])
def test_netns_reinjected_udp_checksums_cover_payload_boundaries(phantun_module, vm, ipv6, gso):
    load_managed_module(phantun_module)
    ensure_netns_topology(vm, with_ipv6=ipv6)
    src_addr, dst_addr = (NS6_ADDR_A, NS6_ADDR_B) if ipv6 else (NS_ADDR_A, NS_ADDR_B)
    src_port, dst_port = PORTS_A[0], PORTS_B[0]
    # Odd GSO segments exercise checksum boundaries after segmentation; normal
    # sends cover tiny odd lengths and the largest translated payload per family.
    payloads = (
        [c * 1439 for c in "ABCD"]
        if gso
        else ["A", "BCD", "e" * 17, "f" * 127, "g" * 1439, "h" * (1440 if ipv6 else 1460)]
    )
    ready_file = f"/tmp/phantun-udp-csum-recv-{uuid.uuid4().hex}"
    capture_ready = f"/tmp/phantun-udp-csum-capture-{uuid.uuid4().hex}"
    server = capture = None
    try:
        server = spawn_netns_scenario(
            vm,
            NS_B,
            "recv_many_reply",
            {
                "bind_addr": dst_addr,
                "bind_port": dst_port,
                "count": len(payloads) + 1,
                "replies": ["ready"],
                "timeout_sec": 20,
                "ready_file": ready_file,
            },
        )
        wait_for_guest_ready_file(vm, ready_file)
        warmup = run_netns_scenario(
            vm,
            NS_A,
            "ping_client",
            {
                "bind_addr": src_addr,
                "bind_port": src_port,
                "target_addr": dst_addr,
                "target_port": dst_port,
                "payload": "warmup",
            },
            timeout=10,
        )
        assert_completed(warmup, "UDP checksum warm-up")
        if parse_guest_json(warmup.stdout, "UDP checksum warm-up")["reply"] != "ready":
            pytest.fail("UDP checksum warm-up did not reach the receiver")

        capture = spawn_netns_scenario(
            vm,
            NS_B,
            "capture_udp_packets",
            {
                "bind_addr": src_addr,
                "bind_port": src_port,
                "target_addr": dst_addr,
                "target_port": dst_port,
                "count": len(payloads),
                "timeout_sec": 20,
                "ready_file": capture_ready,
            },
        )
        wait_for_guest_ready_file(vm, capture_ready)
        sender = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": src_addr,
                "bind_port": src_port,
                "target_addr": dst_addr,
                "target_port": dst_port,
                "payloads": ["".join(payloads)] if gso else payloads,
                "gso_size": 1439 if gso else None,
            },
            timeout=10,
        )
        assert_completed(sender, "UDP checksum boundary sender")
        capture_result = capture.communicate(timeout=25)
        assert_completed(capture_result, "reinjected UDP checksum capture")
        packets = parse_guest_json(capture_result.stdout, "UDP checksum capture")["packets"]
        if [packet["payload"] for packet in packets] != payloads:
            pytest.fail(f"reinjected UDP payload boundaries changed: {packets!r}")
        if not all(packet["checksum_valid"] for packet in packets):
            pytest.fail(f"reinjected UDP checksum is invalid: {packets!r}")
        server_result = server.communicate(timeout=25)
        assert_completed(server_result, "UDP checksum boundary receiver")
        received = parse_guest_json(server_result.stdout, "UDP checksum receiver")["received"]
        if [entry["message"] for entry in received] != ["warmup", *payloads]:
            pytest.fail(f"application UDP payload boundaries changed: {received!r}")
    finally:
        if capture is not None:
            capture.terminate()
        if server is not None:
            server.terminate()
        vm.run(["rm", "-f", ready_file, capture_ready], check=False)
        cleanup_netns_topology(vm)


def test_bad_tcp_checksum_syn_is_silently_dropped(phantun_module, vm):
    phantun_module.load(managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    ingress_probe = make_netns_ingress_flag_drop_probe(
        vm,
        NS_B,
        VETH_B,
        [
            {
                "src_addr": NS_ADDR_A,
                "src_port": src_port,
                "dst_addr": NS_ADDR_B,
                "dst_port": dst_port,
                "flags_expr": "syn",
                "comment": "bad_tcp_syn_ingress",
                "action": "accept",
            }
        ],
    )
    synack_probe = make_netns_output_flag_probe(
        vm,
        NS_B,
        [
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "syn | ack",
                "comment": "bad_tcp_syn_synack",
            }
        ],
    )
    baseline_stats = read_module_stats(vm)

    try:
        run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": "syn",
                "seq": 4095,
                "corrupt_tcp_checksum": True,
            },
        )
        time.sleep(0.2)

        if ingress_probe.packets(vm, "bad_tcp_syn_ingress") == 0:
            pytest.fail("bad-checksum SYN did not reach the remote ingress path in this test environment")
        if synack_probe.packets(vm, "bad_tcp_syn_synack") != 0:
            pytest.fail("bad TCP checksum SYN must be silently dropped without SYN|ACK")

        stats_after = read_module_stats(vm)
        if stats_after["flows_created"] != baseline_stats["flows_created"]:
            pytest.fail(
                f"bad TCP checksum SYN must not create flow state: before={baseline_stats!r} after={stats_after!r}"
            )
        if stats_after["bad_checksum_dropped"] != baseline_stats["bad_checksum_dropped"] + 1:
            pytest.fail(
                f"bad TCP checksum SYN must increment bad_checksum_dropped: before={baseline_stats!r} after={stats_after!r}"
            )
    finally:
        ingress_probe.cleanup(vm)
        synack_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_bad_tcp_checksum_unknown_ack_is_silently_dropped(phantun_module, vm):
    phantun_module.load(managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    ingress_probe = make_netns_ingress_flag_drop_probe(
        vm,
        NS_B,
        VETH_B,
        [
            {
                "src_addr": NS_ADDR_A,
                "src_port": src_port,
                "dst_addr": NS_ADDR_B,
                "dst_port": dst_port,
                "flags_expr": "ack",
                "comment": "bad_tcp_ack_ingress",
                "action": "accept",
            }
        ],
    )
    rst_probe = make_netns_output_flag_probe(
        vm,
        NS_B,
        [
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "rst | ack",
                "comment": "bad_tcp_ack_rst",
            }
        ],
    )
    baseline_stats = read_module_stats(vm)

    try:
        run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": "ack",
                "seq": 12345,
                "ack": 67890,
                "payload": "junk",
                "corrupt_tcp_checksum": True,
            },
        )
        time.sleep(0.2)

        if ingress_probe.packets(vm, "bad_tcp_ack_ingress") == 0:
            pytest.fail("bad-checksum ACK did not reach the remote ingress path in this test environment")
        if rst_probe.packets(vm, "bad_tcp_ack_rst") != 0:
            pytest.fail("bad TCP checksum unknown ACK must be silently dropped without RST|ACK")

        stats_after = read_module_stats(vm)
        if stats_after["rst_sent"] != baseline_stats["rst_sent"]:
            pytest.fail(
                f"bad TCP checksum unknown ACK must not increment rst_sent: before={baseline_stats!r} after={stats_after!r}"
            )
        if stats_after["bad_checksum_dropped"] != baseline_stats["bad_checksum_dropped"] + 1:
            pytest.fail(
                f"bad TCP checksum unknown ACK must increment bad_checksum_dropped: before={baseline_stats!r} after={stats_after!r}"
            )
    finally:
        ingress_probe.cleanup(vm)
        rst_probe.cleanup(vm)
        cleanup_netns_topology(vm)
