"""Payload size limits, path MTU, and UDP GSO segmentation on established flows."""

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
    VETH_A,
    VETH_B,
    assert_completed,
    assert_receiver_messages,
    cleanup_netns_topology,
    ensure_netns_topology,
    load_managed_module,
    make_netns_output_flag_probe,
    make_netns_prerouting_flag_drop_probe,
    parse_guest_json,
    read_module_stat,
    read_module_stats,
    require_guest_command,
    run_in_netns,
    run_netns_scenario,
    spawn_netns_scenario,
    spawn_ready_capture,
    spawn_ready_recv_until_timeout,
    wait_for_guest_ready_file,
    wait_for_stat_greater,
)


def test_established_flow_delivers_udp_gso_superframe(phantun_module, vm):
    load_managed_module(phantun_module)
    ensure_netns_topology(vm)

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    chunks = [c * 1000 for c in "ABCD"]
    ready_file = f"/tmp/phantun_gso_recv_{uuid.uuid4().hex}"
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "recv_many",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 5,
            "timeout_sec": 20,
            "ready_file": ready_file,
        },
    )

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
        assert_completed(warmup, "GSO warm-up sender")

        deadline = time.time() + 5
        while read_module_stat(vm, "flows_established") == 0:
            if time.time() >= deadline:
                pytest.fail("warm-up datagram did not establish the flow")
            time.sleep(0.1)

        gso = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["".join(chunks)],
                "gso_size": 1000,
            },
            timeout=10,
        )
        assert_completed(gso, "UDP GSO sender")

        server_result = server.communicate(timeout=20)
        assert_completed(server_result, "UDP GSO receiver")
        server_data = parse_guest_json(server_result.stdout, "UDP GSO receiver stdout")
        received = [entry["message"] for entry in server_data.get("received", [])]
        if received != ["warmup", *chunks]:
            pytest.fail(f"unexpected UDP GSO payloads: {received!r}")
        if read_module_stat(vm, "oversized_payloads_dropped") != 0:
            pytest.fail("UDP GSO superframe was treated as an oversized payload")
    finally:
        server.terminate()
        cleanup_netns_topology(vm)


@pytest.mark.usefixtures("ipv6_runtime")
def test_ipv6_established_flow_delivers_udp_gso_superframe(phantun_module, vm):
    load_managed_module(phantun_module)
    ensure_netns_topology(vm, with_ipv6=True)

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    chunks = [c * 1000 for c in "ABCD"]
    ready_file = f"/tmp/phantun_v6_gso_recv_{uuid.uuid4().hex}"
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "recv_many",
        {
            "bind_addr": NS6_ADDR_B,
            "bind_port": dst_port,
            "count": 5,
            "timeout_sec": 20,
            "ready_file": ready_file,
        },
    )

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
        assert_completed(warmup, "IPv6 GSO warm-up sender")

        deadline = time.time() + 5
        while read_module_stat(vm, "flows_established") == 0:
            if time.time() >= deadline:
                pytest.fail("IPv6 warm-up datagram did not establish the flow")
            time.sleep(0.1)

        gso = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS6_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS6_ADDR_B,
                "target_port": dst_port,
                "payloads": ["".join(chunks)],
                "gso_size": 1000,
            },
            timeout=10,
        )
        assert_completed(gso, "IPv6 UDP GSO sender")

        server_result = server.communicate(timeout=20)
        assert_completed(server_result, "IPv6 UDP GSO receiver")
        server_data = parse_guest_json(server_result.stdout, "IPv6 UDP GSO receiver stdout")
        received = [entry["message"] for entry in server_data.get("received", [])]
        if received != ["warmup", *chunks]:
            pytest.fail(f"unexpected IPv6 UDP GSO payloads: {received!r}")
        if read_module_stat(vm, "oversized_payloads_dropped") != 0:
            pytest.fail("IPv6 UDP GSO superframe was treated as an oversized payload")
    finally:
        server.terminate()
        cleanup_netns_topology(vm)


def test_oversized_outbound_udp_is_dropped_without_tearing_down_flow(phantun_module, vm):
    phantun_module.load(managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    oversized_payload = "X" * 1470
    baseline_stats = read_module_stats(vm)
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "recv_many",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 2,
            "timeout_sec": 20,
        },
    )

    try:
        time.sleep(0.2)
        client = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["first", oversized_payload, "second"],
                "delay_ms": 300,
            },
            timeout=20,
        )
        server_result = server.communicate(timeout=20)
        assert_completed(client, "oversized outbound UDP client")
        assert_completed(server_result, "oversized outbound UDP server")

        server_data = parse_guest_json(server_result.stdout, "oversized outbound UDP server stdout")
        if [entry["message"] for entry in server_data.get("received", [])] != ["first", "second"]:
            pytest.fail(f"oversized outbound UDP was delivered or flow did not recover: {server_data!r}")

        stats = read_module_stats(vm)
        if stats["oversized_payloads_dropped"] != baseline_stats["oversized_payloads_dropped"] + 1:
            pytest.fail(f"expected one oversized outbound drop: before={baseline_stats!r} after={stats!r}")
        if stats["udp_packets_dropped"] != baseline_stats["udp_packets_dropped"] + 1:
            pytest.fail(f"expected one outbound UDP drop: before={baseline_stats!r} after={stats!r}")
        if stats["rst_sent"] != baseline_stats["rst_sent"]:
            pytest.fail(
                f"oversized outbound UDP must not tear down flow with RST: before={baseline_stats!r} after={stats!r}"
            )
    finally:
        cleanup_netns_topology(vm)


def test_path_mtu_payload_drop_keeps_established_flow_alive(phantun_module, vm):
    phantun_module.load(managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    receiver = spawn_ready_recv_until_timeout(
        vm,
        NS_B,
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 3,
            "timeout_sec": 2,
        },
    )
    baseline_stats = read_module_stats(vm)

    try:
        opener = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["open"],
            },
        )
        assert_completed(opener, "path-MTU opener")
        established_stats = wait_for_stat_greater(
            vm,
            "flows_established",
            baseline_stats["flows_established"],
        )

        run_in_netns(vm, NS_A, ["ip", "link", "set", VETH_A, "mtu", "1300"])
        run_in_netns(
            vm,
            NS_A,
            ["ip", "route", "replace", f"{NS_ADDR_B}/32", "dev", VETH_A, "mtu", "lock", "1300"],
        )

        too_large = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["X" * 1350],
            },
        )
        assert_completed(too_large, "path-MTU oversized sender")
        time.sleep(0.2)

        after_drop = read_module_stats(vm)
        if after_drop["oversized_payloads_dropped"] != established_stats["oversized_payloads_dropped"] + 1:
            pytest.fail(f"path-MTU drop stats mismatch: before={established_stats!r} after={after_drop!r}")
        if after_drop["rst_sent"] != established_stats["rst_sent"]:
            pytest.fail(f"path-MTU drop must not send RST: before={established_stats!r} after={after_drop!r}")
        if after_drop["flows_established"] != established_stats["flows_established"]:
            pytest.fail(f"path-MTU drop must not re-establish flow: before={established_stats!r} after={after_drop!r}")

        small = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["Y" * 1200],
            },
        )
        assert_completed(small, "path-MTU survivor sender")

        receiver_result = receiver.communicate(timeout=6)
        assert_receiver_messages(receiver_result, ["open", "Y" * 1200], "path-MTU receiver", True)
    finally:
        run_in_netns(vm, NS_A, ["ip", "route", "del", f"{NS_ADDR_B}/32", "dev", VETH_A], check=False)
        run_in_netns(vm, NS_A, ["ip", "link", "set", VETH_A, "mtu", "1500"], check=False)
        receiver.terminate()
        cleanup_netns_topology(vm)


def test_oversized_established_payload_is_rejected_and_counted(phantun_module, vm):
    phantun_module.load(managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    run_in_netns(vm, NS_A, ["ip", "link", "set", VETH_A, "mtu", "3000"])
    run_in_netns(vm, NS_B, ["ip", "link", "set", VETH_B, "mtu", "3000"])
    oversize_payload = "X" * 2000
    capture = spawn_ready_capture(
        vm,
        NS_A,
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "target_addr": NS_ADDR_A,
            "target_port": src_port,
            "payload": "msg1",
            "timeout_sec": 15,
        },
    )
    rst_probe = make_netns_output_flag_probe(
        vm,
        NS_A,
        [
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "flags_expr": "rst | ack",
                "comment": "oversized_est_rst",
            }
        ],
    )
    receiver = spawn_netns_scenario(
        vm,
        NS_A,
        "recv_many",
        {
            "bind_addr": NS_ADDR_A,
            "bind_port": src_port,
            "count": 1,
            "timeout_sec": 15,
        },
    )
    baseline_stats = read_module_stats(vm)

    try:
        time.sleep(0.2)
        sender_result = run_netns_scenario(
            vm,
            NS_B,
            "send_many",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "target_addr": NS_ADDR_A,
                "target_port": src_port,
                "payloads": ["msg1"],
            },
        )
        receiver_result = receiver.communicate(timeout=15)
        capture_result = capture.communicate(timeout=15)

        assert_completed(sender_result, "oversized established sender")
        assert_completed(receiver_result, "oversized established receiver")
        assert_completed(capture_result, "oversized established capture")

        captured = parse_guest_json(capture_result.stdout, "oversized established capture stdout")
        baseline_rst = rst_probe.packets(vm, "oversized_est_rst")

        run_netns_scenario(
            vm,
            NS_B,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "target_addr": NS_ADDR_A,
                "target_port": src_port,
                "flags": "ack",
                "seq": captured["seq"] + len("msg1"),
                "ack": captured["ack"],
                "payload": oversize_payload,
            },
        )
        time.sleep(0.2)

        stats_after = read_module_stats(vm)
        if rst_probe.packets(vm, "oversized_est_rst") <= baseline_rst:
            pytest.fail("oversized established payload should trigger RST|ACK")
        if stats_after["oversized_payloads_dropped"] <= baseline_stats["oversized_payloads_dropped"]:
            pytest.fail(
                f"oversized established payload should increment oversized drop stats: before={baseline_stats!r} after={stats_after!r}"
            )
    finally:
        rst_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_oversized_final_ack_payload_is_rejected_and_counted(phantun_module, vm):
    phantun_module.load(managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    oversize_payload = "X" * 2000
    drop_synack = make_netns_prerouting_flag_drop_probe(
        vm,
        NS_A,
        [
            {
                "src_addr": NS_ADDR_B,
                "src_port": dst_port,
                "dst_addr": NS_ADDR_A,
                "dst_port": src_port,
                "flags_expr": "syn | ack",
                "comment": "drop_oversized_synack",
            }
        ],
    )
    run_in_netns(vm, NS_A, ["ip", "link", "set", VETH_A, "mtu", "3000"])
    run_in_netns(vm, NS_B, ["ip", "link", "set", VETH_B, "mtu", "3000"])
    synack_capture = spawn_ready_capture(
        vm,
        NS_A,
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "target_addr": NS_ADDR_A,
            "target_port": src_port,
            "payload": "",
            "timeout_sec": 10,
        },
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
                "comment": "oversized_final_rst",
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
            },
        )
        synack_result = synack_capture.communicate(timeout=10)
        assert_completed(synack_result, "oversized final synack capture")
        synack_data = parse_guest_json(synack_result.stdout, "oversized final synack stdout")
        baseline_rst = rst_probe.packets(vm, "oversized_final_rst")

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
                "seq": 4096,
                "ack": synack_data["seq"] + 1,
                "payload": oversize_payload,
            },
        )
        time.sleep(0.2)

        stats_after = read_module_stats(vm)
        if rst_probe.packets(vm, "oversized_final_rst") <= baseline_rst:
            pytest.fail("oversized final ACK payload should trigger RST|ACK")
        if stats_after["oversized_payloads_dropped"] <= baseline_stats["oversized_payloads_dropped"]:
            pytest.fail(
                f"oversized final ACK payload should increment oversized drop stats: before={baseline_stats!r} after={stats_after!r}"
            )
    finally:
        drop_synack.cleanup(vm)
        rst_probe.cleanup(vm)
        cleanup_netns_topology(vm)
