import time

import pytest

from helpers import (
    NS_A,
    NS_ADDR_A,
    NS_ADDR_B,
    NS_B,
    PORTS_A,
    PORTS_B,
    VETH_A,
    VETH_B,
    assert_completed,
    cleanup_netns_topology,
    ensure_netns_topology,
    make_netns_ingress_flag_drop_probe,
    make_netns_output_flag_probe,
    make_netns_prerouting_flag_drop_probe,
    parse_guest_json,
    read_module_stats,
    require_guest_command,
    run_in_netns,
    run_netns_scenario,
    spawn_netns_scenario,
    spawn_ready_capture,
)

MANAGED_LOCAL_PORTS = "2222,3333,4444,5555"
REQ = "HSREQ42"


def load_recovery_module(phantun_module, **kwargs):
    # Set keepalive interval to 1s to test liveness.
    phantun_module.load(
        managed_local_ports=MANAGED_LOCAL_PORTS,
        keepalive_interval_sec=1,
        keepalive_misses=2,
        handshake_retries=20,
        **kwargs,
    )


def received_messages(payload):
    return payload.get("received", [])


ROUTER_NS = "pht-r"
VETH_A_R = "veth-pht-ar"
VETH_R_A = "veth-pht-ra"
VETH_R_B = "veth-pht-rb"
VETH_B_R = "veth-pht-br"
FWD_ADDR_A = "10.210.0.1"
FWD_ADDR_R_A = "10.210.0.254"
FWD_ADDR_R_B = "10.220.0.254"
FWD_ADDR_B = "10.220.0.2"


def cleanup_forwarding_topology(vm):
    cleanup_netns_topology(vm, namespaces=(NS_A, NS_B, ROUTER_NS))


def ensure_forwarding_topology(vm):
    cleanup_forwarding_topology(vm)

    vm.run(["ip", "netns", "add", NS_A])
    vm.run(["ip", "netns", "add", ROUTER_NS])
    vm.run(["ip", "netns", "add", NS_B])

    vm.run(["ip", "link", "add", VETH_A_R, "type", "veth", "peer", "name", VETH_R_A])
    vm.run(["ip", "link", "add", VETH_R_B, "type", "veth", "peer", "name", VETH_B_R])

    vm.run(["ip", "link", "set", VETH_A_R, "netns", NS_A])
    vm.run(["ip", "link", "set", VETH_R_A, "netns", ROUTER_NS])
    vm.run(["ip", "link", "set", VETH_R_B, "netns", ROUTER_NS])
    vm.run(["ip", "link", "set", VETH_B_R, "netns", NS_B])

    for namespace in (NS_A, ROUTER_NS, NS_B):
        run_in_netns(vm, namespace, ["ip", "link", "set", "lo", "up"])

    run_in_netns(vm, NS_A, ["ip", "addr", "add", f"{FWD_ADDR_A}/24", "dev", VETH_A_R])
    run_in_netns(vm, ROUTER_NS, ["ip", "addr", "add", f"{FWD_ADDR_R_A}/24", "dev", VETH_R_A])
    run_in_netns(vm, ROUTER_NS, ["ip", "addr", "add", f"{FWD_ADDR_R_B}/24", "dev", VETH_R_B])
    run_in_netns(vm, NS_B, ["ip", "addr", "add", f"{FWD_ADDR_B}/24", "dev", VETH_B_R])

    run_in_netns(vm, NS_A, ["ip", "link", "set", VETH_A_R, "up"])
    run_in_netns(vm, ROUTER_NS, ["ip", "link", "set", VETH_R_A, "up"])
    run_in_netns(vm, ROUTER_NS, ["ip", "link", "set", VETH_R_B, "up"])
    run_in_netns(vm, NS_B, ["ip", "link", "set", VETH_B_R, "up"])

    run_in_netns(
        vm,
        NS_A,
        ["ip", "route", "add", f"{FWD_ADDR_B}/32", "via", FWD_ADDR_R_A, "dev", VETH_A_R],
    )
    run_in_netns(
        vm,
        NS_B,
        ["ip", "route", "add", f"{FWD_ADDR_A}/32", "via", FWD_ADDR_R_B, "dev", VETH_B_R],
    )

    run_in_netns(vm, ROUTER_NS, ["sysctl", "-w", "net.ipv4.ip_forward=1"])
    run_in_netns(vm, ROUTER_NS, ["sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"])
    run_in_netns(vm, ROUTER_NS, ["sysctl", "-w", f"net.ipv4.conf.{VETH_R_A}.rp_filter=0"])
    run_in_netns(vm, ROUTER_NS, ["sysctl", "-w", f"net.ipv4.conf.{VETH_R_B}.rp_filter=0"])


def test_forwarded_fake_tcp_is_not_owned_in_prerouting(phantun_module, vm):
    phantun_module.load(managed_local_ports=str(PORTS_B[0]))
    ensure_forwarding_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_forwarding_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = 6000
    dst_port = PORTS_B[0]
    router_pre = make_netns_prerouting_flag_drop_probe(
        vm,
        ROUTER_NS,
        [
            {
                "src_addr": FWD_ADDR_A,
                "src_port": src_port,
                "dst_addr": FWD_ADDR_B,
                "dst_port": dst_port,
                "flags_expr": "syn",
                "comment": "forwarded_syn_seen",
                "action": "accept",
            }
        ],
    )
    router_synack = make_netns_output_flag_probe(
        vm,
        ROUTER_NS,
        [
            {
                "src_addr": FWD_ADDR_B,
                "dst_addr": FWD_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "syn | ack",
                "comment": "router_synack",
            }
        ],
    )
    dst_capture = spawn_ready_capture(
        vm,
        NS_B,
        {
            "bind_addr": FWD_ADDR_A,
            "bind_port": src_port,
            "target_addr": FWD_ADDR_B,
            "target_port": dst_port,
            "payload": "",
            "timeout_sec": 10,
        },
    )

    try:
        run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": FWD_ADDR_A,
                "bind_port": src_port,
                "target_addr": FWD_ADDR_B,
                "target_port": dst_port,
                "flags": "syn",
                "seq": 4095,
            },
        )
        time.sleep(0.5)
        capture_result = dst_capture.communicate(timeout=10)

        if router_pre.packets(vm, "forwarded_syn_seen") == 0:
            pytest.fail("forwarded SYN never reached router PRE_ROUTING in the test topology")
        if router_synack.packets(vm, "router_synack") != 0:
            pytest.fail("router namespace must not own or answer forwarded fake-TCP SYN traffic")
        assert_completed(capture_result, "destination forwarded SYN capture")
    finally:
        router_pre.cleanup(vm)
        router_synack.cleanup(vm)
        cleanup_forwarding_topology(vm)


def test_established_invalid_syn_destroys_flow(phantun_module, vm):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]

    invalid_probe = make_netns_output_flag_probe(
        vm,
        NS_B,
        [
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "rst | ack",
                "comment": "invalid_rst",
            },
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "syn | ack",
                "comment": "invalid_synack",
            },
        ],
    )
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "echo_server",
        {"bind_addr": NS_ADDR_B, "bind_port": dst_port, "count": 2, "timeout_sec": 20},
    )

    try:
        time.sleep(0.2)
        res1 = run_netns_scenario(
            vm,
            NS_A,
            "echo_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["msg1"],
            },
        )
        assert_completed(res1, "initial echo client")

        baseline_invalid_rst = invalid_probe.packets(vm, "invalid_rst")
        baseline_invalid_synack = invalid_probe.packets(vm, "invalid_synack")

        run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": "syn|ack",
                "seq": 12345,
                "ack": 1,
            },
        )
        time.sleep(0.2)

        if invalid_probe.packets(vm, "invalid_rst") <= baseline_invalid_rst:
            pytest.fail("expected RST|ACK in response to invalid established SYN packet")
        if invalid_probe.packets(vm, "invalid_synack") != baseline_invalid_synack:
            pytest.fail("invalid established SYN packet must not be accepted as replacement")

        res2 = run_netns_scenario(
            vm,
            NS_A,
            "echo_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["msg2"],
                "timeout_sec": 15,
            },
        )
        assert_completed(res2, "echo client after invalid SYN")
        data = parse_guest_json(res2.stdout, "echo client")
        if data.get("echoed") != ["msg2"]:
            pytest.fail(f"failed to recover after invalid SYN: {data.get('echoed')!r}")
    finally:
        invalid_probe.cleanup(vm)


def test_bad_final_ack_payload_is_rejected_with_rstack(phantun_module, vm):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    drop_synack = make_netns_ingress_flag_drop_probe(
        vm,
        NS_A,
        VETH_A,
        [
            {
                "src_addr": NS_ADDR_B,
                "src_port": dst_port,
                "dst_addr": NS_ADDR_A,
                "dst_port": src_port,
                "flags_expr": "syn | ack",
                "comment": "drop_half_open_synack",
            }
        ],
    )
    invalid_probe = make_netns_output_flag_probe(
        vm,
        NS_B,
        [
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "rst | ack",
                "comment": "bad_final_rst",
            }
        ],
    )

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
        time.sleep(0.2)
        baseline_bad_final_rst = invalid_probe.packets(vm, "bad_final_rst")

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
                "ack": 0,
                "payload": "junk",
            },
        )
        time.sleep(0.2)

        if invalid_probe.packets(vm, "bad_final_rst") <= baseline_bad_final_rst:
            pytest.fail("expected RST|ACK for payload-bearing final ACK with wrong ack number")
    finally:
        drop_synack.cleanup(vm)
        invalid_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_fragmented_syn_is_rejected_without_creating_flow(phantun_module, vm):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
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
                "comment": "fragmented_syn_synack",
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
                "ip_frag_off": 0x2000,
            },
        )
        time.sleep(0.2)

        if synack_probe.packets(vm, "fragmented_syn_synack") != 0:
            pytest.fail("fragmented SYN must not elicit SYN|ACK")

        stats_after = read_module_stats(vm)
        if stats_after["flows_created"] != baseline_stats["flows_created"]:
            pytest.fail(f"fragmented SYN must not create flow state: before={baseline_stats!r} after={stats_after!r}")
    finally:
        synack_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_bad_tcp_checksum_syn_is_silently_dropped(phantun_module, vm):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS)
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
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS)
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


def test_unknown_synack_is_rejected_without_creating_flow(phantun_module, vm):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]

    invalid_probe = make_netns_output_flag_probe(
        vm,
        NS_B,
        [
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "rst | ack",
                "comment": "unknown_rst",
            },
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "syn | ack",
                "comment": "unknown_synack",
            },
        ],
    )

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
                "flags": "syn|ack",
                "seq": 12345,
                "ack": 1,
            },
        )
        time.sleep(0.2)

        if invalid_probe.packets(vm, "unknown_rst") == 0:
            pytest.fail("expected RST|ACK for unknown SYN|ACK opener")
        if invalid_probe.packets(vm, "unknown_synack") != 0:
            pytest.fail("unknown SYN|ACK must not create a responder half-open flow")
    finally:
        invalid_probe.cleanup(vm)

    server = spawn_netns_scenario(
        vm,
        NS_B,
        "echo_server",
        {"bind_addr": NS_ADDR_B, "bind_port": dst_port, "count": 1},
    )
    time.sleep(0.2)
    client = run_netns_scenario(
        vm,
        NS_A,
        "echo_client",
        {
            "bind_addr": NS_ADDR_A,
            "bind_port": src_port,
            "target_addr": NS_ADDR_B,
            "target_port": dst_port,
            "payloads": ["msg1"],
        },
    )
    server_result = server.communicate(timeout=10)
    assert_completed(client, "echo client after unknown synack")
    assert_completed(server_result, "echo server after unknown synack")
    server_data = parse_guest_json(server_result.stdout, "echo server stdout")
    if received_messages(server_data) != ["msg1"]:
        pytest.fail(f"unexpected server messages after unknown synack: {received_messages(server_data)!r}")


def test_unknown_ack_payload_is_rejected_with_rstack(phantun_module, vm):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    invalid_probe = make_netns_output_flag_probe(
        vm,
        NS_B,
        [
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "rst | ack",
                "comment": "unknown_ack_rst",
            }
        ],
    )

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
            },
        )
        time.sleep(0.2)
        if invalid_probe.packets(vm, "unknown_ack_rst") == 0:
            pytest.fail("expected RST|ACK for unknown non-RST fake-TCP packet")
    finally:
        invalid_probe.cleanup(vm)

    server = spawn_netns_scenario(
        vm,
        NS_B,
        "echo_server",
        {"bind_addr": NS_ADDR_B, "bind_port": dst_port, "count": 1},
    )
    time.sleep(0.2)
    client = run_netns_scenario(
        vm,
        NS_A,
        "echo_client",
        {
            "bind_addr": NS_ADDR_A,
            "bind_port": src_port,
            "target_addr": NS_ADDR_B,
            "target_port": dst_port,
            "payloads": ["msg1"],
        },
    )
    server_result = server.communicate(timeout=10)
    assert_completed(client, "echo client after unknown ack payload")
    assert_completed(server_result, "echo server after unknown ack payload")
    server_data = parse_guest_json(server_result.stdout, "echo server stdout")
    if received_messages(server_data) != ["msg1"]:
        pytest.fail(f"unexpected server messages after unknown ack payload: {received_messages(server_data)!r}")


def test_oversized_established_payload_is_rejected_and_counted(phantun_module, vm):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS)
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
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS)
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
