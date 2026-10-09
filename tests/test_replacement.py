"""Simultaneous-open collisions, generation replacement, replacement protection, quarantine, and retired records."""

import time
import uuid

import pytest

from helpers import (
    MANAGED_LOCAL_PORTS,
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
    load_fast_liveness_module,
    make_netns_ingress_flag_drop_probe,
    make_netns_output_flag_probe,
    make_netns_output_ipv4_pure_ack_probe,
    make_netns_tcp_payload_probe,
    netns_link_mac,
    parse_guest_json,
    read_module_stats,
    received_messages,
    require_guest_command,
    require_nft_or_skip,
    run_in_netns,
    run_netns_scenario,
    spawn_netns_scenario,
    spawn_ready_capture,
    wait_for_flows_current,
    wait_for_guest_ready_file,
    wait_for_stat_greater,
)


def wait_for_probe_packets_after(vm, probe, comment, baseline, label, timeout=5):
    deadline = time.time() + timeout
    last = baseline
    while time.time() < deadline:
        last = probe.packets(vm, comment)
        if last > baseline:
            return last
        time.sleep(0.1)
    pytest.fail(f"{label}: expected {comment} packets to increase beyond {baseline}, got {last}")


def sequence_distance(a, b):
    diff = (a - b) & 0xFFFFFFFF
    return diff if diff < 0x80000000 else 0x100000000 - diff


@pytest.mark.parametrize("saturate_remote", [False, True])
def test_syn_isn_tie_break(phantun_module, vm, saturate_remote):
    phantun_module.load(
        managed_netns="all",
        managed_local_ports=MANAGED_LOCAL_PORTS,
        half_open_limit=2 if saturate_remote else 4096,
        handshake_retries=100,
    )
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")
    if not require_guest_command(vm, "tc"):
        cleanup_netns_topology(vm)
        pytest.skip("tc is not available in the guest")

    initial_stats = read_module_stats(vm)
    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    admission_drops = []

    probe_a = make_netns_ingress_flag_drop_probe(
        vm,
        NS_A,
        VETH_A,
        [
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "syn",
                "comment": "drop syn",
            }
        ],
    )
    probe_b = make_netns_ingress_flag_drop_probe(
        vm,
        NS_B,
        VETH_B,
        [
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "flags_expr": "syn",
                "comment": "drop syn",
            }
        ],
    )

    # Add delay so retransmitted SYNs cross in flight, ensuring both evaluate the collision
    vm.run(["ip", "netns", "exec", NS_A, "tc", "qdisc", "add", "dev", VETH_A, "root", "netem", "delay", "150ms"])
    vm.run(["ip", "netns", "exec", NS_B, "tc", "qdisc", "add", "dev", VETH_B, "root", "netem", "delay", "150ms"])

    try:
        if saturate_remote:
            # Fill each namespace's sole remote-origin slot before either
            # local UDP open. Both ISN outcomes must retain local admission.
            for namespace, addr, port, peer_ns, peer_addr, peer_dev in [
                (NS_A, NS_ADDR_A, src_port, NS_B, NS_ADDR_B, VETH_B),
                (NS_B, NS_ADDR_B, dst_port, NS_A, NS_ADDR_A, VETH_A),
            ]:
                admission_drops.append(
                    make_netns_ingress_flag_drop_probe(
                        vm,
                        peer_ns,
                        peer_dev,
                        [
                            {
                                "src_addr": addr,
                                "dst_addr": peer_addr,
                                "src_port": port,
                                "dst_port": flood_port,
                                "flags_expr": "syn | ack",
                                "comment": f"hold_remote_{flood_port}",
                            }
                            for flood_port in (41001, 41002)
                        ],
                    )
                )
                run_netns_scenario(
                    vm,
                    peer_ns,
                    "send_tcp_packets",
                    {
                        "packets": [
                            {
                                "bind_addr": peer_addr,
                                "bind_port": flood_port,
                                "target_addr": addr,
                                "target_port": port,
                                "flags": "syn",
                                "seq": 4095,
                            }
                            for flood_port in (41001, 41002)
                        ]
                    },
                )
            saturated = wait_for_stat_greater(
                vm, "half_open_rejected", initial_stats["half_open_rejected"] + 1
            )
            assert saturated["flows_created"] - initial_stats["flows_created"] == 2
            assert saturated["flows_current"] - initial_stats["flows_current"] == 2
            assert saturated["half_open_rejected"] - initial_stats["half_open_rejected"] == 2
            initial_stats = saturated

        client_a = spawn_netns_scenario(
            vm,
            NS_A,
            "simultaneous_exchange",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payload": "pingA",
            },
        )
        client_b = spawn_netns_scenario(
            vm,
            NS_B,
            "simultaneous_exchange",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "target_addr": NS_ADDR_A,
                "target_port": src_port,
                "payload": "pingB",
            },
        )
        # Initial SYNs are dropped on both sides; wait past the 1s handshake
        # retransmit timeout so the first retry wave is in flight before we
        # stop dropping.
        time.sleep(1.25)
        probe_a.cleanup(vm)
        probe_b.cleanup(vm)

        res_a = client_a.communicate(timeout=15)
        res_b = client_b.communicate(timeout=15)
        assert_completed(res_a, "client A")
        assert_completed(res_b, "client B")

        data_a = parse_guest_json(res_a.stdout, "client A")
        data_b = parse_guest_json(res_b.stdout, "client B")
        if data_a.get("received") != "pingB":
            pytest.fail(f"client A unexpected reply: {data_a.get('received')!r}")
        if data_b.get("received") != "pingA":
            pytest.fail(f"client B unexpected reply: {data_b.get('received')!r}")

        final_stats = read_module_stats(vm)
        created_diff = final_stats["flows_created"] - initial_stats["flows_created"]
        lost_diff = final_stats["collisions_lost"] - initial_stats["collisions_lost"]

        if created_diff != 3:
            pytest.fail(
                f"expected three flow creations for simultaneous-open handoff, got {created_diff} (stats {final_stats!r})"
            )
        if lost_diff != 1:
            pytest.fail(f"expected exactly one collision loss, got {lost_diff} (stats {final_stats!r})")
        if saturate_remote:
            assert final_stats["half_open_rejected"] == initial_stats["half_open_rejected"]
            assert final_stats["collisions_won"] > initial_stats["collisions_won"]
            assert final_stats["flows_current"] - initial_stats["flows_current"] == 2

            # Completion releases exactly one local charge at each endpoint,
            # including the endpoint that is now a local-origin responder.
            # Keep the next open half-open and ensure a further open is refused.
            for namespace, addr, port, peer_ns, peer_addr, peer_dev in [
                (NS_A, NS_ADDR_A, src_port, NS_B, NS_ADDR_B, VETH_B),
                (NS_B, NS_ADDR_B, dst_port, NS_A, NS_ADDR_A, VETH_A),
            ]:
                admission_drops.append(
                    make_netns_ingress_flag_drop_probe(
                        vm,
                        peer_ns,
                        peer_dev,
                        [
                            {
                                "src_addr": addr,
                                "dst_addr": peer_addr,
                                "src_port": port,
                                "dst_port": remote_port,
                                "flags_expr": "syn",
                                "comment": f"hold_new_local_{remote_port}",
                            }
                            for remote_port in (6666, 6667)
                        ],
                    )
                )
                for remote_port in (6666, 6667):
                    run_netns_scenario(
                        vm,
                        namespace,
                        "send_many",
                        {
                            "bind_addr": addr,
                            "bind_port": port,
                            "target_addr": peer_addr,
                            "target_port": remote_port,
                            "payloads": ["next-local"],
                        },
                    )
            released = read_module_stats(vm)
            assert released["flows_created"] - final_stats["flows_created"] == 2
            assert released["flows_current"] - final_stats["flows_current"] == 2
            assert released["half_open_rejected"] - final_stats["half_open_rejected"] == 2
    finally:
        probe_a.cleanup(vm)
        probe_b.cleanup(vm)
        vm.run(["ip", "netns", "exec", NS_A, "tc", "qdisc", "del", "dev", VETH_A, "root", "netem"], check=False)
        vm.run(["ip", "netns", "exec", NS_B, "tc", "qdisc", "del", "dev", VETH_B, "root", "netem"], check=False)
        for probe in admission_drops:
            probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_established_bare_syn_replacement(phantun_module, vm):
    load_fast_liveness_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]

    replacement_syn = make_netns_output_flag_probe(
        vm,
        NS_A,
        [
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "flags_expr": "syn",
                "comment": "replacement_syn",
            }
        ],
    )
    replacement_synack = make_netns_output_flag_probe(
        vm,
        NS_B,
        [
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "syn | ack",
                "comment": "replacement_synack",
            }
        ],
    )
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "echo_server",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 2,
            # 4s sleep below for quarantine expiration requires higher socket timeout
            "timeout_sec": 20,
        },
    )

    try:
        time.sleep(0.2)
        client_result_1 = run_netns_scenario(
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
        assert_completed(client_result_1, "client send 1")

        baseline_syn = replacement_syn.packets(vm, "replacement_syn")
        baseline_synack = replacement_synack.packets(vm, "replacement_synack")

        vm.run(["ip", "netns", "exec", NS_B, "nft", "add", "table", "inet", "filter"])
        vm.run(
            [
                "ip",
                "netns",
                "exec",
                NS_B,
                "nft",
                "add",
                "chain",
                "inet",
                "filter",
                "output",
                "{ type filter hook output priority 10; policy accept; }",
            ]
        )
        vm.run(
            [
                "ip",
                "netns",
                "exec",
                NS_B,
                "nft",
                "add",
                "rule",
                "inet",
                "filter",
                "output",
                f"ip daddr {NS_ADDR_A} drop",
            ]
        )

        time.sleep(4)
        vm.run(["ip", "netns", "exec", NS_B, "nft", "delete", "table", "inet", "filter"])

        client_result_2 = run_netns_scenario(
            vm,
            NS_A,
            "echo_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["msg2"],
            },
        )
        assert_completed(client_result_2, "client send 2")

        if replacement_syn.packets(vm, "replacement_syn") <= baseline_syn:
            pytest.fail("expected replacement generation SYN from initiator")
        if replacement_synack.packets(vm, "replacement_synack") <= baseline_synack:
            pytest.fail("expected replacement generation SYN|ACK from responder")

        server_result = server.communicate(timeout=15)
        assert_completed(server_result, "server")
        server_data = parse_guest_json(server_result.stdout, "server stdout")
        if received_messages(server_data) != ["msg1", "msg2"]:
            pytest.fail(f"unexpected messages: {received_messages(server_data)!r}")
    finally:
        replacement_syn.cleanup(vm)
        replacement_synack.cleanup(vm)
        vm.run(
            ["ip", "netns", "exec", NS_B, "nft", "delete", "table", "inet", "filter"],
            check=False,
        )


def test_replacement_protect_suppresses_initiator_bare_syn_then_expires(phantun_module, vm):
    protect_ms = 3000
    phantun_module.load(
        managed_netns="all",
        managed_local_ports=MANAGED_LOCAL_PORTS,
        keepalive_interval_sec=60,
        keepalive_misses=2,
        handshake_retries=20,
        replacement_protect_ms=protect_ms,
    )
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    response_probe = make_netns_output_flag_probe(
        vm,
        NS_A,
        [
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "flags_expr": "syn | ack",
                "comment": "protect_synack",
            },
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "flags_expr": "rst",
                "comment": "protect_rst",
            },
        ],
    )
    server_ready_file = f"/tmp/phantun-replacement-protect-{uuid.uuid4().hex}"
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "echo_server",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 2,
            "timeout_sec": 20,
            "ready_file": server_ready_file,
        },
    )

    try:
        wait_for_guest_ready_file(vm, server_ready_file)
        client_result_1 = run_netns_scenario(
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
        assert_completed(client_result_1, "client send 1")

        baseline_synack = response_probe.packets(vm, "protect_synack")
        baseline_rst = response_probe.packets(vm, "protect_rst")
        baseline_stats = read_module_stats(vm)
        stale_syn = run_netns_scenario(
            vm,
            NS_B,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "target_addr": NS_ADDR_A,
                "target_port": src_port,
                "seq": 4095 * 1001,
                "flags": "syn",
            },
        )
        assert_completed(stale_syn, "inject protected stale SYN")
        time.sleep(0.5)

        if response_probe.packets(vm, "protect_synack") != baseline_synack:
            pytest.fail("protected established-initiator bare SYN should not emit SYN|ACK")
        if response_probe.packets(vm, "protect_rst") != baseline_rst:
            pytest.fail("protected established-initiator bare SYN should not emit RST")
        stats = read_module_stats(vm)
        if stats["replacement_protect_dropped"] <= baseline_stats["replacement_protect_dropped"]:
            pytest.fail(f"expected replacement_protect_dropped to increase, got {stats!r}")

        client_result_2 = run_netns_scenario(
            vm,
            NS_A,
            "echo_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["msg2"],
            },
        )
        assert_completed(client_result_2, "client send 2 after protected SYN")
        client_data_2 = parse_guest_json(client_result_2.stdout, "client send 2 stdout")
        if client_data_2.get("echoed") != ["msg2"]:
            pytest.fail(f"protected stale SYN disrupted established flow: {client_data_2!r}")

        time.sleep((protect_ms / 1000) + 0.5)
        baseline_expired_synack = response_probe.packets(vm, "protect_synack")
        replacement_baseline_stats = read_module_stats(vm)
        expired_syn = run_netns_scenario(
            vm,
            NS_B,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "target_addr": NS_ADDR_A,
                "target_port": src_port,
                "seq": 4095 * 1002,
                "flags": "syn",
            },
        )
        assert_completed(expired_syn, "inject expired-window SYN")
        wait_for_probe_packets_after(
            vm,
            response_probe,
            "protect_synack",
            baseline_expired_synack,
            "expired replacement protection",
        )
        replacement_stats = read_module_stats(vm)
        if replacement_stats["replacements_accepted"] <= replacement_baseline_stats["replacements_accepted"]:
            pytest.fail(f"expected replacements_accepted to increase, got {replacement_stats!r}")

        server_result = server.communicate(timeout=15)
        assert_completed(server_result, "server")
        server_data = parse_guest_json(server_result.stdout, "server stdout")
        if received_messages(server_data) != ["msg1", "msg2"]:
            pytest.fail(f"unexpected messages after protected stale SYN: {received_messages(server_data)!r}")
    finally:
        response_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_established_duplicate_current_generation_syn_dispatch(phantun_module, vm):
    phantun_module.load(managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS, keepalive_interval_sec=60)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    syn_ready = f"/tmp/phantun-capture-syn-{uuid.uuid4().hex}"
    synack_ready = f"/tmp/phantun-capture-synack-{uuid.uuid4().hex}"
    server_ready = f"/tmp/phantun-duplicate-syn-server-{uuid.uuid4().hex}"
    capture_syn = spawn_netns_scenario(
        vm,
        NS_B,
        "capture_tcp_packet",
        {
            "bind_addr": NS_ADDR_A,
            "bind_port": src_port,
            "target_addr": NS_ADDR_B,
            "target_port": dst_port,
            "ready_file": syn_ready,
            "timeout_sec": 10,
        },
    )
    capture_synack = spawn_netns_scenario(
        vm,
        NS_A,
        "capture_tcp_packet",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "target_addr": NS_ADDR_A,
            "target_port": src_port,
            "ready_file": synack_ready,
            "timeout_sec": 10,
        },
    )
    initiator_probe = make_netns_output_flag_probe(
        vm,
        NS_A,
        [
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "flags_expr": "ack",
                "comment": "dup_synack_ack",
            },
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "flags_expr": "rst",
                "comment": "dup_synack_rst",
            },
        ],
    )
    responder_probe = make_netns_output_flag_probe(
        vm,
        NS_B,
        [
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "syn | ack",
                "comment": "dup_syn_synack",
            },
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "rst",
                "comment": "dup_syn_rst",
            },
        ],
    )
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "echo_server",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 1,
            "timeout_sec": 10,
            "ready_file": server_ready,
        },
    )

    try:
        wait_for_guest_ready_file(vm, syn_ready, timeout=5)
        wait_for_guest_ready_file(vm, synack_ready, timeout=5)
        wait_for_guest_ready_file(vm, server_ready, timeout=5)
        client_result = run_netns_scenario(
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
        assert_completed(client_result, "client send")
        server_result = server.communicate(timeout=10)
        assert_completed(server_result, "server")

        syn_result = capture_syn.communicate(timeout=10)
        synack_result = capture_synack.communicate(timeout=10)
        assert_completed(syn_result, "capture opening SYN")
        assert_completed(synack_result, "capture opening SYN|ACK")
        syn_data = parse_guest_json(syn_result.stdout, "opening SYN")
        synack_data = parse_guest_json(synack_result.stdout, "opening SYN|ACK")
        if syn_data.get("flags") != 0x02:
            pytest.fail(f"expected captured opening SYN, got {syn_data!r}")
        if synack_data.get("flags") != 0x12:
            pytest.fail(f"expected captured opening SYN|ACK, got {synack_data!r}")

        baseline_ack = initiator_probe.packets(vm, "dup_synack_ack")
        baseline_initiator_rst = initiator_probe.packets(vm, "dup_synack_rst")
        baseline_stats = read_module_stats(vm)
        duplicate_synack = run_netns_scenario(
            vm,
            NS_B,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "target_addr": NS_ADDR_A,
                "target_port": src_port,
                "seq": synack_data["seq"],
                "ack": synack_data["ack"],
                "flags": "syn|ack",
            },
        )
        assert_completed(duplicate_synack, "inject duplicate SYN|ACK")
        wait_for_probe_packets_after(
            vm,
            initiator_probe,
            "dup_synack_ack",
            baseline_ack,
            "duplicate current-generation SYN|ACK",
        )
        if initiator_probe.packets(vm, "dup_synack_rst") != baseline_initiator_rst:
            pytest.fail("duplicate current-generation SYN|ACK should not emit RST")
        if read_module_stats(vm)["flows_created"] != baseline_stats["flows_created"]:
            pytest.fail("duplicate current-generation SYN|ACK should not replace the flow")

        baseline_synack = responder_probe.packets(vm, "dup_syn_synack")
        baseline_responder_rst = responder_probe.packets(vm, "dup_syn_rst")
        baseline_stats = read_module_stats(vm)
        duplicate_syn = run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "seq": syn_data["seq"],
                "flags": "syn",
            },
        )
        assert_completed(duplicate_syn, "inject duplicate SYN")
        wait_for_probe_packets_after(
            vm,
            responder_probe,
            "dup_syn_synack",
            baseline_synack,
            "duplicate current-generation SYN",
        )
        if responder_probe.packets(vm, "dup_syn_rst") != baseline_responder_rst:
            pytest.fail("duplicate current-generation SYN should not emit RST")
        if read_module_stats(vm)["flows_created"] != baseline_stats["flows_created"]:
            pytest.fail("duplicate current-generation SYN should not replace the flow")
    finally:
        for process in (server, capture_syn, capture_synack):
            process.terminate()
        vm.run(["rm", "-f", syn_ready, synack_ready, server_ready], check=False)
        initiator_probe.cleanup(vm)
        responder_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_duplicate_synack_during_completion_does_not_rewind_sequence(phantun_module, vm):
    phantun_module.load(
        managed_netns="all",
        managed_local_ports=MANAGED_LOCAL_PORTS,
        keepalive_interval_sec=60,
        handshake_timeout_ms=800,
        handshake_retries=20,
    )
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    payloads = ["race1", "race2", "race3", "race4"]
    remaining_payloads = payloads[1:]
    synack_ready = f"/tmp/phantun-capture-synack-race-{uuid.uuid4().hex}"
    server_ready = f"/tmp/phantun-echo-synack-race-{uuid.uuid4().hex}"
    capture_synack = spawn_netns_scenario(
        vm,
        NS_A,
        "capture_tcp_packet",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "target_addr": NS_ADDR_A,
            "target_port": src_port,
            "ready_file": synack_ready,
            "timeout_sec": 15,
        },
    )
    ack_probe = make_netns_output_ipv4_pure_ack_probe(vm, NS_A, NS_ADDR_A, src_port, NS_ADDR_B, dst_port)
    rst_probe = make_netns_output_flag_probe(
        vm,
        NS_A,
        [
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "flags_expr": "rst",
                "comment": "duplicate_completion_synack_rst",
            },
        ],
    )
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "echo_server",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": len(payloads),
            "timeout_sec": 20,
            "ready_file": server_ready,
        },
    )

    try:
        wait_for_guest_ready_file(vm, synack_ready, timeout=5)
        wait_for_guest_ready_file(vm, server_ready, timeout=10)
        baseline_stats = read_module_stats(vm)

        first_client = run_netns_scenario(
            vm,
            NS_A,
            "echo_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": [payloads[0]],
                "timeout_sec": 20,
            },
        )
        assert_completed(first_client, "first echo before duplicate SYN|ACK")
        first_data = parse_guest_json(first_client.stdout, "first echo stdout")
        if first_data.get("echoed") != [payloads[0]]:
            pytest.fail(f"unexpected first echo before duplicate SYN|ACK: {first_data!r}")

        synack_result = capture_synack.communicate(timeout=20)
        assert_completed(synack_result, "capture opening SYN|ACK")
        synack_data = parse_guest_json(synack_result.stdout, "opening SYN|ACK")
        if synack_data.get("flags") != 0x12:
            pytest.fail(f"expected captured opening SYN|ACK, got {synack_data!r}")

        baseline_ack = ack_probe.packets(vm, "pure_ipv4_ack")
        baseline_rst = rst_probe.packets(vm, "duplicate_completion_synack_rst")
        duplicate_baseline = read_module_stats(vm)
        for _ in range(5):
            duplicate = run_netns_scenario(
                vm,
                NS_B,
                "send_tcp_packet",
                {
                    "bind_addr": NS_ADDR_B,
                    "bind_port": dst_port,
                    "target_addr": NS_ADDR_A,
                    "target_port": src_port,
                    "seq": synack_data["seq"],
                    "ack": synack_data["ack"],
                    "flags": "syn|ack",
                },
            )
            assert_completed(duplicate, "inject duplicate SYN|ACK after establishment")

        wait_for_probe_packets_after(
            vm,
            ack_probe,
            "pure_ipv4_ack",
            baseline_ack,
            "duplicate SYN|ACK completion ACK",
        )
        if rst_probe.packets(vm, "duplicate_completion_synack_rst") != baseline_rst:
            pytest.fail("duplicate SYN|ACK should not emit RST")
        if read_module_stats(vm)["flows_created"] != duplicate_baseline["flows_created"]:
            pytest.fail("duplicate SYN|ACK should not create another flow")

        next_client = run_netns_scenario(
            vm,
            NS_A,
            "echo_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": remaining_payloads,
                "timeout_sec": 20,
            },
        )
        assert_completed(next_client, "echo after duplicate SYN|ACK")
        next_data = parse_guest_json(next_client.stdout, "post-duplicate echo stdout")
        if next_data.get("echoed") != remaining_payloads:
            pytest.fail(f"unexpected echoed payloads after duplicate SYN|ACKs: {next_data!r}")

        server_result = server.communicate(timeout=30)
        assert_completed(server_result, "duplicate SYN|ACK completion server")
        server_data = parse_guest_json(server_result.stdout, "duplicate SYN|ACK completion server stdout")
        if received_messages(server_data) != payloads:
            pytest.fail(f"unexpected server payloads after duplicate SYN|ACKs: {server_data!r}")

        stats = read_module_stats(vm)
        if stats["flows_established"] != baseline_stats["flows_established"] + 2:
            pytest.fail(f"expected both endpoint flows to establish, before={baseline_stats!r} after={stats!r}")
    finally:
        ack_probe.cleanup(vm)
        rst_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_established_syn_fin_is_not_accepted_as_replacement(phantun_module, vm):
    phantun_module.load(managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS)
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
                "comment": "est_syn_fin_rst",
            },
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "syn | ack",
                "comment": "est_syn_fin_synack",
            },
        ],
    )
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "echo_server",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 2,
            "timeout_sec": 20,
        },
    )

    try:
        time.sleep(0.2)
        first = run_netns_scenario(
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
        assert_completed(first, "established baseline echo")
        baseline_rst = invalid_probe.packets(vm, "est_syn_fin_rst")
        baseline_synack = invalid_probe.packets(vm, "est_syn_fin_synack")

        run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": "syn|fin",
                "seq": 4095,
            },
        )
        time.sleep(0.2)

        if invalid_probe.packets(vm, "est_syn_fin_synack") != baseline_synack:
            pytest.fail("SYN|FIN must not be accepted as an established replacement SYN")
        if invalid_probe.packets(vm, "est_syn_fin_rst") <= baseline_rst:
            pytest.fail("SYN|FIN on established flow should be rejected with RST|ACK")
    finally:
        invalid_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_established_invalid_syn_destroys_flow(phantun_module, vm):
    reopen_guard_bytes = 1_000_000_000
    phantun_module.load(
        managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS, reopen_guard_bytes=reopen_guard_bytes
    )
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

    baseline_stats = read_module_stats(vm)

    try:
        time.sleep(0.2)
        initial_syn_capture = spawn_ready_capture(
            vm,
            NS_B,
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payload": "",
                "timeout_sec": 10,
            },
        )
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
        initial_syn_result = initial_syn_capture.communicate(timeout=10)
        assert_completed(initial_syn_result, "initial SYN capture")
        initial_syn = parse_guest_json(initial_syn_result.stdout, "initial SYN capture stdout")
        if initial_syn["flags"] & 0x02 == 0:
            pytest.fail(f"expected initial opener to be a SYN: {initial_syn!r}")

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
        stats_after_teardown = wait_for_flows_current(vm, baseline_stats["flows_current"], timeout=5)
        if stats_after_teardown["flows_current"] != baseline_stats["flows_current"]:
            pytest.fail(
                f"terminal teardown should return flows_current to baseline: "
                f"before={baseline_stats!r} after={stats_after_teardown!r}"
            )

        reopen_syn_capture = spawn_ready_capture(
            vm,
            NS_B,
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payload": "",
                "timeout_sec": 10,
            },
        )

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
        reopen_syn_result = reopen_syn_capture.communicate(timeout=10)
        assert_completed(reopen_syn_result, "reopen SYN capture")
        reopen_syn = parse_guest_json(reopen_syn_result.stdout, "reopen SYN capture stdout")
        if reopen_syn["flags"] & 0x02 == 0:
            pytest.fail(f"expected reopen opener to be a SYN: {reopen_syn!r}")

        previous_seq = (initial_syn["seq"] + 1 + len("msg1")) & 0xFFFFFFFF
        if sequence_distance(reopen_syn["seq"], previous_seq) < reopen_guard_bytes:
            pytest.fail(
                f"reopen SYN sequence did not honor guard: initial={initial_syn!r} "
                f"reopen={reopen_syn!r} previous_seq={previous_seq}"
            )
        data = parse_guest_json(res2.stdout, "echo client")
        if data.get("echoed") != ["msg2"]:
            pytest.fail(f"failed to recover after invalid SYN: {data.get('echoed')!r}")
    finally:
        invalid_probe.cleanup(vm)


def test_replacement_quarantine_drops_delayed_old_generation_packet(phantun_module, vm):
    load_fast_liveness_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    captured_packet = spawn_netns_scenario(
        vm,
        NS_B,
        "capture_tcp_packet",
        {
            "bind_addr": NS_ADDR_A,
            "bind_port": src_port,
            "target_addr": NS_ADDR_B,
            "target_port": dst_port,
            "payload": "msg1",
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
                "flags_expr": "rst",
                "comment": "quarantine_rst",
            }
        ],
    )
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "echo_server",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 2,
            # 4s sleep below for quarantine expiration requires higher socket timeout
            "timeout_sec": 20,
        },
    )

    try:
        time.sleep(0.2)
        client_result_1 = run_netns_scenario(
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
        assert_completed(client_result_1, "client send 1")

        captured_result = captured_packet.communicate(timeout=10)
        assert_completed(captured_result, "capture old generation packet")
        captured_data = parse_guest_json(captured_result.stdout, "captured old packet")
        baseline_rst = rst_probe.packets(vm, "quarantine_rst")

        vm.run(["ip", "netns", "exec", NS_B, "nft", "add", "table", "inet", "filter"])
        vm.run(
            [
                "ip",
                "netns",
                "exec",
                NS_B,
                "nft",
                "add",
                "chain",
                "inet",
                "filter",
                "output",
                "{ type filter hook output priority 10; policy accept; }",
            ]
        )
        vm.run(
            [
                "ip",
                "netns",
                "exec",
                NS_B,
                "nft",
                "add",
                "rule",
                "inet",
                "filter",
                "output",
                f"ip daddr {NS_ADDR_A} drop",
            ]
        )
        time.sleep(4)
        vm.run(["ip", "netns", "exec", NS_B, "nft", "delete", "table", "inet", "filter"])

        client_result_2 = spawn_netns_scenario(
            vm,
            NS_A,
            "echo_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["msg2"],
            },
        )
        time.sleep(0.3)
        stale_packet = run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "seq": captured_data["seq"],
                "ack": captured_data["ack"],
                "flags": "ack",
                "payload": captured_data["payload"],
            },
        )
        assert_completed(stale_packet, "inject stale packet")
        client_result_2 = client_result_2.communicate(timeout=15)
        assert_completed(client_result_2, "client send 2")
        client_data = parse_guest_json(client_result_2.stdout, "client send 2 stdout")
        if client_data.get("echoed") != ["msg2"]:
            pytest.fail(f"stale packet escaped quarantine and confused the client: {client_data!r}")

        server_result = server.communicate(timeout=15)
        assert_completed(server_result, "server")
        server_data = parse_guest_json(server_result.stdout, "server stdout")
        if received_messages(server_data) != ["msg1", "msg2"]:
            pytest.fail(f"stale packet escaped quarantine and reached UDP delivery: {received_messages(server_data)!r}")
        if rst_probe.packets(vm, "quarantine_rst") != baseline_rst:
            pytest.fail("stale old-generation packet should be dropped without emitting RST")
    finally:
        rst_probe.cleanup(vm)
        vm.run(
            ["ip", "netns", "exec", NS_B, "nft", "delete", "table", "inet", "filter"],
            check=False,
        )
        cleanup_netns_topology(vm)


def test_replacement_quarantine_drops_half_space_old_generation_packet(phantun_module, vm):
    phantun_module.load(
        managed_netns="all",
        managed_local_ports=MANAGED_LOCAL_PORTS,
        keepalive_interval_sec=30,
        keepalive_misses=2,
        handshake_retries=20,
    )
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    captured_packet = spawn_netns_scenario(
        vm,
        NS_B,
        "capture_tcp_packet",
        {
            "bind_addr": NS_ADDR_A,
            "bind_port": src_port,
            "target_addr": NS_ADDR_B,
            "target_port": dst_port,
            "payload": "msg1",
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
                "flags_expr": "rst",
                "comment": "half_space_quarantine_rst",
            }
        ],
    )
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "echo_server",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 1,
            "timeout_sec": 15,
        },
    )
    synack_drop_probe = None

    try:
        time.sleep(0.2)
        client_result = run_netns_scenario(
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
        assert_completed(client_result, "client send initial packet")

        captured_result = captured_packet.communicate(timeout=10)
        assert_completed(captured_result, "capture old generation packet")
        captured_data = parse_guest_json(captured_result.stdout, "captured old packet")
        server_result = server.communicate(timeout=15)
        assert_completed(server_result, "server")
        server_data = parse_guest_json(server_result.stdout, "server stdout")
        if received_messages(server_data) != ["msg1"]:
            pytest.fail(f"initial packet did not reach UDP server: {received_messages(server_data)!r}")

        high_seq_1 = (captured_data["seq"] + 0x70000000) & 0xFFFFFFFF
        high_seq_2 = (high_seq_1 + 0x70000000) & 0xFFFFFFFF
        for label, seq, payload in (
            ("advance old generation seq window 1", high_seq_1, "jump1"),
            ("advance old generation seq window 2", high_seq_2, "jump2"),
        ):
            advanced = run_netns_scenario(
                vm,
                NS_A,
                "send_tcp_packet",
                {
                    "bind_addr": NS_ADDR_A,
                    "bind_port": src_port,
                    "target_addr": NS_ADDR_B,
                    "target_port": dst_port,
                    "seq": seq,
                    "ack": captured_data["ack"],
                    "flags": "ack",
                    "payload": payload,
                },
            )
            assert_completed(advanced, label)
        time.sleep(0.2)

        synack_drop_probe = make_netns_ingress_flag_drop_probe(
            vm,
            NS_A,
            VETH_A,
            [
                {
                    "src_addr": NS_ADDR_B,
                    "dst_addr": NS_ADDR_A,
                    "src_port": dst_port,
                    "dst_port": src_port,
                    "flags_expr": "syn | ack",
                    "comment": "half_space_quarantine_synack",
                }
            ],
        )

        baseline_stats = read_module_stats(vm)
        baseline_rst = rst_probe.packets(vm, "half_space_quarantine_rst")
        replacement_syn = run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "seq": 4095 * 17,
                "ack": 0,
                "flags": "syn",
            },
        )
        assert_completed(replacement_syn, "inject replacement SYN")

        deadline = time.time() + 5
        replacement_stats = baseline_stats
        while time.time() < deadline:
            replacement_stats = read_module_stats(vm)
            if replacement_stats["replacements_accepted"] > baseline_stats["replacements_accepted"]:
                break
            time.sleep(0.1)
        else:
            pytest.fail(f"expected replacement SYN to be accepted, got {replacement_stats!r}")

        quarantine_baseline = replacement_stats["replacement_quarantine_dropped"]
        stale_packet = run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "seq": high_seq_2,
                "ack": captured_data["ack"],
                "flags": "ack",
                "payload": "stale",
            },
        )
        assert_completed(stale_packet, "inject stale high-sequence packet")

        deadline = time.time() + 5
        final_stats = replacement_stats
        while time.time() < deadline:
            final_stats = read_module_stats(vm)
            if final_stats["replacement_quarantine_dropped"] > quarantine_baseline:
                break
            time.sleep(0.1)
        else:
            pytest.fail(f"expected stale high-sequence packet to hit quarantine, got {final_stats!r}")

        if rst_probe.packets(vm, "half_space_quarantine_rst") != baseline_rst:
            pytest.fail("stale high-sequence old-generation packet should not emit RST")
    finally:
        rst_probe.cleanup(vm)
        if synack_drop_probe is not None:
            synack_drop_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_retired_record_cache_evicts_under_tuple_churn(phantun_module, vm):
    alias_base = "10.210.0.1"
    alias_route = "10.210.0.0/20"
    churn_count = 2049
    payload = "post-retired-churn"
    server = None

    phantun_module.load(
        managed_netns="all",
        managed_local_ports=MANAGED_LOCAL_PORTS,
        hard_idle_timeout_sec=600,
        keepalive_interval_sec=60,
    )
    ensure_netns_topology(vm)

    try:
        run_netns_scenario(
            vm,
            NS_A,
            "configure_ipv4_aliases",
            {
                "device": VETH_A,
                "base_addr": alias_base,
                "count": churn_count,
                "action": "del",
            },
            check=False,
        )
        run_netns_scenario(
            vm,
            NS_A,
            "configure_ipv4_aliases",
            {
                "device": VETH_A,
                "base_addr": alias_base,
                "count": churn_count,
                "action": "add",
            },
        )
        run_in_netns(vm, NS_B, ["ip", "route", "replace", alias_route, "dev", VETH_B])

        mac_a = netns_link_mac(vm, NS_A, VETH_A)
        baseline_stats = read_module_stats(vm)
        churn = run_netns_scenario(
            vm,
            NS_B,
            "churn_retired_records",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": 61000,
                "target_base_addr": alias_base,
                "target_ports": [PORTS_A[0]],
                "count": churn_count,
                "device": VETH_B,
                "dst_mac": mac_a,
            },
        )
        assert_completed(churn, "retired-record churn")

        wait_for_stat_greater(
            vm,
            "retired_evicted",
            baseline_stats["retired_evicted"],
            timeout=10,
        )
        wait_for_flows_current(vm, baseline_stats["flows_current"], timeout=10)
        mac_b = netns_link_mac(vm, NS_B, VETH_B)
        run_in_netns(
            vm,
            NS_A,
            ["ip", "neigh", "replace", NS_ADDR_B, "lladdr", mac_b, "dev", VETH_A, "nud", "permanent"],
        )
        run_in_netns(
            vm,
            NS_B,
            ["ip", "neigh", "replace", NS_ADDR_A, "lladdr", mac_a, "dev", VETH_B, "nud", "permanent"],
        )
        run_in_netns(vm, NS_B, ["ip", "route", "del", alias_route, "dev", VETH_B], check=False)
        run_netns_scenario(
            vm,
            NS_A,
            "configure_ipv4_aliases",
            {
                "device": VETH_A,
                "base_addr": alias_base,
                "count": churn_count,
                "action": "del",
            },
            check=False,
        )
        time.sleep(3.0)

        server = spawn_netns_scenario(
            vm,
            NS_B,
            "echo_server",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": PORTS_B[1],
                "count": 1,
                "timeout_sec": 30,
            },
        )
        time.sleep(0.2)
        client = run_netns_scenario(
            vm,
            NS_A,
            "echo_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": PORTS_A[1],
                "target_addr": NS_ADDR_B,
                "target_port": PORTS_B[1],
                "timeout_sec": 30,
                "payloads": [payload],
            },
            check=False,
        )
        if client.returncode != 0:
            pytest.fail(f"post-churn echo client failed: stderr={client.stderr!r} stats={read_module_stats(vm)!r}")
        client_data = parse_guest_json(client.stdout, "post-churn echo stdout")
        if client_data.get("echoed") != [payload]:
            pytest.fail(f"post-churn echo failed: {client_data!r}")

        server_result = server.communicate(timeout=10)
        assert_completed(server_result, "post-churn echo server")
        server_data = parse_guest_json(server_result.stdout, "post-churn server stdout")
        if received_messages(server_data) != [payload]:
            pytest.fail(f"unexpected post-churn server messages: {server_data!r}")
    finally:
        if server is not None and server.proc.poll() is None:
            server.terminate()
        run_in_netns(vm, NS_B, ["ip", "route", "del", alias_route, "dev", VETH_B], check=False)
        run_netns_scenario(
            vm,
            NS_A,
            "configure_ipv4_aliases",
            {
                "device": VETH_A,
                "base_addr": alias_base,
                "count": churn_count,
                "action": "del",
            },
            check=False,
        )
        cleanup_netns_topology(vm)


@pytest.mark.parametrize("limit, remote_limit", [(1, 1), (4, 3)])
def test_half_open_replacement_keeps_queue_and_admission(phantun_module, vm, limit, remote_limit):
    phantun_module.load(
        managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS,
        half_open_limit=limit, handshake_timeout_ms=1000, handshake_retries=120,
        replacement_quarantine_ms=60000,
    )
    ensure_netns_topology(vm)
    require_nft_or_skip(vm)
    src_port, dst_port = PORTS_A[0], PORTS_B[0]
    source_ports = [src_port, 41001, 41002, 41003]
    drop = make_netns_ingress_flag_drop_probe(
        vm, NS_A, VETH_A,
        [
            {
                "src_addr": NS_ADDR_B, "src_port": dst_port,
                "dst_addr": NS_ADDR_A, "dst_port": port,
                "flags_expr": flags, "comment": f"raw_peer_{port}_{index}",
            }
            for port in source_ports
            for index, flags in enumerate(("syn | ack", "ack", "rst", "rst | ack"))
        ],
    )
    payload_probe = make_netns_tcp_payload_probe(
        vm, NS_B,
        [{
            "src_addr": NS_ADDR_B, "src_port": dst_port,
            "dst_addr": NS_ADDR_A, "dst_port": src_port,
            "payload": "saved-queue", "comment": "replacement_queue",
        }],
    )
    packet = {
        "bind_addr": NS_ADDR_A, "bind_port": src_port,
        "target_addr": NS_ADDR_B, "target_port": dst_port,
    }

    def capture_synack(seq):
        return spawn_ready_capture(
            vm, NS_B,
            {
                "bind_addr": NS_ADDR_B, "bind_port": dst_port,
                "target_addr": NS_ADDR_A, "target_port": src_port,
                "payload": "", "flags": "syn|ack", "ack": seq + 1, "timeout_sec": 15,
                "include_outgoing": True,
            },
        )

    def inject(**fields):
        result = run_netns_scenario(vm, NS_A, "send_tcp_packet", {**packet, **fields})
        assert_completed(result, "half-open replacement packet")

    def finish_capture(capture):
        result = capture.communicate(timeout=15)
        assert_completed(result, "replacement SYNACK capture")
        return parse_guest_json(result.stdout, "replacement SYNACK")

    baseline = read_module_stats(vm)
    try:
        capture = capture_synack(4095)
        inject(flags="syn", seq=4095)
        old = finish_capture(capture)
        for port in source_ports[1:remote_limit]:
            inject(bind_port=port, flags="syn", seq=4095)
        queued = run_netns_scenario(
            vm, NS_B, "send_many",
            {
                "bind_addr": NS_ADDR_B, "bind_port": dst_port,
                "target_addr": NS_ADDR_A, "target_port": src_port,
                "payloads": ["saved-queue"], "mark": 73, "ipv4_tos": 40,
            },
        )
        assert_completed(queued, "queue before half-open replacement")
        held = read_module_stats(vm)
        assert held["flows_current"] == baseline["flows_current"] + remote_limit
        assert held["udp_packets_queued"] == baseline["udp_packets_queued"] + 1

        capture = capture_synack(8190)
        # A callback emitting outside its lock may defer replacement with
        # -EAGAIN; retransmit this opener as a real peer would.
        retried = run_netns_scenario(
            vm, NS_A, "send_tcp_packets",
            {"packets": [{**packet, "flags": "syn", "seq": 8190}] * 5, "delay_ms": 100},
        )
        assert_completed(retried, "replacement opener retransmits")
        current = finish_capture(capture)
        replaced = read_module_stats(vm)
        assert replaced["flows_created"] == held["flows_created"] + 1
        assert replaced["flows_current"] == held["flows_current"]
        assert replaced["half_open_rejected"] == held["half_open_rejected"]
        assert payload_probe.packets(vm, "replacement_queue") == 0

        # Identical current opener retransmits this SYNACK, not a new generation.
        capture = capture_synack(8190)
        inject(flags="syn", seq=8190)
        duplicate = finish_capture(capture)
        assert duplicate["seq"] == current["seq"]
        # The immediately previous opener cannot bounce us back, even repeatedly.
        inject(flags="syn", seq=4095)
        inject(flags="syn", seq=4095)
        inject(flags="ack|psh", seq=4096, ack=(old["seq"] + 1) & 0xFFFFFFFF, payload="old")
        retained = read_module_stats(vm)
        assert retained["flows_created"] == replaced["flows_created"]
        assert retained["flows_established"] == baseline["flows_established"]
        assert retained["rst_sent"] == baseline["rst_sent"]
        assert retained["replacement_quarantine_dropped"] >= replaced["replacement_quarantine_dropped"] + 3
        # A replacement still owns exactly one remote charge at saturation.
        inject(bind_port=source_ports[remote_limit], flags="syn", seq=12285)
        full = read_module_stats(vm)
        assert full["half_open_rejected"] == retained["half_open_rejected"] + 1
        assert full["flows_current"] == held["flows_current"]

        inject(flags="ack", seq=8191, ack=(current["seq"] + 1) & 0xFFFFFFFF)
        wait_for_stat_greater(vm, "flows_established", baseline["flows_established"])
        wait_for_probe_packets_after(vm, payload_probe, "replacement_queue", 0, "retained UDP queue")
        inject(flags="ack", seq=8191, ack=(current["seq"] + 1) & 0xFFFFFFFF)
        assert payload_probe.packets(vm, "replacement_queue") == 1
        # Quarantine survives completion; the old opener must still be inert.
        inject(flags="syn", seq=4095)
        completed = read_module_stats(vm)
        assert completed["flows_created"] == replaced["flows_created"]
        assert completed["replacement_quarantine_dropped"] > retained["replacement_quarantine_dropped"]
        inject(bind_port=source_ports[remote_limit], flags="syn", seq=12285)
        released = wait_for_stat_greater(vm, "flows_created", completed["flows_created"])
        assert released["half_open_rejected"] == full["half_open_rejected"]
        assert released["flows_current"] == held["flows_current"] + 1
    finally:
        payload_probe.cleanup(vm)
        drop.cleanup(vm)
        cleanup_netns_topology(vm)


def test_half_open_replacements_do_not_restart_retry_lifetime(phantun_module, vm):
    phantun_module.load(
        managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS,
        half_open_limit=1, handshake_timeout_ms=500, handshake_retries=5,
    )
    ensure_netns_topology(vm)
    require_nft_or_skip(vm)
    src_port, dst_port = PORTS_A[0], PORTS_B[0]
    drop = make_netns_ingress_flag_drop_probe(
        vm, NS_A, VETH_A,
        [{
            "src_addr": NS_ADDR_B, "src_port": dst_port,
            "dst_addr": NS_ADDR_A, "dst_port": src_port,
            "flags_expr": "syn | ack", "comment": "hold_replacement_lifetime",
        }],
    )
    packet = {
        "bind_addr": NS_ADDR_A, "bind_port": src_port,
        "target_addr": NS_ADDR_B, "target_port": dst_port,
    }
    baseline = read_module_stats(vm)
    try:
        # Change opener throughout the first two seconds, then keep sending old
        # data past the original three-second retry lifetime. No new SYN after
        # that lifetime can accidentally start a legitimately fresh generation.
        result = run_netns_scenario(
            vm, NS_A, "send_tcp_packets",
            {
                "packets": [
                    {**packet, "flags": "syn", "seq": 4095 * index}
                    for index in range(1, 21)
                ] + [
                    {**packet, "flags": "ack|psh", "seq": 123456, "ack": 0, "payload": "old"}
                ] * 17,
                "delay_ms": 100,
            },
        )
        assert_completed(result, "bounded replacement stream")
        expired = read_module_stats(vm)
        assert expired["handshake_retries_exhausted"] == baseline["handshake_retries_exhausted"] + 1
        assert expired["flows_current"] == baseline["flows_current"]
        assert expired["flows_created"] > baseline["flows_created"] + 1
        assert expired["flows_established"] == baseline["flows_established"]
        assert expired["half_open_rejected"] == baseline["half_open_rejected"]
    finally:
        drop.cleanup(vm)
        cleanup_netns_topology(vm)
