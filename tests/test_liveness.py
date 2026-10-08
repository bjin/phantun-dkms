"""Keepalive liveness timeouts and idle ACK generation."""

import time
import uuid

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
    load_fast_liveness_module,
    load_managed_module,
    make_netns_ingress_drop_probe,
    make_netns_output_flag_probe,
    make_netns_output_ipv4_pure_ack_probe,
    parse_guest_json,
    read_module_stats,
    received_messages,
    require_guest_command,
    run_netns_scenario,
    spawn_netns_scenario,
    wait_for_guest_ready_file,
    write_guest_text,
)


def test_liveness_timeout_recovers(phantun_module, vm):
    load_fast_liveness_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]

    server = spawn_netns_scenario(
        vm,
        NS_B,
        "echo_server",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 2,
            # The test blocks traffic well past the 2s liveness deadline
            # (1s interval * 2 misses). The default 5s socket timeout in the
            # guest scenario runner is too tight and causes the server to crash
            # before the second payload arrives.
            "timeout_sec": 20,
        },
    )
    keepalive_probe = None
    drop_probe = None
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

        keepalive_probe = make_netns_output_flag_probe(
            vm,
            NS_A,
            [
                {
                    "src_addr": NS_ADDR_A,
                    "dst_addr": NS_ADDR_B,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "flags_expr": "rst",
                    "comment": "liveness_rst",
                },
            ],
        )
        baseline_rst = keepalive_probe.packets(vm, "liveness_rst")
        baseline_stats = read_module_stats(vm)
        baseline_rst_sent = baseline_stats["rst_sent"]
        baseline_liveness_timeouts = baseline_stats["established_liveness_timeouts"]
        drop_probe = make_netns_ingress_drop_probe(
            vm,
            NS_A,
            VETH_A,
            [
                {
                    "src_addr": NS_ADDR_B,
                    "dst_addr": NS_ADDR_A,
                    "src_port": dst_port,
                    "dst_port": src_port,
                    "comment": "drop_inbound_fake_tcp",
                }
            ],
        )

        # The 2s liveness deadline is driven by delayed GC work. Poll for the
        # contract change instead of sleeping a fixed interval: once local
        # liveness fails, the old generation should emit at least one RST before
        # recovery opens a replacement generation.
        deadline = time.time() + 8.0
        rst_packets = 0
        while time.time() < deadline:
            rst_packets = keepalive_probe.packets(vm, "liveness_rst") - baseline_rst
            if rst_packets > 0:
                break
            time.sleep(0.1)

        if rst_packets <= 0:
            pytest.fail("expected local RST after liveness teardown, got none")
        stats_after_liveness = read_module_stats(vm)
        rst_sent = stats_after_liveness["rst_sent"] - baseline_rst_sent
        if rst_sent <= 0:
            pytest.fail(f"expected rst_sent to increase after liveness teardown, got {rst_sent}")
        liveness_timeouts = stats_after_liveness["established_liveness_timeouts"] - baseline_liveness_timeouts
        if liveness_timeouts <= 0:
            pytest.fail(
                "expected established_liveness_timeouts to increase after liveness teardown, "
                f"got {stats_after_liveness!r}"
            )

        drop_probe.cleanup(vm)
        drop_probe = None

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

        server_result = server.communicate(timeout=15)
        assert_completed(server_result, "server")
        server_data = parse_guest_json(server_result.stdout, "server stdout")
        if received_messages(server_data) != ["msg1", "msg2"]:
            pytest.fail(f"unexpected messages received by server: {received_messages(server_data)!r}")
    finally:
        if keepalive_probe is not None:
            keepalive_probe.cleanup(vm)
        if drop_probe is not None:
            drop_probe.cleanup(vm)
        vm.run(["ip", "netns", "exec", NS_A, "nft", "flush", "ruleset"], check=False)


def test_liveness_reinitiates_flow_with_queued_packet(phantun_module, vm):
    load_fast_liveness_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    probe_b = make_netns_ingress_drop_probe(
        vm,
        NS_B,
        VETH_B,
        [
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "comment": "drop all fake tcp",
            }
        ],
    )
    initial_stats = read_module_stats(vm)

    # Spawn a client that will hang sending msg1 because it gets no replies
    client = spawn_netns_scenario(
        vm,
        NS_A,
        "echo_client",
        {
            "bind_addr": NS_ADDR_A,
            "bind_port": src_port,
            "target_addr": NS_ADDR_B,
            "target_port": dst_port,
            "payloads": ["msg1"],
            "timeout_sec": 20,
        },
    )

    try:
        time.sleep(0.5)
        stats_after_first_syn = read_module_stats(vm)
        flows_created_1 = stats_after_first_syn["flows_created"] - initial_stats["flows_created"]
        if flows_created_1 != 1:
            pytest.fail(f"expected 1 flow created (1 initiator), got {flows_created_1}")

        # The flow is created at t=0.
        # Retransmits happen at t=1s, 2s, 3s, 4s...
        # Liveness timeout happens at t=2s. When liveness timeout occurs, the queued UDP
        # packet is reinjected, creating a new flow.
        # Since VM time can drift or be delayed relative to host time, poll the stats
        # for up to 10 seconds (20 iterations of 0.5s).
        success = False
        for _ in range(20):
            time.sleep(0.5)
            stats_after_liveness = read_module_stats(vm)
            flows_created_2 = stats_after_liveness["flows_created"] - stats_after_first_syn["flows_created"]
            if flows_created_2 >= 2:
                success = True
                break

        if not success:
            pytest.fail(f"expected flow to be re-initiated 2 times due to liveness, got {flows_created_2}")

        rst_sent = stats_after_liveness["rst_sent"] - initial_stats["rst_sent"]
        if rst_sent != 0:
            pytest.fail(f"half-open liveness reinitiation must not emit RST before retry exhaustion, got {rst_sent}")
    finally:
        probe_b.cleanup(vm)
        vm.run(["ip", "netns", "exec", NS_A, "nft", "flush", "ruleset"], check=False)


def test_netns_recent_bidirectional_payload_suppresses_idle_ack(phantun_module, vm):
    load_managed_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    prefix = f"/tmp/phantun_ack_suppress_{uuid.uuid4().hex}"
    server_ready = f"{prefix}_server_ready"
    first_received = f"{prefix}_first_received"
    send_reply = f"{prefix}_send_reply"
    immediate_received = f"{prefix}_immediate_received"
    send_delayed = f"{prefix}_send_delayed"
    ack_probe = make_netns_output_ipv4_pure_ack_probe(
        vm,
        NS_B,
        NS_ADDR_B,
        dst_port,
        NS_ADDR_A,
        src_port,
    )
    server = None
    client = None

    try:
        server = spawn_netns_scenario(
            vm,
            NS_B,
            "ack_suppression_barrier_server",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "timeout_sec": 20,
                "ready_file": server_ready,
                "first_received_file": first_received,
                "send_reply_file": send_reply,
                "immediate_received_file": immediate_received,
                "barrier_timeout_sec": 12,
                "reply_delay_ms": 400,
                "reply_payload": "reply",
            },
        )
        wait_for_guest_ready_file(vm, server_ready, timeout=5)

        pure_before = ack_probe.packets(vm, "pure_ipv4_ack")
        stats_before = read_module_stats(vm)
        client = spawn_netns_scenario(
            vm,
            NS_A,
            "ack_suppression_barrier_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "timeout_sec": 20,
                "payloads": ["receive-only", "immediate", "delayed"],
                "send_delayed_file": send_delayed,
                "barrier_timeout_sec": 12,
                "delayed_payload_delay_ms": 400,
            },
        )

        wait_for_guest_ready_file(vm, first_received, timeout=10)
        deadline = time.time() + 5
        while time.time() < deadline:
            pure_after_receive_only = ack_probe.packets(vm, "pure_ipv4_ack")
            if pure_after_receive_only > pure_before:
                break
            time.sleep(0.05)
        else:
            pytest.fail("receive-only established payload did not emit a pure ACK")

        stats_after_receive_only = read_module_stats(vm)
        if stats_after_receive_only["idle_acks_suppressed"] != stats_before["idle_acks_suppressed"]:
            pytest.fail(
                "receive-only established payload should not suppress its ACK: "
                f"before={stats_before!r} after={stats_after_receive_only!r}"
            )

        write_guest_text(vm, send_reply, "ready\n")
        wait_for_guest_ready_file(vm, immediate_received, timeout=10)
        deadline = time.time() + 5
        while time.time() < deadline:
            stats_after_immediate = read_module_stats(vm)
            if stats_after_immediate["idle_acks_suppressed"] > stats_after_receive_only["idle_acks_suppressed"]:
                break
            time.sleep(0.05)
        else:
            pytest.fail("recent bidirectional payload did not increment idle_acks_suppressed")

        pure_after_immediate = ack_probe.packets(vm, "pure_ipv4_ack")
        if pure_after_immediate != pure_after_receive_only:
            pytest.fail(
                "recent bidirectional payload should suppress the pure ACK: "
                f"receive_only={pure_after_receive_only} immediate={pure_after_immediate}"
            )

        write_guest_text(vm, send_delayed, "ready\n")
        server_result = server.communicate(timeout=20)
        client_result = client.communicate(timeout=20)
        assert_completed(server_result, "ACK suppression barrier receiver")
        assert_completed(client_result, "ACK suppression barrier sender")

        server_data = parse_guest_json(server_result.stdout, "ACK suppression receiver stdout")
        client_data = parse_guest_json(client_result.stdout, "ACK suppression sender stdout")
        if [entry["message"] for entry in server_data.get("received", [])] != [
            "receive-only",
            "immediate",
            "delayed",
        ]:
            pytest.fail(f"ACK suppression receiver saw unexpected payloads: {server_data!r}")
        if [entry["message"] for entry in client_data.get("replies", [])] != ["reply"]:
            pytest.fail(f"ACK suppression sender saw unexpected replies: {client_data!r}")

        deadline = time.time() + 5
        while time.time() < deadline:
            pure_after_delayed = ack_probe.packets(vm, "pure_ipv4_ack")
            if pure_after_delayed > pure_after_immediate:
                break
            time.sleep(0.05)
        else:
            pytest.fail("payload outside ACK suppression window did not emit a pure ACK")

        stats_after_delayed = read_module_stats(vm)
        if stats_after_delayed["idle_acks_suppressed"] != stats_after_immediate["idle_acks_suppressed"]:
            pytest.fail(
                "payload outside ACK suppression window should not increment suppressed ACK stats: "
                f"immediate={stats_after_immediate!r} delayed={stats_after_delayed!r}"
            )
    finally:
        for process in (client, server):
            if process is not None and process.proc.poll() is None:
                process.terminate()
        ack_probe.cleanup(vm)
        cleanup_netns_topology(vm)
