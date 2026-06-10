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
    VETH_A_ALT,
    VETH_B_ALT,
    assert_completed,
    cleanup_netns_topology,
    ensure_netns_topology,
    ensure_netns_second_path,
    make_netns_ingress_drop_probe,
    make_netns_ingress_flag_drop_probe,
    make_netns_ingress_payload_drop_probe,
    make_netns_output_flag_probe,
    make_netns_output_ipv4_pure_ack_probe,
    parse_guest_json,
    read_module_stats,
    require_guest_command,
    run_in_netns,
    run_netns_scenario,
    spawn_netns_scenario,
    wait_for_guest_condition,
    wait_for_guest_ready_file,
)

MANAGED_LOCAL_PORTS = "2222,3333,4444,5555"
REQ = "HSREQ42"
RESP = "HSRESP42"


def load_recovery_module(phantun_module, **kwargs):
    # Set keepalive interval to 1s to test liveness.
    phantun_module.load(
        managed_netns="all",
        managed_local_ports=MANAGED_LOCAL_PORTS,
        keepalive_interval_sec=1,
        keepalive_misses=2,
        handshake_retries=20,
        **kwargs,
    )


def received_messages(payload):
    return payload.get("received", [])


def wait_for_probe_packets_after(vm, probe, comment, baseline, label, timeout=5):
    deadline = time.time() + timeout
    last = baseline
    while time.time() < deadline:
        last = probe.packets(vm, comment)
        if last > baseline:
            return last
        time.sleep(0.1)
    pytest.fail(f"{label}: expected {comment} packets to increase beyond {baseline}, got {last}")


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


def test_liveness_timeout_recovers(phantun_module, vm):
    load_recovery_module(phantun_module)
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
    load_recovery_module(phantun_module)
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


def test_syn_isn_tie_break(phantun_module, vm):
    phantun_module.load(managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS)
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
    finally:
        probe_a.cleanup(vm)
        probe_b.cleanup(vm)
        vm.run(["ip", "netns", "exec", NS_A, "tc", "qdisc", "del", "dev", VETH_A, "root", "netem"], check=False)
        vm.run(["ip", "netns", "exec", NS_B, "tc", "qdisc", "del", "dev", VETH_B, "root", "netem"], check=False)


def test_established_bare_syn_replacement(phantun_module, vm):
    load_recovery_module(phantun_module)
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
    protect_ms = 5000
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
        },
    )

    try:
        wait_for_guest_ready_file(vm, syn_ready, timeout=5)
        wait_for_guest_ready_file(vm, synack_ready, timeout=5)
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

    if not require_guest_command(vm, "tc"):
        cleanup_netns_topology(vm)
        pytest.skip("tc is not available in the guest")
    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    payloads = ["race1", "race2", "race3", "race4"]
    synack_ready = f"/tmp/phantun-capture-synack-race-{uuid.uuid4().hex}"
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
        },
    )

    try:
        wait_for_guest_ready_file(vm, synack_ready, timeout=5)
        run_in_netns(vm, NS_A, ["tc", "qdisc", "replace", "dev", VETH_A, "root", "netem", "delay", "150ms"])
        baseline_stats = read_module_stats(vm)
        client = spawn_netns_scenario(
            vm,
            NS_A,
            "send_many_recv",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": payloads,
                "recv_count": len(payloads),
                "delay_ms": 300,
                "timeout_sec": 20,
            },
        )

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
            assert_completed(duplicate, "inject duplicate SYN|ACK during completion")

        wait_for_probe_packets_after(
            vm,
            ack_probe,
            "pure_ipv4_ack",
            baseline_ack,
            "duplicate SYN|ACK completion ACK",
        )
        if rst_probe.packets(vm, "duplicate_completion_synack_rst") != baseline_rst:
            pytest.fail("duplicate SYN|ACK during completion should not emit RST")
        if read_module_stats(vm)["flows_created"] != duplicate_baseline["flows_created"]:
            pytest.fail("duplicate SYN|ACK during completion should not create another flow")

        client_result = client.communicate(timeout=30)
        server_result = server.communicate(timeout=30)
        assert_completed(client_result, "duplicate SYN|ACK completion client")
        assert_completed(server_result, "duplicate SYN|ACK completion server")
        client_data = parse_guest_json(client_result.stdout, "duplicate SYN|ACK completion client stdout")
        server_data = parse_guest_json(server_result.stdout, "duplicate SYN|ACK completion server stdout")
        client_replies = [reply["message"] for reply in client_data.get("replies", [])]
        if client_replies != payloads:
            pytest.fail(f"unexpected echoed payloads after duplicate SYN|ACKs: {client_data!r}")
        if received_messages(server_data) != payloads:
            pytest.fail(f"unexpected server payloads after duplicate SYN|ACKs: {server_data!r}")

        stats = read_module_stats(vm)
        if stats["flows_established"] != baseline_stats["flows_established"] + 2:
            pytest.fail(f"expected both endpoint flows to establish, before={baseline_stats!r} after={stats!r}")
    finally:
        run_in_netns(vm, NS_A, ["tc", "qdisc", "del", "dev", VETH_A, "root"], check=False)
        ack_probe.cleanup(vm)
        rst_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_duplicate_final_ack_during_responder_completion_is_single_winner(phantun_module, vm):
    phantun_module.load(
        managed_netns="all",
        managed_local_ports=MANAGED_LOCAL_PORTS,
        keepalive_interval_sec=60,
        handshake_timeout_ms=800,
        handshake_retries=20,
        handshake_request=REQ,
        handshake_response=RESP,
    )
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "tc"):
        cleanup_netns_topology(vm)
        pytest.skip("tc is not available in the guest")
    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[1]
    dst_port = PORTS_B[1]
    open_payload = "final-open"
    final_ack_ready = f"/tmp/phantun-capture-final-ack-race-{uuid.uuid4().hex}"
    capture_final_ack = spawn_netns_scenario(
        vm,
        NS_B,
        "capture_tcp_packet",
        {
            "bind_addr": NS_ADDR_A,
            "bind_port": src_port,
            "target_addr": NS_ADDR_B,
            "target_port": dst_port,
            "payload": REQ,
            "ready_file": final_ack_ready,
            "timeout_sec": 20,
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
                "comment": "duplicate_final_ack_rst",
            },
        ],
    )
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "recv_many",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 1,
            "timeout_sec": 20,
        },
    )

    try:
        wait_for_guest_ready_file(vm, final_ack_ready, timeout=5)
        run_in_netns(vm, NS_A, ["tc", "qdisc", "replace", "dev", VETH_A, "root", "netem", "delay", "150ms"])
        baseline_stats = read_module_stats(vm)
        client = spawn_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": [open_payload],
                "timeout_sec": 20,
            },
        )

        final_ack_result = capture_final_ack.communicate(timeout=25)
        assert_completed(final_ack_result, "capture final ACK handshake request")
        final_ack_data = parse_guest_json(final_ack_result.stdout, "final ACK handshake request")
        if final_ack_data.get("flags") & 0x10 == 0:
            pytest.fail(f"expected captured final ACK, got {final_ack_data!r}")

        baseline_rst = rst_probe.packets(vm, "duplicate_final_ack_rst")

        for _ in range(5):
            duplicate = run_netns_scenario(
                vm,
                NS_A,
                "send_tcp_packet",
                {
                    "bind_addr": NS_ADDR_A,
                    "bind_port": src_port,
                    "target_addr": NS_ADDR_B,
                    "target_port": dst_port,
                    "seq": final_ack_data["seq"],
                    "ack": final_ack_data["ack"],
                    "flags": "ack",
                },
            )
            assert_completed(duplicate, "inject duplicate final ACK during completion")

        client_result = client.communicate(timeout=30)
        server_result = server.communicate(timeout=30)
        assert_completed(client_result, "duplicate final ACK completion opener")
        assert_completed(server_result, "duplicate final ACK completion receiver")
        server_data = parse_guest_json(server_result.stdout, "duplicate final ACK completion receiver stdout")
        opener_messages = [item["message"] for item in server_data.get("received", [])]
        if opener_messages != [open_payload]:
            pytest.fail(f"unexpected opener payloads after duplicate final ACKs: {server_data!r}")

        stats = read_module_stats(vm)
        if stats["flows_established"] != baseline_stats["flows_established"] + 2:
            pytest.fail(f"expected both endpoint flows to establish, before={baseline_stats!r} after={stats!r}")
        if stats["response_payloads_injected"] != baseline_stats["response_payloads_injected"] + 1:
            pytest.fail(f"expected one injected response, before={baseline_stats!r} after={stats!r}")
        if rst_probe.packets(vm, "duplicate_final_ack_rst") != baseline_rst:
            pytest.fail("duplicate final ACK during responder completion should not emit RST")
        if stats["flows_created"] != baseline_stats["flows_created"] + 2:
            pytest.fail(
                f"duplicate final ACKs should not create another flow, before={baseline_stats!r} after={stats!r}"
            )
    finally:
        run_in_netns(vm, NS_A, ["tc", "qdisc", "del", "dev", VETH_A, "root"], check=False)
        rst_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_replacement_quarantine_drops_delayed_old_generation_packet(phantun_module, vm):
    load_recovery_module(phantun_module)
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


def test_delayed_handshake_request_does_not_regress_ack(phantun_module, vm):
    load_recovery_module(phantun_module, handshake_request=REQ)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]

    syn_ready_file = f"/tmp/phantun-syn-capture-{uuid.uuid4().hex}"
    syn_capture = spawn_netns_scenario(
        vm,
        NS_B,
        "capture_tcp_packet",
        {
            "bind_addr": NS_ADDR_A,
            "bind_port": src_port,
            "target_addr": NS_ADDR_B,
            "target_port": dst_port,
            "payload": "",
            "ready_file": syn_ready_file,
            "timeout_sec": 30,
        },
    )
    drop_request = make_netns_ingress_payload_drop_probe(
        vm,
        NS_B,
        VETH_B,
        [
            {
                "src_addr": NS_ADDR_A,
                "src_port": src_port,
                "dst_addr": NS_ADDR_B,
                "dst_port": dst_port,
                "payload": REQ,
                "comment": "drop_delayed_req",
            }
        ],
    )
    # echo_server receives both msg1 (before injection) and msg2 (after injection)
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "echo_server",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 2,
            "timeout_sec": 30,
        },
    )

    try:
        wait_for_guest_ready_file(vm, syn_ready_file, timeout=30)
        time.sleep(0.2)

        # Phase 1: send msg1, establishing the flow while REQ is dropped on ingress.
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
                "timeout_sec": 15,
            },
        )
        assert_completed(client_result_1, "msg1 echo")

        # Capture the initiator's SYN to learn the ISN for the delayed injection.
        syn_result = syn_capture.communicate(timeout=30)
        assert_completed(syn_result, "capture initiator SYN")
        syn_data = parse_guest_json(syn_result.stdout, "captured initiator SYN")
        if (syn_data.get("flags", 0) & 0x02) == 0 or (syn_data.get("flags", 0) & 0x10) != 0:
            pytest.fail(f"expected bare SYN, got {syn_data!r}")
        if drop_request.packets(vm, "drop_delayed_req") == 0:
            pytest.fail("failed to drop the original reserved handshake_request")

        # Phase 2: remove the drop rule and inject the delayed REQ at the old
        # sequence number. If the responder's ACK regresses, it would re-request
        # already-delivered data, causing duplicates or stalling the connection.
        drop_request.cleanup(vm)
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
                "seq": syn_data["seq"] + 1,
                "ack": 1,
                "payload": REQ,
            },
        )

        # Phase 3: send msg2 through the same flow. If the delayed injection
        # corrupted the responder's ACK state, this would fail or duplicate.
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
                "timeout_sec": 15,
            },
        )
        assert_completed(client_result_2, "msg2 echo after delayed REQ")

        server_result = server.communicate(timeout=20)
        assert_completed(server_result, "echo server")
        server_data = parse_guest_json(server_result.stdout, "echo server stdout")
        if received_messages(server_data) != ["msg1", "msg2"]:
            pytest.fail(
                f"delayed REQ injection corrupted delivery: "
                f"expected ['msg1', 'msg2'], got {received_messages(server_data)!r}"
            )
    finally:
        drop_request.cleanup(vm)
        vm.run(["rm", "-f", syn_ready_file], check=False)
        cleanup_netns_topology(vm)


def test_route_change_revalidates_cached_dst_without_rst(phantun_module, vm):
    load_recovery_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    ensure_netns_second_path(vm)
    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    path_a_probe = make_netns_ingress_payload_drop_probe(
        vm,
        NS_B,
        VETH_B,
        [
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "payload": "route-before",
                "action": "accept",
                "comment": "route_before_on_path_a",
            },
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "payload": "route-after",
                "action": "accept",
                "comment": "route_after_on_path_a",
            },
        ],
    )
    path_b_probe = make_netns_ingress_payload_drop_probe(
        vm,
        NS_B,
        VETH_B_ALT,
        [
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "payload": "route-before",
                "action": "accept",
                "comment": "route_before_on_path_b",
            },
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "payload": "route-after",
                "action": "accept",
                "comment": "route_after_on_path_b",
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
            "ping_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payload": "route-before",
            },
            timeout=10,
        )
        assert_completed(first, "stale-route first client")
        if path_a_probe.packets(vm, "route_before_on_path_a") == 0:
            pytest.fail("initial payload did not use path A before route change")

        baseline_rst_sent = read_module_stats(vm)["rst_sent"]
        run_in_netns(vm, NS_A, ["ip", "route", "replace", NS_ADDR_B, "dev", VETH_A_ALT, "src", NS_ADDR_A])
        time.sleep(0.2)

        second = run_netns_scenario(
            vm,
            NS_A,
            "ping_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payload": "route-after",
            },
            timeout=10,
        )
        assert_completed(second, "stale-route second client")

        server_result = server.communicate(timeout=15)
        assert_completed(server_result, "stale-route echo server")
        server_data = parse_guest_json(server_result.stdout, "stale-route server stdout")
        if server_data.get("received") != ["route-before", "route-after"]:
            pytest.fail(f"unexpected stale-route server payloads: {server_data.get('received')!r}")

        if path_b_probe.packets(vm, "route_after_on_path_b") == 0:
            pytest.fail("payload after route change did not use path B")
        if path_a_probe.packets(vm, "route_after_on_path_a") != 0:
            pytest.fail("stale cached path A dst was reused after route change")
        if read_module_stats(vm)["rst_sent"] != baseline_rst_sent:
            pytest.fail("route-only dst revalidation unexpectedly emitted RST")
    finally:
        path_a_probe.cleanup(vm)
        path_b_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def assert_flow_recreated_after_local_topology_change(vm, change_steps, label, settle_cmd=None):
    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    reconnect_probe = make_netns_output_flag_probe(
        vm,
        NS_A,
        [
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "flags_expr": "syn",
                "comment": "reconnect_syn",
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
        assert_completed(first, f"{label} first echo")

        baseline_syn = reconnect_probe.packets(vm, "reconnect_syn")
        if baseline_syn == 0:
            pytest.fail(f"expected initial SYN before {label}, got {baseline_syn}")
        baseline_rst_sent = read_module_stats(vm)["rst_sent"]

        for step in change_steps:
            vm.run(step)
        if settle_cmd is not None:
            wait_for_guest_condition(vm, settle_cmd, timeout=5, description=f"{label} settle")
        else:
            time.sleep(0.2)
        rst_sent_after_change = read_module_stats(vm)["rst_sent"]
        if rst_sent_after_change != baseline_rst_sent:
            pytest.fail(
                f"topology invalidation must stay silent for {label}: "
                f"rst_sent before={baseline_rst_sent} after={rst_sent_after_change}"
            )

        second = run_netns_scenario(
            vm,
            NS_A,
            "echo_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["msg2"],
                "timeout_sec": 10,
            },
        )
        assert_completed(second, f"{label} second echo")

        new_syns = reconnect_probe.packets(vm, "reconnect_syn") - baseline_syn
        if new_syns < 1:
            pytest.fail(f"expected a fresh SYN after {label}, got {new_syns}")

        server_result = server.communicate(timeout=15)
        assert_completed(server_result, f"{label} server")
        server_data = parse_guest_json(server_result.stdout, f"{label} server stdout")
        if received_messages(server_data) != ["msg1", "msg2"]:
            pytest.fail(f"unexpected server messages after {label}: {received_messages(server_data)!r}")
    finally:
        reconnect_probe.cleanup(vm)


def test_device_down_invalidation_recreates_flow(phantun_module, vm):
    load_recovery_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    assert_flow_recreated_after_local_topology_change(
        vm,
        [
            ["ip", "netns", "exec", NS_A, "ip", "link", "set", "dev", VETH_A, "down"],
            ["ip", "netns", "exec", NS_A, "ip", "link", "set", "dev", VETH_A, "up"],
        ],
        "device bounce invalidation",
        [
            "ip",
            "netns",
            "exec",
            NS_A,
            "bash",
            "-lc",
            f"ip -o link show dev {VETH_A} | grep -q 'state UP' && ip -o -4 addr show dev {VETH_A} | grep -q '{NS_ADDR_A}/24'",
        ],
    )


def test_local_addr_removal_invalidation_recreates_flow(phantun_module, vm):
    load_recovery_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    assert_flow_recreated_after_local_topology_change(
        vm,
        [
            [
                "ip",
                "netns",
                "exec",
                NS_A,
                "ip",
                "addr",
                "del",
                f"{NS_ADDR_A}/24",
                "dev",
                VETH_A,
            ],
            [
                "ip",
                "netns",
                "exec",
                NS_A,
                "ip",
                "addr",
                "add",
                f"{NS_ADDR_A}/24",
                "dev",
                VETH_A,
            ],
        ],
        "local IPv4 removal invalidation",
        [
            "ip",
            "netns",
            "exec",
            NS_A,
            "bash",
            "-lc",
            f"ip -o -4 addr show dev {VETH_A} | grep -q '{NS_ADDR_A}/24'",
        ],
    )
