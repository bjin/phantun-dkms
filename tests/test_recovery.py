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
    cleanup_netns_topology,
    ensure_netns_topology,
    require_guest_command,
    run_netns_scenario,
    spawn_netns_scenario,
    parse_guest_json,
    make_netns_ingress_flag_drop_probe,
    make_netns_output_flag_probe,
    read_module_stats,
)

MANAGED_LOCAL_PORTS = "2222,3333,4444,5555"


def load_recovery_module(phantun_module, **kwargs):
    # Set keepalive interval to 1s to test liveness.
    phantun_module.load(
        managed_local_ports=MANAGED_LOCAL_PORTS,
        keepalive_interval_sec=1,
        keepalive_misses=2,
        **kwargs,
    )


def assert_completed(result, label):
    if result.returncode != 0:
        pytest.fail(f"{label} failed: {result.stderr!r}")


def received_messages(payload):
    return payload.get("received", [])


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
        },
    )
    keepalive_probe = None

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
                    "flags_expr": "ack",
                    "comment": "keepalive_ack",
                },
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
        baseline_keepalive = keepalive_probe.packets(vm, "keepalive_ack")
        baseline_rst = keepalive_probe.packets(vm, "liveness_rst")

        vm.run(["ip", "netns", "exec", NS_A, "nft", "add", "table", "inet", "filter"])
        vm.run(
            [
                "ip",
                "netns",
                "exec",
                NS_A,
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
                NS_A,
                "nft",
                "add",
                "rule",
                "inet",
                "filter",
                "output",
                "drop",
            ]
        )

        time.sleep(4)

        keepalive_packets = keepalive_probe.packets(vm, "keepalive_ack")
        rst_packets = keepalive_probe.packets(vm, "liveness_rst")
        if keepalive_packets <= baseline_keepalive:
            pytest.fail("expected at least one keepalive ACK before liveness teardown")
        if rst_packets != baseline_rst:
            pytest.fail(
                f"expected silent liveness teardown without local RST, got {rst_packets - baseline_rst}"
            )

        vm.run(["ip", "netns", "exec", NS_A, "nft", "flush", "ruleset"])

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
            pytest.fail(
                f"unexpected messages received by server: {received_messages(server_data)!r}"
            )
    finally:
        if keepalive_probe is not None:
            keepalive_probe.cleanup(vm)
        vm.run(["ip", "netns", "exec", NS_A, "nft", "flush", "ruleset"], check=False)


def test_syn_isn_tie_break(phantun_module, vm):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

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
        time.sleep(0.5)
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
        if final_stats["collisions_won"] - initial_stats["collisions_won"] != 1:
            pytest.fail(
                f"expected exactly one collision win, got stats {final_stats!r}"
            )
        if final_stats["collisions_lost"] - initial_stats["collisions_lost"] != 1:
            pytest.fail(
                f"expected exactly one collision loss, got stats {final_stats!r}"
            )
    finally:
        probe_a.cleanup(vm)
        probe_b.cleanup(vm)


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
        {"bind_addr": NS_ADDR_B, "bind_port": dst_port, "count": 2},
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
        vm.run(
            ["ip", "netns", "exec", NS_B, "nft", "delete", "table", "inet", "filter"]
        )

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
        {"bind_addr": NS_ADDR_B, "bind_port": dst_port, "count": 2},
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
        vm.run(
            ["ip", "netns", "exec", NS_B, "nft", "delete", "table", "inet", "filter"]
        )

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
            pytest.fail(
                f"stale packet escaped quarantine and confused the client: {client_data!r}"
            )

        server_result = server.communicate(timeout=15)
        assert_completed(server_result, "server")
        server_data = parse_guest_json(server_result.stdout, "server stdout")
        if received_messages(server_data) != ["msg1", "msg2"]:
            pytest.fail(
                f"stale packet escaped quarantine and reached UDP delivery: {received_messages(server_data)!r}"
            )
        if rst_probe.packets(vm, "quarantine_rst") != baseline_rst:
            pytest.fail(
                "stale old-generation packet should be dropped without emitting RST"
            )
    finally:
        rst_probe.cleanup(vm)
        vm.run(
            ["ip", "netns", "exec", NS_B, "nft", "delete", "table", "inet", "filter"],
            check=False,
        )
        cleanup_netns_topology(vm)


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
        {"bind_addr": NS_ADDR_B, "bind_port": dst_port, "count": 2},
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
            pytest.fail(
                "expected RST|ACK in response to invalid established SYN packet"
            )
        if invalid_probe.packets(vm, "invalid_synack") != baseline_invalid_synack:
            pytest.fail(
                "invalid established SYN packet must not be accepted as replacement"
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
            },
        )
        assert_completed(res2, "echo client after invalid SYN")
        data = parse_guest_json(res2.stdout, "echo client")
        if data.get("echoed") != ["msg2"]:
            pytest.fail(f"failed to recover after invalid SYN: {data.get('echoed')!r}")
    finally:
        invalid_probe.cleanup(vm)


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
        pytest.fail(
            f"unexpected server messages after unknown synack: {received_messages(server_data)!r}"
        )


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
        pytest.fail(
            f"unexpected server messages after unknown ack payload: {received_messages(server_data)!r}"
        )
