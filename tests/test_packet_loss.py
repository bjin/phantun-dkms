import json
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
    make_netns_ingress_flag_drop_probe,
    make_netns_ingress_payload_drop_probe,
    make_netns_output_flag_probe,
    make_netns_output_ipv4_pure_ack_probe,
    make_netns_tcp_payload_probe,
    parse_guest_json,
    read_module_stats,
    require_guest_command,
    run_netns_scenario,
    spawn_netns_scenario,
    wait_for_guest_ready_file,
)

MANAGED_LOCAL_PORTS = "2222,3333,4444,5555"
REQ = "HSREQ42"
RESP = "HSRESP42"


def load_loss_module(phantun_module, **kwargs):
    phantun_module.load(managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS, **kwargs)


def received_messages(payload):
    return [entry["message"] for entry in payload.get("received", [])]


def reply_messages(payload):
    return [entry["message"] for entry in payload.get("replies", [])]


def count_nonzero_probe_hits(vm, probe, comments):
    return sum(1 for comment in comments if probe.packets(vm, comment) > 0)


def write_guest_text(vm, path, content):
    vm.run(["python3", "-c", f"from pathlib import Path; Path({path!r}).write_text({content!r})"])


def wait_for_half_open_drain(vm, baseline_stats, expected_rst, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        stats = read_module_stats(vm)
        if (
            stats["rst_sent"] - baseline_stats["rst_sent"] >= expected_rst
            and stats["flows_current"] == baseline_stats["flows_current"]
        ):
            return stats
        time.sleep(0.1)

    pytest.fail(
        "half-open flows did not drain back to baseline: "
        f"baseline={baseline_stats!r} current={stats!r} expected_rst={expected_rst}"
    )


def wait_for_flows_current(vm, expected, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        stats = read_module_stats(vm)
        if stats["flows_current"] == expected:
            return stats
        time.sleep(0.1)

    pytest.fail(f"flows_current did not reach {expected}: current={stats!r}")


def test_initial_syn_emit_failure_releases_flow_slot_and_queue(phantun_module, vm):
    load_loss_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    baseline_stats = read_module_stats(vm)
    probe = make_netns_output_flag_probe(
        vm,
        NS_A,
        [
            {
                "src_addr": NS_ADDR_A,
                "src_port": src_port,
                "dst_addr": NS_ADDR_B,
                "dst_port": dst_port,
                "flags_expr": "syn",
                "action": "drop",
                "comment": "drop_initial_syn_local_emit",
            }
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
            "timeout_sec": 10,
        },
    )

    try:
        time.sleep(0.2)
        first = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["must-not-leak"],
            },
        )
        assert_completed(first, "initial SYN local emit failure sender")
        if probe.packets(vm, "drop_initial_syn_local_emit") <= 0:
            pytest.fail("expected nft OUTPUT rule to drop the locally emitted SYN")

        stats_after_failure = wait_for_flows_current(vm, baseline_stats["flows_current"])
        if stats_after_failure["udp_packets_dropped"] <= baseline_stats["udp_packets_dropped"]:
            pytest.fail(f"expected failed initial SYN emit to count a UDP drop: {stats_after_failure!r}")
        if stats_after_failure["udp_translation_failed_dropped"] <= baseline_stats["udp_translation_failed_dropped"]:
            pytest.fail(
                "expected failed initial SYN emit to count a UDP translation failure, " f"got {stats_after_failure!r}"
            )

        probe.cleanup(vm)
        second = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["fresh-flow"],
            },
        )
        assert_completed(second, "fresh flow sender after failed SYN")
        server_result = server.communicate(timeout=15)
        assert_completed(server_result, "fresh flow receiver after failed SYN")
        server_data = parse_guest_json(server_result.stdout, "fresh flow receiver stdout")
        if received_messages(server_data) != ["fresh-flow"]:
            pytest.fail(f"failed initial SYN retained or delivered queued skb: {server_data!r}")
    finally:
        probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_syn_loss_is_retried(phantun_module, vm):
    load_loss_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    probe = make_netns_ingress_flag_drop_probe(
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
                "comment": "drop_syn",
            }
        ],
    )
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "ping_server",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "reply": "pong",
        },
    )

    try:
        time.sleep(0.2)
        client = spawn_netns_scenario(
            vm,
            NS_A,
            "ping_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payload": "ping",
            },
        )
        time.sleep(1.25)
        probe.cleanup(vm)

        client_result = client.communicate(timeout=12)
        server_result = server.communicate(timeout=12)
        assert_completed(client_result, "syn-loss client")
        assert_completed(server_result, "syn-loss server")

        client_data = parse_guest_json(client_result.stdout, "syn-loss client stdout")
        server_data = parse_guest_json(server_result.stdout, "syn-loss server stdout")
        if client_data.get("reply") != "pong":
            pytest.fail(f"unexpected client reply after SYN loss: {client_data.get('reply')!r}")
        if server_data.get("received") != "ping":
            pytest.fail(f"unexpected server payload after SYN loss: {server_data.get('received')!r}")
    finally:
        probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_synack_loss_is_retried(phantun_module, vm):
    load_loss_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    initial_stats = read_module_stats(vm)
    probe = make_netns_ingress_flag_drop_probe(
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
                "comment": "drop_synack",
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
                "comment": "sent_synack",
            }
        ],
    )
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "ping_server",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "reply": "pong",
        },
    )

    try:
        time.sleep(0.2)
        baseline_synack = synack_probe.packets(vm, "sent_synack")
        client = spawn_netns_scenario(
            vm,
            NS_A,
            "ping_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payload": "ping",
            },
        )
        time.sleep(1.25)
        probe.cleanup(vm)

        client_result = client.communicate(timeout=12)
        server_result = server.communicate(timeout=12)
        assert_completed(client_result, "synack-loss client")
        assert_completed(server_result, "synack-loss server")

        client_data = parse_guest_json(client_result.stdout, "synack-loss client stdout")
        server_data = parse_guest_json(server_result.stdout, "synack-loss server stdout")
        if client_data.get("reply") != "pong":
            pytest.fail(f"unexpected client reply after SYN|ACK loss: {client_data.get('reply')!r}")
        if server_data.get("received") != "ping":
            pytest.fail(f"unexpected server payload after SYN|ACK loss: {server_data.get('received')!r}")
        if synack_probe.packets(vm, "sent_synack") <= baseline_synack + 1:
            pytest.fail("expected responder to re-send SYN|ACK after initiator re-sent SYN")

        final_stats = read_module_stats(vm)
        if final_stats["flows_created"] - initial_stats["flows_created"] != 2:
            pytest.fail(f"duplicate SYN after lost SYN|ACK should not create extra flows: {final_stats!r}")
    finally:
        probe.cleanup(vm)
        synack_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_half_open_retry_exhaustion_releases_flow_slot(phantun_module, vm):
    phantun_module.load(
        managed_netns="all",
        managed_local_ports=MANAGED_LOCAL_PORTS,
        handshake_timeout_ms=200,
        handshake_retries=1,
    )
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
                "comment": "drop_exhausted_synack",
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
                "comment": "sent_exhausted_synack",
            }
        ],
    )
    baseline_stats = read_module_stats(vm)
    baseline_synack = synack_probe.packets(vm, "sent_exhausted_synack")

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

        # On slow nested-QEMU CI the responder half-open may be created and
        # exhausted between host-side polls. Assert on cumulative counters and
        # the emitted SYN|ACK instead of a transient flows_current spike.
        stats = wait_for_half_open_drain(vm, baseline_stats, expected_rst=1)

        if synack_probe.packets(vm, "sent_exhausted_synack") <= baseline_synack:
            pytest.fail("expected responder to emit SYN|ACK before retry exhaustion")

        if stats["flows_created"] <= baseline_stats["flows_created"]:
            pytest.fail(
                "expected responder half-open flow creation before retry exhaustion: "
                f"baseline={baseline_stats!r} current={stats!r}"
            )
        if stats["handshake_retries_exhausted"] <= baseline_stats["handshake_retries_exhausted"]:
            pytest.fail(f"expected handshake_retries_exhausted to increase, got {stats!r}")
    finally:
        drop_synack.cleanup(vm)
        synack_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_responder_half_open_limit_rejects_excess_bare_syns(phantun_module, vm):
    phantun_module.load(
        managed_netns="all",
        managed_local_ports=MANAGED_LOCAL_PORTS,
        half_open_limit=2,
        handshake_timeout_ms=2000,
        handshake_retries=1,
    )
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    dst_port = PORTS_B[0]
    source_ports = [41001, 41002, 41003, 41004, 41005]
    synack_comments = [f"limited_synack_{port}" for port in source_ports]
    drop_synack = make_netns_ingress_flag_drop_probe(
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
                "comment": f"drop_limited_synack_{src_port}",
            }
            for src_port in source_ports
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
                "comment": f"limited_synack_{src_port}",
            }
            for src_port in source_ports
        ],
    )
    baseline_stats = read_module_stats(vm)

    try:
        for index, src_port in enumerate(source_ports[:4], start=1):
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
                    "seq": 4095 * index,
                },
            )

        deadline = time.time() + 5
        while time.time() < deadline:
            stats = read_module_stats(vm)
            rejected = stats["half_open_rejected"] - baseline_stats["half_open_rejected"]
            admitted = count_nonzero_probe_hits(vm, synack_probe, synack_comments)
            if rejected == 2 and admitted == 2:
                break
            time.sleep(0.1)
        else:
            pytest.fail(
                "responder half-open limit did not reject excess bare SYNs: " f"stats={stats!r} admitted={admitted}"
            )

        wait_for_half_open_drain(vm, baseline_stats, expected_rst=2)

        run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": source_ports[4],
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": "syn",
                "seq": 4095 * 5,
            },
        )

        deadline = time.time() + 5
        while time.time() < deadline:
            stats = read_module_stats(vm)
            admitted = count_nonzero_probe_hits(vm, synack_probe, synack_comments)
            rejected = stats["half_open_rejected"] - baseline_stats["half_open_rejected"]
            if admitted == 3 and rejected == 2:
                break
            time.sleep(0.1)
        else:
            pytest.fail(
                "responder half-open slot should reopen after retry exhaustion: " f"stats={stats!r} admitted={admitted}"
            )
    finally:
        drop_synack.cleanup(vm)
        synack_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_initiator_half_open_limit_rejects_excess_udp(phantun_module, vm):
    phantun_module.load(
        managed_netns="all",
        managed_local_ports=MANAGED_LOCAL_PORTS,
        half_open_limit=2,
        handshake_timeout_ms=2000,
        handshake_retries=1,
    )
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    remote_ports = [PORTS_B[0], PORTS_B[1], 6666, 6667, 6668]
    syn_comments = [f"limited_syn_{port}" for port in remote_ports]
    drop_synack = make_netns_ingress_flag_drop_probe(
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
                "comment": f"drop_limited_synack_{dst_port}",
            }
            for dst_port in remote_ports
        ],
    )
    syn_probe = make_netns_output_flag_probe(
        vm,
        NS_A,
        [
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "flags_expr": "syn",
                "comment": f"limited_syn_{dst_port}",
            }
            for dst_port in remote_ports
        ],
    )
    baseline_stats = read_module_stats(vm)

    try:
        for dst_port in remote_ports[:4]:
            run_netns_scenario(
                vm,
                NS_A,
                "send_many",
                {
                    "bind_addr": NS_ADDR_A,
                    "bind_port": src_port,
                    "target_addr": NS_ADDR_B,
                    "target_port": dst_port,
                    "payloads": [f"payload-{dst_port}"],
                },
            )

        deadline = time.time() + 5
        while time.time() < deadline:
            stats = read_module_stats(vm)
            rejected = stats["half_open_rejected"] - baseline_stats["half_open_rejected"]
            dropped = stats["udp_packets_dropped"] - baseline_stats["udp_packets_dropped"]
            admitted = count_nonzero_probe_hits(vm, syn_probe, syn_comments)
            if rejected == 2 and dropped == 2 and admitted == 2:
                break
            time.sleep(0.1)
        else:
            pytest.fail(
                "initiator half-open limit did not reject excess outbound UDP: " f"stats={stats!r} admitted={admitted}"
            )

        wait_for_half_open_drain(vm, baseline_stats, expected_rst=2)

        run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": remote_ports[4],
                "payloads": ["payload-reopen"],
            },
        )

        deadline = time.time() + 5
        while time.time() < deadline:
            stats = read_module_stats(vm)
            admitted = count_nonzero_probe_hits(vm, syn_probe, syn_comments)
            rejected = stats["half_open_rejected"] - baseline_stats["half_open_rejected"]
            if admitted == 3 and rejected == 2:
                break
            time.sleep(0.1)
        else:
            pytest.fail(
                "initiator half-open slot should reopen after retry exhaustion: " f"stats={stats!r} admitted={admitted}"
            )
    finally:
        drop_synack.cleanup(vm)
        syn_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_handshake_request_loss_does_not_drop_later_payloads(phantun_module, vm):
    load_loss_module(phantun_module, handshake_request=REQ)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    probe = make_netns_ingress_payload_drop_probe(
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
                "comment": "drop_req",
            }
        ],
    )
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "recv_many",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 3,
        },
    )

    try:
        time.sleep(0.2)
        client_result = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["client-0", "client-1", "client-2"],
                "delay_ms": 400,
            },
        )
        time.sleep(1.25)
        probe.cleanup(vm)
        server_result = server.communicate(timeout=15)

        assert_completed(client_result, "request-loss sender")
        assert_completed(server_result, "request-loss receiver")

        server_data = parse_guest_json(server_result.stdout, "request-loss server stdout")
        if received_messages(server_data) != ["client-0", "client-1", "client-2"]:
            pytest.fail(
                "lost handshake_request must not cause later higher-sequence payloads to be dropped; "
                f"got {received_messages(server_data)!r}"
            )
    finally:
        probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_handshake_response_loss_does_not_drop_later_replies(phantun_module, vm):
    load_loss_module(phantun_module, handshake_request=REQ, handshake_response=RESP)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    probe = make_netns_ingress_payload_drop_probe(
        vm,
        NS_A,
        VETH_A,
        [
            {
                "src_addr": NS_ADDR_B,
                "src_port": dst_port,
                "dst_addr": NS_ADDR_A,
                "dst_port": src_port,
                "payload": RESP,
                "comment": "drop_resp",
            }
        ],
    )
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "recv_many_reply",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 3,
            "replies": ["reply-0", "reply-1", "reply-2"],
        },
    )

    try:
        time.sleep(0.2)
        client_result = run_netns_scenario(
            vm,
            NS_A,
            "send_many_recv",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["client-0", "client-1", "client-2"],
                "recv_count": 3,
                "delay_ms": 400,
            },
            timeout=20,
        )
        time.sleep(1.25)
        probe.cleanup(vm)
        server_result = server.communicate(timeout=20)

        assert_completed(client_result, "response-loss client")
        assert_completed(server_result, "response-loss server")

        client_data = parse_guest_json(client_result.stdout, "response-loss client stdout")
        server_data = parse_guest_json(server_result.stdout, "response-loss server stdout")
        if received_messages(server_data) != ["client-0", "client-1", "client-2"]:
            pytest.fail(f"unexpected responder receive set after response loss: {received_messages(server_data)!r}")
        if reply_messages(client_data) != ["reply-0", "reply-1", "reply-2"]:
            pytest.fail(
                "lost handshake_response must not cause later higher-sequence replies to be dropped; "
                f"got {reply_messages(client_data)!r}"
            )
    finally:
        probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_final_ack_shaping_payload_drop_is_one_shot(phantun_module, vm):
    load_loss_module(phantun_module, handshake_request=REQ)
    ensure_netns_topology(vm)

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    prefix = f"/tmp/phantun-final-ack-control-drop-{uuid.uuid4().hex}"
    final_ack_ready = f"{prefix}-capture-ready"
    server_ready = f"{prefix}-server-ready"
    replay_ready = f"{prefix}-replay-ready"
    final_ack_capture = spawn_netns_scenario(
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
    server = None
    replay_receiver = None
    try:
        wait_for_guest_ready_file(vm, final_ack_ready, timeout=5)
        server = spawn_netns_scenario(
            vm,
            NS_B,
            "recv_until_timeout",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "count": 1,
                "ready_file": server_ready,
                "timeout_sec": 20,
            },
        )
        wait_for_guest_ready_file(vm, server_ready, timeout=5)
        baseline_stats = read_module_stats(vm)

        client_result = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["client-final-ack"],
            },
        )
        capture_result = final_ack_capture.communicate(timeout=20)
        server_result = server.communicate(timeout=20)
        assert_completed(client_result, "final-ACK sender")
        assert_completed(capture_result, "capture final ACK control payload")
        assert_completed(server_result, "final-ACK receiver")

        final_ack_data = parse_guest_json(capture_result.stdout, "captured final ACK control payload")
        if (final_ack_data.get("flags", 0) & 0x12) != 0x10:
            pytest.fail(f"expected final ACK control payload, got {final_ack_data!r}")

        server_data = parse_guest_json(server_result.stdout, "final-ACK receiver stdout")
        if received_messages(server_data) != ["client-final-ack"]:
            pytest.fail(f"final-ACK receiver saw unexpected payloads: {server_data!r}")

        expected_drops = baseline_stats["shaping_payloads_dropped"] + 1
        first_stats = read_module_stats(vm)
        if first_stats["shaping_payloads_dropped"] != expected_drops:
            pytest.fail(
                "final ACK handshake_request must be accounted exactly once as a dropped shaping payload: "
                f"before={baseline_stats!r} after={first_stats!r}"
            )

        replay_receiver = spawn_netns_scenario(
            vm,
            NS_B,
            "recv_until_timeout",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "count": 1,
                "ready_file": replay_ready,
                "timeout_sec": 20,
            },
        )
        wait_for_guest_ready_file(vm, replay_ready, timeout=5)

        replay_result = run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": "ack",
                "seq": final_ack_data["seq"],
                "ack": final_ack_data["ack"],
                "payload": REQ,
            },
        )
        replay_receiver_result = replay_receiver.communicate(timeout=20)
        assert_completed(replay_result, "final-ACK replay sender")
        assert_completed(replay_receiver_result, "final-ACK replay receiver")
        replay_data = parse_guest_json(replay_receiver_result.stdout, "final-ACK replay receiver stdout")
        if received_messages(replay_data) != [REQ]:
            pytest.fail(f"final-ACK replay was not delivered after consuming the reservation: {replay_data!r}")
        time.sleep(0.2)
        replay_stats = read_module_stats(vm)
        if replay_stats["shaping_payloads_dropped"] != expected_drops:
            pytest.fail(
                "replayed final ACK handshake_request reused a consumed shaping reservation: "
                f"baseline={baseline_stats!r} first={first_stats!r} replay={replay_stats!r}"
            )
    finally:
        for process in (server, replay_receiver, final_ack_capture):
            if process is not None and process.proc.poll() is None:
                process.terminate()
        vm.run(["rm", "-f", final_ack_ready, server_ready, replay_ready], check=False)
        cleanup_netns_topology(vm)


def test_delayed_handshake_response_control_drop_acks_after_recent_tx(phantun_module, vm):
    load_loss_module(phantun_module, handshake_request=REQ, handshake_response=RESP)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    prefix = f"/tmp/phantun-control-drop-ack-{uuid.uuid4().hex}"
    syn_ready = f"{prefix}-syn-ready"
    synack_ready = f"{prefix}-synack-ready"
    server_ready = f"{prefix}-server-ready"
    continue_file = f"{prefix}-continue"
    replay_ready = f"{prefix}-replay-ready"
    inject_config_file = f"{prefix}-inject.json"
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
            "ready_file": syn_ready,
            "timeout_sec": 20,
        },
    )
    synack_capture = spawn_netns_scenario(
        vm,
        NS_A,
        "capture_tcp_packet",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "target_addr": NS_ADDR_A,
            "target_port": src_port,
            "payload": "",
            "ready_file": synack_ready,
            "timeout_sec": 20,
        },
    )
    drop_response = make_netns_ingress_payload_drop_probe(
        vm,
        NS_A,
        VETH_A,
        [
            {
                "src_addr": NS_ADDR_B,
                "src_port": dst_port,
                "dst_addr": NS_ADDR_A,
                "dst_port": src_port,
                "payload": RESP,
                "comment": "drop_resp_before_control_inject",
            }
        ],
    )
    ack_probe = make_netns_output_ipv4_pure_ack_probe(
        vm,
        NS_A,
        NS_ADDR_A,
        src_port,
        NS_ADDR_B,
        dst_port,
    )
    server = None
    client = None
    replay_receiver = None
    try:
        wait_for_guest_ready_file(vm, syn_ready, timeout=5)
        wait_for_guest_ready_file(vm, synack_ready, timeout=5)
        server = spawn_netns_scenario(
            vm,
            NS_B,
            "recv_many_then_inject_tcp",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "count": 2,
                "inject_after_count": 2,
                "inject_config_file": inject_config_file,
                "ready_file": server_ready,
                "barrier_timeout_sec": 12,
                "timeout_sec": 20,
            },
        )
        wait_for_guest_ready_file(vm, server_ready, timeout=5)
        client = spawn_netns_scenario(
            vm,
            NS_A,
            "send_many_with_barrier",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["client-0", "client-1"],
                "continue_file": continue_file,
                "barrier_timeout_sec": 12,
                "timeout_sec": 20,
            },
        )

        syn_result = syn_capture.communicate(timeout=20)
        synack_result = synack_capture.communicate(timeout=20)
        assert_completed(syn_result, "capture initiator SYN")
        assert_completed(synack_result, "capture responder SYN|ACK")
        syn_data = parse_guest_json(syn_result.stdout, "captured initiator SYN")
        synack_data = parse_guest_json(synack_result.stdout, "captured responder SYN|ACK")
        if (syn_data.get("flags", 0) & 0x12) != 0x02:
            pytest.fail(f"expected bare SYN, got {syn_data!r}")
        if (synack_data.get("flags", 0) & 0x12) != 0x12:
            pytest.fail(f"expected SYN|ACK, got {synack_data!r}")

        deadline = time.time() + 5
        while time.time() < deadline:
            if drop_response.packets(vm, "drop_resp_before_control_inject") > 0:
                break
            time.sleep(0.05)
        else:
            pytest.fail("failed to drop the original handshake_response before delayed injection")

        drop_response.cleanup(vm)
        baseline_ack = ack_probe.packets(vm, "pure_ipv4_ack")
        baseline_stats = read_module_stats(vm)
        inject_config = {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "target_addr": NS_ADDR_A,
            "target_port": src_port,
            "flags": "ack",
            "seq": synack_data["seq"] + 1,
            "ack": syn_data["seq"] + 1 + len(REQ),
            "payload": RESP,
        }
        write_guest_text(vm, inject_config_file, json.dumps(inject_config))
        write_guest_text(vm, continue_file, "ready\n")

        client_result = client.communicate(timeout=20)
        server_result = server.communicate(timeout=20)
        assert_completed(client_result, "control-drop ACK sender")
        assert_completed(server_result, "control-drop ACK receiver")
        client_data = parse_guest_json(client_result.stdout, "control-drop ACK sender stdout")
        server_data = parse_guest_json(server_result.stdout, "control-drop ACK receiver stdout")
        if client_data.get("sent") != ["client-0", "client-1"]:
            pytest.fail(f"control-drop ACK sender sent unexpected payloads: {client_data!r}")
        if received_messages(server_data) != ["client-0", "client-1"]:
            pytest.fail(f"control-drop ACK receiver saw unexpected payloads: {server_data!r}")
        if not server_data.get("injected"):
            pytest.fail(f"control-drop ACK receiver did not inject delayed response: {server_data!r}")

        deadline = time.time() + 5
        while time.time() < deadline:
            final_ack = ack_probe.packets(vm, "pure_ipv4_ack")
            if final_ack > baseline_ack:
                break
            time.sleep(0.05)
        else:
            pytest.fail("delayed control-payload drop did not emit its immediate pure ACK")

        final_stats = read_module_stats(vm)
        if final_stats["idle_acks_suppressed"] != baseline_stats["idle_acks_suppressed"]:
            pytest.fail(
                "control-payload drops must not use the idle ACK suppression path: "
                f"before={baseline_stats!r} after={final_stats!r}"
            )
        expected_drops = baseline_stats["shaping_payloads_dropped"] + 1
        if final_stats["shaping_payloads_dropped"] != expected_drops:
            pytest.fail(
                "delayed handshake_response must be accounted exactly once as a dropped shaping payload: "
                f"before={baseline_stats!r} after={final_stats!r}"
            )

        replay_receiver = spawn_netns_scenario(
            vm,
            NS_A,
            "recv_until_timeout",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "count": 1,
                "ready_file": replay_ready,
                "timeout_sec": 20,
            },
        )
        wait_for_guest_ready_file(vm, replay_ready, timeout=5)

        replay_result = run_netns_scenario(vm, NS_B, "send_tcp_packet", inject_config)
        replay_receiver_result = replay_receiver.communicate(timeout=20)
        assert_completed(replay_result, "control-drop replay sender")
        assert_completed(replay_receiver_result, "control-drop replay receiver")
        replay_data = parse_guest_json(replay_receiver_result.stdout, "control-drop replay receiver stdout")
        if received_messages(replay_data) != [RESP]:
            pytest.fail(
                f"delayed handshake_response replay was not delivered after consuming the reservation: {replay_data!r}"
            )
        time.sleep(0.2)
        replay_stats = read_module_stats(vm)
        if replay_stats["shaping_payloads_dropped"] != expected_drops:
            pytest.fail(
                "replayed delayed handshake_response reused a consumed shaping reservation: "
                f"baseline={baseline_stats!r} first={final_stats!r} replay={replay_stats!r}"
            )
    finally:
        for process in (client, server, replay_receiver, syn_capture, synack_capture):
            if process is not None and process.proc.poll() is None:
                process.terminate()
        drop_response.cleanup(vm)
        ack_probe.cleanup(vm)
        vm.run(
            ["rm", "-f", syn_ready, synack_ready, server_ready, replay_ready, continue_file, inject_config_file],
            check=False,
        )
        cleanup_netns_topology(vm)


def test_lost_handshake_request_with_response_enabled_does_not_trigger_rstack(phantun_module, vm):
    load_loss_module(phantun_module, handshake_request=REQ, handshake_response=RESP)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
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
                "comment": "drop_req_with_resp",
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
                "comment": "bad_followup_rst",
            }
        ],
    )

    try:
        baseline_bad_followup_rst = rst_probe.packets(vm, "bad_followup_rst")
        client_result = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["client-0"],
            },
        )
        assert_completed(client_result, "response-enabled request-loss sender")
        time.sleep(0.5)

        if rst_probe.packets(vm, "bad_followup_rst") != baseline_bad_followup_rst:
            pytest.fail(
                "lost handshake_request with handshake_response enabled must not turn the "
                "next initiator payload into a bad final ACK reset"
            )
    finally:
        drop_request.cleanup(vm)
        rst_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_duplicate_outbound_udp_while_half_open_queues_only_one_skb(phantun_module, vm):
    load_loss_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    initial_stats = read_module_stats(vm)
    probe = make_netns_ingress_flag_drop_probe(
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
                "comment": "drop_synack",
            }
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
                "payloads": ["client-0", "client-1"],
            },
        )
        time.sleep(1.25)
        probe.cleanup(vm)
        server_result = server.communicate(timeout=12)
        assert_completed(client, "duplicate-half-open sender")
        assert_completed(server_result, "duplicate-half-open receiver")

        server_data = parse_guest_json(server_result.stdout, "duplicate-half-open server stdout")
        if received_messages(server_data) != ["client-0"]:
            pytest.fail(f"expected only the first half-open payload to survive, got {received_messages(server_data)!r}")

        final_stats = read_module_stats(vm)
        if final_stats["flows_created"] - initial_stats["flows_created"] != 2:
            pytest.fail(f"expected one initiator and one responder flow, got {final_stats!r}")
        if final_stats["udp_packets_queued"] - initial_stats["udp_packets_queued"] != 1:
            pytest.fail(f"expected exactly one queued UDP packet while half-open, got {final_stats!r}")
        if final_stats["udp_packets_dropped"] <= initial_stats["udp_packets_dropped"]:
            pytest.fail(f"expected later duplicate UDP during half-open to be dropped, got {final_stats!r}")
        if final_stats["udp_queue_full_dropped"] <= initial_stats["udp_queue_full_dropped"]:
            pytest.fail(f"expected later duplicate UDP to count as queue-full drop, got {final_stats!r}")
    finally:
        probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_responder_reply_waits_for_ack_covering_handshake_response(phantun_module, vm):
    load_loss_module(phantun_module, handshake_request=REQ, handshake_response=RESP)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    drop_response = make_netns_ingress_payload_drop_probe(
        vm,
        NS_A,
        VETH_A,
        [
            {
                "src_addr": NS_ADDR_B,
                "src_port": dst_port,
                "dst_addr": NS_ADDR_A,
                "dst_port": src_port,
                "payload": RESP,
                "comment": "drop_resp_hold",
            }
        ],
    )
    drop_client_payload = make_netns_ingress_payload_drop_probe(
        vm,
        NS_B,
        VETH_B,
        [
            {
                "src_addr": NS_ADDR_A,
                "src_port": src_port,
                "dst_addr": NS_ADDR_B,
                "dst_port": dst_port,
                "payload": "client-0",
                "comment": "drop_client0",
            }
        ],
    )
    reply_probe = make_netns_tcp_payload_probe(
        vm,
        NS_B,
        [
            {
                "src_addr": NS_ADDR_B,
                "src_port": dst_port,
                "dst_addr": NS_ADDR_A,
                "dst_port": src_port,
                "payload": "server-0",
                "comment": "queued_reply",
                "action": "accept",
            }
        ],
    )
    delayed_sender = spawn_netns_scenario(
        vm,
        NS_B,
        "delayed_send",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "target_addr": NS_ADDR_A,
            "target_port": src_port,
            "payload": "server-0",
            "delay_ms": 300,
        },
    )

    try:
        time.sleep(0.2)
        client_result_1 = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["client-0"],
            },
        )
        assert_completed(client_result_1, "response-pending sender 1")
        delayed_sender_result = delayed_sender.communicate(timeout=10)
        assert_completed(delayed_sender_result, "delayed responder sender")
        time.sleep(0.5)
        if reply_probe.packets(vm, "queued_reply") != 0:
            pytest.fail("responder data must stay queued until an initiator ACK covers handshake_response")

        drop_response.cleanup(vm)
        drop_client_payload.cleanup(vm)
        client_result_2 = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["client-1"],
            },
        )
        assert_completed(client_result_2, "response-pending sender 2")
        time.sleep(0.5)
        if reply_probe.packets(vm, "queued_reply") == 0:
            pytest.fail(
                "queued responder payload was never released after a later initiator ACK covered handshake_response"
            )
    finally:
        drop_response.cleanup(vm)
        drop_client_payload.cleanup(vm)
        reply_probe.cleanup(vm)
        cleanup_netns_topology(vm)
