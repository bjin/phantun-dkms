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
    make_netns_ingress_flag_drop_probe,
    make_netns_ingress_payload_drop_probe,
    make_netns_output_flag_probe,
    make_netns_tcp_payload_probe,
    parse_guest_json,
    read_module_stats,
    require_guest_command,
    run_netns_scenario,
    spawn_netns_scenario,
)

MANAGED_LOCAL_PORTS = "2222,3333,4444,5555"
REQ = "HSREQ42"
RESP = "HSRESP42"


def load_loss_module(phantun_module, **kwargs):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS, **kwargs)


def assert_completed(result, label):
    if result.returncode != 0:
        pytest.fail(f"{label} failed: {result.stderr!r}")


def received_messages(payload):
    return [entry["message"] for entry in payload.get("received", [])]


def reply_messages(payload):
    return [entry["message"] for entry in payload.get("replies", [])]


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
        deadline = time.time() + 15
        while time.time() < deadline:
            stats = read_module_stats(vm)
            if (
                stats["rst_sent"] > baseline_stats["rst_sent"]
                and stats["flows_current"] == baseline_stats["flows_current"]
            ):
                break
            time.sleep(0.1)
        else:
            pytest.fail(
                "half-open flow should be unhashed promptly after retry exhaustion: "
                f"baseline={baseline_stats!r} current={stats!r}"
            )

        if synack_probe.packets(vm, "sent_exhausted_synack") <= baseline_synack:
            pytest.fail("expected responder to emit SYN|ACK before retry exhaustion")

        if stats["flows_created"] <= baseline_stats["flows_created"]:
            pytest.fail(
                "expected responder half-open flow creation before retry exhaustion: "
                f"baseline={baseline_stats!r} current={stats!r}"
            )
    finally:
        drop_synack.cleanup(vm)
        synack_probe.cleanup(vm)
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
