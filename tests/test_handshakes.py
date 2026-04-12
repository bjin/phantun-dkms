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
    VETH_B,
    assert_completed,
    cleanup_netns_topology,
    ensure_netns_topology,
    make_netns_ingress_payload_drop_probe,
    make_netns_output_flag_probe,
    make_netns_tcp_payload_probe,
    parse_guest_json,
    received_entry_messages,
    received_plain_messages,
    reply_entry_messages,
    require_guest_command,
    run_netns_scenario,
    spawn_netns_scenario,
    wait_for_guest_ready_file,
)

MANAGED_LOCAL_PORTS = "2222,3333,4444,5555"
REQ = "HSREQ42"
RESP = "HSRESP42"


def load_handshake_module(phantun_module, **kwargs):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS, **kwargs)


def test_handshake_request_is_injected_and_hidden_from_udp_app(phantun_module, vm):
    load_handshake_module(phantun_module, handshake_request=REQ)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    probe = make_netns_tcp_payload_probe(
        vm,
        NS_A,
        [
            {
                "src_addr": NS_ADDR_A,
                "src_port": src_port,
                "dst_addr": NS_ADDR_B,
                "dst_port": dst_port,
                "payload": REQ,
                "comment": "req_only",
                "action": "accept",
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
            "count": 2,
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
                "payloads": ["client-0", "client-1"],
                "delay_ms": 100,
            },
        )
        server_result = server.communicate(timeout=15)

        assert_completed(client_result, "request-only sender")
        assert_completed(server_result, "request-only receiver")

        server_data = parse_guest_json(server_result.stdout, "request-only server stdout")
        if received_entry_messages(server_data) != ["client-0", "client-1"]:
            pytest.fail(f"unexpected responder payloads: {received_entry_messages(server_data)!r}")
        if REQ in received_entry_messages(server_data):
            pytest.fail("handshake_request leaked to responder UDP app")
        if probe.packets(vm, "req_only") == 0:
            pytest.fail("did not observe handshake_request on the TCP output path")
    finally:
        probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_handshake_request_and_response_are_both_hidden_from_udp_apps(phantun_module, vm):
    load_handshake_module(
        phantun_module,
        handshake_request=REQ,
        handshake_response=RESP,
    )
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    probe_a = make_netns_tcp_payload_probe(
        vm,
        NS_A,
        [
            {
                "src_addr": NS_ADDR_A,
                "src_port": src_port,
                "dst_addr": NS_ADDR_B,
                "dst_port": dst_port,
                "payload": REQ,
                "comment": "req_both",
                "action": "accept",
            }
        ],
    )
    probe_b = make_netns_tcp_payload_probe(
        vm,
        NS_B,
        [
            {
                "src_addr": NS_ADDR_B,
                "src_port": dst_port,
                "dst_addr": NS_ADDR_A,
                "dst_port": src_port,
                "payload": RESP,
                "comment": "resp_both",
                "action": "accept",
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
            "count": 2,
            "replies": ["reply-0", "reply-1"],
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
                "payloads": ["client-0", "client-1"],
                "recv_count": 2,
                "delay_ms": 100,
            },
            timeout=20,
        )
        server_result = server.communicate(timeout=20)

        assert_completed(client_result, "request-response client")
        assert_completed(server_result, "request-response server")

        server_data = parse_guest_json(server_result.stdout, "request-response server stdout")
        client_data = parse_guest_json(client_result.stdout, "request-response client stdout")

        if received_entry_messages(server_data) != ["client-0", "client-1"]:
            pytest.fail(f"unexpected responder payloads: {received_entry_messages(server_data)!r}")
        if REQ in received_entry_messages(server_data):
            pytest.fail("handshake_request leaked to responder UDP app")
        if reply_entry_messages(client_data) != ["reply-0", "reply-1"]:
            pytest.fail(f"unexpected initiator replies: {reply_entry_messages(client_data)!r}")
        if RESP in reply_entry_messages(client_data):
            pytest.fail("handshake_response leaked to initiator UDP app")
        if probe_a.packets(vm, "req_both") == 0:
            pytest.fail("did not observe handshake_request on the initiator TCP output path")
        if probe_b.packets(vm, "resp_both") == 0:
            pytest.fail("did not observe handshake_response on the responder TCP output path")
    finally:
        probe_a.cleanup(vm)
        probe_b.cleanup(vm)
        cleanup_netns_topology(vm)


def test_handshake_response_without_request_is_disabled(phantun_module, vm):
    load_handshake_module(phantun_module, handshake_response=RESP)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    probe = make_netns_tcp_payload_probe(
        vm,
        NS_B,
        [
            {
                "src_addr": NS_ADDR_B,
                "src_port": dst_port,
                "dst_addr": NS_ADDR_A,
                "dst_port": src_port,
                "payload": RESP,
                "comment": "resp_disabled",
                "action": "accept",
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
        client_result = run_netns_scenario(
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
        server_result = server.communicate(timeout=10)

        assert_completed(client_result, "response-only client")
        assert_completed(server_result, "response-only server")

        server_data = parse_guest_json(server_result.stdout, "response-only server stdout")
        client_data = parse_guest_json(client_result.stdout, "response-only client stdout")

        if server_data.get("received") != "ping":
            pytest.fail(f"unexpected responder payload: {server_data.get('received')!r}")
        if client_data.get("reply") != "pong":
            pytest.fail(f"unexpected initiator reply: {client_data.get('reply')!r}")
        if probe.packets(vm, "resp_disabled") != 0:
            pytest.fail("handshake_response should not be emitted when handshake_request is unset")
    finally:
        probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_delayed_handshake_request_does_not_regress_ack(phantun_module, vm):
    load_handshake_module(phantun_module, handshake_request=REQ)
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
        if received_plain_messages(server_data) != ["msg1", "msg2"]:
            pytest.fail(
                f"delayed REQ injection corrupted delivery: "
                f"expected ['msg1', 'msg2'], got {received_plain_messages(server_data)!r}"
            )
    finally:
        drop_request.cleanup(vm)
        vm.run(["rm", "-f", syn_ready_file], check=False)
        cleanup_netns_topology(vm)


def test_skipped_handshake_request_does_not_accept_future_sequence_gap(phantun_module, vm):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS, handshake_request=REQ)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    syn_ready_file = f"/tmp/phantun-gap-syn-{uuid.uuid4().hex}"
    capture = spawn_netns_scenario(
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
                "comment": "drop_gap_req",
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
                "comment": "gap_rst",
            }
        ],
    )
    receiver = spawn_netns_scenario(
        vm,
        NS_B,
        "recv_many",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 1,
            "timeout_sec": 15,
        },
    )

    try:
        wait_for_guest_ready_file(vm, syn_ready_file, timeout=30)
        time.sleep(0.2)
        sender_result = run_netns_scenario(
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
        receiver_result = receiver.communicate(timeout=15)
        capture_result = capture.communicate(timeout=30)

        assert_completed(sender_result, "gap sender")
        assert_completed(receiver_result, "gap receiver")
        assert_completed(capture_result, "gap capture")

        captured = parse_guest_json(capture_result.stdout, "gap capture stdout")
        baseline_rst = rst_probe.packets(vm, "gap_rst")

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
                "seq": captured["seq"] + 1 + len(REQ) + len("client-0") + 1000,
                "ack": 1 + len(REQ),
                "payload": "future",
            },
        )
        time.sleep(0.2)

        if rst_probe.packets(vm, "gap_rst") <= baseline_rst:
            pytest.fail("skipped handshake_request must not leave a permanent future-sequence bypass")
    finally:
        drop_request.cleanup(vm)
        rst_probe.cleanup(vm)
        vm.run(["rm", "-f", syn_ready_file], check=False)
        cleanup_netns_topology(vm)
