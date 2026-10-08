"""handshake_request/handshake_response control payloads: injection, hiding, loss, and sequence slots."""

import base64
import json
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
    REQ,
    RESP,
    VETH_A,
    VETH_B,
    assert_completed,
    cleanup_netns_topology,
    ensure_netns_topology,
    kernel_has_base64_support,
    load_fast_liveness_module,
    load_managed_module,
    make_netns_ingress_payload_drop_probe,
    make_netns_output_flag_probe,
    make_netns_output_ipv4_pure_ack_probe,
    make_netns_tcp_payload_probe,
    parse_guest_json,
    read_module_stats,
    received_messages,
    reply_messages,
    require_guest_command,
    run_in_netns,
    run_netns_scenario,
    spawn_netns_scenario,
    wait_for_guest_ready_file,
    write_guest_text,
)

REQ_BASE64 = "base64:" + base64.b64encode(REQ.encode()).decode()
RESP_BASE64 = "base64:" + base64.b64encode(RESP.encode()).decode()


def test_handshake_request_is_injected_and_hidden_from_udp_app(phantun_module, vm):
    load_managed_module(phantun_module, handshake_request=REQ)
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
        if received_messages(server_data) != ["client-0", "client-1"]:
            pytest.fail(f"unexpected responder payloads: {received_messages(server_data)!r}")
        if REQ in received_messages(server_data):
            pytest.fail("handshake_request leaked to responder UDP app")
        if probe.packets(vm, "req_only") == 0:
            pytest.fail("did not observe handshake_request on the TCP output path")
    finally:
        probe.cleanup(vm)
        cleanup_netns_topology(vm)


@pytest.mark.parametrize(
    ("request_param", "response_param"),
    [
        pytest.param(REQ, RESP, id="plain"),
        pytest.param(REQ_BASE64, RESP_BASE64, id="base64"),
    ],
)
def test_handshake_request_and_response_are_both_hidden_from_udp_apps(
    phantun_module, vm, request_param, response_param
):
    if request_param.startswith("base64:") and not kernel_has_base64_support(vm):
        pytest.skip("kernel lacks in-kernel base64 decode support")

    load_managed_module(
        phantun_module,
        handshake_request=request_param,
        handshake_response=response_param,
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

        if received_messages(server_data) != ["client-0", "client-1"]:
            pytest.fail(f"unexpected responder payloads: {received_messages(server_data)!r}")
        if REQ in received_messages(server_data):
            pytest.fail("handshake_request leaked to responder UDP app")
        if reply_messages(client_data) != ["reply-0", "reply-1"]:
            pytest.fail(f"unexpected initiator replies: {reply_messages(client_data)!r}")
        if RESP in reply_messages(client_data):
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
    load_managed_module(phantun_module, handshake_response=RESP)
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


def test_final_ack_shaping_payload_drop_is_one_shot(phantun_module, vm):
    load_managed_module(phantun_module, handshake_request=REQ)
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


def test_handshake_request_loss_does_not_drop_later_payloads(phantun_module, vm):
    load_managed_module(phantun_module, handshake_request=REQ)
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
    load_managed_module(phantun_module, handshake_request=REQ, handshake_response=RESP)
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
    load_managed_module(phantun_module, handshake_request=REQ, handshake_response=RESP)
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


def test_delayed_handshake_response_control_drop_acks_after_recent_tx(phantun_module, vm):
    load_managed_module(phantun_module, handshake_request=REQ, handshake_response=RESP)
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


def test_responder_reply_waits_for_ack_covering_handshake_response(phantun_module, vm):
    load_managed_module(phantun_module, handshake_request=REQ, handshake_response=RESP)
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


def test_delayed_handshake_request_does_not_regress_ack(phantun_module, vm):
    load_fast_liveness_module(phantun_module, handshake_request=REQ)
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


def test_ignore_slot_disarms_after_half_space_ack_advance(phantun_module, vm):
    # Same shape as load_fast_liveness_module but with a 10s liveness budget: this
    # test spans several guest round-trips between establishment and the
    # forged probes, and the 2s recovery deadline can legitimately tear the
    # flow down during a scheduling stall on slow nested-QEMU runners.
    phantun_module.load(
        managed_netns="all",
        managed_local_ports=MANAGED_LOCAL_PORTS,
        keepalive_interval_sec=1,
        keepalive_misses=10,
        handshake_retries=20,
        handshake_request=REQ,
    )
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
    # Dropping the reserved handshake_request on ingress leaves the responder's
    # first-payload ignore slot armed at I+1 after the flow is established by
    # the higher-sequence msg1 packet.
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
                "comment": "drop_slot_req",
            }
        ],
    )
    ready_file_1 = f"/tmp/phantun-slot1-{uuid.uuid4().hex}"
    ready_file_2 = f"/tmp/phantun-slot2-{uuid.uuid4().hex}"
    server_1 = spawn_netns_scenario(
        vm,
        NS_B,
        "recv_until_timeout",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 1,
            "timeout_sec": 15,
            "ready_file": ready_file_1,
        },
    )

    try:
        wait_for_guest_ready_file(vm, syn_ready_file, timeout=30)
        wait_for_guest_ready_file(vm, ready_file_1, timeout=10)

        # Phase 1: establish the flow while REQ is dropped on ingress. msg1
        # received by the application proves the responder is ESTABLISHED and
        # msg1 was reinjected -- only then is forging safe (a forged packet
        # reaching a still-SYN_RCVD responder would destroy the flow).
        client_result = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["msg1"],
            },
        )
        assert_completed(client_result, "send msg1")

        syn_result = syn_capture.communicate(timeout=30)
        assert_completed(syn_result, "capture initiator SYN")
        syn_data = parse_guest_json(syn_result.stdout, "captured initiator SYN")
        if (syn_data.get("flags", 0) & 0x02) == 0 or (syn_data.get("flags", 0) & 0x10) != 0:
            pytest.fail(f"expected bare SYN, got {syn_data!r}")
        drop_seq = (syn_data["seq"] + 1) & 0xFFFFFFFF

        server_1_result = server_1.communicate(timeout=25)
        assert_completed(server_1_result, "slot server phase 1")
        payload_1 = parse_guest_json(server_1_result.stdout, "slot server phase 1")
        if [entry["message"] for entry in payload_1["received"]] != ["msg1"]:
            pytest.fail(f"phase 1 delivery mismatch: {payload_1!r}")
        if payload_1["timed_out"] is not False:
            pytest.fail(f"phase 1 server timed out: {payload_1!r}")

        # Phase 2: fresh listener before any forging so jumps cannot land in a
        # listener gap between the two sockets.
        server_2 = spawn_netns_scenario(
            vm,
            NS_B,
            "recv_until_timeout",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "count": 3,
                "timeout_sec": 25,
                "ready_file": ready_file_2,
            },
        )
        wait_for_guest_ready_file(vm, ready_file_2, timeout=10)

        if drop_request.packets(vm, "drop_slot_req") == 0:
            pytest.fail("reserved handshake_request was never seen/dropped; slot is not armed")

        # Advance the responder's ack in two sub-half-space hops so the final
        # distance from the armed slot is exactly 2**31 (the disarm boundary).
        for label, offset in (("jump1", 0x40000000), ("jump2", 0x80000000)):
            jump_result = run_netns_scenario(
                vm,
                NS_A,
                "send_tcp_packet",
                {
                    "bind_addr": NS_ADDR_A,
                    "bind_port": src_port,
                    "target_addr": NS_ADDR_B,
                    "target_port": dst_port,
                    "flags": "ack",
                    "seq": (drop_seq + offset - len(label)) & 0xFFFFFFFF,
                    "ack": 1,
                    "payload": label,
                },
            )
            assert_completed(jump_result, f"inject {label}")

        mid = read_module_stats(vm)
        # A payload at the armed sequence itself: with the slot disarmed it
        # must reach the application instead of being eaten as shaping traffic.
        # Its payload differs from REQ so the still-installed drop rule does
        # not match (slot matching is by sequence only).
        wrapped_result = run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": "ack",
                "seq": drop_seq,
                "ack": 1,
                "payload": "wrapped",
            },
        )
        assert_completed(wrapped_result, "inject wrapped payload")

        server_2_result = server_2.communicate(timeout=35)
        assert_completed(server_2_result, "slot server phase 2")
        payload_2 = parse_guest_json(server_2_result.stdout, "slot server phase 2")
        messages = [entry["message"] for entry in payload_2["received"]]
        if messages != ["jump1", "jump2", "wrapped"]:
            pytest.fail(f"expected ['jump1', 'jump2', 'wrapped'], got {messages!r}")
        if payload_2["timed_out"] is not False:
            pytest.fail(f"phase 2 server timed out: {payload_2!r}")
        final_stats = read_module_stats(vm)
        if final_stats["shaping_payloads_dropped"] != mid["shaping_payloads_dropped"]:
            pytest.fail(
                f"wrapped payload was eaten as shaping traffic: "
                f"{mid['shaping_payloads_dropped']} -> {final_stats['shaping_payloads_dropped']}"
            )
    finally:
        drop_request.cleanup(vm)
        vm.run(["rm", "-f", syn_ready_file, ready_file_1, ready_file_2], check=False)
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
