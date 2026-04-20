import base64
import time

import pytest

from helpers import (
    NS_A,
    NS_ADDR_A,
    NS_ADDR_B,
    NS_B,
    PORTS_A,
    PORTS_B,
    assert_completed,
    cleanup_netns_topology,
    ensure_netns_topology,
    kernel_has_base64_support,
    make_netns_tcp_payload_probe,
    parse_guest_json,
    require_guest_command,
    run_netns_scenario,
    spawn_netns_scenario,
)

MANAGED_LOCAL_PORTS = "2222,3333,4444,5555"
REQ = "HSREQ42"
RESP = "HSRESP42"

REQ_BASE64 = "base64:" + base64.b64encode(REQ.encode()).decode()
RESP_BASE64 = "base64:" + base64.b64encode(RESP.encode()).decode()


def load_handshake_module(phantun_module, **kwargs):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS, **kwargs)


def received_messages(payload):
    return [entry["message"] for entry in payload.get("received", [])]


def reply_messages(payload):
    return [entry["message"] for entry in payload.get("replies", [])]


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

    load_handshake_module(
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
