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
    parse_guest_json,
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
            pytest.fail(
                f"unexpected client reply after SYN loss: {client_data.get('reply')!r}"
            )
        if server_data.get("received") != "ping":
            pytest.fail(
                f"unexpected server payload after SYN loss: {server_data.get('received')!r}"
            )
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
        assert_completed(client_result, "synack-loss client")
        assert_completed(server_result, "synack-loss server")

        client_data = parse_guest_json(
            client_result.stdout, "synack-loss client stdout"
        )
        server_data = parse_guest_json(
            server_result.stdout, "synack-loss server stdout"
        )
        if client_data.get("reply") != "pong":
            pytest.fail(
                f"unexpected client reply after SYN|ACK loss: {client_data.get('reply')!r}"
            )
        if server_data.get("received") != "ping":
            pytest.fail(
                f"unexpected server payload after SYN|ACK loss: {server_data.get('received')!r}"
            )
    finally:
        probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_handshake_request_loss_drops_one_later_payload(phantun_module, vm):
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
                "payloads": ["client-0", "client-1", "client-2"],
                "delay_ms": 400,
            },
        )
        time.sleep(1.25)
        probe.cleanup(vm)
        server_result = server.communicate(timeout=15)

        assert_completed(client_result, "request-loss sender")
        assert_completed(server_result, "request-loss receiver")

        server_data = parse_guest_json(
            server_result.stdout, "request-loss server stdout"
        )
        if received_messages(server_data) != ["client-1", "client-2"]:
            pytest.fail(
                "lost handshake_request should cause exactly one later payload drop; "
                f"got {received_messages(server_data)!r}"
            )
    finally:
        probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_handshake_response_loss_drops_one_later_reply(phantun_module, vm):
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
                "recv_count": 2,
                "delay_ms": 400,
            },
            timeout=20,
        )
        time.sleep(1.25)
        probe.cleanup(vm)
        server_result = server.communicate(timeout=20)

        assert_completed(client_result, "response-loss client")
        assert_completed(server_result, "response-loss server")

        client_data = parse_guest_json(
            client_result.stdout, "response-loss client stdout"
        )
        server_data = parse_guest_json(
            server_result.stdout, "response-loss server stdout"
        )
        if received_messages(server_data) != ["client-0", "client-1", "client-2"]:
            pytest.fail(
                f"unexpected responder receive set after response loss: {received_messages(server_data)!r}"
            )
        if reply_messages(client_data) != ["reply-1", "reply-2"]:
            pytest.fail(
                "lost handshake_response should cause exactly one later responder payload drop; "
                f"got {reply_messages(client_data)!r}"
            )
    finally:
        probe.cleanup(vm)
        cleanup_netns_topology(vm)
