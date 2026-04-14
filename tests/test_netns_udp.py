import time
import uuid

import pytest

from helpers import (
    NS_A,
    NS_ADDR_A,
    NS_ADDR_B,
    NS_B,
    NetnsNftProbe,
    PORTS_A,
    PORTS_B,
    assert_completed,
    cleanup_netns_topology,
    ensure_netns_topology,
    make_netns_output_probe,
    parse_guest_json,
    probe_comment,
    require_guest_command,
    run_in_netns,
    run_netns_scenario,
    spawn_netns_scenario,
)

MANAGED_LOCAL_PORTS = "2222,3333,4444,5555"


def load_netns_module(phantun_module):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS)


# Build small INPUT policies that mimic stateful host firewalls. The reply path
# should survive on conntrack state alone when there is no explicit UDP allow.
def make_netns_input_probe(vm, namespace, dst_port, allow_udp_dport):
    table_name = f"phantun_in_valid_{uuid.uuid4().hex[:8]}"
    run_in_netns(vm, namespace, ["nft", "delete", "table", "inet", table_name], check=False)
    run_in_netns(vm, namespace, ["nft", "add", "table", "inet", table_name])
    run_in_netns(
        vm,
        namespace,
        [
            "nft",
            "add",
            "chain",
            "inet",
            table_name,
            "input",
            "{ type filter hook input priority 0; policy drop; }",
        ],
    )
    run_in_netns(
        vm,
        namespace,
        [
            "nft",
            "add",
            "rule",
            "inet",
            table_name,
            "input",
            "iifname",
            "lo",
            "counter",
            "accept",
            "comment",
            "loopback",
        ],
    )
    run_in_netns(
        vm,
        namespace,
        [
            "nft",
            "add",
            "rule",
            "inet",
            table_name,
            "input",
            "ct",
            "state",
            "established,related",
            "counter",
            "accept",
            "comment",
            "established",
        ],
    )
    run_in_netns(
        vm,
        namespace,
        [
            "nft",
            "add",
            "rule",
            "inet",
            table_name,
            "input",
            "ct",
            "state",
            "invalid",
            "counter",
            "drop",
            "comment",
            "invalid_drop",
        ],
    )
    if allow_udp_dport:
        run_in_netns(
            vm,
            namespace,
            [
                "nft",
                "add",
                "rule",
                "inet",
                table_name,
                "input",
                "udp",
                "dport",
                str(dst_port),
                "counter",
                "accept",
                "comment",
                "udp_accept",
            ],
        )
    run_in_netns(
        vm,
        namespace,
        [
            "nft",
            "add",
            "rule",
            "inet",
            table_name,
            "input",
            "counter",
            "drop",
            "comment",
            "final_drop",
        ],
    )
    return NetnsNftProbe(namespace, "inet", table_name, "input")


def make_netns_input_invalid_drop_probe(vm, namespace, dst_port):
    return make_netns_input_probe(vm, namespace, dst_port, allow_udp_dport=True)


def test_netns_ping_pong_uses_tcp_output_only(phantun_module, vm):
    load_netns_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    probe_a = make_netns_output_probe(vm, NS_A, [(NS_ADDR_A, src_port, NS_ADDR_B, dst_port)])
    probe_b = make_netns_output_probe(vm, NS_B, [(NS_ADDR_B, dst_port, NS_ADDR_A, src_port)])
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

        assert_completed(client_result, "ping client")
        assert_completed(server_result, "ping server")

        server_data = parse_guest_json(server_result.stdout, "ping server stdout")
        client_data = parse_guest_json(client_result.stdout, "ping client stdout")

        if server_data.get("received") != "ping":
            pytest.fail(f"expected server to receive 'ping', got {server_data.get('received')!r}")
        if server_data.get("peer") != [NS_ADDR_A, src_port]:
            pytest.fail(f"unexpected server peer: {server_data.get('peer')!r}")
        if client_data.get("reply") != "pong":
            pytest.fail(f"expected client to receive 'pong', got {client_data.get('reply')!r}")
        if client_data.get("peer") != [NS_ADDR_B, dst_port]:
            pytest.fail(f"unexpected client peer: {client_data.get('peer')!r}")

        udp_a = probe_a.packets(vm, probe_comment("udp", NS_ADDR_A, src_port, NS_ADDR_B, dst_port))
        tcp_a = probe_a.packets(vm, probe_comment("tcp", NS_ADDR_A, src_port, NS_ADDR_B, dst_port))
        udp_b = probe_b.packets(vm, probe_comment("udp", NS_ADDR_B, dst_port, NS_ADDR_A, src_port))
        tcp_b = probe_b.packets(vm, probe_comment("tcp", NS_ADDR_B, dst_port, NS_ADDR_A, src_port))

        if udp_a != 0 or udp_b != 0:
            pytest.fail(f"raw UDP escaped LOCAL_OUT in netns: ns_a={udp_a}, ns_b={udp_b}")
        if tcp_a == 0 or tcp_b == 0:
            pytest.fail(f"expected translated TCP on both netns output paths, got ns_a={tcp_a}, ns_b={tcp_b}")
    finally:
        probe_a.cleanup(vm)
        probe_b.cleanup(vm)
        cleanup_netns_topology(vm)


def test_netns_reinjected_udp_passes_conntrack_input_policy(phantun_module, vm):
    load_netns_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    input_probe = make_netns_input_invalid_drop_probe(vm, NS_B, dst_port)
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
            timeout=10,
        )
        server_result = server.communicate(timeout=10)

        assert_completed(client_result, "stateful firewall client")
        assert_completed(server_result, "stateful firewall server")

        server_data = parse_guest_json(server_result.stdout, "stateful firewall server stdout")
        client_data = parse_guest_json(client_result.stdout, "stateful firewall client stdout")

        if server_data.get("received") != "ping":
            pytest.fail(f"expected server to receive 'ping', got {server_data.get('received')!r}")
        if client_data.get("reply") != "pong":
            pytest.fail(f"expected client to receive 'pong', got {client_data.get('reply')!r}")
        if input_probe.packets(vm, "invalid_drop") != 0:
            pytest.fail("reinjected UDP must not hit ct state invalid input policy")
        if input_probe.packets(vm, "udp_accept") == 0:
            pytest.fail("reinjected UDP did not traverse the input accept rule")
    finally:
        input_probe.cleanup(vm)
        cleanup_netns_topology(vm)


# This matches the real WireGuard host setup: replies must be admitted by
# ESTABLISHED/RELATED state, not by a dedicated allow rule for the ephemeral
# local listen port.
def test_netns_reinjected_udp_is_established_without_explicit_port_allow(phantun_module, vm):
    load_netns_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    input_probe = make_netns_input_probe(vm, NS_A, src_port, allow_udp_dport=False)
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
            check=False,
            timeout=10,
        )
        server_result = server.communicate(timeout=10)

        if client_result.returncode == 0:
            assert_completed(server_result, "established-only firewall server")
            client_data = parse_guest_json(client_result.stdout, "established-only firewall client stdout")
            server_data = parse_guest_json(server_result.stdout, "established-only firewall server stdout")
            if client_data.get("reply") != "pong":
                pytest.fail(f"expected client to receive 'pong', got {client_data.get('reply')!r}")
            if server_data.get("received") != "ping":
                pytest.fail(f"expected server to receive 'ping', got {server_data.get('received')!r}")
        else:
            if server_result.returncode != 0:
                pytest.fail(f"established-only firewall server failed: {server_result.stderr!r}")

        if input_probe.packets(vm, "established") == 0:
            pytest.fail(
                "translated UDP reply must enter INPUT as established/related even when the original UDP send "
                "was stolen in LOCAL_OUT"
            )
        if input_probe.packets(vm, "invalid_drop") != 0:
            pytest.fail("translated UDP reply incorrectly hit ct state invalid")
        if input_probe.packets(vm, "final_drop") != 0:
            pytest.fail("translated UDP reply fell through to the default input drop rule")
    finally:
        input_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_netns_echo_ten_packets(phantun_module, vm):
    load_netns_module(phantun_module)
    ensure_netns_topology(vm)

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    payloads = [f"packet-{idx}" for idx in range(10)]
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "echo_server",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": len(payloads),
        },
    )

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
                "payloads": payloads,
            },
        )
        server_result = server.communicate(timeout=15)

        assert_completed(client_result, "echo client")
        assert_completed(server_result, "echo server")

        server_data = parse_guest_json(server_result.stdout, "echo server stdout")
        client_data = parse_guest_json(client_result.stdout, "echo client stdout")

        expected = sorted(payloads)
        server_seen = sorted(server_data.get("received", []))
        echoed = sorted(client_data.get("echoed", []))

        if server_seen != expected:
            pytest.fail(f"server payload mismatch: expected {expected}, got {server_seen}")
        if echoed != expected:
            pytest.fail(f"client echo mismatch: expected {expected}, got {echoed}")
    finally:
        cleanup_netns_topology(vm)


def test_netns_all_four_channels(phantun_module, vm):
    load_netns_module(phantun_module)
    ensure_netns_topology(vm)

    channels = [
        {
            "src_port": PORTS_A[0],
            "dst_port": PORTS_B[0],
            "dst_addr": NS_ADDR_B,
            "message": "chan-2222-3333",
        },
        {
            "src_port": PORTS_A[0],
            "dst_port": PORTS_B[1],
            "dst_addr": NS_ADDR_B,
            "message": "chan-2222-5555",
        },
        {
            "src_port": PORTS_A[1],
            "dst_port": PORTS_B[0],
            "dst_addr": NS_ADDR_B,
            "message": "chan-4444-3333",
        },
        {
            "src_port": PORTS_A[1],
            "dst_port": PORTS_B[1],
            "dst_addr": NS_ADDR_B,
            "message": "chan-4444-5555",
        },
    ]
    servers = [
        spawn_netns_scenario(
            vm,
            NS_B,
            "multi_server",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": PORTS_B[0],
                "count": 2,
                "ack_prefix": "ack:",
            },
        ),
        spawn_netns_scenario(
            vm,
            NS_B,
            "multi_server",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": PORTS_B[1],
                "count": 2,
                "ack_prefix": "ack:",
            },
        ),
    ]

    try:
        time.sleep(0.2)
        client_result = run_netns_scenario(
            vm,
            NS_A,
            "multi_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_ports": list(PORTS_A),
                "channels": channels,
            },
            timeout=15,
        )
        server_results = [server.communicate(timeout=15) for server in servers]

        assert_completed(client_result, "multi-channel client")
        client_data = parse_guest_json(client_result.stdout, "multi-channel client stdout")

        expected_channels = {
            (entry["src_port"], entry["dst_port"]): entry["message"] for entry in client_data.get("channels", [])
        }
        if len(expected_channels) != 4:
            pytest.fail(f"expected 4 channel definitions, got {expected_channels!r}")

        received = {}
        for index, result in enumerate(server_results):
            assert_completed(result, f"multi-channel server {index}")
            server_data = parse_guest_json(result.stdout, f"multi-channel server {index} stdout")
            for entry in server_data.get("received", []):
                peer = entry.get("peer", [None, None])
                received[(peer[1], server_data.get("port"))] = entry.get("message")
                if peer[0] != NS_ADDR_A:
                    pytest.fail(f"unexpected sender address for server port {server_data.get('port')}: {peer!r}")

        if received != expected_channels:
            pytest.fail(f"server channel mismatch: expected {expected_channels}, got {received}")

        replies = {}
        for reply in client_data.get("replies", []):
            peer = reply.get("peer", [None, None])
            key = (reply.get("local_port"), peer[1])
            replies[key] = reply.get("message")
            if peer[0] != NS_ADDR_B:
                pytest.fail(f"unexpected reply address for local port {reply.get('local_port')}: {peer!r}")

        expected_replies = {key: f"ack:{message}" for key, message in expected_channels.items()}
        if replies != expected_replies:
            pytest.fail(f"reply mismatch: expected {expected_replies}, got {replies}")
    finally:
        cleanup_netns_topology(vm)
