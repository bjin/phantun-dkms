import json
import subprocess
import time

import pytest

from helpers import (
    GUEST_SCENARIOS,
    MODULE_STAT_NAMES,
    NS_A,
    NS_ADDR_A,
    NS_ADDR_B,
    NS_B,
    PORTS_A,
    PORTS_B,
    assert_completed,
    cleanup_netns_topology,
    ensure_netns_topology,
    make_netns_output_probe,
    parse_guest_json,
    probe_comment,
    read_module_stats,
    run_netns_scenario,
    spawn_guest_command,
    spawn_netns_scenario,
)

MANAGED_LOCAL_PORTS = "2222,3333,4444,5555"
REQ = "HSREQ42"
RESP = "HSRESP42"


def run_guest_scenario(vm, scenario, config, check=True, **kwargs):
    return vm.run(["python3", GUEST_SCENARIOS, scenario, json.dumps(config)], check=check, **kwargs)


def spawn_guest_scenario(vm, scenario, config, **kwargs):
    return spawn_guest_command(vm, ["python3", GUEST_SCENARIOS, scenario, json.dumps(config)], **kwargs)


def test_sysfs_stats_exist_and_increment(phantun_module, vm):
    phantun_module.load(
        managed_local_ports=MANAGED_LOCAL_PORTS,
        handshake_request=REQ,
        handshake_response=RESP,
    )
    initial = read_module_stats(vm)
    missing = [name for name in MODULE_STAT_NAMES if name not in initial]
    if missing:
        pytest.fail(f"missing module stats: {missing!r}")
    if any(value != 0 for value in initial.values()):
        pytest.fail(f"expected fresh module stats to start at zero, got {initial!r}")

    ensure_netns_topology(vm)
    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
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
        client = run_netns_scenario(
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
        assert_completed(client, "stats client")
        assert_completed(server_result, "stats server")

        client_data = parse_guest_json(client.stdout, "stats client stdout")
        server_data = parse_guest_json(server_result.stdout, "stats server stdout")
        if [entry["message"] for entry in server_data.get("received", [])] != [
            "client-0",
            "client-1",
        ]:
            pytest.fail(f"unexpected server payloads: {server_data!r}")
        if [entry["message"] for entry in client_data.get("replies", [])] != [
            "reply-0",
            "reply-1",
        ]:
            pytest.fail(f"unexpected client replies: {client_data!r}")
    finally:
        cleanup_netns_topology(vm)

    stats = read_module_stats(vm)
    expected = {
        "flows_created": 2,
        "flows_established": 2,
        "request_payloads_injected": 1,
        "response_payloads_injected": 1,
        "collisions_won": 0,
        "collisions_lost": 0,
        "rst_sent": 0,
        "udp_packets_dropped": 0,
    }
    for name, value in expected.items():
        if stats.get(name) != value:
            pytest.fail(f"unexpected {name}: expected {value}, got {stats.get(name)} in {stats!r}")
    if stats.get("udp_packets_queued", 0) < 1:
        pytest.fail(f"expected at least one queued UDP packet, got {stats!r}")
    if stats.get("shaping_payloads_dropped", 0) < 1:
        pytest.fail(f"expected at least one shaping payload drop, got {stats!r}")


def test_managed_remote_peers_filter_blocks_unmatched_remote_peer(phantun_module, vm):
    phantun_module.load(
        managed_local_ports=MANAGED_LOCAL_PORTS,
        managed_remote_peers="10.200.1.2:3333",
    )
    ensure_netns_topology(vm)

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    probe_a = make_netns_output_probe(vm, NS_A, [(NS_ADDR_A, src_port, NS_ADDR_B, dst_port)])
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
        # The OUTPUT probe intentionally drops raw UDP. If the managed-remote-peer
        # filter bypasses translation correctly, sendto fails locally and the
        # server receives nothing.
        client = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["blocked-by-cidr"],
            },
            check=False,
        )
        server_result = server.communicate(timeout=10)
        if client.returncode == 0:
            pytest.fail("sender unexpectedly succeeded despite unmatched managed_remote_peers entry")
        if server_result.returncode == 0:
            pytest.fail("server unexpectedly received payload despite unmatched managed_remote_peers entry")

        udp_a = probe_a.packets(vm, probe_comment("udp", NS_ADDR_A, src_port, NS_ADDR_B, dst_port))
        tcp_a = probe_a.packets(vm, probe_comment("tcp", NS_ADDR_A, src_port, NS_ADDR_B, dst_port))
        if udp_a == 0:
            pytest.fail("expected raw UDP to escape when managed_remote_peers rejects the tuple")
        if tcp_a != 0:
            pytest.fail(f"expected no translated TCP when managed_remote_peers rejects the tuple, got {tcp_a}")
    finally:
        probe_a.cleanup(vm)
        cleanup_netns_topology(vm)


def test_managed_remote_peers_filter_blocks_unmatched_peer_port(phantun_module, vm):
    phantun_module.load(
        managed_local_ports=MANAGED_LOCAL_PORTS,
        managed_remote_peers="10.200.0.2:5555",
    )
    ensure_netns_topology(vm)

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    probe_a = make_netns_output_probe(vm, NS_A, [(NS_ADDR_A, src_port, NS_ADDR_B, dst_port)])
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

    # The OUTPUT probe intentionally drops raw UDP. If the managed-remote-peer
    # filter bypasses translation correctly, sendto fails locally and the
    # server receives nothing.
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
                "payloads": ["blocked-by-port"],
            },
            check=False,
        )
        server_result = server.communicate(timeout=10)
        if client.returncode == 0:
            pytest.fail("sender unexpectedly succeeded despite unmatched managed_remote_peers port")
        if server_result.returncode == 0:
            pytest.fail("server unexpectedly received payload despite unmatched managed_remote_peers port")

        udp_a = probe_a.packets(vm, probe_comment("udp", NS_ADDR_A, src_port, NS_ADDR_B, dst_port))
        tcp_a = probe_a.packets(vm, probe_comment("tcp", NS_ADDR_A, src_port, NS_ADDR_B, dst_port))
        if udp_a == 0:
            pytest.fail("expected raw UDP to escape when managed_remote_peers rejects the tuple")
        if tcp_a != 0:
            pytest.fail(f"expected no translated TCP when managed_remote_peers rejects the tuple, got {tcp_a}")
    finally:
        probe_a.cleanup(vm)
        cleanup_netns_topology(vm)


def test_peer_only_mode_translates_matching_peers(phantun_module, vm):
    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    managed_peers = f"{NS_ADDR_A}:{src_port},{NS_ADDR_B}:{dst_port}"

    phantun_module.load(managed_remote_peers=managed_peers)
    ensure_netns_topology(vm)

    probe_a = make_netns_output_probe(vm, NS_A, [(NS_ADDR_A, src_port, NS_ADDR_B, dst_port)])
    probe_b = make_netns_output_probe(vm, NS_B, [(NS_ADDR_B, dst_port, NS_ADDR_A, src_port)])
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "recv_many_reply",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 1,
            "replies": ["peer-only-reply"],
        },
    )

    try:
        time.sleep(0.2)
        client = run_netns_scenario(
            vm,
            NS_A,
            "send_many_recv",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["peer-only-request"],
                "recv_count": 1,
            },
            timeout=20,
        )
        server_result = server.communicate(timeout=20)
        assert_completed(client, "peer-only client")
        assert_completed(server_result, "peer-only server")

        client_data = parse_guest_json(client.stdout, "peer-only client stdout")
        server_data = parse_guest_json(server_result.stdout, "peer-only server stdout")
        if [entry["message"] for entry in server_data.get("received", [])] != ["peer-only-request"]:
            pytest.fail(f"unexpected peer-only server payloads: {server_data!r}")
        if [entry["message"] for entry in client_data.get("replies", [])] != ["peer-only-reply"]:
            pytest.fail(f"unexpected peer-only client replies: {client_data!r}")

        udp_a = probe_a.packets(vm, probe_comment("udp", NS_ADDR_A, src_port, NS_ADDR_B, dst_port))
        tcp_a = probe_a.packets(vm, probe_comment("tcp", NS_ADDR_A, src_port, NS_ADDR_B, dst_port))
        udp_b = probe_b.packets(vm, probe_comment("udp", NS_ADDR_B, dst_port, NS_ADDR_A, src_port))
        tcp_b = probe_b.packets(vm, probe_comment("tcp", NS_ADDR_B, dst_port, NS_ADDR_A, src_port))
        if udp_a != 0 or udp_b != 0:
            pytest.fail(f"raw UDP escaped in peer-only mode: ns_a={udp_a}, ns_b={udp_b}")
        if tcp_a == 0 or tcp_b == 0:
            pytest.fail(f"expected translated TCP in peer-only mode, got ns_a={tcp_a}, ns_b={tcp_b}")
    finally:
        probe_a.cleanup(vm)
        probe_b.cleanup(vm)
        cleanup_netns_topology(vm)


def test_intersection_mode_requires_local_and_remote_match(phantun_module, vm):
    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]

    phantun_module.load(
        managed_local_ports="5555",
        managed_remote_peers=f"{NS_ADDR_B}:{dst_port}",
    )
    ensure_netns_topology(vm)

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
                "payloads": ["intersection-raw"],
            },
        )
        server_result = server.communicate(timeout=10)
        assert_completed(client, "intersection client")
        assert_completed(server_result, "intersection server")

        server_data = parse_guest_json(server_result.stdout, "intersection server stdout")
        if [entry["message"] for entry in server_data.get("received", [])] != ["intersection-raw"]:
            pytest.fail(f"unexpected intersection server payloads: {server_data!r}")

    finally:
        cleanup_netns_topology(vm)


def test_loopback_localhost_udp_on_managed_port_is_ignored(phantun_module, vm):
    managed_port = PORTS_A[0]
    other_port = PORTS_B[0]

    phantun_module.load(managed_local_ports=str(managed_port))
    initial_stats = read_module_stats(vm)
    server = spawn_guest_scenario(
        vm,
        "ping_server",
        {
            "bind_addr": "127.0.0.1",
            "bind_port": other_port,
        },
    )
    server_result = None

    try:
        time.sleep(0.2)
        client = run_guest_scenario(
            vm,
            "ping_client",
            {
                "bind_addr": "127.0.0.1",
                "bind_port": managed_port,
                "target_addr": "127.0.0.1",
                "target_port": other_port,
                "payload": "loopback-localhost",
            },
            check=False,
            timeout=10,
        )
        try:
            server_result = server.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            pytest.fail("loopback localhost server did not receive UDP on a managed_local_ports tuple")

        assert_completed(client, "loopback localhost client")
        assert_completed(server_result, "loopback localhost server")

        client_data = parse_guest_json(client.stdout, "loopback localhost client stdout")
        server_data = parse_guest_json(server_result.stdout, "loopback localhost server stdout")
        if server_data.get("received") != "loopback-localhost":
            pytest.fail(f"unexpected localhost server payload: {server_data!r}")
        if client_data.get("reply") != "pong":
            pytest.fail(f"unexpected localhost client reply: {client_data!r}")

        stats = read_module_stats(vm)
        if stats != initial_stats:
            pytest.fail(
                "localhost UDP between managed_local_ports and another localhost port must bypass phantun "
                f"entirely; expected stats {initial_stats!r}, got {stats!r}"
            )
    finally:
        if server_result is None and server.proc.poll() is None:
            server.terminate()
            try:
                server.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                pytest.fail("loopback localhost server did not exit after termination")


def test_inbound_udp_to_managed_local_port_is_dropped(phantun_module, vm):
    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]

    phantun_module.load(managed_local_ports=str(dst_port))
    ensure_netns_topology(vm)

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
                "payloads": ["should-drop-raw-udp"],
            },
            check=False,
        )
        server_result = server.communicate(timeout=10)
        if client.returncode != 0:
            pytest.fail(f"raw-udp client unexpectedly failed before inbound drop: {client.stderr!r}")
        if server_result.returncode == 0:
            pytest.fail("server unexpectedly received raw UDP on a managed local port")
    finally:
        cleanup_netns_topology(vm)
