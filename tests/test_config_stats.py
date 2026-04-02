import time

import pytest

from helpers import (
    MODULE_STAT_NAMES,
    NS_A,
    NS_ADDR_A,
    NS_ADDR_B,
    NS_B,
    PORTS_A,
    PORTS_B,
    cleanup_netns_topology,
    ensure_netns_topology,
    make_netns_output_probe,
    parse_guest_json,
    probe_comment,
    read_module_stats,
    run_netns_scenario,
    spawn_netns_scenario,
)

MANAGED_PORTS = "2222,3333,4444,5555"
REQ = "HSREQ42"
RESP = "HSRESP42"


def assert_completed(result, label):
    if result.returncode != 0:
        pytest.fail(f"{label} failed: {result.stderr!r}")


def test_sysfs_stats_exist_and_increment(phantun_module, vm):
    phantun_module.load(
        managed_ports=MANAGED_PORTS,
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
        'recv_many_reply',
        {
            'bind_addr': NS_ADDR_B,
            'bind_port': dst_port,
            'count': 2,
            'replies': ['reply-0', 'reply-1'],
        },
    )

    try:
        time.sleep(0.2)
        client = run_netns_scenario(
            vm,
            NS_A,
            'send_many_recv',
            {
                'bind_addr': NS_ADDR_A,
                'bind_port': src_port,
                'target_addr': NS_ADDR_B,
                'target_port': dst_port,
                'payloads': ['client-0', 'client-1'],
                'recv_count': 2,
                'delay_ms': 100,
            },
            timeout=20,
        )
        server_result = server.communicate(timeout=20)
        assert_completed(client, 'stats client')
        assert_completed(server_result, 'stats server')

        client_data = parse_guest_json(client.stdout, 'stats client stdout')
        server_data = parse_guest_json(server_result.stdout, 'stats server stdout')
        if [entry['message'] for entry in server_data.get('received', [])] != ['client-0', 'client-1']:
            pytest.fail(f"unexpected server payloads: {server_data!r}")
        if [entry['message'] for entry in client_data.get('replies', [])] != ['reply-0', 'reply-1']:
            pytest.fail(f"unexpected client replies: {client_data!r}")
    finally:
        cleanup_netns_topology(vm)

    stats = read_module_stats(vm)
    expected = {
        'flows_created': 2,
        'flows_established': 2,
        'request_payloads_injected': 1,
        'response_payloads_injected': 1,
        'collisions_won': 0,
        'collisions_lost': 0,
        'rst_sent': 0,
        'udp_packets_dropped': 0,
    }
    for name, value in expected.items():
        if stats.get(name) != value:
            pytest.fail(f"unexpected {name}: expected {value}, got {stats.get(name)} in {stats!r}")
    if stats.get('udp_packets_queued', 0) < 1:
        pytest.fail(f"expected at least one queued UDP packet, got {stats!r}")
    if stats.get('shaping_payloads_dropped', 0) < 1:
        pytest.fail(f"expected at least one shaping payload drop, got {stats!r}")


def test_remote_ipv4_cidr_filter_blocks_unmatched_remote(phantun_module, vm):
    phantun_module.load(managed_ports=MANAGED_PORTS, remote_ipv4_cidr='10.200.1.0/24')
    ensure_netns_topology(vm)

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    probe_a = make_netns_output_probe(vm, NS_A, [(NS_ADDR_A, src_port, NS_ADDR_B, dst_port)])
    server = spawn_netns_scenario(
        vm,
        NS_B,
        'recv_many',
        {
            'bind_addr': NS_ADDR_B,
            'bind_port': dst_port,
            'count': 1,
        },
    )

    try:
        time.sleep(0.2)
        # The OUTPUT probe intentionally drops raw UDP. If the CIDR filter
        # bypasses translation correctly, sendto fails locally and the server
        # receives nothing.
        client = run_netns_scenario(
            vm,
            NS_A,
            'send_many',
            {
                'bind_addr': NS_ADDR_A,
                'bind_port': src_port,
                'target_addr': NS_ADDR_B,
                'target_port': dst_port,
                'payloads': ['blocked-by-cidr'],
            },
            check=False,
        )
        server_result = server.communicate(timeout=10)
        if client.returncode == 0:
            pytest.fail('sender unexpectedly succeeded despite unmatched remote_ipv4_cidr')
        if server_result.returncode == 0:
            pytest.fail('server unexpectedly received payload despite unmatched remote_ipv4_cidr')

        udp_a = probe_a.packets(vm, probe_comment('udp', NS_ADDR_A, src_port, NS_ADDR_B, dst_port))
        tcp_a = probe_a.packets(vm, probe_comment('tcp', NS_ADDR_A, src_port, NS_ADDR_B, dst_port))
        if udp_a == 0:
            pytest.fail('expected raw UDP to escape when remote_ipv4_cidr rejects the tuple')
        if tcp_a != 0:
            pytest.fail(f'expected no translated TCP when remote_ipv4_cidr rejects the tuple, got {tcp_a}')
    finally:
        probe_a.cleanup(vm)
        cleanup_netns_topology(vm)



def test_remote_port_filter_blocks_unmatched_remote_port(phantun_module, vm):
    phantun_module.load(managed_ports=MANAGED_PORTS, remote_port='5555')
    ensure_netns_topology(vm)

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    probe_a = make_netns_output_probe(vm, NS_A, [(NS_ADDR_A, src_port, NS_ADDR_B, dst_port)])
    server = spawn_netns_scenario(
        vm,
        NS_B,
        'recv_many',
        {
            'bind_addr': NS_ADDR_B,
            'bind_port': dst_port,
            'count': 1,
        },
    )

        # The OUTPUT probe intentionally drops raw UDP. If the remote-port
        # filter bypasses translation correctly, sendto fails locally and the
        # server receives nothing.
    try:
        time.sleep(0.2)
        client = run_netns_scenario(
            vm,
            NS_A,
            'send_many',
            {
                'bind_addr': NS_ADDR_A,
                'bind_port': src_port,
                'target_addr': NS_ADDR_B,
                'target_port': dst_port,
                'payloads': ['blocked-by-port'],
            },
            check=False,
        )
        server_result = server.communicate(timeout=10)
        if client.returncode == 0:
            pytest.fail('sender unexpectedly succeeded despite unmatched remote_port')
        if server_result.returncode == 0:
            pytest.fail('server unexpectedly received payload despite unmatched remote_port')

        udp_a = probe_a.packets(vm, probe_comment('udp', NS_ADDR_A, src_port, NS_ADDR_B, dst_port))
        tcp_a = probe_a.packets(vm, probe_comment('tcp', NS_ADDR_A, src_port, NS_ADDR_B, dst_port))
        if udp_a == 0:
            pytest.fail('expected raw UDP to escape when remote_port rejects the tuple')
        if tcp_a != 0:
            pytest.fail(f'expected no translated TCP when remote_port rejects the tuple, got {tcp_a}')
    finally:
        probe_a.cleanup(vm)
        cleanup_netns_topology(vm)
