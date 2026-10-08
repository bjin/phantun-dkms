"""Local addresses, routes, and devices: endpoint validity and topology-change invalidation."""

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
    VETH_A_ALT,
    VETH_B,
    VETH_B_ALT,
    assert_completed,
    cleanup_netns_topology,
    ensure_netns_second_path,
    ensure_netns_topology,
    load_fast_liveness_module,
    load_managed_module,
    make_netns_ingress_payload_drop_probe,
    make_netns_output_flag_probe,
    make_netns_output_probe,
    parse_guest_json,
    probe_comment,
    read_module_stat,
    read_module_stats,
    received_messages,
    require_guest_command,
    require_nft_or_skip,
    run_in_netns,
    run_netns_scenario,
    run_ping_pong,
    spawn_netns_scenario,
    wait_for_guest_condition,
)

DEPRECATED6_ADDR_A = "fd00:200::10"
DEPRECATED6_ADDR_B = "fd00:200::20"
LINKLOCAL6_ADDR_A = "fe80::a"
LINKLOCAL6_ADDR_B = "fe80::b"
SECONDARY_ADDR_A = "10.200.0.10"
SECONDARY_ADDR_B = "10.200.0.20"


def assert_flow_recreated_after_local_topology_change(vm, change_steps, label, settle_cmd=None):
    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    reconnect_probe = make_netns_output_flag_probe(
        vm,
        NS_A,
        [
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "flags_expr": "syn",
                "comment": "reconnect_syn",
            }
        ],
    )
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "echo_server",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 2,
            "timeout_sec": 20,
        },
    )

    try:
        time.sleep(0.2)
        first = run_netns_scenario(
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
        assert_completed(first, f"{label} first echo")

        baseline_syn = reconnect_probe.packets(vm, "reconnect_syn")
        if baseline_syn == 0:
            pytest.fail(f"expected initial SYN before {label}, got {baseline_syn}")
        baseline_rst_sent = read_module_stats(vm)["rst_sent"]

        for step in change_steps:
            vm.run(step)
        if settle_cmd is not None:
            wait_for_guest_condition(vm, settle_cmd, timeout=5, description=f"{label} settle")
        else:
            time.sleep(0.2)
        rst_sent_after_change = read_module_stats(vm)["rst_sent"]
        if rst_sent_after_change != baseline_rst_sent:
            pytest.fail(
                f"topology invalidation must stay silent for {label}: "
                f"rst_sent before={baseline_rst_sent} after={rst_sent_after_change}"
            )

        second = run_netns_scenario(
            vm,
            NS_A,
            "echo_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["msg2"],
                "timeout_sec": 10,
            },
        )
        assert_completed(second, f"{label} second echo")

        new_syns = reconnect_probe.packets(vm, "reconnect_syn") - baseline_syn
        if new_syns < 1:
            pytest.fail(f"expected a fresh SYN after {label}, got {new_syns}")

        server_result = server.communicate(timeout=15)
        assert_completed(server_result, f"{label} server")
        server_data = parse_guest_json(server_result.stdout, f"{label} server stdout")
        if received_messages(server_data) != ["msg1", "msg2"]:
            pytest.fail(f"unexpected server messages after {label}: {received_messages(server_data)!r}")
    finally:
        reconnect_probe.cleanup(vm)


def test_netns_ipv4_secondary_addresses_are_preserved_and_removed_flows_invalidate(phantun_module, vm):
    load_managed_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    run_in_netns(vm, NS_A, ["ip", "addr", "add", f"{SECONDARY_ADDR_A}/32", "dev", VETH_A])
    run_in_netns(vm, NS_B, ["ip", "addr", "add", f"{SECONDARY_ADDR_B}/32", "dev", VETH_B])
    run_in_netns(vm, NS_A, ["ip", "route", "add", f"{SECONDARY_ADDR_B}/32", "dev", VETH_A])
    run_in_netns(vm, NS_B, ["ip", "route", "add", f"{SECONDARY_ADDR_A}/32", "dev", VETH_B])

    probe_a = make_netns_output_probe(vm, NS_A, [(SECONDARY_ADDR_A, src_port, SECONDARY_ADDR_B, dst_port)])
    probe_b = make_netns_output_probe(vm, NS_B, [(SECONDARY_ADDR_B, dst_port, SECONDARY_ADDR_A, src_port)])
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "ping_server",
        {
            "bind_addr": SECONDARY_ADDR_B,
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
                "bind_addr": SECONDARY_ADDR_A,
                "bind_port": src_port,
                "target_addr": SECONDARY_ADDR_B,
                "target_port": dst_port,
                "payload": "ping",
            },
            timeout=10,
        )
        server_result = server.communicate(timeout=10)

        assert_completed(client_result, "secondary-address ping client")
        assert_completed(server_result, "secondary-address ping server")
        server_data = parse_guest_json(server_result.stdout, "secondary-address ping server stdout")
        client_data = parse_guest_json(client_result.stdout, "secondary-address ping client stdout")
        assert server_data.get("peer") == [SECONDARY_ADDR_A, src_port]
        assert client_data.get("peer") == [SECONDARY_ADDR_B, dst_port]
        assert probe_a.packets(vm, probe_comment("tcp", SECONDARY_ADDR_A, src_port, SECONDARY_ADDR_B, dst_port)) > 0
        assert probe_b.packets(vm, probe_comment("tcp", SECONDARY_ADDR_B, dst_port, SECONDARY_ADDR_A, src_port)) > 0
        assert probe_a.packets(vm, probe_comment("udp", SECONDARY_ADDR_A, src_port, SECONDARY_ADDR_B, dst_port)) == 0
        assert probe_b.packets(vm, probe_comment("udp", SECONDARY_ADDR_B, dst_port, SECONDARY_ADDR_A, src_port)) == 0

        flows_before_remove = read_module_stat(vm, "flows_current")
        if flows_before_remove < 1:
            pytest.fail("expected at least one current flow before removing the secondary local address")
        run_in_netns(vm, NS_A, ["ip", "addr", "del", f"{SECONDARY_ADDR_A}/32", "dev", VETH_A])
        deadline = time.time() + 5
        while time.time() < deadline:
            if read_module_stat(vm, "flows_current") <= flows_before_remove - 1:
                break
            time.sleep(0.1)
        else:
            pytest.fail("removing the exact secondary local IPv4 address did not invalidate its flow")
    finally:
        probe_a.cleanup(vm)
        probe_b.cleanup(vm)
        cleanup_netns_topology(vm)


@pytest.mark.usefixtures("ipv6_runtime")
def test_ipv6_deprecated_global_addresses_are_preserved(phantun_module, vm):
    load_managed_module(phantun_module)
    ensure_netns_topology(vm, with_ipv6=True)
    require_nft_or_skip(vm)

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    run_in_netns(
        vm,
        NS_A,
        [
            "ip",
            "-6",
            "addr",
            "add",
            f"{DEPRECATED6_ADDR_A}/128",
            "dev",
            VETH_A,
            "preferred_lft",
            "0",
            "valid_lft",
            "forever",
            "nodad",
        ],
    )
    run_in_netns(
        vm,
        NS_B,
        [
            "ip",
            "-6",
            "addr",
            "add",
            f"{DEPRECATED6_ADDR_B}/128",
            "dev",
            VETH_B,
            "preferred_lft",
            "0",
            "valid_lft",
            "forever",
            "nodad",
        ],
    )
    run_in_netns(vm, NS_A, ["ip", "-6", "route", "add", f"{DEPRECATED6_ADDR_B}/128", "dev", VETH_A])
    run_in_netns(vm, NS_B, ["ip", "-6", "route", "add", f"{DEPRECATED6_ADDR_A}/128", "dev", VETH_B])

    probe_a = make_netns_output_probe(vm, NS_A, [(DEPRECATED6_ADDR_A, src_port, DEPRECATED6_ADDR_B, dst_port)])
    probe_b = make_netns_output_probe(vm, NS_B, [(DEPRECATED6_ADDR_B, dst_port, DEPRECATED6_ADDR_A, src_port)])
    try:
        run_ping_pong(vm, DEPRECATED6_ADDR_A, DEPRECATED6_ADDR_B, src_port, dst_port)
        assert probe_a.packets(vm, probe_comment("tcp", DEPRECATED6_ADDR_A, src_port, DEPRECATED6_ADDR_B, dst_port)) > 0
        assert probe_b.packets(vm, probe_comment("tcp", DEPRECATED6_ADDR_B, dst_port, DEPRECATED6_ADDR_A, src_port)) > 0
        assert (
            probe_a.packets(vm, probe_comment("udp", DEPRECATED6_ADDR_A, src_port, DEPRECATED6_ADDR_B, dst_port)) == 0
        )
        assert (
            probe_b.packets(vm, probe_comment("udp", DEPRECATED6_ADDR_B, dst_port, DEPRECATED6_ADDR_A, src_port)) == 0
        )
    finally:
        probe_a.cleanup(vm)
        probe_b.cleanup(vm)
        cleanup_netns_topology(vm)


@pytest.mark.usefixtures("ipv6_runtime")
def test_ipv6_link_local_endpoints_are_rejected(phantun_module, vm):
    load_managed_module(phantun_module)
    ensure_netns_topology(vm, with_ipv6=True)
    require_nft_or_skip(vm)

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    run_in_netns(vm, NS_A, ["ip", "-6", "addr", "add", f"{LINKLOCAL6_ADDR_A}/64", "dev", VETH_A, "nodad"])
    run_in_netns(vm, NS_B, ["ip", "-6", "addr", "add", f"{LINKLOCAL6_ADDR_B}/64", "dev", VETH_B, "nodad"])
    probe_a = make_netns_output_probe(vm, NS_A, [(LINKLOCAL6_ADDR_A, src_port, LINKLOCAL6_ADDR_B, dst_port)])
    dropped_before = read_module_stat(vm, "udp_packets_dropped")

    try:
        result = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": LINKLOCAL6_ADDR_A,
                "bind_port": src_port,
                "bind_scope_dev": VETH_A,
                "target_addr": LINKLOCAL6_ADDR_B,
                "target_port": dst_port,
                "target_scope_dev": VETH_A,
                "payloads": ["link-local"],
                "allow_send_errors": True,
            },
            timeout=10,
        )
        assert_completed(result, "link-local send")
        dropped_after = read_module_stat(vm, "udp_packets_dropped")
        if dropped_after <= dropped_before:
            pytest.fail("link-local endpoint send did not increment the translated UDP drop counter")
        assert probe_a.packets(vm, probe_comment("udp", LINKLOCAL6_ADDR_A, src_port, LINKLOCAL6_ADDR_B, dst_port)) == 0
        assert probe_a.packets(vm, probe_comment("tcp", LINKLOCAL6_ADDR_A, src_port, LINKLOCAL6_ADDR_B, dst_port)) == 0
    finally:
        probe_a.cleanup(vm)
        cleanup_netns_topology(vm)


def test_route_change_revalidates_cached_dst_without_rst(phantun_module, vm):
    load_fast_liveness_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    ensure_netns_second_path(vm)
    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    path_a_probe = make_netns_ingress_payload_drop_probe(
        vm,
        NS_B,
        VETH_B,
        [
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "payload": "route-before",
                "action": "accept",
                "comment": "route_before_on_path_a",
            },
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "payload": "route-after",
                "action": "accept",
                "comment": "route_after_on_path_a",
            },
        ],
    )
    path_b_probe = make_netns_ingress_payload_drop_probe(
        vm,
        NS_B,
        VETH_B_ALT,
        [
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "payload": "route-before",
                "action": "accept",
                "comment": "route_before_on_path_b",
            },
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "payload": "route-after",
                "action": "accept",
                "comment": "route_after_on_path_b",
            },
        ],
    )
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "echo_server",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 2,
            "timeout_sec": 20,
        },
    )

    try:
        time.sleep(0.2)
        first = run_netns_scenario(
            vm,
            NS_A,
            "ping_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payload": "route-before",
            },
            timeout=10,
        )
        assert_completed(first, "stale-route first client")
        if path_a_probe.packets(vm, "route_before_on_path_a") == 0:
            pytest.fail("initial payload did not use path A before route change")

        baseline_rst_sent = read_module_stats(vm)["rst_sent"]
        run_in_netns(vm, NS_A, ["ip", "route", "replace", NS_ADDR_B, "dev", VETH_A_ALT, "src", NS_ADDR_A])
        time.sleep(0.2)

        second = run_netns_scenario(
            vm,
            NS_A,
            "ping_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payload": "route-after",
            },
            timeout=10,
        )
        assert_completed(second, "stale-route second client")

        server_result = server.communicate(timeout=15)
        assert_completed(server_result, "stale-route echo server")
        server_data = parse_guest_json(server_result.stdout, "stale-route server stdout")
        if server_data.get("received") != ["route-before", "route-after"]:
            pytest.fail(f"unexpected stale-route server payloads: {server_data.get('received')!r}")

        if path_b_probe.packets(vm, "route_after_on_path_b") == 0:
            pytest.fail("payload after route change did not use path B")
        if path_a_probe.packets(vm, "route_after_on_path_a") != 0:
            pytest.fail("stale cached path A dst was reused after route change")
        if read_module_stats(vm)["rst_sent"] != baseline_rst_sent:
            pytest.fail("route-only dst revalidation unexpectedly emitted RST")
    finally:
        path_a_probe.cleanup(vm)
        path_b_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_device_down_invalidation_recreates_flow(phantun_module, vm):
    load_fast_liveness_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    assert_flow_recreated_after_local_topology_change(
        vm,
        [
            ["ip", "netns", "exec", NS_A, "ip", "link", "set", "dev", VETH_A, "down"],
            ["ip", "netns", "exec", NS_A, "ip", "link", "set", "dev", VETH_A, "up"],
        ],
        "device bounce invalidation",
        [
            "ip",
            "netns",
            "exec",
            NS_A,
            "bash",
            "-lc",
            f"ip -o link show dev {VETH_A} | grep -q 'state UP' && ip -o -4 addr show dev {VETH_A} | grep -q '{NS_ADDR_A}/24'",
        ],
    )


def test_local_addr_removal_invalidation_recreates_flow(phantun_module, vm):
    load_fast_liveness_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    assert_flow_recreated_after_local_topology_change(
        vm,
        [
            [
                "ip",
                "netns",
                "exec",
                NS_A,
                "ip",
                "addr",
                "del",
                f"{NS_ADDR_A}/24",
                "dev",
                VETH_A,
            ],
            [
                "ip",
                "netns",
                "exec",
                NS_A,
                "ip",
                "addr",
                "add",
                f"{NS_ADDR_A}/24",
                "dev",
                VETH_A,
            ],
        ],
        "local IPv4 removal invalidation",
        [
            "ip",
            "netns",
            "exec",
            NS_A,
            "bash",
            "-lc",
            f"ip -o -4 addr show dev {VETH_A} | grep -q '{NS_ADDR_A}/24'",
        ],
    )
