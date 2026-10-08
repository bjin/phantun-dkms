"""skb metadata (mark, DSCP, traffic class, UID, oif) on fake TCP and the flow route cache."""

import time
import uuid

import pytest

from helpers import (
    MANAGED_LOCAL_PORTS,
    NS6_ADDR_A,
    NS6_ADDR_B,
    NS_A,
    NS_ADDR_A,
    NS_ADDR_B,
    NS_B,
    NetnsNftProbe,
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
    load_managed_module,
    make_netns_ingress_flag_drop_probe,
    make_netns_ingress_payload_drop_probe,
    parse_guest_json,
    read_module_stats,
    require_guest_command,
    require_nft_or_skip,
    run_in_netns,
    run_netns_scenario,
    spawn_netns_scenario,
    wait_for_guest_ready_file,
)


def make_netns_output_udp_mark_set_probe(vm, namespace, src_addr, src_port, dst_addr, dst_port, mark):
    table_name = f"phantun_mark_set_{uuid.uuid4().hex[:8]}"
    lines = [
        f"nft delete table inet {table_name} >/dev/null 2>&1 || true",
        f"nft add table inet {table_name}",
        (f"nft 'add chain inet {table_name} output " "{ type filter hook output priority -300; policy accept; }'"),
        (
            f"nft 'add rule inet {table_name} output "
            f"ip saddr {src_addr} ip daddr {dst_addr} "
            f"udp sport {src_port} udp dport {dst_port} "
            f'counter meta mark set {mark:#x} accept comment "mark_udp_before_phantun"\''
        ),
    ]
    run_in_netns(vm, namespace, "\n".join(lines))
    return NetnsNftProbe(namespace, "inet", table_name, "output")


def make_netns_output_tcp_mark_probe(vm, namespace, src_addr, src_port, dst_addr, dst_port, mark):
    table_name = f"phantun_mark_seen_{uuid.uuid4().hex[:8]}"
    lines = [
        f"nft delete table inet {table_name} >/dev/null 2>&1 || true",
        f"nft add table inet {table_name}",
        (f"nft 'add chain inet {table_name} output " "{ type filter hook output priority 0; policy accept; }'"),
        (
            f"nft 'add rule inet {table_name} output "
            f"ip saddr {src_addr} ip daddr {dst_addr} "
            f"tcp sport {src_port} tcp dport {dst_port} meta mark {mark:#x} "
            f'counter accept comment "marked_fake_tcp"\''
        ),
    ]
    run_in_netns(vm, namespace, "\n".join(lines))
    return NetnsNftProbe(namespace, "inet", table_name, "output")


def make_netns_prerouting_syn_meta_set_probe(
    vm,
    namespace,
    src_addr,
    src_port,
    dst_addr,
    dst_port,
    mark,
    dscp,
):
    table_name = f"phantun_in_meta_{uuid.uuid4().hex[:8]}"
    lines = [
        f"nft delete table inet {table_name} >/dev/null 2>&1 || true",
        f"nft add table inet {table_name}",
        (
            f"nft 'add chain inet {table_name} prerouting "
            "{ type filter hook prerouting priority -500; policy accept; }'"
        ),
        (
            f"nft 'add rule inet {table_name} prerouting "
            f"ip saddr {src_addr} ip daddr {dst_addr} "
            f"tcp sport {src_port} tcp dport {dst_port} "
            "tcp flags & (fin|syn|rst|ack) == syn "
            f"counter meta mark set {mark:#x} ip dscp set {dscp:#x} "
            'accept comment "mark_inbound_syn_before_phantun"\''
        ),
    ]
    run_in_netns(vm, namespace, "\n".join(lines))
    return NetnsNftProbe(namespace, "inet", table_name, "prerouting")


def make_netns_output_synack_reply_scope_probe(
    vm,
    namespace,
    src_addr,
    src_port,
    dst_addr,
    dst_port,
    mark,
    dscp,
):
    table_name = f"phantun_reply_scope_{uuid.uuid4().hex[:8]}"
    lines = [
        f"nft delete table inet {table_name} >/dev/null 2>&1 || true",
        f"nft add table inet {table_name}",
        (f"nft 'add chain inet {table_name} output " "{ type filter hook output priority 0; policy accept; }'"),
        (
            f"nft 'add rule inet {table_name} output "
            f"ip saddr {src_addr} ip daddr {dst_addr} "
            f"tcp sport {src_port} tcp dport {dst_port} "
            "tcp flags & (fin|syn|rst|ack) == syn|ack "
            f"meta mark {mark:#x} ip dscp {dscp:#x} "
            'counter accept comment "inbound_marked_synack"\''
        ),
        (
            f"nft 'add rule inet {table_name} output "
            f"ip saddr {src_addr} ip daddr {dst_addr} "
            f"tcp sport {src_port} tcp dport {dst_port} "
            "tcp flags & (fin|syn|rst|ack) == syn|ack "
            "meta mark 0 ip dscp 0x0 "
            'counter accept comment "default_synack_retransmit"\''
        ),
    ]
    run_in_netns(vm, namespace, "\n".join(lines))
    return NetnsNftProbe(namespace, "inet", table_name, "output")


def make_netns_prerouting_ack_meta_set_probe(
    vm,
    namespace,
    src_addr,
    src_port,
    dst_addr,
    dst_port,
    mark,
    dscp,
):
    table_name = f"phantun_ack_meta_{uuid.uuid4().hex[:8]}"
    lines = [
        f"nft delete table inet {table_name} >/dev/null 2>&1 || true",
        f"nft add table inet {table_name}",
        (
            f"nft 'add chain inet {table_name} prerouting "
            "{ type filter hook prerouting priority -500; policy accept; }'"
        ),
        (
            f"nft 'add rule inet {table_name} prerouting "
            f"ip saddr {src_addr} ip daddr {dst_addr} "
            f"tcp sport {src_port} tcp dport {dst_port} "
            "tcp flags & (fin|syn|rst|ack) == ack "
            f"counter meta mark set {mark:#x} ip dscp set {dscp:#x} "
            'accept comment "mark_inbound_ack_before_phantun"\''
        ),
    ]
    run_in_netns(vm, namespace, "\n".join(lines))
    return NetnsNftProbe(namespace, "inet", table_name, "prerouting")


def make_netns_output_ack_reply_scope_probe(
    vm,
    namespace,
    src_addr,
    src_port,
    dst_addr,
    dst_port,
    mark,
    dscp,
):
    table_name = f"phantun_ack_reply_{uuid.uuid4().hex[:8]}"
    lines = [
        f"nft delete table inet {table_name} >/dev/null 2>&1 || true",
        f"nft add table inet {table_name}",
        (f"nft 'add chain inet {table_name} output " "{ type filter hook output priority 0; policy accept; }'"),
        (
            f"nft 'add rule inet {table_name} output "
            f"ip saddr {src_addr} ip daddr {dst_addr} "
            f"tcp sport {src_port} tcp dport {dst_port} "
            "tcp flags & (fin|syn|rst|ack) == ack "
            f"meta mark {mark:#x} ip dscp {dscp:#x} "
            'counter accept comment "inbound_marked_ack"\''
        ),
    ]
    run_in_netns(vm, namespace, "\n".join(lines))
    return NetnsNftProbe(namespace, "inet", table_name, "output")


def make_netns_ingress_synack_dscp_drop_probe(
    vm,
    namespace,
    device,
    src_addr,
    src_port,
    dst_addr,
    dst_port,
    dscp,
):
    table_name = f"phantun_dscp_drop_{uuid.uuid4().hex[:8]}"
    lines = [
        f"nft delete table netdev {table_name} >/dev/null 2>&1 || true",
        f"nft add table netdev {table_name}",
        (
            f"nft 'add chain netdev {table_name} ingress "
            f"{{ type filter hook ingress device {device} priority 0; policy accept; }}'"
        ),
        (
            f"nft 'add rule netdev {table_name} ingress "
            f"ip saddr {src_addr} ip daddr {dst_addr} "
            f"tcp sport {src_port} tcp dport {dst_port} "
            "tcp flags & (fin|syn|rst|ack) == syn|ack "
            f'ip dscp {dscp:#x} counter drop comment "dscp_synack_drop"\''
        ),
    ]
    run_in_netns(vm, namespace, "\n".join(lines))
    return NetnsNftProbe(namespace, "netdev", table_name, "ingress")


def test_netns_outbound_mark_propagates_to_fake_tcp(phantun_module, vm):
    load_managed_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    mark = 0x42
    mark_setter = make_netns_output_udp_mark_set_probe(
        vm,
        NS_A,
        NS_ADDR_A,
        src_port,
        NS_ADDR_B,
        dst_port,
        mark,
    )
    mark_probe = make_netns_output_tcp_mark_probe(
        vm,
        NS_A,
        NS_ADDR_A,
        src_port,
        NS_ADDR_B,
        dst_port,
        mark,
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

        assert_completed(client_result, "marked ping client")
        assert_completed(server_result, "marked ping server")

        if mark_setter.packets(vm, "mark_udp_before_phantun") == 0:
            pytest.fail("test mark rule did not see the original outbound UDP before phantun")
        if mark_probe.packets(vm, "marked_fake_tcp") == 0:
            pytest.fail("generated fake-TCP packets did not preserve the outbound UDP mark")
    finally:
        mark_setter.cleanup(vm)
        mark_probe.cleanup(vm)
        cleanup_netns_topology(vm)


@pytest.mark.parametrize(
    ("rule_match", "second_meta", "metadata_label"),
    [
        pytest.param(["fwmark", "0x42"], {"mark": 0x42}, "mark", id="mark"),
        pytest.param(["tos", "0x10"], {"ipv4_tos": 0x10}, "tos", id="tos"),
        pytest.param(["uidrange", "4242-4242"], {"run_as_uid": 4242}, "uid", id="uid"),
        pytest.param(
            ["fwmark", "0x42", "tos", "0x10"], {"mark": 0x42, "ipv4_tos": 0x10}, "mark-and-tos", id="mark-and-tos"
        ),
    ],
)
def test_netns_route_cache_key_includes_policy_metadata(phantun_module, vm, rule_match, second_meta, metadata_label):
    load_managed_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    ensure_netns_second_path(vm)
    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    rule = ["ip", "rule", "add", "priority", "100", *rule_match, "table", "200"]

    run_in_netns(vm, NS_A, ["ip", "route", "add", NS_ADDR_B, "dev", VETH_A_ALT, "src", NS_ADDR_A, "table", "200"])
    run_in_netns(vm, NS_A, rule)

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
                "payload": "route-a",
                "action": "accept",
                "comment": "route_a_on_path_a",
            },
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "payload": "route-hit",
                "action": "accept",
                "comment": "route_hit_on_path_a",
            },
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "payload": "route-b",
                "action": "accept",
                "comment": "route_b_on_path_a",
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
                "payload": "route-a",
                "action": "accept",
                "comment": "route_a_on_path_b",
            },
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "payload": "route-hit",
                "action": "accept",
                "comment": "route_hit_on_path_b",
            },
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "payload": "route-b",
                "action": "accept",
                "comment": "route_b_on_path_b",
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
            "count": 3,
            "timeout_sec": 20,
        },
    )

    try:
        time.sleep(0.2)
        stats_before = read_module_stats(vm)
        first = run_netns_scenario(
            vm,
            NS_A,
            "ping_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payload": "route-a",
            },
            timeout=10,
        )
        assert_completed(first, "route-cache first client")

        stats_after_first = read_module_stats(vm)
        if stats_after_first["route_cache_misses"] <= stats_before["route_cache_misses"]:
            pytest.fail(
                "first established payload should populate the route cache with a miss: "
                f"before={stats_before!r} after={stats_after_first!r}"
            )

        hit = run_netns_scenario(
            vm,
            NS_A,
            "ping_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payload": "route-hit",
            },
            timeout=10,
        )
        assert_completed(hit, "route-cache hit client")
        stats_after_hit = read_module_stats(vm)
        if stats_after_hit["route_cache_hits"] <= stats_after_first["route_cache_hits"]:
            pytest.fail(
                "second identical established payload should reuse the cached route: "
                f"before={stats_after_first!r} after={stats_after_hit!r}"
            )

        second_config = {
            "bind_addr": NS_ADDR_A,
            "bind_port": src_port,
            "target_addr": NS_ADDR_B,
            "target_port": dst_port,
            "payload": "route-b",
            **second_meta,
        }
        second = run_netns_scenario(
            vm,
            NS_A,
            "ping_client",
            second_config,
            timeout=10,
        )
        assert_completed(second, f"route-cache {metadata_label} client")

        server_result = server.communicate(timeout=15)
        assert_completed(server_result, "route-cache echo server")
        server_data = parse_guest_json(server_result.stdout, "route-cache server stdout")
        if server_data.get("received") != ["route-a", "route-hit", "route-b"]:
            pytest.fail(f"unexpected route-cache server payloads: {server_data.get('received')!r}")

        if path_a_probe.packets(vm, "route_a_on_path_a") == 0:
            pytest.fail("initial unmarked payload did not use path A")
        if path_b_probe.packets(vm, "route_a_on_path_b") != 0:
            pytest.fail("initial unmarked payload unexpectedly used path B")
        if path_a_probe.packets(vm, "route_hit_on_path_a") == 0:
            pytest.fail("second unmarked payload did not use cached path A")
        if path_b_probe.packets(vm, "route_hit_on_path_b") != 0:
            pytest.fail("second unmarked payload unexpectedly used path B")
        if path_b_probe.packets(vm, "route_b_on_path_b") == 0:
            pytest.fail(f"{metadata_label} payload did not use policy-routed path B")
        if path_a_probe.packets(vm, "route_b_on_path_a") != 0:
            pytest.fail(f"cached path A dst was reused for {metadata_label} payload")
    finally:
        path_a_probe.cleanup(vm)
        path_b_probe.cleanup(vm)
        cleanup_netns_topology(vm)


@pytest.mark.usefixtures("ipv6_runtime")
def test_ipv6_route_cache_key_includes_bound_oif(phantun_module, vm):
    load_managed_module(phantun_module)
    ensure_netns_topology(vm, with_ipv6=True)
    require_nft_or_skip(vm)
    ensure_netns_second_path(vm, with_ipv6=True)

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    run_in_netns(vm, NS_A, ["ip", "-6", "route", "add", f"{NS6_ADDR_B}/128", "dev", VETH_A_ALT, "table", "200"])
    run_in_netns(vm, NS_A, ["ip", "-6", "rule", "add", "priority", "100", "oif", VETH_A_ALT, "table", "200"])
    path_a_probe = make_netns_ingress_payload_drop_probe(
        vm,
        NS_B,
        VETH_B,
        [
            {
                "src_addr": NS6_ADDR_A,
                "dst_addr": NS6_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "payload": "v6-path-a",
                "action": "accept",
                "comment": "v6_oif_a_on_main",
            },
            {
                "src_addr": NS6_ADDR_A,
                "dst_addr": NS6_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "payload": "v6-path-b",
                "action": "accept",
                "comment": "v6_oif_b_on_main",
            },
        ],
    )
    path_b_probe = make_netns_ingress_payload_drop_probe(
        vm,
        NS_B,
        VETH_B_ALT,
        [
            {
                "src_addr": NS6_ADDR_A,
                "dst_addr": NS6_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "payload": "v6-path-a",
                "action": "accept",
                "comment": "v6_oif_a_on_alt",
            },
            {
                "src_addr": NS6_ADDR_A,
                "dst_addr": NS6_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "payload": "v6-path-b",
                "action": "accept",
                "comment": "v6_oif_b_on_alt",
            },
        ],
    )
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "echo_server",
        {
            "bind_addr": NS6_ADDR_B,
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
                "bind_addr": NS6_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS6_ADDR_B,
                "target_port": dst_port,
                "payload": "v6-path-a",
            },
            timeout=10,
        )
        assert_completed(first, "IPv6 main-oif client")

        if path_a_probe.packets(vm, "v6_oif_a_on_main") == 0:
            pytest.fail("initial IPv6 payload did not use the main path")
        if path_b_probe.packets(vm, "v6_oif_a_on_alt") != 0:
            pytest.fail("initial IPv6 payload unexpectedly used the alternate path")

        second = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS6_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS6_ADDR_B,
                "target_port": dst_port,
                "payloads": ["v6-path-b"],
                "bind_device": VETH_A_ALT,
            },
            timeout=10,
        )
        assert_completed(second, "IPv6 bound-oif sender")

        server_result = server.communicate(timeout=15)
        assert_completed(server_result, "IPv6 oif route-cache server")
        server_data = parse_guest_json(server_result.stdout, "IPv6 oif server stdout")
        if server_data.get("received") != ["v6-path-a", "v6-path-b"]:
            pytest.fail(f"unexpected IPv6 oif server payloads: {server_data.get('received')!r}")

        if path_b_probe.packets(vm, "v6_oif_b_on_alt") == 0:
            pytest.fail("IPv6 send with bound oif did not use the alternate path")
        if path_a_probe.packets(vm, "v6_oif_b_on_main") != 0:
            pytest.fail("cached IPv6 main-path dst was reused despite a different bound oif")
    finally:
        path_a_probe.cleanup(vm)
        path_b_probe.cleanup(vm)
        cleanup_netns_topology(vm)


@pytest.mark.usefixtures("ipv6_runtime")
def test_ipv6_route_cache_key_includes_tclass(phantun_module, vm):
    load_managed_module(phantun_module)
    ensure_netns_topology(vm, with_ipv6=True)
    require_nft_or_skip(vm)
    ensure_netns_second_path(vm, with_ipv6=True)

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    run_in_netns(vm, NS_A, ["ip", "-6", "route", "add", f"{NS6_ADDR_B}/128", "dev", VETH_A_ALT, "table", "200"])
    run_in_netns(vm, NS_A, ["ip", "-6", "rule", "add", "priority", "100", "tos", "0x10", "table", "200"])

    path_a_probe = make_netns_ingress_payload_drop_probe(
        vm,
        NS_B,
        VETH_B,
        [
            {
                "src_addr": NS6_ADDR_A,
                "dst_addr": NS6_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "payload": "v6-tc-a",
                "action": "accept",
                "comment": "v6_tclass_a_on_main",
            },
            {
                "src_addr": NS6_ADDR_A,
                "dst_addr": NS6_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "payload": "v6-tc-b",
                "action": "accept",
                "comment": "v6_tclass_b_on_main",
            },
        ],
    )
    path_b_probe = make_netns_ingress_payload_drop_probe(
        vm,
        NS_B,
        VETH_B_ALT,
        [
            {
                "src_addr": NS6_ADDR_A,
                "dst_addr": NS6_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "payload": "v6-tc-a",
                "action": "accept",
                "comment": "v6_tclass_a_on_alt",
            },
            {
                "src_addr": NS6_ADDR_A,
                "dst_addr": NS6_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "payload": "v6-tc-b",
                "action": "accept",
                "comment": "v6_tclass_b_on_alt",
            },
        ],
    )
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "echo_server",
        {
            "bind_addr": NS6_ADDR_B,
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
                "bind_addr": NS6_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS6_ADDR_B,
                "target_port": dst_port,
                "payload": "v6-tc-a",
            },
            timeout=10,
        )
        assert_completed(first, "IPv6 tclass baseline sender")

        second = run_netns_scenario(
            vm,
            NS_A,
            "ping_client",
            {
                "bind_addr": NS6_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS6_ADDR_B,
                "target_port": dst_port,
                "payload": "v6-tc-b",
                "ipv6_tclass": 0x10,
            },
            timeout=10,
        )
        assert_completed(second, "IPv6 tclass policy sender")

        server_result = server.communicate(timeout=15)
        assert_completed(server_result, "IPv6 tclass route-cache server")
        server_data = parse_guest_json(server_result.stdout, "IPv6 tclass server stdout")
        if server_data.get("received") != ["v6-tc-a", "v6-tc-b"]:
            pytest.fail(f"unexpected IPv6 tclass server payloads: {server_data.get('received')!r}")

        if path_a_probe.packets(vm, "v6_tclass_a_on_main") == 0:
            pytest.fail("initial IPv6 payload did not use the main path")
        if path_b_probe.packets(vm, "v6_tclass_a_on_alt") != 0:
            pytest.fail("initial IPv6 payload unexpectedly used the alternate path")
        if path_b_probe.packets(vm, "v6_tclass_b_on_alt") == 0:
            pytest.fail("IPv6 tclass payload did not use the policy-routed path")
        if path_a_probe.packets(vm, "v6_tclass_b_on_main") != 0:
            pytest.fail("cached IPv6 main-path dst was reused despite a different traffic class")
    finally:
        path_a_probe.cleanup(vm)
        path_b_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_netns_inbound_metadata_is_reply_scoped(phantun_module, vm):
    phantun_module.load(
        managed_netns="all",
        managed_local_ports=MANAGED_LOCAL_PORTS,
        handshake_timeout_ms=200,
        handshake_retries=3,
    )
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    mark = 0x42
    dscp = 0x12
    inbound_marker = make_netns_prerouting_syn_meta_set_probe(
        vm,
        NS_B,
        NS_ADDR_A,
        src_port,
        NS_ADDR_B,
        dst_port,
        mark,
        dscp,
    )
    synack_probe = make_netns_output_synack_reply_scope_probe(
        vm,
        NS_B,
        NS_ADDR_B,
        dst_port,
        NS_ADDR_A,
        src_port,
        mark,
        dscp,
    )
    synack_drop = make_netns_ingress_synack_dscp_drop_probe(
        vm,
        NS_A,
        VETH_A,
        NS_ADDR_B,
        dst_port,
        NS_ADDR_A,
        src_port,
        dscp,
    )
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "ping_server",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "reply": "pong",
            "timeout_sec": 8,
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
                "timeout_sec": 8,
            },
            timeout=12,
        )
        server_result = server.communicate(timeout=12)

        assert_completed(client_result, "reply-scoped metadata ping client")
        assert_completed(server_result, "reply-scoped metadata ping server")

        if inbound_marker.packets(vm, "mark_inbound_syn_before_phantun") == 0:
            pytest.fail("test rule did not mark inbound SYN metadata before phantun")
        if synack_probe.packets(vm, "inbound_marked_synack") == 0:
            pytest.fail("immediate responder SYN|ACK did not copy inbound fake-TCP metadata")
        if synack_drop.packets(vm, "dscp_synack_drop") == 0:
            pytest.fail("receiver-side DSCP drop did not exercise the immediate SYN|ACK")
        if synack_probe.packets(vm, "default_synack_retransmit") == 0:
            pytest.fail("responder SYN|ACK retransmit inherited inbound metadata")
    finally:
        inbound_marker.cleanup(vm)
        synack_probe.cleanup(vm)
        synack_drop.cleanup(vm)
        cleanup_netns_topology(vm)


def test_netns_established_payload_ack_uses_inbound_reply_metadata(phantun_module, vm):
    load_managed_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    mark = 0x52
    dscp = 0x16
    setup_ready = f"/tmp/phantun_ack_setup_{uuid.uuid4().hex}"
    marked_ready = f"/tmp/phantun_ack_marked_{uuid.uuid4().hex}"
    probes = []

    try:
        setup_server = spawn_netns_scenario(
            vm,
            NS_B,
            "recv_until_timeout",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "count": 1,
                "timeout_sec": 8,
                "ready_file": setup_ready,
            },
        )
        wait_for_guest_ready_file(vm, setup_ready, timeout=5)
        setup = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["setup"],
            },
        )
        assert_completed(setup, "metadata ACK setup sender")
        setup_result = setup_server.communicate(timeout=10)
        assert_completed(setup_result, "metadata ACK setup receiver")
        setup_data = parse_guest_json(setup_result.stdout, "metadata ACK setup receiver stdout")
        if [entry["message"] for entry in setup_data.get("received", [])] != ["setup"]:
            pytest.fail(f"metadata ACK setup receiver saw unexpected payloads: {setup_data!r}")

        inbound_marker = make_netns_prerouting_ack_meta_set_probe(
            vm,
            NS_B,
            NS_ADDR_A,
            src_port,
            NS_ADDR_B,
            dst_port,
            mark,
            dscp,
        )
        probes.append(inbound_marker)
        ack_probe = make_netns_output_ack_reply_scope_probe(
            vm,
            NS_B,
            NS_ADDR_B,
            dst_port,
            NS_ADDR_A,
            src_port,
            mark,
            dscp,
        )
        probes.append(ack_probe)
        stats_before_marked = read_module_stats(vm)

        marked_server = spawn_netns_scenario(
            vm,
            NS_B,
            "recv_until_timeout",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "count": 1,
                "timeout_sec": 8,
                "ready_file": marked_ready,
            },
        )
        wait_for_guest_ready_file(vm, marked_ready, timeout=5)
        marked = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["marked"],
            },
        )
        assert_completed(marked, "metadata ACK marked sender")
        marked_result = marked_server.communicate(timeout=10)
        assert_completed(marked_result, "metadata ACK marked receiver")

        marked_data = parse_guest_json(marked_result.stdout, "metadata ACK marked receiver stdout")
        if [entry["message"] for entry in marked_data.get("received", [])] != ["marked"]:
            pytest.fail(f"metadata ACK marked receiver saw unexpected payloads: {marked_data!r}")
        if inbound_marker.packets(vm, "mark_inbound_ack_before_phantun") == 0:
            pytest.fail("test rule did not mark established inbound fake-TCP payload metadata")
        if ack_probe.packets(vm, "inbound_marked_ack") == 0:
            pytest.fail("pure ACK reply did not copy inbound fake-TCP metadata")
        stats_after_marked = read_module_stats(vm)
        if stats_after_marked["idle_acks_suppressed"] != stats_before_marked["idle_acks_suppressed"]:
            pytest.fail(
                "receive-only established payload should still emit an immediate ACK: "
                f"before={stats_before_marked!r} after={stats_after_marked!r}"
            )
    finally:
        for probe in probes:
            probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_netns_half_open_responder_retransmit_uses_queued_udp_metadata(phantun_module, vm):
    phantun_module.load(
        managed_netns="all",
        managed_local_ports=MANAGED_LOCAL_PORTS,
        handshake_timeout_ms=1000,
        handshake_retries=6,
    )
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    initial_mark = 0x43
    latest_mark = 0x44
    mark_setters = []
    initial_mark_setter = make_netns_output_udp_mark_set_probe(
        vm,
        NS_B,
        NS_ADDR_B,
        dst_port,
        NS_ADDR_A,
        src_port,
        initial_mark,
    )
    mark_setters.append(initial_mark_setter)
    synack_probe = make_netns_output_synack_reply_scope_probe(
        vm,
        NS_B,
        NS_ADDR_B,
        dst_port,
        NS_ADDR_A,
        src_port,
        latest_mark,
        0,
    )
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
                "flags_expr": "syn|ack",
                "comment": "drop_half_open_synack",
            }
        ],
    )

    try:
        opener = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["open"],
            },
        )
        assert_completed(opener, "half-open metadata opener")

        deadline = time.time() + 5
        while time.time() < deadline:
            if drop_synack.packets(vm, "drop_half_open_synack") > 0:
                break
            time.sleep(0.1)
        else:
            pytest.fail("responder did not emit the initial SYN|ACK before queueing UDP")
        queued = run_netns_scenario(
            vm,
            NS_B,
            "send_many",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "target_addr": NS_ADDR_A,
                "target_port": src_port,
                "payloads": ["queued"],
            },
        )
        assert_completed(queued, "half-open metadata queued sender")
        if initial_mark_setter.packets(vm, "mark_udp_before_phantun") == 0:
            pytest.fail("test mark rule did not see queued responder UDP before phantun")
        initial_mark_setter.cleanup(vm)
        mark_setters.remove(initial_mark_setter)

        latest_mark_setter = make_netns_output_udp_mark_set_probe(
            vm,
            NS_B,
            NS_ADDR_B,
            dst_port,
            NS_ADDR_A,
            src_port,
            latest_mark,
        )
        mark_setters.append(latest_mark_setter)
        dropped = run_netns_scenario(
            vm,
            NS_B,
            "send_many",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "target_addr": NS_ADDR_A,
                "target_port": src_port,
                "payloads": ["updates-policy-while-queue-full"],
            },
        )
        assert_completed(dropped, "half-open metadata queue-full sender")

        deadline = time.time() + 5
        while time.time() < deadline:
            if synack_probe.packets(vm, "inbound_marked_synack") > 0:
                break
            time.sleep(0.1)
        else:
            pytest.fail("SYN|ACK retransmit did not use queued outbound UDP metadata")

        if latest_mark_setter.packets(vm, "mark_udp_before_phantun") == 0:
            pytest.fail("test mark rule did not see queue-full responder UDP before phantun")
    finally:
        for mark_setter in mark_setters:
            mark_setter.cleanup(vm)
        synack_probe.cleanup(vm)
        drop_synack.cleanup(vm)
        cleanup_netns_topology(vm)


def test_netns_collision_loser_retransmit_preserves_outbound_metadata(phantun_module, vm):
    phantun_module.load(
        managed_netns="all",
        managed_local_ports=MANAGED_LOCAL_PORTS,
        handshake_timeout_ms=300,
        handshake_retries=10,
    )
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    mark_a = 0x41
    mark_b = 0x42
    initial_stats = read_module_stats(vm)

    mark_setter_a = make_netns_output_udp_mark_set_probe(
        vm,
        NS_A,
        NS_ADDR_A,
        src_port,
        NS_ADDR_B,
        dst_port,
        mark_a,
    )
    mark_setter_b = make_netns_output_udp_mark_set_probe(
        vm,
        NS_B,
        NS_ADDR_B,
        dst_port,
        NS_ADDR_A,
        src_port,
        mark_b,
    )
    marked_synack_a = make_netns_output_synack_reply_scope_probe(
        vm,
        NS_A,
        NS_ADDR_A,
        src_port,
        NS_ADDR_B,
        dst_port,
        mark_a,
        0,
    )
    marked_synack_b = make_netns_output_synack_reply_scope_probe(
        vm,
        NS_B,
        NS_ADDR_B,
        dst_port,
        NS_ADDR_A,
        src_port,
        mark_b,
        0,
    )
    drop_initial_syn_a = make_netns_ingress_flag_drop_probe(
        vm,
        NS_A,
        VETH_A,
        [
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "syn",
                "comment": "drop_initial_syn_a",
            }
        ],
    )
    drop_initial_syn_b = make_netns_ingress_flag_drop_probe(
        vm,
        NS_B,
        VETH_B,
        [
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "flags_expr": "syn",
                "comment": "drop_initial_syn_b",
            }
        ],
    )
    drop_immediate_synack_a = make_netns_ingress_flag_drop_probe(
        vm,
        NS_A,
        VETH_A,
        [
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "syn|ack",
                "comment": "drop_immediate_synack_a",
            }
        ],
    )
    drop_immediate_synack_b = make_netns_ingress_flag_drop_probe(
        vm,
        NS_B,
        VETH_B,
        [
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "flags_expr": "syn|ack",
                "comment": "drop_immediate_synack_b",
            }
        ],
    )

    vm.run(["ip", "netns", "exec", NS_A, "tc", "qdisc", "add", "dev", VETH_A, "root", "netem", "delay", "150ms"])
    vm.run(["ip", "netns", "exec", NS_B, "tc", "qdisc", "add", "dev", VETH_B, "root", "netem", "delay", "150ms"])

    try:
        client_a = spawn_netns_scenario(
            vm,
            NS_A,
            "simultaneous_exchange",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payload": "pingA",
            },
        )
        client_b = spawn_netns_scenario(
            vm,
            NS_B,
            "simultaneous_exchange",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "target_addr": NS_ADDR_A,
                "target_port": src_port,
                "payload": "pingB",
            },
        )

        time.sleep(0.55)
        drop_initial_syn_a.cleanup(vm)
        drop_initial_syn_b.cleanup(vm)
        time.sleep(0.45)
        drop_immediate_synack_a.cleanup(vm)
        drop_immediate_synack_b.cleanup(vm)

        res_a = client_a.communicate(timeout=15)
        res_b = client_b.communicate(timeout=15)
        assert_completed(res_a, "collision metadata client A")
        assert_completed(res_b, "collision metadata client B")

        data_a = parse_guest_json(res_a.stdout, "collision metadata client A")
        data_b = parse_guest_json(res_b.stdout, "collision metadata client B")
        if data_a.get("received") != "pingB":
            pytest.fail(f"client A unexpected collision reply: {data_a.get('received')!r}")
        if data_b.get("received") != "pingA":
            pytest.fail(f"client B unexpected collision reply: {data_b.get('received')!r}")

        final_stats = read_module_stats(vm)
        if final_stats["collisions_lost"] - initial_stats["collisions_lost"] != 1:
            pytest.fail(f"expected exactly one collision loss, got stats {final_stats!r}")

        marked_retransmits = marked_synack_a.packets(vm, "inbound_marked_synack") + marked_synack_b.packets(
            vm,
            "inbound_marked_synack",
        )
        if marked_retransmits == 0:
            pytest.fail("collision-loser SYN|ACK retransmit did not preserve queued outbound metadata")
    finally:
        mark_setter_a.cleanup(vm)
        mark_setter_b.cleanup(vm)
        marked_synack_a.cleanup(vm)
        marked_synack_b.cleanup(vm)
        drop_initial_syn_a.cleanup(vm)
        drop_initial_syn_b.cleanup(vm)
        drop_immediate_synack_a.cleanup(vm)
        drop_immediate_synack_b.cleanup(vm)
        vm.run(["ip", "netns", "exec", NS_A, "tc", "qdisc", "del", "dev", VETH_A, "root", "netem"], check=False)
        vm.run(["ip", "netns", "exec", NS_B, "tc", "qdisc", "del", "dev", VETH_B, "root", "netem"], check=False)
        cleanup_netns_topology(vm)
