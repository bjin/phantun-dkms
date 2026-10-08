"""Coexistence with netfilter/conntrack policy, reinjection cookies, and forwarding."""

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
    load_managed_module,
    make_netns_output_flag_probe,
    make_netns_prerouting_flag_drop_probe,
    parse_guest_json,
    require_guest_command,
    run_in_netns,
    run_netns_scenario,
    spawn_netns_scenario,
    spawn_ready_capture,
    wait_for_guest_ready_file,
)

ROUTER_NS = "pht-r"
VETH_A_R = "veth-pht-ar"
VETH_R_A = "veth-pht-ra"
VETH_R_B = "veth-pht-rb"
VETH_B_R = "veth-pht-br"
FWD_ADDR_A = "10.210.0.1"
FWD_ADDR_R_A = "10.210.0.254"
FWD_ADDR_R_B = "10.220.0.254"
FWD_ADDR_B = "10.220.0.2"


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


def make_netns_output_invalid_drop_probe(vm, namespace):
    table_name = f"phantun_out_invalid_{uuid.uuid4().hex[:8]}"
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
            "output",
            "{ type filter hook output priority 0; policy accept; }",
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
            "output",
            "ct",
            "state",
            "invalid",
            "counter",
            "drop",
            "comment",
            "invalid_drop_out",
        ],
    )
    return NetnsNftProbe(namespace, "inet", table_name, "output")


def make_netns_prerouting_udp_mark_set_probe(
    vm,
    namespace,
    src_addr,
    src_port,
    dst_addr,
    dst_port,
    mark,
):
    table_name = f"phantun_udp_mark_{uuid.uuid4().hex[:8]}"
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
            f"udp sport {src_port} udp dport {dst_port} "
            f'counter meta mark set {mark:#x} accept comment "spoof_old_reinject_mark"\''
        ),
    ]
    run_in_netns(vm, namespace, "\n".join(lines))
    return NetnsNftProbe(namespace, "inet", table_name, "prerouting")


def make_netns_input_invalid_drop_probe(vm, namespace, dst_port):
    return make_netns_input_probe(vm, namespace, dst_port, allow_udp_dport=True)


def cleanup_forwarding_topology(vm):
    cleanup_netns_topology(vm, namespaces=(NS_A, NS_B, ROUTER_NS))


def ensure_forwarding_topology(vm):
    cleanup_forwarding_topology(vm)

    vm.run(["ip", "netns", "add", NS_A])
    vm.run(["ip", "netns", "add", ROUTER_NS])
    vm.run(["ip", "netns", "add", NS_B])

    vm.run(["ip", "link", "add", VETH_A_R, "type", "veth", "peer", "name", VETH_R_A])
    vm.run(["ip", "link", "add", VETH_R_B, "type", "veth", "peer", "name", VETH_B_R])

    vm.run(["ip", "link", "set", VETH_A_R, "netns", NS_A])
    vm.run(["ip", "link", "set", VETH_R_A, "netns", ROUTER_NS])
    vm.run(["ip", "link", "set", VETH_R_B, "netns", ROUTER_NS])
    vm.run(["ip", "link", "set", VETH_B_R, "netns", NS_B])

    for namespace in (NS_A, ROUTER_NS, NS_B):
        run_in_netns(vm, namespace, ["ip", "link", "set", "lo", "up"])

    run_in_netns(vm, NS_A, ["ip", "addr", "add", f"{FWD_ADDR_A}/24", "dev", VETH_A_R])
    run_in_netns(vm, ROUTER_NS, ["ip", "addr", "add", f"{FWD_ADDR_R_A}/24", "dev", VETH_R_A])
    run_in_netns(vm, ROUTER_NS, ["ip", "addr", "add", f"{FWD_ADDR_R_B}/24", "dev", VETH_R_B])
    run_in_netns(vm, NS_B, ["ip", "addr", "add", f"{FWD_ADDR_B}/24", "dev", VETH_B_R])

    run_in_netns(vm, NS_A, ["ip", "link", "set", VETH_A_R, "up"])
    run_in_netns(vm, ROUTER_NS, ["ip", "link", "set", VETH_R_A, "up"])
    run_in_netns(vm, ROUTER_NS, ["ip", "link", "set", VETH_R_B, "up"])
    run_in_netns(vm, NS_B, ["ip", "link", "set", VETH_B_R, "up"])

    run_in_netns(
        vm,
        NS_A,
        ["ip", "route", "add", f"{FWD_ADDR_B}/32", "via", FWD_ADDR_R_A, "dev", VETH_A_R],
    )
    run_in_netns(
        vm,
        NS_B,
        ["ip", "route", "add", f"{FWD_ADDR_A}/32", "via", FWD_ADDR_R_B, "dev", VETH_B_R],
    )

    run_in_netns(vm, ROUTER_NS, ["sysctl", "-w", "net.ipv4.ip_forward=1"])
    run_in_netns(vm, ROUTER_NS, ["sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"])
    run_in_netns(vm, ROUTER_NS, ["sysctl", "-w", f"net.ipv4.conf.{VETH_R_A}.rp_filter=0"])
    run_in_netns(vm, ROUTER_NS, ["sysctl", "-w", f"net.ipv4.conf.{VETH_R_B}.rp_filter=0"])


def test_netns_generated_fake_tcp_bypasses_output_invalid_drop(phantun_module, vm):
    load_managed_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    ready_file = f"/tmp/phantun_output_ct_{uuid.uuid4().hex}"
    probe_a = make_netns_output_invalid_drop_probe(vm, NS_A)
    probe_b = make_netns_output_invalid_drop_probe(vm, NS_B)
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "recv_many_reply",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 1,
            "replies": ["strict-reply"],
            "timeout_sec": 15,
            "ready_file": ready_file,
        },
    )

    try:
        wait_for_guest_ready_file(vm, ready_file, timeout=5)
        client = run_netns_scenario(
            vm,
            NS_A,
            "send_many_recv",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["strict-request"],
                "recv_count": 1,
            },
            timeout=15,
        )
        server_result = server.communicate(timeout=15)

        assert_completed(client, "output invalid-drop client")
        assert_completed(server_result, "output invalid-drop server")
        client_data = parse_guest_json(client.stdout, "output invalid-drop client stdout")
        server_data = parse_guest_json(server_result.stdout, "output invalid-drop server stdout")
        server_received = [entry["message"] for entry in server_data.get("received", [])]
        client_replies = [entry["message"] for entry in client_data.get("replies", [])]
        if server_received != ["strict-request"]:
            pytest.fail(f"server did not receive strict-firewall request: {server_data!r}")
        if client_replies != ["strict-reply"]:
            pytest.fail(f"client did not receive strict-firewall reply: {client_data!r}")
        if probe_a.packets(vm, "invalid_drop_out") != 0:
            pytest.fail("NS_A output ct invalid-drop rule matched generated fake TCP")
        if probe_b.packets(vm, "invalid_drop_out") != 0:
            pytest.fail("NS_B output ct invalid-drop rule matched generated fake TCP")
    finally:
        server.terminate()
        probe_a.cleanup(vm)
        probe_b.cleanup(vm)
        cleanup_netns_topology(vm)


def test_netns_reinjected_udp_passes_conntrack_input_policy(phantun_module, vm):
    load_managed_module(phantun_module)
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
    load_managed_module(phantun_module)
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


def test_netns_tcp_mark_collision_does_not_bypass_translation(phantun_module, vm):
    if not require_guest_command(vm, "nft"):
        pytest.skip("nft is not available in the guest")
    load_managed_module(phantun_module)
    ensure_netns_topology(vm)
    src_port, dst_port = PORTS_A[0], PORTS_B[0]
    table = f"phantun_cookie_{uuid.uuid4().hex[:8]}"
    ready_file = f"/tmp/phantun-cookie-ready-{uuid.uuid4().hex}"
    received_file = f"/tmp/phantun-cookie-received-{uuid.uuid4().hex}"
    server = None
    try:
        run_in_netns(vm, NS_B, ["nft", "add", "table", "inet", table])
        run_in_netns(vm, NS_B, ["nft", "add", "set", "inet", table, "cookies", "{ type mark; flags dynamic; size 4; }"])
        run_in_netns(
            vm,
            NS_B,
            [
                "nft",
                "add",
                "chain",
                "inet",
                table,
                "ingress",
                "{ type filter hook prerouting priority -450; policy accept; }",
            ],
        )
        # Observe the actual per-netns cookie on manufactured UDP before the
        # module clears it, without depending on private struct layout.
        run_in_netns(
            vm,
            NS_B,
            [
                "nft",
                "add",
                "rule",
                "inet",
                table,
                "ingress",
                "ip",
                "saddr",
                NS_ADDR_A,
                "ip",
                "daddr",
                NS_ADDR_B,
                "udp",
                "dport",
                str(dst_port),
                "meta",
                "mark",
                "!=",
                "0",
                "add",
                "@cookies",
                "{ meta mark }",
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
                "timeout_sec": 20,
                "ready_file": ready_file,
                "first_received_file": received_file,
            },
        )
        wait_for_guest_ready_file(vm, ready_file)
        sender_config = {
            "bind_addr": NS_ADDR_A,
            "bind_port": src_port,
            "target_addr": NS_ADDR_B,
            "target_port": dst_port,
        }
        warmup = run_netns_scenario(vm, NS_A, "send_many", {**sender_config, "payloads": ["warmup"]}, timeout=10)
        assert_completed(warmup, "mark-collision warm-up")
        wait_for_guest_ready_file(vm, received_file)
        cookie_result = run_in_netns(vm, NS_B, ["nft", "-j", "list", "set", "inet", table, "cookies"])
        cookie_data = parse_guest_json(cookie_result.stdout, "reinjection cookie set")
        cookies = [
            value for entry in cookie_data["nftables"] if "set" in entry for value in entry["set"].get("elem", [])
        ]
        if len(cookies) != 1:
            pytest.fail(f"expected one observed reinjection cookie: {cookie_data!r}")
        cookie = int(cookies[0], 0) if isinstance(cookies[0], str) else cookies[0]
        if not isinstance(cookie, int) or cookie == 0:
            pytest.fail(f"invalid observed reinjection cookie: {cookie_data!r}")
        run_in_netns(
            vm,
            NS_B,
            [
                "nft",
                "add",
                "rule",
                "inet",
                table,
                "ingress",
                "ip",
                "saddr",
                NS_ADDR_A,
                "ip",
                "daddr",
                NS_ADDR_B,
                "tcp",
                "sport",
                str(src_port),
                "tcp",
                "dport",
                str(dst_port),
                "meta",
                "mark",
                "set",
                str(cookie),
                "counter",
                "comment",
                "cookie_collision",
            ],
        )
        sender = run_netns_scenario(vm, NS_A, "send_many", {**sender_config, "payloads": ["marked-data"]}, timeout=10)
        assert_completed(sender, "mark-collision sender")
        result = server.communicate(timeout=25)
        assert_completed(result, "mark-collision receiver")
        received = parse_guest_json(result.stdout, "mark-collision receiver")["received"]
        if [entry["message"] for entry in received] != ["warmup", "marked-data"]:
            pytest.fail(f"TCP carrying the UDP reinjection cookie bypassed translation: {received!r}")
        if NetnsNftProbe(NS_B, "inet", table, "ingress").packets(vm, "cookie_collision") == 0:
            pytest.fail("the TCP reinjection-mark collision was not exercised")
    finally:
        if server is not None:
            server.terminate()
        run_in_netns(vm, NS_B, ["nft", "delete", "table", "inet", table], check=False)
        vm.run(["rm", "-f", ready_file, received_file], check=False)
        cleanup_netns_topology(vm)


def test_netns_old_reinject_mark_constant_does_not_bypass_raw_udp_drop(phantun_module, vm):
    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    old_public_mark = 0x50485455
    ready_file = f"/tmp/phantun_old_reinject_{uuid.uuid4().hex}"

    phantun_module.load(managed_netns="all", managed_local_ports=str(dst_port))
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    mark_spoofer = make_netns_prerouting_udp_mark_set_probe(
        vm,
        NS_B,
        NS_ADDR_A,
        src_port,
        NS_ADDR_B,
        dst_port,
        old_public_mark,
    )
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "recv_until_timeout",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 1,
            "timeout_sec": 1,
            "ready_file": ready_file,
        },
    )

    try:
        wait_for_guest_ready_file(vm, ready_file, timeout=5)
        client = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["spoofed-reinject-mark"],
            },
        )
        assert_completed(client, "old reinject mark raw UDP sender")
        server_result = server.communicate(timeout=5)
        assert_completed(server_result, "old reinject mark raw UDP receiver")

        if mark_spoofer.packets(vm, "spoof_old_reinject_mark") == 0:
            pytest.fail("test rule did not set the old public reinjection mark")
        server_data = parse_guest_json(server_result.stdout, "old reinject mark receiver stdout")
        if server_data.get("received"):
            pytest.fail(f"old public reinjection mark bypassed raw UDP drop: {server_data!r}")
    finally:
        mark_spoofer.cleanup(vm)
        cleanup_netns_topology(vm)


def test_forwarded_fake_tcp_is_not_owned_in_prerouting(phantun_module, vm):
    phantun_module.load(managed_netns="all", managed_local_ports=str(PORTS_B[0]))
    ensure_forwarding_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_forwarding_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = 6000
    dst_port = PORTS_B[0]
    router_pre = make_netns_prerouting_flag_drop_probe(
        vm,
        ROUTER_NS,
        [
            {
                "src_addr": FWD_ADDR_A,
                "src_port": src_port,
                "dst_addr": FWD_ADDR_B,
                "dst_port": dst_port,
                "flags_expr": "syn",
                "comment": "forwarded_syn_seen",
                "action": "accept",
            }
        ],
    )
    router_synack = make_netns_output_flag_probe(
        vm,
        ROUTER_NS,
        [
            {
                "src_addr": FWD_ADDR_B,
                "dst_addr": FWD_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "syn | ack",
                "comment": "router_synack",
            }
        ],
    )
    dst_capture = spawn_ready_capture(
        vm,
        NS_B,
        {
            "bind_addr": FWD_ADDR_A,
            "bind_port": src_port,
            "target_addr": FWD_ADDR_B,
            "target_port": dst_port,
            "payload": "",
            "timeout_sec": 10,
        },
    )

    try:
        run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": FWD_ADDR_A,
                "bind_port": src_port,
                "target_addr": FWD_ADDR_B,
                "target_port": dst_port,
                "flags": "syn",
                "seq": 4095,
            },
        )
        time.sleep(0.5)
        capture_result = dst_capture.communicate(timeout=10)

        if router_pre.packets(vm, "forwarded_syn_seen") == 0:
            pytest.fail("forwarded SYN never reached router PRE_ROUTING in the test topology")
        if router_synack.packets(vm, "router_synack") != 0:
            pytest.fail("router namespace must not own or answer forwarded fake-TCP SYN traffic")
        assert_completed(capture_result, "destination forwarded SYN capture")
    finally:
        router_pre.cleanup(vm)
        router_synack.cleanup(vm)
        cleanup_forwarding_topology(vm)
