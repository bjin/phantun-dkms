import errno
import subprocess
import shlex
import time

import pytest

from helpers import (
    NS_A,
    NS_ADDR_A,
    NS_ADDR_B,
    NS_B,
    NS6_ADDR_A,
    NS6_ADDR_B,
    PORTS_A,
    PORTS_B,
    VETH_A,
    VETH_B,
    assert_completed,
    cleanup_netns_topology,
    ensure_netns_topology,
    make_netns_ingress_flag_drop_probe,
    make_netns_output_flag_probe,
    make_netns_output_probe,
    parse_guest_json,
    probe_comment,
    require_guest_command,
    run_guest_scenario,
    run_in_netns,
    run_netns_scenario,
    read_module_stat,
    spawn_netns_scenario,
)
from test_wireguard import (
    assert_ping_clean,
    assert_underlay_translation,
    guest_keypair,
    require_wireguard_stack,
    sum_probe_packets,
    wait_for_endpoint,
    wait_for_handshake,
    write_guest_secret,
)

MANAGED_LOCAL_PORTS = "2222,3333,4444,5555"
WG6_ADDR_A = "fd10:200::1/64"
WG6_ADDR_B = "fd10:200::2/64"
WG6_PEER_A = "fd10:200::1"
WG6_PEER_B = "fd10:200::2"
PORT_A = 2222
PORT_B = 3333
WG6_MTU = 1408
WG6_PING_PAYLOAD = 1360

DEPRECATED6_ADDR_A = "fd00:200::10"
DEPRECATED6_ADDR_B = "fd00:200::20"
LINKLOCAL6_ADDR_A = "fe80::a"
LINKLOCAL6_ADDR_B = "fe80::b"


def wg_endpoint(addr, port):
    return f"[{addr}]:{port}" if ":" in addr else f"{addr}:{port}"


def load_ipv6_module(phantun_module, **kwargs):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS, **kwargs)


def require_runtime_ipv6_support(phantun_module):
    cached = getattr(phantun_module, "_runtime_ipv6_supported", None)
    if cached is False:
        pytest.skip("runtime IPv6 translation support is unavailable for this module build")
    if cached is True:
        return

    try:
        phantun_module.load(managed_local_ports=str(PORTS_A[0]), ip_families="ipv6")
    except subprocess.CalledProcessError as exc:
        phantun_module._runtime_ipv6_supported = False
        phantun_module.unload()
        phantun_module.vm.run(["rm", "-f", "/etc/modprobe.d/phantun.conf"], check=False)
        detail = (exc.stderr or exc.stdout or str(exc)).strip()
        pytest.skip(
            "runtime IPv6 translation support is unavailable for this module build" + (f": {detail}" if detail else "")
        )
    else:
        phantun_module._runtime_ipv6_supported = True
        phantun_module.unload()
        phantun_module.vm.run(["rm", "-f", "/etc/modprobe.d/phantun.conf"], check=False)


@pytest.fixture(autouse=True)
def require_runtime_ipv6_for_test(phantun_module):
    require_runtime_ipv6_support(phantun_module)


def run_ping_pong(vm, src_addr, dst_addr, src_port=None, dst_port=None):
    src_port = src_port or PORTS_A[0]
    dst_port = dst_port or PORTS_B[0]
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "ping_server",
        {"bind_addr": dst_addr, "bind_port": dst_port, "reply": "pong"},
    )
    try:
        time.sleep(0.2)
        client_result = run_netns_scenario(
            vm,
            NS_A,
            "ping_client",
            {
                "bind_addr": src_addr,
                "bind_port": src_port,
                "target_addr": dst_addr,
                "target_port": dst_port,
                "payload": "ping",
            },
            timeout=10,
        )
        server_result = server.communicate(timeout=10)
    except Exception:
        server.terminate()
        raise

    assert_completed(client_result, "ping client")
    assert_completed(server_result, "ping server")
    server_data = parse_guest_json(server_result.stdout, "ping server stdout")
    client_data = parse_guest_json(client_result.stdout, "ping client stdout")
    assert server_data.get("received") == "ping"
    assert server_data.get("peer") == [src_addr, src_port]
    assert client_data.get("reply") == "pong"
    assert client_data.get("peer") == [dst_addr, dst_port]


def run_tcp_bind_probe(vm, bind_addr, bind_port, v6only=None):
    result = run_guest_scenario(
        vm,
        "tcp_bind_listen",
        {"bind_addr": bind_addr, "bind_port": bind_port, "v6only": v6only},
    )
    return parse_guest_json(result.stdout, f"tcp bind probe {bind_addr}:{bind_port}")


def require_nft_or_skip(vm):
    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")


def test_ipv6_udp_ping_pong_uses_tcp_output_only(phantun_module, vm):
    load_ipv6_module(phantun_module)
    ensure_netns_topology(vm, with_ipv6=True)
    require_nft_or_skip(vm)

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    probe_a = make_netns_output_probe(vm, NS_A, [(NS6_ADDR_A, src_port, NS6_ADDR_B, dst_port)])
    probe_b = make_netns_output_probe(vm, NS_B, [(NS6_ADDR_B, dst_port, NS6_ADDR_A, src_port)])
    try:
        run_ping_pong(vm, NS6_ADDR_A, NS6_ADDR_B, src_port, dst_port)
        udp_a = probe_a.packets(vm, probe_comment("udp", NS6_ADDR_A, src_port, NS6_ADDR_B, dst_port))
        tcp_a = probe_a.packets(vm, probe_comment("tcp", NS6_ADDR_A, src_port, NS6_ADDR_B, dst_port))
        udp_b = probe_b.packets(vm, probe_comment("udp", NS6_ADDR_B, dst_port, NS6_ADDR_A, src_port))
        tcp_b = probe_b.packets(vm, probe_comment("tcp", NS6_ADDR_B, dst_port, NS6_ADDR_A, src_port))
        assert udp_a == 0 and udp_b == 0
        assert tcp_a > 0 and tcp_b > 0
    finally:
        probe_a.cleanup(vm)
        probe_b.cleanup(vm)
        cleanup_netns_topology(vm)


def test_ipv6_managed_remote_peers_bracketed_peer(phantun_module, vm):
    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    phantun_module.load(managed_remote_peers=f"[{NS6_ADDR_B}]:{dst_port},[{NS6_ADDR_A}]:{src_port}")
    ensure_netns_topology(vm, with_ipv6=True)
    require_nft_or_skip(vm)

    probe_a = make_netns_output_probe(vm, NS_A, [(NS6_ADDR_A, src_port, NS6_ADDR_B, dst_port)])
    try:
        run_ping_pong(vm, NS6_ADDR_A, NS6_ADDR_B, src_port, dst_port)
        assert probe_a.packets(vm, probe_comment("tcp", NS6_ADDR_A, src_port, NS6_ADDR_B, dst_port)) > 0
    finally:
        probe_a.cleanup(vm)
        cleanup_netns_topology(vm)

    phantun_module.unload()
    vm.run("echo 'options phantun managed_remote_peers=fd00:200::2:3333' > /etc/modprobe.d/phantun.conf")
    try:
        res = vm.run(["modprobe", "phantun"], check=False)
        assert res.returncode != 0
    finally:
        vm.run(["rm", "-f", "/etc/modprobe.d/phantun.conf"])
        phantun_module.unload()


def test_ipv6_deprecated_global_addresses_are_preserved(phantun_module, vm):
    load_ipv6_module(phantun_module)
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


def test_ipv6_link_local_endpoints_are_rejected(phantun_module, vm):
    load_ipv6_module(phantun_module)
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


def test_ip_families_can_disable_one_family(phantun_module, vm):
    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]

    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS, ip_families="ipv4")
    ensure_netns_topology(vm, with_ipv6=True)
    require_nft_or_skip(vm)
    probe_v6_plain = make_netns_output_probe(
        vm,
        NS_A,
        [(NS6_ADDR_A, src_port, NS6_ADDR_B, dst_port)],
        udp_action="accept",
    )
    try:
        run_ping_pong(vm, NS6_ADDR_A, NS6_ADDR_B, src_port, dst_port)
        assert probe_v6_plain.packets(vm, probe_comment("udp", NS6_ADDR_A, src_port, NS6_ADDR_B, dst_port)) > 0
        assert probe_v6_plain.packets(vm, probe_comment("tcp", NS6_ADDR_A, src_port, NS6_ADDR_B, dst_port)) == 0
    finally:
        probe_v6_plain.cleanup(vm)
        cleanup_netns_topology(vm)

    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS, ip_families="ipv6")
    ensure_netns_topology(vm, with_ipv6=True)
    require_nft_or_skip(vm)
    probe_v4_plain = make_netns_output_probe(
        vm,
        NS_A,
        [(NS_ADDR_A, src_port, NS_ADDR_B, dst_port)],
        udp_action="accept",
    )
    probe_v6 = make_netns_output_probe(vm, NS_A, [(NS6_ADDR_A, src_port, NS6_ADDR_B, dst_port)])
    try:
        run_ping_pong(vm, NS_ADDR_A, NS_ADDR_B, src_port, dst_port)
        assert probe_v4_plain.packets(vm, probe_comment("udp", NS_ADDR_A, src_port, NS_ADDR_B, dst_port)) > 0
        assert probe_v4_plain.packets(vm, probe_comment("tcp", NS_ADDR_A, src_port, NS_ADDR_B, dst_port)) == 0
        run_ping_pong(vm, NS6_ADDR_A, NS6_ADDR_B, src_port, dst_port)
        assert probe_v6.packets(vm, probe_comment("tcp", NS6_ADDR_A, src_port, NS6_ADDR_B, dst_port)) > 0
    finally:
        probe_v4_plain.cleanup(vm)
        probe_v6.cleanup(vm)
        cleanup_netns_topology(vm)


def test_reserved_local_ports_respect_ipv6_family_mode(phantun_module, vm):
    managed_port = PORTS_A[0]
    phantun_module.load(
        managed_local_ports=str(managed_port),
        reserved_local_ports="all",
        ip_families="ipv6",
    )

    ipv4_probe = run_tcp_bind_probe(vm, "0.0.0.0", managed_port)
    ipv6_probe = run_tcp_bind_probe(vm, "::", managed_port, v6only=True)
    assert ipv4_probe.get("ok")
    assert not ipv6_probe.get("ok") and ipv6_probe.get("errno") == errno.EADDRINUSE

    phantun_module.load(
        managed_local_ports=str(managed_port),
        reserved_local_ports="all",
        ip_families="both",
    )

    ipv4_probe = run_tcp_bind_probe(vm, "0.0.0.0", managed_port)
    ipv6_probe = run_tcp_bind_probe(vm, "::", managed_port, v6only=True)
    assert not ipv4_probe.get("ok") and ipv4_probe.get("errno") == errno.EADDRINUSE
    assert not ipv6_probe.get("ok") and ipv6_probe.get("errno") == errno.EADDRINUSE


def test_ipv6_synack_loss_is_retried(phantun_module, vm):
    load_ipv6_module(phantun_module)
    ensure_netns_topology(vm, with_ipv6=True)
    require_nft_or_skip(vm)

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    probe = make_netns_ingress_flag_drop_probe(
        vm,
        NS_A,
        VETH_A,
        [
            {
                "src_addr": NS6_ADDR_B,
                "src_port": dst_port,
                "dst_addr": NS6_ADDR_A,
                "dst_port": src_port,
                "flags_expr": "syn | ack",
                "comment": "drop_synack_v6",
            }
        ],
    )
    synack_probe = make_netns_output_flag_probe(
        vm,
        NS_B,
        [
            {
                "src_addr": NS6_ADDR_B,
                "dst_addr": NS6_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "syn | ack",
                "comment": "sent_synack_v6",
            }
        ],
    )
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "ping_server",
        {
            "bind_addr": NS6_ADDR_B,
            "bind_port": dst_port,
            "reply": "pong",
        },
    )

    try:
        time.sleep(0.2)
        baseline_synack = synack_probe.packets(vm, "sent_synack_v6")
        client = spawn_netns_scenario(
            vm,
            NS_A,
            "ping_client",
            {
                "bind_addr": NS6_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS6_ADDR_B,
                "target_port": dst_port,
                "payload": "ping",
            },
        )
        time.sleep(1.25)
        probe.cleanup(vm)

        client_result = client.communicate(timeout=12)
        server_result = server.communicate(timeout=12)
        assert_completed(client_result, "ipv6 synack-loss client")
        assert_completed(server_result, "ipv6 synack-loss server")

        client_data = parse_guest_json(client_result.stdout, "ipv6 synack-loss client stdout")
        server_data = parse_guest_json(server_result.stdout, "ipv6 synack-loss server stdout")
        assert client_data.get("reply") == "pong"
        assert server_data.get("received") == "ping"
        if synack_probe.packets(vm, "sent_synack_v6") <= baseline_synack + 1:
            pytest.fail("expected responder to re-send IPv6 SYN|ACK after initiator re-sent SYN")
    finally:
        probe.cleanup(vm)
        synack_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def setup_wireguard_pair_ipv6(vm, endpoint_a=NS6_ADDR_A, endpoint_b=NS6_ADDR_B):
    priv_a, pub_a = guest_keypair(vm)
    priv_b, pub_b = guest_keypair(vm)
    key_a_path = "/tmp/wg6-a.key"
    key_b_path = "/tmp/wg6-b.key"

    write_guest_secret(vm, key_a_path, priv_a)
    write_guest_secret(vm, key_b_path, priv_b)
    run_in_netns(vm, NS_A, ["ip", "link", "add", "wg0", "type", "wireguard"])
    run_in_netns(vm, NS_B, ["ip", "link", "add", "wg0", "type", "wireguard"])
    run_in_netns(vm, NS_A, ["ip", "-6", "address", "add", WG6_ADDR_A, "dev", "wg0", "nodad"])
    run_in_netns(vm, NS_B, ["ip", "-6", "address", "add", WG6_ADDR_B, "dev", "wg0", "nodad"])
    for namespace in (NS_A, NS_B):
        run_in_netns(vm, namespace, ["ip", "link", "set", "wg0", "mtu", str(WG6_MTU)])

    run_in_netns(
        vm,
        NS_A,
        [
            "wg",
            "set",
            "wg0",
            "listen-port",
            str(PORT_A),
            "private-key",
            key_a_path,
            "peer",
            pub_b,
            "allowed-ips",
            f"{WG6_PEER_B}/128",
            "endpoint",
            wg_endpoint(endpoint_b, PORT_B),
            "persistent-keepalive",
            "1",
        ],
    )
    run_in_netns(
        vm,
        NS_B,
        [
            "wg",
            "set",
            "wg0",
            "listen-port",
            str(PORT_B),
            "private-key",
            key_b_path,
            "peer",
            pub_a,
            "allowed-ips",
            f"{WG6_PEER_A}/128",
            "endpoint",
            wg_endpoint(endpoint_a, PORT_A),
            "persistent-keepalive",
            "1",
        ],
    )
    run_in_netns(vm, NS_A, ["ip", "link", "set", "wg0", "up"])
    run_in_netns(vm, NS_B, ["ip", "link", "set", "wg0", "up"])
    return key_a_path, key_b_path


def ping6_wireguard_peer(vm, namespace, target, label, size=None):
    command = ["ping", "-6", "-c", "3", "-W", "1"]
    if size is not None:
        command.extend(["-s", str(size)])
    command.append(target)
    result = run_in_netns(vm, namespace, command)
    assert_ping_clean(result, label)


def cleanup_wireguard(vm, key_a_path, key_b_path):
    run_in_netns(vm, NS_A, ["ip", "link", "del", "wg0"], check=False)
    run_in_netns(vm, NS_B, ["ip", "link", "del", "wg0"], check=False)
    vm.run(["rm", "-f", key_a_path, key_b_path], check=False)
    cleanup_netns_topology(vm)


def test_kernel_wireguard_over_ipv6_phantun_translates_underlay(phantun_module, vm):
    require_wireguard_stack(vm)
    phantun_module.load(managed_local_ports=f"{PORT_A},{PORT_B}")
    ensure_netns_topology(vm, with_ipv6=True)
    key_a_path = key_b_path = "/tmp/nonexistent"
    underlay_a = [(NS6_ADDR_A, PORT_A, NS6_ADDR_B, PORT_B)]
    underlay_b = [(NS6_ADDR_B, PORT_B, NS6_ADDR_A, PORT_A)]
    probe_a = make_netns_output_probe(vm, NS_A, underlay_a)
    probe_b = make_netns_output_probe(vm, NS_B, underlay_b)
    try:
        key_a_path, key_b_path = setup_wireguard_pair_ipv6(vm)
        ping6_wireguard_peer(vm, NS_A, WG6_PEER_B, "ns_a -> ns_b IPv6 ping")
        ping6_wireguard_peer(vm, NS_B, WG6_PEER_A, "ns_b -> ns_a IPv6 ping")
        ping6_wireguard_peer(
            vm,
            NS_A,
            WG6_PEER_B,
            "ns_a -> ns_b IPv6 near-MTU ping",
            size=WG6_PING_PAYLOAD,
        )
        ping6_wireguard_peer(
            vm,
            NS_B,
            WG6_PEER_A,
            "ns_b -> ns_a IPv6 near-MTU ping",
            size=WG6_PING_PAYLOAD,
        )
        wait_for_handshake(vm)
        wait_for_endpoint(vm, NS_A, wg_endpoint(NS6_ADDR_B, PORT_B))
        wait_for_endpoint(vm, NS_B, wg_endpoint(NS6_ADDR_A, PORT_A))
        assert_underlay_translation(vm, probe_a, probe_b, underlay_a, underlay_b, "wireguard IPv6")
    finally:
        probe_a.cleanup(vm)
        probe_b.cleanup(vm)
        cleanup_wireguard(vm, key_a_path, key_b_path)


def test_kernel_wireguard_roaming_between_ipv4_and_ipv6_endpoints(phantun_module, vm):
    require_wireguard_stack(vm)
    phantun_module.load(managed_local_ports=f"{PORT_A},{PORT_B}")
    ensure_netns_topology(vm, with_ipv6=True)
    key_a_path = key_b_path = "/tmp/nonexistent"
    ipv6_a = (NS6_ADDR_A, PORT_A, NS6_ADDR_B, PORT_B)
    ipv6_b = (NS6_ADDR_B, PORT_B, NS6_ADDR_A, PORT_A)
    ipv4_a = (NS_ADDR_A, PORT_A, NS_ADDR_B, PORT_B)
    ipv4_b = (NS_ADDR_B, PORT_B, NS_ADDR_A, PORT_A)
    probe_a = make_netns_output_probe(vm, NS_A, [ipv6_a, ipv4_a])
    probe_b = make_netns_output_probe(vm, NS_B, [ipv6_b, ipv4_b])
    try:
        key_a_path, key_b_path = setup_wireguard_pair_ipv6(vm)
        ping6_wireguard_peer(vm, NS_A, WG6_PEER_B, "initial IPv6 underlay ping")
        wait_for_endpoint(vm, NS_A, wg_endpoint(NS6_ADDR_B, PORT_B))
        assert_underlay_translation(vm, probe_a, probe_b, [ipv6_a], [ipv6_b], "initial IPv6 underlay")

        base_v4_a = sum_probe_packets(vm, probe_a, "tcp", [ipv4_a])
        base_v4_b = sum_probe_packets(vm, probe_b, "tcp", [ipv4_b])
        run_in_netns(
            vm,
            NS_B,
            f"wg set wg0 peer $(wg show wg0 peers) endpoint {shlex.quote(wg_endpoint(NS_ADDR_A, PORT_A))}",
        )
        ping6_wireguard_peer(vm, NS_B, WG6_PEER_A, "roam to IPv4 underlay ping")
        wait_for_endpoint(vm, NS_A, wg_endpoint(NS_ADDR_B, PORT_B))
        if sum_probe_packets(vm, probe_a, "tcp", [ipv4_a]) <= base_v4_a:
            pytest.fail("return traffic did not move to IPv4 translated TCP")
        if sum_probe_packets(vm, probe_b, "tcp", [ipv4_b]) <= base_v4_b:
            pytest.fail("roaming peer did not send IPv4 translated TCP")

        base_v6_a = sum_probe_packets(vm, probe_a, "tcp", [ipv6_a])
        base_v6_b = sum_probe_packets(vm, probe_b, "tcp", [ipv6_b])
        run_in_netns(
            vm,
            NS_B,
            f"wg set wg0 peer $(wg show wg0 peers) endpoint {shlex.quote(wg_endpoint(NS6_ADDR_A, PORT_A))}",
        )
        ping6_wireguard_peer(vm, NS_B, WG6_PEER_A, "roam back to IPv6 underlay ping")
        wait_for_endpoint(vm, NS_A, wg_endpoint(NS6_ADDR_B, PORT_B))
        if sum_probe_packets(vm, probe_a, "tcp", [ipv6_a]) <= base_v6_a:
            pytest.fail("return traffic did not move back to IPv6 translated TCP")
        if sum_probe_packets(vm, probe_b, "tcp", [ipv6_b]) <= base_v6_b:
            pytest.fail("roaming peer did not send IPv6 translated TCP")
        if sum_probe_packets(vm, probe_a, "udp", [ipv6_a, ipv4_a]) != 0:
            pytest.fail("raw UDP escaped from ns_a during mixed-family roaming")
        if sum_probe_packets(vm, probe_b, "udp", [ipv6_b, ipv4_b]) != 0:
            pytest.fail("raw UDP escaped from ns_b during mixed-family roaming")
    finally:
        probe_a.cleanup(vm)
        probe_b.cleanup(vm)
        cleanup_wireguard(vm, key_a_path, key_b_path)
