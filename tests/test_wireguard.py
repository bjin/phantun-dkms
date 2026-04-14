import re
import shlex
import time

import pytest

from helpers import (
    NS_A,
    NS_ADDR_A,
    NS_ADDR_B,
    NS_B,
    VETH_A,
    VETH_B,
    assert_completed,
    cleanup_netns_topology,
    ensure_netns_topology,
    make_netns_output_probe,
    make_netns_tcp_payload_probe,
    parse_guest_json,
    probe_comment,
    read_module_stats,
    require_guest_command,
    run_in_netns,
    run_netns_scenario,
    spawn_netns_scenario,
)

WG_ADDR_A = "10.10.0.1/24"
WG_ADDR_B = "10.10.0.2/24"
WG_PEER_A = "10.10.0.1"
WG_PEER_B = "10.10.0.2"
PORT_A = 2222
PORT_B = 3333
MANAGED_LOCAL_PORTS = "2222,3333"
REQ = "WGREQ42"
RESP = "WGRESP42"
NS_ADDR_B_ROAM = "10.200.0.22"


def load_wireguard_module(phantun_module, **kwargs):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS, **kwargs)


def require_wireguard_stack(vm):
    if not require_guest_command(vm, "wg"):
        pytest.skip("wg userspace tool is not available in the guest")
    if not require_guest_command(vm, "ping"):
        pytest.skip("ping is not available in the guest")
    if vm.run(["modprobe", "wireguard"], check=False).returncode != 0:
        pytest.skip("wireguard kernel module is not available in the guest")


def guest_keypair(vm):
    private_key = vm.run(["wg", "genkey"]).stdout.strip()
    public_key = vm.run(f"printf '%s' {shlex.quote(private_key)} | wg pubkey").stdout.strip()
    return private_key, public_key


def write_guest_secret(vm, path, secret):
    vm.run(f"umask 077 && printf '%s' {shlex.quote(secret)} > {shlex.quote(path)}")


def latest_handshake_timestamp(vm, namespace):
    res = run_in_netns(vm, namespace, ["wg", "show", "wg0", "latest-handshakes"])
    parts = res.stdout.strip().split()
    if len(parts) < 2:
        return 0
    return int(parts[1])


def wait_for_handshake(vm, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if latest_handshake_timestamp(vm, NS_A) > 0 and latest_handshake_timestamp(vm, NS_B) > 0:
            return
        time.sleep(0.5)
    pytest.fail("WireGuard handshake did not complete on both peers")


def wait_for_endpoint(vm, namespace, expected_endpoint, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        show = run_in_netns(vm, namespace, ["wg", "show", "wg0"]).stdout
        if f"endpoint: {expected_endpoint}" in show:
            return show
        time.sleep(0.5)
    pytest.fail(f"wg0 in {namespace} never reported endpoint {expected_endpoint!r} within {timeout}s")


def assert_ping_clean(result, label):
    summary = None
    for line in result.stdout.splitlines():
        if "packets transmitted" in line:
            summary = line.strip()
            break

    if summary is None:
        pytest.fail(f"{label}: ping output missing summary: {result.stdout!r}")
    if not re.search(r"\b3 packets transmitted, 3 received\b", summary):
        pytest.fail(f"{label}: unexpected ping summary: {summary!r}")
    if "duplicates" in summary or "DUP!" in result.stdout:
        pytest.fail(f"{label}: duplicate ICMP replies detected: {result.stdout!r}")


def ping_wireguard_peer(vm, namespace, target, label):
    result = run_in_netns(vm, namespace, ["ping", "-c", "3", "-W", "1", target])
    assert_ping_clean(result, label)


def sum_probe_packets(vm, probe, prefix, channels):
    return sum(probe.packets(vm, probe_comment(prefix, *channel)) for channel in channels)


def setup_wireguard_pair(vm, endpoint_a=NS_ADDR_A, endpoint_b=NS_ADDR_B):
    priv_a, pub_a = guest_keypair(vm)
    priv_b, pub_b = guest_keypair(vm)
    key_a_path = "/tmp/wg-a.key"
    key_b_path = "/tmp/wg-b.key"

    write_guest_secret(vm, key_a_path, priv_a)
    write_guest_secret(vm, key_b_path, priv_b)

    run_in_netns(vm, NS_A, ["ip", "link", "add", "wg0", "type", "wireguard"])
    run_in_netns(vm, NS_B, ["ip", "link", "add", "wg0", "type", "wireguard"])
    run_in_netns(vm, NS_A, ["ip", "address", "add", WG_ADDR_A, "dev", "wg0"])
    run_in_netns(vm, NS_B, ["ip", "address", "add", WG_ADDR_B, "dev", "wg0"])

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
            f"{WG_PEER_B}/32",
            "endpoint",
            f"{endpoint_b}:{PORT_B}",
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
            f"{WG_PEER_A}/32",
            "endpoint",
            f"{endpoint_a}:{PORT_A}",
            "persistent-keepalive",
            "1",
        ],
    )
    run_in_netns(vm, NS_A, ["ip", "link", "set", "wg0", "up"])
    run_in_netns(vm, NS_B, ["ip", "link", "set", "wg0", "up"])
    return key_a_path, key_b_path


def assert_wireguard_peer_state(vm, endpoint_a, endpoint_b):
    wait_for_handshake(vm)
    wg_a = wait_for_endpoint(vm, NS_A, f"{endpoint_b}:{PORT_B}")
    wg_b = wait_for_endpoint(vm, NS_B, f"{endpoint_a}:{PORT_A}")
    if "latest handshake" not in wg_a or "latest handshake" not in wg_b:
        pytest.fail("`wg show wg0` did not report a successful handshake on both peers")
    if "127.0.0.1:" in wg_a or "127.0.0.1:" in wg_b:
        pytest.fail("`wg show wg0` reported a loopback endpoint, which should never be required")
    return wg_a, wg_b


def assert_underlay_translation(vm, probe_a, probe_b, channels_a, channels_b, label):
    udp_a = sum_probe_packets(vm, probe_a, "udp", channels_a)
    tcp_a = sum_probe_packets(vm, probe_a, "tcp", channels_a)
    udp_b = sum_probe_packets(vm, probe_b, "udp", channels_b)
    tcp_b = sum_probe_packets(vm, probe_b, "tcp", channels_b)

    if udp_a != 0 or udp_b != 0:
        pytest.fail(f"{label}: raw UDP escaped on the WireGuard underlay path: ns_a={udp_a}, ns_b={udp_b}")
    if tcp_a == 0 or tcp_b == 0:
        pytest.fail(f"{label}: expected translated TCP on the WireGuard underlay path, got ns_a={tcp_a}, ns_b={tcp_b}")


def build_payload_probes(vm, handshake_request=None, handshake_response=None):
    probe_a = None
    probe_b = None
    if handshake_request:
        probe_a = make_netns_tcp_payload_probe(
            vm,
            NS_A,
            [
                {
                    "src_addr": NS_ADDR_A,
                    "src_port": PORT_A,
                    "dst_addr": NS_ADDR_B,
                    "dst_port": PORT_B,
                    "payload": handshake_request,
                    "comment": "wireguard_req",
                    "action": "accept",
                }
            ],
        )
    if handshake_response:
        probe_b = make_netns_tcp_payload_probe(
            vm,
            NS_B,
            [
                {
                    "src_addr": NS_ADDR_B,
                    "src_port": PORT_B,
                    "dst_addr": NS_ADDR_A,
                    "dst_port": PORT_A,
                    "payload": handshake_response,
                    "comment": "wireguard_resp",
                    "action": "accept",
                }
            ],
        )
    return probe_a, probe_b


def set_underlay_netem(vm, delay_ms, loss_percent=None):
    cmd_a = ["tc", "qdisc", "replace", "dev", VETH_A, "root", "netem", "delay", f"{delay_ms}ms"]
    cmd_b = ["tc", "qdisc", "replace", "dev", VETH_B, "root", "netem", "delay", f"{delay_ms}ms"]
    if loss_percent is not None:
        cmd_a.extend(["loss", f"{loss_percent}%"])
        cmd_b.extend(["loss", f"{loss_percent}%"])
    run_in_netns(vm, NS_A, cmd_a)
    run_in_netns(vm, NS_B, cmd_b)


def clear_underlay_netem(vm):
    run_in_netns(vm, NS_A, ["tc", "qdisc", "del", "dev", VETH_A, "root"], check=False)
    run_in_netns(vm, NS_B, ["tc", "qdisc", "del", "dev", VETH_B, "root"], check=False)


def test_kernel_wireguard_bulk_tcp_transfer_keeps_flows_stable(phantun_module, vm):
    require_wireguard_stack(vm)
    if not require_guest_command(vm, "tc"):
        pytest.skip("tc is not available in the guest")

    load_wireguard_module(phantun_module, handshake_request=REQ)
    ensure_netns_topology(vm)

    key_a_path = "/tmp/wg-a.key"
    key_b_path = "/tmp/wg-b.key"
    total_bytes = 8 * 1024 * 1024
    baseline_stats = None

    try:
        set_underlay_netem(vm, delay_ms=20)
        key_a_path, key_b_path = setup_wireguard_pair(vm)
        wait_for_handshake(vm, timeout=20)
        wait_for_endpoint(vm, NS_A, f"{NS_ADDR_B}:{PORT_B}", timeout=20)
        wait_for_endpoint(vm, NS_B, f"{NS_ADDR_A}:{PORT_A}", timeout=20)
        ping_wireguard_peer(vm, NS_A, WG_PEER_B, "bulk wireguard ping a->b")
        ping_wireguard_peer(vm, NS_B, WG_PEER_A, "bulk wireguard ping b->a")

        baseline_stats = read_module_stats(vm)
        server = spawn_netns_scenario(
            vm,
            NS_B,
            "tcp_bulk_server",
            {
                "bind_addr": WG_PEER_B,
                "bind_port": 5001,
                "bytes": total_bytes,
                "timeout_sec": 30,
            },
        )
        time.sleep(0.2)
        client_result = run_netns_scenario(
            vm,
            NS_A,
            "tcp_bulk_client",
            {
                "bind_addr": WG_PEER_A,
                "bind_port": 0,
                "target_addr": WG_PEER_B,
                "target_port": 5001,
                "bytes": total_bytes,
                "timeout_sec": 30,
            },
            timeout=40,
        )
        server_result = server.communicate(timeout=40)

        assert_completed(client_result, "wireguard bulk tcp client")
        assert_completed(server_result, "wireguard bulk tcp server")

        client_data = parse_guest_json(client_result.stdout, "wireguard bulk tcp client stdout")
        server_data = parse_guest_json(server_result.stdout, "wireguard bulk tcp server stdout")
        final_stats = read_module_stats(vm)

        if client_data.get("sent_bytes") != total_bytes:
            pytest.fail(f"bulk tcp client sent unexpected byte count: {client_data!r}")
        if server_data.get("received_bytes") != total_bytes:
            pytest.fail(f"bulk tcp server received unexpected byte count: {server_data!r}")

        server_seconds = server_data.get("seconds", 0)
        if not isinstance(server_seconds, (int, float)) or server_seconds <= 0:
            pytest.fail(f"bulk tcp server reported invalid duration: {server_data!r}")
        if server_seconds > 15:
            pytest.fail(f"bulk tcp transfer took unexpectedly long over WireGuard: {server_data!r}")

        created_delta = final_stats["flows_created"] - baseline_stats["flows_created"]
        queued_delta = final_stats["udp_packets_queued"] - baseline_stats["udp_packets_queued"]
        rst_delta = final_stats["rst_sent"] - baseline_stats["rst_sent"]
        if created_delta > 2:
            pytest.fail(
                f"bulk tcp transfer created too many new phantun flows after handshake: baseline={baseline_stats!r} final={final_stats!r}"
            )
        if queued_delta > 2:
            pytest.fail(
                f"bulk tcp transfer queued too many UDP packets after handshake: baseline={baseline_stats!r} final={final_stats!r}"
            )
        if rst_delta != 0:
            pytest.fail(
                f"bulk tcp transfer emitted unexpected RSTs after handshake: baseline={baseline_stats!r} final={final_stats!r}"
            )
    finally:
        clear_underlay_netem(vm)
        run_in_netns(vm, NS_A, ["ip", "link", "del", "wg0"], check=False)
        run_in_netns(vm, NS_B, ["ip", "link", "del", "wg0"], check=False)
        vm.run(["rm", "-f", key_a_path, key_b_path], check=False)
        cleanup_netns_topology(vm)


@pytest.mark.parametrize(
    ("module_kwargs", "expect_request", "expect_response"),
    [
        pytest.param({}, False, False, id="plain"),
        pytest.param({"handshake_request": REQ}, True, False, id="request"),
        pytest.param(
            {"handshake_request": REQ, "handshake_response": RESP},
            True,
            True,
            id="request-response",
        ),
    ],
)
def test_kernel_wireguard_over_phantun_translates_underlay(
    phantun_module, vm, module_kwargs, expect_request, expect_response
):
    require_wireguard_stack(vm)
    load_wireguard_module(phantun_module, **module_kwargs)
    ensure_netns_topology(vm)

    underlay_a = [(NS_ADDR_A, PORT_A, NS_ADDR_B, PORT_B)]
    underlay_b = [(NS_ADDR_B, PORT_B, NS_ADDR_A, PORT_A)]
    probe_a = make_netns_output_probe(vm, NS_A, underlay_a)
    probe_b = make_netns_output_probe(vm, NS_B, underlay_b)
    payload_probe_a, payload_probe_b = build_payload_probes(
        vm,
        handshake_request=module_kwargs.get("handshake_request"),
        handshake_response=module_kwargs.get("handshake_response"),
    )
    key_a_path = "/tmp/wg-a.key"
    key_b_path = "/tmp/wg-b.key"

    try:
        key_a_path, key_b_path = setup_wireguard_pair(vm)
        ping_wireguard_peer(vm, NS_A, WG_PEER_B, "ns_a -> ns_b ping")
        ping_wireguard_peer(vm, NS_B, WG_PEER_A, "ns_b -> ns_a ping")
        assert_wireguard_peer_state(vm, NS_ADDR_A, NS_ADDR_B)
        assert_underlay_translation(vm, probe_a, probe_b, underlay_a, underlay_b, "wireguard")

        if expect_request:
            if payload_probe_a is None:
                pytest.fail("handshake_request probe was not armed")
            if payload_probe_a.packets(vm, "wireguard_req") == 0:
                pytest.fail("did not observe handshake_request on the WireGuard TCP underlay path")
        if expect_response:
            if payload_probe_b is None:
                pytest.fail("handshake_response probe was not armed")
            if payload_probe_b.packets(vm, "wireguard_resp") == 0:
                pytest.fail("did not observe handshake_response on the WireGuard TCP underlay path")
    finally:
        run_in_netns(vm, NS_A, ["ip", "link", "del", "wg0"], check=False)
        run_in_netns(vm, NS_B, ["ip", "link", "del", "wg0"], check=False)
        vm.run(["rm", "-f", key_a_path, key_b_path], check=False)
        if payload_probe_a is not None:
            payload_probe_a.cleanup(vm)
        if payload_probe_b is not None:
            payload_probe_b.cleanup(vm)
        probe_a.cleanup(vm)
        probe_b.cleanup(vm)
        cleanup_netns_topology(vm)


def test_kernel_wireguard_roaming_updates_endpoint(phantun_module, vm):
    require_wireguard_stack(vm)
    load_wireguard_module(phantun_module)
    ensure_netns_topology(vm)

    old_underlay_a = (NS_ADDR_A, PORT_A, NS_ADDR_B, PORT_B)
    old_underlay_b = (NS_ADDR_B, PORT_B, NS_ADDR_A, PORT_A)
    new_underlay_a = (NS_ADDR_A, PORT_A, NS_ADDR_B_ROAM, PORT_B)
    new_underlay_b = (NS_ADDR_B_ROAM, PORT_B, NS_ADDR_A, PORT_A)
    probe_a = make_netns_output_probe(vm, NS_A, [old_underlay_a, new_underlay_a])
    probe_b = make_netns_output_probe(vm, NS_B, [old_underlay_b, new_underlay_b])
    key_a_path = "/tmp/wg-a.key"
    key_b_path = "/tmp/wg-b.key"

    try:
        key_a_path, key_b_path = setup_wireguard_pair(vm)
        ping_wireguard_peer(vm, NS_A, WG_PEER_B, "initial ns_a -> ns_b ping")
        ping_wireguard_peer(vm, NS_B, WG_PEER_A, "initial ns_b -> ns_a ping")
        assert_wireguard_peer_state(vm, NS_ADDR_A, NS_ADDR_B)
        assert_underlay_translation(
            vm,
            probe_a,
            probe_b,
            [old_underlay_a],
            [old_underlay_b],
            "wireguard initial path",
        )

        baseline_new_tcp_a = sum_probe_packets(vm, probe_a, "tcp", [new_underlay_a])
        baseline_new_tcp_b = sum_probe_packets(vm, probe_b, "tcp", [new_underlay_b])

        run_in_netns(vm, NS_B, ["ip", "addr", "del", f"{NS_ADDR_B}/24", "dev", VETH_B])
        run_in_netns(vm, NS_B, ["ip", "addr", "add", f"{NS_ADDR_B_ROAM}/24", "dev", VETH_B])
        time.sleep(0.2)

        ping_wireguard_peer(vm, NS_B, WG_PEER_A, "roamed ns_b -> ns_a ping")
        wait_for_endpoint(vm, NS_A, f"{NS_ADDR_B_ROAM}:{PORT_B}")
        ping_wireguard_peer(vm, NS_A, WG_PEER_B, "post-roam ns_a -> ns_b ping")
        assert_wireguard_peer_state(vm, NS_ADDR_A, NS_ADDR_B_ROAM)

        new_tcp_a = sum_probe_packets(vm, probe_a, "tcp", [new_underlay_a]) - baseline_new_tcp_a
        new_tcp_b = sum_probe_packets(vm, probe_b, "tcp", [new_underlay_b]) - baseline_new_tcp_b
        if new_tcp_a == 0 or new_tcp_b == 0:
            pytest.fail("WireGuard roaming did not move the translated TCP underlay traffic onto the new endpoint")
        if sum_probe_packets(vm, probe_a, "udp", [old_underlay_a, new_underlay_a]) != 0:
            pytest.fail("raw UDP escaped from the unchanged peer during WireGuard roaming")
        if sum_probe_packets(vm, probe_b, "udp", [old_underlay_b, new_underlay_b]) != 0:
            pytest.fail("raw UDP escaped from the roaming peer during WireGuard roaming")
    finally:
        run_in_netns(vm, NS_A, ["ip", "link", "del", "wg0"], check=False)
        run_in_netns(vm, NS_B, ["ip", "link", "del", "wg0"], check=False)
        vm.run(["rm", "-f", key_a_path, key_b_path], check=False)
        probe_a.cleanup(vm)
        probe_b.cleanup(vm)
        cleanup_netns_topology(vm)
