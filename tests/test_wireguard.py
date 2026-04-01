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
    cleanup_netns_topology,
    ensure_netns_topology,
    make_netns_output_probe,
    probe_comment,
    require_guest_command,
    run_in_netns,
)

WG_ADDR_A = "10.10.0.1/24"
WG_ADDR_B = "10.10.0.2/24"
WG_PEER_A = "10.10.0.1"
WG_PEER_B = "10.10.0.2"
PORT_A = 2222
PORT_B = 3333
MANAGED_PORTS = "2222,3333"


def load_wireguard_module(phantun_module):
    phantun_module.load(managed_ports=MANAGED_PORTS)


def guest_keypair(vm):
    private_key = vm.run(['wg', 'genkey']).stdout.strip()
    public_key = vm.run(
        f"printf '%s' {shlex.quote(private_key)} | wg pubkey"
    ).stdout.strip()
    return private_key, public_key


def write_guest_secret(vm, path, secret):
    vm.run(
        f"umask 077 && printf '%s' {shlex.quote(secret)} > {shlex.quote(path)}"
    )


def latest_handshake_timestamp(vm, namespace):
    res = run_in_netns(vm, namespace, ['wg', 'show', 'wg0', 'latest-handshakes'])
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


def assert_ping_clean(result, label):
    summary = None
    for line in result.stdout.splitlines():
        if 'packets transmitted' in line:
            summary = line.strip()
            break

    if summary is None:
        pytest.fail(f"{label}: ping output missing summary: {result.stdout!r}")
    if not re.search(r'\b3 packets transmitted, 3 received\b', summary):
        pytest.fail(f"{label}: unexpected ping summary: {summary!r}")
    if 'duplicates' in summary or 'DUP!' in result.stdout:
        pytest.fail(f"{label}: duplicate ICMP replies detected: {result.stdout!r}")



def test_kernel_wireguard_over_phantun_uses_no_raw_udp(phantun_module, vm):
    if not require_guest_command(vm, 'wg'):
        pytest.skip("wg userspace tool is not available in the guest")
    if not require_guest_command(vm, 'ping'):
        pytest.skip("ping is not available in the guest")
    if vm.run(['modprobe', 'wireguard'], check=False).returncode != 0:
        pytest.skip("wireguard kernel module is not available in the guest")

    load_wireguard_module(phantun_module)
    ensure_netns_topology(vm)

    probe_a = make_netns_output_probe(vm, NS_A, [(NS_ADDR_A, PORT_A, NS_ADDR_B, PORT_B)])
    probe_b = make_netns_output_probe(vm, NS_B, [(NS_ADDR_B, PORT_B, NS_ADDR_A, PORT_A)])

    priv_a, pub_a = guest_keypair(vm)
    priv_b, pub_b = guest_keypair(vm)
    key_a_path = '/tmp/wg-a.key'
    key_b_path = '/tmp/wg-b.key'

    try:
        write_guest_secret(vm, key_a_path, priv_a)
        write_guest_secret(vm, key_b_path, priv_b)

        run_in_netns(vm, NS_A, ['ip', 'link', 'add', 'wg0', 'type', 'wireguard'])
        run_in_netns(vm, NS_B, ['ip', 'link', 'add', 'wg0', 'type', 'wireguard'])
        run_in_netns(vm, NS_A, ['ip', 'address', 'add', WG_ADDR_A, 'dev', 'wg0'])
        run_in_netns(vm, NS_B, ['ip', 'address', 'add', WG_ADDR_B, 'dev', 'wg0'])

        run_in_netns(
            vm,
            NS_A,
            [
                'wg', 'set', 'wg0',
                'listen-port', str(PORT_A),
                'private-key', key_a_path,
                'peer', pub_b,
                'allowed-ips', f'{WG_PEER_B}/32',
                'endpoint', f'{NS_ADDR_B}:{PORT_B}',
                'persistent-keepalive', '1',
            ],
        )
        run_in_netns(
            vm,
            NS_B,
            [
                'wg', 'set', 'wg0',
                'listen-port', str(PORT_B),
                'private-key', key_b_path,
                'peer', pub_a,
                'allowed-ips', f'{WG_PEER_A}/32',
                'endpoint', f'{NS_ADDR_A}:{PORT_A}',
                'persistent-keepalive', '1',
            ],
        )
        run_in_netns(vm, NS_A, ['ip', 'link', 'set', 'wg0', 'up'])
        run_in_netns(vm, NS_B, ['ip', 'link', 'set', 'wg0', 'up'])

        ping_a = run_in_netns(vm, NS_A, ['ping', '-c', '3', '-W', '1', WG_PEER_B])
        ping_b = run_in_netns(vm, NS_B, ['ping', '-c', '3', '-W', '1', WG_PEER_A])
        assert_ping_clean(ping_a, 'ns_a -> ns_b ping')
        assert_ping_clean(ping_b, 'ns_b -> ns_a ping')
        wait_for_handshake(vm)

        wg_a = run_in_netns(vm, NS_A, ['wg', 'show', 'wg0']).stdout
        wg_b = run_in_netns(vm, NS_B, ['wg', 'show', 'wg0']).stdout
        if 'latest handshake' not in wg_a or 'latest handshake' not in wg_b:
            pytest.fail('`wg show wg0` did not report a successful handshake on both peers')
        if '127.0.0.1:' in wg_a or '127.0.0.1:' in wg_b:
            pytest.fail('`wg show wg0` reported a loopback endpoint, which should never be required')
        if f'endpoint: {NS_ADDR_B}:{PORT_B}' not in wg_a:
            pytest.fail(f'wg0 in {NS_A} did not show the real peer endpoint: {wg_a!r}')
        if f'endpoint: {NS_ADDR_A}:{PORT_A}' not in wg_b:
            pytest.fail(f'wg0 in {NS_B} did not show the real peer endpoint: {wg_b!r}')

        udp_a = probe_a.packets(vm, probe_comment('udp', NS_ADDR_A, PORT_A, NS_ADDR_B, PORT_B))
        tcp_a = probe_a.packets(vm, probe_comment('tcp', NS_ADDR_A, PORT_A, NS_ADDR_B, PORT_B))
        udp_b = probe_b.packets(vm, probe_comment('udp', NS_ADDR_B, PORT_B, NS_ADDR_A, PORT_A))
        tcp_b = probe_b.packets(vm, probe_comment('tcp', NS_ADDR_B, PORT_B, NS_ADDR_A, PORT_A))

        if udp_a != 0 or udp_b != 0:
            pytest.fail(f"raw UDP escaped on the WireGuard underlay path: ns_a={udp_a}, ns_b={udp_b}")
        if tcp_a == 0 or tcp_b == 0:
            pytest.fail(f"expected translated TCP on the WireGuard underlay path, got ns_a={tcp_a}, ns_b={tcp_b}")
    finally:
        run_in_netns(vm, NS_A, ['ip', 'link', 'del', 'wg0'], check=False)
        run_in_netns(vm, NS_B, ['ip', 'link', 'del', 'wg0'], check=False)
        vm.run(['rm', '-f', key_a_path, key_b_path], check=False)
        probe_a.cleanup(vm)
        probe_b.cleanup(vm)
        cleanup_netns_topology(vm)
