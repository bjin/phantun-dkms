import json

import pytest

from helpers import (
    NS_A,
    NS_ADDR_A,
    NS_ADDR_B,
    NS_B,
    PORTS_A,
    PORTS_B,
    cleanup_netns_topology,
    ensure_netns_topology,
    make_netns_output_probe,
    probe_comment,
    require_guest_command,
    run_guest_python,
)

MANAGED_PORTS = "2222,3333,4444,5555"


def load_netns_module(phantun_module):
    phantun_module.load(managed_ports=MANAGED_PORTS)


def parse_guest_json(stdout, context):
    body = stdout.strip()
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        pytest.fail(f"{context}: invalid guest JSON: {exc}: {body}")


def test_netns_ping_pong_uses_tcp_output_only(phantun_module, vm):
    load_netns_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, 'nft'):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    probe_a = make_netns_output_probe(vm, NS_A, [(NS_ADDR_A, 2222, NS_ADDR_B, 3333)])
    probe_b = make_netns_output_probe(vm, NS_B, [(NS_ADDR_B, 3333, NS_ADDR_A, 2222)])

    server_code = """
import json
import socket

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(5)
    sock.bind(('10.200.0.2', 3333))
    data, addr = sock.recvfrom(2048)
    sock.sendto(b'pong', addr)
    print(json.dumps({
        'received': data.decode(),
        'peer': [addr[0], addr[1]],
    }))
"""

    client_code = """
import json
import socket

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(5)
    sock.bind(('10.200.0.1', 2222))
    sock.sendto(b'ping', ('10.200.0.2', 3333))
    reply, addr = sock.recvfrom(2048)
    print(json.dumps({
        'reply': reply.decode(),
        'peer': [addr[0], addr[1]],
    }))
"""

    try:
        res = run_guest_python(vm, f"""
            import json
            import subprocess
            import time

            server = subprocess.Popen(
                ['ip', 'netns', 'exec', {NS_B!r}, 'python3', '-c', {server_code!r}],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(0.2)
            client = subprocess.run(
                ['ip', 'netns', 'exec', {NS_A!r}, 'python3', '-c', {client_code!r}],
                capture_output=True,
                text=True,
                timeout=10,
            )
            server_stdout, server_stderr = server.communicate(timeout=10)
            print(json.dumps({{
                'server_rc': server.returncode,
                'server_stdout': server_stdout,
                'server_stderr': server_stderr,
                'client_rc': client.returncode,
                'client_stdout': client.stdout,
                'client_stderr': client.stderr,
            }}))
        """)
        data = parse_guest_json(res.stdout, "netns ping/pong run")

        if data.get('server_rc') != 0:
            pytest.fail(f"server failed: {data.get('server_stderr')!r}")
        if data.get('client_rc') != 0:
            pytest.fail(f"client failed: {data.get('client_stderr')!r}")

        server = parse_guest_json(data.get('server_stdout', ''), "server stdout")
        client = parse_guest_json(data.get('client_stdout', ''), "client stdout")

        if server.get('received') != 'ping':
            pytest.fail(f"expected server to receive 'ping', got {server.get('received')!r}")
        if server.get('peer') != [NS_ADDR_A, 2222]:
            pytest.fail(f"unexpected server peer: {server.get('peer')!r}")
        if client.get('reply') != 'pong':
            pytest.fail(f"expected client to receive 'pong', got {client.get('reply')!r}")
        if client.get('peer') != [NS_ADDR_B, 3333]:
            pytest.fail(f"unexpected client peer: {client.get('peer')!r}")

        udp_a = probe_a.packets(vm, probe_comment('udp', NS_ADDR_A, 2222, NS_ADDR_B, 3333))
        tcp_a = probe_a.packets(vm, probe_comment('tcp', NS_ADDR_A, 2222, NS_ADDR_B, 3333))
        udp_b = probe_b.packets(vm, probe_comment('udp', NS_ADDR_B, 3333, NS_ADDR_A, 2222))
        tcp_b = probe_b.packets(vm, probe_comment('tcp', NS_ADDR_B, 3333, NS_ADDR_A, 2222))

        if udp_a != 0 or udp_b != 0:
            pytest.fail(f"raw UDP escaped LOCAL_OUT in netns: ns_a={udp_a}, ns_b={udp_b}")
        if tcp_a == 0 or tcp_b == 0:
            pytest.fail(f"expected translated TCP on both netns output paths, got ns_a={tcp_a}, ns_b={tcp_b}")
    finally:
        probe_a.cleanup(vm)
        probe_b.cleanup(vm)
        cleanup_netns_topology(vm)



def test_netns_echo_ten_packets(phantun_module, vm):
    load_netns_module(phantun_module)
    ensure_netns_topology(vm)

    server_code = """
import json
import socket

payloads = []
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(5)
    sock.bind(('10.200.0.2', 3333))
    while len(payloads) < 10:
        data, addr = sock.recvfrom(2048)
        text = data.decode()
        payloads.append(text)
        sock.sendto(data, addr)
print(json.dumps({'received': payloads}))
"""

    client_code = """
import json
import socket

payloads = [f'packet-{idx}' for idx in range(10)]
echoed = []
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(5)
    sock.bind(('10.200.0.1', 2222))
    for payload in payloads:
        sock.sendto(payload.encode(), ('10.200.0.2', 3333))
    while len(echoed) < len(payloads):
        reply, _ = sock.recvfrom(2048)
        echoed.append(reply.decode())
print(json.dumps({'sent': payloads, 'echoed': echoed}))
"""

    try:
        res = run_guest_python(vm, f"""
            import json
            import subprocess
            import time

            server = subprocess.Popen(
                ['ip', 'netns', 'exec', {NS_B!r}, 'python3', '-c', {server_code!r}],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(0.2)
            client = subprocess.run(
                ['ip', 'netns', 'exec', {NS_A!r}, 'python3', '-c', {client_code!r}],
                capture_output=True,
                text=True,
                timeout=15,
            )
            server_stdout, server_stderr = server.communicate(timeout=15)
            print(json.dumps({{
                'server_rc': server.returncode,
                'server_stdout': server_stdout,
                'server_stderr': server_stderr,
                'client_rc': client.returncode,
                'client_stdout': client.stdout,
                'client_stderr': client.stderr,
            }}))
        """)
        data = parse_guest_json(res.stdout, "netns echo run")

        if data.get('server_rc') != 0:
            pytest.fail(f"server failed: {data.get('server_stderr')!r}")
        if data.get('client_rc') != 0:
            pytest.fail(f"client failed: {data.get('client_stderr')!r}")

        server = parse_guest_json(data.get('server_stdout', ''), "echo server stdout")
        client = parse_guest_json(data.get('client_stdout', ''), "echo client stdout")

        expected = sorted(client.get('sent', []))
        server_seen = sorted(server.get('received', []))
        echoed = sorted(client.get('echoed', []))

        if server_seen != expected:
            pytest.fail(f"server payload mismatch: expected {expected}, got {server_seen}")
        if echoed != expected:
            pytest.fail(f"client echo mismatch: expected {expected}, got {echoed}")
    finally:
        cleanup_netns_topology(vm)



def test_netns_all_four_channels(phantun_module, vm):
    load_netns_module(phantun_module)
    ensure_netns_topology(vm)

    server_code = """
import json
import socket
import sys

port = int(sys.argv[1])
expected = int(sys.argv[2])
received = []
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(5)
    sock.bind(('10.200.0.2', port))
    while len(received) < expected:
        data, addr = sock.recvfrom(2048)
        message = data.decode()
        received.append({
            'message': message,
            'peer': [addr[0], addr[1]],
        })
        sock.sendto(f'ack:{message}'.encode(), addr)
print(json.dumps({'port': port, 'received': received}))
"""

    client_code = """
import json
import select
import socket

channels = [
    (2222, 3333, 'chan-2222-3333'),
    (2222, 5555, 'chan-2222-5555'),
    (4444, 3333, 'chan-4444-3333'),
    (4444, 5555, 'chan-4444-5555'),
]
clients = {}
replies = []
for port in (2222, 4444):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.bind(('10.200.0.1', port))
    clients[port] = sock

try:
    for src_port, dst_port, message in channels:
        clients[src_port].sendto(message.encode(), ('10.200.0.2', dst_port))

    while len(replies) < len(channels):
        ready, _, _ = select.select(list(clients.values()), [], [], 5)
        if not ready:
            raise TimeoutError('timed out waiting for multi-channel replies')
        for sock in ready:
            data, addr = sock.recvfrom(2048)
            replies.append({
                'local_port': sock.getsockname()[1],
                'message': data.decode(),
                'peer': [addr[0], addr[1]],
            })
finally:
    for sock in clients.values():
        sock.close()

print(json.dumps({
    'channels': [
        {'src_port': src_port, 'dst_port': dst_port, 'message': message}
        for src_port, dst_port, message in channels
    ],
    'replies': replies,
}))
"""

    try:
        res = run_guest_python(vm, f"""
            import json
            import subprocess
            import time

            servers = [
                subprocess.Popen(
                    ['ip', 'netns', 'exec', {NS_B!r}, 'python3', '-c', {server_code!r}, str(port), str(expected)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                for port, expected in ((3333, 2), (5555, 2))
            ]
            time.sleep(0.2)
            client = subprocess.run(
                ['ip', 'netns', 'exec', {NS_A!r}, 'python3', '-c', {client_code!r}],
                capture_output=True,
                text=True,
                timeout=15,
            )
            server_results = []
            for server in servers:
                stdout, stderr = server.communicate(timeout=15)
                server_results.append({{
                    'rc': server.returncode,
                    'stdout': stdout,
                    'stderr': stderr,
                }})
            print(json.dumps({{
                'client_rc': client.returncode,
                'client_stdout': client.stdout,
                'client_stderr': client.stderr,
                'servers': server_results,
            }}))
        """)
        data = parse_guest_json(res.stdout, "netns four-channel run")

        if data.get('client_rc') != 0:
            pytest.fail(f"client failed: {data.get('client_stderr')!r}")

        client = parse_guest_json(data.get('client_stdout', ''), "multi-channel client stdout")
        expected_channels = {
            (entry['src_port'], entry['dst_port']): entry['message']
            for entry in client.get('channels', [])
        }
        if len(expected_channels) != 4:
            pytest.fail(f"expected 4 channel definitions, got {expected_channels!r}")

        received = {}
        for server in data.get('servers', []):
            if server.get('rc') != 0:
                pytest.fail(f"server failed: {server.get('stderr')!r}")
            result = parse_guest_json(server.get('stdout', ''), "multi-channel server stdout")
            for entry in result.get('received', []):
                peer = entry.get('peer', [None, None])
                received[(peer[1], result.get('port'))] = entry.get('message')
                if peer[0] != NS_ADDR_A:
                    pytest.fail(f"unexpected sender address for server port {result.get('port')}: {peer!r}")

        if received != expected_channels:
            pytest.fail(f"server channel mismatch: expected {expected_channels}, got {received}")

        replies = {}
        for reply in client.get('replies', []):
            peer = reply.get('peer', [None, None])
            key = (reply.get('local_port'), peer[1])
            replies[key] = reply.get('message')
            if peer[0] != NS_ADDR_B:
                pytest.fail(f"unexpected reply address for local port {reply.get('local_port')}: {peer!r}")

        expected_replies = {
            key: f"ack:{message}"
            for key, message in expected_channels.items()
        }
        if replies != expected_replies:
            pytest.fail(f"reply mismatch: expected {expected_replies}, got {replies}")
    finally:
        cleanup_netns_topology(vm)
