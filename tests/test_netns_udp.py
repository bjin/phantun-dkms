import time
import uuid

import pytest

from helpers import (
    NS_A,
    NS_ADDR_A,
    NS_ADDR_B,
    NS_B,
    VETH_A,
    VETH_B,
    VETH_A_ALT,
    VETH_B_ALT,
    NetnsNftProbe,
    PORTS_A,
    PORTS_B,
    assert_completed,
    cleanup_netns_topology,
    ensure_netns_topology,
    ensure_netns_second_path,
    make_netns_ingress_flag_drop_probe,
    make_netns_ingress_payload_drop_probe,
    make_netns_output_probe,
    make_netns_output_ipv4_pure_ack_probe,
    parse_guest_json,
    probe_comment,
    read_module_stat,
    read_module_stats,
    require_guest_command,
    run_in_netns,
    run_netns_scenario,
    spawn_netns_scenario,
    spawn_ready_capture,
    wait_for_guest_ready_file,
)

MANAGED_LOCAL_PORTS = "2222,3333,4444,5555"
SECONDARY_ADDR_A = "10.200.0.10"
SECONDARY_ADDR_B = "10.200.0.20"


def load_netns_module(phantun_module):
    phantun_module.load(managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS)


def write_guest_marker(vm, path):
    vm.run(["python3", "-c", f"from pathlib import Path; Path({path!r}).write_text('ready\\n')"])


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


def test_established_flow_delivers_udp_gso_superframe(phantun_module, vm):
    load_netns_module(phantun_module)
    ensure_netns_topology(vm)

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    chunks = [c * 1000 for c in "ABCD"]
    ready_file = f"/tmp/phantun_gso_recv_{uuid.uuid4().hex}"
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "recv_many",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 5,
            "timeout_sec": 20,
            "ready_file": ready_file,
        },
    )

    try:
        wait_for_guest_ready_file(vm, ready_file, timeout=5)
        warmup = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["warmup"],
            },
            timeout=10,
        )
        assert_completed(warmup, "GSO warm-up sender")

        deadline = time.time() + 5
        while read_module_stat(vm, "flows_established") == 0:
            if time.time() >= deadline:
                pytest.fail("warm-up datagram did not establish the flow")
            time.sleep(0.1)

        gso = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["".join(chunks)],
                "gso_size": 1000,
            },
            timeout=10,
        )
        assert_completed(gso, "UDP GSO sender")

        server_result = server.communicate(timeout=20)
        assert_completed(server_result, "UDP GSO receiver")
        server_data = parse_guest_json(server_result.stdout, "UDP GSO receiver stdout")
        received = [entry["message"] for entry in server_data.get("received", [])]
        if received != ["warmup", *chunks]:
            pytest.fail(f"unexpected UDP GSO payloads: {received!r}")
        if read_module_stat(vm, "oversized_payloads_dropped") != 0:
            pytest.fail("UDP GSO superframe was treated as an oversized payload")
    finally:
        server.terminate()
        cleanup_netns_topology(vm)


def test_netns_generated_fake_tcp_bypasses_output_invalid_drop(phantun_module, vm):
    load_netns_module(phantun_module)
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


def test_netns_generated_fake_tcp_checksum_state_is_valid_or_partial(phantun_module, vm):
    load_netns_module(phantun_module)
    ensure_netns_topology(vm)

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    payload = "checksum-v4"
    ready_file = f"/tmp/phantun_csum_v4_{uuid.uuid4().hex}"
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
        },
    )
    capture = None

    try:
        wait_for_guest_ready_file(vm, ready_file, timeout=5)
        warmup = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["warmup"],
            },
            timeout=10,
        )
        assert_completed(warmup, "checksum warm-up sender")

        deadline = time.time() + 5
        while read_module_stat(vm, "flows_established") == 0:
            if time.time() >= deadline:
                pytest.fail("checksum warm-up datagram did not establish the flow")
            time.sleep(0.1)

        capture = spawn_ready_capture(
            vm,
            NS_B,
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payload": payload,
                "timeout_sec": 20,
            },
        )
        sender = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": [payload],
            },
            timeout=10,
        )
        assert_completed(sender, "checksum payload sender")

        capture_result = capture.communicate(timeout=20)
        assert_completed(capture_result, "checksum capture")
        captured = parse_guest_json(capture_result.stdout, "checksum capture stdout")
        # Regression guard for the pseudo-header seed. Depending on the capture
        # point, the checksum may already be resolved or still CHECKSUM_PARTIAL.
        if captured.get("csum_state") not in ("valid", "partial_seed"):
            pytest.fail(f"generated fake-TCP checksum state is invalid: {captured!r}")

        server_result = server.communicate(timeout=20)
        assert_completed(server_result, "checksum receiver")
    finally:
        if capture is not None:
            capture.terminate()
        server.terminate()
        cleanup_netns_topology(vm)


def test_netns_outbound_mark_propagates_to_fake_tcp(phantun_module, vm):
    load_netns_module(phantun_module)
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
    load_netns_module(phantun_module)
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
    load_netns_module(phantun_module)
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


def test_netns_recent_bidirectional_payload_suppresses_idle_ack(phantun_module, vm):
    load_netns_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    prefix = f"/tmp/phantun_ack_suppress_{uuid.uuid4().hex}"
    server_ready = f"{prefix}_server_ready"
    first_received = f"{prefix}_first_received"
    send_reply = f"{prefix}_send_reply"
    immediate_received = f"{prefix}_immediate_received"
    send_delayed = f"{prefix}_send_delayed"
    ack_probe = make_netns_output_ipv4_pure_ack_probe(
        vm,
        NS_B,
        NS_ADDR_B,
        dst_port,
        NS_ADDR_A,
        src_port,
    )
    server = None
    client = None

    try:
        server = spawn_netns_scenario(
            vm,
            NS_B,
            "ack_suppression_barrier_server",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "timeout_sec": 20,
                "ready_file": server_ready,
                "first_received_file": first_received,
                "send_reply_file": send_reply,
                "immediate_received_file": immediate_received,
                "barrier_timeout_sec": 12,
                "reply_delay_ms": 400,
                "reply_payload": "reply",
            },
        )
        wait_for_guest_ready_file(vm, server_ready, timeout=5)

        pure_before = ack_probe.packets(vm, "pure_ipv4_ack")
        stats_before = read_module_stats(vm)
        client = spawn_netns_scenario(
            vm,
            NS_A,
            "ack_suppression_barrier_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "timeout_sec": 20,
                "payloads": ["receive-only", "immediate", "delayed"],
                "send_delayed_file": send_delayed,
                "barrier_timeout_sec": 12,
                "delayed_payload_delay_ms": 400,
            },
        )

        wait_for_guest_ready_file(vm, first_received, timeout=10)
        deadline = time.time() + 5
        while time.time() < deadline:
            pure_after_receive_only = ack_probe.packets(vm, "pure_ipv4_ack")
            if pure_after_receive_only > pure_before:
                break
            time.sleep(0.05)
        else:
            pytest.fail("receive-only established payload did not emit a pure ACK")

        stats_after_receive_only = read_module_stats(vm)
        if stats_after_receive_only["idle_acks_suppressed"] != stats_before["idle_acks_suppressed"]:
            pytest.fail(
                "receive-only established payload should not suppress its ACK: "
                f"before={stats_before!r} after={stats_after_receive_only!r}"
            )

        write_guest_marker(vm, send_reply)
        wait_for_guest_ready_file(vm, immediate_received, timeout=10)
        deadline = time.time() + 5
        while time.time() < deadline:
            stats_after_immediate = read_module_stats(vm)
            if stats_after_immediate["idle_acks_suppressed"] > stats_after_receive_only["idle_acks_suppressed"]:
                break
            time.sleep(0.05)
        else:
            pytest.fail("recent bidirectional payload did not increment idle_acks_suppressed")

        pure_after_immediate = ack_probe.packets(vm, "pure_ipv4_ack")
        if pure_after_immediate != pure_after_receive_only:
            pytest.fail(
                "recent bidirectional payload should suppress the pure ACK: "
                f"receive_only={pure_after_receive_only} immediate={pure_after_immediate}"
            )

        write_guest_marker(vm, send_delayed)
        server_result = server.communicate(timeout=20)
        client_result = client.communicate(timeout=20)
        assert_completed(server_result, "ACK suppression barrier receiver")
        assert_completed(client_result, "ACK suppression barrier sender")

        server_data = parse_guest_json(server_result.stdout, "ACK suppression receiver stdout")
        client_data = parse_guest_json(client_result.stdout, "ACK suppression sender stdout")
        if [entry["message"] for entry in server_data.get("received", [])] != [
            "receive-only",
            "immediate",
            "delayed",
        ]:
            pytest.fail(f"ACK suppression receiver saw unexpected payloads: {server_data!r}")
        if [entry["message"] for entry in client_data.get("replies", [])] != ["reply"]:
            pytest.fail(f"ACK suppression sender saw unexpected replies: {client_data!r}")

        deadline = time.time() + 5
        while time.time() < deadline:
            pure_after_delayed = ack_probe.packets(vm, "pure_ipv4_ack")
            if pure_after_delayed > pure_after_immediate:
                break
            time.sleep(0.05)
        else:
            pytest.fail("payload outside ACK suppression window did not emit a pure ACK")

        stats_after_delayed = read_module_stats(vm)
        if stats_after_delayed["idle_acks_suppressed"] != stats_after_immediate["idle_acks_suppressed"]:
            pytest.fail(
                "payload outside ACK suppression window should not increment suppressed ACK stats: "
                f"immediate={stats_after_immediate!r} delayed={stats_after_delayed!r}"
            )
    finally:
        for process in (client, server):
            if process is not None and process.proc.poll() is None:
                process.terminate()
        ack_probe.cleanup(vm)
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


def test_netns_fragmented_raw_udp_is_dropped_after_defrag(phantun_module, vm):
    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    ready_file = f"/tmp/phantun_frag_udp_{uuid.uuid4().hex}"

    phantun_module.load(managed_netns="all", managed_local_ports=str(dst_port), ip_families="ipv4")
    ensure_netns_topology(vm)

    receiver = spawn_netns_scenario(
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
    baseline_stats = read_module_stats(vm)

    try:
        wait_for_guest_ready_file(vm, ready_file, timeout=5)
        sender = run_netns_scenario(
            vm,
            NS_A,
            "send_ipv4_udp_fragments",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payload": "fragmented-raw-udp",
                "first_fragment_len": 16,
            },
        )
        receiver_result = receiver.communicate(timeout=5)

        assert_completed(sender, "fragmented raw UDP sender")
        assert_completed(receiver_result, "fragmented raw UDP receiver")

        received = parse_guest_json(receiver_result.stdout, "fragmented raw UDP receiver stdout")
        if not received.get("timed_out") or received.get("received") != []:
            pytest.fail(f"fragmented raw UDP should not be delivered: {received!r}")

        stats_after = read_module_stats(vm)
        if stats_after["udp_raw_inbound_dropped"] != baseline_stats["udp_raw_inbound_dropped"] + 1:
            pytest.fail(
                "fragmented raw UDP should increment raw inbound drop stats once: "
                f"before={baseline_stats!r} after={stats_after!r}"
            )
        if stats_after["udp_packets_dropped"] != baseline_stats["udp_packets_dropped"] + 1:
            pytest.fail(
                "fragmented raw UDP should increment UDP drop stats once: "
                f"before={baseline_stats!r} after={stats_after!r}"
            )
    finally:
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


def test_zero_length_udp_is_dropped_without_flow(phantun_module, vm):
    load_netns_module(phantun_module)
    ensure_netns_topology(vm)

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    receiver = spawn_netns_scenario(
        vm,
        NS_B,
        "recv_until_timeout",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 1,
            "timeout_sec": 1,
        },
    )
    baseline_stats = read_module_stats(vm)

    try:
        time.sleep(0.2)
        sender = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": [""],
            },
        )
        receiver_result = receiver.communicate(timeout=5)

        assert_completed(sender, "zero-length UDP sender")
        assert_completed(receiver_result, "zero-length UDP receiver")
        received = parse_guest_json(receiver_result.stdout, "zero-length UDP receiver stdout")
        if not received.get("timed_out") or received.get("received") != []:
            pytest.fail(f"zero-length UDP should not be delivered: {received!r}")

        stats_after = read_module_stats(vm)
        if stats_after["flows_created"] != baseline_stats["flows_created"]:
            pytest.fail(f"zero-length UDP must not create a flow: before={baseline_stats!r} after={stats_after!r}")
        if stats_after["flows_current"] != baseline_stats["flows_current"]:
            pytest.fail(f"zero-length UDP must not leave a flow: before={baseline_stats!r} after={stats_after!r}")
        if stats_after["udp_packets_dropped"] != baseline_stats["udp_packets_dropped"] + 1:
            pytest.fail(
                f"zero-length UDP should increment drop stats once: before={baseline_stats!r} after={stats_after!r}"
            )
    finally:
        cleanup_netns_topology(vm)


def test_netns_ipv4_secondary_addresses_are_preserved_and_removed_flows_invalidate(phantun_module, vm):
    load_netns_module(phantun_module)
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
