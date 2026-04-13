import time
import uuid

import pytest

from helpers import (
    NS_A,
    NS_ADDR_A,
    NS_ADDR_B,
    NS_B,
    PORTS_A,
    PORTS_B,
    VETH_A,
    VETH_B,
    assert_completed,
    cleanup_netns_topology,
    ensure_netns_topology,
    require_guest_command,
    received_plain_messages,
    run_in_netns,
    run_netns_scenario,
    spawn_netns_scenario,
    parse_guest_json,
    make_netns_ingress_flag_drop_probe,
    make_netns_output_flag_probe,
    make_netns_prerouting_flag_drop_probe,
    read_module_stats,
    read_netns_iface_mac,
)

MANAGED_LOCAL_PORTS = "2222,3333,4444,5555"


def load_recovery_module(phantun_module, **kwargs):
    # Set keepalive interval to 1s to test liveness.
    phantun_module.load(
        managed_local_ports=MANAGED_LOCAL_PORTS,
        keepalive_interval_sec=1,
        keepalive_misses=2,
        handshake_retries=20,
        **kwargs,
    )


def wait_for_guest_ready_file(vm, path, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if vm.run(["test", "-e", path], check=False).returncode == 0:
            return
        time.sleep(0.1)
    pytest.fail(f"guest readiness file {path!r} was not observed within {timeout}s")


def spawn_ready_capture(vm, namespace, config):
    ready_file = f"/tmp/phantun-capture-{uuid.uuid4().hex}"
    capture = spawn_netns_scenario(
        vm,
        namespace,
        "capture_tcp_packet",
        {**config, "ready_file": ready_file},
    )
    wait_for_guest_ready_file(vm, ready_file, timeout=config.get("timeout_sec", 10))
    return capture


ROUTER_NS = "pht-r"
VETH_A_R = "veth-pht-ar"
VETH_R_A = "veth-pht-ra"
VETH_R_B = "veth-pht-rb"
VETH_B_R = "veth-pht-br"
FWD_ADDR_A = "10.210.0.1"
FWD_ADDR_R_A = "10.210.0.254"
FWD_ADDR_R_B = "10.220.0.254"
FWD_ADDR_B = "10.220.0.2"


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


def test_forwarded_fake_tcp_is_not_owned_in_prerouting(phantun_module, vm):
    phantun_module.load(managed_local_ports=str(PORTS_B[0]))
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


def test_syn_fin_is_rejected_without_creating_flow(phantun_module, vm):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    invalid_probe = make_netns_output_flag_probe(
        vm,
        NS_B,
        [
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "rst | ack",
                "comment": "syn_fin_rst",
            },
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "syn | ack",
                "comment": "syn_fin_synack",
            },
        ],
    )

    try:
        run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": "syn|fin",
                "seq": 4095,
            },
        )
        time.sleep(0.2)

        if invalid_probe.packets(vm, "syn_fin_synack") != 0:
            pytest.fail("SYN|FIN must not be accepted as a new bare SYN opener")
        if invalid_probe.packets(vm, "syn_fin_rst") == 0:
            pytest.fail("SYN|FIN opener should be rejected with RST|ACK")
    finally:
        invalid_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_established_syn_fin_is_not_accepted_as_replacement(phantun_module, vm):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    invalid_probe = make_netns_output_flag_probe(
        vm,
        NS_B,
        [
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "rst | ack",
                "comment": "est_syn_fin_rst",
            },
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "syn | ack",
                "comment": "est_syn_fin_synack",
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
            "echo_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["msg1"],
            },
        )
        assert_completed(first, "established baseline echo")
        baseline_rst = invalid_probe.packets(vm, "est_syn_fin_rst")
        baseline_synack = invalid_probe.packets(vm, "est_syn_fin_synack")

        run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": "syn|fin",
                "seq": 4095,
            },
        )
        time.sleep(0.2)

        if invalid_probe.packets(vm, "est_syn_fin_synack") != baseline_synack:
            pytest.fail("SYN|FIN must not be accepted as an established replacement SYN")
        if invalid_probe.packets(vm, "est_syn_fin_rst") <= baseline_rst:
            pytest.fail("SYN|FIN on established flow should be rejected with RST|ACK")
    finally:
        invalid_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_established_invalid_syn_destroys_flow(phantun_module, vm):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]

    invalid_probe = make_netns_output_flag_probe(
        vm,
        NS_B,
        [
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "rst | ack",
                "comment": "invalid_rst",
            },
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "syn | ack",
                "comment": "invalid_synack",
            },
        ],
    )
    _server = spawn_netns_scenario(
        vm,
        NS_B,
        "echo_server",
        {"bind_addr": NS_ADDR_B, "bind_port": dst_port, "count": 2, "timeout_sec": 20},
    )

    try:
        time.sleep(0.2)
        res1 = run_netns_scenario(
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
        assert_completed(res1, "initial echo client")

        baseline_invalid_rst = invalid_probe.packets(vm, "invalid_rst")
        baseline_invalid_synack = invalid_probe.packets(vm, "invalid_synack")

        run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": "syn|ack",
                "seq": 12345,
                "ack": 1,
            },
        )
        time.sleep(0.2)

        if invalid_probe.packets(vm, "invalid_rst") <= baseline_invalid_rst:
            pytest.fail("expected RST|ACK in response to invalid established SYN packet")
        if invalid_probe.packets(vm, "invalid_synack") != baseline_invalid_synack:
            pytest.fail("invalid established SYN packet must not be accepted as replacement")

        res2 = run_netns_scenario(
            vm,
            NS_A,
            "echo_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["msg2"],
                "timeout_sec": 15,
            },
        )
        assert_completed(res2, "echo client after invalid SYN")
        data = parse_guest_json(res2.stdout, "echo client")
        if data.get("echoed") != ["msg2"]:
            pytest.fail(f"failed to recover after invalid SYN: {data.get('echoed')!r}")
    finally:
        invalid_probe.cleanup(vm)


def test_established_later_sequence_payload_is_delivered_without_reset(phantun_module, vm):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    capture = spawn_ready_capture(
        vm,
        NS_A,
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "target_addr": NS_ADDR_A,
            "target_port": src_port,
            "payload": "msg1",
            "timeout_sec": 15,
        },
    )
    rst_probe = make_netns_output_flag_probe(
        vm,
        NS_A,
        [
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "flags_expr": "rst | ack",
                "comment": "later_payload_rst",
            }
        ],
    )
    receiver = spawn_netns_scenario(
        vm,
        NS_A,
        "recv_many",
        {
            "bind_addr": NS_ADDR_A,
            "bind_port": src_port,
            "count": 2,
            "timeout_sec": 15,
        },
    )

    try:
        time.sleep(0.2)
        sender_result = run_netns_scenario(
            vm,
            NS_B,
            "send_many",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "target_addr": NS_ADDR_A,
                "target_port": src_port,
                "payloads": ["msg1"],
            },
        )
        capture_result = capture.communicate(timeout=15)
        assert_completed(sender_result, "later-payload sender")
        assert_completed(capture_result, "later-payload capture")

        captured = parse_guest_json(capture_result.stdout, "later-payload capture stdout")
        baseline_rst = rst_probe.packets(vm, "later_payload_rst")

        run_netns_scenario(
            vm,
            NS_B,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "target_addr": NS_ADDR_A,
                "target_port": src_port,
                "flags": "ack",
                "seq": captured["seq"] + len("msg1") + len("gap"),
                "ack": captured["ack"],
                "payload": "later",
            },
        )
        receiver_result = receiver.communicate(timeout=15)
        assert_completed(receiver_result, "later-payload receiver")

        receiver_data = parse_guest_json(receiver_result.stdout, "later-payload receiver stdout")
        receiver_messages = [entry["message"] for entry in receiver_data.get("received", [])]
        if sorted(receiver_messages) != ["later", "msg1"]:
            pytest.fail(f"later-sequence payload should still reach UDP without reset: {receiver_messages!r}")
        if rst_probe.packets(vm, "later_payload_rst") != baseline_rst:
            pytest.fail("later-sequence payload should not trigger RST|ACK")
    finally:
        rst_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_established_overlapping_payload_is_rejected_with_rstack(phantun_module, vm):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    local_port = PORTS_A[0]
    remote_port = PORTS_B[0]
    capture = spawn_ready_capture(
        vm,
        NS_A,
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": remote_port,
            "target_addr": NS_ADDR_A,
            "target_port": local_port,
            "payload": "msg1",
            "timeout_sec": 15,
        },
    )
    rst_probe = make_netns_output_flag_probe(
        vm,
        NS_A,
        [
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": local_port,
                "dst_port": remote_port,
                "flags_expr": "rst | ack",
                "comment": "overlap_rst",
            }
        ],
    )
    receiver = spawn_netns_scenario(
        vm,
        NS_A,
        "recv_many",
        {
            "bind_addr": NS_ADDR_A,
            "bind_port": local_port,
            "count": 1,
            "timeout_sec": 15,
        },
    )

    try:
        time.sleep(0.2)
        sender_result = run_netns_scenario(
            vm,
            NS_B,
            "send_many",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": remote_port,
                "target_addr": NS_ADDR_A,
                "target_port": local_port,
                "payloads": ["msg1"],
            },
        )
        receiver_result = receiver.communicate(timeout=15)
        capture_result = capture.communicate(timeout=15)

        assert_completed(sender_result, "overlap sender")
        assert_completed(receiver_result, "overlap receiver")
        assert_completed(capture_result, "overlap capture")

        captured = parse_guest_json(capture_result.stdout, "overlap capture stdout")
        baseline_rst = rst_probe.packets(vm, "overlap_rst")

        run_netns_scenario(
            vm,
            NS_B,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": remote_port,
                "target_addr": NS_ADDR_A,
                "target_port": local_port,
                "flags": "ack",
                "seq": captured["seq"] + len("msg1") - 2,
                "ack": captured["ack"],
                "payload": "overlap",
            },
        )
        time.sleep(0.2)

        if rst_probe.packets(vm, "overlap_rst") <= baseline_rst:
            pytest.fail("payload overlapping the current receive frontier should trigger RST|ACK")
    finally:
        rst_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_established_ack_beyond_local_seq_is_rejected_with_rstack(phantun_module, vm):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    local_port = PORTS_A[0]
    remote_port = PORTS_B[0]
    capture = spawn_ready_capture(
        vm,
        NS_A,
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": remote_port,
            "target_addr": NS_ADDR_A,
            "target_port": local_port,
            "payload": "msg1",
            "timeout_sec": 15,
        },
    )
    rst_probe = make_netns_output_flag_probe(
        vm,
        NS_A,
        [
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": local_port,
                "dst_port": remote_port,
                "flags_expr": "rst | ack",
                "comment": "ack_beyond_rst",
            }
        ],
    )
    receiver = spawn_netns_scenario(
        vm,
        NS_A,
        "recv_many",
        {
            "bind_addr": NS_ADDR_A,
            "bind_port": local_port,
            "count": 1,
            "timeout_sec": 15,
        },
    )

    try:
        time.sleep(0.2)
        sender_result = run_netns_scenario(
            vm,
            NS_B,
            "send_many",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": remote_port,
                "target_addr": NS_ADDR_A,
                "target_port": local_port,
                "payloads": ["msg1"],
            },
        )
        receiver_result = receiver.communicate(timeout=15)
        capture_result = capture.communicate(timeout=15)

        assert_completed(sender_result, "ack-beyond sender")
        assert_completed(receiver_result, "ack-beyond receiver")
        assert_completed(capture_result, "ack-beyond capture")

        captured = parse_guest_json(capture_result.stdout, "ack-beyond capture stdout")
        baseline_rst = rst_probe.packets(vm, "ack_beyond_rst")

        run_netns_scenario(
            vm,
            NS_B,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": remote_port,
                "target_addr": NS_ADDR_A,
                "target_port": local_port,
                "flags": "ack",
                "seq": captured["seq"] + len("msg1"),
                "ack": captured["ack"] + 1000,
            },
        )
        time.sleep(0.2)

        if rst_probe.packets(vm, "ack_beyond_rst") <= baseline_rst:
            pytest.fail("ACK beyond the local send frontier should trigger RST|ACK")
    finally:
        rst_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_future_sequence_pure_ack_is_silently_absorbed(phantun_module, vm):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    capture = spawn_ready_capture(
        vm,
        NS_A,
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "target_addr": NS_ADDR_A,
            "target_port": src_port,
            "payload": "msg1",
            "timeout_sec": 15,
        },
    )
    rst_probe = make_netns_output_flag_probe(
        vm,
        NS_A,
        [
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "flags_expr": "rst | ack",
                "comment": "future_pure_ack_rst",
            }
        ],
    )
    receiver = spawn_netns_scenario(
        vm,
        NS_A,
        "recv_many",
        {
            "bind_addr": NS_ADDR_A,
            "bind_port": src_port,
            "count": 1,
            "timeout_sec": 15,
        },
    )

    try:
        time.sleep(0.2)
        sender_result = run_netns_scenario(
            vm,
            NS_B,
            "send_many",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "target_addr": NS_ADDR_A,
                "target_port": src_port,
                "payloads": ["msg1"],
            },
        )
        receiver_result = receiver.communicate(timeout=15)
        capture_result = capture.communicate(timeout=15)

        assert_completed(sender_result, "future pure ack sender")
        assert_completed(receiver_result, "future pure ack receiver")
        assert_completed(capture_result, "future pure ack capture")

        captured = parse_guest_json(capture_result.stdout, "future pure ack capture stdout")
        baseline_rst = rst_probe.packets(vm, "future_pure_ack_rst")

        run_netns_scenario(
            vm,
            NS_B,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "target_addr": NS_ADDR_A,
                "target_port": src_port,
                "flags": "ack",
                "seq": captured["seq"] + len("msg1") + 1000,
                "ack": captured["ack"],
            },
        )
        time.sleep(0.2)

        if rst_probe.packets(vm, "future_pure_ack_rst") != baseline_rst:
            pytest.fail("future-sequence pure ACK should be absorbed without RST|ACK")
    finally:
        rst_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_future_sequence_pure_ack_still_does_not_refresh_liveness(phantun_module, vm):
    load_recovery_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    capture = spawn_ready_capture(
        vm,
        NS_A,
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "target_addr": NS_ADDR_A,
            "target_port": src_port,
            "payload": "msg1",
            "timeout_sec": 15,
        },
    )
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
                "comment": "future_pure_ack_syn",
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
        first_result = run_netns_scenario(
            vm,
            NS_A,
            "echo_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["msg1"],
                "timeout_sec": 15,
            },
        )
        capture_result = capture.communicate(timeout=15)
        assert_completed(first_result, "future pure ack first echo")
        assert_completed(capture_result, "future pure ack capture")
        captured = parse_guest_json(capture_result.stdout, "future pure ack capture stdout")
        baseline_syn = reconnect_probe.packets(vm, "future_pure_ack_syn")

        for _ in range(5):
            run_netns_scenario(
                vm,
                NS_B,
                "send_tcp_packet",
                {
                    "bind_addr": NS_ADDR_B,
                    "bind_port": dst_port,
                    "target_addr": NS_ADDR_A,
                    "target_port": src_port,
                    "flags": "ack",
                    "seq": captured["seq"] + len("msg1") + 1000,
                    "ack": captured["ack"],
                },
            )
            time.sleep(0.6)

        second_result = run_netns_scenario(
            vm,
            NS_A,
            "echo_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["msg2"],
                "timeout_sec": 15,
            },
        )
        assert_completed(second_result, "future pure ack second echo")

        if reconnect_probe.packets(vm, "future_pure_ack_syn") <= baseline_syn:
            pytest.fail("future-sequence pure ACK should not keep the flow alive")

        server_result = server.communicate(timeout=20)
        assert_completed(server_result, "future pure ack server")
        server_data = parse_guest_json(server_result.stdout, "future pure ack server stdout")
        if received_plain_messages(server_data) != ["msg1", "msg2"]:
            pytest.fail(
                f"unexpected server messages after future pure ACK liveness test: {received_plain_messages(server_data)!r}"
            )
    finally:
        reconnect_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_invalid_pure_ack_does_not_refresh_liveness(phantun_module, vm):
    load_recovery_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    local_port = PORTS_A[0]
    remote_port = PORTS_B[0]
    syn_probe = make_netns_output_flag_probe(
        vm,
        NS_A,
        [
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": local_port,
                "dst_port": remote_port,
                "flags_expr": "syn",
                "comment": "invalid_ack_keepalive_syn",
            }
        ],
    )
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "echo_server",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": remote_port,
            "count": 2,
            "timeout_sec": 20,
        },
    )

    try:
        time.sleep(0.2)
        first_result = run_netns_scenario(
            vm,
            NS_A,
            "echo_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": local_port,
                "target_addr": NS_ADDR_B,
                "target_port": remote_port,
                "payloads": ["msg1"],
                "timeout_sec": 15,
            },
        )
        assert_completed(first_result, "invalid-ack first echo")
        baseline_syn = syn_probe.packets(vm, "invalid_ack_keepalive_syn")

        for _ in range(5):
            run_netns_scenario(
                vm,
                NS_B,
                "send_tcp_packet",
                {
                    "bind_addr": NS_ADDR_B,
                    "bind_port": remote_port,
                    "target_addr": NS_ADDR_A,
                    "target_port": local_port,
                    "flags": "ack",
                    "seq": 12345,
                    "ack": 67890,
                },
            )
            time.sleep(0.6)

        second_result = run_netns_scenario(
            vm,
            NS_A,
            "echo_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": local_port,
                "target_addr": NS_ADDR_B,
                "target_port": remote_port,
                "payloads": ["msg2"],
                "timeout_sec": 15,
            },
        )
        assert_completed(second_result, "invalid-ack second echo")

        if syn_probe.packets(vm, "invalid_ack_keepalive_syn") <= baseline_syn:
            pytest.fail("invalid pure ACKs should not keep the established flow alive")

        server_result = server.communicate(timeout=20)
        assert_completed(server_result, "invalid-ack server")
        server_data = parse_guest_json(server_result.stdout, "invalid-ack server stdout")
        if received_plain_messages(server_data) != ["msg1", "msg2"]:
            pytest.fail(
                f"unexpected server delivery after invalid ACK liveness test: {received_plain_messages(server_data)!r}"
            )
    finally:
        syn_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_bad_final_ack_payload_is_rejected_with_rstack(phantun_module, vm):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    drop_synack = make_netns_ingress_flag_drop_probe(
        vm,
        NS_A,
        VETH_A,
        [
            {
                "src_addr": NS_ADDR_B,
                "src_port": dst_port,
                "dst_addr": NS_ADDR_A,
                "dst_port": src_port,
                "flags_expr": "syn | ack",
                "comment": "drop_half_open_synack",
            }
        ],
    )
    invalid_probe = make_netns_output_flag_probe(
        vm,
        NS_B,
        [
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "rst | ack",
                "comment": "bad_final_rst",
            }
        ],
    )

    try:
        run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": "syn",
                "seq": 4095,
            },
        )
        time.sleep(0.2)
        baseline_bad_final_rst = invalid_probe.packets(vm, "bad_final_rst")

        run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": "ack",
                "seq": 4096,
                "ack": 0,
                "payload": "junk",
            },
        )
        time.sleep(0.2)

        if invalid_probe.packets(vm, "bad_final_rst") <= baseline_bad_final_rst:
            pytest.fail("expected RST|ACK for payload-bearing final ACK with wrong ack number")
    finally:
        drop_synack.cleanup(vm)
        invalid_probe.cleanup(vm)


def test_bad_final_ack_wrong_seq_is_rejected_with_rstack(phantun_module, vm):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    drop_synack = make_netns_prerouting_flag_drop_probe(
        vm,
        NS_A,
        [
            {
                "src_addr": NS_ADDR_B,
                "src_port": dst_port,
                "dst_addr": NS_ADDR_A,
                "dst_port": src_port,
                "flags_expr": "syn | ack",
                "comment": "drop_half_open_synack_wrong_seq",
            }
        ],
    )
    synack_capture = spawn_ready_capture(
        vm,
        NS_A,
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "target_addr": NS_ADDR_A,
            "target_port": src_port,
            "payload": "",
            "timeout_sec": 10,
        },
    )
    invalid_probe = make_netns_output_flag_probe(
        vm,
        NS_B,
        [
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "rst | ack",
                "comment": "bad_final_wrong_seq_rst",
            }
        ],
    )

    try:
        run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": "syn",
                "seq": 4095,
            },
        )
        synack_result = synack_capture.communicate(timeout=10)
        assert_completed(synack_result, "capture responder SYN|ACK")
        synack_data = parse_guest_json(synack_result.stdout, "captured responder SYN|ACK")
        if (synack_data.get("flags", 0) & 0x12) != 0x12:
            pytest.fail(f"expected SYN|ACK from responder, got {synack_data!r}")

        baseline_bad_final_rst = invalid_probe.packets(vm, "bad_final_wrong_seq_rst")

        run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": "ack",
                "seq": 5000,
                "ack": synack_data["seq"] + 1,
            },
        )
        time.sleep(0.2)

        if invalid_probe.packets(vm, "bad_final_wrong_seq_rst") <= baseline_bad_final_rst:
            pytest.fail("expected RST|ACK for final ACK with wrong sequence number")
    finally:
        drop_synack.cleanup(vm)
        invalid_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_bad_final_ack_flags_are_rejected_with_rstack(phantun_module, vm):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    drop_synack = make_netns_prerouting_flag_drop_probe(
        vm,
        NS_A,
        [
            {
                "src_addr": NS_ADDR_B,
                "src_port": dst_port,
                "dst_addr": NS_ADDR_A,
                "dst_port": src_port,
                "flags_expr": "syn | ack",
                "comment": "drop_half_open_synack_flags",
            }
        ],
    )
    synack_capture = spawn_ready_capture(
        vm,
        NS_A,
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "target_addr": NS_ADDR_A,
            "target_port": src_port,
            "payload": "",
            "timeout_sec": 10,
        },
    )
    invalid_probe = make_netns_output_flag_probe(
        vm,
        NS_B,
        [
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "rst | ack",
                "comment": "bad_final_flag_rst",
            }
        ],
    )

    try:
        run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": "syn",
                "seq": 4095,
            },
        )
        synack_result = synack_capture.communicate(timeout=10)
        assert_completed(synack_result, "capture responder SYN|ACK")
        synack_data = parse_guest_json(synack_result.stdout, "captured responder SYN|ACK")
        if (synack_data.get("flags", 0) & 0x12) != 0x12:
            pytest.fail(f"expected SYN|ACK from responder, got {synack_data!r}")

        baseline_bad_final_rst = invalid_probe.packets(vm, "bad_final_flag_rst")

        run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": "ack|fin",
                "seq": 4096,
                "ack": synack_data["seq"] + 1,
            },
        )
        time.sleep(0.2)

        if invalid_probe.packets(vm, "bad_final_flag_rst") <= baseline_bad_final_rst:
            pytest.fail("expected RST|ACK for final ACK carrying unexpected control flags")
    finally:
        drop_synack.cleanup(vm)
        invalid_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_fragmented_syn_is_rejected_without_creating_flow(phantun_module, vm):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    synack_probe = make_netns_output_flag_probe(
        vm,
        NS_B,
        [
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "syn | ack",
                "comment": "fragmented_syn_synack",
            }
        ],
    )
    baseline_stats = read_module_stats(vm)

    try:
        run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": "syn",
                "seq": 4095,
                "ip_frag_off": 0x2000,
            },
        )
        time.sleep(0.2)

        if synack_probe.packets(vm, "fragmented_syn_synack") != 0:
            pytest.fail("fragmented SYN must not elicit SYN|ACK")

        stats_after = read_module_stats(vm)
        if stats_after["flows_created"] != baseline_stats["flows_created"]:
            pytest.fail(f"fragmented SYN must not create flow state: before={baseline_stats!r} after={stats_after!r}")
    finally:
        synack_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_bad_tcp_checksum_syn_is_silently_dropped(phantun_module, vm):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    ingress_probe = make_netns_ingress_flag_drop_probe(
        vm,
        NS_B,
        VETH_B,
        [
            {
                "src_addr": NS_ADDR_A,
                "src_port": src_port,
                "dst_addr": NS_ADDR_B,
                "dst_port": dst_port,
                "flags_expr": "syn",
                "comment": "bad_tcp_syn_ingress",
                "action": "accept",
            }
        ],
    )
    synack_probe = make_netns_output_flag_probe(
        vm,
        NS_B,
        [
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "syn | ack",
                "comment": "bad_tcp_syn_synack",
            }
        ],
    )
    baseline_stats = read_module_stats(vm)

    try:
        run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": "syn",
                "seq": 4095,
                "corrupt_tcp_checksum": True,
            },
        )
        time.sleep(0.2)

        if ingress_probe.packets(vm, "bad_tcp_syn_ingress") == 0:
            pytest.fail("bad-checksum SYN did not reach the remote ingress path in this test environment")
        if synack_probe.packets(vm, "bad_tcp_syn_synack") != 0:
            pytest.fail("bad TCP checksum SYN must be silently dropped without SYN|ACK")

        stats_after = read_module_stats(vm)
        if stats_after["flows_created"] != baseline_stats["flows_created"]:
            pytest.fail(
                f"bad TCP checksum SYN must not create flow state: before={baseline_stats!r} after={stats_after!r}"
            )
    finally:
        ingress_probe.cleanup(vm)
        synack_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_bad_ip_checksum_syn_is_silently_dropped(phantun_module, vm):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    ingress_probe = make_netns_ingress_flag_drop_probe(
        vm,
        NS_B,
        VETH_B,
        [
            {
                "src_addr": NS_ADDR_A,
                "src_port": src_port,
                "dst_addr": NS_ADDR_B,
                "dst_port": dst_port,
                "flags_expr": "syn",
                "comment": "bad_ip_syn_ingress",
                "action": "accept",
            }
        ],
    )
    synack_probe = make_netns_output_flag_probe(
        vm,
        NS_B,
        [
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "syn | ack",
                "comment": "bad_ip_syn_synack",
            }
        ],
    )
    baseline_stats = read_module_stats(vm)

    try:
        dst_mac = read_netns_iface_mac(vm, NS_B, VETH_B)
        run_netns_scenario(
            vm,
            NS_A,
            "send_l2_tcp_packet",
            {
                "device": VETH_A,
                "dst_mac": dst_mac,
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": "syn",
                "seq": 4095,
                "corrupt_ip_checksum": True,
            },
        )
        time.sleep(0.2)

        if ingress_probe.packets(vm, "bad_ip_syn_ingress") == 0:
            pytest.fail("bad-IP-checksum SYN did not reach the remote ingress path in this test environment")
        if synack_probe.packets(vm, "bad_ip_syn_synack") != 0:
            pytest.fail("bad IP checksum SYN must be silently dropped without SYN|ACK")

        stats_after = read_module_stats(vm)
        if stats_after["flows_created"] != baseline_stats["flows_created"]:
            pytest.fail(
                f"bad IP checksum SYN must not create flow state: before={baseline_stats!r} after={stats_after!r}"
            )
    finally:
        ingress_probe.cleanup(vm)
        synack_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_bad_tcp_checksum_unknown_ack_is_silently_dropped(phantun_module, vm):
    phantun_module.load(managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    ingress_probe = make_netns_ingress_flag_drop_probe(
        vm,
        NS_B,
        VETH_B,
        [
            {
                "src_addr": NS_ADDR_A,
                "src_port": src_port,
                "dst_addr": NS_ADDR_B,
                "dst_port": dst_port,
                "flags_expr": "ack",
                "comment": "bad_tcp_ack_ingress",
                "action": "accept",
            }
        ],
    )
    rst_probe = make_netns_output_flag_probe(
        vm,
        NS_B,
        [
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "rst | ack",
                "comment": "bad_tcp_ack_rst",
            }
        ],
    )
    baseline_stats = read_module_stats(vm)

    try:
        run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": "ack",
                "seq": 12345,
                "ack": 67890,
                "payload": "junk",
                "corrupt_tcp_checksum": True,
            },
        )
        time.sleep(0.2)

        if ingress_probe.packets(vm, "bad_tcp_ack_ingress") == 0:
            pytest.fail("bad-checksum ACK did not reach the remote ingress path in this test environment")
        if rst_probe.packets(vm, "bad_tcp_ack_rst") != 0:
            pytest.fail("bad TCP checksum unknown ACK must be silently dropped without RST|ACK")

        stats_after = read_module_stats(vm)
        if stats_after["rst_sent"] != baseline_stats["rst_sent"]:
            pytest.fail(
                f"bad TCP checksum unknown ACK must not increment rst_sent: before={baseline_stats!r} after={stats_after!r}"
            )
    finally:
        ingress_probe.cleanup(vm)
        rst_probe.cleanup(vm)
        cleanup_netns_topology(vm)
