"""Inbound fake-TCP classification: flag/ACK/sequence validation and unknown-tuple RSTs."""

import time
import uuid

import pytest

from helpers import (
    MANAGED_LOCAL_PORTS,
    NS_A,
    NS_ADDR_A,
    NS_ADDR_B,
    NS_B,
    PORTS_A,
    PORTS_B,
    VETH_A,
    assert_completed,
    assert_receiver_messages,
    cleanup_netns_topology,
    ensure_netns_topology,
    make_netns_ingress_flag_drop_probe,
    make_netns_output_flag_probe,
    make_netns_prerouting_flag_drop_probe,
    parse_guest_json,
    read_module_stats,
    received_messages,
    require_guest_command,
    run_netns_scenario,
    spawn_netns_scenario,
    spawn_ready_capture,
    spawn_ready_recv_until_timeout,
    wait_for_flows_current,
    wait_for_guest_ready_file,
    wait_for_stat_greater,
)


def open_flow_to_waiting_receiver(vm, src_port, dst_port, timeout_sec=3):
    receiver = spawn_ready_recv_until_timeout(
        vm,
        NS_B,
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 2,
            "timeout_sec": timeout_sec,
        },
    )
    baseline_stats = read_module_stats(vm)
    sender = run_netns_scenario(
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
    assert_completed(sender, "established-flow opener")
    wait_for_stat_greater(vm, "flows_established", baseline_stats["flows_established"])
    return receiver


def test_syn_fin_is_rejected_without_creating_flow(phantun_module, vm):
    phantun_module.load(managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS)
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


def test_fragmented_syn_is_rejected_without_creating_flow(phantun_module, vm):
    phantun_module.load(managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS)
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


@pytest.mark.parametrize(
    ("flags", "tag"),
    (
        ("syn|ack|fin", "fin"),
        ("syn|ack|psh", "psh"),
        ("syn|ack|urg", "urg"),
        ("ack|fin", "ackfin"),
        ("ack|urg", "ackurg"),
    ),
)
def test_malformed_handshake_flags_do_not_complete_syn_sent(phantun_module, vm, flags, tag):
    phantun_module.load(managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS, handshake_timeout_ms=5000)
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
                "comment": f"drop_syn_sent_{tag}_synack",
            }
        ],
    )
    syn_capture = spawn_ready_capture(
        vm,
        NS_B,
        {
            "bind_addr": NS_ADDR_A,
            "bind_port": src_port,
            "target_addr": NS_ADDR_B,
            "target_port": dst_port,
            "payload": "",
            "timeout_sec": 10,
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
                "comment": f"syn_sent_bad_{tag}_rst",
            }
        ],
    )
    baseline_stats = read_module_stats(vm)

    try:
        sender = run_netns_scenario(
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
        assert_completed(sender, f"{tag} malformed SYN|ACK opener")

        syn_result = syn_capture.communicate(timeout=10)
        assert_completed(syn_result, f"{tag} initial SYN capture")
        syn_data = parse_guest_json(syn_result.stdout, f"{tag} initial SYN capture stdout")
        baseline_rst = rst_probe.packets(vm, f"syn_sent_bad_{tag}_rst")

        drop_synack.cleanup(vm)
        drop_synack = None

        run_netns_scenario(
            vm,
            NS_B,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "target_addr": NS_ADDR_A,
                "target_port": src_port,
                "flags": flags,
                "seq": 8190,
                "ack": syn_data["seq"] + 1,
            },
        )
        time.sleep(0.2)

        if rst_probe.packets(vm, f"syn_sent_bad_{tag}_rst") <= baseline_rst:
            pytest.fail(f"malformed SYN|ACK flags {flags!r} should be rejected with RST|ACK")

        stats_after = wait_for_flows_current(vm, baseline_stats["flows_current"], timeout=5)
        if stats_after["flows_established"] != baseline_stats["flows_established"]:
            pytest.fail(
                f"malformed SYN|ACK flags {flags!r} must not establish flow: "
                f"before={baseline_stats!r} after={stats_after!r}"
            )
    finally:
        if drop_synack is not None:
            drop_synack.cleanup(vm)
        rst_probe.cleanup(vm)
        cleanup_netns_topology(vm)


@pytest.mark.parametrize("flags", ["ack", "ack|psh"])
@pytest.mark.parametrize("payload", ["", "junk"])
def test_wrong_final_ack_retains_half_open_until_valid_completion(phantun_module, vm, flags, payload):
    phantun_module.load(
        managed_netns="all",
        managed_local_ports=MANAGED_LOCAL_PORTS,
        handshake_timeout_ms=1000,
        handshake_retries=60,
    )
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

    synack_capture = spawn_ready_capture(
        vm,
        NS_B,
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "target_addr": NS_ADDR_A,
            "target_port": src_port,
            "payload": "",
            "flags": "syn|ack",
            "timeout_sec": 15,
            "include_outgoing": True,
        },
    )
    stop_file = f"/tmp/phantun-wrong-ack-stop-{uuid.uuid4().hex}"
    receiver = spawn_ready_recv_until_timeout(
        vm,
        NS_B,
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 2,
            "timeout_sec": 60,
            "stop_file": stop_file,
        },
    )
    baseline = read_module_stats(vm)
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
        captured = synack_capture.communicate(timeout=15)
        assert_completed(captured, "half-open SYNACK capture")
        synack = parse_guest_json(captured.stdout, "half-open SYNACK")
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
                "flags": flags,
                "seq": 4096,
                "ack": (synack["seq"] + 2) & 0xFFFFFFFF,
                "payload": payload,
            },
        )
        time.sleep(0.2)

        retained = read_module_stats(vm)
        assert retained["flows_current"] == baseline["flows_current"] + 1
        assert retained["flows_established"] == baseline["flows_established"]
        assert retained["tcp_protocol_rejected"] == baseline["tcp_protocol_rejected"]
        assert invalid_probe.packets(vm, "bad_final_rst") == baseline_bad_final_rst
        valid = run_netns_scenario(
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
                "ack": (synack["seq"] + 1) & 0xFFFFFFFF,
                "payload": "fresh",
            },
        )
        assert_completed(valid, "valid final ACK after stale traffic")
        wait_for_stat_greater(vm, "flows_established", baseline["flows_established"])
        vm.run(["touch", stop_file])
        result = receiver.communicate(timeout=10)
        assert_completed(result, "wrong-final-ACK receiver")
        assert received_messages(parse_guest_json(result.stdout, "wrong-final-ACK receiver")) == ["fresh"]
    finally:
        drop_synack.cleanup(vm)
        invalid_probe.cleanup(vm)
        if receiver.proc.poll() is None:
            receiver.terminate()
        vm.run(["rm", "-f", stop_file], check=False)
        cleanup_netns_topology(vm)


@pytest.mark.parametrize(
    ("flags", "tag"),
    (
        ("syn|ack", "synack"),
        ("ack|urg", "ackurg"),
        ("ack|fin", "ackfin"),
    ),
)
def test_unsupported_final_ack_flags_are_rejected_with_rstack(phantun_module, vm, flags, tag):
    phantun_module.load(managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS)
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
                "comment": f"drop_{tag}_synack",
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
                "comment": f"unsupported_final_{tag}_rst",
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
            },
        )
        synack_result = synack_capture.communicate(timeout=10)
        assert_completed(synack_result, f"{tag} final-ACK SYN|ACK capture")
        synack_data = parse_guest_json(synack_result.stdout, f"{tag} final-ACK SYN|ACK stdout")
        baseline_rst = rst_probe.packets(vm, f"unsupported_final_{tag}_rst")

        run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": flags,
                "seq": 4096,
                "ack": synack_data["seq"] + 1,
            },
        )
        time.sleep(0.2)

        stats_after = read_module_stats(vm)
        if rst_probe.packets(vm, f"unsupported_final_{tag}_rst") <= baseline_rst:
            pytest.fail(f"expected RST|ACK for unsupported final ACK flags {flags!r}")
        if stats_after["flows_established"] != baseline_stats["flows_established"]:
            pytest.fail(
                f"unsupported final ACK flags must not establish flow: before={baseline_stats!r} after={stats_after!r}"
            )
    finally:
        drop_synack.cleanup(vm)
        rst_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_established_payload_without_ack_is_rejected_with_rstack(phantun_module, vm):
    phantun_module.load(managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    receiver = None
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
                "comment": "est_no_ack_rst",
            }
        ],
    )

    baseline_stats = read_module_stats(vm)

    try:
        receiver = open_flow_to_waiting_receiver(vm, src_port, dst_port)
        baseline_rst = rst_probe.packets(vm, "est_no_ack_rst")

        run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": "psh",
                "seq": 12345,
                "payload": "blocked",
            },
        )
        time.sleep(0.2)

        if rst_probe.packets(vm, "est_no_ack_rst") <= baseline_rst:
            pytest.fail("established payload without ACK should be rejected with RST|ACK")
        wait_for_flows_current(vm, baseline_stats["flows_current"], timeout=5)

        receiver_result = receiver.communicate(timeout=10)
        receiver = None
        assert_receiver_messages(
            receiver_result,
            ["open"],
            "established no-ACK receiver",
            timed_out=True,
        )
    finally:
        if receiver is not None:
            receiver.terminate()
        rst_probe.cleanup(vm)
        cleanup_netns_topology(vm)


@pytest.mark.parametrize(
    ("flags", "tag"),
    (
        ("ack|fin", "fin"),
        ("ack|urg", "urg"),
    ),
)
def test_established_ack_payload_with_unsupported_flags_tears_down_flow(phantun_module, vm, flags, tag):
    phantun_module.load(managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    receiver = None
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
                "comment": f"est_ack_{tag}_rst",
            }
        ],
    )

    baseline_stats = read_module_stats(vm)

    try:
        receiver = open_flow_to_waiting_receiver(vm, src_port, dst_port)
        baseline_rst = rst_probe.packets(vm, f"est_ack_{tag}_rst")

        run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": flags,
                "seq": 12345,
                "ack": 1,
                "payload": "blocked",
            },
        )
        time.sleep(0.2)

        if rst_probe.packets(vm, f"est_ack_{tag}_rst") <= baseline_rst:
            pytest.fail(f"established ACK payload with {flags!r} should be rejected with RST|ACK")
        wait_for_flows_current(vm, baseline_stats["flows_current"], timeout=5)

        receiver_result = receiver.communicate(timeout=10)
        receiver = None
        assert_receiver_messages(
            receiver_result,
            ["open"],
            f"established ACK {tag} receiver",
            timed_out=True,
        )
    finally:
        if receiver is not None:
            receiver.terminate()
        rst_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_established_ack_psh_payload_is_accepted(phantun_module, vm):
    phantun_module.load(managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    receiver = None
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
                "comment": "est_ack_psh_rst",
            }
        ],
    )

    try:
        receiver = open_flow_to_waiting_receiver(vm, src_port, dst_port)
        baseline_rst = rst_probe.packets(vm, "est_ack_psh_rst")

        run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": "ack|psh",
                "seq": 12345,
                "ack": 1,
                "payload": "accepted",
            },
        )

        receiver_result = receiver.communicate(timeout=10)
        receiver = None
        assert_receiver_messages(
            receiver_result,
            ["open", "accepted"],
            "established ACK|PSH receiver",
            timed_out=False,
        )
        if rst_probe.packets(vm, "est_ack_psh_rst") != baseline_rst:
            pytest.fail("established ACK|PSH payload should not be rejected with RST|ACK")
    finally:
        if receiver is not None:
            receiver.terminate()
        rst_probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_established_pure_ack_does_not_advance_payload_ack(phantun_module, vm):
    phantun_module.load(managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS, keepalive_interval_sec=60)
    ensure_netns_topology(vm)
    src_port, dst_port = PORTS_A[0], PORTS_B[0]
    ready_file = f"/tmp/phantun-pure-ack-{uuid.uuid4().hex}"
    server = first_capture = reply_capture = None
    try:
        server = spawn_netns_scenario(
            vm,
            NS_B,
            "recv_many_reply",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "count": 2,
                "replies": ["ready", "after-ready"],
                "ready_file": ready_file,
                "timeout_sec": 30,
            },
        )
        wait_for_guest_ready_file(vm, ready_file)
        first_capture = spawn_ready_capture(
            vm,
            NS_B,
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payload": "warmup",
                "timeout_sec": 20,
            },
        )
        client_config = {
            "bind_addr": NS_ADDR_A,
            "bind_port": src_port,
            "target_addr": NS_ADDR_B,
            "target_port": dst_port,
        }
        warmup = run_netns_scenario(vm, NS_A, "ping_client", {**client_config, "payload": "warmup"}, timeout=10)
        assert_completed(warmup, "pure-ACK warm-up")
        if parse_guest_json(warmup.stdout, "pure-ACK warm-up")["reply"] != "ready":
            pytest.fail("pure-ACK warm-up did not establish bidirectional delivery")
        first_result = first_capture.communicate(timeout=20)
        assert_completed(first_result, "initial payload sequence capture")
        first = parse_guest_json(first_result.stdout, "initial payload sequence")
        next_seq = (first["seq"] + len("warmup")) & 0xFFFFFFFF

        # An ACK-only keepalive consumes no sequence space. A future seq must
        # not move the receiver's advertised payload ACK past real later data.
        injected = run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                **client_config,
                "flags": "ack",
                "seq": (next_seq + 65536) & 0xFFFFFFFF,
                "ack": (first["ack"] + len("ready")) & 0xFFFFFFFF,
                "payload": "",
            },
            timeout=10,
        )
        assert_completed(injected, "future-sequence pure ACK")
        reply_capture = spawn_ready_capture(
            vm,
            NS_A,
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "target_addr": NS_ADDR_A,
                "target_port": src_port,
                "payload": "after-ready",
                "timeout_sec": 20,
            },
        )
        later = run_netns_scenario(vm, NS_A, "ping_client", {**client_config, "payload": "after-ack"}, timeout=10)
        assert_completed(later, "payload after pure ACK")
        if parse_guest_json(later.stdout, "payload after pure ACK")["reply"] != "after-ready":
            pytest.fail("application reply after pure ACK was corrupted")
        reply_result = reply_capture.communicate(timeout=20)
        assert_completed(reply_result, "payload ACK capture")
        reply = parse_guest_json(reply_result.stdout, "payload ACK capture")
        expected_ack = (next_seq + len("after-ack")) & 0xFFFFFFFF
        if reply["ack"] != expected_ack:
            pytest.fail(f"pure ACK advanced the receive sequence window: {reply!r}")
        server_result = server.communicate(timeout=20)
        assert_completed(server_result, "pure-ACK receiver")
        received = parse_guest_json(server_result.stdout, "pure-ACK receiver")["received"]
        if [entry["message"] for entry in received] != ["warmup", "after-ack"]:
            pytest.fail(f"pure ACK altered UDP delivery: {received!r}")
    finally:
        for process in (reply_capture, first_capture, server):
            if process is not None:
                process.terminate()
        vm.run(["rm", "-f", ready_file], check=False)
        cleanup_netns_topology(vm)


def test_unknown_synack_is_rejected_without_creating_flow(phantun_module, vm):
    phantun_module.load(managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS)
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
                "comment": "unknown_rst",
            },
            {
                "src_addr": NS_ADDR_B,
                "dst_addr": NS_ADDR_A,
                "src_port": dst_port,
                "dst_port": src_port,
                "flags_expr": "syn | ack",
                "comment": "unknown_synack",
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
                "flags": "syn|ack",
                "seq": 12345,
                "ack": 1,
            },
        )
        time.sleep(0.2)

        if invalid_probe.packets(vm, "unknown_rst") == 0:
            pytest.fail("expected RST|ACK for unknown SYN|ACK opener")
        if invalid_probe.packets(vm, "unknown_synack") != 0:
            pytest.fail("unknown SYN|ACK must not create a responder half-open flow")
    finally:
        invalid_probe.cleanup(vm)

    server = spawn_netns_scenario(
        vm,
        NS_B,
        "echo_server",
        {"bind_addr": NS_ADDR_B, "bind_port": dst_port, "count": 1},
    )
    time.sleep(0.2)
    client = run_netns_scenario(
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
    server_result = server.communicate(timeout=10)
    assert_completed(client, "echo client after unknown synack")
    assert_completed(server_result, "echo server after unknown synack")
    server_data = parse_guest_json(server_result.stdout, "echo server stdout")
    if received_messages(server_data) != ["msg1"]:
        pytest.fail(f"unexpected server messages after unknown synack: {received_messages(server_data)!r}")


def test_unknown_ack_payload_is_rejected_with_rstack(phantun_module, vm):
    phantun_module.load(managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS)
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
                "comment": "unknown_ack_rst",
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
            },
        )
        time.sleep(0.2)
        if invalid_probe.packets(vm, "unknown_ack_rst") == 0:
            pytest.fail("expected RST|ACK for unknown non-RST fake-TCP packet")
        stats = read_module_stats(vm)
        if stats["tcp_protocol_rejected"] <= baseline_stats["tcp_protocol_rejected"]:
            pytest.fail(f"expected tcp_protocol_rejected to increase, got {stats!r}")
        if stats["tcp_unknown_tuple_rejected"] <= baseline_stats["tcp_unknown_tuple_rejected"]:
            pytest.fail(f"expected tcp_unknown_tuple_rejected to increase, got {stats!r}")
    finally:
        invalid_probe.cleanup(vm)

    server = spawn_netns_scenario(
        vm,
        NS_B,
        "echo_server",
        {"bind_addr": NS_ADDR_B, "bind_port": dst_port, "count": 1},
    )
    time.sleep(0.2)
    client = run_netns_scenario(
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
    server_result = server.communicate(timeout=10)
    assert_completed(client, "echo client after unknown ack payload")
    assert_completed(server_result, "echo server after unknown ack payload")
    server_data = parse_guest_json(server_result.stdout, "echo server stdout")
    if received_messages(server_data) != ["msg1"]:
        pytest.fail(f"unexpected server messages after unknown ack payload: {received_messages(server_data)!r}")


def test_unknown_tuple_rst_sequence_follows_ack_flag(phantun_module, vm):
    phantun_module.load(managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS)
    ensure_netns_topology(vm)

    # 45001 is neither a managed local port nor in PORTS_A/PORTS_B, so the
    # module in NS_A never selector-matches the RST replies captured here.
    src_port = 45001
    dst_port = PORTS_B[0]

    try:
        baseline = read_module_stats(vm)

        # Case A: ACK-less FIN to an unknown tuple. RFC 793 reset generation:
        # no ACK on the incoming segment means the RST must carry seq=0.
        capture_a = spawn_ready_capture(
            vm,
            NS_A,
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "target_addr": NS_ADDR_A,
                "target_port": src_port,
                "timeout_sec": 10,
            },
        )
        inject_a = run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": "fin",
                "seq": 0x10203040,
                "ack": 0xDEADBEEF,
            },
        )
        assert_completed(inject_a, "inject ACK-less FIN")
        result_a = capture_a.communicate(timeout=15)
        assert_completed(result_a, "capture RST reply to ACK-less FIN")
        data_a = parse_guest_json(result_a.stdout, "fin reply")

        # Case B: SYN|ACK to an unknown tuple. The incoming segment has ACK
        # set, so the RST must echo its ack_seq as the sequence number.
        capture_b = spawn_ready_capture(
            vm,
            NS_A,
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "target_addr": NS_ADDR_A,
                "target_port": src_port,
                "timeout_sec": 10,
            },
        )
        inject_b = run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": "syn|ack",
                "seq": 0x55667788,
                "ack": 0x22334455,
            },
        )
        assert_completed(inject_b, "inject SYN|ACK")
        result_b = capture_b.communicate(timeout=15)
        assert_completed(result_b, "capture RST reply to SYN|ACK")
        data_b = parse_guest_json(result_b.stdout, "synack reply")

        # Collect all mismatches so a single run reports both bad seq values.
        expectations = [
            ("case A (ACK-less FIN) flags", data_a["flags"], 0x14),
            ("case A (ACK-less FIN) seq", data_a["seq"], 0),
            ("case A (ACK-less FIN) ack", data_a["ack"], 0x10203041),
            ("case B (SYN|ACK) flags", data_b["flags"], 0x14),
            ("case B (SYN|ACK) seq", data_b["seq"], 0x22334455),
            ("case B (SYN|ACK) ack", data_b["ack"], 0x55667789),
        ]
        failures = [
            f"{label}: expected 0x{expected:x}, observed 0x{observed:x}"
            for label, observed, expected in expectations
            if observed != expected
        ]
        if failures:
            pytest.fail("\n".join(failures))

        stats = read_module_stats(vm)
        assert stats["tcp_unknown_tuple_rejected"] == baseline["tcp_unknown_tuple_rejected"] + 2
        assert stats["rst_sent"] == baseline["rst_sent"] + 2
    finally:
        cleanup_netns_topology(vm)
