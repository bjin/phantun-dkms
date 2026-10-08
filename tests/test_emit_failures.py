"""Local fake-TCP send (OUTPUT) failures in every handshake and established state."""

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
    REQ,
    RESP,
    VETH_A,
    assert_completed,
    cleanup_netns_topology,
    ensure_netns_topology,
    load_managed_module,
    make_netns_ingress_flag_drop_probe,
    make_netns_output_flag_probe,
    make_netns_tcp_payload_probe,
    parse_guest_json,
    read_module_stats,
    received_messages,
    require_guest_command,
    run_netns_scenario,
    spawn_netns_scenario,
    wait_for_flows_current,
    wait_for_guest_ready_file,
    write_guest_text,
)


def wait_for_flows_above(vm, baseline, timeout=5):
    stats = read_module_stats(vm)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if stats["flows_current"] > baseline:
            return stats
        time.sleep(0.1)
        stats = read_module_stats(vm)
    pytest.fail(f"flows_current did not exceed {baseline}: current={stats!r}")


def wait_for_flows_below(vm, baseline, timeout=10):
    stats = read_module_stats(vm)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if stats["flows_current"] < baseline:
            return stats
        time.sleep(0.1)
        stats = read_module_stats(vm)
    pytest.fail(f"flows_current did not fall below {baseline}: current={stats!r}")


def wait_for_probe_packets(vm, probe, comment, timeout=5):
    packets = 0
    deadline = time.time() + timeout
    while time.time() < deadline:
        packets = probe.packets(vm, comment)
        if packets > 0:
            return packets
        time.sleep(0.1)

    pytest.fail(f"probe {comment!r} did not observe packets: packets={packets}")


def test_initial_syn_emit_failure_releases_flow_slot_and_queue(phantun_module, vm):
    load_managed_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    baseline_stats = read_module_stats(vm)
    probe = make_netns_output_flag_probe(
        vm,
        NS_A,
        [
            {
                "src_addr": NS_ADDR_A,
                "src_port": src_port,
                "dst_addr": NS_ADDR_B,
                "dst_port": dst_port,
                "flags_expr": "syn",
                "action": "drop",
                "comment": "drop_initial_syn_local_emit",
            }
        ],
    )
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "recv_many",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 1,
            "timeout_sec": 10,
        },
    )

    try:
        time.sleep(0.2)
        first = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["must-not-leak"],
            },
        )
        assert_completed(first, "initial SYN local emit failure sender")
        if probe.packets(vm, "drop_initial_syn_local_emit") <= 0:
            pytest.fail("expected nft OUTPUT rule to drop the locally emitted SYN")

        stats_after_failure = wait_for_flows_current(vm, baseline_stats["flows_current"])
        if stats_after_failure["udp_packets_dropped"] <= baseline_stats["udp_packets_dropped"]:
            pytest.fail(f"expected failed initial SYN emit to count a UDP drop: {stats_after_failure!r}")
        if stats_after_failure["udp_translation_failed_dropped"] <= baseline_stats["udp_translation_failed_dropped"]:
            pytest.fail(
                "expected failed initial SYN emit to count a UDP translation failure, " f"got {stats_after_failure!r}"
            )

        probe.cleanup(vm)
        second = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["fresh-flow"],
            },
        )
        assert_completed(second, "fresh flow sender after failed SYN")
        server_result = server.communicate(timeout=15)
        assert_completed(server_result, "fresh flow receiver after failed SYN")
        server_data = parse_guest_json(server_result.stdout, "fresh flow receiver stdout")
        if received_messages(server_data) != ["fresh-flow"]:
            pytest.fail(f"failed initial SYN retained or delivered queued skb: {server_data!r}")
    finally:
        probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_responder_synack_emit_failure_does_not_keep_half_open_flow(phantun_module, vm):
    # A long handshake timeout leaves a quiet window between the initiator's
    # SYN retransmissions in which the responder's state can be observed.
    load_managed_module(phantun_module, handshake_timeout_ms=3000, handshake_retries=3)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    payload = "queued-before-synack"
    ready_file = f"/tmp/phantun-synack-emit-failure-{uuid.uuid4().hex}"
    synack_drop = make_netns_output_flag_probe(
        vm,
        NS_B,
        [
            {
                "src_addr": NS_ADDR_B,
                "src_port": dst_port,
                "dst_addr": NS_ADDR_A,
                "dst_port": src_port,
                "flags_expr": "syn | ack",
                "action": "drop",
                "comment": "drop_synack_local_emit",
            }
        ],
    )
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "recv_many",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 1,
            "timeout_sec": 20,
            "ready_file": ready_file,
        },
    )

    try:
        wait_for_guest_ready_file(vm, ready_file, timeout=5)
        baseline_stats = read_module_stats(vm)
        client = run_netns_scenario(
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
        )
        assert_completed(client, "SYN|ACK emit failure sender")
        wait_for_probe_packets(vm, synack_drop, "drop_synack_local_emit")

        # Only the initiator's SYN_SENT flow may remain. A responder that could
        # not answer must not keep half-open state for the tuple until its own
        # retransmit budget runs out.
        wait_for_flows_current(
            vm,
            baseline_stats["flows_current"] + 1,
            timeout=2,
            reason="responder kept half-open state after a fatal SYN|ACK emit failure",
        )

        synack_drop.cleanup(vm)
        server_result = server.communicate(timeout=20)
        assert_completed(server_result, "SYN|ACK emit failure receiver")
        server_data = parse_guest_json(server_result.stdout, "SYN|ACK emit failure receiver stdout")
        if received_messages(server_data) != [payload]:
            pytest.fail(f"initiator SYN retransmission did not recover the queued payload: {server_data!r}")

        final_stats = read_module_stats(vm)
        if final_stats["flows_established"] - baseline_stats["flows_established"] != 2:
            pytest.fail(f"expected the recovered handshake to establish both ends: {final_stats!r}")
    finally:
        synack_drop.cleanup(vm)
        if server.proc.poll() is None:
            server.terminate()
        cleanup_netns_topology(vm)


def test_handshake_request_emit_failure_never_sends_application_data(phantun_module, vm):
    load_managed_module(phantun_module, handshake_request=REQ)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    stale_payload = "queued-before-request"
    fresh_payload = "sent-after-reopen"
    ready_file = f"/tmp/phantun-request-emit-failure-{uuid.uuid4().hex}"
    request_drop = make_netns_tcp_payload_probe(
        vm,
        NS_A,
        [
            {
                "src_addr": NS_ADDR_A,
                "src_port": src_port,
                "dst_addr": NS_ADDR_B,
                "dst_port": dst_port,
                "payload": REQ,
                "action": "drop",
                "comment": "drop_request_local_emit",
            }
        ],
    )
    stale_probe = make_netns_tcp_payload_probe(
        vm,
        NS_A,
        [
            {
                "src_addr": NS_ADDR_A,
                "src_port": src_port,
                "dst_addr": NS_ADDR_B,
                "dst_port": dst_port,
                "payload": stale_payload,
                "comment": "stale_payload_emitted",
            }
        ],
    )
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "recv_many",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 1,
            "timeout_sec": 20,
            "ready_file": ready_file,
        },
    )

    try:
        wait_for_guest_ready_file(vm, ready_file, timeout=5)
        baseline_stats = read_module_stats(vm)
        first = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": [stale_payload],
            },
        )
        assert_completed(first, "request emit failure sender")
        wait_for_probe_packets(vm, request_drop, "drop_request_local_emit")

        # The queued payload would be flushed right behind the request in the
        # same receive path, so a leak is already visible on the wire here.
        if stale_probe.packets(vm, "stale_payload_emitted") != 0:
            pytest.fail("initiator sent application data on a generation whose handshake_request failed")

        # The initiator abandons the generation; the responder's SYN|ACK
        # retransmission then meets an unknown tuple and is reset, so both ends
        # drain.
        wait_for_flows_current(
            vm,
            baseline_stats["flows_current"],
            reason="a failed handshake_request did not tear down the generation on both ends",
        )

        request_drop.cleanup(vm)
        second = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": [fresh_payload],
            },
        )
        assert_completed(second, "sender after request emit failure")
        server_result = server.communicate(timeout=20)
        assert_completed(server_result, "receiver after request emit failure")
        server_data = parse_guest_json(server_result.stdout, "request emit failure receiver stdout")
        if received_messages(server_data) != [fresh_payload]:
            pytest.fail(f"expected only the payload sent after reopening, got {server_data!r}")
        if stale_probe.packets(vm, "stale_payload_emitted") != 0:
            pytest.fail("payload queued on the failed generation was sent after reopening")
    finally:
        request_drop.cleanup(vm)
        stale_probe.cleanup(vm)
        if server.proc.poll() is None:
            server.terminate()
        cleanup_netns_topology(vm)


def test_handshake_response_emit_failure_tears_down_responder_generation(phantun_module, vm):
    load_managed_module(phantun_module, handshake_request=REQ, handshake_response=RESP)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    stale_payload = "opened-before-response"
    fresh_payload = "sent-after-reopen"
    ready_file = f"/tmp/phantun-response-emit-failure-{uuid.uuid4().hex}"
    response_drop = make_netns_tcp_payload_probe(
        vm,
        NS_B,
        [
            {
                "src_addr": NS_ADDR_B,
                "src_port": dst_port,
                "dst_addr": NS_ADDR_A,
                "dst_port": src_port,
                "payload": RESP,
                "action": "drop",
                "comment": "drop_response_local_emit",
            }
        ],
    )
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "recv_many",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 1,
            "timeout_sec": 20,
            "ready_file": ready_file,
        },
    )

    try:
        wait_for_guest_ready_file(vm, ready_file, timeout=5)
        baseline_stats = read_module_stats(vm)
        first = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": [stale_payload],
            },
        )
        assert_completed(first, "response emit failure sender")
        wait_for_probe_packets(vm, response_drop, "drop_response_local_emit")

        # The responder drops the generation it could not announce. Data the
        # initiator already sent on it hits an unknown tuple and is reset, so
        # both ends drain and none of it reaches the responder's UDP socket.
        wait_for_flows_current(
            vm,
            baseline_stats["flows_current"],
            reason="a failed handshake_response did not tear down the generation on both ends",
        )

        response_drop.cleanup(vm)
        second = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": [fresh_payload],
            },
        )
        assert_completed(second, "sender after response emit failure")
        server_result = server.communicate(timeout=20)
        assert_completed(server_result, "receiver after response emit failure")
        server_data = parse_guest_json(server_result.stdout, "response emit failure receiver stdout")
        if received_messages(server_data) != [fresh_payload]:
            pytest.fail(f"responder delivered data from a generation whose handshake_response failed: {server_data!r}")
    finally:
        response_drop.cleanup(vm)
        if server.proc.poll() is None:
            server.terminate()
        cleanup_netns_topology(vm)


def test_established_payload_terminal_output_error_tears_down_flow_and_allows_reopen(phantun_module, vm):
    load_managed_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    baseline_stats = read_module_stats(vm)
    continue_file = f"/tmp/phantun-established-drop-{uuid.uuid4().hex}"
    drop_probe = None
    client = None
    first_server = None
    fresh_server = None

    try:
        first_server = spawn_netns_scenario(
            vm,
            NS_B,
            "recv_many",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "count": 1,
                "timeout_sec": 10,
            },
        )
        time.sleep(0.2)
        client = spawn_netns_scenario(
            vm,
            NS_A,
            "send_many_with_barrier",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["establish-ok", "fatal-established-drop"],
                "initial_count": 1,
                "continue_file": continue_file,
                "barrier_timeout_sec": 10,
            },
        )

        first_result = first_server.communicate(timeout=15)
        assert_completed(first_result, "established-send failure first receiver")
        first_data = parse_guest_json(first_result.stdout, "established-send failure first stdout")
        if received_messages(first_data) != ["establish-ok"]:
            pytest.fail(f"expected established first payload before drop, got {first_data!r}")

        wait_for_flows_above(vm, baseline_stats["flows_current"])
        drop_probe = make_netns_output_flag_probe(
            vm,
            NS_A,
            [
                {
                    "src_addr": NS_ADDR_A,
                    "src_port": src_port,
                    "dst_addr": NS_ADDR_B,
                    "dst_port": dst_port,
                    "flags_expr": "ack",
                    "action": "drop",
                    "comment": "drop_established_payload_emit",
                }
            ],
        )

        write_guest_text(vm, continue_file, "continue\n")
        client_result = client.communicate(timeout=15)
        assert_completed(client_result, "established-send failure sender")
        wait_for_probe_packets(vm, drop_probe, "drop_established_payload_emit")

        failure_stats = wait_for_flows_current(vm, baseline_stats["flows_current"])
        translation_failures = (
            failure_stats["udp_translation_failed_dropped"] - baseline_stats["udp_translation_failed_dropped"]
        )
        if translation_failures != 1:
            pytest.fail(f"expected exactly one established UDP translation failure, got {failure_stats!r}")
        if failure_stats["rst_sent"] <= baseline_stats["rst_sent"]:
            pytest.fail(f"expected established-send failure to emit a best-effort RST, got {failure_stats!r}")

        drop_probe.cleanup(vm)
        drop_probe = None

        fresh_server = spawn_netns_scenario(
            vm,
            NS_B,
            "recv_many",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "count": 1,
                "timeout_sec": 10,
            },
        )
        time.sleep(0.2)
        fresh_client = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["fresh-flow"],
            },
        )
        assert_completed(fresh_client, "fresh flow sender after established-send failure")
        fresh_result = fresh_server.communicate(timeout=15)
        assert_completed(fresh_result, "fresh flow receiver after established-send failure")
        fresh_data = parse_guest_json(fresh_result.stdout, "fresh flow receiver stdout")
        if received_messages(fresh_data) != ["fresh-flow"]:
            pytest.fail(f"established-send failure retained a stale flow: {fresh_data!r}")
    finally:
        if drop_probe is not None:
            drop_probe.cleanup(vm)
        for proc in (client, first_server, fresh_server):
            if proc is not None and proc.proc.poll() is None:
                proc.terminate()
        cleanup_netns_topology(vm)


def test_queued_established_payload_emit_failure_frees_skb_and_does_not_send_rst(phantun_module, vm):
    load_managed_module(phantun_module, handshake_timeout_ms=3000, handshake_retries=1)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    initial_stats = read_module_stats(vm)
    drop_synack = None
    drop_queued = None
    payload_probe = None
    server = None
    fresh_server = None

    try:
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
                    "comment": "drop_synack_before_queue_flush",
                }
            ],
        )
        server_ready_file = f"/tmp/phantun-queued-failure-server-{uuid.uuid4().hex}"
        server_stop_file = f"/tmp/phantun-queued-failure-stop-{uuid.uuid4().hex}"
        server = spawn_netns_scenario(
            vm,
            NS_B,
            "recv_until_timeout",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "count": 1,
                "timeout_sec": 30,
                "ready_file": server_ready_file,
                "stop_file": server_stop_file,
            },
        )
        wait_for_guest_ready_file(vm, server_ready_file)
        client = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["queued-fatal-drop"],
            },
        )
        assert_completed(client, "queued established-send failure sender")

        queued_stats = read_module_stats(vm)
        deadline = time.time() + 5
        while time.time() < deadline:
            if queued_stats["udp_packets_queued"] - initial_stats["udp_packets_queued"] == 1:
                break
            time.sleep(0.1)
            queued_stats = read_module_stats(vm)
        else:
            pytest.fail(f"expected one half-open queued UDP skb, got {queued_stats!r}")

        wait_for_probe_packets(vm, drop_synack, "drop_synack_before_queue_flush")
        queued_stats = read_module_stats(vm)
        drop_queued = make_netns_output_flag_probe(
            vm,
            NS_A,
            [
                {
                    "src_addr": NS_ADDR_A,
                    "src_port": src_port,
                    "dst_addr": NS_ADDR_B,
                    "dst_port": dst_port,
                    "flags_expr": "ack",
                    "action": "drop",
                    "comment": "drop_queued_payload_emit",
                },
                {
                    "src_addr": NS_ADDR_A,
                    "src_port": src_port,
                    "dst_addr": NS_ADDR_B,
                    "dst_port": dst_port,
                    "flags_expr": "rst | ack",
                    "action": "drop",
                    "comment": "drop_unrelated_unknown_tuple_rstack",
                },
            ],
        )

        drop_synack.cleanup(vm)
        drop_synack = None
        wait_for_probe_packets(vm, drop_queued, "drop_queued_payload_emit", timeout=6)

        failure_stats = read_module_stats(vm)
        translation_failures = (
            failure_stats["udp_translation_failed_dropped"] - queued_stats["udp_translation_failed_dropped"]
        )
        if translation_failures != 1:
            pytest.fail(f"expected exactly one queued UDP translation failure, got {failure_stats!r}")
        if failure_stats["rst_sent"] != queued_stats["rst_sent"]:
            pytest.fail(f"queued established-send failure must not emit RST, got {failure_stats!r}")

        wait_for_flows_below(vm, queued_stats["flows_current"])

        write_guest_text(vm, server_stop_file, "stop\n")
        server_result = server.communicate(timeout=12)
        assert_completed(server_result, "queued established-send failure receiver")
        server_data = parse_guest_json(server_result.stdout, "queued failure receiver stdout")
        if not server_data.get("stopped") or received_messages(server_data):
            pytest.fail(f"queued payload was unexpectedly delivered before server stop: {server_data!r}")

        payload_probe = make_netns_tcp_payload_probe(
            vm,
            NS_A,
            [
                {
                    "src_addr": NS_ADDR_A,
                    "src_port": src_port,
                    "dst_addr": NS_ADDR_B,
                    "dst_port": dst_port,
                    "payload": "queued-fatal-drop",
                    "comment": "queued_payload_replayed",
                    "action": "accept",
                }
            ],
        )
        drop_queued.cleanup(vm)
        drop_queued = None

        deadline = time.time() + 1.0
        while time.time() < deadline:
            if payload_probe.packets(vm, "queued_payload_replayed") != 0:
                pytest.fail("queued payload was retained and replayed after the drop rule was removed")
            time.sleep(0.1)

        wait_for_flows_current(vm, initial_stats["flows_current"], timeout=12)
        fresh_ready_file = f"/tmp/phantun-queued-failure-fresh-{uuid.uuid4().hex}"
        fresh_server = spawn_netns_scenario(
            vm,
            NS_B,
            "recv_many",
            {
                "bind_addr": NS_ADDR_B,
                "bind_port": dst_port,
                "count": 1,
                "timeout_sec": 10,
                "ready_file": fresh_ready_file,
            },
        )
        wait_for_guest_ready_file(vm, fresh_ready_file)
        fresh_client = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["fresh-after-queued-failure"],
            },
        )
        assert_completed(fresh_client, "fresh sender after queued established-send failure")
        fresh_result = fresh_server.communicate(timeout=15)
        assert_completed(fresh_result, "fresh receiver after queued established-send failure")
        fresh_data = parse_guest_json(fresh_result.stdout, "fresh queued-failure receiver stdout")
        if received_messages(fresh_data) != ["fresh-after-queued-failure"]:
            pytest.fail(f"queued established-send failure retained a stale flow: {fresh_data!r}")
    finally:
        for probe in (drop_synack, drop_queued, payload_probe):
            if probe is not None:
                probe.cleanup(vm)
        for proc in (server, fresh_server):
            if proc is not None and proc.proc.poll() is None:
                proc.terminate()
        cleanup_netns_topology(vm)
