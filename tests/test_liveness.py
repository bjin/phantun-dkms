"""Keepalive liveness timeouts and idle ACK generation."""

import time
import uuid
from contextlib import contextmanager
from math import floor

import pytest

from helpers import (
    NS6_ADDR_A,
    NS6_ADDR_B,
    NS_A,
    NS_ADDR_A,
    NS_ADDR_B,
    NS_B,
    PORTS_A,
    PORTS_B,
    REQ,
    RESP,
    VETH_A,
    VETH_B,
    assert_completed,
    cleanup_netns_topology,
    ensure_netns_topology,
    load_fast_liveness_module,
    load_managed_module,
    make_netns_ingress_drop_probe,
    make_netns_output_flag_probe,
    make_netns_output_ipv4_pure_ack_probe,
    parse_guest_json,
    read_module_stats,
    received_messages,
    require_guest_command,
    run_in_netns,
    run_netns_scenario,
    spawn_netns_scenario,
    spawn_ready_capture,
    wait_for_guest_ready_file,
    wait_for_stat_greater,
    write_guest_text,
)


def test_liveness_timeout_recovers(phantun_module, vm):
    load_fast_liveness_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]

    server = spawn_netns_scenario(
        vm,
        NS_B,
        "echo_server",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 2,
            # The test blocks traffic well past the 3s liveness deadline
            # (1s interval * (2 misses + 1)). The default 5s socket timeout in the
            # guest scenario runner is too tight and causes the server to crash
            # before the second payload arrives.
            "timeout_sec": 20,
        },
    )
    keepalive_probe = None
    drop_probe = None
    try:
        time.sleep(0.2)
        client_result_1 = run_netns_scenario(
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
        assert_completed(client_result_1, "client send 1")

        keepalive_probe = make_netns_output_flag_probe(
            vm,
            NS_A,
            [
                {
                    "src_addr": NS_ADDR_A,
                    "dst_addr": NS_ADDR_B,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "flags_expr": "rst",
                    "comment": "liveness_rst",
                },
            ],
        )
        baseline_rst = keepalive_probe.packets(vm, "liveness_rst")
        baseline_stats = read_module_stats(vm)
        baseline_rst_sent = baseline_stats["rst_sent"]
        baseline_liveness_timeouts = baseline_stats["established_liveness_timeouts"]
        drop_probe = make_netns_ingress_drop_probe(
            vm,
            NS_A,
            VETH_A,
            [
                {
                    "src_addr": NS_ADDR_B,
                    "dst_addr": NS_ADDR_A,
                    "src_port": dst_port,
                    "dst_port": src_port,
                    "comment": "drop_inbound_fake_tcp",
                }
            ],
        )

        # The 3s liveness deadline is driven by delayed GC work. Poll for the
        # contract change instead of sleeping a fixed interval: once local
        # liveness fails, the old generation should emit at least one RST before
        # recovery opens a replacement generation.
        deadline = time.time() + 8.0
        rst_packets = 0
        while time.time() < deadline:
            rst_packets = keepalive_probe.packets(vm, "liveness_rst") - baseline_rst
            if rst_packets > 0:
                break
            time.sleep(0.1)

        if rst_packets <= 0:
            pytest.fail("expected local RST after liveness teardown, got none")
        stats_after_liveness = read_module_stats(vm)
        rst_sent = stats_after_liveness["rst_sent"] - baseline_rst_sent
        if rst_sent <= 0:
            pytest.fail(f"expected rst_sent to increase after liveness teardown, got {rst_sent}")
        liveness_timeouts = stats_after_liveness["established_liveness_timeouts"] - baseline_liveness_timeouts
        if liveness_timeouts <= 0:
            pytest.fail(
                "expected established_liveness_timeouts to increase after liveness teardown, "
                f"got {stats_after_liveness!r}"
            )

        drop_probe.cleanup(vm)
        drop_probe = None

        client_result_2 = run_netns_scenario(
            vm,
            NS_A,
            "echo_client",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["msg2"],
            },
        )
        assert_completed(client_result_2, "client send 2")

        server_result = server.communicate(timeout=15)
        assert_completed(server_result, "server")
        server_data = parse_guest_json(server_result.stdout, "server stdout")
        if received_messages(server_data) != ["msg1", "msg2"]:
            pytest.fail(f"unexpected messages received by server: {received_messages(server_data)!r}")
    finally:
        if keepalive_probe is not None:
            keepalive_probe.cleanup(vm)
        if drop_probe is not None:
            drop_probe.cleanup(vm)
        vm.run(["ip", "netns", "exec", NS_A, "nft", "flush", "ruleset"], check=False)


def test_liveness_reinitiates_flow_with_queued_packet(phantun_module, vm):
    load_fast_liveness_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    probe_b = make_netns_ingress_drop_probe(
        vm,
        NS_B,
        VETH_B,
        [
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "comment": "drop all fake tcp",
            }
        ],
    )
    initial_stats = read_module_stats(vm)

    # Spawn a client that will hang sending msg1 because it gets no replies
    client = spawn_netns_scenario(
        vm,
        NS_A,
        "echo_client",
        {
            "bind_addr": NS_ADDR_A,
            "bind_port": src_port,
            "target_addr": NS_ADDR_B,
            "target_port": dst_port,
            "payloads": ["msg1"],
            "timeout_sec": 20,
        },
    )

    try:
        time.sleep(0.5)
        stats_after_first_syn = read_module_stats(vm)
        flows_created_1 = stats_after_first_syn["flows_created"] - initial_stats["flows_created"]
        if flows_created_1 != 1:
            pytest.fail(f"expected 1 flow created (1 initiator), got {flows_created_1}")

        # The flow is created at t=0.
        # Retransmits happen at t=1s, 2s, 3s, 4s...
        # Liveness timeout happens at t=3s. When liveness timeout occurs, the queued UDP
        # packet is reinjected, creating a new flow.
        # Since VM time can drift or be delayed relative to host time, poll the stats
        # for up to 10 seconds (20 iterations of 0.5s).
        success = False
        for _ in range(20):
            time.sleep(0.5)
            stats_after_liveness = read_module_stats(vm)
            flows_created_2 = stats_after_liveness["flows_created"] - stats_after_first_syn["flows_created"]
            if flows_created_2 >= 2:
                success = True
                break

        if not success:
            pytest.fail(f"expected flow to be re-initiated 2 times due to liveness, got {flows_created_2}")

        rst_sent = stats_after_liveness["rst_sent"] - initial_stats["rst_sent"]
        if rst_sent != 0:
            pytest.fail(f"half-open liveness reinitiation must not emit RST before retry exhaustion, got {rst_sent}")
    finally:
        probe_b.cleanup(vm)
        vm.run(["ip", "netns", "exec", NS_A, "nft", "flush", "ruleset"], check=False)


def test_netns_recent_bidirectional_payload_suppresses_idle_ack(phantun_module, vm):
    load_managed_module(phantun_module)
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

        write_guest_text(vm, send_reply, "ready\n")
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

        write_guest_text(vm, send_delayed, "ready\n")
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


@contextmanager
def _liveness_echo_pair(vm, addr_a=NS_ADDR_A, addr_b=NS_ADDR_B, echo_count=100000):
    ready = f"/tmp/phantun-liveness-{uuid.uuid4().hex}"
    server = spawn_netns_scenario(
        vm, NS_B, "echo_server",
        {"bind_addr": addr_b, "bind_port": PORTS_B[0], "count": 100000,
         "timeout_sec": 60, "ready_file": ready, "echo_count": echo_count},
    )
    client = {
        "bind_addr": addr_a, "bind_port": PORTS_A[0],
        "target_addr": addr_b, "target_port": PORTS_B[0],
    }
    try:
        wait_for_guest_ready_file(vm, ready)
        result = run_netns_scenario(vm, NS_A, "echo_client", {**client, "payloads": ["open"]})
        assert_completed(result, "liveness initial echo")
        assert parse_guest_json(result.stdout, "initial echo")["echoed"] == ["open"]
        yield client
    finally:
        if server.proc.poll() is None:
            server.terminate()


def _liveness_flag_probe(vm, namespace, src_addr, dst_addr, src_port, dst_port, action="accept"):
    return make_netns_output_flag_probe(vm, namespace, [{
        "src_addr": src_addr, "dst_addr": dst_addr,
        "src_port": src_port, "dst_port": dst_port,
        "flags_expr": "ack", "action": action, "comment": "liveness_ack",
    }])


def _liveness_window(vm, probe, **kwargs):
    result = run_netns_scenario(vm, probe.namespace, "liveness_window", {
        "family": probe.family, "table_name": probe.table_name,
        "chain_name": probe.chain_name, **kwargs,
    })
    assert_completed(result, "guest liveness observation")
    return parse_guest_json(result.stdout, "guest liveness observation")


def _healthy_idle_survives(phantun_module, vm, ipv6, misses, phase, shaping):
    if not require_guest_command(vm, "nft"):
        pytest.skip("nft is not available in the guest")
    load_managed_module(
        phantun_module, keepalive_interval_sec=1, keepalive_misses=misses,
        hard_idle_timeout_sec=60,
        **({"handshake_request": REQ, "handshake_response": RESP} if shaping else {}),
    )
    ensure_netns_topology(vm, with_ipv6=ipv6, namespace_delay_sec=phase)
    addr_a, addr_b = (NS6_ADDR_A, NS6_ADDR_B) if ipv6 else (NS_ADDR_A, NS_ADDR_B)
    probes = []
    try:
        for namespace, src, dst, sport, dport in (
            (NS_A, addr_a, addr_b, PORTS_A[0], PORTS_B[0]),
            (NS_B, addr_b, addr_a, PORTS_B[0], PORTS_A[0]),
        ):
            probes.append(_liveness_flag_probe(vm, namespace, src, dst, sport, dport))
        with _liveness_echo_pair(vm, addr_a, addr_b) as client:
            before = read_module_stats(vm)
            ack_before = [probe.packets(vm, "liveness_ack") for probe in probes]
            # Use guest elapsed time, spanning at least three silence timeouts.
            vm.run(["sleep", str(3 * (misses + 1))])
            idle = read_module_stats(vm)
            assert idle["flows_current"] == before["flows_current"] == 2
            assert idle["established_liveness_timeouts"] == before["established_liveness_timeouts"]
            assert idle["rst_sent"] == before["rst_sent"]
            for probe, count in zip(probes, ack_before):
                assert probe.packets(vm, "liveness_ack") - count >= 2
            result = run_netns_scenario(
                vm, NS_A, "echo_client", {**client, "payloads": ["after-idle"]},
            )
            assert_completed(result, "echo after multiple idle timeouts")
            assert parse_guest_json(result.stdout, "post-idle echo")["echoed"] == ["after-idle"]
            after = read_module_stats(vm)
            assert after["flows_created"] == before["flows_created"]
            assert after["flows_established"] == before["flows_established"]
    finally:
        for probe in probes:
            probe.cleanup(vm)
        cleanup_netns_topology(vm)


@pytest.mark.parametrize("misses,phase,shaping", [(1, 0, False), (1, 0.25, True), (3, 0.25, False)])
def test_healthy_idle_survives_multiple_timeouts(phantun_module, vm, misses, phase, shaping):
    _healthy_idle_survives(phantun_module, vm, False, misses, phase, shaping)


@pytest.mark.usefixtures("ipv6_runtime")
@pytest.mark.parametrize("misses,phase,shaping", [(1, 0, False), (1, 0.25, True), (3, 0.25, False)])
def test_ipv6_healthy_idle_survives_multiple_timeouts(phantun_module, vm, misses, phase, shaping):
    _healthy_idle_survives(phantun_module, vm, True, misses, phase, shaping)


@pytest.mark.parametrize("pmtu_failure", [False, True], ids=["successful-payload", "failed-payload"])
def test_probe_deadline_tracks_actual_payload_output(phantun_module, vm, pmtu_failure):
    if not require_guest_command(vm, "nft"):
        pytest.skip("nft is not available in the guest")
    load_managed_module(phantun_module, keepalive_interval_sec=1, keepalive_misses=20)
    ensure_netns_topology(vm)
    probe = make_netns_output_ipv4_pure_ack_probe(
        vm, NS_A, NS_ADDR_A, PORTS_A[0], NS_ADDR_B, PORTS_B[0],
    )
    try:
        with _liveness_echo_pair(vm, echo_count=1) as client:
            if pmtu_failure:
                # UDP still reaches the translator; fake TCP fails its routed
                # MTU check. Its public UDP send wrapper consumes that failure.
                run_in_netns(vm, NS_A, ["ip", "link", "set", VETH_A, "mtu", "1300"])
                run_in_netns(vm, NS_A, [
                    "ip", "route", "replace", f"{NS_ADDR_B}/32", "dev", VETH_A,
                    "mtu", "lock", "1300",
                ])
            observed = _liveness_window(
                vm, probe, **client, duration_sec=5.5,
                payload="X" * 1350 if pmtu_failure else "cached-payload",
                warmup=not pmtu_failure, period_ms=100,
            )
            before, after = observed["before"], observed["after"]
            probes = after["packets"]["pure_ipv4_ack"] - before["packets"]["pure_ipv4_ack"]
            assert observed["sent"] >= 10, observed
            assert after["stats"]["flows_created"] == before["stats"]["flows_created"]
            assert after["stats"]["established_liveness_timeouts"] == before["stats"]["established_liveness_timeouts"]
            if pmtu_failure:
                assert after["stats"]["oversized_payloads_dropped"] - before["stats"]["oversized_payloads_dropped"] == observed["sent"]
                assert 3 <= probes <= floor(observed["elapsed_sec"]) + 1, observed
            else:
                # B ACKs this one-way stream without sending payload, so A
                # owes no payload ACKs that could obscure the probe count.
                assert observed["max_send_gap_sec"] < 1, observed
                assert probes == 0, observed
                assert after["stats"]["route_cache_hits"] > before["stats"]["route_cache_hits"]
    finally:
        probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_keepalive_output_failures_are_paced_despite_continuing_rx(phantun_module, vm):
    if not require_guest_command(vm, "nft"):
        pytest.skip("nft is not available in the guest")
    load_managed_module(phantun_module, keepalive_interval_sec=1, keepalive_misses=20)
    ensure_netns_topology(vm)
    capture = spawn_ready_capture(vm, NS_A, {
        "bind_addr": NS_ADDR_B, "bind_port": PORTS_B[0],
        "target_addr": NS_ADDR_A, "target_port": PORTS_A[0], "payload": "open",
    })
    probe = None
    sender = None
    prefix = f"/tmp/phantun-liveness-rx-{uuid.uuid4().hex}"
    sender_ready, sender_stop = f"{prefix}-ready", f"{prefix}-stop"
    try:
        with _liveness_echo_pair(vm):
            captured = capture.communicate(timeout=10)
            assert_completed(captured, "liveness peer packet capture")
            packet = parse_guest_json(captured.stdout, "liveness captured peer packet")
            probe = _liveness_flag_probe(
                vm, NS_A, NS_ADDR_A, NS_ADDR_B, PORTS_A[0], PORTS_B[0], action="drop",
            )
            # Repeated valid pure ACK RX must neither answer with an ACK nor
            # move A's probe deadline. OUTPUT drops exercise local failure,
            # rather than successful sends subsequently lost on ingress.
            ack = {
                "bind_addr": NS_ADDR_B, "bind_port": PORTS_B[0],
                "target_addr": NS_ADDR_A, "target_port": PORTS_A[0],
                "seq": (packet["seq"] + len("open")) & 0xFFFFFFFF,
                "ack": packet["ack"], "flags": "ack",
            }
            sender = spawn_netns_scenario(
                vm, NS_B, "send_tcp_packets",
                {"packets": [ack] * 600, "delay_ms": 100,
                 "ready_file": sender_ready, "stop_file": sender_stop},
            )
            wait_for_guest_ready_file(vm, sender_ready)
            observed = _liveness_window(vm, probe, duration_sec=5.5)
            write_guest_text(vm, sender_stop, "stop\n")
            sent = sender.communicate(timeout=10)
            assert_completed(sent, "continuous peer ACK sender")
            assert parse_guest_json(sent.stdout, "continuous peer ACK sender")["sent"] >= 20
            before, after = observed["before"], observed["after"]
            attempts = after["packets"]["liveness_ack"] - before["packets"]["liveness_ack"]
            assert 3 <= attempts <= floor(observed["elapsed_sec"]) + 1, observed
            assert after["stats"]["flows_current"] == before["stats"]["flows_current"] == 2
            assert after["stats"]["rst_sent"] == before["stats"]["rst_sent"]
    finally:
        if sender is not None and sender.proc.poll() is None:
            write_guest_text(vm, sender_stop, "stop\n")
        for process in (capture, sender):
            if process is not None and process.proc.poll() is None:
                process.terminate()
        if probe is not None:
            probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_successful_payload_output_cannot_hide_inbound_loss(phantun_module, vm):
    if not require_guest_command(vm, "nft"):
        pytest.skip("nft is not available in the guest")
    load_fast_liveness_module(phantun_module)
    ensure_netns_topology(vm)
    probe = _liveness_flag_probe(vm, NS_A, NS_ADDR_A, NS_ADDR_B, PORTS_A[0], PORTS_B[0])
    drop = None
    try:
        with _liveness_echo_pair(vm) as client:
            drop = make_netns_ingress_drop_probe(vm, NS_A, VETH_A, [{
                "src_addr": NS_ADDR_B, "dst_addr": NS_ADDR_A,
                "src_port": PORTS_B[0], "dst_port": PORTS_A[0],
                "comment": "inbound_loss",
            }])
            observed = _liveness_window(
                vm, probe, **client, duration_sec=8, payload="still-transmitting",
                period_ms=100, stop_on_liveness_timeout=True,
            )
            before, after = observed["before"], observed["after"]
            assert after["packets"]["liveness_ack"] - before["packets"]["liveness_ack"] >= 5, observed
            assert drop.packets(vm, "inbound_loss") >= 5
            assert after["stats"]["established_liveness_timeouts"] > before["stats"]["established_liveness_timeouts"], observed
            # Timeout accounting precedes the unlocked best-effort RST.
            wait_for_stat_greater(vm, "rst_sent", before["stats"]["rst_sent"])
    finally:
        if drop is not None:
            drop.cleanup(vm)
        probe.cleanup(vm)
        cleanup_netns_topology(vm)
