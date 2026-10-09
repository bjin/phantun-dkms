"""Half-open handshakes: SYN/SYN|ACK loss retries, retry exhaustion, half-open limits, SYN_SENT queueing."""

import time
import uuid

import pytest

from helpers import (
    MANAGED_LOCAL_PORTS,
    NS6_ADDR_A,
    NS6_ADDR_B,
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
    load_managed_module,
    make_netns_ingress_flag_drop_probe,
    make_netns_output_flag_probe,
    make_netns_output_probe,
    parse_guest_json,
    probe_comment,
    read_module_stats,
    received_messages,
    require_guest_command,
    require_nft_or_skip,
    run_netns_scenario,
    run_ping_pong,
    spawn_netns_scenario,
    spawn_ready_recv_until_timeout,
    wait_for_stat_greater,
    wait_for_guest_ready_file,
)


def count_nonzero_probe_hits(vm, probe, comments):
    return sum(1 for comment in comments if probe.packets(vm, comment) > 0)


def wait_for_half_open_drain(vm, baseline_stats, expected_rst, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        stats = read_module_stats(vm)
        if (
            stats["rst_sent"] - baseline_stats["rst_sent"] >= expected_rst
            and stats["flows_current"] == baseline_stats["flows_current"]
        ):
            return stats
        time.sleep(0.1)

    pytest.fail(
        "half-open flows did not drain back to baseline: "
        f"baseline={baseline_stats!r} current={stats!r} expected_rst={expected_rst}"
    )


def test_syn_loss_is_retried(phantun_module, vm):
    load_managed_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    probe = make_netns_ingress_flag_drop_probe(
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
                "comment": "drop_syn",
            }
        ],
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
        client = spawn_netns_scenario(
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
        time.sleep(1.25)
        probe.cleanup(vm)

        client_result = client.communicate(timeout=12)
        server_result = server.communicate(timeout=12)
        assert_completed(client_result, "syn-loss client")
        assert_completed(server_result, "syn-loss server")

        client_data = parse_guest_json(client_result.stdout, "syn-loss client stdout")
        server_data = parse_guest_json(server_result.stdout, "syn-loss server stdout")
        if client_data.get("reply") != "pong":
            pytest.fail(f"unexpected client reply after SYN loss: {client_data.get('reply')!r}")
        if server_data.get("received") != "ping":
            pytest.fail(f"unexpected server payload after SYN loss: {server_data.get('received')!r}")
    finally:
        probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_synack_loss_is_retried(phantun_module, vm):
    load_managed_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    initial_stats = read_module_stats(vm)
    probe = make_netns_ingress_flag_drop_probe(
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
                "comment": "drop_synack",
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
                "comment": "sent_synack",
            }
        ],
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
        baseline_synack = synack_probe.packets(vm, "sent_synack")
        client = spawn_netns_scenario(
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
        time.sleep(1.25)
        probe.cleanup(vm)

        client_result = client.communicate(timeout=12)
        server_result = server.communicate(timeout=12)
        assert_completed(client_result, "synack-loss client")
        assert_completed(server_result, "synack-loss server")

        client_data = parse_guest_json(client_result.stdout, "synack-loss client stdout")
        server_data = parse_guest_json(server_result.stdout, "synack-loss server stdout")
        if client_data.get("reply") != "pong":
            pytest.fail(f"unexpected client reply after SYN|ACK loss: {client_data.get('reply')!r}")
        if server_data.get("received") != "ping":
            pytest.fail(f"unexpected server payload after SYN|ACK loss: {server_data.get('received')!r}")
        if synack_probe.packets(vm, "sent_synack") <= baseline_synack + 1:
            pytest.fail("expected responder to re-send SYN|ACK after initiator re-sent SYN")

        final_stats = read_module_stats(vm)
        if final_stats["flows_created"] - initial_stats["flows_created"] != 2:
            pytest.fail(f"duplicate SYN after lost SYN|ACK should not create extra flows: {final_stats!r}")
    finally:
        probe.cleanup(vm)
        synack_probe.cleanup(vm)
        cleanup_netns_topology(vm)


@pytest.mark.usefixtures("ipv6_runtime")
def test_ipv6_synack_loss_is_retried(phantun_module, vm):
    load_managed_module(phantun_module)
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


def test_half_open_retry_exhaustion_releases_flow_slot(phantun_module, vm):
    phantun_module.load(
        managed_netns="all",
        managed_local_ports=MANAGED_LOCAL_PORTS,
        handshake_timeout_ms=200,
        handshake_retries=1,
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
                "comment": "drop_exhausted_synack",
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
                "comment": "sent_exhausted_synack",
            }
        ],
    )
    baseline_stats = read_module_stats(vm)
    baseline_synack = synack_probe.packets(vm, "sent_exhausted_synack")

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

        # On slow nested-QEMU CI the responder half-open may be created and
        # exhausted between host-side polls. Assert on cumulative counters and
        # the emitted SYN|ACK instead of a transient flows_current spike.
        stats = wait_for_half_open_drain(vm, baseline_stats, expected_rst=1)

        if synack_probe.packets(vm, "sent_exhausted_synack") <= baseline_synack:
            pytest.fail("expected responder to emit SYN|ACK before retry exhaustion")

        if stats["flows_created"] <= baseline_stats["flows_created"]:
            pytest.fail(
                "expected responder half-open flow creation before retry exhaustion: "
                f"baseline={baseline_stats!r} current={stats!r}"
            )
        if stats["handshake_retries_exhausted"] <= baseline_stats["handshake_retries_exhausted"]:
            pytest.fail(f"expected handshake_retries_exhausted to increase, got {stats!r}")
    finally:
        drop_synack.cleanup(vm)
        synack_probe.cleanup(vm)
        cleanup_netns_topology(vm)


@pytest.mark.parametrize("limit, remote_limit", [(1, 1), (2, 1), (4, 3)])
def test_responder_half_open_limit_rejects_excess_bare_syns(phantun_module, vm, limit, remote_limit):
    phantun_module.load(
        managed_netns="all",
        managed_local_ports=MANAGED_LOCAL_PORTS,
        half_open_limit=limit,
        handshake_timeout_ms=2000,
        handshake_retries=1,
    )
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    dst_port = PORTS_B[0]
    source_ports = [41001, 41002, 41003, 41004, 41005]
    synack_comments = [f"limited_synack_{port}" for port in source_ports]
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
                "flags_expr": "syn | ack",
                "comment": f"drop_limited_synack_{src_port}",
            }
            for src_port in source_ports
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
                "comment": f"limited_synack_{src_port}",
            }
            for src_port in source_ports
        ],
    )
    baseline_stats = read_module_stats(vm)

    try:
        run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packets",
            {
                "packets": [
                    {
                        "bind_addr": NS_ADDR_A,
                        "bind_port": src_port,
                        "target_addr": NS_ADDR_B,
                        "target_port": dst_port,
                        "flags": "syn",
                        "seq": 4095 * index,
                    }
                    for index, src_port in enumerate(source_ports[:4], start=1)
                ]
            },
        )

        deadline = time.time() + 5
        while time.time() < deadline:
            stats = read_module_stats(vm)
            rejected = stats["half_open_rejected"] - baseline_stats["half_open_rejected"]
            admitted = count_nonzero_probe_hits(vm, synack_probe, synack_comments)
            if rejected == 4 - remote_limit and admitted == remote_limit:
                break
            time.sleep(0.1)
        else:
            pytest.fail(
                "responder half-open limit did not reject excess bare SYNs: " f"stats={stats!r} admitted={admitted}"
            )

        wait_for_half_open_drain(vm, baseline_stats, expected_rst=remote_limit)

        run_netns_scenario(
            vm,
            NS_A,
            "send_tcp_packet",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": source_ports[4],
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "flags": "syn",
                "seq": 4095 * 5,
            },
        )

        deadline = time.time() + 5
        while time.time() < deadline:
            stats = read_module_stats(vm)
            admitted = count_nonzero_probe_hits(vm, synack_probe, synack_comments)
            rejected = stats["half_open_rejected"] - baseline_stats["half_open_rejected"]
            if admitted == remote_limit + 1 and rejected == 4 - remote_limit:
                break
            time.sleep(0.1)
        else:
            pytest.fail(
                "responder half-open slot should reopen after retry exhaustion: " f"stats={stats!r} admitted={admitted}"
            )
    finally:
        drop_synack.cleanup(vm)
        synack_probe.cleanup(vm)
        cleanup_netns_topology(vm)


@pytest.mark.parametrize("limit", [1, 2])
def test_initiator_half_open_limit_rejects_excess_udp(phantun_module, vm, limit):
    phantun_module.load(
        managed_netns="all",
        managed_local_ports=MANAGED_LOCAL_PORTS,
        half_open_limit=limit,
        handshake_timeout_ms=2000,
        handshake_retries=1,
    )
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    remote_ports = [PORTS_B[0], PORTS_B[1], 6666, 6667, 6668]
    syn_comments = [f"limited_syn_{port}" for port in remote_ports]
    # Isolate local admission: no peer responder charge/rejection contributes
    # to the module-wide counters.
    drop_syn = make_netns_ingress_flag_drop_probe(
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
                "comment": f"drop_limited_syn_{dst_port}",
            }
            for dst_port in remote_ports
        ],
    )
    syn_probe = make_netns_output_flag_probe(
        vm,
        NS_A,
        [
            {
                "src_addr": NS_ADDR_A,
                "dst_addr": NS_ADDR_B,
                "src_port": src_port,
                "dst_port": dst_port,
                "flags_expr": "syn",
                "comment": f"limited_syn_{dst_port}",
            }
            for dst_port in remote_ports
        ],
    )
    baseline_stats = read_module_stats(vm)

    try:
        for dst_port in remote_ports[:4]:
            run_netns_scenario(
                vm,
                NS_A,
                "send_many",
                {
                    "bind_addr": NS_ADDR_A,
                    "bind_port": src_port,
                    "target_addr": NS_ADDR_B,
                    "target_port": dst_port,
                    "payloads": [f"payload-{dst_port}"],
                },
            )

        deadline = time.time() + 5
        while time.time() < deadline:
            stats = read_module_stats(vm)
            rejected = stats["half_open_rejected"] - baseline_stats["half_open_rejected"]
            dropped = stats["udp_packets_dropped"] - baseline_stats["udp_packets_dropped"]
            admitted = count_nonzero_probe_hits(vm, syn_probe, syn_comments)
            if rejected == 4 - limit and dropped == 4 - limit and admitted == limit:
                break
            time.sleep(0.1)
        else:
            pytest.fail(
                "initiator half-open limit did not reject excess outbound UDP: " f"stats={stats!r} admitted={admitted}"
            )

        wait_for_half_open_drain(vm, baseline_stats, expected_rst=limit)

        run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": remote_ports[4],
                "payloads": ["payload-reopen"],
            },
        )

        deadline = time.time() + 5
        while time.time() < deadline:
            stats = read_module_stats(vm)
            admitted = count_nonzero_probe_hits(vm, syn_probe, syn_comments)
            rejected = stats["half_open_rejected"] - baseline_stats["half_open_rejected"]
            if admitted == limit + 1 and rejected == 4 - limit:
                break
            time.sleep(0.1)
        else:
            pytest.fail(
                "initiator half-open slot should reopen after retry exhaustion: " f"stats={stats!r} admitted={admitted}"
            )
    finally:
        drop_syn.cleanup(vm)
        syn_probe.cleanup(vm)
        cleanup_netns_topology(vm)


@pytest.mark.parametrize("limit", [1, 2])
def test_half_open_completion_releases_both_origin_slots(phantun_module, vm, limit):
    load_managed_module(phantun_module, half_open_limit=limit)
    ensure_netns_topology(vm)
    try:
        baseline = read_module_stats(vm)
        # Two distinct tuples must finish even when there is only one remote
        # slot. This checks both the initiator and responder completion release.
        for src_port, dst_port in zip(PORTS_A, PORTS_B):
            run_ping_pong(vm, NS_ADDR_A, NS_ADDR_B, src_port, dst_port)
        stats = read_module_stats(vm)
        assert stats["flows_established"] - baseline["flows_established"] == 4
        assert stats["half_open_rejected"] == baseline["half_open_rejected"]
    finally:
        cleanup_netns_topology(vm)


def test_duplicate_outbound_udp_while_half_open_queues_only_one_skb(phantun_module, vm):
    load_managed_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    initial_stats = read_module_stats(vm)
    probe = make_netns_ingress_flag_drop_probe(
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
                "comment": "drop_synack",
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
        },
    )

    try:
        time.sleep(0.2)
        client = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["client-0", "client-1"],
            },
        )
        time.sleep(1.25)
        probe.cleanup(vm)
        server_result = server.communicate(timeout=12)
        assert_completed(client, "duplicate-half-open sender")
        assert_completed(server_result, "duplicate-half-open receiver")

        server_data = parse_guest_json(server_result.stdout, "duplicate-half-open server stdout")
        if received_messages(server_data) != ["client-0"]:
            pytest.fail(f"expected only the first half-open payload to survive, got {received_messages(server_data)!r}")

        final_stats = read_module_stats(vm)
        if final_stats["flows_created"] - initial_stats["flows_created"] != 2:
            pytest.fail(f"expected one initiator and one responder flow, got {final_stats!r}")
        if final_stats["udp_packets_queued"] - initial_stats["udp_packets_queued"] != 1:
            pytest.fail(f"expected exactly one queued UDP packet while half-open, got {final_stats!r}")
        if final_stats["udp_packets_dropped"] <= initial_stats["udp_packets_dropped"]:
            pytest.fail(f"expected later duplicate UDP during half-open to be dropped, got {final_stats!r}")
        if final_stats["udp_queue_full_dropped"] <= initial_stats["udp_queue_full_dropped"]:
            pytest.fail(f"expected later duplicate UDP to count as queue-full drop, got {final_stats!r}")
    finally:
        probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_cold_start_udp_gso_superframe_queues_only_first_segment(phantun_module, vm):
    load_managed_module(phantun_module)
    ensure_netns_topology(vm)

    if not require_guest_command(vm, "nft"):
        cleanup_netns_topology(vm)
        pytest.skip("nft is not available in the guest")

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    chunks = [c * 1000 for c in "ABCD"]
    sentinel = "after-handshake"
    ready_file = f"/tmp/phantun-gso-half-open-{uuid.uuid4().hex}"
    first_received_file = f"/tmp/phantun-gso-first-received-{uuid.uuid4().hex}"
    # Hold the initiator in SYN_SENT: on veth the handshake can otherwise
    # complete inside the first segment's send, before the rest of the
    # superframe is translated.
    synack_drop = make_netns_ingress_flag_drop_probe(
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
                "comment": "drop_synack",
            }
        ],
    )
    raw_probe = make_netns_output_probe(vm, NS_A, [(NS_ADDR_A, src_port, NS_ADDR_B, dst_port)])
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
            "first_received_file": first_received_file,
        },
    )

    try:
        wait_for_guest_ready_file(vm, ready_file, timeout=5)
        baseline_stats = read_module_stats(vm)
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
        assert_completed(gso, "cold-start UDP GSO sender")

        # The superframe is split inside sendto(), so every datagram has been
        # queued or dropped by now: one fills the half-open queue and the rest
        # are queue-full drops.
        half_open_stats = read_module_stats(vm)
        queued = half_open_stats["udp_packets_queued"] - baseline_stats["udp_packets_queued"]
        queue_full = half_open_stats["udp_queue_full_dropped"] - baseline_stats["udp_queue_full_dropped"]
        if queued != 1 or queue_full != len(chunks) - 1:
            pytest.fail(
                f"expected 1 queued and {len(chunks) - 1} queue-full GSO segments while half-open: "
                f"before={baseline_stats!r} after={half_open_stats!r}"
            )

        synack_drop.cleanup(vm)
        # Barrier on the application itself: the flow counters advance before
        # the opening payload is reinjected, so they do not prove delivery.
        wait_for_guest_ready_file(vm, first_received_file, timeout=10)
        after = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": [sentinel],
            },
        )
        assert_completed(after, "post-handshake sentinel sender")

        server_result = server.communicate(timeout=20)
        assert_completed(server_result, "cold-start UDP GSO receiver")
        server_data = parse_guest_json(server_result.stdout, "cold-start UDP GSO receiver stdout")
        # The sentinel is only sent after the receiver reported the first
        # segment, so any other segment the flow emitted for the superframe
        # would precede it.
        if received_messages(server_data) != [chunks[0], sentinel]:
            pytest.fail(f"unexpected payloads after cold-start GSO superframe: {received_messages(server_data)!r}")
        if raw_probe.packets(vm, probe_comment("udp", NS_ADDR_A, src_port, NS_ADDR_B, dst_port)) != 0:
            pytest.fail("cold-start GSO segment escaped LOCAL_OUT as raw UDP")
    finally:
        synack_drop.cleanup(vm)
        raw_probe.cleanup(vm)
        if server.proc.poll() is None:
            server.terminate()
        vm.run(["rm", "-f", first_received_file], check=False)
        cleanup_netns_topology(vm)


@pytest.mark.parametrize("flags", ["ack", "ack|psh"])
def test_stale_half_open_traffic_preserves_queued_udp(phantun_module, vm, flags):
    load_managed_module(phantun_module, handshake_timeout_ms=500, handshake_retries=120)
    ensure_netns_topology(vm)
    require_nft_or_skip(vm)
    src_port, dst_port = PORTS_A[0], PORTS_B[0]
    drop = make_netns_ingress_flag_drop_probe(
        vm, NS_A, VETH_A,
        [{
            "src_addr": NS_ADDR_B, "src_port": dst_port,
            "dst_addr": NS_ADDR_A, "dst_port": src_port,
            "flags_expr": "syn | ack", "comment": "hold_fresh_handshake",
        }],
    )
    stop_file = f"/tmp/phantun-stale-half-open-stop-{uuid.uuid4().hex}"
    receiver = spawn_ready_recv_until_timeout(
        vm, NS_B,
        {
            "bind_addr": NS_ADDR_B, "bind_port": dst_port,
            "count": 3, "timeout_sec": 60, "stop_file": stop_file,
        },
    )
    baseline = read_module_stats(vm)
    try:
        sent = run_netns_scenario(
            vm, NS_A, "send_many",
            {
                "bind_addr": NS_ADDR_A, "bind_port": src_port,
                "target_addr": NS_ADDR_B, "target_port": dst_port,
                "payloads": ["queued"],
            },
        )
        assert_completed(sent, "queued recovery datagram")
        held = wait_for_stat_greater(vm, "flows_created", baseline["flows_created"] + 1)
        assert held["flows_current"] == baseline["flows_current"] + 2
        # The dropped SYNACK leaves A in SYN_SENT and B in SYN_RCVD.
        for namespace, addr, port, peer, peer_port in (
            (NS_A, NS_ADDR_A, src_port, NS_ADDR_B, dst_port),
            (NS_B, NS_ADDR_B, dst_port, NS_ADDR_A, src_port),
        ):
            stale = run_netns_scenario(
                vm, namespace, "send_tcp_packets",
                {"packets": [
                    {
                        "bind_addr": addr, "bind_port": port,
                        "target_addr": peer, "target_port": peer_port,
                        "flags": flags, "seq": 123456, "ack": 0, "payload": payload,
                    }
                    for payload in ("", "old-data", "old-data")
                ]},
            )
            assert_completed(stale, "old ACK/data in half-open state")
        retained = read_module_stats(vm)
        for counter in ("rst_sent", "tcp_protocol_rejected", "flows_established", "flows_created"):
            assert retained[counter] == held[counter], (counter, held, retained)
        assert retained["flows_current"] == held["flows_current"]
        drop.cleanup(vm)
        wait_for_stat_greater(vm, "flows_established", baseline["flows_established"] + 1)
        # A post-completion datagram is a delivery-order barrier for the queue.
        sent = run_netns_scenario(
            vm, NS_A, "send_many",
            {
                "bind_addr": NS_ADDR_A, "bind_port": src_port,
                "target_addr": NS_ADDR_B, "target_port": dst_port, "payloads": ["after"],
            },
        )
        assert_completed(sent, "post-recovery barrier")
        vm.run(["touch", stop_file])
        result = receiver.communicate(timeout=10)
        assert_completed(result, "recovery receiver")
        assert received_messages(parse_guest_json(result.stdout, "recovery receiver")) == ["queued", "after"]
        assert read_module_stats(vm)["udp_packets_queued"] == baseline["udp_packets_queued"] + 1
    finally:
        drop.cleanup(vm)
        if receiver.proc.poll() is None:
            receiver.terminate()
        vm.run(["rm", "-f", stop_file], check=False)
        cleanup_netns_topology(vm)


@pytest.mark.parametrize("state", ["syn_sent", "syn_rcvd"])
def test_stale_data_does_not_extend_half_open_timeout(phantun_module, vm, state):
    load_managed_module(phantun_module, handshake_timeout_ms=200, handshake_retries=5)
    ensure_netns_topology(vm)
    require_nft_or_skip(vm)
    src_port, dst_port = PORTS_A[0], PORTS_B[0]
    initiator = state == "syn_sent"
    drop = make_netns_ingress_flag_drop_probe(
        vm, NS_B if initiator else NS_A, VETH_B if initiator else VETH_A,
        [{
            "src_addr": NS_ADDR_A if initiator else NS_ADDR_B,
            "src_port": src_port if initiator else dst_port,
            "dst_addr": NS_ADDR_B if initiator else NS_ADDR_A,
            "dst_port": dst_port if initiator else src_port,
            "flags_expr": "syn" if initiator else "syn | ack",
            "comment": "hold_timeout_handshake",
        }],
    )
    baseline = read_module_stats(vm)
    try:
        opener = {
            "bind_addr": NS_ADDR_A, "bind_port": src_port,
            "target_addr": NS_ADDR_B, "target_port": dst_port,
        }
        if initiator:
            opened = run_netns_scenario(vm, NS_A, "send_many", {**opener, "payloads": ["queued"]})
        else:
            opened = run_netns_scenario(vm, NS_A, "send_tcp_packet", {**opener, "flags": "syn", "seq": 4095})
        assert_completed(opened, "timeout opener")
        stray = {
            "bind_addr": NS_ADDR_B if initiator else NS_ADDR_A,
            "bind_port": dst_port if initiator else src_port,
            "target_addr": NS_ADDR_A if initiator else NS_ADDR_B,
            "target_port": src_port if initiator else dst_port,
            "flags": "ack|psh", "seq": 123456, "ack": 0, "payload": "old-data",
        }
        stream = run_netns_scenario(
            vm, NS_B if initiator else NS_A, "send_tcp_packets",
            {"packets": [stray] * 80, "delay_ms": 50},
        )
        assert_completed(stream, "continued stale data")
        expired = wait_for_half_open_drain(vm, baseline, expected_rst=1)
        assert expired["handshake_retries_exhausted"] == baseline["handshake_retries_exhausted"] + 1
        assert expired["flows_established"] == baseline["flows_established"]
        assert expired["flows_created"] == baseline["flows_created"] + 1
    finally:
        drop.cleanup(vm)
        cleanup_netns_topology(vm)
