"""Traffic ownership: which UDP flows are translated, and owned raw UDP drops."""

import subprocess
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
    assert_completed,
    cleanup_netns_topology,
    ensure_netns_topology,
    make_netns_output_probe,
    parse_guest_json,
    probe_comment,
    read_module_stat,
    read_module_stats,
    require_nft_or_skip,
    run_guest_scenario,
    run_netns_scenario,
    run_ping_pong,
    spawn_guest_scenario,
    spawn_netns_scenario,
    wait_for_guest_ready_file,
)


def test_managed_remote_peers_filter_blocks_unmatched_remote_peer(phantun_module, vm):
    phantun_module.load(
        managed_netns="all",
        managed_local_ports=MANAGED_LOCAL_PORTS,
        managed_remote_peers="10.200.1.2:3333",
    )
    ensure_netns_topology(vm)

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    probe_a = make_netns_output_probe(vm, NS_A, [(NS_ADDR_A, src_port, NS_ADDR_B, dst_port)])
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
        # The OUTPUT probe intentionally drops raw UDP. If the managed-remote-peer
        # filter bypasses translation correctly, sendto fails locally and the
        # server receives nothing.
        client = run_netns_scenario(
            vm,
            NS_A,
            "send_many",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["blocked-by-cidr"],
            },
            check=False,
        )
        server_result = server.communicate(timeout=10)
        if client.returncode == 0:
            pytest.fail("sender unexpectedly succeeded despite unmatched managed_remote_peers entry")
        if server_result.returncode == 0:
            pytest.fail("server unexpectedly received payload despite unmatched managed_remote_peers entry")

        udp_a = probe_a.packets(vm, probe_comment("udp", NS_ADDR_A, src_port, NS_ADDR_B, dst_port))
        tcp_a = probe_a.packets(vm, probe_comment("tcp", NS_ADDR_A, src_port, NS_ADDR_B, dst_port))
        if udp_a == 0:
            pytest.fail("expected raw UDP to escape when managed_remote_peers rejects the tuple")
        if tcp_a != 0:
            pytest.fail(f"expected no translated TCP when managed_remote_peers rejects the tuple, got {tcp_a}")
    finally:
        probe_a.cleanup(vm)
        cleanup_netns_topology(vm)


def test_managed_remote_peers_filter_blocks_unmatched_peer_port(phantun_module, vm):
    phantun_module.load(
        managed_netns="all",
        managed_local_ports=MANAGED_LOCAL_PORTS,
        managed_remote_peers="10.200.0.2:5555",
    )
    ensure_netns_topology(vm)

    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    probe_a = make_netns_output_probe(vm, NS_A, [(NS_ADDR_A, src_port, NS_ADDR_B, dst_port)])
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

    # The OUTPUT probe intentionally drops raw UDP. If the managed-remote-peer
    # filter bypasses translation correctly, sendto fails locally and the
    # server receives nothing.
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
                "payloads": ["blocked-by-port"],
            },
            check=False,
        )
        server_result = server.communicate(timeout=10)
        if client.returncode == 0:
            pytest.fail("sender unexpectedly succeeded despite unmatched managed_remote_peers port")
        if server_result.returncode == 0:
            pytest.fail("server unexpectedly received payload despite unmatched managed_remote_peers port")

        udp_a = probe_a.packets(vm, probe_comment("udp", NS_ADDR_A, src_port, NS_ADDR_B, dst_port))
        tcp_a = probe_a.packets(vm, probe_comment("tcp", NS_ADDR_A, src_port, NS_ADDR_B, dst_port))
        if udp_a == 0:
            pytest.fail("expected raw UDP to escape when managed_remote_peers rejects the tuple")
        if tcp_a != 0:
            pytest.fail(f"expected no translated TCP when managed_remote_peers rejects the tuple, got {tcp_a}")
    finally:
        probe_a.cleanup(vm)
        cleanup_netns_topology(vm)


def test_peer_only_mode_translates_matching_peers(phantun_module, vm):
    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    managed_peers = f"{NS_ADDR_A}:{src_port},{NS_ADDR_B}:{dst_port}"

    phantun_module.load(managed_netns="all", managed_remote_peers=managed_peers)
    ensure_netns_topology(vm)

    probe_a = make_netns_output_probe(vm, NS_A, [(NS_ADDR_A, src_port, NS_ADDR_B, dst_port)])
    probe_b = make_netns_output_probe(vm, NS_B, [(NS_ADDR_B, dst_port, NS_ADDR_A, src_port)])
    server = spawn_netns_scenario(
        vm,
        NS_B,
        "recv_many_reply",
        {
            "bind_addr": NS_ADDR_B,
            "bind_port": dst_port,
            "count": 1,
            "replies": ["peer-only-reply"],
        },
    )

    try:
        time.sleep(0.2)
        client = run_netns_scenario(
            vm,
            NS_A,
            "send_many_recv",
            {
                "bind_addr": NS_ADDR_A,
                "bind_port": src_port,
                "target_addr": NS_ADDR_B,
                "target_port": dst_port,
                "payloads": ["peer-only-request"],
                "recv_count": 1,
            },
            timeout=20,
        )
        server_result = server.communicate(timeout=20)
        assert_completed(client, "peer-only client")
        assert_completed(server_result, "peer-only server")

        client_data = parse_guest_json(client.stdout, "peer-only client stdout")
        server_data = parse_guest_json(server_result.stdout, "peer-only server stdout")
        if [entry["message"] for entry in server_data.get("received", [])] != ["peer-only-request"]:
            pytest.fail(f"unexpected peer-only server payloads: {server_data!r}")
        if [entry["message"] for entry in client_data.get("replies", [])] != ["peer-only-reply"]:
            pytest.fail(f"unexpected peer-only client replies: {client_data!r}")

        udp_a = probe_a.packets(vm, probe_comment("udp", NS_ADDR_A, src_port, NS_ADDR_B, dst_port))
        tcp_a = probe_a.packets(vm, probe_comment("tcp", NS_ADDR_A, src_port, NS_ADDR_B, dst_port))
        udp_b = probe_b.packets(vm, probe_comment("udp", NS_ADDR_B, dst_port, NS_ADDR_A, src_port))
        tcp_b = probe_b.packets(vm, probe_comment("tcp", NS_ADDR_B, dst_port, NS_ADDR_A, src_port))
        if udp_a != 0 or udp_b != 0:
            pytest.fail(f"raw UDP escaped in peer-only mode: ns_a={udp_a}, ns_b={udp_b}")
        if tcp_a == 0 or tcp_b == 0:
            pytest.fail(f"expected translated TCP in peer-only mode, got ns_a={tcp_a}, ns_b={tcp_b}")
    finally:
        probe_a.cleanup(vm)
        probe_b.cleanup(vm)
        cleanup_netns_topology(vm)


@pytest.mark.usefixtures("ipv6_runtime")
def test_ipv6_managed_remote_peers_bracketed_peer(phantun_module, vm):
    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]
    phantun_module.load(
        managed_netns="all", managed_remote_peers=f"[{NS6_ADDR_B}]:{dst_port},[{NS6_ADDR_A}]:{src_port}"
    )
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


def test_intersection_mode_requires_local_and_remote_match(phantun_module, vm):
    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]

    phantun_module.load(
        managed_netns="all",
        managed_local_ports="5555",
        managed_remote_peers=f"{NS_ADDR_B}:{dst_port}",
    )
    ensure_netns_topology(vm)

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
                "payloads": ["intersection-raw"],
            },
        )
        server_result = server.communicate(timeout=10)
        assert_completed(client, "intersection client")
        assert_completed(server_result, "intersection server")

        server_data = parse_guest_json(server_result.stdout, "intersection server stdout")
        if [entry["message"] for entry in server_data.get("received", [])] != ["intersection-raw"]:
            pytest.fail(f"unexpected intersection server payloads: {server_data!r}")

    finally:
        cleanup_netns_topology(vm)


@pytest.mark.parametrize(
    ("destination", "selector_mode"),
    [
        pytest.param("239.1.2.3", "local", id="ipv4-multicast-selected-local"),
        pytest.param("239.1.2.3", "unmatched-local", id="ipv4-multicast-local-miss"),
        pytest.param("255.255.255.255", "peer", id="limited-broadcast-selected-peer"),
        pytest.param("255.255.255.255", "unmatched-peer-address", id="limited-broadcast-address-miss"),
        pytest.param("10.200.0.255", "intersection", id="directed-broadcast-selected-intersection"),
        pytest.param("10.200.0.255", "unmatched-peer-port", id="directed-broadcast-port-miss"),
        pytest.param("ff02::123", "intersection", id="ipv6-link-multicast-selected-intersection"),
        pytest.param("ff02::123", "unmatched-local", id="ipv6-link-multicast-local-miss"),
        pytest.param("ff0e::123", "peer", id="ipv6-global-multicast-selected-peer"),
        pytest.param("ff0e::123", "unmatched-peer-address", id="ipv6-global-multicast-address-miss"),
    ],
)
def test_nonunicast_output_respects_selector_ownership(phantun_module, vm, request, destination, selector_mode):
    ipv6 = ":" in destination
    if ipv6:
        request.getfixturevalue("ipv6_runtime")
    source = NS6_ADDR_A if ipv6 else NS_ADDR_A
    src_port, dst_port = PORTS_A[0], PORTS_B[0]
    selected = selector_mode in ("local", "peer", "intersection")
    peer_address = destination
    peer_port = dst_port
    if selector_mode == "unmatched-peer-address":
        peer_address = NS6_ADDR_B if ipv6 else NS_ADDR_B
    if selector_mode == "unmatched-peer-port":
        peer_port += 1
    peer = f"[{peer_address}]:{peer_port}" if ipv6 else f"{peer_address}:{peer_port}"
    selectors = {}
    if selector_mode != "peer":
        selectors["managed_local_ports"] = str(src_port + 1 if selector_mode == "unmatched-local" else src_port)
    if selector_mode != "local":
        selectors["managed_remote_peers"] = peer
    phantun_module.load(managed_netns="all", **selectors)
    ensure_netns_topology(vm, with_ipv6=ipv6)
    require_nft_or_skip(vm)
    probe = None
    try:
        if destination == "10.200.0.255":
            # Install an explicit subnet broadcast, so this exercises the
            # output route's broadcast classification, not address guessing.
            vm.run(["ip", "netns", "exec", NS_A, "ip", "addr", "change",
                    f"{NS_ADDR_A}/24", "brd", "+", "dev", VETH_A])
            route = vm.run(["ip", "netns", "exec", NS_A, "ip", "route", "get", destination])
            assert "broadcast" in route.stdout, route.stdout
        elif destination == "239.1.2.3" or ipv6:
            family = ["-6"] if ipv6 else []
            vm.run(["ip", "netns", "exec", NS_A, "ip", *family, "route", "replace",
                    destination + ("/128" if ipv6 else "/32"), "dev", VETH_A])

        # Priority zero observes packets after Phantun's ownership decision.
        # Accept UDP so unselected cases exercise the normal output path.
        probe = make_netns_output_probe(
            vm, NS_A, [(source, src_port, destination, dst_port)], udp_action="accept"
        )
        before = read_module_stats(vm)
        result = run_netns_scenario(
            vm, NS_A, "send_many",
            {
                "bind_addr": source,
                "bind_port": src_port,
                "bind_device": VETH_A,
                "target_addr": destination,
                "target_port": dst_port,
                "target_scope_dev": VETH_A if ipv6 else None,
                "broadcast": not ipv6,
                "payloads": ["nonunicast-ownership"],
                "allow_send_errors": True,
            },
        )
        assert_completed(result, "non-unicast sender")
        sent = parse_guest_json(result.stdout, "non-unicast sender stdout")
        after = read_module_stats(vm)
        assert probe.packets(vm, probe_comment("tcp", source, src_port, destination, dst_port)) == 0
        assert probe.packets(vm, probe_comment("udp", source, src_port, destination, dst_port)) == (
            0 if selected else 1
        )
        for counter in ("flows_created", "flows_current", "udp_packets_queued"):
            assert after[counter] == before[counter], (counter, before, after)
        assert after["udp_packets_dropped"] - before["udp_packets_dropped"] == int(selected)
        if selected:
            assert len(sent["errors"]) == 1, sent
        else:
            assert sent["errors"] == [], sent
    finally:
        if probe is not None:
            probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_loopback_multicast_on_managed_port_is_ignored(phantun_module, vm):
    source, destination = "127.0.0.1", "239.1.2.3"
    src_port, dst_port = PORTS_A[0], PORTS_B[0]
    phantun_module.load(managed_netns="all", managed_local_ports=str(src_port))
    ensure_netns_topology(vm)
    require_nft_or_skip(vm)
    probe = None
    try:
        vm.run(["ip", "netns", "exec", NS_A, "ip", "route", "add",
                f"{destination}/32", "dev", "lo", "src", source])
        probe = make_netns_output_probe(
            vm, NS_A, [(source, src_port, destination, dst_port)], udp_action="accept"
        )
        before = read_module_stats(vm)
        result = run_netns_scenario(
            vm, NS_A, "send_many",
            {
                "bind_addr": source,
                "bind_port": src_port,
                "bind_device": "lo",
                "target_addr": destination,
                "target_port": dst_port,
                "payloads": ["loopback-multicast"],
            },
        )
        assert_completed(result, "loopback multicast sender")
        after = read_module_stats(vm)
        assert probe.packets(vm, probe_comment("udp", source, src_port, destination, dst_port)) == 1
        assert probe.packets(vm, probe_comment("tcp", source, src_port, destination, dst_port)) == 0
        for counter in ("flows_created", "flows_current", "udp_packets_queued", "udp_packets_dropped"):
            assert after[counter] == before[counter], (counter, before, after)
    finally:
        if probe is not None:
            probe.cleanup(vm)
        cleanup_netns_topology(vm)


def test_loopback_localhost_udp_on_managed_port_is_ignored(phantun_module, vm):
    managed_port = PORTS_A[0]
    other_port = PORTS_B[0]

    phantun_module.load(managed_local_ports=str(managed_port))
    initial_stats = read_module_stats(vm)
    server = spawn_guest_scenario(
        vm,
        "ping_server",
        {
            "bind_addr": "127.0.0.1",
            "bind_port": other_port,
        },
    )
    server_result = None

    try:
        time.sleep(0.2)
        client = run_guest_scenario(
            vm,
            "ping_client",
            {
                "bind_addr": "127.0.0.1",
                "bind_port": managed_port,
                "target_addr": "127.0.0.1",
                "target_port": other_port,
                "payload": "loopback-localhost",
            },
            check=False,
            timeout=10,
        )
        try:
            server_result = server.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            pytest.fail("loopback localhost server did not receive UDP on a managed_local_ports tuple")

        assert_completed(client, "loopback localhost client")
        assert_completed(server_result, "loopback localhost server")

        client_data = parse_guest_json(client.stdout, "loopback localhost client stdout")
        server_data = parse_guest_json(server_result.stdout, "loopback localhost server stdout")
        if server_data.get("received") != "loopback-localhost":
            pytest.fail(f"unexpected localhost server payload: {server_data!r}")
        if client_data.get("reply") != "pong":
            pytest.fail(f"unexpected localhost client reply: {client_data!r}")

        stats = read_module_stats(vm)
        if stats != initial_stats:
            pytest.fail(
                "localhost UDP between managed_local_ports and another localhost port must bypass phantun "
                f"entirely; expected stats {initial_stats!r}, got {stats!r}"
            )
    finally:
        if server_result is None and server.proc.poll() is None:
            server.terminate()
            try:
                server.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                pytest.fail("loopback localhost server did not exit after termination")


def test_default_init_mode_leaves_non_init_netns_udp_untranslated(phantun_module, vm):
    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]

    phantun_module.load(managed_local_ports=str(src_port))
    ensure_netns_topology(vm)
    baseline_stats = read_module_stats(vm)
    probe = make_netns_output_probe(
        vm,
        NS_A,
        [(NS_ADDR_A, src_port, NS_ADDR_B, dst_port)],
        udp_action="accept",
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
                "payloads": ["default-init-raw-udp"],
            },
            timeout=10,
        )
        server_result = server.communicate(timeout=10)
        assert_completed(client, "default init-mode client")
        assert_completed(server_result, "default init-mode server")

        server_data = parse_guest_json(server_result.stdout, "default init-mode server stdout")
        if [entry["message"] for entry in server_data.get("received", [])] != [
            "default-init-raw-udp",
        ]:
            pytest.fail(f"unexpected default init-mode server payloads: {server_data!r}")

        udp_packets = probe.packets(vm, probe_comment("udp", NS_ADDR_A, src_port, NS_ADDR_B, dst_port))
        tcp_packets = probe.packets(vm, probe_comment("tcp", NS_ADDR_A, src_port, NS_ADDR_B, dst_port))
        if udp_packets == 0:
            pytest.fail("expected raw UDP to leave a non-init netns in default managed_netns=init mode")
        if tcp_packets != 0:
            pytest.fail(f"expected no fake-TCP output in default managed_netns=init mode, got {tcp_packets}")

        stats = read_module_stats(vm)
        if stats != baseline_stats:
            pytest.fail(f"default init-mode non-init traffic must not touch module stats: {stats!r}")
    finally:
        probe.cleanup(vm)
        cleanup_netns_topology(vm)


@pytest.mark.usefixtures("ipv6_runtime")
def test_ip_families_can_disable_one_family(phantun_module, dmesg, vm):
    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]

    phantun_module.load(managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS, ip_families="ipv4")
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

    phantun_module.unload()
    dmesg.get_new_lines()
    dmesg.clear()

    phantun_module.load(managed_netns="all", managed_local_ports=MANAGED_LOCAL_PORTS, ip_families="ipv6")
    ensure_netns_topology(vm, with_ipv6=True)
    require_nft_or_skip(vm)
    probe_v4_plain = make_netns_output_probe(
        vm,
        NS_A,
        [(NS_ADDR_A, src_port, NS_ADDR_B, dst_port)],
        udp_action="accept",
    )
    probe_v6 = make_netns_output_probe(vm, NS_A, [(NS6_ADDR_A, src_port, NS6_ADDR_B, dst_port)])
    bad_lines = []
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
        phantun_module.unload()
        time.sleep(0.5)
        bad_lines = [
            line for line in dmesg.get_new_lines() if any(marker in line for marker in ("WARNING:", "Oops", "BUG:"))
        ]

    if bad_lines:
        pytest.fail("IPv6-only module load/unload emitted kernel diagnostics:\n" + "\n".join(bad_lines))


def test_inbound_udp_to_managed_local_port_is_dropped(phantun_module, vm):
    src_port = PORTS_A[0]
    dst_port = PORTS_B[0]

    phantun_module.load(managed_netns="all", managed_local_ports=str(dst_port))
    ensure_netns_topology(vm)
    baseline_stats = read_module_stats(vm)

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
                "payloads": ["should-drop-raw-udp"],
            },
            check=False,
        )
        server_result = server.communicate(timeout=10)
        if client.returncode != 0:
            pytest.fail(f"raw-udp client unexpectedly failed before inbound drop: {client.stderr!r}")
        if server_result.returncode == 0:
            pytest.fail("server unexpectedly received raw UDP on a managed local port")

        stats = read_module_stats(vm)
        if stats["udp_raw_inbound_dropped"] <= baseline_stats["udp_raw_inbound_dropped"]:
            pytest.fail(f"expected raw inbound UDP drop counter to increase, got {stats!r}")
    finally:
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


@pytest.mark.usefixtures("ipv6_runtime")
@pytest.mark.parametrize("managed", [True, False], ids=["owned", "unowned"])
def test_ipv6_destination_options_udp_ownership(phantun_module, vm, managed):
    phantun_module.load(managed_netns="all", managed_local_ports=str(PORTS_B[0]))
    ensure_netns_topology(vm, with_ipv6=True)
    dst_port = PORTS_B[0] if managed else PORTS_B[0] + 1
    ready_file = f"/tmp/phantun-ipv6-options-{uuid.uuid4().hex}"
    stop_file = f"/tmp/phantun-ipv6-options-stop-{uuid.uuid4().hex}"
    receiver = None
    before = read_module_stat(vm, "udp_raw_inbound_dropped")
    try:
        receiver = spawn_netns_scenario(
            vm,
            NS_B,
            "recv_until_timeout",
            {
                "bind_addr": NS6_ADDR_B,
                "bind_port": dst_port,
                "count": 1,
                "timeout_sec": 20,
                "ready_file": ready_file,
                "stop_file": stop_file,
            },
        )
        wait_for_guest_ready_file(vm, ready_file)
        sender = run_netns_scenario(
            vm,
            NS_A,
            "send_ipv6_udp_options",
            {
                "bind_addr": NS6_ADDR_A,
                "bind_port": 45678,
                "target_addr": NS6_ADDR_B,
                "target_port": dst_port,
                "payload": "destination-options",
            },
            timeout=10,
        )
        assert_completed(sender, "IPv6 Destination Options sender")
        if managed:
            deadline = time.monotonic() + 20
            while read_module_stat(vm, "udp_raw_inbound_dropped") == before:
                if time.monotonic() >= deadline:
                    pytest.fail("owned IPv6 extension-header UDP was not dropped")
                time.sleep(0.1)
            vm.run(["touch", stop_file])
        result = receiver.communicate(timeout=25)
        assert_completed(result, "IPv6 Destination Options receiver")
        received = parse_guest_json(result.stdout, "IPv6 Destination Options receiver")["received"]
        expected = [] if managed else [{"message": "destination-options", "peer": [NS6_ADDR_A, 45678]}]
        if received != expected:
            pytest.fail(f"incorrect IPv6 extension-header UDP ownership: {received!r}")
        if read_module_stat(vm, "udp_raw_inbound_dropped") - before != int(managed):
            pytest.fail("IPv6 extension-header UDP was not classified by its final transport protocol")
    finally:
        if receiver is not None:
            receiver.terminate()
        vm.run(["rm", "-f", ready_file, stop_file], check=False)
        cleanup_netns_topology(vm)
