"""Packet diagnostics are bounded without suppressing accounting or delivery."""

import uuid

import pytest

from helpers import (
    NS_A,
    NS_ADDR_A,
    NS_ADDR_B,
    NS_B,
    PORTS_A,
    PORTS_B,
    assert_completed,
    cleanup_netns_topology,
    ensure_netns_topology,
    load_managed_module,
    make_netns_output_flag_probe,
    parse_guest_json,
    read_module_stats,
    received_messages,
    require_guest_command,
    run_netns_scenario,
    spawn_netns_scenario,
    wait_for_guest_ready_file,
)

PACKETS = 64
FORWARD = {
    "bind_addr": NS_ADDR_A,
    "bind_port": PORTS_A[0],
    "target_addr": NS_ADDR_B,
    "target_port": PORTS_B[0],
}


def diagnostic_count(vm, level):
    # Read the ring synchronously, not the asynchronous host dmesg collector.
    result = vm.run(["dmesg", "--notime", f"--level={level}"])
    return sum(line.startswith("phantun: ") for line in result.stdout.splitlines())


@pytest.mark.parametrize("path", ["warning", "replacement"])
def test_packet_diagnostics_are_ratelimited(phantun_module, vm, path):
    if not require_guest_command(vm, "nft"):
        pytest.skip("nft is not available in the guest")
    load_managed_module(phantun_module)
    ensure_netns_topology(vm)
    probe = None
    server = None
    try:
        if path == "warning":
            # Intentional local terminal emit error, not simulated path loss.
            probe = make_netns_output_flag_probe(
                vm,
                NS_A,
                [
                    {
                        "src_addr": NS_ADDR_A,
                        "src_port": PORTS_A[0],
                        "dst_addr": NS_ADDR_B,
                        "dst_port": PORTS_B[0],
                        "flags_expr": "syn",
                        "action": "drop",
                        "comment": "logging_syn_drop",
                    }
                ],
            )
        else:
            # Raw peer ports are unmanaged. Prevent its kernel TCP stack from
            # resetting the real module's SYN|ACKs before our peer ACKs them.
            probe = make_netns_output_flag_probe(
                vm,
                NS_B,
                [
                    {
                        "src_addr": NS_ADDR_B,
                        "dst_addr": NS_ADDR_A,
                        "src_port": f"45000-{45000 + PACKETS - 1}",
                        "dst_port": PORTS_A[0],
                        "flags_expr": flags,
                        "action": "drop",
                        "comment": f"raw_peer_{index}",
                    }
                    for index, flags in enumerate(("rst", "rst | ack"))
                ],
            )
            ready = f"/tmp/phantun-log-receiver-{uuid.uuid4().hex}"
            server = spawn_netns_scenario(
                vm,
                NS_A,
                "recv_many",
                {
                    "bind_addr": NS_ADDR_A,
                    "bind_port": PORTS_A[0],
                    "count": PACKETS,
                    "timeout_sec": 60,
                    "ready_file": ready,
                },
            )
            wait_for_guest_ready_file(vm, ready)

        initial = read_module_stats(vm)
        level = "warn" if path == "warning" else "info"
        # Isolate this flood instead of subtracting totals in an overwriting
        # ring. CLEAR advances the dmesg history boundary; it does not remove
        # records or move the existing host collector's /dev/kmsg read cursor.
        vm.run(["dmesg", "--clear"])
        if path == "warning":
            flood = run_netns_scenario(
                vm,
                NS_A,
                "send_many",
                {**FORWARD, "payloads": ["must-not-leak"] * PACKETS},
            )
        else:
            # Each peer-controlled opener establishes and replaces a fresh
            # responder tuple. No comparison to random local ISNs is needed.
            flood = run_netns_scenario(
                vm,
                NS_B,
                "replace_responder_generations",
                {
                    "bind_addr": NS_ADDR_B,
                    "bind_port": 45000,
                    "target_addr": NS_ADDR_A,
                    "target_port": PORTS_A[0],
                    "count": PACKETS,
                },
                timeout=90,
            )
        assert_completed(flood, "packet diagnostic flood")
        if path == "replacement":
            delivered = server.communicate(timeout=65)
            assert_completed(delivered, "UDP receiver during replacement flood")
            data = parse_guest_json(delivered.stdout, "replacement flood delivery")
            assert sorted(received_messages(data)) == sorted(f"replacement-{index}" for index in range(PACKETS))

        final = read_module_stats(vm)
        if path == "warning":
            events = final["udp_translation_failed_dropped"] - initial["udp_translation_failed_dropped"]
            assert events == PACKETS
            assert probe.packets(vm, "logging_syn_drop") == PACKETS
            assert final["udp_packets_dropped"] - initial["udp_packets_dropped"] == PACKETS
            assert final["flows_created"] - initial["flows_created"] == PACKETS
            assert final["flows_current"] == initial["flows_current"]
        else:
            events = final["replacements_accepted"] - initial["replacements_accepted"]
            assert events == PACKETS
            assert final["flows_created"] - initial["flows_created"] == 2 * PACKETS
            assert final["flows_established"] - initial["flows_established"] == 2 * PACKETS
            assert final["flows_current"] - initial["flows_current"] == PACKETS
            assert final["udp_packets_dropped"] == initial["udp_packets_dropped"]
        diagnostics = diagnostic_count(vm, level)
        # Assert actual suppression, not incidental kernel burst/interval values.
        assert 0 < diagnostics < events, f"{level}: {diagnostics} diagnostics for {events} accounted events"
        assert final["handshake_retries_exhausted"] == initial["handshake_retries_exhausted"]

        if path == "warning":
            ready = f"/tmp/phantun-log-receiver-{uuid.uuid4().hex}"
            server = spawn_netns_scenario(
                vm,
                NS_B,
                "recv_many",
                {"bind_addr": NS_ADDR_B, "bind_port": PORTS_B[0], "count": 1, "timeout_sec": 30, "ready_file": ready},
            )
            wait_for_guest_ready_file(vm, ready)
            probe.cleanup(vm)
            recovery = run_netns_scenario(vm, NS_A, "send_many", {**FORWARD, "payloads": ["recovered"]})
            assert_completed(recovery, "sender after local emit errors")
            delivered = server.communicate(timeout=35)
            assert_completed(delivered, "receiver after diagnostic flood")
            data = parse_guest_json(delivered.stdout, "diagnostic flood recovery")
            assert received_messages(data) == ["recovered"]
            recovered = read_module_stats(vm)
            assert recovered["flows_established"] - initial["flows_established"] == 2
    finally:
        if server is not None:
            server.terminate()
        if probe is not None:
            probe.cleanup(vm)
        cleanup_netns_topology(vm)
