import json
import shlex
import subprocess
import textwrap
import time
import uuid
from pathlib import Path

import pytest

NS_A = "pht-a"
NS_B = "pht-b"
VETH_A = "veth-pht-a"
VETH_B = "veth-pht-b"
NS_ADDR_A = "10.200.0.1"
NS_ADDR_B = "10.200.0.2"
PORTS_A = (2222, 4444)
PORTS_B = (3333, 5555)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
GUEST_SCENARIOS = str(PROJECT_ROOT / "tests/guest/scenarios.py")
MODULE_STAT_NAMES = (
    "flows_created",
    "flows_established",
    "flows_current",
    "request_payloads_injected",
    "response_payloads_injected",
    "collisions_won",
    "collisions_lost",
    "rst_sent",
    "udp_packets_queued",
    "udp_packets_dropped",
    "shaping_payloads_dropped",
    "bad_checksum_dropped",
    "oversized_payloads_dropped",
)


class GuestProcess:
    def __init__(self, proc):
        self.proc = proc

    def communicate(self, timeout=None):
        stdout, stderr = self.proc.communicate(timeout=timeout)
        return subprocess.CompletedProcess(
            args=self.proc.args,
            returncode=self.proc.returncode,
            stdout=stdout,
            stderr=stderr,
        )

    def terminate(self):
        self.proc.terminate()


class NetnsNftProbe:
    def __init__(self, namespace, family, table_name, chain_name):
        self.namespace = namespace
        self.family = family
        self.table_name = table_name
        self.chain_name = chain_name

    def packets(self, vm, comment):
        res = run_in_netns(
            vm,
            self.namespace,
            [
                "nft",
                "-j",
                "list",
                "chain",
                self.family,
                self.table_name,
                self.chain_name,
            ],
        )
        data = json.loads(res.stdout)

        for item in data.get("nftables", []):
            rule = item.get("rule")
            if not rule or rule.get("comment") != comment:
                continue

            for expr in rule.get("expr", []):
                counter = expr.get("counter")
                if counter is not None:
                    return counter.get("packets", 0)

        raise KeyError(f"Missing nft rule comment in {self.namespace}: {comment}")

    def cleanup(self, vm):
        run_in_netns(
            vm,
            self.namespace,
            ["nft", "delete", "table", self.family, self.table_name],
            check=False,
        )


def assert_completed(result, label):
    if result.returncode != 0:
        pytest.fail(f"{label} failed: {result.stderr!r}")


def run_guest_python(vm, script, check=True):
    body = textwrap.dedent(script).strip()
    command = f"python3 - <<'PY'\n{body}\nPY"
    return vm.run(command, check=check)


def run_in_netns(vm, namespace, cmd, check=True, **kwargs):
    if isinstance(cmd, list):
        return vm.run(["ip", "netns", "exec", namespace, *cmd], check=check, **kwargs)

    return vm.run(
        f"ip netns exec {shlex.quote(namespace)} bash -c {shlex.quote(cmd)}",
        check=check,
        **kwargs,
    )


def guest_command(cmd):
    if isinstance(cmd, list):
        return " ".join(shlex.quote(part) for part in cmd)

    return cmd


def spawn_guest_command(vm, cmd, **kwargs):
    ssh_cmd = vm.base_ssh_cmd + [f"bash -c {shlex.quote(guest_command(cmd))}"]
    proc = subprocess.Popen(
        ssh_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        **kwargs,
    )
    return GuestProcess(proc)


def run_netns_scenario(vm, namespace, scenario, config, check=True, **kwargs):
    return run_in_netns(
        vm,
        namespace,
        ["python3", GUEST_SCENARIOS, scenario, json.dumps(config)],
        check=check,
        **kwargs,
    )


def spawn_netns_scenario(vm, namespace, scenario, config, **kwargs):
    return spawn_guest_command(
        vm,
        [
            "ip",
            "netns",
            "exec",
            namespace,
            "python3",
            GUEST_SCENARIOS,
            scenario,
            json.dumps(config),
        ],
        **kwargs,
    )


def wait_for_guest_condition(vm, cmd, timeout, description, interval=0.1):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if vm.run(cmd, check=False).returncode == 0:
            return
        time.sleep(interval)
    pytest.fail(f"{description} was not observed within {timeout}s")


def wait_for_guest_ready_file(vm, path, timeout=5):
    wait_for_guest_condition(vm, ["test", "-e", path], timeout, f"guest readiness file {path!r}")


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


def parse_guest_json(stdout, context):
    body = stdout.strip()
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"{context}: invalid guest JSON: {exc}: {body}") from exc


def require_guest_command(vm, command):
    res = vm.run(f"command -v {shlex.quote(command)}", check=False)
    return res.returncode == 0


def read_module_stat(vm, name):
    res = run_guest_python(
        vm,
        f"""
from pathlib import Path
print(Path('/sys/module/phantun/stats/{name}').read_text().strip())
""",
    )
    return int(res.stdout.strip())


def read_module_stats(vm):
    # Packet-loss and recovery tests poll stats in tight loops. Read all stat files
    # in one guest process/SSH round-trip so slow nested-QEMU runners do not miss
    # short-lived state transitions between per-stat polls.
    res = run_guest_python(
        vm,
        """
import json
from pathlib import Path

stats_root = Path('/sys/module/phantun/stats')
stats = {
    name: int((stats_root / name).read_text().strip())
    for name in %r
}
print(json.dumps(stats))
""" % (MODULE_STAT_NAMES,),
    )
    return parse_guest_json(res.stdout, "module stats stdout")


def cleanup_netns_topology(vm, namespaces=(NS_A, NS_B)):
    for namespace in namespaces:
        vm.run(["ip", "netns", "del", namespace], check=False)


def ensure_netns_topology(vm):
    cleanup_netns_topology(vm)

    vm.run(["ip", "netns", "add", NS_A])
    vm.run(["ip", "netns", "add", NS_B])
    vm.run(["ip", "link", "add", VETH_A, "type", "veth", "peer", "name", VETH_B])
    vm.run(["ip", "link", "set", VETH_A, "netns", NS_A])
    vm.run(["ip", "link", "set", VETH_B, "netns", NS_B])

    run_in_netns(vm, NS_A, ["ip", "link", "set", "lo", "up"])
    run_in_netns(vm, NS_B, ["ip", "link", "set", "lo", "up"])

    run_in_netns(vm, NS_A, ["ip", "addr", "add", f"{NS_ADDR_A}/24", "dev", VETH_A])
    run_in_netns(vm, NS_B, ["ip", "addr", "add", f"{NS_ADDR_B}/24", "dev", VETH_B])
    run_in_netns(vm, NS_A, ["ip", "link", "set", VETH_A, "up"])
    run_in_netns(vm, NS_B, ["ip", "link", "set", VETH_B, "up"])
    run_in_netns(vm, NS_A, ["ip", "route", "add", f"{NS_ADDR_B}/32", "dev", VETH_A])
    run_in_netns(vm, NS_B, ["ip", "route", "add", f"{NS_ADDR_A}/32", "dev", VETH_B])


def make_netns_output_probe(vm, namespace, channels):
    table_name = f"phantun_netns_{uuid.uuid4().hex[:8]}"
    lines = [
        f"nft delete table inet {table_name} >/dev/null 2>&1 || true",
        f"nft add table inet {table_name}",
        (f"nft 'add chain inet {table_name} output " "{ type filter hook output priority 0; policy accept; }'"),
    ]

    for src_addr, src_port, dst_addr, dst_port in channels:
        tag = flow_tag(src_addr, src_port, dst_addr, dst_port)
        lines.append(
            f"nft add rule inet {table_name} output "
            f"ip saddr {src_addr} ip daddr {dst_addr} "
            f"udp sport {src_port} udp dport {dst_port} "
            f'counter drop comment "udp_{tag}"'
        )
        lines.append(
            f"nft add rule inet {table_name} output "
            f"ip saddr {src_addr} ip daddr {dst_addr} "
            f"tcp sport {src_port} tcp dport {dst_port} "
            f'counter accept comment "tcp_{tag}"'
        )

    run_in_netns(vm, namespace, "\n".join(lines))
    return NetnsNftProbe(namespace, "inet", table_name, "output")


def make_netns_output_flag_probe(vm, namespace, rules):
    table_name = f"phantun_out_flags_{uuid.uuid4().hex[:8]}"
    lines = [
        f"nft delete table inet {table_name} >/dev/null 2>&1 || true",
        f"nft add table inet {table_name}",
        (f"nft 'add chain inet {table_name} output " "{ type filter hook output priority 0; policy accept; }'"),
    ]

    for rule in rules:
        lines.append(
            f"nft 'add rule inet {table_name} output "
            f"ip saddr {rule['src_addr']} ip daddr {rule['dst_addr']} "
            f"tcp sport {rule['src_port']} tcp dport {rule['dst_port']} "
            f"tcp flags & (fin|syn|rst|ack) == {rule['flags_expr']} "
            f"counter {rule.get('action', 'accept')} comment \"{rule['comment']}\"'"
        )

    run_in_netns(vm, namespace, "\n".join(lines))
    return NetnsNftProbe(namespace, "inet", table_name, "output")


def make_netns_prerouting_flag_drop_probe(vm, namespace, rules):
    table_name = f"phantun_prerouting_{uuid.uuid4().hex[:8]}"
    lines = [
        f"nft delete table inet {table_name} >/dev/null 2>&1 || true",
        f"nft add table inet {table_name}",
        (
            f"nft 'add chain inet {table_name} prerouting "
            "{ type filter hook prerouting priority -500; policy accept; }'"
        ),
    ]

    for rule in rules:
        lines.append(
            f"nft 'add rule inet {table_name} prerouting "
            f"ip saddr {rule['src_addr']} ip daddr {rule['dst_addr']} "
            f"tcp sport {rule['src_port']} tcp dport {rule['dst_port']} "
            f"tcp flags & (fin|syn|rst|ack) == {rule['flags_expr']} "
            f"counter {rule.get('action', 'drop')} comment \"{rule['comment']}\"'"
        )

    run_in_netns(vm, namespace, "\n".join(lines))
    return NetnsNftProbe(namespace, "inet", table_name, "prerouting")


def make_netns_ingress_drop_probe(vm, namespace, dev, rules):
    table_name = f"phantun_in_drop_{uuid.uuid4().hex[:8]}"
    lines = [
        f"nft delete table netdev {table_name} >/dev/null 2>&1 || true",
        f"nft add table netdev {table_name}",
        (
            f"nft 'add chain netdev {table_name} ingress "
            f"{{ type filter hook ingress device {dev} priority 0; policy accept; }}'"
        ),
    ]

    for rule in rules:
        lines.append(
            f"nft 'add rule netdev {table_name} ingress "
            f"ip saddr {rule['src_addr']} ip daddr {rule['dst_addr']} "
            f"tcp sport {rule['src_port']} tcp dport {rule['dst_port']} "
            f"counter drop comment \"{rule['comment']}\"'"
        )

    run_in_netns(vm, namespace, "\n".join(lines))
    return NetnsNftProbe(namespace, "netdev", table_name, "ingress")


def payload_hex(payload):
    if isinstance(payload, str):
        payload = payload.encode()

    return payload.hex()


def make_netns_tcp_payload_probe(vm, namespace, payload_rules):
    table_name = f"phantun_payload_{uuid.uuid4().hex[:8]}"
    lines = [
        f"nft delete table inet {table_name} >/dev/null 2>&1 || true",
        f"nft add table inet {table_name}",
        (f"nft 'add chain inet {table_name} output " "{ type filter hook output priority 0; policy accept; }'"),
    ]

    for rule in payload_rules:
        payload_bits = len(rule["payload"].encode() if isinstance(rule["payload"], str) else rule["payload"]) * 8
        payload_value = payload_hex(rule["payload"])
        action = rule.get("action", "accept")
        lines.append(
            f"nft add rule inet {table_name} output "
            f'ip saddr {rule["src_addr"]} ip daddr {rule["dst_addr"]} '
            f'tcp sport {rule["src_port"]} tcp dport {rule["dst_port"]} '
            f"@th,160,{payload_bits} 0x{payload_value} "
            f'counter {action} comment "{rule["comment"]}"'
        )

    run_in_netns(vm, namespace, "\n".join(lines))
    return NetnsNftProbe(namespace, "inet", table_name, "output")


def make_netns_ingress_flag_drop_probe(vm, namespace, device, rules):
    table_name = f"phantun_ingress_{uuid.uuid4().hex[:8]}"
    lines = [
        f"nft delete table netdev {table_name} >/dev/null 2>&1 || true",
        f"nft add table netdev {table_name}",
        (
            f"nft 'add chain netdev {table_name} ingress "
            f"{{ type filter hook ingress device {device} priority 0; policy accept; }}'"
        ),
    ]

    for rule in rules:
        lines.append(
            f"nft 'add rule netdev {table_name} ingress "
            f"ip saddr {rule['src_addr']} ip daddr {rule['dst_addr']} "
            f"tcp sport {rule['src_port']} tcp dport {rule['dst_port']} "
            f"tcp flags & (fin|syn|rst|ack) == {rule['flags_expr']} "
            f"counter {rule.get('action', 'drop')} comment \"{rule['comment']}\"'"
        )

    run_in_netns(vm, namespace, "\n".join(lines))
    return NetnsNftProbe(namespace, "netdev", table_name, "ingress")


def make_netns_ingress_payload_drop_probe(vm, namespace, device, rules):
    table_name = f"phantun_ingress_{uuid.uuid4().hex[:8]}"
    lines = [
        f"nft delete table netdev {table_name} >/dev/null 2>&1 || true",
        f"nft add table netdev {table_name}",
        (
            f"nft 'add chain netdev {table_name} ingress "
            f"{{ type filter hook ingress device {device} priority 0; policy accept; }}'"
        ),
    ]

    for rule in rules:
        payload_bits = len(rule["payload"].encode() if isinstance(rule["payload"], str) else rule["payload"]) * 8
        payload_value = payload_hex(rule["payload"])
        lines.append(
            f"nft 'add rule netdev {table_name} ingress "
            f"ip saddr {rule['src_addr']} ip daddr {rule['dst_addr']} "
            f"tcp sport {rule['src_port']} tcp dport {rule['dst_port']} "
            f"@th,160,{payload_bits} 0x{payload_value} "
            f"counter {rule.get('action', 'drop')} comment \"{rule['comment']}\"'"
        )

    run_in_netns(vm, namespace, "\n".join(lines))
    return NetnsNftProbe(namespace, "netdev", table_name, "ingress")


def probe_comment(prefix, src_addr, src_port, dst_addr, dst_port):
    return f"{prefix}_{flow_tag(src_addr, src_port, dst_addr, dst_port)}"


def flow_tag(src_addr, src_port, dst_addr, dst_port):
    return f"{src_addr}_{src_port}_to_{dst_addr}_{dst_port}".replace(".", "_")
