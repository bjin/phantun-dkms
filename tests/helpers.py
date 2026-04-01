import json
import shlex
import textwrap
import uuid

NS_A = "pht-a"
NS_B = "pht-b"
VETH_A = "veth-pht-a"
VETH_B = "veth-pht-b"
NS_ADDR_A = "10.200.0.1"
NS_ADDR_B = "10.200.0.2"
PORTS_A = (2222, 4444)
PORTS_B = (3333, 5555)


class NetnsOutputProbe:
    def __init__(self, namespace, table_name):
        self.namespace = namespace
        self.table_name = table_name

    def packets(self, vm, comment):
        res = run_in_netns(
            vm,
            self.namespace,
            ['nft', '-j', 'list', 'chain', 'inet', self.table_name, 'output'],
        )
        data = json.loads(res.stdout)

        for item in data.get('nftables', []):
            rule = item.get('rule')
            if not rule or rule.get('comment') != comment:
                continue

            for expr in rule.get('expr', []):
                counter = expr.get('counter')
                if counter is not None:
                    return counter.get('packets', 0)

        raise KeyError(f"Missing nft rule comment in {self.namespace}: {comment}")

    def cleanup(self, vm):
        run_in_netns(
            vm,
            self.namespace,
            ['nft', 'delete', 'table', 'inet', self.table_name],
            check=False,
        )


def run_guest_python(vm, script, check=True):
    body = textwrap.dedent(script).strip()
    command = f"python3 - <<'PY'\n{body}\nPY"
    return vm.run(command, check=check)


def run_in_netns(vm, namespace, cmd, check=True, **kwargs):
    if isinstance(cmd, list):
        return vm.run(['ip', 'netns', 'exec', namespace, *cmd], check=check, **kwargs)

    return vm.run(f"ip netns exec {shlex.quote(namespace)} bash -c {shlex.quote(cmd)}", check=check, **kwargs)


def require_guest_command(vm, command):
    res = vm.run(f"command -v {shlex.quote(command)}", check=False)
    return res.returncode == 0


def cleanup_netns_topology(vm, namespaces=(NS_A, NS_B)):
    for namespace in namespaces:
        vm.run(['ip', 'netns', 'del', namespace], check=False)


def ensure_netns_topology(vm):
    cleanup_netns_topology(vm)

    vm.run(['ip', 'netns', 'add', NS_A])
    vm.run(['ip', 'netns', 'add', NS_B])
    vm.run(['ip', 'link', 'add', VETH_A, 'type', 'veth', 'peer', 'name', VETH_B])
    vm.run(['ip', 'link', 'set', VETH_A, 'netns', NS_A])
    vm.run(['ip', 'link', 'set', VETH_B, 'netns', NS_B])

    run_in_netns(vm, NS_A, ['ip', 'link', 'set', 'lo', 'up'])
    run_in_netns(vm, NS_B, ['ip', 'link', 'set', 'lo', 'up'])

    run_in_netns(vm, NS_A, ['ip', 'addr', 'add', f'{NS_ADDR_A}/24', 'dev', VETH_A])
    run_in_netns(vm, NS_B, ['ip', 'addr', 'add', f'{NS_ADDR_B}/24', 'dev', VETH_B])
    run_in_netns(vm, NS_A, ['ip', 'link', 'set', VETH_A, 'up'])
    run_in_netns(vm, NS_B, ['ip', 'link', 'set', VETH_B, 'up'])
    run_in_netns(vm, NS_A, ['ip', 'route', 'add', f'{NS_ADDR_B}/32', 'dev', VETH_A])
    run_in_netns(vm, NS_B, ['ip', 'route', 'add', f'{NS_ADDR_A}/32', 'dev', VETH_B])


def make_netns_output_probe(vm, namespace, channels):
    table_name = f"phantun_netns_{uuid.uuid4().hex[:8]}"
    lines = [
        f"nft delete table inet {table_name} >/dev/null 2>&1 || true",
        f"nft add table inet {table_name}",
        (
            f"nft 'add chain inet {table_name} output "
            "{ type filter hook output priority 0; policy accept; }'"
        ),
    ]

    for src_addr, src_port, dst_addr, dst_port in channels:
        tag = flow_tag(src_addr, src_port, dst_addr, dst_port)
        lines.append(
            f'nft add rule inet {table_name} output '
            f'ip saddr {src_addr} ip daddr {dst_addr} '
            f'udp sport {src_port} udp dport {dst_port} '
            f'counter drop comment "udp_{tag}"'
        )
        lines.append(
            f'nft add rule inet {table_name} output '
            f'ip saddr {src_addr} ip daddr {dst_addr} '
            f'tcp sport {src_port} tcp dport {dst_port} '
            f'counter accept comment "tcp_{tag}"'
        )

    run_in_netns(vm, namespace, "\n".join(lines))
    return NetnsOutputProbe(namespace, table_name)


def probe_comment(prefix, src_addr, src_port, dst_addr, dst_port):
    return f"{prefix}_{flow_tag(src_addr, src_port, dst_addr, dst_port)}"


def flow_tag(src_addr, src_port, dst_addr, dst_port):
    return f"{src_addr}_{src_port}_to_{dst_addr}_{dst_port}".replace('.', '_')
