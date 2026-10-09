# End-to-end testing with virtme-ng

The integration tests use `pytest` and `virtme-ng` (vng). `virtme-ng` boots a QEMU virtual machine utilizing either the host kernel or a cached Ubuntu mainline kernel, while using a Copy-on-Write (COW) overlay of the host filesystem.

## Prerequisites

- `virtme-ng` installed on the host.
- `dpkg-deb` (for `prepare.py` to extract kernels).
- `git` (used by the test framework to copy only tracked files into the VM).

> **Important:** `virtme-ng` uses a **COW (Copy-on-Write)** filesystem. This means the guest VM sees a "snapshot" of the host filesystem at the moment it is created. Any subsequent modifications to host files (e.g. editing source code) will **not** be visible to the guest until the VM is restarted. 
>
> The test framework handles this by preparing a source tarball (`.dkms_copy.tar`) **before** spawning the VM, ensuring the latest git-tracked changes are captured.

### Arch Linux guest SSH startup

Arch's OpenSSH uses `/usr/share/empty.sshd` as its pre-authentication chroot. If that directory inherits non-root ownership or group/other write permissions, OpenSSH rejects it and VM startup times out. Debian/Ubuntu use `/run/sshd`, which virtme-ng already creates as guest root, so they need no such workaround.

The harness runs `tests/guest/bootstrap.py` through `vng --exec`, independently of SSH. For the existing Arch directory, it sets non-root ownership to `0:0` and removes group/other write bits as needed. Valid or absent directories are left alone. Changes stay in the guest's COW overlay and do not modify the host.

This guest-SSH setup gap was reproduced on 2026-10-04 with upstream virtme-ng [`main` at `da73944`](https://github.com/arighi/virtme-ng/blob/da73944e81bafd74de78fe37e08ff944b53e4d4e/virtme/guest/virtme-sshd-script). Upstream could handle Arch's chroot in that script before starting `sshd`.

## Preparing Kernels

Before testing against a specific Ubuntu kernel version, you must prepare it on the host:

```bash
# Prepare one or more versions
python prepare-kernels.py v6.19.1 v6.19.2

# List all prepared kernels and verify their integrity
python prepare-kernels.py
```

This script:
1. Downloads `.deb` packages from the Ubuntu mainline repository to `kernels/<version>/`.
2. Extracts them using `dpkg-deb`.
3. Verifies the integrity of `vmlinuz` and kernel headers (automatically cleans up corrupted ones).
4. Repairs symlinks so DKMS can find headers correctly within the VM.

## Running the tests

### Test against host kernel (default)
```bash
pytest
```
The pytest configuration in `pyproject.toml` limits default collection to `tests/`, so bare `pytest` does not recurse into prepared kernel trees or build artifacts.

### Test against all prepared kernels
```bash
pytest --all-kernels
```

### Test against a specific cached kernel
```bash
pytest --kernel v6.19.1
```

### Test against multiple kernels (Matrix)
```bash
pytest --kernel host --kernel v6.19.1
```

### Debugging
To see real-time output (including module load logs and VM setup):
```bash
pytest -s
```
Logs are automatically saved to `~/.cache/logs/phantun_tests/YYYYMMDD_HHMMSS/`.

## Framework Structure

- `tests/conftest.py`: Core framework. Provides:
  - `vm`: manages the virtme-ng / QEMU lifecycle (4G guest RAM)
  - `phantun_module`: installs via DKMS once per session and reloads module parameters through `/etc/modprobe.d/phantun.conf`
  - `dmesg`: waits for new kernel log lines
  - `ipv6_runtime`: skips the test unless this module build loads with `ip_families=ipv6`; request it with `@pytest.mark.usefixtures("ipv6_runtime")`
- `tests/helpers.py`: Shared helper API for namespaces, guest scenario execution, nft probes, module loading, and module stat reads.
- `tests/guest/bootstrap.py`: repairs Arch's pre-auth chroot ownership and permissions inside the guest.
- `tests/guest/scenarios.py`: Small checked-in guest-side Python scenarios used by the tests.

Test modules are grouped by the behavior under test, not by address family; IPv6 cases sit next to their IPv4 counterparts.

| Module | Covers |
|---|---|
| `tests/test_module_lifecycle.py` | Kernel-version sanity, DKMS-installed module load, unload, and reload |
| `tests/test_module_params.py` | Load-time parameter parsing and rejection (shaping payload encodings and sizes, `reopen_guard_bytes`, timers, selectors, `managed_netns`) and derived settings such as auto `replacement_protect_ms` |
| `tests/test_module_stats.py` | `/sys/module/phantun/stats/*` counters and `skb:kfree_skb` drop attribution |
| `tests/test_port_reservation.py` | `reserved_local_ports` TCP reservations across selector modes, namespaces, and address families |
| `tests/test_selectors.py` | Which traffic is owned: `managed_local_ports`, `managed_remote_peers`, `managed_netns`, `ip_families`, loopback, and dropping raw UDP sent to owned ports (fragments, IPv6 Destination Options) |
| `tests/test_translation.py` | Basic UDP to fake-TCP translation: IPv4/IPv6 ping-pong, echo, four concurrent channels, zero-length UDP |
| `tests/test_checksums.py` | Generated fake-TCP checksum state, reinjected UDP checksums at payload and GSO boundaries in both families, inbound bad-checksum drops |
| `tests/test_payload_size.py` | Established-flow UDP GSO superframes, oversized and path-MTU payloads in both directions |
| `tests/test_netfilter.py` | Coexistence with conntrack/firewall policies, reinjection-cookie trust, forwarded fake TCP |
| `tests/test_metadata_routing.py` | Mark, DSCP, traffic class, UID, and oif propagation to fake TCP and route-cache keying |
| `tests/test_topology.py` | Secondary, deprecated, and link-local addresses; route changes, device down, and address removal |
| `tests/test_handshake_half_open.py` | SYN and SYN\|ACK loss retries, retry exhaustion under continued stale ACK/data, half-open limits, queued UDP survival and exactly-once delivery through recovery |
| `tests/test_handshake_shaping.py` | `handshake_request` / `handshake_response` injection, persistent reserved-slot replay suppression, mandatory control ACKs, responder queue hold/release (including opening application replay delivery without release), loss, and exact half-space disarm |
| `tests/test_emit_failures.py` | Local fake-TCP send failures (drops on the sender's `OUTPUT`) in each handshake and established state |
| `tests/test_liveness.py` | Healthy idle survival, periodic probes despite successful/failed output, bidirectional payload-loss survival over a delayed live control path, half-open queued UDP recovery before hard idle, inbound-loss timeout and reinitiation, idle-ACK suppression |
| `tests/test_replacement.py` | Simultaneous-open collisions, established generation replacement and protection, quarantine, reordered opener retry and data recovery, retired-record eviction |
| `tests/test_inbound_validation.py` | Inbound flag, ACK, and sequence validation; wrong-final-ACK retention followed by valid completion; unknown-tuple RSTs |
| `tests/test_wireguard.py` | End-to-end kernel WireGuard over IPv4 and IPv6 underlays, endpoint roaming, TIME_WAIT ACK metadata |

The raw-IP checksum cases in `tests/test_checksums.py` verify packet bytes
independently of skb checksum flags, but do not force nonlinear source skbs or
odd source offsets. Dedicated coverage of nonlinear layouts, odd offsets,
source-range rejection, and computed-zero checksums is not part of the
persistent suite. Those cases were exercised using a temporary kernel probe; no
reusable probe is checked into this repository.

### Where new tests and helpers go

- Add a test to the module that owns the behavior it asserts. An IPv6 variant goes next to its IPv4 counterpart and requests `ipv6_runtime`.
- Helpers used by more than one test module live in `tests/helpers.py`; helpers used by a single module stay in that module. Test modules never import from other `test_*.py` modules.
- Shared defaults in `tests/helpers.py`:
  - `MANAGED_LOCAL_PORTS`, `REQ`, `RESP`: standard selector and shaping payloads.
  - `load_managed_module(phantun_module, **kwargs)`: loads with `managed_netns=all` and `MANAGED_LOCAL_PORTS`.
  - `load_fast_liveness_module(phantun_module, **kwargs)`: same, plus a 1s keepalive interval, 2 keepalive misses, and 20 handshake retries.

### Best Practices

1. **Use the `phantun_module` fixture for module lifecycle**
   - Call `phantun_module.load(...)` with the parameters under test, for example:
   - `managed_local_ports="51820"`
   - `managed_remote_peers="198.51.100.20:51820"`
   - The helper unloads/reloads the module cleanly between parameter sets.

2. **Remember the VM sees a COW snapshot**
   - If you change tracked files after the VM has already booted, the guest will not see those edits.
   - Restart the pytest session / VM after source changes that must be visible inside the guest.

3. **Use the namespace helpers instead of hand-rolled shell**
   - `ensure_netns_topology(vm)` and `cleanup_netns_topology(vm)` create and tear down the standard `pht-a` / `pht-b` veth setup.
   - `run_netns_scenario(...)` is for synchronous guest actions.
   - `spawn_netns_scenario(...)` is for long-running concurrent actors like servers, delayed senders, or capture helpers.

4. **Prefer checked-in guest scenarios over inline Python**
   - Add reusable guest behavior to `tests/guest/scenarios.py` instead of embedding heredoc Python in tests.
   - This keeps scenarios visible to the guest through the tracked-file tarball and avoids duplicated test logic.

5. **Use the right nft probe for the question you are asking**
   - `make_netns_output_probe(...)`: verify raw UDP vs translated TCP on namespace `output`.
   - `make_netns_output_flag_probe(...)`: verify specific TCP flag patterns (`SYN`, `SYN|ACK`, `RST|ACK`, keepalive ACKs, etc.).
   - `make_netns_tcp_payload_probe(...)`: verify specific TCP payloads such as shaping/control payloads or queued responder data.
   - `make_netns_ingress_flag_drop_probe(...)`: drop packets on veth ingress for packet-loss tests.
   - `make_netns_ingress_payload_drop_probe(...)`: drop specific TCP payloads on veth ingress.

6. **For packet-loss tests, drop on veth ingress, not sender output**
   - Use the `netdev` ingress probes on `VETH_A` / `VETH_B` to simulate on-path loss.
   - Do not drop on sender `OUTPUT` when you mean network loss; that turns the test into a local send failure instead (covered by `tests/test_emit_failures.py`).

7. **Read stats and logs through helpers**
   - Use `read_module_stats(vm)` / `read_module_stat(vm, name)` for `/sys/module/phantun/stats/*`.
   - Use the `dmesg` fixture when the observable result is a kernel log line instead of a packet or stat counter.

8. **Handle expected failures explicitly**
   - Pass `check=False` when the test intentionally expects a guest command or `modprobe` to fail.
   - For successful guest scenarios, use `assert_completed(...)` from `tests/helpers.py` or explicit `pytest.fail(...)` checks for clearer errors.

9. **Keep assertions specific to the behavior under test**
   - For selector tests, check whether raw UDP escaped vs translated TCP appeared.
   - For shaping tests, check both on-wire payload probes and what the UDP app actually received.
   - For recovery tests, check both data-plane success and control-plane side effects such as `RST`, collision stats, queued packets, or quarantine behavior.

10. **Run the smallest useful subset first**
   - During development, prefer targeted invocations such as:
   - `pytest tests/test_handshake_half_open.py -q`
   - `pytest tests/test_replacement.py::test_established_bare_syn_replacement -q -vv`
   - Expand to the broader regression suite once the focused case passes.

11. **Control timing instead of hoping for it**
   - If a test requires specific events to cross in flight (e.g., simultaneous connection opens), do not rely on Python's sequential execution or small `time.sleep()` calls. The CPU scheduler will ruin your assumptions under load, causing flakiness.
   - Instead, enforce the timing in the data plane by adding latency with `tc netem`:
     ```python
     vm.run(["ip", "netns", "exec", NS_A, "tc", "qdisc", "add", "dev", VETH_A, "root", "netem", "delay", "150ms"])
     ```
   - This ensures packets sit in the queue long enough for the test scenario to trigger the necessary overlapping state transitions. Remember to clean up the `qdisc` in a `finally` block or when tearing down the topology.

## GitHub Actions slowness warning

> **Important:** GitHub's hosted runners are already virtualized. Our test framework then boots another QEMU guest through `virtme-ng`, so CI is effectively nested QEMU. Tests that finish quickly on a local machine can run much slower on GitHub Actions, and short-lived states may come and go between host-side polls.

When adding or debugging tests, assume GitHub CI is the worst-case scheduler and timing environment:

- Prefer observables that persist long enough to survive slow polling: nft counters, cumulative module stats, guest-visible outcomes, or dmesg lines. Do not make a test depend only on catching a brief intermediate value such as a momentary `flows_current` spike.
- If a test must poll guest state, read it in as few guest round-trips as possible. Extend shared helpers when needed instead of open-coding many small SSH commands inside a loop.
- Use `tc netem` or another data-plane control to force ordering/overlap. Do not rely on tiny `time.sleep()` gaps to create races that only happen on a fast laptop.
- Before merging a timing-sensitive test, ask whether the assertion still holds if the runner is 5-10x slower and host/guest time are both noisy. If not, the test is probably checking the wrong thing.
