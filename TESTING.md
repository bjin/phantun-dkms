# End-to-end testing with virtme-ng

The integration tests use `pytest` and `virtme-ng` (vng). `virtme-ng` boots a QEMU virtual machine utilizing either the host kernel or a cached Ubuntu mainline kernel, while using a Copy-on-Write (COW) overlay of the host filesystem.

## Prerequisites

- `virtme-ng` installed on the host.
- `dpkg-deb` (for `prepare.py` to extract kernels).
- `git` (used by the test framework to copy only tracked files into the VM).

> **Important:** `virtme-ng` uses a **COW (Copy-on-Write)** filesystem. This means the guest VM sees a "snapshot" of the host filesystem at the moment it is created. Any subsequent modifications to host files (e.g. editing source code) will **not** be visible to the guest until the VM is restarted. 
>
> The test framework handles this by preparing a source tarball (`.dkms_copy.tar`) **before** spawning the VM, ensuring the latest git-tracked changes are captured.
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
pytest tests
```
### Test against all prepared kernels
```bash
pytest tests --all-kernels
```

### Test against a specific cached kernel
```bash
pytest tests --kernel v6.19.1
```

### Test against multiple kernels (Matrix)
```bash
pytest tests --kernel host --kernel v6.19.1
```

### Debugging
To see real-time output (including module load logs and VM setup):
```bash
pytest -s tests
```
Logs are automatically saved to `~/.cache/logs/phantun_tests/YYYYMMDD_HHMMSS/`.

## Framework Structure

- `tests/conftest.py`: Core framework. Provides:
  - `vm`: manages the virtme-ng / QEMU lifecycle
  - `phantun_module`: installs via DKMS once per session and reloads module parameters through `/etc/modprobe.d/phantun.conf`
  - `dmesg`: waits for new kernel log lines
- `tests/helpers.py`: Shared helper API for namespaces, guest scenario execution, nft probes, and module stat reads.
- `tests/guest/scenarios.py`: Small checked-in guest-side Python scenarios used by the tests.
- `tests/test_dkms.py`: DKMS install/load/reload and parameter validation coverage.
- `tests/test_config_stats.py`: selector configuration, `/sys/module/phantun/stats/*`, and basic selector-path behavior.
- `tests/test_handshakes.py`: shaping semantics and control-payload visibility rules.
- `tests/test_netns_udp.py`: basic namespace UDP-to-fake-TCP operation and multi-channel behavior.
- `tests/test_packet_loss.py`: handshake retries, payload-loss behavior, and state-machine behavior under packet loss.
- `tests/test_recovery.py`: collision handling, same-tuple replacement, quarantine, and unknown-packet recovery behavior.
- `tests/test_wireguard.py`: end-to-end coverage for kernel WireGuard and `wireguard-go`.

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
   - Do not drop on sender `OUTPUT` when you mean network loss; that turns the test into a local send failure instead.

7. **Read stats and logs through helpers**
   - Use `read_module_stats(vm)` / `read_module_stat(vm, name)` for `/sys/module/phantun/stats/*`.
   - Use the `dmesg` fixture when the observable result is a kernel log line instead of a packet or stat counter.

8. **Handle expected failures explicitly**
   - Pass `check=False` when the test intentionally expects a guest command or `modprobe` to fail.
   - For successful guest scenarios, use a local `assert_completed(...)` helper or explicit `pytest.fail(...)` checks for clearer errors.

9. **Keep assertions specific to the behavior under test**
   - For selector tests, check whether raw UDP escaped vs translated TCP appeared.
   - For shaping tests, check both on-wire payload probes and what the UDP app actually received.
   - For recovery tests, check both data-plane success and control-plane side effects such as `RST`, collision stats, queued packets, or quarantine behavior.

10. **Run the smallest useful subset first**
   - During development, prefer targeted invocations such as:
   - `pytest tests/test_packet_loss.py -q`
   - `pytest tests/test_recovery.py::test_established_bare_syn_replacement -q -vv`
   - Expand to the broader regression suite once the focused case passes.

11. **Control timing instead of hoping for it**
   - If a test requires specific events to cross in flight (e.g., simultaneous connection opens), do not rely on Python's sequential execution or small `time.sleep()` calls. The CPU scheduler will ruin your assumptions under load, causing flakiness.
   - Instead, enforce the timing in the data plane by adding latency with `tc netem`:
     ```python
     vm.run(["ip", "netns", "exec", NS_A, "tc", "qdisc", "add", "dev", VETH_A, "root", "netem", "delay", "150ms"])
     ```
   - This ensures packets sit in the queue long enough for the test scenario to trigger the necessary overlapping state transitions. Remember to clean up the `qdisc` in a `finally` block or when tearing down the topology.
