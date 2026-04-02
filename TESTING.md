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

- `tests/conftest.py`: Core framework. Provides the `vm` fixture (manages QEMU lifecycle) and `phantun_module` fixture (manages DKMS install/load lifecycle).
- `tests/prepare.py`: CLI tool for kernel cache management.
- `tests/test_*.py`: Actual test cases.

### Best Practices
1. **Use the `phantun_module` fixture**: It automatically handles `dkms install` at the start of the session and `dkms uninstall` at the end.
2. **Dynamic Loading**: Use `phantun_module.load(param=value)` to test different module parameters. This helper automatically unloads the module and updates `/etc/modprobe.d/phantun.conf` before reloading.
3. **Log Verification**: Use the `dmesg` fixture to verify kernel output.
   ```python
   def test_my_feature(phantun_module, dmesg):
       phantun_module.load(managed_local_ports="9999")
       if not dmesg.wait_for(r"expected log message", timeout=5):
           pytest.fail("Feature failed to log success")
   ```
4. **Command Execution**: Use `vm.run(['command', 'arg1'])`. Pass a **list** for standard commands. Pass a **string** only if you need shell features like redirection (`>`) or pipes (`|`).
5. **Assertions**: Avoid Python's `assert` statement for critical checks; prefer `if not condition: pytest.fail("message")` for better error clarity in the test reports.
