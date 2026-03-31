# End-to-end testing with virtme-ng

The integration tests run using `pytest` and `virtme-ng` (vng). `virtme-ng` boots a fresh qemu virtual machine utilizing the host kernel (`uname -r`), while using a Copy-on-Write (COW) overlay of the host filesystem. This means testing operations (like compiling modules, installing packages via `dkms`, loading modules with `insmod`/`modprobe`) can safely happen inside the VM without affecting the host system.

## Running the tests

Simply run:
```bash
pytest tests
```

To see output during execution (including SSH setup and module messages):
```bash
pytest -s tests
```

## Structure

- `tests/conftest.py`: Defines the `vng_vm` pytest fixture, scoped to the session. This fixture spins up the `virtme-ng` instance via an SSH proxy server (`--ssh` mode with an empty root password), waits for it to become ready, and provides an `ssh_run` helper to run commands securely and transparently as `root` in the guest VM. It also dumps a `dmesg -w` stream inside the container to `dmesg.log`.
- `tests/test_module.py`: Tests actual functionality. Currently covers:
  - Sanity check that the guest kernel matches the host kernel.
  - Test compiling the module from the host's read-write mount using `make` and inserting it via `insmod`. Checks `dmesg` for success and unloads the module.
  - Test packaging the module with DKMS. Copies the host directory to `/usr/src/phantun-0.1.0` and runs `dkms add/build/install`. It configures module load parameters inside `/etc/modprobe.d/phantun.conf`, runs `modprobe phantun`, and ensures it cleanly unloads and uninstalls.
