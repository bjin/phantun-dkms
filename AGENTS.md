# AGENTS.md

This repo builds a Linux kernel module that runs Phantun-style fake-TCP in-kernel so UDP apps (especially WireGuard / wireguard-go) can use fake TCP without a TUN device.

## Layout
- `src/phantun_main.c`: module entry, config, netfilter hooks, protocol state machine
- `src/phantun_packet.[ch]`: IPv4/TCP/UDP parsing, packet build, checksum, tx/reinject helpers
- `src/phantun_flow.[ch]`: flow table, timers, retries, queued skb handling
- `Kbuild`, `Makefile`, `dkms.conf`: external module build / DKMS
- `prepare-kernels.py`: CLI to download/verify Ubuntu mainline kernels for matrix testing
- `DESIGN.md`: protocol/design notes
- `TESTING.md`: detailed integration testing instructions

## Build
- Bootstrap: `./autogen.sh`
- Configure: `./configure`
- Build module: `make`
- Refresh compile database: `make compile_commands`
- If autodetect fails, pass `KDIR=/path/to/kernel/build`
* Format C: `clang-format -i --style=file src/some_file.c` (only do this before staging changes)
* Format Python: `python3 -m black some_file.py` (only do this before staging changes)

## Testing
- Integration tests use `pytest` + `virtme-ng` (COW snapshots).
- Read `TESTING.md` before adding or changing tests.
- Prepare kernels: `python prepare-kernels.py <ver>`
- Run: `pytest tests [-v] [--kernel host|<ver>]`

## Important reminders
- This project is IPv4-only for now.
- Managed traffic is intercepted in netfilter `LOCAL_OUT` and `PRE_ROUTING`.
- Fake TCP is strict: 3-way handshake, seq/ack accounting, no FIN, RST on error.
- First payloads are mandatory control payloads and are never delivered to the UDP app.
- Initial initiator seq must be a random `u32` aligned so `seq % 4095 == 0`.
- For packet-loss tests, drop packets on veth ingress with nft `netdev` rules, not on sender `OUTPUT`, so loss is simulated on-path instead of as a local send failure.
- Prefer checked-in guest helper scripts under `tests/guest/` over embedded Python strings in tests; virtme-ng COW snapshots make tracked repo files visible inside the guest.
- Braces are structure, not text: if an edit emits `}`, prove the old `}` was removed, then re-read the surrounding block immediately.

## Coding style / safety
- LLVM styles with 4 space tab width, small static helpers, explicit return-value checks.
* Trailing whitespaces should by removed in C and Python code.
- Do not sleep in hook/atomic paths; use `GFP_ATOMIC` there.
- Prefer cached config/state in hot paths instead of reparsing strings.
- Use clear cleanup paths; keep teardown idempotent and avoid `BUG()` for recoverable failures.
- Prefer safe string handling and validate all inputs before using them.
