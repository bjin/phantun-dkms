# AGENTS.md

This repo builds a Linux kernel module that runs Phantun-style fake-TCP in-kernel so UDP apps (especially WireGuard / wireguard-go) can use fake TCP without a TUN device.

## Layout
- `src/phantun_dkms_main.c`: module entry, config, netfilter hooks, protocol state machine
- `src/phantun_dkms_packet.[ch]`: IPv4/TCP/UDP parsing, packet build, checksum, tx/reinject helpers
- `src/phantun_dkms_flow.[ch]`: flow table, timers, retries, queued skb handling
- `Kbuild`, `Makefile`, `dkms.conf`: external module build / DKMS
- `DESIGN.md`: protocol/design notes
- `PLAN.md`: implementation checklist

## Build
- Build module: `make`
- Refresh compile database: `make compile_commands`
- Clean: `make clean`
- On NixOS, `Makefile` auto-detects kernel.dev in `/nix/store/.../lib/modules/$(uname -r)/build`
- If autodetect fails, pass `KDIR=/path/to/kernel/build`

## Important reminders
- Run `make compile_commands` when `compile_commands.json` was removed by `make clean` or when adding new `.c` files; existing entries are usually fine for edits to existing files.
- Even with fresh `compile_commands.json`, clangd may still complain about unsupported kernel flags; successful `make` is the source of truth.
- This project is IPv4-only for now.
- Managed traffic is intercepted in netfilter `LOCAL_OUT` and `PRE_ROUTING`.
- Fake TCP is strict: 3-way handshake, seq/ack accounting, no FIN, RST on error.
- First payloads are mandatory control payloads and are never delivered to the UDP app.
- Initial initiator seq must be a random `u32` aligned so `seq % 4095 == 0`.

## Coding style / safety
- Kernel style: tabs, small static helpers, explicit return-value checks.
- Do not sleep in hook/atomic paths; use `GFP_ATOMIC` there.
- Prefer cached config/state in hot paths instead of reparsing strings.
- Use clear cleanup paths; keep teardown idempotent and avoid `BUG()` for recoverable failures.
- Prefer safe string handling and validate all inputs before using them.
- When unsure, trust the built module over editor diagnostics.
