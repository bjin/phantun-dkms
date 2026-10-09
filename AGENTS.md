# AGENTS.md

This repo builds a Linux kernel module that runs Phantun-style fake-TCP in-kernel so UDP apps (especially WireGuard / wireguard-go) can use fake TCP without a TUN device.

## Layout
- `src/phantun_main.c`: module entry, netfilter hooks, protocol state machine
- `src/phantun_config.c`: single-pass parameter parsing, validation, config/payload ownership
- `src/phantun_netns.c`: namespace lifecycle, TCP reservations, defrag, topology notifiers
- `src/phantun_packet.[ch]`: IPv4/IPv6/TCP/UDP parsing, packet build, checksum, tx/reinject helpers
- `src/phantun_flow.[ch]`: flow table, timers, retries, queued skb handling
- `Kbuild`, `Makefile`, `dkms.conf`: external module build / DKMS
- `flake.nix`, `flake.lock`: Nix flake outputs for building the module and exporting the NixOS module; keep in sync with Nix packaging/module changes
- `nix/package.nix`: Nix derivation for building `phantun.ko` against a passed `kernel`
- `nix/nixos-module.nix`: NixOS module for typed `services.phantun` options, modprobe parameter rendering, and boot-time loading
- `prepare-kernels.py`: CLI to download/verify Ubuntu mainline kernels for matrix testing
- `DESIGN.md`: protocol/design notes
- `TESTING.md`: detailed integration testing instructions

## Build
- Build module: `make`
- Refresh compile database: `make compile_commands`
- `make` bootstraps `./autogen.sh` and `./configure` only when generated files are missing or stale.
- If autodetect fails, pass `KDIR=/path/to/kernel/build`
* Format: `./format.sh`

## Testing
- Integration tests use `pytest` + `virtme-ng` (COW snapshots).
- Read `TESTING.md` before adding or changing tests.
- Prepare kernels: `python prepare-kernels.py <ver>`
- Run: `pytest [-v] [--kernel host|<ver>]`

## Important reminders
- Managed traffic is intercepted in netfilter `LOCAL_OUT` and `PRE_ROUTING`.
- Fake TCP is strict: 3-way handshake, seq/ack accounting, no FIN, RST on error.
- Configured first-payload shaping hints are optional, best-effort control bytes. Losing or reordering them must not block ordinary UDP progress.
- Initial initiator seq must be a random `u32` aligned so `seq % 4095 == 0`.
- For packet-loss tests, drop packets on veth ingress with nft `netdev` rules, not on sender `OUTPUT`, so loss is simulated on-path instead of as a local send failure.
- Prefer checked-in guest helper scripts under `tests/guest/` over embedded Python strings in tests; virtme-ng COW snapshots make tracked repo files visible inside the guest.
- Braces are structure, not text: if an edit emits `}`, prove the old `}` was removed, then re-read the surrounding block immediately.

## Tolerance contract
- The carrier is raw UDP, not a reliable TCP byte stream. Design and test for both heavy loss (including 70% loss with 200ms+ latency) and fast LANs (10Gbps with sub-millisecond latency). A loss percentage does not bound bursts, outage duration, or reordering.
- Do not introduce an established receive window, contiguous-delivery prerequisite, or general payload deduplication. Sequence/ACK bookkeeping must not turn missing earlier packets into rejection of later valid UDP data.
- A previous >=10MB receive-window experiment was reverted because rolling its state depended on unreliable packets. Enlarging such a window does not repair the dependency.
- Prefer ordinary UDP progress over perfect shaping replay suppression. Do not add persistent payload-drop masks whose retirement depends on observing peer sequence progress, or wait for shaping ACKs/further client data before releasing responder UDP. A documented one-shot shaping exception is bounded; arbitrarily delayed duplicates and sequence reuse are not perfectly distinguishable on this wire format.
- Keepalive opportunities must not be indefinitely postponed by accepted RX or unconfirmed local TX. Local output success is not peer receipt, and live keepalives do not prove a queued application datagram can make progress.
- Preserve a full responder completion opportunity for the one-time simultaneous-open role handoff. Keep admission/queue ownership atomic without silently spending the new phase's budget in the old phase.
- Do not infer generation age from SYN arrival order or random ISN magnitude. Do not add half-open replacement/quarantine policies that exclude a useful opener solely because another opener arrived later.
- Bounded admission, handshake retries, liveness, and hard-idle expiry remain valid resource policies, not loss-free service guarantees. Document capacity and timer tradeoffs; do not require every prior payload or any single best-effort shaping packet to arrive.
- Review protocol changes against their immediate parent with loss, reordering, duplication, wrap, late handoff, and one-way traffic traces. Distinguish random loss from correlated/size-selective loss, application retransmission (new sequence) from a network duplicate, and simulated sequence wrap from measured line-rate throughput.
- See DESIGN.md section 2.3 for the normative contract and its limits.

## Coding style / safety
- LLVM styles with 4 space tab width, small static helpers, explicit return-value checks.
* Trailing whitespaces should by removed in C and Python code.
- Write comments for an experienced kernel reviewer with little to no `DESIGN.md` context: explain non-obvious invariants, state-machine transitions, lock ownership, and edge cases; do not comment obvious code.
- Do not sleep in hook/atomic paths; use `GFP_ATOMIC` there.
- Prefer cached config/state in hot paths instead of reparsing strings.
- Use clear cleanup paths; keep teardown idempotent and avoid `BUG()` for recoverable failures.
- Prefer safe string handling and validate all inputs before using them.
