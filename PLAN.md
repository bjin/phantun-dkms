# phantun-dkms remaining plan

This plan replaces the original pre-`FLAWS.md` checklist.
It tracks only unfinished work that still matters after the recovery redesign.

## Phase 0 - selector model redesign

- [x] Rewrite `DESIGN.md` around two optional interception selectors instead of "managed ports plus optional remote filters"
  - [x] rename `managed_ports` to `managed_local_ports` everywhere the design describes interception policy
  - [x] replace `remote_ipv4_cidr` + `remote_port` with `managed_remote_peers` entries in `x.y.z.w:p` form
  - [x] define the three selector modes explicitly: local-only, peer-only, and local+peer intersection
  - [x] define the mirrored inbound-UDP drop rule and document that `PRE_ROUTING` placement avoids a reinjection bypass in v1
- [x] Reshape kernel configuration storage before changing hook behavior
  - [x] update `src/phantun.h` config types and limits for `managed_local_ports` and parsed `managed_remote_peers`
  - [x] update `src/phantun_main.c` module parameters, parsing helpers, validation, config snapshotting, and startup logging
  - [x] reject invalid selector configurations early: both lists empty, malformed peer strings, invalid/zero ports, and any out-of-range entries
- [x] Land a mechanical selector cutover with a buildable checkpoint
  - [x] rename tests, helper defaults, and module-load examples from `managed_ports` to `managed_local_ports`
  - [x] switch exact-peer configuration from `remote_ipv4_cidr` / `remote_port` to `managed_remote_peers`
  - [x] keep the existing `managed_local_ports` interception path behaviorally equivalent until the selector cutover lands
- [x] Implement selector-aware interception semantics in the netfilter hooks
  - [x] outbound UDP: match local source port iff `managed_local_ports` is configured, remote destination peer iff `managed_remote_peers` is configured
  - [x] inbound fake-TCP: existing flows still win first; new responder creation uses the same selector intersection
  - [x] peer-only mode must allow responder creation without a managed local-port gate
- [x] Enforce the new default inbound-UDP drop without black-holing translated traffic
  - [x] add an inbound UDP path whose match rule mirrors fake-TCP interception eligibility
  - [x] place that drop in `PRE_ROUTING` so module-reinjected decapsulated UDP stays outside the raw-wire drop path
  - [x] verify the drop path does not interfere with normal unmatched UDP or established flow recovery
- [x] Expand focused coverage before resuming later recovery work
  - [x] config validation: neither selector set, malformed `managed_remote_peers`, and bad per-entry ports are rejected
  - [x] peer-only mode: matching peers translate; non-matching peers remain raw UDP/TCP
  - [x] combined filters: both local port and remote peer must match
  - [x] inbound UDP drop: raw matching UDP is dropped, reinjected translated UDP still arrives
  - [x] run at least one DKMS/module-load smoke test plus selector-focused netns tests after each checkpoint


## Phase 1 - recovery refinement

- [x] Add a short quarantine window after accepting a replacement generation
  - [x] keep a small per-flow quarantine record for the immediately previous generation
  - [x] during the quarantine window, silently drop stale-looking old-generation traffic instead of replying with `RST`
  - [x] expire the quarantine state automatically after a short timeout
  - [x] keep the implementation bounded and cheap on the hot path
- [x] Document the quarantine rule in `DESIGN.md`

## Phase 2 - targeted state-machine coverage

- [x] Extend tests for the remaining high-value edge cases
  - [x] duplicate outbound UDP while half-open => still only one flow, with at most one queued skb
  - [x] duplicate initiator `SYN` after lost `SYN|ACK` => responder re-sends `SYN|ACK` without creating a second flow
  - [x] responder-owned queued UDP is released only after an initiator `ACK` covers an injected `handshake_response`
  - [x] unknown inbound non-`RST` fake-TCP still gets `RST|ACK`
  - [x] delayed old-generation packets after replacement are silently dropped during quarantine
- [x] Add at least one packet-loss or reorder-style test that exercises the quarantine path directly

## Phase 3 - operational hardening

- [x] Add ratelimited warnings for malformed or impossible fake-TCP traffic
- [x] Re-audit teardown and recovery paths for idempotency
- [x] Re-audit skb ownership across recovery and replacement paths
- [x] Re-audit hook/atomic paths to ensure no accidental sleep/regression was introduced by later changes

## Phase 4 - documentation cleanup

- [x] Document required firewall policy changes
  - [x] allow fake-TCP for selector-matched tuples instead of thinking only in terms of one managed port
  - [x] explain that raw inbound UDP matching the selectors is dropped by default while module-reinjected UDP is exempt
  - [x] clarify that old TUN NAT rules do not apply here
- [x] Document WireGuard MTU reduction guidance
- [x] Document the exact shaping semantics for `handshake_request` / `handshake_response`
- [x] Document this protocol as a kernel-to-kernel variant, not a compatibility mode for legacy userspace Phantun
- [x] Add concise operational examples for kernel WireGuard and `wireguard-go`

