# phantun-dkms remaining plan

This plan replaces the original pre-`FLAWS.md` checklist.
It tracks only unfinished work that still matters after the recovery redesign.

## Phase 1 - recovery refinement

- [ ] Add a short quarantine window after accepting a replacement generation
  - [ ] keep a small per-flow quarantine record for the immediately previous generation
  - [ ] during the quarantine window, silently drop stale-looking old-generation traffic instead of replying with `RST`
  - [ ] expire the quarantine state automatically after a short timeout
  - [ ] keep the implementation bounded and cheap on the hot path
- [ ] Document the quarantine rule in `DESIGN.md`

## Phase 2 - targeted state-machine coverage

- [ ] Extend tests for the remaining high-value edge cases
  - [ ] duplicate outbound UDP while half-open => still only one flow, with at most one queued skb
  - [ ] duplicate initiator `SYN` after lost `SYN|ACK` => responder re-sends `SYN|ACK` without creating a second flow
  - [ ] responder-owned queued UDP is released only after an initiator `ACK` covers an injected `handshake_response`
  - [ ] unknown inbound non-`RST` fake-TCP still gets `RST|ACK`
  - [ ] delayed old-generation packets after replacement are silently dropped during quarantine
- [ ] Add at least one packet-loss or reorder-style test that exercises the quarantine path directly

## Phase 3 - operational hardening

- [ ] Add ratelimited warnings for malformed or impossible fake-TCP traffic
- [ ] Re-audit teardown and recovery paths for idempotency
- [ ] Re-audit skb ownership across recovery and replacement paths
- [ ] Re-audit hook/atomic paths to ensure no accidental sleep/regression was introduced by later changes

## Phase 4 - documentation cleanup

- [ ] Document required firewall policy changes
  - [ ] allow TCP on the managed port
  - [ ] allow local inbound UDP delivery on the managed port for reinjected payloads
  - [ ] clarify that old TUN NAT rules do not apply here
- [ ] Document WireGuard MTU reduction guidance
- [ ] Document the exact shaping semantics for `handshake_request` / `handshake_response`
- [ ] Document this protocol as a kernel-to-kernel variant, not a compatibility mode for legacy userspace Phantun
- [ ] Add concise operational examples for kernel WireGuard and `wireguard-go`

