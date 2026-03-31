# phantun-dkms plan

## Phase 0 - freeze the v1 contract

- [x] Confirm v1 scope is exactly:
  - [x] IPv4 only
  - [x] kernel module only
  - [x] symmetric initiator/responder flows
  - [x] mandatory `handshake_request` / `handshake_response`
  - [x] one queued UDP skb per half-open flow
  - [x] no userspace-Phantun compatibility promise
- [x] Convert the design assumptions into module constants / config knobs:
  - [x] managed local ports
  - [x] handshake request bytes
  - [x] handshake response bytes
  - [x] handshake timeout and retry count
  - [x] idle timeout
  - [x] optional remote IPv4 / remote port filters

## Phase 1 - repository and build skeleton

- [x] Add DKMS-friendly kernel module layout
- [x] Add `Kbuild` / Makefile pieces for out-of-tree builds
- [x] Add a minimal module init/exit path
- [x] Register/unregister the two netfilter hooks:
  - [x] `NF_INET_LOCAL_OUT` for outbound UDP capture
  - [x] `NF_INET_PRE_ROUTING` for inbound fake-TCP capture
- [x] Add structured logging macros and a module name prefix

## Phase 2 - packet helpers

- [x] Add IPv4/TCP/UDP parsing helpers for skb-backed packets
- [x] Add fake-TCP packet builders for:
  - [x] `SYN`
  - [x] `SYN|ACK`
  - [x] `ACK`
  - [x] `ACK + payload`
  - [x] `RST`
  - [x] `RST|ACK`
- [x] Add checksum helpers for synthesized IPv4/TCP/UDP packets
- [x] Add helpers to copy payload bytes safely out of skb data
- [x] Add helpers to synthesize and transmit:
  - [x] outbound fake-TCP skb via local output path
  - [x] decapsulated UDP skb via local receive path

## Phase 3 - flow table and timers

- [x] Define the canonical flow key and oriented endpoint fields
- [x] Define the per-flow object:
  - [x] role
  - [x] state
  - [x] seq / ack / last_ack
  - [x] queued skb pointer
  - [x] handshake verification flags
  - [x] retry / timeout bookkeeping
  - [x] last activity timestamp
- [x] Choose locking/refcount strategy
  - [x] one global table lock vs hashed buckets
  - [x] per-flow spinlock
  - [x] refcounted lifetime
- [x] Add lookup/create/delete helpers
- [x] Add idle GC timer/work
- [x] Add retransmit timer logic for half-open flows

## Phase 4 - initiator path

- [x] In `LOCAL_OUT`, match managed outbound UDP
- [x] Lookup canonical tuple before creating a new flow
- [x] Reuse established flows instead of opening duplicates
- [x] If handshaking flow exists:
  - [x] queue one UDP skb if empty
  - [x] otherwise drop
- [x] If no valid flow exists:
  - [x] create initiator flow in `SYN_SENT`
  - [x] generate the initiator's initial seq from the `u32` range and align it so `seq % 4095 == 0`
  - [x] queue the triggering skb
  - [x] send `SYN`
- [x] Steal original UDP skb from the stack

## Phase 5 - responder path

- [x] In `PRE_ROUTING`, match inbound fake-TCP for managed ports
- [x] Reject unknown non-RST packets with `RST|ACK`
- [x] For new `SYN`:
  - [x] verify `seq % 4095 == 0`
  - [x] create responder flow in `SYN_RCVD`
  - [x] send `SYN|ACK`
- [x] For existing responder flow:
  - [x] validate final ACK number
  - [x] transition to `AWAIT_HS_REQ` or directly consume `ACK + handshake_request`
  - [x] resend `SYN|ACK` on duplicate/retransmitted `SYN` while still half-open
  - [x] tolerate pure duplicate `ACK` while waiting for the first control payload
- [x] Never let fake-TCP reach the real TCP stack

## Phase 6 - mandatory control payload handshake

- [x] Implement initiator `HS_REQ_SENT`
  - [x] after valid `SYN|ACK`, send `ACK + handshake_request`
  - [x] retransmit on timeout if needed
  - [x] resend `ACK + handshake_request` if a duplicate valid `SYN|ACK` arrives before response verification
- [x] Implement responder request verification
  - [x] exact length match
  - [x] exact byte-for-byte match
  - [x] mismatch => `RST` + destroy flow
- [x] Implement responder post-response state (`HS_RESP_SENT`)
  - [x] send `ACK + handshake_response`
  - [x] resend the same control response on duplicate exact `handshake_request`
  - [x] wait for later initiator traffic to acknowledge the response before flushing responder-owned queued UDP
- [x] Implement initiator response verification
  - [x] exact length match
  - [x] exact byte-for-byte match
  - [x] mismatch => `RST` + destroy flow
- [x] Ensure control payloads are consumed internally and never delivered to UDP sockets
- [x] Flush the initiator-owned queued UDP skb only after initiator response verification succeeds
- [x] Define the responder-owned queued UDP release/drop rule explicitly
  - [x] flush only after later initiator traffic acknowledges `handshake_response`
  - [x] drop on teardown or handshake timeout

## Phase 7 - symmetric conflict resolution

- [x] Handle duplicate local-initiation attempts cleanly
- [x] Detect inbound bare `SYN` while local flow is `SYN_SENT`
- [x] Implement deterministic tie-break rule
  - [x] lower `(ip, port)` endpoint keeps initiator role
  - [x] higher endpoint tears down local half-open flow and becomes responder
- [x] Re-home the queued UDP skb when the local side loses the initiator race
- [x] Apply the responder-owned queued UDP release/drop rule after tie-loss handover
- [x] Add clear logging for collision decisions

## Phase 8 - established data path

- [x] Translate outbound UDP -> fake-TCP `ACK + payload`
- [x] Translate inbound fake-TCP payload -> local UDP reinjection
- [x] Keep seq/ack accounting identical to `fake-tcp`
- [x] Send idle ACKs only if still needed after the new in-kernel flow model is complete
- [x] Destroy flows on peer `RST`
- [x] Send local `RST` on teardown / timeout / validation failure

## Phase 9 - policy and configuration surface

- [ ] Start with the smallest practical config mechanism:
  - [ ] module params for a single managed port + handshake strings, or
  - [ ] generic netlink from the start if multi-port support is required immediately
- [ ] Support optional remote IPv4 CIDR restrictions
- [ ] Support optional remote port restrictions
- [ ] Document the exact matching rule for outbound interception
- [ ] Defer xtables/nftables integration until the core translator is proven

## Phase 10 - observability and safety

- [ ] Add counters for:
  - [ ] flows created
  - [ ] flows established
  - [ ] handshake request mismatches
  - [ ] handshake response mismatches
  - [ ] collisions won/lost
  - [ ] RST sent
  - [ ] UDP packets queued/dropped during handshake
- [ ] Add ratelimited warnings for malformed traffic
- [ ] Add a debug dump path for active flows
- [ ] Make teardown paths idempotent
- [ ] Audit all skb allocations and frees
- [ ] Re-audit atomic hook paths for no-sleep behavior and cached hot-path config use


## Phase 11 - testing

### Unit-ish / helper validation

- [ ] Verify fake-TCP packet builders produce correct flags, seq, ack, and checksums
- [ ] Verify control payload verification is exact and rejects prefix/suffix mismatches
- [ ] Verify canonical tuple ordering and tie-break behavior

### Namespace / integration tests

- [ ] Two network namespaces, one managed port, raw UDP echo
- [ ] Initiator-only handshake success path
- [ ] Request mismatch => responder sends `RST`
- [ ] Response mismatch => initiator sends `RST`
- [ ] Duplicate outbound UDP while half-open => only one flow exists
- [ ] Duplicate initiator `SYN` after lost `SYN|ACK` => responder re-sends `SYN|ACK` without creating a second flow
- [ ] Duplicate responder `SYN|ACK` before response verification => initiator re-sends `ACK + handshake_request`
- [ ] Lost `handshake_response` => initiator repeats request and responder re-sends the control response instead of treating it as user data
- [ ] Simultaneous initiation => deterministic winner, one surviving flow
- [ ] Simultaneous-initiation loser with a queued UDP skb => packet is either flushed by the responder rule or dropped on timeout, never retained indefinitely
- [ ] Idle timeout => flow removed and next UDP triggers a new handshake

### WireGuard-specific tests

- [ ] kernel WireGuard peer-to-peer over the module
- [ ] `wireguard-go` peer-to-peer over the module
- [ ] mixed kernel WireGuard <-> `wireguard-go`
- [ ] verify no endpoint rewrite to `127.0.0.1:*` is needed
- [ ] verify roaming still works because the real peer IP/port stay visible to WireGuard

## Phase 12 - documentation

- [ ] Document required firewall policy changes:
  - [ ] allow TCP on managed port
  - [ ] allow local inbound UDP delivery on the managed port for reinjected payloads
  - [ ] old TUN NAT rules are not required for this mode
- [ ] Document MTU reduction requirements for WireGuard
- [ ] Document that control payloads are internal and not delivered to the UDP app
- [ ] Document incompatibility with existing userspace client/server assumptions
- [ ] Add operational examples for:
  - [ ] kernel WireGuard
  - [ ] `wireguard-go`

## Suggested execution order

1. Phase 1
2. Phase 2
3. Phase 3
4. Phase 4
5. Phase 5
6. Phase 6
7. Phase 7
8. Phase 8
9. Phase 11 basic namespace tests
10. Phase 9
11. Phase 10
12. Phase 11 WireGuard coverage
13. Phase 12

## Explicit deferrals

- [ ] IPv6
- [ ] nftables / iptables front-end integration
- [ ] compatibility mode for old Phantun userspace binaries
- [ ] eBPF prototype
- [ ] TCP-option camouflage beyond what fake-tcp already does
