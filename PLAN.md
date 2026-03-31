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

- [ ] Add IPv4/TCP/UDP parsing helpers for skb-backed packets
- [ ] Add fake-TCP packet builders for:
  - [ ] `SYN`
  - [ ] `SYN|ACK`
  - [ ] `ACK`
  - [ ] `ACK + payload`
  - [ ] `RST`
  - [ ] `RST|ACK`
- [ ] Add checksum helpers for synthesized IPv4/TCP/UDP packets
- [ ] Add helpers to copy payload bytes safely out of skb data
- [ ] Add helpers to synthesize and transmit:
  - [ ] outbound fake-TCP skb via local output path
  - [ ] decapsulated UDP skb via local receive path

## Phase 3 - flow table and timers

- [ ] Define the canonical flow key and oriented endpoint fields
- [ ] Define the per-flow object:
  - [ ] role
  - [ ] state
  - [ ] seq / ack / last_ack
  - [ ] queued skb pointer
  - [ ] handshake verification flags
  - [ ] retry / timeout bookkeeping
  - [ ] last activity timestamp
- [ ] Choose locking/refcount strategy
  - [ ] one global table lock vs hashed buckets
  - [ ] per-flow spinlock
  - [ ] refcounted lifetime
- [ ] Add lookup/create/delete helpers
- [ ] Add idle GC timer/work
- [ ] Add retransmit timer logic for half-open flows

## Phase 4 - initiator path

- [ ] In `LOCAL_OUT`, match managed outbound UDP
- [ ] Lookup canonical tuple before creating a new flow
- [ ] Reuse established flows instead of opening duplicates
- [ ] If handshaking flow exists:
  - [ ] queue one UDP skb if empty
  - [ ] otherwise drop
- [ ] If no valid flow exists:
  - [ ] create initiator flow in `SYN_SENT`
  - [ ] generate the initiator's initial seq from the `u32` range and align it so `seq % 4095 == 0`
  - [ ] queue the triggering skb
  - [ ] send `SYN`
- [ ] Steal original UDP skb from the stack

## Phase 5 - responder path

- [ ] In `PRE_ROUTING`, match inbound fake-TCP for managed ports
- [ ] Reject unknown non-RST packets with `RST|ACK`
- [ ] For new `SYN`:
  - [ ] verify `seq % 4095 == 0`
  - [ ] create responder flow in `SYN_RCVD`
  - [ ] send `SYN|ACK`
- [ ] For existing responder flow:
  - [ ] validate final ACK number
  - [ ] transition to `AWAIT_HS_REQ` or directly consume `ACK + handshake_request`
  - [ ] resend `SYN|ACK` on duplicate/retransmitted `SYN` while still half-open
  - [ ] tolerate pure duplicate `ACK` while waiting for the first control payload
- [ ] Never let fake-TCP reach the real TCP stack

## Phase 6 - mandatory control payload handshake

- [ ] Implement initiator `HS_REQ_SENT`
  - [ ] after valid `SYN|ACK`, send `ACK + handshake_request`
  - [ ] retransmit on timeout if needed
  - [ ] resend `ACK + handshake_request` if a duplicate valid `SYN|ACK` arrives before response verification
- [ ] Implement responder request verification
  - [ ] exact length match
  - [ ] exact byte-for-byte match
  - [ ] mismatch => `RST` + destroy flow
- [ ] Implement responder post-response state (`HS_RESP_SENT`)
  - [ ] send `ACK + handshake_response`
  - [ ] resend the same control response on duplicate exact `handshake_request`
  - [ ] wait for later initiator traffic to acknowledge the response before flushing responder-owned queued UDP
- [ ] Implement initiator response verification
  - [ ] exact length match
  - [ ] exact byte-for-byte match
  - [ ] mismatch => `RST` + destroy flow
- [ ] Ensure control payloads are consumed internally and never delivered to UDP sockets
- [ ] Flush the initiator-owned queued UDP skb only after initiator response verification succeeds
- [ ] Define the responder-owned queued UDP release/drop rule explicitly
  - [ ] flush only after later initiator traffic acknowledges `handshake_response`
  - [ ] drop on teardown or handshake timeout

## Phase 7 - symmetric conflict resolution

- [ ] Handle duplicate local-initiation attempts cleanly
- [ ] Detect inbound bare `SYN` while local flow is `SYN_SENT`
- [ ] Implement deterministic tie-break rule
  - [ ] lower `(ip, port)` endpoint keeps initiator role
  - [ ] higher endpoint tears down local half-open flow and becomes responder
- [ ] Re-home the queued UDP skb when the local side loses the initiator race
- [ ] Apply the responder-owned queued UDP release/drop rule after tie-loss handover
- [ ] Add clear logging for collision decisions

## Phase 8 - established data path

- [ ] Translate outbound UDP -> fake-TCP `ACK + payload`
- [ ] Translate inbound fake-TCP payload -> local UDP reinjection
- [ ] Keep seq/ack accounting identical to `fake-tcp`
- [ ] Send idle ACKs only if still needed after the new in-kernel flow model is complete
- [ ] Destroy flows on peer `RST`
- [ ] Send local `RST` on teardown / timeout / validation failure

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
