# phantun-dkms plan

## Phase 0 - freeze the v1 contract

- [x] Confirm v1 scope is exactly:
  - [x] IPv4 only
  - [x] kernel module only
  - [x] symmetric initiator/responder flows
  - [x] optional best-effort `handshake_request` / `handshake_response`
  - [x] one queued UDP skb per half-open flow
  - [x] no userspace-Phantun compatibility promise
- [x] Convert the design assumptions into module constants / config knobs:
  - [x] managed local ports
  - [x] optional handshake request / response bytes
  - [x] SYN / `SYN|ACK` retransmit timeout and retry count
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
  - [x] first-payload ignore / responder-response-pending flags
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
  - [x] transition directly to `ESTABLISHED` after the three-way handshake
  - [x] when `handshake_request` is configured, drop the first inbound payload without validating it
  - [x] when both control payloads are configured, send `ACK + handshake_response` and hold responder-owned queued UDP until a later initiator ACK covers it
  - [x] resend `SYN|ACK` on duplicate/retransmitted `SYN` while still half-open
- [x] Never let fake-TCP reach the real TCP stack

## Phase 6 - optional handshake payload shaping

- [x] If `handshake_request` is set, initiator sends `ACK + handshake_request` as its first fake-TCP payload
- [x] If `handshake_request` is not set, initiator flushes the queued first UDP packet immediately after `SYN|ACK` (or sends a pure `ACK` if nothing is queued)
- [x] Responder never verifies the first inbound payload; when request shaping is enabled it drops the first inbound payload it sees
- [x] If both `handshake_request` and `handshake_response` are set, responder sends `ACK + handshake_response` as its first responder payload
- [x] If only `handshake_response` is set, treat it as disabled and keep normal data flow
- [x] Initiator never verifies the first responder payload; when response shaping is enabled it drops the first inbound responder payload it sees
- [x] Missing, duplicated, or unexpected request/response shaping payloads do not reset or tear down the flow
- [x] Keep responder-owned queued UDP blocked only until a later initiator ACK covers an injected `handshake_response`

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
  - [ ] optional request payloads injected
  - [ ] optional response payloads injected
  - [ ] collisions won/lost
  - [ ] RST sent
  - [ ] UDP packets queued/dropped while half-open or while a responder control response is waiting for ACK
  - [ ] first inbound payloads dropped by shaping logic
- [ ] Add ratelimited warnings for malformed traffic
- [ ] Add a debug dump path for active flows
- [ ] Make teardown paths idempotent
- [ ] Audit all skb allocations and frees
- [ ] Re-audit atomic hook paths for no-sleep behavior and cached hot-path config use


## Phase 11 - testing

### Current coverage / framework baseline

- [x] `tests/test_dkms.py` covers DKMS build, module load, module unload, and reload-with-new-params inside the virtme-ng guest
- [x] `tests/conftest.py` provides the shared `vm`, `phantun_module`, and `dmesg` fixtures
- [ ] Keep Phase 11 aligned with the current pytest + virtme-ng conventions instead of inventing a second harness

### Shared test infrastructure additions

- [ ] Extend the existing fixture-driven framework; do not duplicate VM, DKMS, or dmesg lifecycle code in individual tests
- [ ] Add reusable guest-side helpers for common setup/teardown steps so `test_*.py` files stay short and readable:
  - [ ] network namespace create/delete
  - [ ] veth pair creation, addressing, link-up, and route setup
  - [ ] small UDP send/receive/echo helpers invoked via `vm.run(...)`
  - [ ] common wait/assert helpers for process completion and expected dmesg patterns
- [ ] Keep shared helpers in the current `tests/` support code path (`conftest.py` and, if they grow beyond a few small helpers, a dedicated helper module imported by tests)
- [ ] Keep assertions explicit: observable packet/result checks first, `dmesg` verification second, `pytest.fail(...)` for clear failures

### Loopback UDP translation tests

- [ ] Add `tests/test_loopback_udp.py` for same-VM coverage over `lo`
- [ ] Cover loopback traffic between `127.0.0.2` and `127.0.0.3` on the same managed UDP port
- [ ] Cover loopback traffic using the same loopback address but different UDP ports
- [ ] Verify the plain no-hint path: with no `handshake_request` configured, the first queued UDP payload is delivered end-to-end
- [ ] Verify idle timeout => flow is removed and the next UDP packet triggers a fresh handshake

### Optional handshake behavior tests

- [ ] Add `tests/test_handshakes.py` for focused first-payload-shaping coverage using the existing virtme-ng + pytest harness
- [ ] Reuse the shared UDP/helper code so these tests describe behavior, not shell plumbing
- [ ] `handshake_request` only => initiator injects the configured request, responder drops exactly one inbound payload, and later payloads continue normally
- [ ] `handshake_request` + `handshake_response` => responder injects the configured response, initiator drops exactly one inbound responder payload, and the flow stays established
- [ ] `handshake_response` without `handshake_request` => both sides behave like the no-hint path
- [ ] Duplicate pure ACKs and unexpected first-payload contents do not trigger `RST` or teardown once the three-way handshake has completed

### Namespace + veth UDP integration tests

- [ ] Add `tests/test_netns_udp.py` that creates two guest network namespaces and connects them with a veth pair
- [ ] Reuse the shared namespace/veth helpers so each test body describes topology plus expectations, not shell plumbing
- [ ] End-to-end raw UDP echo/data with no optional handshake payloads configured
- [ ] Request-only path across namespaces
- [ ] Request+response path across namespaces
- [ ] Duplicate outbound UDP while half-open => only one flow exists; one packet may be queued, later packets are dropped per design
- [ ] Duplicate initiator `SYN` after lost `SYN|ACK` => responder re-sends `SYN|ACK` without creating a second flow
- [ ] Responder-owned queued UDP is flushed only after a later initiator ACK covers an injected `handshake_response`
- [ ] If an injected `handshake_request` is lost, the next payload seen by the responder is dropped once, but the flow stays established
- [ ] If an injected `handshake_response` is lost, the initiator does not tear the flow down; later responder payloads still progress the flow
- [ ] Simultaneous initiation => deterministic winner and exactly one surviving flow
- [ ] Simultaneous-initiation loser with a queued UDP skb => packet is flushed by the responder rule or dropped on timeout, never retained indefinitely
- [ ] Unknown inbound non-`RST` fake-TCP => module sends `RST|ACK`
- [ ] Stray inbound `RST` or teardown path => local state is cleaned up without spurious flow recreation

### WireGuard end-to-end tests

- [ ] Add `tests/test_wireguard.py` using the same two-namespace veth topology, then create one kernel WireGuard gateway inside each namespace
- [ ] Verify kernel WireGuard peer-to-peer handshake and bidirectional payload delivery over the module
- [ ] Verify no endpoint rewrite to `127.0.0.1:*` is needed
- [ ] Verify the real peer IP/port remain visible to WireGuard so roaming semantics are preserved
- [ ] After the kernel-WireGuard path is stable, reuse the same topology helpers for `wireguard-go` peer-to-peer coverage
- [ ] After that, add mixed kernel WireGuard <-> `wireguard-go` coverage without creating a separate topology harness
- [ ] Run the fast loopback/handshake/netns suites first on `--kernel host`, then use the existing pytest kernel-matrix options for broader regression coverage of the stable scenarios


## Phase 12 - documentation

- [ ] Document required firewall policy changes:
  - [ ] allow TCP on managed port
  - [ ] allow local inbound UDP delivery on the managed port for reinjected payloads
  - [ ] old TUN NAT rules are not required for this mode
- [ ] Document MTU reduction requirements for WireGuard
- [ ] Document when optional control payloads are injected/ignored and when they are not delivered to the UDP app
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
9. Phase 11 loopback + handshake + namespace UDP tests
10. Phase 9
11. Phase 10
12. Phase 11 WireGuard end-to-end tests
13. Phase 12

## Explicit deferrals

- [ ] IPv6
- [ ] nftables / iptables front-end integration
- [ ] compatibility mode for old Phantun userspace binaries
- [ ] eBPF prototype
- [ ] TCP-option camouflage beyond what fake-tcp already does
