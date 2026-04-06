# phantun-dkms design

## 1. Scope

This document describes the v1 design for running Phantun-style fake-TCP directly in the Linux kernel, without a TUN device.

Primary goals:

- Work transparently with:
  - kernel WireGuard
  - `wireguard-go`
- IPv4 only in v1
- No TUN-side DNAT/SNAT topology
- Preserve the fake-TCP three-way handshake, sequence/ack behavior, and RST-on-error behavior from `fake-tcp`
- Add optional first-payload shaping so configured request/response bytes can make the opening packets look ASCII-like without becoming a required verified sub-protocol
- Remove fixed client/server node roles; each flow has only:
  - initiator
  - responder

Non-goals for v1:

- IPv6
- userspace Phantun interoperability guarantees
- eBPF implementation
- xtables target as the core data plane
- real TCP socket/listener integration

## 2. What is carried forward from the references

### `fake-tcp`

From `../phantun/fake-tcp/src/lib.rs`:

- Three-way handshake stays strict:
  - initiator sends `SYN`
  - responder replies `SYN|ACK`
  - initiator finishes with `ACK`
- responder only accepts `SYN` when `seq % 4095 == 0`
- data packets are `ACK` packets carrying UDP payload as TCP payload
- `seq` grows by payload length on send
- `ack` tracks peer `seq + payload_len` on receive
- no FIN/CLOSE state machine
- `RST` is the only teardown/error signal
- unknown or malformed packets are kicked with `RST`

These properties are kept.

### userspace Phantun handshake-packet behavior

From `../phantun/phantun/src/bin/client.rs` and `server.rs`:

- Phantun can inject a configured first payload via `--handshake-packet`
- The peer can skip delivering that payload to UDP via `--ignore-first-packet`

For the kernel design, this becomes a best-effort shaping hint rather than a verified sub-protocol:

- `handshake_request` can optionally replace the initiator's first user payload
- `handshake_response` can optionally replace the responder's first user payload, but only when `handshake_request` is also configured
- when those hints are active, the matching first inbound payload is defined by the lowest payload sequence number reserved for that flow generation, not by arrival order
- loss, duplication, delay, or absence of those payloads does not break flow establishment; later higher-sequence payloads may still proceed normally

### `xt_wgobfs`

`../xt_wgobfs` is a good reference for transparent interception around existing WireGuard UDP sockets, but not for the actual translation engine.

What we borrow:

- transparent operation against existing kernel/userspace WireGuard sockets
- in-kernel packet interception on normal network paths
- no endpoint rewrite to `127.0.0.1:...`

What we do not borrow:

- xtables-target-only architecture
- in-place packet mangling assumptions

`xt_wgobfs` mutates UDP packets in place. This project must translate UDP <-> fake TCP and own per-flow handshake/state/timers, which is materially larger.

## 3. Chosen implementation vehicle

## Decision

Implement the core as an out-of-tree C kernel module using raw netfilter hooks.

## Why

- The required work is stateful translation, not simple packet mangling.
- The module must:
  - intercept outbound UDP
  - create fake-TCP packets
  - intercept inbound fake-TCP before the real TCP stack sees it
  - optionally inject/drop first-payload hints without enforcing them
  - reinject decapsulated UDP into the local stack
  - manage timers, retransmissions, GC, and conflict resolution
- This fits netfilter + `sk_buff` directly.

## Rejected alternatives

### eBPF

Rejected for v1 because the hard part is not filtering but stateful packet origination/reinjection and protocol translation. It is also a worse portability story for DKMS-style deployment.

### iptables target as the core design

Rejected as the primary architecture. A target can be added later as a configuration surface, but the real work still needs a substantial kernel module underneath.

### real kernel TCP listener/socket

Rejected because the wire protocol is intentionally not real TCP after the handshake. Letting the normal TCP stack own the socket would be a design mismatch and would fight the no-FIN/no-retransmit/no-flow-control model.

## 4. Top-level architecture

Each host runs the same module. There is no node-level client/server distinction.

Per flow, there is exactly one role pair:

- initiator: the side that creates the flow due to outbound UDP
- responder: the side that accepts the incoming fake-TCP `SYN`

The module is configured with two interception selectors:

- `managed_local_ports`: optional local UDP/TCP ports. For WireGuard, this is usually the local listen port.
- `managed_remote_peers`: optional exact remote IPv4:port peers in `x.y.z.w:p` form.
- at least one selector must be non-empty.

## 4.1 Interception selector model

The selectors define which tuples the translator owns. A packet must satisfy every selector that is configured.

Selector modes:

- local-only mode: only `managed_local_ports` is configured
  - outbound UDP matches by local source port
  - inbound fake-TCP matches by local destination port
- peer-only mode: only `managed_remote_peers` is configured
  - outbound UDP matches by remote destination IPv4:UDP port
  - inbound fake-TCP matches by remote source IPv4:TCP port
- intersection mode: both selectors are configured
  - both the local-port selector and the exact-remote-peer selector must match


Loopback-device exclusion:

- selector ownership applies only to non-loopback traffic
- outbound UDP routed to a loopback device is left as UDP
- inbound fake TCP arriving from a loopback device is ignored by the module
- raw inbound UDP arriving from a loopback device is not subject to the selector-matched drop rule

This keeps localhost traffic available for other local components, including a user-space Phantun instance talking to `127.0.0.1`.

Important consequence of peer-only mode:

- inbound TCP ownership is broad: a listed `managed_remote_peers` entry claims inbound fake-TCP interception from that peer regardless of local destination port
- therefore peer-only mode should be used only when that remote IPv4:port is dedicated to this translator, not when the same peer is also expected to talk ordinary TCP to unrelated local services
This preserves the old fixed-port behavior when `managed_local_ports` alone is used, while also allowing exact-peer-only interception when no local port list is supplied.

## 4.2 Default inbound raw-UDP drop

By default, raw inbound UDP that matches the configured selectors and arrives from a non-loopback device is dropped instead of being delivered to the local UDP socket.

Reason:

- if a tuple is meant to be owned by the fake-TCP translator, letting raw inbound UDP for the same selector space arrive locally would create ambiguous mixed delivery
- the drop rule keeps the ownership boundary honest: selector-matched inbound wire traffic is either fake-TCP handled by the module or raw UDP rejected by policy
- loopback-device traffic is exempt so localhost applications can keep using those ports without interference

The drop rule is implemented in inbound `PRE_ROUTING`, not `LOCAL_IN`.

- decapsulated UDP reinjected by the module is routed and injected directly into the local-delivery input path after `PRE_ROUTING`
- reinjected translated UDP therefore still reaches later inbound firewall/local-delivery processing without being mistaken for raw wire UDP

## 5. Protocol changes relative to today

## 5.1 Optional control-payload hints

The old user-space handshake-packet feature remains available as an optional shaping hint, not as a protocol requirement.

Module parameters / config:

- `handshake_request`: optional byte string
- `handshake_response`: optional byte string; only used when `handshake_request` is also configured

Protocol rules:

- if `handshake_request` is configured, the initiator sends it as the first fake-TCP payload, starting at initiator sequence `initiator_isn + 1`
- if `handshake_request` is configured, the responder suppresses inbound payload whose starting sequence is `initiator_isn + 1`; a higher-sequence payload that arrives first is not reclassified as the ignored payload
- if `handshake_request` is not configured, the initiator sends the first queued UDP packet as its first fake-TCP payload; if no queued packet exists, it sends a pure final `ACK`
- if both `handshake_request` and `handshake_response` are configured, the responder sends `handshake_response` as its first fake-TCP payload, starting at responder sequence `responder_isn + 1`, and the initiator suppresses inbound payload whose starting sequence is `responder_isn + 1`
- if only `handshake_response` is configured, it has no effect
- these payloads are best-effort shaping hints, not a verified handshake; missing, duplicated, or delayed reserved sequence ranges do not trigger `RST` or teardown, and later higher-sequence payloads may still drive normal state

Only payloads intentionally ignored by the shaping logic are kept away from the UDP socket.

## 5.2 ACK + optional first payload are combined

When `handshake_request` is configured, module-generated initiator traffic still combines the final handshake `ACK` with `handshake_request` in the same TCP packet.

So the preferred path becomes:

1. initiator: `SYN`
2. responder: `SYN|ACK`
3. initiator: `ACK + handshake_request` when configured, otherwise `ACK + first UDP payload` when a queued packet exists
4. responder: `ACK + handshake_response` when both control payloads are configured, otherwise normal responder data may begin immediately
5. normal data packets continue

Responder code should still accept either a combined final `ACK + payload` or a pure final `ACK` followed by later payload, because the shaping hints are optional.

## 5.3 Packet-loss tolerance expectations

The translator is expected to tolerate loss of handshake-path packets within the configured retry budget. These are not optional nice-to-haves; they are part of the connection contract.

Expected behaviors:

- lost initiator `SYN`: initiator stays in `SYN_SENT`, retransmits `SYN` on each handshake timeout, and keeps at most one queued UDP skb until either a valid `SYN|ACK` arrives or the retry budget is exhausted
- lost responder `SYN|ACK`: responder stays in `SYN_RCVD`; duplicate/retransmitted `SYN` and the responder retransmit timer both re-send `SYN|ACK` until a valid final `ACK` arrives or the retry budget is exhausted
- lost `handshake_request`: flow establishment is not revoked; if the reserved initiator first-payload sequence never arrives, later higher-sequence initiator payloads are still deliverable, and a delayed copy of that reserved sequence is ignored if it arrives later
- lost `handshake_response`: flow establishment is not revoked; if the reserved responder first-payload sequence never arrives, later higher-sequence responder payloads are still deliverable, and a delayed copy of that reserved sequence is ignored if it arrives later
- duplicate or delayed optional shaping payloads never trigger `RST`; only the reserved lowest-sequence control-payload slot is ignored locally

If retries are exhausted before the three-way handshake completes, the half-open flow is torn down and signaled with `RST`. Optional shaping-payload loss by itself must never be promoted into handshake failure.

## 5.4 Symmetric role model

Each flow is independent. The same node may be:

- initiator for one peer
- responder for another peer
- initiator for one tuple and responder for the reverse tuple at another time

The module does not expose client/server mode bits.

## 6. Flow identity and conflict handling

## 6.1 Canonical flow key

A flow is keyed by a canonical IPv4 4-tuple:

- compare `(ip, port)` lexicographically
- store the smaller endpoint first
- store the larger endpoint second

This is necessary because once node roles are symmetric, these two events refer to the same conceptual flow slot:

- local outbound UDP that wants to create a new connection
- inbound `SYN` from the peer for the same endpoint pair

The flow object still stores oriented addresses:

- `local_addr`
- `remote_addr`
- `role`

The canonical key is only for lookup and collision prevention.

## 6.2 Duplicate local initiation rule

Before creating a new outbound flow, the initiator must look up the canonical tuple.

Rules:

- if an `ESTABLISHED` flow exists: reuse it
- if a handshaking flow exists: do not create a second flow
  - queue at most one triggering UDP skb if the flow has no queued skb yet
  - otherwise drop and rely on WireGuard retransmission
- if a stale/dead flow exists: remove the local state without sending `RST`, then create a fresh initiator flow
  - preserve at most one queued outbound UDP skb across that local reopen
- only if no valid flow exists may a new outbound `SYN` be sent

This directly addresses the requirement that initiators must not create a second session for an already-valid tuple.

## 6.3 Replacement-generation quarantine

Accepting a bare replacement `SYN` on an existing tuple must not immediately turn every delayed old-generation packet into a fresh protocol error.

Rule:

- when an `ESTABLISHED` flow accepts a bare aligned replacement `SYN`, preserve a small quarantine record for the generation that was just replaced
- the record is only for the immediately previous generation on that tuple; do not build an unbounded history
- the quarantine window is short and bounded; it exists only to absorb delayed packets from the just-replaced generation, not to preserve concurrent sessions
- packets that still look like the quarantined old generation are silently dropped during that window instead of getting `RST`
- once the quarantine window expires, normal unknown-tuple handling resumes

Intent:

- avoid poisoning recovery when a peer re-establishes on the same tuple and delayed packets from the old generation arrive just after the replacement was accepted
- keep the hot path cheap by remembering only one previous generation with a short timeout


## 6.4 Simultaneous initiation policy

True simultaneous open is rejected.

Reason:

- the translator still wants one surviving flow per canonical tuple
- deterministic collapse keeps initiator/responder orientation stable without adding a second conflict-resolution handshake
- optional first-payload shaping remains unambiguous once only one flow survives

### Chosen policy: SYN-ISN tie-break

If a node is in `SYN_SENT` and receives a bare `SYN` for the same canonical tuple:

- compare the two initial sequence numbers (ISNs)
- the flow with the lower ISN wins the initiator role
- the flow with the higher ISN loses its initiator role and reprocesses the incoming `SYN` as responder
- if the ISNs are exactly equal, the packet is dropped and both sides rely on retransmission

This guarantees deterministic collapse without relying on potentially NAT-rewritten endpoints.

## 7. Per-flow state machine

Each flow contains:

- role: `INITIATOR` or `RESPONDER`
- state
- local/remote oriented addresses
- send sequence number
- receive acknowledgement number
- last acknowledged value
- one queued UDP skb pointer
- reserved first-payload-sequence ignore slot
- responder control-response pending-ACK / pending-release flag
- retransmit timer state
- idle timestamp
- refcount + lock

## 7.1 Initiator states

### `SYN_SENT`

Entered when outbound UDP for a managed tuple appears and no valid flow exists.

Actions:

- generate initial seq as a randomly chosen `u32` value rounded/aligned so it is also a multiple of `4095`
  - reject candidate ISNs that are within `reopen_guard_bytes` of the previous generation's sequence space
- send `SYN`
- queue at most one UDP skb
- start retransmit timer

Accepts:

- valid `SYN|ACK` with exact `ack = syn_seq + 1`
- bare aligned collision `SYN` for deterministic tie-break handling
- `RST` => destroy flow

On valid `SYN|ACK`:

- set `ack = responder_seq + 1`
- if `handshake_request` is configured, send `ACK + handshake_request`
- otherwise, if a queued UDP skb exists, send it as the first fake-TCP payload; if none exists, send a pure final `ACK`
- if both `handshake_request` and `handshake_response` are configured, arm an ignore slot for payload whose starting sequence is `responder_seq + 1`
- transition immediately to `ESTABLISHED`

### `ESTABLISHED`

Entered as soon as the three-way handshake completes.

Actions:

- if `handshake_request` was configured, flush the initiator-owned queued UDP skb after the injected request packet
- if the responder first-payload ignore slot is armed, drop inbound payload only when its starting sequence matches the reserved `handshake_response` sequence; later higher-sequence responder payloads are delivered normally
- from then on translate UDP <-> fake-TCP normally
- inbound traffic handling prioritizes flag classification:
  - `RST`: destroy local state silently
  - bare `SYN` (syn=1, ack=0, payload=0, aligned): accept as generation replacement. Destroy old flow state, move the just-replaced generation into a short quarantine window, create new `SYN_RCVD` responder flow, and send `SYN|ACK`.
  - any other packet with `SYN` set: send `RST|ACK` and destroy local state
  - no `SYN`: normal established data processing
- any valid inbound fake-TCP packet that is accepted for this flow, including pure `ACK`s and handshake-response acknowledgement traffic, refreshes liveness suspicion
- if no valid inbound packet has been seen for `keepalive_interval_sec`, send a pure `ACK` keepalive
- if no valid inbound packet has been seen for `keepalive_misses * keepalive_interval_sec`, destroy local state silently
  - if a queued outbound UDP skb already exists, immediately create a fresh `SYN_SENT` flow, carry one queued skb into it, and send `SYN`
  - otherwise wait for future outbound UDP to create the next generation

## 7.2 Responder states

### `SYN_RCVD`

Entered when inbound `SYN` is seen on a selector-matched tuple and no existing flow handles the tuple.

Validation:

- packet must be a bare `SYN` (no `ACK`, no payload)
- `seq % 4095 == 0`
- tuple must pass local policy checks

Actions:

- choose responder seq
- set `ack = initiator_seq + 1`
- send `SYN|ACK`
- start timer

Accepts while still half-open:

- duplicate inbound `SYN` retransmit => resend `SYN|ACK` and stay in `SYN_RCVD`
- valid final `ACK`

On valid final `ACK`:

- advance local `seq` to `responder_seq + 1`
- if `handshake_request` is configured and the final `ACK` already carries payload, suppress that payload immediately because it occupies the reserved initiator first-payload sequence
- if `handshake_request` is configured and the final `ACK` carries no payload, arm an ignore slot for inbound payload whose starting sequence is `initiator_seq + 1`
- if both `handshake_request` and `handshake_response` are configured, send `ACK + handshake_response`, advance `seq` by `handshake_response.len()`, and keep responder-owned queued UDP blocked until either a later initiator `ACK` covers the end of that injected response or later initiator traffic establishes that the reserved responder first-payload sequence was skipped
- otherwise transition directly to `ESTABLISHED`; responder-owned queued UDP may flow immediately

### `ESTABLISHED`

After establishment:

- outbound UDP becomes fake-TCP `ACK + payload`
- incoming fake-TCP payload becomes local UDP unless the first-payload-sequence ignore slot is armed for that payload's starting sequence; the reserved control-sequence payload is dropped locally and later higher-sequence payloads are delivered normally
- `seq` grows by payload length on send
- `ack` tracks peer `seq + payload_len` on receive
- inbound traffic handling prioritizes flag classification:
  - `RST`: destroy local state silently
  - bare `SYN` (syn=1, ack=0, payload=0, aligned): accept as generation replacement. Destroy old flow state, move the just-replaced generation into a short quarantine window, create new `SYN_RCVD` responder flow, and send `SYN|ACK`.
  - any other packet with `SYN` set: send `RST|ACK` and destroy local state
  - no `SYN`: normal established data processing
- any valid inbound fake-TCP packet that is accepted for this flow, including pure `ACK`s and handshake-response acknowledgement traffic, refreshes liveness suspicion
- if an injected responder `handshake_response` is still waiting for acknowledgement, local responder UDP is queued/dropped by the one-skb rule until either a later initiator `ACK` covers the injected response or later initiator traffic arrives and releases the queue while keeping the reserved ignore slot tied to responder sequence `responder_isn + 1`
- if no valid inbound packet has been seen for `keepalive_interval_sec`, send a pure `ACK` keepalive
- if no valid inbound packet has been seen for `keepalive_misses * keepalive_interval_sec`, destroy local state silently
  - if a queued outbound UDP skb already exists, immediately create a fresh `SYN_SENT` flow, carry one queued skb into it, and send `SYN`
  - otherwise wait for future outbound UDP to create the next generation
- explicit peer `RST` destroys the flow silently

## 8. Strict failure policy

Optional first-payload hints are best-effort and are never validated.

Cases that trigger immediate `RST` + flow destruction:

- bad `SYN` alignment
- wrong final `ACK` number during the three-way handshake
- impossible flag/state combination
- non-`RST` packet for unknown tuple

  In peer-only mode, this still applies when a packet from a managed remote peer does not match an existing flow and is not a valid new responder-creating bare `SYN`. The module should reject it with `RST`, not silently drop it, so the peer learns that local state does not recognize that fake-TCP tuple and can recover promptly.

Cases that do not trigger a reply:

- stray inbound `RST` for unknown tuple
- inbound `RST` for an existing tuple: just destroy local state
- stale-looking packets from the immediately previous generation while its short quarantine window is still active: silently drop them

Missing, duplicated, or unexpected optional request/response payloads are tolerated; later packets continue to drive normal `seq`/`ack` state.

## 9. Packet path in the kernel

## 9.1 Outbound UDP interception

Hook:

- `NF_INET_LOCAL_OUT`

Priority:

- after initial `LOCAL_OUT` conntrack classification (current code target: `-199`)

Match policy for v1:

- IPv4 UDP
- skip packets whose routed egress device is loopback
- if `managed_local_ports` is configured, the local source port must be in that list
- if `managed_remote_peers` is configured, the outbound destination IPv4:UDP port must match one exact managed peer

Behavior:

- if established flow exists: consume UDP skb and emit fake-TCP skb
- if handshaking flow exists: queue one skb or drop
- if no flow exists: create initiator flow, queue one skb, send `SYN`
- if the skb already carries conntrack state, confirm that original UDP entry before stealing the packet so translated inbound replies can match ESTABLISHED host-firewall policy
- original UDP skb is stolen from the stack

Why `LOCAL_OUT`:

- catches both kernel WireGuard and `wireguard-go` traffic without changing application configuration
- avoids TUN routing and NAT topology
- lets the module see locally generated UDP after the host classified the original UDP flow, but before the packet leaves as normal UDP

## 9.2 Inbound fake-TCP interception

Hook:

- `NF_INET_PRE_ROUTING`

Priority:

- before conntrack and before real TCP processing

Match policy for v1:

- IPv4 TCP
- tuple already exists in the flow table, or the packet is eligible to create a new responder flow under the selector policy
- skip packets arriving on loopback devices
- if `managed_local_ports` is configured, inbound destination port must be in that list for new responder creation
- if `managed_remote_peers` is configured, inbound source IPv4:TCP port must match one exact managed peer for new responder creation

Behavior:

- handle handshake packets in module state machine
- handle data packets in established flows
- in peer-only mode, a bare aligned `SYN` from a managed remote peer may create a responder flow on any local destination port
- if no existing flow matches and the packet is not a valid new bare `SYN`, reject it as an unknown tuple rather than passing it to the real TCP stack
- consume fake-TCP before the real TCP stack can send its own reset

## 9.3 Inbound raw UDP drop

Hook:

- `NF_INET_PRE_ROUTING`

Priority:

- before conntrack and before local UDP processing (same design target: `-400`)

Match policy for v1:

- IPv4 UDP
- skip packets arriving on loopback devices
- if `managed_local_ports` is configured, inbound destination port must be in that list
- if `managed_remote_peers` is configured, inbound source IPv4:UDP port must match one exact managed peer

Behavior:

- drop selector-matched raw inbound UDP by default
- allow unmatched inbound UDP to continue normally
- this drop does not apply to module-reinjected decapsulated UDP, because reinjection enters after `PRE_ROUTING` rather than as a fresh wire packet

## 9.4 Decapsulated UDP reinjection

For inbound established fake-TCP data:

- build a new UDP skb using the oriented tuple
- preserve original UDP src/dst IPs and ports
- route it for local input and inject it directly into the post-`PRE_ROUTING` local-delivery path (`ip_route_input` + `dst_input`-style reinjection)

Why:

- local UDP sockets, including kernel WireGuard and `wireguard-go`, receive traffic as if it arrived as native UDP
- later local inbound firewall and delivery hooks still run
- the `PRE_ROUTING` raw-UDP drop rule does not see this skb, so translated traffic is not black-holed

## 9.5 Generated fake-TCP transmission

For module-generated fake-TCP packets:

- build a new TCP skb
- set IPv4/TCP headers and checksums explicitly
- clear conntrack association before injection
- transmit via the normal local output path (`ip_local_out`-style send)

Because the `LOCAL_OUT` hook only steals UDP, not TCP, the module does not need a complicated self-loop bypass just to transmit its own fake-TCP packets.

## 9.6 Best-effort local flow invalidation

Some local topology changes make an existing fake-TCP generation no longer safely reusable even if the peer has not timed it out yet.

Chosen policy:

- each flow caches the last successful routed egress device used for fake-TCP transmission
- if that cached egress device goes `GOING_DOWN`, `DOWN`, or is unregistered, invalidate the local flow immediately
- if the exact local IPv4 address bound into the flow tuple is removed, invalidate the local flow immediately
- invalidation is silent local teardown: do not fabricate `RST` from a path/source identity that just disappeared
- next local outbound UDP may create a fresh flow generation normally

Intentionally not done in v1:

- do not invalidate on default-gateway or general FIB changes
- do not invalidate merely because some other IPv4 on the device changed, or because a different address became primary

Reason: every outbound fake-TCP send already performs a fresh route lookup using the flow's fixed local/remote IPv4 tuple. If that exact local source address is still valid, ordinary route/gateway migration may remain seamless, so reacting to broader routing churn would add complexity and false positives without clear benefit.
## 10. Configuration model

## v1 choice

Use simple module configuration first, not rule-language integration.

Selector config:

- `managed_local_ports`: optional list of up to 16 local UDP/TCP ports
- `managed_remote_peers`: optional list of up to 16 exact `x.y.z.w:p` peers
- at least one of those two lists must be non-empty

Recommended optional config:

- `handshake_request`
- `handshake_response` (effective only when `handshake_request` is also configured)
- `keepalive_interval_sec`
- `keepalive_misses`
- `hard_idle_timeout_sec`
- `reopen_guard_bytes`
- handshake timeout
- retry count

Rationale:

- one WireGuard listen port is still the main target use case
- exact-peer-only mode is also supported when local-port ownership is not the desired selector
- keep v1 small enough to finish
- add richer control plane later

Future control plane choices:

- generic netlink is preferred for structured runtime config
- xtables/nftables integration may be added later as a selector surface, but not as the core engine

## 11. MTU and firewall considerations

## MTU

Replacing UDP with TCP adds TCP header overhead.

For v1, require the managed UDP application to run with a reduced MTU budget. For WireGuard, document the required MTU reduction explicitly.

Do not attempt TCP fragmentation/resegmentation logic in v1.

## Conntrack / firewall

Because the module steals original UDP before normal transmission and emits new TCP packets instead:

- generated fake-TCP will look like new TCP traffic to the host firewall
- users must allow TCP for selector-matched fake-TCP tuples
- raw inbound UDP on selector-matched tuples is dropped in `PRE_ROUTING` by design
- decapsulated inbound payload is reinjected as UDP after `PRE_ROUTING` and will still traverse later local inbound UDP firewall/delivery hooks before the socket receives it
- users must therefore allow local UDP delivery for reinjected translated traffic on the tuples they intend the module to serve
- any old Phantun DNAT/SNAT-on-TUN documentation no longer applies

## 12. Compatibility statement

This design is intentionally not just “Phantun client/server in kernel”.

It changes the contract in important ways:

- no node-level client/server split
- selector-based interception via optional `managed_local_ports` and `managed_remote_peers` lists
- optional best-effort request/response first-payload shaping instead of mandatory verification
- local dropping of only the reserved first inbound payload sequence when shaping is enabled
- default dropping of selector-matched raw inbound UDP
- deterministic simultaneous-initiation collapse
- no TUN topology

Therefore v1 should be treated as a new kernel-to-kernel protocol variant, even though it preserves the same fake-TCP wire shape for the basic handshake/data/RST model.

If userspace interoperability is desired later, it should be an explicit compatibility mode, not an accidental side effect.

## 13. Implementation choices worth defending

### One queued UDP skb per half-open flow

Chosen because:

- saves one full WireGuard retransmit cycle
- bounded memory cost
- avoids building a second queueing subsystem inside the module

Everything beyond the first queued skb is dropped during handshake.

### Deterministic tie-break instead of simultaneous open

Chosen because it preserves a single unambiguous initiator/responder pair, keeps one translator per tuple, and leaves any optional first-payload shaping unambiguous.

### Selector-based interception, not a fake TCP listener socket

Chosen because it works with existing UDP applications directly, allows either local-port or exact-peer ownership, and avoids lying to the kernel by pretending this is normal TCP.

### Netfilter core, not xtables target core

Chosen because translation/state ownership belongs in a real module, not in a target callback abstraction designed mainly for policy integration.

