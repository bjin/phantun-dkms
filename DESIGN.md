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
- when those hints are active, the matching first inbound payload is ignored locally and is never delivered to the UDP socket
- loss, duplication, or absence of those payloads does not break flow establishment

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

The module is configured with one or more managed local UDP/TCP ports. For WireGuard, this is the local listen port.

For a managed port:

- outbound UDP sourced from that local port may create or use a fake-TCP flow
- inbound fake-TCP destined to that local port may create or use a fake-TCP flow

Optional peer restrictions may narrow matching by remote IPv4 CIDR and/or remote port.

## 5. Protocol changes relative to today

## 5.1 Optional control-payload hints

The old user-space handshake-packet feature remains available as an optional shaping hint, not as a protocol requirement.

Module parameters / config:

- `handshake_request`: optional byte string
- `handshake_response`: optional byte string; only used when `handshake_request` is also configured

Protocol rules:

- if `handshake_request` is configured, the initiator sends it as the first fake-TCP payload
- if `handshake_request` is configured, the responder ignores the first inbound payload it sees for that flow
- if `handshake_request` is not configured, the initiator sends the first queued UDP packet as its first fake-TCP payload; if no queued packet exists, it sends a pure final `ACK`
- if both `handshake_request` and `handshake_response` are configured, the responder sends `handshake_response` as its first fake-TCP payload and the initiator ignores the first inbound payload it sees for that flow
- if only `handshake_response` is configured, it has no effect
- these payloads are best-effort shaping hints, not a verified handshake; missing, duplicated, or unexpected payloads do not trigger `RST` or teardown

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
- lost `handshake_request`: flow establishment is not revoked; responder still applies the one-shot “ignore first inbound payload” rule, so the next inbound payload it sees is dropped once, and later payloads continue normally
- lost `handshake_response`: flow establishment is not revoked; initiator still applies its one-shot “ignore first inbound responder payload” rule, so the next responder payload it sees is dropped once, and later responder payloads continue normally
- duplicate or delayed optional shaping payloads never trigger `RST`; they only affect which payload is ignored once on the receiving side

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

## 6.3 Simultaneous initiation policy

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
- one-shot first-inbound-payload ignore flag
- responder control-response pending-ACK flag
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
- if both `handshake_request` and `handshake_response` are configured, arm a one-shot drop for the first responder payload
- transition immediately to `ESTABLISHED`

### `ESTABLISHED`

Entered as soon as the three-way handshake completes.

Actions:

- if `handshake_request` was configured, flush the initiator-owned queued UDP skb after the injected request packet
- if the one-shot inbound ignore flag is armed, drop the first responder payload received and then clear the flag
- from then on translate UDP <-> fake-TCP normally
- inbound traffic handling prioritizes flag classification:
  - `RST`: destroy local state silently
  - bare `SYN` (syn=1, ack=0, payload=0, aligned): accept as generation replacement. Destroy old flow state, drop old skb, create new `SYN_RCVD` responder flow, and send `SYN|ACK`.
  - any other packet with `SYN` set: send `RST|ACK` and destroy local state
  - no `SYN`: normal established data processing
- any valid inbound fake-TCP packet that is accepted for this flow, including pure `ACK`s and handshake-response acknowledgement traffic, refreshes liveness suspicion
- if no valid inbound packet has been seen for `keepalive_interval_sec`, send a pure `ACK` keepalive
- if no valid inbound packet has been seen for `keepalive_misses * keepalive_interval_sec`, destroy local state silently
  - if a queued outbound UDP skb already exists, immediately create a fresh `SYN_SENT` flow, carry one queued skb into it, and send `SYN`
  - otherwise wait for future outbound UDP to create the next generation

## 7.2 Responder states

### `SYN_RCVD`

Entered when inbound `SYN` is seen on a managed port and no existing flow handles the tuple.

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
- if `handshake_request` is configured and the final `ACK` already carries payload, drop that payload immediately
- if `handshake_request` is configured and the final `ACK` carries no payload, arm a one-shot drop for the first later inbound payload
- if both `handshake_request` and `handshake_response` are configured, send `ACK + handshake_response`, advance `seq` by `handshake_response.len()`, and keep responder-owned queued UDP blocked until a later initiator `ACK` covers the end of that injected response
- otherwise transition directly to `ESTABLISHED`; responder-owned queued UDP may flow immediately

### `ESTABLISHED`

After establishment:

- outbound UDP becomes fake-TCP `ACK + payload`
- incoming fake-TCP payload becomes local UDP unless the one-shot ignore flag is still armed; if it is armed, drop that first payload and clear the flag
- `seq` grows by payload length on send
- `ack` tracks peer `seq + payload_len` on receive
- inbound traffic handling prioritizes flag classification:
  - `RST`: destroy local state silently
  - bare `SYN` (syn=1, ack=0, payload=0, aligned): accept as generation replacement. Destroy old flow state, drop old skb, create new `SYN_RCVD` responder flow, and send `SYN|ACK`.
  - any other packet with `SYN` set: send `RST|ACK` and destroy local state
  - no `SYN`: normal established data processing
- any valid inbound fake-TCP packet that is accepted for this flow, including pure `ACK`s and handshake-response acknowledgement traffic, refreshes liveness suspicion
- if an injected responder `handshake_response` is still waiting for acknowledgement, local responder UDP is queued/dropped by the one-skb rule until a later initiator `ACK` covers the end of that injected response; inbound initiator traffic is still processed normally
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

Cases that do not trigger a reply:

- stray inbound `RST` for unknown tuple
- inbound `RST` for an existing tuple: just destroy local state

Missing, duplicated, or unexpected optional request/response payloads are tolerated; later packets continue to drive normal `seq`/`ack` state.

## 9. Packet path in the kernel

## 9.1 Outbound UDP interception

Hook:

- `NF_INET_LOCAL_OUT`

Priority:

- before conntrack (default design target: `-400`)

Match policy for v1:

- IPv4 UDP
- local source port is a managed port
- if `remote_ipv4_cidr` is configured, outbound destination IPv4 must fall within that CIDR
- if `remote_port` is configured, outbound destination UDP port must equal that port

Behavior:

- if established flow exists: consume UDP skb and emit fake-TCP skb
- if handshaking flow exists: queue one skb or drop
- if no flow exists: create initiator flow, queue one skb, send `SYN`
- original UDP skb is stolen from the stack

Why `LOCAL_OUT`:

- catches both kernel WireGuard and `wireguard-go` traffic without changing application configuration
- avoids TUN routing and NAT topology
- allows the module to see locally generated UDP before it becomes a normal UDP transmission

## 9.2 Inbound fake-TCP interception

Hook:

- `NF_INET_PRE_ROUTING`

Priority:

- before conntrack and before real TCP processing

Match policy for v1:

- IPv4 TCP
- destination port is a managed port, or tuple already exists in the flow table
- if `remote_ipv4_cidr` is configured, inbound source IPv4 must fall within that CIDR
- if `remote_port` is configured, inbound source TCP port must equal that port

Behavior:

- handle handshake packets in module state machine
- handle data packets in established flows
- consume fake-TCP before the real TCP stack can send its own reset

## 9.3 Decapsulated UDP reinjection

For inbound established fake-TCP data:

- build a new UDP skb using the oriented tuple
- preserve original UDP src/dst IPs and ports
- inject it via the normal receive path (`netif_receive_skb`-style reinjection)

Why:

- local UDP sockets, including kernel WireGuard and `wireguard-go`, receive traffic as if it arrived as native UDP
- other normal receive-path hooks still run
- the reinjected packet therefore traverses the host's inbound UDP firewall path again before the local socket receives it

## 9.4 Generated fake-TCP transmission

For module-generated fake-TCP packets:

- build a new TCP skb
- set IPv4/TCP headers and checksums explicitly
- clear conntrack association before injection
- transmit via the normal local output path (`ip_local_out`-style send)

Because the `LOCAL_OUT` hook only steals UDP, not TCP, the module does not need a complicated self-loop bypass just to transmit its own fake-TCP packets.

## 10. Configuration model

## v1 choice

Use simple module configuration first, not rule-language integration.

Required config:

- managed local port list

Recommended optional config:

- `handshake_request`
- `handshake_response` (effective only when `handshake_request` is also configured)
- allowed remote IPv4 CIDRs
- allowed remote ports
- `keepalive_interval_sec`
- `keepalive_misses`
- `hard_idle_timeout_sec`
- `reopen_guard_bytes`
- handshake timeout
- retry count

Rationale:

- one WireGuard listen port is the main target use case
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
- users must allow TCP on the managed port
- decapsulated inbound payload is reinjected as UDP and will traverse the local inbound UDP firewall path again
- users must therefore also allow local UDP delivery on the managed port for the reinjected traffic
- any old Phantun DNAT/SNAT-on-TUN documentation no longer applies

## 12. Compatibility statement

This design is intentionally not just “Phantun client/server in kernel”.

It changes the contract in important ways:

- no node-level client/server split
- optional best-effort request/response first-payload shaping instead of mandatory verification
- local dropping of the first inbound payload when shaping is enabled
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

### Managed local ports, not a fake TCP listener socket

Chosen because it works with existing UDP applications directly and avoids lying to the kernel by pretending this is normal TCP.

### Netfilter core, not xtables target core

Chosen because translation/state ownership belongs in a real module, not in a target callback abstraction designed mainly for policy integration.

