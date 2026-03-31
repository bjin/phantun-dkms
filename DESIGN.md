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
- Add mandatory first-payload verification so the first request/response packets contain configured ASCII-looking bytes
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

For the kernel design, that becomes stricter:

- first payload is mandatory, not optional
- both sides know exactly what first request and first response must be
- those control payloads are consumed by the module and are never delivered to the local UDP socket
- `ignore-first-packet` disappears because the module handles it internally

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
  - verify the first payload request/response pair
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

## 5.1 Mandatory control payloads

The old optional user-space handshake-packet feature becomes a protocol requirement.

New module parameters / config:

- `handshake_request`: required ASCII byte string
- `handshake_response`: required ASCII byte string

Protocol rule:

- initiator must send `handshake_request` as the first fake-TCP payload
- responder must verify it exactly
- responder must then send `handshake_response` as its first fake-TCP payload
- initiator must verify it exactly
- mismatch or timeout => send `RST` and destroy flow

These control payloads are module-internal and are not delivered to UDP sockets.

## 5.2 ACK + first payload are combined

To maximize the chance that the first request packet on the TCP connection looks like a plausible ASCII protocol exchange, the initiator should send the final handshake `ACK` together with `handshake_request` in the same TCP packet.

So the normal path is:

1. initiator: `SYN`
2. responder: `SYN|ACK`
3. initiator: `ACK + handshake_request`
4. responder: `ACK + handshake_response`
5. normal data packets begin

Responder should still be coded to tolerate a split final `ACK` followed immediately by a request payload, but module-generated traffic should always use the combined form.

## 5.3 Symmetric role model

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
- if a stale flow exists: send `RST`, remove it, then create a new flow
- only if no valid flow exists may a new outbound `SYN` be sent

This directly addresses the requirement that initiators must not create a second session for an already-valid tuple.

## 6.3 Simultaneous initiation policy

True simultaneous open is rejected.

Reason:

- it conflicts with the new requirement that the first payload from each role is predetermined (`request` from initiator, `response` from responder)
- supporting TCP-style simultaneous open would require an additional role negotiation phase or ambiguous first payloads
- that defeats the “first request/response should look like ASCII application traffic” goal

### Chosen policy: deterministic collapse

If a node is in `SYN_SENT` and receives a bare `SYN` for the same canonical tuple:

- compare the two oriented endpoints numerically
- the endpoint with the lower `(ip, port)` wins the initiator role
- winner keeps its outbound `SYN_SENT` flow
- loser destroys its outbound half-open flow and reprocesses the incoming `SYN` as responder

This guarantees that only one connection survives for a tuple.

## 7. Per-flow state machine

Each flow contains:

- role: `INITIATOR` or `RESPONDER`
- state
- local/remote oriented addresses
- send sequence number
- receive acknowledgement number
- last acknowledged value
- `handshake_verified` flags
- one queued UDP skb pointer
- retransmit timer state
- idle timestamp
- refcount + lock

## 7.1 Initiator states

### `SYN_SENT`

Entered when outbound UDP for a managed tuple appears and no valid flow exists.

Actions:

- generate initial seq as a randomly chosen `u32` value rounded/aligned so it is also a multiple of `4095`
- send `SYN`
- queue at most one UDP skb
- start retransmit timer

Accepts:

- valid `SYN|ACK` with exact `ack = syn_seq + 1`
- duplicate valid `SYN|ACK` while still waiting for the control response => resend `ACK + handshake_request`
- collision `SYN` for deterministic tie-break handling
- `RST` => destroy flow

### `HS_REQ_SENT`

Entered after valid `SYN|ACK`.

Actions:

- advance seq for the sent `SYN`
- set `ack = responder_seq + 1`
- send `ACK + handshake_request`
- advance seq by `handshake_request.len()`
- restart retransmit/response timer

Accepts:

- duplicate valid `SYN|ACK` => resend `ACK + handshake_request`
- exact first responder payload `handshake_response` => transition to `ESTABLISHED`
- pure `ACK` with no payload => ignore and keep waiting
- anything else => `RST` + destroy

### `ESTABLISHED`

Entered only after exact response verification.

Actions:

- mark request/response exchange complete
- flush the initiator-owned queued UDP skb as the first user-data payload
- from now on translate UDP <-> fake-TCP normally

## 7.2 Responder states

### `SYN_RCVD`

Entered when inbound `SYN` is seen on a managed port and no existing flow handles the tuple.

Validation:

- packet must be `SYN`
- `seq % 4095 == 0`
- tuple must pass local policy checks

Actions:

- choose responder seq
- set `ack = initiator_seq + 1`
- send `SYN|ACK`
- start timer

Accepts while still half-open:

- duplicate inbound `SYN` retransmit => resend `SYN|ACK` and stay in `SYN_RCVD`
- valid final `ACK` => transition to `AWAIT_HS_REQ`
- valid combined `ACK + handshake_request` => verify request immediately and, if exact, transition to `HS_RESP_SENT`

### `AWAIT_HS_REQ`

Entered after receiving a valid final `ACK` with no control payload.

The module should accept both:

- pure duplicate `ACK`, then continue waiting for first payload
- a later payload packet whose first payload is `handshake_request`

Validation:

- final ACK number must equal `responder_seq + 1`
- duplicate `SYN` retransmit from the initiator => resend `SYN|ACK`
- if the first payload is present, it must exactly equal `handshake_request`

### `HS_RESP_SENT`

Entered only after exact request verification and after sending `ACK + handshake_response`.

Actions:

- consume request control payload internally
- send `ACK + handshake_response`
- advance seq by `handshake_response.len()`
- keep any responder-owned queued UDP skb, if present, until later initiator traffic acknowledges the control response

Accepts:

- duplicate exact `handshake_request` => resend `ACK + handshake_response` and stay in `HS_RESP_SENT`
- the first later initiator packet whose ACK covers the end of `handshake_response` => transition to `ESTABLISHED`
- if that same packet also carries user payload, process it as the first normal inbound UDP payload while transitioning
- `RST` => destroy flow

## 7.3 Common established behavior

After establishment:

- outbound UDP becomes fake-TCP `ACK + payload`
- incoming fake-TCP payload becomes local UDP
- `seq` grows by payload length on send
- `ack` tracks peer `seq + payload_len` on receive
- initiator-owned queued UDP is flushed only after exact response verification
- responder-owned queued UDP is flushed only after a later initiator packet acknowledges `handshake_response`; if teardown or timeout happens first, it is dropped
- idle timeout destroys the flow and sends `RST`
- explicit peer `RST` destroys the flow silently

## 8. Strict failure policy

Mismatch handling is intentionally harsh.

Cases that trigger immediate `RST` + flow destruction:

- bad `SYN` alignment
- wrong ACK number during handshake
- first request payload != configured `handshake_request`
- first response payload != configured `handshake_response`
- impossible flag/state combination
- non-`RST` packet for unknown tuple

Cases that do not trigger a reply:

- stray inbound `RST` for unknown tuple
- inbound `RST` for an existing tuple: just destroy local state

## 9. Packet path in the kernel

## 9.1 Outbound UDP interception

Hook:

- `NF_INET_LOCAL_OUT`

Priority:

- before conntrack (default design target: `-400`)

Match policy for v1:

- IPv4 UDP
- local source port is a managed port
- optional remote IPv4/port policy matches

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
- `handshake_request`
- `handshake_response`

Recommended optional config:

- allowed remote IPv4 CIDRs
- allowed remote ports
- idle timeout
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
- mandatory request/response control payload verification
- internal consumption of those control payloads
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

Chosen because it preserves a single unambiguous initiator/responder pair and keeps the first payload semantics fixed.

### Managed local ports, not a fake TCP listener socket

Chosen because it works with existing UDP applications directly and avoids lying to the kernel by pretending this is normal TCP.

### Netfilter core, not xtables target core

Chosen because translation/state ownership belongs in a real module, not in a target callback abstraction designed mainly for policy integration.
