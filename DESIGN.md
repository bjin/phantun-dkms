# phantun-dkms design

This document covers **internal design decisions** and **protocol behavior**.
For installation, everyday configuration, examples, stats, MTU guidance, and operational notes, use [**`README.md`**](./README.md).

## 1. Scope

### Goals

- Run **Phantun-style fake TCP** directly in the Linux kernel.
- Work transparently with existing UDP applications, especially:
  - kernel WireGuard
  - `wireguard-go`
- Avoid a **TUN** device and TUN-side NAT topology.
- Preserve the core fake-TCP wire model:
  - strict three-way handshake
  - payload in `ACK` packets
  - byte-accurate `seq` / `ack`
  - `RST` on protocol error
  - no FIN close state machine
- Support optional **first-payload shaping hints** without turning them into a required verified sub-protocol.
- Use a **symmetric node model**: each flow has only an initiator and a responder.

### Non-goals

- IPv6 in v1
- user-space Phantun interoperability guarantees
- eBPF as the primary implementation
- xtables target as the core data plane
- real kernel TCP listener/socket ownership

## 2. Core protocol contract

### 2.1 Wire semantics preserved

The module keeps these fake-TCP invariants:

- strict handshake:
  1. initiator sends `SYN`
  2. responder replies `SYN|ACK`
  3. initiator finishes with `ACK`
- responder accepts `SYN` only when `seq % 4095 == 0`
- data packets are `ACK` packets carrying payload
- sender `seq` advances by payload length
- receiver `ack` tracks `peer_seq + payload_len`
- no FIN/CLOSE state machine
- `RST` is the teardown and error signal
- malformed or impossible packets are rejected with `RST` unless explicitly listed as silent-drop cases

### 2.2 Optional shaping hints

`handshake_request` and `handshake_response` are **best-effort shaping hints**.
They do **not** become a required handshake sub-protocol.

Rules:

- `handshake_request` optionally occupies the initiator's first payload slot.
- `handshake_response` optionally occupies the responder's first payload slot, but only when `handshake_request` is also configured.
- The payload to ignore is identified by the **reserved lowest payload sequence number** for that flow generation, **not** by arrival order.
- Missing, delayed, duplicated, or reordered shaping payloads do **not** fail establishment by themselves.
- Only payloads intentionally suppressed by shaping logic are hidden from the local UDP socket.

Preferred happy path:

1. initiator: `SYN`
2. responder: `SYN|ACK`
3. initiator: `ACK + handshake_request` when configured, otherwise `ACK + first queued UDP payload` when present, otherwise pure `ACK`
4. responder: `ACK + handshake_response` when both hints are configured, otherwise normal responder data may begin immediately
5. normal data continues

Implementation must also accept a pure final `ACK` followed by later payload because shaping remains optional.

## 3. Chosen implementation vehicle

### Decision

Use an **out-of-tree C kernel module** built around **raw netfilter hooks**.

### Why

The hard part is not filtering. It is full stateful translation:

- steal outbound UDP
- originate fake-TCP packets
- intercept inbound fake TCP before the real TCP stack sees it
- decapsulate payload back to UDP
- reinject for local delivery
- manage timers, retries, liveness, conflict resolution, and teardown

That fits netfilter plus direct `sk_buff` ownership better than eBPF, xtables-target core logic, or pretending the protocol is normal TCP.

## 4. Top-level architecture

### 4.1 Symmetric nodes

Every host runs the same module.
There is **no node-level client/server mode bit**.

Per flow, roles are only:

- **initiator**: creates the flow because local outbound UDP appears
- **responder**: accepts an inbound fake-TCP `SYN`

### 4.2 Interception selectors

The translator owns traffic based on two optional selector lists.
A packet must satisfy **every configured selector**.

| Selector | Purpose |
|---|---|
| `managed_local_ports` | Local UDP/TCP ports the translator owns |
| `managed_remote_peers` | Exact remote `IPv4:port` peers the translator owns |

Selector modes:

| Mode | Outbound match | Inbound fake-TCP match |
|---|---|---|
| Local-only | local source port | local destination port |
| Peer-only | remote destination `IPv4:UDP port` | remote source `IPv4:TCP port` |
| Intersection | both must match | both must match |

Constraints:

- at least one selector list must be non-empty
- selector ownership applies only to **non-loopback** traffic
- inbound selector ownership applies only after confirming the destination IPv4 is locally delivered to the current host/netns; forwarded traffic is never translator-owned
- outbound UDP routed to loopback stays UDP
- inbound fake TCP arriving on loopback is ignored by the module
- raw inbound UDP arriving on loopback is not subject to selector-owned drop

Peer-only caveat:

- inbound TCP ownership becomes broad for that remote `IPv4:port`
- use peer-only mode only when that remote peer is dedicated to this translator

### 4.3 Default inbound raw-UDP drop

By default, raw inbound UDP that matches configured selectors, is destined for local delivery in the current host/netns, and arrives from a non-loopback device is dropped in `PRE_ROUTING`.

Reason:

- selector-matched traffic must have one owner
- allowing both raw UDP delivery and translated fake-TCP delivery would create ambiguous mixed delivery
- forwarded UDP is not translator-owned traffic and must continue through the normal routing path
- reinjected translated UDP enters after `PRE_ROUTING`, so translated traffic is not black-holed by this drop rule

## 5. Flow identity and conflict handling

### 5.1 Canonical flow key

A flow is keyed by a canonical IPv4 4-tuple:

- compare `(ip, port)` lexicographically
- store smaller endpoint first
- store larger endpoint second

The flow still stores oriented local/remote addresses and role.
The canonical key exists only for lookup and collision prevention.

### 5.2 Duplicate local initiation rule

Before creating a new outbound flow for a tuple:

- if an `ESTABLISHED` flow exists: reuse it
- if a handshaking flow exists:
  - do not create a second flow
  - queue at most one outbound UDP skb if none is already queued
  - otherwise drop and rely on application retransmission
- if only stale/dead local state exists:
  - remove it silently
  - preserve at most one queued outbound UDP skb across reopen
  - create a fresh initiator flow

### 5.3 Replacement-generation quarantine

If an established flow accepts a valid bare replacement `SYN` on the same tuple:

- destroy current generation
- keep a short quarantine record for the immediately previous generation only
- during that short window, packets that still look like the old generation are silently dropped instead of provoking `RST`
- after expiry, normal unknown-tuple handling resumes

Purpose: avoid poisoning recovery with delayed old-generation packets just after tuple reuse.

### 5.4 Simultaneous initiation policy

True simultaneous open is rejected.
The design wants **one surviving flow per canonical tuple**.

Tie-break rule for `SYN_SENT` receiving a bare `SYN` on the same canonical tuple:

- lower ISN wins initiator role
- higher ISN loses initiator role and reprocesses inbound `SYN` as responder
- exact ISN tie: drop and rely on retransmission

This avoids NAT-sensitive endpoint heuristics and keeps shaping unambiguous.

### 5.5 One queued UDP skb

Half-open flow buffering is intentionally small:

- queue **at most one** outbound UDP skb per handshaking flow
- save one retransmit cycle for common WireGuard behavior
- bound memory and complexity
- anything beyond the first queued skb is dropped

## 6. Per-flow state machine

Each flow stores:

- role: `INITIATOR` or `RESPONDER`
- state
- oriented local/remote addresses
- send sequence number
- receive acknowledgement number
- last acknowledged value
- one queued UDP skb pointer
- reserved first-payload ignore slot
- responder control-response pending-ACK / pending-release flag
- retransmit timer state
- idle timestamp
- refcount and lock

### 6.1 Initiator states

#### `SYN_SENT`

Entered when managed outbound UDP appears and no valid flow exists.

Actions:

- choose random `u32` initial sequence number aligned so `seq % 4095 == 0`
- reject candidate ISNs that violate `reopen_guard_bytes` distance from prior generation
- send `SYN`
- queue at most one UDP skb
- start retransmit timer

Accepts:

- valid `SYN|ACK` with exact `ack = syn_seq + 1`
- bare aligned collision `SYN` for tie-break handling
- `RST` → destroy flow

On valid `SYN|ACK`:

- set `ack = responder_seq + 1`
- if `handshake_request` configured: send `ACK + handshake_request`
- else if queued UDP exists: send `ACK + first queued UDP payload`
- else: send pure final `ACK`
- if both `handshake_request` and `handshake_response` configured: arm ignore slot for payload starting at `responder_seq + 1`
- transition immediately to `ESTABLISHED`

#### `ESTABLISHED`

Behavior:

- if `handshake_request` was injected, flush initiator-owned queued UDP after that injected request
- if responder first-payload ignore slot is armed, suppress only payload whose starting sequence matches reserved responder control sequence
- later responder payload may be delivered best-effort once it is wholly above the current receive frontier; payload that overlaps the frontier is invalid
- normal UDP ↔ fake-TCP translation follows
- only inbound packets valid for the current generation refresh liveness suspicion, including pure `ACK` and handshake-response acknowledgement traffic
- after `keepalive_interval_sec` without valid inbound traffic: send pure `ACK` keepalive
- after `keepalive_misses * keepalive_interval_sec` without valid inbound traffic: destroy local state silently
  - if one outbound UDP skb is already queued, create fresh `SYN_SENT`, carry that skb, send `SYN`
  - otherwise wait for future outbound UDP

Inbound flag priority in established state:

1. `RST` → destroy local state silently
2. bare aligned `SYN` with no payload, no `ACK`, and no other control flags → accept as generation replacement, move old generation into quarantine, create new responder `SYN_RCVD`, send `SYN|ACK`
3. any other packet with `SYN` set → send `RST|ACK`, destroy local state
4. otherwise → normal data processing

### 6.2 Responder states

#### `SYN_RCVD`

Entered when a selector-matched inbound `SYN` arrives and no existing flow owns the tuple.

Validation:

- bare `SYN` only (`SYN` set, no `ACK`, no payload, no other control flags)
- `seq % 4095 == 0`
- tuple passes selector policy

Actions:

- choose responder sequence
- set `ack = initiator_seq + 1`
- send `SYN|ACK`
- start retransmit timer

Accepts while half-open:

- duplicate inbound bare `SYN` retransmit → resend `SYN|ACK`
- valid final `ACK`

On valid final `ACK`:

- advance local `seq` to `responder_seq + 1`
- if `handshake_request` configured and final `ACK` already carries payload: suppress that payload immediately because it occupies reserved initiator first-payload sequence
- if `handshake_request` configured and final `ACK` carries no payload: arm ignore slot for inbound payload starting at `initiator_seq + 1`
- if both shaping hints configured:
  - send `ACK + handshake_response`
  - advance `seq` by `handshake_response.len()`
  - keep responder-owned queued UDP blocked until later initiator `ACK` covers injected response or later initiator traffic establishes reserved responder sequence was skipped
- otherwise transition directly to `ESTABLISHED`

#### `ESTABLISHED`

Behavior:

- outbound UDP becomes `ACK + payload`
- inbound fake-TCP payload becomes local UDP unless payload start sequence matches an armed ignore slot
- `seq` grows by outbound payload length
- `ack` tracks the next receive frontier monotonically and never regresses
- if injected responder `handshake_response` still awaits acknowledgement, responder UDP follows the one-skb queue/drop rule until release
- only inbound packets valid for the current generation refresh liveness suspicion
- keepalive and silent idle teardown use the same policy as initiator-established flows

Inbound flag priority matches initiator-established handling:

1. `RST` → destroy flow silently
2. bare aligned replacement `SYN` with no payload, no `ACK`, and no other control flags → replace generation, quarantine old generation, create new `SYN_RCVD`, send `SYN|ACK`
3. any other packet with `SYN` set → send `RST|ACK`, destroy flow
4. otherwise → normal data processing

### 6.3 Established receive classifier and acceptance window

Established-state inbound processing uses a classifier over the current flow generation and one inbound fake-TCP packet. The classifier is a design constraint, not merely an implementation detail: packets outside these classes must not refresh liveness, advance ACK state, release queued responder data, or reach the UDP socket.

Classifier classes:
- `VALID_ACK_ONLY`: packet carries `ACK`, no payload, no illegal control flags, and its `ack_seq` is valid for the current generation
- `VALID_IN_ORDER_PAYLOAD`: packet carries `ACK` and payload that starts at or beyond the current receive frontier and can be delivered immediately as best-effort UDP
- `VALID_RESERVED_SHAPING_DROP`: packet matches an armed reserved shaping sequence slot and is silently suppressed without UDP delivery
- `VALID_DUPLICATE_OLD`: packet is entirely below the current receive frontier and may be silently absorbed without changing externally visible state
- `VALID_RESPONSE_SKIP_PROOF`: while responder `handshake_response` is still pending acknowledgement, later initiator payload may prove that the reserved responder-control slot was skipped; this both releases queued responder UDP and still delivers the proving payload to UDP
- `INVALID`: impossible ACK progression, overlapping old/new payload, missing required `ACK`, or any packet that does not fit the current generation's rules

Receive-window definition for this protocol:
- There is no general out-of-order receive queue in v1
- The current receive frontier is the flow's `ack` value
- Pure ACK may be silently absorbed when its `seq` is below or above the current receive frontier, but only the exact-frontier form is allowed to refresh liveness or release responder-side state
- Whole payload datagrams that start at or above the current receive frontier may still be delivered best-effort, even when they arrive later than an unseen lower-sequence datagram
- Duplicate old payload is tolerated only when the entire payload lies below the current receive frontier; duplicates must not be reinjected to UDP and must not regress ACK state
- Payload that starts below the current receive frontier but extends past it is invalid because there is no overlap trimming or partial reassembly path

ACK validation rules in `ESTABLISHED`:
- Normal established traffic must carry `ACK`
- `ack_seq` must stay within the local send frontier of the current generation
- `ack_seq` greater than locally sent bytes is invalid
- Pure ACK outside the current receive frontier may be silently absorbed as harmless bookkeeping, but it must not refresh liveness, release `response_pending_ack`, or advance any sequence state

State-machine consequences:
- `VALID_ACK_ONLY` refreshes liveness and may release queued responder UDP only when it validly acknowledges the injected responder handshake-response range
- `VALID_IN_ORDER_PAYLOAD` refreshes liveness, advances the receive frontier monotonically, may release responder queued UDP when it proves a reserved response slot was skipped, and reinjects payload to local UDP
- `VALID_RESERVED_SHAPING_DROP` refreshes liveness only for the current generation, never delivers to UDP, and must not regress ACK state
- `VALID_DUPLICATE_OLD` is silently absorbed; it does not refresh liveness, does not deliver to UDP, and does not alter ACK state
- `VALID_RESPONSE_SKIP_PROOF` refreshes liveness, advances the receive frontier monotonically, releases queued responder UDP, and still delivers the proving payload to UDP
- `INVALID` is a protocol error and triggers `RST|ACK` plus local teardown, except where the failure policy explicitly lists a silent-drop case

These rules intentionally preserve handshake shaping loss-tolerance and tolerate benign datagram reordering while still rejecting impossible ACK progression and overlapping payload shapes.
## 7. Failure policy

### 7.1 Immediate `RST` + flow destruction

- bad `SYN` alignment
- wrong final `ACK` during handshake
- impossible flag/state combination
- non-`RST` packet for unknown tuple

Peer-only mode keeps this rule: if a packet from a managed remote peer does not match local flow state and is not a valid new bare `SYN`, reject with `RST` instead of silently dropping it.

### 7.2 Silent cases

- stray inbound `RST` for unknown tuple
- inbound `RST` for known tuple: destroy local state, no reply
- inbound packets failing IPv4 or TCP checksum validation
- packets from immediately previous generation while quarantine is active
- shaping-payload loss, duplication, delay, or reordering

### 7.3 Handshake loss tolerance

The translator must tolerate loss of handshake-path packets within retry budget:

- lost initiator `SYN` → stay `SYN_SENT`, retransmit `SYN`, keep at most one queued UDP skb
- lost responder `SYN|ACK` → stay `SYN_RCVD`, retransmit `SYN|ACK` on timer and duplicate `SYN`
- lost `handshake_request` or `handshake_response` → establishment still stands; later higher-sequence payloads may proceed
- retry exhaustion before three-way handshake completes → tear down half-open flow and signal with `RST`

## 8. Packet path in kernel

### 8.1 Outbound UDP interception

| Item | Value |
|---|---|
| Hook | `NF_INET_LOCAL_OUT` |
| Target priority | after initial `LOCAL_OUT` conntrack classification (`-199` in current design target) |
| Match | IPv4 UDP, non-loopback egress, selector-matched tuple |

Behavior:

- established flow → consume UDP skb, emit fake-TCP skb
- handshaking flow → queue one skb or drop
- no flow → create initiator flow, queue one skb, send `SYN`
- if skb already carries conntrack state, confirm original UDP entry before stealing packet so translated inbound replies can match established host-firewall policy
- original UDP skb is stolen from the stack

### 8.2 Inbound fake-TCP interception

| Item | Value |
|---|---|
| Hook | `NF_INET_PRE_ROUTING` |
| Target priority | before conntrack and before real TCP processing |
| Match | IPv4 TCP, selector-matched existing flow or eligible new responder `SYN`, locally delivered in the current host/netns, non-loopback ingress |

Behavior:

- handle handshake and established data in module state machine
- in peer-only mode, bare aligned `SYN` from a managed remote peer may create responder flow on any local destination port, but only when the packet is locally delivered to this host/netns
- if no flow matches and packet is not valid new bare `SYN`, reject as unknown tuple instead of passing to the real TCP stack
- consume packet before real TCP stack can generate its own reset

### 8.3 Inbound raw-UDP drop

| Item | Value |
|---|---|
| Hook | `NF_INET_PRE_ROUTING` |
| Target priority | before conntrack and before local UDP processing (`-400` in current design target) |
| Match | IPv4 UDP, selector-matched tuple, locally delivered in the current host/netns, non-loopback ingress |

Behavior:

- drop selector-matched raw inbound UDP by default
- allow unmatched or merely forwarded inbound UDP normally
- do not apply this drop to module-reinjected translated UDP

### 8.4 Decapsulated UDP reinjection

For inbound established fake-TCP data:

- build a new UDP skb using the oriented tuple
- preserve original UDP source/destination IPs and ports
- route for local input
- inject directly into post-`PRE_ROUTING` local-delivery path (`ip_route_input` + `dst_input` style)

Result:

- local UDP sockets, including kernel WireGuard and `wireguard-go`, receive data as normal UDP
- later local inbound firewall and delivery hooks still run
- translated UDP avoids the raw-UDP drop hook because reinjection occurs after `PRE_ROUTING`

### 8.5 Generated fake-TCP transmission

For module-generated fake-TCP packets:

- build a new TCP skb
- set IPv4/TCP headers and checksums explicitly
- clear conntrack association before injection
- transmit via normal local output path (`ip_local_out` style)

Because `LOCAL_OUT` steals UDP, not TCP, module-generated fake TCP does not need a complex self-bypass path.

## 9. Best-effort local flow invalidation

Some local topology changes make an existing generation unsafe to reuse.
Chosen policy:

- cache last successful routed egress device used for fake-TCP transmission
- if that device goes `GOING_DOWN`, `DOWN`, or is unregistered: invalidate flow immediately
- if the exact local IPv4 address bound into the flow tuple is removed: invalidate flow immediately
- invalidation is silent local teardown; do not fabricate `RST` from a path or source identity that no longer exists
- next outbound UDP may create a fresh generation normally

Intentionally **not** done in v1:

- no invalidation on generic FIB/default-gateway churn
- no invalidation because some other address on the device changed

Reason: every outbound send already performs a fresh route lookup using the fixed flow tuple; broad routing churn would add false positives without clear benefit.

## 10. Configuration surface

v1 uses **simple module parameters** first.
README owns user-facing parameter documentation.

Design constraints:

- up to 16 `managed_local_ports`
- up to 16 `managed_remote_peers`
- at least one selector list must be non-empty

Future control plane direction:

- generic netlink preferred for structured runtime config
- xtables/nftables integration may exist later as selector surface, not as core engine

## 11. Implementation choices worth defending

### Netfilter core, not xtables-target core

Translation, state ownership, timers, reinjection, and protocol semantics belong in a real module, not in a target callback abstraction built mainly for policy plumbing.

### Selector-based interception, not fake TCP listener sockets

This design works with existing UDP applications directly, supports local-port and exact-peer ownership, and does not lie to the kernel by pretending fake TCP is normal TCP.

### One queued UDP skb per half-open flow

One skb saves a retransmit cycle for common WireGuard behavior while keeping memory and complexity bounded.

### Deterministic tie-break instead of simultaneous open

A single surviving initiator/responder pair keeps flow ownership stable and shaping semantics unambiguous.
