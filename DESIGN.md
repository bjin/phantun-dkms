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

- removing the separate IPv4/IPv6 family split in packet-boundary helpers
- user-space Phantun interoperability guarantees
- eBPF as the primary implementation
- xtables target as the core data plane
- real kernel TCP listener/service implementation

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

### 4.2 Namespace attachment

`managed_netns=init|all` is the outer attachment boundary.

| Value | Effect |
|---|---|
| `init` | Default. Attach only to `init_net`. |
| `all` | Attach to every network namespace through pernet init. |

Only selected namespaces receive a flow table, per-net netdevice notifier, reserved local TCP sockets, and IPv4/IPv6 netfilter hooks. The selector rules below still decide traffic ownership inside each selected namespace. Skipped namespaces must remain invisible to global address notifiers and exit as no-ops because their pernet storage has no initialized flow table.

### 4.3 Interception selectors

The translator owns traffic based on two optional selector lists.
A packet must satisfy **every configured selector**.

| Selector | Purpose |
|---|---|
| `managed_local_ports` | Local UDP/TCP ports the translator owns |
| `managed_remote_peers` | Exact remote `IPv4:port` or `[IPv6]:port` peers the translator owns |

Selector modes:

| Mode | Outbound match | Inbound fake-TCP match |
|---|---|---|
| Local-only | local source port | local destination port |
| Peer-only | remote destination `IPv4/IPv6:UDP port` | remote source `IPv4/IPv6:TCP port` |
| Intersection | both must match | both must match |

Constraints:

- at least one selector list must be non-empty
- selector ownership applies only to **non-loopback** traffic
- inbound selector ownership applies only after confirming the destination address is locally delivered to the current host/netns; forwarded traffic is never translator-owned
- outbound UDP routed to loopback stays UDP
- inbound fake TCP arriving on loopback is ignored by the module
- raw inbound UDP arriving on loopback is not subject to selector-owned drop

- `ip_families=both|ipv4|ipv6` gates which netfilter families are registered; default `both` registers both families when kernel IPv6 support is available
- IPv6 `managed_remote_peers` entries must use bracketed `[IPv6]:port` syntax; unbracketed IPv6 is rejected
- `managed_remote_peers` is exact-address matching; remote privacy-address rotation is a new remote endpoint and requires config update unless local-port selection is used instead
- IPv6 link-local endpoint addresses are intentionally unsupported and rejected until scoped link-local flow identity, validation, and invalidation are implemented consistently
Peer-only caveat:

- inbound TCP ownership becomes broad for that remote `IPv4:port` or `[IPv6]:port`
- use peer-only mode only when that remote peer is dedicated to this translator

### 4.4 Optional local TCP reservation guard

Local-only mode selects inbound fake TCP by destination port, but selector ownership alone does not make the module the real TCP owner of that port. Operators that want the kernel to reject competing TCP listeners can configure `reserved_local_ports`.

Rules:

- effective only when `managed_local_ports` is set and `managed_remote_peers` is empty
- during `phantun_net_init()`, the module attempts wildcard TCP binds for each effective reserved port and enabled family in selected netns (`0.0.0.0:port`, `[::]:port`)
- those sockets stay bound until `phantun_net_exit()`
- bind failures are logged and do not disable interception in that namespace
- wildcard bind intentionally blocks loopback listeners on the same port too

This is a defensive ownership guard only. The module does **not** call `listen()`, does **not** accept connections, and does **not** behave like a real TCP service endpoint.

### 4.5 Default inbound raw-UDP drop

By default, raw inbound UDP that matches configured selectors, is destined for local delivery in the current host/netns, and arrives from a non-loopback device is dropped in `PRE_ROUTING`.

Reason:

- selector-matched traffic must have one owner
- allowing both raw UDP delivery and translated fake-TCP delivery would create ambiguous mixed delivery
- forwarded UDP is not translator-owned traffic and must continue through the normal routing path
- reinjected translated UDP enters after `PRE_ROUTING`, so translated traffic is not black-holed by this drop rule

## 5. Flow identity and conflict handling

### 5.1 Local-oriented endpoint identity

A flow is keyed by the packet-boundary local/remote endpoint pair, including address family:

- `local` is always this host/netns endpoint
- `remote` is always the peer endpoint
- family + address bytes + ports are matched directly
- outbound UDP and inbound fake TCP therefore land in the same flow without canonical tuple sorting

- IPv4 secondary addresses and IPv6 global temporary/deprecated addresses remain distinct endpoint identities; translated fake-TCP packet headers and route lookups use the exact stored local address rather than substituting another local address
- IPv6 link-local addresses are rejected for both local and remote endpoint positions because current scope handling is not a complete scoped-link-local contract

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

### 5.3 Replacement-generation quarantine and protection

If an established flow accepts a valid bare replacement `SYN` on the same tuple:

- destroy current generation
- keep a short quarantine record for the immediately previous generation only
- during that short window, packets that still look like the old generation are silently dropped instead of provoking `RST`
- after expiry, normal unknown-tuple handling resumes
- v1 default quarantine window: `3000 ms` (`replacement_quarantine_ms`)

Purpose: avoid poisoning recovery with delayed old-generation packets just after tuple reuse.

Established initiator flows also arm a non-sliding bare-`SYN` replacement protection deadline when the `SYN_SENT` handshake accepts a clean `SYN|ACK`.
During that deadline, a bare aligned replacement `SYN` is silently dropped before generic replacement handling.
This covers delayed loser `SYN` packets from simultaneous initiation without changing responder duplicate-`SYN` handling.
`replacement_protect_ms = 0` means auto: use `min(replacement_quarantine_ms, handshake_timeout_ms * max(1, handshake_retries / 2))`.
A non-zero `replacement_protect_ms` is used directly, and replacement behavior resumes unchanged after the deadline expires.

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
- idle and inbound-liveness timestamps
- last successful established local-payload transmit timestamp for ACK suppression
- initiator bare-`SYN` replacement-protection deadline
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
- arm the non-sliding established-initiator replacement-protection deadline
- transition immediately to `ESTABLISHED`

#### `ESTABLISHED`

Behavior:

- if `handshake_request` was injected, flush initiator-owned queued UDP after that injected request
- if responder first-payload ignore slot is armed, suppress only payload whose starting sequence matches reserved responder control sequence
- later higher-sequence responder payloads deliver normally
- normal UDP ↔ fake-TCP translation follows
- accepted inbound packet refreshes liveness suspicion, including pure `ACK` and handshake-response acknowledgement traffic
- accepted inbound payload normally sends an immediate pure `ACK`
- that immediate payload `ACK` may be skipped only when this endpoint sent established fake-TCP payload data on the same flow within the fixed 250 ms suppression window
- reserved first-payload control drops still send the immediate pure `ACK`; they are not eligible for suppression
- receive-only flows and flows outside that window keep the previous immediate pure-`ACK` behavior
- after `keepalive_interval_sec` without valid inbound traffic: send pure `ACK` keepalive
- the suppression window does not change this inbound-driven liveness rule
- after `keepalive_misses * keepalive_interval_sec` without valid inbound traffic: send a best-effort `RST` if the stored route/source identity can still transmit, then destroy local state
  - if RST emission fails, destroy local state silently
  - if one outbound UDP skb is already queued, create fresh `SYN_SENT`, carry that skb, send `SYN`
  - otherwise wait for future outbound UDP

Inbound flag priority in established state:

1. `RST` → destroy local state silently
2. duplicate current-generation `SYN|ACK` → send pure `ACK`, keep current generation
3. bare aligned `SYN` while the established-initiator replacement protection deadline is active → silently drop, keep current generation
4. bare aligned `SYN` with no payload, no `ACK`, and no other control flags → accept as generation replacement, move old generation into quarantine, create new responder `SYN_RCVD`, send `SYN|ACK`
5. any other packet with `SYN` set → send `RST|ACK`, destroy local state
6. otherwise → normal data processing

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
- payload larger than the translator's maximum supported UDP reinjection size is invalid and rejected with `RST|ACK`
- `seq` grows by outbound payload length
- `ack` tracks peer `seq + payload_len`
- if injected responder `handshake_response` still awaits acknowledgement, responder UDP follows the one-skb queue/drop rule until release
- accepted inbound packet refreshes liveness suspicion
- accepted inbound payload normally sends an immediate pure `ACK`
- that immediate payload `ACK` may be skipped only when this endpoint sent established fake-TCP payload data on the same flow within the fixed 250 ms suppression window
- reserved first-payload control drops still send the immediate pure `ACK`; they are not eligible for suppression
- receive-only flows and flows outside that window keep the previous immediate pure-`ACK` behavior
- if a payload-bearing final `ACK` transitions the responder to established and also flushes queued responder UDP first, the flushed data can carry the pre-payload `ack`; suppressing the follow-up pure `ACK` briefly leaves that acknowledgement lagging until later traffic because the protocol has no data retransmit
- keepalive, liveness failure, and hard idle teardown use the same policy as initiator-established flows

Inbound flag priority:

1. `RST` → destroy flow silently
2. duplicate current-generation bare `SYN` → re-emit `SYN|ACK`, keep current generation
3. bare aligned replacement `SYN` with no payload, no `ACK`, and no other control flags → replace generation, quarantine old generation, create new `SYN_RCVD`, send `SYN|ACK`
4. any other packet with `SYN` set → send `RST|ACK`, destroy flow
5. otherwise → normal data processing

## 7. Failure policy

### 7.1 Immediate `RST` + flow destruction

- bad `SYN` alignment
- wrong final `ACK` during handshake
- impossible flag/state combination
- oversized inbound payload beyond the translator's supported UDP reinjection size
- non-`RST` packet for unknown tuple

Peer-only mode keeps this rule: if a packet from a managed remote peer does not match local flow state and is not a valid new bare `SYN`, reject with `RST` instead of silently dropping it.

### 7.2 Silent cases

- stray inbound `RST` for unknown tuple
- inbound `RST` for known tuple: destroy local state, no reply
- inbound packets failing TCP checksum validation
- packets from immediately previous generation while quarantine is active
- shaping-payload loss, duplication, delay, or reordering
- established liveness failure falls back to silent teardown only when best-effort `RST` emission cannot route or transmit
- topology-driven invalidation and hard idle expiry: local teardown without `RST`

### 7.3 Handshake loss tolerance

The translator must tolerate loss of handshake-path packets within retry budget:

- lost initiator `SYN` → stay `SYN_SENT`, retransmit `SYN`, keep at most one queued UDP skb
- lost responder `SYN|ACK` → stay `SYN_RCVD`, retransmit `SYN|ACK` on timer and duplicate `SYN`
- lost `handshake_request` or `handshake_response` → establishment still stands; later higher-sequence payloads may proceed
- retry exhaustion before three-way handshake completes → tear down half-open flow and signal with `RST`

### 7.4 Local I/O pressure

Transient local queue or memory pressure (`NET_XMIT_DROP`, `-ENOBUFS`, or
`-ENOMEM`) drops only the affected payload or control packet and keeps the flow
generation live. Half-open handshake packets remain armed for timer retry, and
established payload sequence space is not reused. Terminal routing or structural
errors such as unreachable routes, unsupported families, access denial, or
invalid packet construction still tear down the affected generation.

## 8. Packet path in kernel

### 8.1 Outbound UDP interception

| Item | Value |
|---|---|
| Hook | `NF_INET_LOCAL_OUT` |
| Target priority | after initial `LOCAL_OUT` conntrack classification (`-199` in current design target) |
| Match | IPv4 or IPv6 UDP, non-loopback egress, selector-matched tuple |

Behavior:

- established flow → consume UDP skb, emit fake-TCP skb
- handshaking flow → queue one skb or drop
- no flow → create initiator flow, queue one skb, send `SYN`
- zero-payload UDP on an owned tuple is consumed/dropped instead of translated because fake-TCP payload data rides in ACK payloads and has no empty datagram representation
- outbound UDP GSO superframes are software-segmented before translation; each segment is translated independently and the half-open one-skb queue rule applies per segment
- if skb already carries conntrack state, confirm original UDP entry before stealing packet so translated inbound replies can match established host-firewall policy
- copy the outbound UDP packet's transmit metadata to the generated fake-TCP packet
- original UDP skb is stolen from the stack

### 8.2 Inbound fake-TCP interception

| Item | Value |
|---|---|
| Hook | `NF_INET_PRE_ROUTING` |
| Target priority | before conntrack and before real TCP processing (`PHANTUN_PRE_ROUTING_PRIORITY`, `-399`) |
| Match | IPv4 or IPv6 TCP, selector-matched existing flow or eligible new responder `SYN`, locally delivered in the current host/netns, non-loopback ingress |

Behavior:

- handle handshake and established data in module state machine
- in peer-only mode, bare aligned `SYN` from a managed remote peer may create responder flow on any local destination port, but only when the packet is locally delivered to this host/netns
- if no flow matches and packet is not valid new bare `SYN`, reject as unknown tuple instead of passing to the real TCP stack
- consume packet before real TCP stack can generate its own reset
- inbound fake-TCP metadata may be copied only to fake-TCP replies caused by that same inbound packet

### 8.3 Inbound raw-UDP drop

| Item | Value |
|---|---|
| Hook | `NF_INET_PRE_ROUTING` |
| Target priority | raw-UDP drop runs at `PHANTUN_PRE_ROUTING_PRIORITY` (`-399`), before conntrack and local UDP processing, after IPv4/IPv6 defrag at `-400` |
| Match | IPv4 or IPv6 UDP, selector-matched tuple, locally delivered in the current host/netns, non-loopback ingress |

Behavior:

- drop selector-matched raw inbound UDP by default
- allow unmatched or merely forwarded inbound UDP normally
- do not apply this drop to module-reinjected translated UDP

raw-UDP drop and fake-TCP interception both use priority `-399`. Linux inserts equal-priority hooks before existing entries, so the ops arrays register `phantun_pre_routing` before `phantun_pre_routing_udp_drop` and selector-matched raw UDP executes first.

### 8.4 Decapsulated UDP reinjection

For inbound established fake-TCP data:

- build a new UDP skb using the oriented tuple
- preserve original UDP source/destination IPs and ports
- inject through the original ingress device with `netif_rx()` so receive processing uses that device's network namespace
- require the original ingress device namespace to match the netfilter hook namespace before reinjecting
- mark reinjected UDP so the module's raw-UDP drop hook exempts the manufactured skb on its second `PRE_ROUTING` pass

Result:

- local UDP sockets, including kernel WireGuard and `wireguard-go`, receive data as normal UDP
- later inbound firewall and delivery hooks still run in the same netns as the intercepted fake-TCP packet
- translated UDP avoids the raw-UDP drop hook because the reinjection mark is consumed by that hook

### 8.5 Generated fake-TCP transmission

For module-generated fake-TCP packets:

- build a new TCP skb
- set IPv4/TCP or IPv6/TCP headers and checksums explicitly for the active family
- clear conntrack association before injection
- transmit via the normal family-specific local output path (`ip_local_out` / `ip6_local_out` style)
- apply the selected per-packet transmit metadata before routing and local output

Because `LOCAL_OUT` steals UDP, not TCP, module-generated fake TCP does not need a complex self-bypass path.

### 8.6 Transmit metadata propagation

Metadata is treated as **per-packet transmit context**, not as flow identity.

For fake-TCP packets generated from a current outbound UDP skb:

- copy the UDP skb mark and priority
- copy IPv4 TOS, or IPv6 traffic-class / flow-label
- copy socket UID and explicitly bound output interface when available
- use that metadata for the generated fake-TCP skb and route lookup

For fake-TCP replies generated directly from an inbound fake-TCP packet, such as responder `SYN|ACK` or an injected `handshake_response`:

- copy inbound fake-TCP metadata only for that immediate reply
- do not persist inbound metadata in the flow
- do not let inbound marks, TOS, traffic-class, flow-label, or priority affect later outbound packets

A flow stores only `local_tx_meta`: the last known local outbound UDP transmit policy context. It exists only because some outbound fake-TCP packets have no original UDP skb to copy from:

- handshake retransmits (`SYN`, `SYN|ACK`)
- configured handshake control payloads when no queued UDP payload is being emitted
- keepalive `ACK`s
- local liveness / teardown control packets such as best-effort `RST`

`local_tx_meta` is used only for outbound generated fake-TCP packets. It must not be updated from inbound fake-TCP packets and must not affect inbound UDP reinjection. Decapsulated UDP reinjection uses its own receive-path skb and only uses the private reinjection mark needed to bypass the module's raw-UDP drop hook.

## 9. Best-effort local flow invalidation

Some local topology changes make an existing generation unsafe to reuse.
Chosen policy:

- cache last successful routed egress device used for fake-TCP transmission
- if that device goes `GOING_DOWN`, `DOWN`, or is unregistered: invalidate flow immediately
- if the exact local IPv4 or IPv6 address bound into the flow tuple is removed: invalidate flow immediately
- invalidation is silent local teardown; do not fabricate `RST` from a path or source identity that no longer exists
- this is intentionally stricter than established liveness failure: topology invalidation must not fabricate `RST` from a path or source identity known to be stale
- next outbound UDP may create a fresh generation normally

Intentionally **not** done in v1:

- no invalidation on generic FIB/default-gateway churn
- no invalidation because some other address on the device changed

- no invalidation on IPv6 address deprecation or temporary-address flag changes; flows are invalidated only when the exact local address is removed
Reason: every outbound send already performs a fresh route lookup using the fixed flow tuple; broad routing churn would add false positives without clear benefit.

## 10. Configuration surface

v1 uses **simple module parameters** first.
README owns user-facing parameter documentation.

Design constraints:

- up to 64 `managed_local_ports`
- up to 64 `managed_remote_peers`
- at least one selector list must be non-empty
- `ip_families` is one of `both`, `ipv4`, `ipv6`; default `both`
- `managed_netns` is one of `init`, `all`; default `init`
- `reopen_guard_bytes < 2^30`
- malformed explicit `hex:`/`base64:` shaping payloads are load errors; unsupported Base64 decode on older kernels remains a warned no-payload fallback

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
