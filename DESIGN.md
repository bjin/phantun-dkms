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
- At most one payload candidate starting at the **reserved lowest payload sequence number** is suppressed per direction and flow generation. Matching uses sequence, **not** arrival order or contents. Consuming that one-shot slot disarms it immediately, regardless of any later loss or sequence progress.
- A never-consumed slot is also disarmed early when observed receive `ack` progress reaches **at least 2^31 bytes** past its sequence. This is best effort: missing sequence history can hide that boundary, and an old hint cannot be distinguished perfectly from application sequence reuse. The inherited ambiguity can cost at most one candidate, not a persistent mask across wraps. Arbitrarily delayed or duplicated controls are not guaranteed to stay hidden.
- Missing, delayed, duplicated, or reordered shaping payloads do **not** fail establishment by themselves.
- Only payloads intentionally suppressed by shaping logic are hidden from the local UDP socket.
- Each candidate actually suppressed by the one-shot exception increments `shaping_payloads_dropped`, at most once per direction/generation. Ordinary established application payloads are not deduplicated.
- Completion reserves the optional response's sequence space before publishing `ESTABLISHED`, then attempts response output and releases queued responder UDP. Neither its ACK nor later client traffic is required. Transient output pressure may lose the hint without holding the queue; terminal local errors retain normal teardown semantics.

Preferred happy path:

1. initiator: `SYN`
2. responder: `SYN|ACK`
3. initiator: `ACK + handshake_request` when configured, otherwise `ACK + first queued UDP payload` when present, otherwise pure `ACK`
4. responder: `ACK + handshake_response` when both hints are configured, otherwise normal responder data may begin immediately
5. normal data continues

Implementation must also accept a pure final `ACK` followed by later payload because shaping remains optional.

### 2.3 UDP tolerance is a protocol requirement

The fake-TCP carrier transports **unreliable, unordered UDP datagrams**, not a
reliable byte stream. Design targets include paths with 70% packet loss and
200ms-or-greater latency, as well as 10Gbps LANs with sub-millisecond latency.
These are workload characteristics, not a guarantee that finite retry/expiry
budgets survive every such path. A percentage does not bound consecutive loss,
outage length, reordering age, or whether loss depends on packet size.

An earlier receive-window experiment, even with a window of at least 10MB,
was reverted after loss desynchronized its rolling state and caused valid
payloads to be dropped. A larger window does not fix a state transition that
requires unreliable packets to arrive.

The following requirements take precedence over an optimization or stronger
replay-filtering promise:

- **No general established receive window.** Gaps, reordering, duplication,
  and modulo sequence wrap do not require receipt of earlier payloads before
  ordinary UDP can be delivered. ACK bookkeeping is not proof of contiguous
  delivery and must not become an application-data admission gate.
- **No reliable shaping sub-protocol.** A configured hint may be lost,
  delayed, or duplicated. Reserve its sequence space without waiting for its
  ACK or for another client datagram before releasing responder UDP. Perfect
  duplicate-control suppression is less important than data-plane progress.
  A one-shot reserved-slot exception has a bounded suppression cost; it is not
  permission for a persistent mask retired only by observed receive progress.
- **Independent control opportunities.** Accepted inbound traffic and local
  transmit acceptance must not indefinitely suppress periodic liveness probes.
  Successful local output does not establish peer receipt. A healthy control
  exchange must not keep a blocked application queue alive indefinitely.
- **A usable budget for a new handshake phase.** The one-time local
  initiator-to-responder collision handoff retains atomic admission/queue
  ownership but receives a full responder retry and lifetime opportunity.
  It must not require the final exchange to fit an arbitrarily small remainder
  of the abandoned initiator phase. This does not authorize unbounded lifetime
  extension by repeated remote openers.
- **No inferred generation chronology.** Random ISNs identify an opener and
  resolve the existing simultaneous-open role tie; their magnitude is not
  age. Receiving a different SYN later does not prove it is newer. Do not
  quarantine a useful half-open opener solely from that inference.
- **Resource bounds remain explicit.** Admission ceilings, bounded handshake
  buffering/retries, liveness suspicion, and hard-idle expiry can still lose
  individual datagrams or end a flow. Capacity reservations and changes in
  expiry precedence require a before/after tolerance review, rather than being
  treated as reliability-neutral implementation details.

The wire has no unbounded generation identity: sufficiently delayed control
copies and wrapped sequence reuse can be ambiguous. Shaping recognition is
best effort, not a promise to hide every old copy. Existing flag/checksum/size
validation and bounded previous-generation quarantine are separate contracts;
they are not a general receive window. No delivery guarantee is made across an
arbitrarily long outage or after a configured lifetime has expired.

At a hypothetical 10Gbps of sequence-counted payload, the signed half-space
is traversed in about 1.72 seconds and a full 32-bit wrap in about 3.44 seconds.
Those are calculations, not measured module throughput; packet overhead makes
the corresponding link-rate times longer. A proof that depends on observing
receive progress before either boundary must state that extra assumption.

Validation must distinguish independent random loss from burst/size-selective
loss, one-way delay from RTT, and a fresh application retransmission from an
exact duplicate network packet. Compare against the immediate parent, including
late collisions, reordered openers, lost shaping responses, active output with
lost payload, and sequence gaps across the half-space boundary.

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

`src/phantun_config.c` parses and validates module parameters once, owns the
decoded shaping payloads, and finishes construction before any namespace or
packet hook can read the configuration. Configuration is immutable while the
module is attached and is released only after all namespaces have detached.

`src/phantun_netns.c` owns namespace attachment, TCP port reservations,
defragmentation, and topology notifiers. Normal exit withdraws packet hooks in
pernet `.pre_exit`, then destroys their state in `.exit` after the kernel's
intervening RCU grace period. Failed attachment explicitly waits for networking
readers after hook withdrawal before using the same readiness-guarded resource
cleanup. `src/phantun_main.c` retains module entry/exit and the packet hooks and
protocol state machine.

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

VRF/l3mdev support is outside this attachment contract. IPv4 local-delivery
classification consults `RT_TABLE_LOCAL`, and flow identity does not distinguish
VRFs within a namespace. Outbound interception can therefore be asymmetric with
inbound ownership, and overlapping VRF tuples are unsupported. Consulting an
l3mdev table alone would not establish support: routing, flow identity,
reinjection, and topology invalidation would also need a consistent contract.

Hook withdrawal clears `active` and unregisters every installed hook family,
but keeps the initialized flow table available to in-flight hook readers.
Neither `active = false` nor hook unregistration alone drains those readers.
For failed attachment, `synchronize_net()` runs on every initialized-table
rollback, even when neither family registration flag was set: registration can
publish the first hook in a family and internally withdraw it when a later hook
fails. Successful attachment uses the pernet `.pre_exit` / grace period / `.exit`
ordering, including module unload from live namespaces.

Only after that grace period does resource cleanup disable defragmentation,
unregister the per-net netdevice notifier, release reserved sockets, and destroy
the flow table. Table destruction retains GC cancellation, retransmit-timer
shutdown, and both finalization-work flushes before pernet storage is released.
Readiness and registration flags keep skipped namespaces inert and partial
withdrawal/resource cleanup idempotent; the grace period is never conditional on
the hook registration flags.

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
- reinjected translated UDP re-enters `PRE_ROUTING` with a namespace-private mark that exempts it from raw-UDP dropping

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

Bucket selection hashes one compact sequence of initialized `u32` words:
both endpoint families, both ports, scope, and only the active address bytes.
It excludes structure padding and unused IPv4 union storage, so equal
endpoints always choose the same bucket regardless of their backing bytes.
Each table retains its random hash seed; bucket collisions still require
full endpoint equality under the bucket lock.

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

A different bare `SYN` in `SYN_RCVD` is rejected with `RST` and removes the
half-open flow; it does not replace it or quarantine the previous opener.
A useful opener can retry to create a fresh responder and complete normally.
Arrival order and random ISN magnitude do not identify generation age.
Identical current openers still retransmit the same `SYN|ACK`.
Bare `SYN` packets are exempt from previous-generation quarantine and use the
state-specific duplicate/replacement rules instead.

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
- higher ISN loses initiator role and atomically replaces its generation with a responder
- exact ISN tie: drop and rely on retransmission

This avoids NAT-sensitive endpoint heuristics and keeps shaping unambiguous.

The losing handoff retains its **local-origin** admission token without
releasing/reacquiring capacity. With the tuple bucket and old flow lock held,
the transaction revalidates a local-origin `SYN_SENT` initiator before moving
the queued skb, its packet metadata, and the independently maintained local
transmit policy. Allocation or revalidation failure leaves the old owner and
queue intact; a concurrent handshake completion cannot be replaced.
Publication starts a fresh `SYN_RCVD` phase: zero retries spent, the full table
retry budget, a new next retry deadline, and fresh activity, inbound, and periodic
probe timestamps. Only this one-time role change restarts the phase; a different
opener in `SYN_RCVD` still follows the strict rejection policy.
An old retransmit callback already emitting retains its own timer reference,
observes `DEAD` on return, and is drained by finalization. The old table reference
transfers to process-context finalization only after dropping its flow lock;
the new timer and table take their own references before the bucket is unlocked.
Old and new flow locks are never held together, and packet emission occurs only
after dropping the bucket, flow, and admission locks.

### 5.5 One queued UDP skb

Half-open flow buffering is intentionally small:

- queue **at most one** outbound UDP skb per handshaking flow
- save one retransmit cycle for common WireGuard behavior
- bound memory and complexity
- anything beyond the first queued skb is dropped

Queued skb metadata is separate from the persistent local transmit policy.

### 5.6 Protected half-open admission

`half_open_limit = L` remains the total admitted half-open ceiling per selected
network namespace, shared by enabled address families and selectors. Reserve
`R = max(1, floor(L / 4))` slots for **local-origin** work when `L > 1`; for
`L = 1`, use `R = 0` so remote initiation remains possible.

Remote-origin flows may occupy at most `L - R` slots. Local-origin flows may
use all unused total capacity. The token records its charged origin independently
of state and role: a simultaneous-open loser remains local-origin even as a
responder. The admission lock serializes total/remote charging, token transfer,
and exactly-once release on establishment or any terminal exit. Neither a
handoff nor a failed duplicate publication releases and reacquires a live token.
An already detached generation cannot accept a newly queued skb through a
cached pre-handoff state snapshot.

This bounds admitted half-opens, not all module memory: allocation precedes
admission, finalizing objects may retain references, and established flows are
outside this count. A one-slot namespace cannot guarantee both remote admission
and a protected local slot.

## 6. Per-flow state machine

Each flow stores:

- role: `INITIATOR` or `RESPONDER`
- state
- oriented local/remote addresses
- send sequence number
- receive acknowledgement number
- one queued UDP skb pointer, used only during the handshake
- one-shot reserved first-payload shaping slot
- retransmit timer state, with expiry owned by the kernel timer itself
- idle and inbound-liveness timestamps
- independent 64-bit next-probe deadline, initialized to creation time plus the keepalive interval
- last successful established local-payload transmit timestamp for ACK suppression
- initiator bare-`SYN` replacement-protection deadline
- refcount and lock

Established ACK/data processing has a locked preparation phase and an unlocked
execution phase. The initial flow lock covers generation classification,
quarantine, one-shot shaping consumption, raced final-ACK payload protection,
ACK/window progress, and liveness updates. A small stack action then selects
ignore/quarantine, payload delivery, or oversized rejection.
Pure ACKs refresh liveness without advancing the payload ACK. Only raced
opening application replays suppress delivery and progress; ordinary established
application copies still deliver and refresh normal monotonic progress/liveness.
The actual suppressed shaping candidate retains monotonic progress and a
mandatory ACK. Oversized delivery is rejected before ACK/liveness changes.

The hook retains its lookup reference across both phases. Handshake payload
delivery rechecks `ESTABLISHED` when committing progress; an already committed
action can finish concurrently with later teardown without losing that
reference. No packet allocation, routing, reinjection, or transmission occurs
under the preparation lock. Handshake completion flushes its queue before the
idle-ACK suppression decision, so a just-flushed or concurrent local payload
can carry the ACK. Ordinary established receive has no response-gated queue to
release. The separate `tx_lock` still orders sequence reservation and rollback.

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
- ordinary ACK-shaped packets (ACK required, PSH optional, no SYN/RST/FIN/URG) that do not complete the handshake → silently ignore; retain queue and retry/lifetime state

On valid `SYN|ACK`:

- set `ack = responder_seq + 1`
- if `handshake_request` configured: send `ACK + handshake_request`
- else if queued UDP exists: send `ACK + first queued UDP payload`
- else: send pure final `ACK`
- if both `handshake_request` and `handshake_response` configured: reserve a one-shot shaping slot for payload starting at `responder_seq + 1`
- arm the non-sliding established-initiator replacement-protection deadline
- transition immediately to `ESTABLISHED`

#### `ESTABLISHED`

Behavior:

- if `handshake_request` was injected, flush initiator-owned queued UDP after that injected request
- consume the pending responder shaping slot on the first payload starting at its reserved sequence; suppress that one candidate only
- later higher-sequence responder payloads deliver normally
- normal UDP ↔ fake-TCP translation follows
- accepted inbound packet refreshes liveness suspicion, including pure `ACK` and handshake-response acknowledgement traffic
- accepted inbound payload normally sends an immediate pure `ACK`
- that immediate payload `ACK` may be skipped only when this endpoint sent established fake-TCP payload data on the same flow within the fixed 250 ms suppression window
- reserved first-payload control drops still send the immediate pure `ACK`; they are not eligible for suppression
- receive-only flows and flows outside that window keep the previous immediate pure-`ACK` behavior
- every `keepalive_interval_sec`: send a periodic pure `ACK` keepalive, independently of accepted RX and successful ordinary/control TX; local output acceptance is not peer acknowledgement
- GC collects due candidates with a temporary reference, then rechecks state and deadline under the flow lock before reserving `now + interval`; output runs outside bucket/flow locks and both failed and successful attempts keep the reservation
- only probe attempt reservation advances the 64-bit deadline during a flow phase; delayed work does not create catch-up bursts, and output completing after death never reschedules the generation
- the separate 250 ms payload-ACK suppression marker and existing hard-idle activity updates remain unchanged; keepalive attempts do not refresh hard-idle activity or inbound liveness
- after `max(2, keepalive_misses) * keepalive_interval_sec` without valid inbound traffic: send a best-effort `RST` if the stored route/source identity can still transmit, then destroy local state
  - if RST emission fails, destroy local state silently
  - if one outbound UDP skb is already queued, create fresh `SYN_SENT`, carry that skb, send `SYN`
  - otherwise wait for future outbound UDP

`keepalive_misses` sets an inbound-silence interval budget, not a count of
actual unanswered packets. Values of 1 and 2 both give two intervals of
inbound silence, leaving a full nominal response interval after the first
probe is due. The default interval of 30 seconds and budget of 3 give a
90-second timeout. GC runs at `min(30 seconds, interval / 2)` (at least one
jiffy); scheduling delay and RTT still consume the response window.
The complete silence timeout uses the same minimum-two factor in validation
and construction and is checked against the signed jiffies range before
multiplication. Hard-idle expiry retains
precedence and is silent. Both endpoints must use independent scheduling for
healthy idle survival: new probes can still suppress an older peer's
inbound-driven schedule. Pure ACKs are not answered merely to sustain liveness.

The hard-idle check measures elapsed jiffies since `last_activity_jiffies`,
using the configured timeout; it is not a maximum generation age or application-idle
deadline. Accepted inbound packets, including pure ACKs/keepalives, refresh
activity alongside the inbound-liveness clock. Local queue admission and
successful payload/immediate-control sends can also refresh activity, but
periodic keepalive attempts do not. Healthy control traffic can thus sustain an
application-idle generation indefinitely. A DEAD tombstone is collected using
its retained activity timestamp, without granting a new timeout at retirement.
If terminal removal cannot allocate retired sequence metadata, the hashed DEAD
tombstone preserves the reopen sequence identity and still counts toward hash
occupancy. Its abandoned queued UDP skb is detached under the flow lock and
freed outside bucket/flow locks, releasing any attached socket reference without
waiting for tombstone expiry. This terminal discard does not change half-open
liveness-GC replay or simultaneous-open queue transfer.

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
- ordinary ACK-shaped traffic that does not carry the exact final acknowledgement → silently ignore, without establishing, emitting `RST`, or refreshing retries/activity/liveness

Exact valid completion is checked first; previous-generation quarantine then
takes precedence over generic stray-ACK tolerance. Malformed flags and
different or misaligned `SYN` retain rejection/removal, and known-tuple `RST`
retains its existing teardown/quarantine policy.

On valid final `ACK`:

- advance local `seq` to `responder_seq + 1`
- if `handshake_request` configured: reserve the one-shot inbound shaping slot at `initiator_seq + 1`, whether the final ACK is pure or carries payload
- suppress final-ACK payload only when it starts at that reserved sequence, consuming the slot immediately
- if both shaping hints configured, reserve `handshake_response.len()` bytes in local `seq` before publishing `ESTABLISHED`, then attempt `ACK + handshake_response`
- release any queued responder UDP after the optional response attempt, without waiting for its ACK or later initiator traffic
- deliver non-control payload from the winning final ACK; stale half-open receive snapshots cannot deliver that winner's payload a second time

The queue decision and handshake completion share `flow->lock`. A LOCAL_OUT
snapshot that became stale returns its still-owned skb for the existing
dispatch retry, rather than queueing into an established flow after the
completion flush. Queue-full local output still updates `local_tx_meta`, but
never overwrites the queued skb's exact `queued_tx_meta`. No new queue entries
are admitted after establishment.

#### `ESTABLISHED`

Behavior:

- outbound UDP becomes `ACK + payload`
- inbound fake-TCP payload becomes local UDP unless it consumes the pending one-shot shaping slot
- payload larger than the translator's maximum supported UDP reinjection size is invalid and rejected with `RST|ACK`
- `seq` grows by outbound payload length
- `ack` tracks peer `seq + payload_len`
- accepted inbound packet refreshes liveness suspicion
- accepted inbound payload normally sends an immediate pure `ACK`
- that immediate payload `ACK` may be skipped only when this endpoint sent established fake-TCP payload data on the same flow within the fixed 250 ms suppression window
- the one suppressed shaping candidate still sends the immediate pure `ACK`; it is not eligible for ACK suppression and never postpones periodic keepalives
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
- malformed handshake controls (ordinary stale ACK/data on an existing half-open tuple is an explicit silent exception)
- impossible flag/state combination
- oversized inbound payload beyond the translator's supported UDP reinjection size
- non-`RST` packet for unknown tuple

Peer-only mode keeps this rule: if a packet from a managed remote peer does not match local flow state and is not a valid new bare `SYN`, reject with `RST` instead of silently dropping it.

### 7.2 Silent cases

- stray inbound `RST` for unknown tuple
- inbound `RST` for known tuple: destroy local state, no reply
- inbound packets failing TCP checksum validation
- packets from immediately previous generation while quarantine is active
- ordinary stale ACK/data during `SYN_SENT` or `SYN_RCVD`: keep the half-open and its queued UDP, with no timer/lifetime refresh
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
`-ENOMEM`) and path-MTU refusal (`-EMSGSIZE`) drop only the affected payload or
control packet and keep the flow generation live. Half-open handshake packets
remain armed for timer retry, and established payload sequence space is not
reused. Established `-EMSGSIZE` sends are counted as oversized drops rather than
translation failures. Terminal routing or structural errors such as unreachable
routes, unsupported families, access denial, or invalid packet construction
still tear down the affected generation.

### 7.5 Spoofing posture

Inbound `RST` on a known tuple and inbound aligned bare replacement `SYN` on an
established tuple are accepted without current-generation sequence-window
validation; data-path window validation is deliberately absent because payloads
are UDP.

Consequence: an off-path sender who knows the 4-tuple can tear down or replace
a generation with one checksum-valid packet. Replacement-protect shields
established initiator-role flows only; the exact current-opener duplicate `SYN`
is exempt on responders; an active replacement quarantine incidentally filters
`RST`s classified into the previous-generation window.

Posture: accepted v1 tradeoff (peers recover by re-handshake). A future
hardening, if ever needed, is gating the `RST` path on the existing
current-generation window check (`remote_seq_window_start..ack` /
`local_seq_window_start..seq`) without touching data-path semantics.

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

Early confirmation preserves the original UDP conntrack identity for stateful
firewall handling of reinjected replies; it does not provide ordinary UDP NAT
traversal. The stolen packet never reaches later `LOCAL_OUT` DNAT or
`POST_ROUTING` SNAT/MASQUERADE hooks. Generated fake TCP is untracked, and owned
inbound fake TCP is consumed before carrier conntrack/NAT, so ordinary
conntrack-based host NAT must not be assumed to translate the carrier either.
Reinjected UDP still traverses later ingress conntrack/filter processing. NAT
performed elsewhere on the path is a separate deployment concern.

Outbound translation caps generated fake-TCP IP packets at 1500 bytes, allowing
UDP payloads of at most 1460 bytes over IPv4 or 1440 bytes over IPv6. This is a
fixed builder limit, not a discovered path MTU; smaller paths can impose a lower
limit, and larger paths do not raise it. Oversized outbound payloads are
consumed/dropped without a size error or PMTU feedback to the original UDP
socket, incrementing both `oversized_payloads_dropped` and `udp_packets_dropped`.
The limit applies per datagram after UDP GSO segmentation.

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

One `PRE_ROUTING` hook per family selects its IP parser from `state->pf`,
not `skb->protocol`, then parses L3 and discovers the final TCP/UDP protocol
before dispatching raw-UDP ownership or fake-TCP handling. IPv6
extension headers are walked once from the outer header, and borrowed header
pointers are refreshed after any pull that can relocate the skb head. Parsing
does not advance `skb->transport_header`, so unowned packets can resume normal
IPv6 extension-header processing. Only owned TCP gets its transport offset
set for segmentation. There is no equal-priority registration-order dependency.

The dispatcher consumes the private reinjection mark before loopback and
protocol dispatch, but exempts only UDP from raw-UDP dropping. TCP carrying an
externally applied matching mark still follows normal selector checks and
fake-TCP validation; the cookie must never become a TCP bypass.
The cookie occupies one random high-bit value in the shared `skb->mark` space
per attached namespace, not an isolated metadata field. An externally applied
exact match is therefore cleared even on loopback or non-UDP packets; a matching
UDP packet is indistinguishable from reinjection and also bypasses raw-UDP
dropping. Randomization avoids common low marks but does not eliminate
collisions or provide an authenticated exemption.

### 8.4 Decapsulated UDP reinjection

For inbound established fake-TCP data:

- build a new UDP skb using the oriented tuple
- preserve original UDP source/destination IPs and ports
- fuse copying and checksum accumulation for head-contiguous payloads; for fragmented skbs, use a checked copy followed by one contiguous checksum to avoid per-fragment checksum folding
- complete the checksum by adding the UDP header and family-specific pseudo-header to the payload sum
- retain a complete nonzero UDP checksum (`CSUM_MANGLED_0` for a computed zero) and mark the manufactured skb `CHECKSUM_UNNECESSARY`
- inject through the original ingress device with `netif_rx()` so receive processing uses that device's network namespace
- require the original ingress device namespace to match the netfilter hook namespace before reinjecting
- mark reinjected UDP so the UDP branch of the ingress dispatcher exempts the manufactured skb on its second `PRE_ROUTING` pass

Result:

- local UDP sockets, including kernel WireGuard and `wireguard-go`, receive data as normal UDP
- later inbound firewall and delivery hooks still run in the same netns as the intercepted fake-TCP packet
- translated UDP avoids raw-UDP dropping because the ingress dispatcher consumes its reinjection mark

#### IPv4 reverse-path filtering

Reinjected UDP retains the fake-TCP packet's ingress device. With strict IPv4 `rp_filter=1`, policy routing may resolve the UDP peer through a tunnel instead of that ingress device and drop the packet before local delivery. IPv6 has no kernel `rp_filter` equivalent, although firewall-based reverse-path checks can impose the same constraint.

The module does not change host source-validation policy; deployments must use loose RPF or an explicit WireGuard peer rule.

### 8.5 Generated fake-TCP transmission

For module-generated fake-TCP packets:

- build a new TCP skb
- set IPv4/TCP or IPv6/TCP headers explicitly; emit the TCP checksum as `CHECKSUM_PARTIAL` with a pseudo-header seed for the device or `skb_checksum_help` to resolve
- emit generated fake TCP as conntrack-untracked (`IP_CT_UNTRACKED`) before local output so conntrack never tracks the half-visible fake-TCP exchange
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

`local_tx_meta` is used only for outbound generated fake-TCP packets. It must not be updated from inbound fake-TCP packets and must not affect inbound UDP reinjection. Decapsulated UDP uses its own receive-path skb and only the private mark needed to bypass the ingress dispatcher's raw-UDP drop branch.

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
