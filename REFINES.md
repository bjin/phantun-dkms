# phantun-kmod design refinement recommendations

This document records the recommended design changes for making the current symmetric fixed-port kernel design more survivable on the real Internet.

It is written to survive context loss after compaction.

The goal is not to make roaming/NAT rebinding magically perfect. That is not realistic as long as the outer wrapper still looks like stateful TCP to middleboxes.

The goal is a best-effort redesign that:
- avoids obviously broken assumptions
- improves recovery after path breakage or stale state
- makes simultaneous recovery deterministic again
- tightens liveness behavior so stale flows do not linger for minutes

---

# 0. Constraints and baseline reality

Before the individual recommendations, keep these realities in mind:

1. The outer fake-TCP transport is stateful.
2. The real Internet path contains NATs and middleboxes we do not control.
3. NATs can rewrite outer IP/port and can change those mappings later.
4. Middleboxes can forget state independently on each side.
5. Because traffic looks like TCP, true seamless roaming is not realistically achievable in general.
6. Therefore the practical target is best-effort break detection and fast re-establishment, not transparent live-session migration.

That framing matters. Several recommendations below are about making reconnection safe and deterministic, not about pretending the old connection can be preserved forever.

---

# A. Replace tuple-based simultaneous-open tie-break with SYN-ISN tie-break

## Problem being fixed

The current tie-break compares endpoint tuples. That fails across NAT because the two peers do not necessarily see the same tuple:
- one side sees its pre-NAT local tuple in `LOCAL_OUT`
- the other side sees the post-NAT public tuple

Therefore the current rule is not globally deterministic in real deployments.

## Recommendation

Use the initiator SYN initial sequence numbers themselves to break ties.

### Rule
When both sides are in `SYN_SENT` and receive a bare inbound `SYN` for the same conceptual flow:
- compare the two SYN ISNs
- lower ISN wins initiator role
- higher ISN loses initiator role and becomes responder
- if equal, drop the incoming SYN and rely on retransmit/retry

## Why this is better

Unlike endpoint tuples, SYN sequence numbers are:
- chosen by the endpoint
- visible on the wire to both sides
- not rewritten by NAT

So both sides can compare the same two values.

## Important details

1. Retransmitted SYN must keep the same ISN.
2. A brand-new reinitiation attempt after local teardown must use a fresh ISN.
3. Equal ISN is extremely unlikely because initiator ISNs are aligned to `4095`, leaving about `2^32 / 4095` usable values. Equality is roughly a 1-in-1,048,833 event, so dropping and retrying is acceptable.

## Effect

This recommendation directly addresses the NAT-broken tie-break flaw.

---

# B. Add aggressive liveness probing instead of relying on coarse idle GC

## Problem being fixed

`idle_timeout_sec` today behaves as coarse garbage collection:
- default 180 seconds
- checked by a GC worker every 30 seconds
- refreshed by broad phantun activity, not just meaningful peer communication

That means stale flows can remain alive for far too long and interfere with recovery.

## Recommendation

Split liveness from garbage collection.

Introduce separate concepts:
- `keepalive_interval_sec`
- `keepalive_misses`
- optionally `hard_idle_timeout_sec`

## Recommended behavior

### Liveness accounting
Any valid inbound fake-TCP packet should count as proof of life, not just explicit keepalive packets.

That includes:
- `ACK + payload`
- pure `ACK`
- valid handshake-path packets
- any valid replacement-generation SYN handling

### Keepalive behavior
If no valid traffic has been seen for `keepalive_interval_sec`:
- send a keepalive packet

If no inbound valid packet is seen after `keepalive_misses` probes:
- declare the flow dead locally

### Hard GC behavior
Optionally keep a separate hard timeout as a last-resort GC bound.

## Why this is better

It makes stale-state cleanup proactive instead of waiting minutes.

## Important detail

Do not require “keepalive packets in both directions”.

The correct rule is:
- any valid inbound traffic resets liveness suspicion
- keepalives are only sent when normal traffic is absent

---

# C. On suspected path failure, drop local state and reopen on demand

## Problem being fixed

If the path is broken, sending local RST is usually not helpful:
- if the path is dead, RST will not arrive
- if the path is only partially broken, RST may destroy a peer state that could have recovered more safely

## Recommendation

When liveness fails:
- destroy local flow state silently
- do not rely on RST for recovery semantics

### If there is no queued outbound data
- just forget local state
- wait for future traffic to create a fresh flow

### If there is queued outbound data or a trigger packet exists
- destroy local state
- immediately create a new `SYN_SENT` flow
- queue one UDP skb
- send SYN

## Why this is better

This gives fast best-effort re-establishment without assuming the old path is still capable of carrying teardown signals.

---

# D. Treat a bare inbound SYN on an established tuple as a possible generation replacement

## Problem being fixed

Today, stale same-tuple state is one of the worst failure cases.

If one side lost state but the other still thinks the tuple is established, a new `SYN` on the same tuple can be ignored or mishandled instead of replacing stale state.

That prevents same-port recovery.

## Recommendation

For `ESTABLISHED` flows, explicitly recognize a bare aligned `SYN` as a replacement-generation candidate.

This is not normal data traffic.

Normal established traffic should not carry `SYN`.

## Important clarification

Do **not** try to distinguish “normal traffic” from “replacement” using sequence-number windows.

Flags come first:
- `SYN` on an established flow is already special
- the question is whether it is a valid replacement attempt or a protocol error

That is much simpler and more robust.

---

# E. Separate generation sequence spaces using a large reopen guard band

## Problem being fixed

If a new generation reuses sequence numbers too close to an old generation, delayed old packets can look more plausible to the new state.

This does not matter for distinguishing normal traffic from a bare `SYN`, but it does matter for reducing confusion with delayed old-generation packets after replacement.

## Recommendation

When creating a fresh initiator generation after teardown/recovery:
- choose a random aligned ISN (`seq % 4095 == 0`)
- reject candidates whose modular distance from the previous local generation's sequence space is too small

Use a named constant such as:
- `REOPEN_GUARD_BYTES`

## Recommendation on size

Do not make this merely equal to the maximum tolerated reorder window.

Use something much larger, for example:
- 1 MiB
- or 4 MiB

The aligned sequence space is still large enough for this to be cheap.

## Why this is better

It creates clearer separation between generations and reduces ambiguity from delayed packets belonging to the dead generation.

---

# F. Refined explicit rule set for ESTABLISHED flows when a new SYN arrives

This is the refined version of recommendation F.

It is the most important concrete state-machine change.

## Key principle

For an `ESTABLISHED` flow, classify incoming packets by flags first, not sequence windows.

A bare `SYN` is not ordinary established traffic.

That means the categories are:
1. normal established traffic (no `SYN`)
2. protocol error
3. generation replacement request

not:
- normal traffic vs replacement based on seq overlap

## Proposed classification for inbound packets on `ESTABLISHED`

### Case 1: `RST`
Action:
- destroy local flow state
- no further processing

### Case 2: bare replacement SYN candidate
Conditions:
- `syn == 1`
- `ack == 0`
- `payload_len == 0`
- `seq % 4095 == 0`
- tuple passes configured policy filters

Interpretation:
- candidate generation replacement request

Action:
1. destroy old established flow state
2. drop any queued skb belonging to the old generation
3. create a new responder flow in `SYN_RCVD`
4. set `ack = incoming_syn_seq + 1`
5. choose a fresh responder ISN
6. send `SYN|ACK`
7. continue as responder for the new generation

### Case 3: packet has `SYN` set in any other form
Examples:
- `SYN|ACK`
- `SYN + payload`
- `SYN|ACK + payload`

Interpretation:
- protocol error / impossible state for established traffic or replacement

Action:
- send `RST|ACK`
- destroy local state

### Case 4: no `SYN`
Interpretation:
- normal established processing

Action:
- use existing established logic
- apply shaping one-shot drop if armed
- process seq/ack normally

## Why this is the right split

It avoids the biggest conceptual mistake:
trying to distinguish replacement from established data by sequence-number distance.

A bare `SYN` is already outside the normal established-data path.

---

# G. Explicit simultaneous-reopen rule in SYN_SENT

Once recommendation D exists, both sides may reinitiate at the same time after a suspected break.

That means simultaneous-open is still possible during recovery.

## Rule
In `SYN_SENT`, when a bare inbound `SYN` arrives for the same conceptual flow:
- compare the two SYN ISNs
- lower ISN keeps initiator role
- higher ISN becomes responder
- equal ISN: drop and rely on retransmission

This pairs naturally with recommendation D:
- `ESTABLISHED` + bare `SYN` means “replacement attempt accepted”
- `SYN_SENT` + bare `SYN` means “simultaneous reopen, resolve by ISN tie-break”

---

# H. Optional short quarantine for stale old-generation packets

## Problem being fixed

Immediately after generation replacement, delayed packets from the dead generation may still arrive.

## Recommendation

After accepting a replacement generation:
- keep a short quarantine window
- during that window, stale-looking old-generation traffic is silently dropped instead of answered with RST

## Why this is useful

It avoids noisy or misleading teardown reactions to delayed packets that belong to a generation we already decided to abandon.

## Status

This is optional for the first best-effort recovery implementation, but it is a useful refinement.

---

# I. What these recommendations solve, and what they do not

## Strongly improved / mostly solved

1. NAT-broken simultaneous-open tie-break
   - solved by SYN-ISN tie-break

2. Same-tuple stale-state recovery
   - greatly improved by explicit bare-SYN replacement handling

3. Long stale-state persistence
   - improved by aggressive liveness probing instead of coarse GC-only behavior

4. Fixed-port recovery pain
   - improved because same-tuple replacement becomes possible

## Only partially solved

1. Outer tuple being treated too much like identity
   - improved, but not eliminated

2. Recovery after roaming / NAT rebinding
   - improved as reconnection, not seamless migration

## Still not solved in a true sense

1. Seamless roaming / live tuple migration
2. A transport-independent session identity visible beyond SYN
3. Full WireGuard-like endpoint update semantics

These remain fundamentally difficult because the outer wire image still looks like TCP to middleboxes.

---

# J. Recommended concrete starter parameter model

If implementing the recommendations above, the first practical control plane could expose:

- `keepalive_interval_sec`
- `keepalive_misses`
- `hard_idle_timeout_sec`
- `reopen_guard_bytes`

Suggested meaning:
- `keepalive_interval_sec`: send keepalive after this much idle time
- `keepalive_misses`: number of unanswered keepalive intervals before local teardown
- `hard_idle_timeout_sec`: upper bound for garbage collection even if logic goes wrong
- `reopen_guard_bytes`: minimum sequence-space separation from the old local generation when choosing a new initiator ISN

---

# K. Minimal best-effort redesign summary

If the goal is a practical best-effort redesign rather than a protocol rewrite, the minimum coherent package is:

1. replace tuple-based tie-break with SYN-ISN tie-break
2. add liveness probing with aggressive failure detection
3. destroy local state silently on liveness failure
4. immediately reopen if outbound data exists
5. accept bare aligned `SYN` on `ESTABLISHED` as generation replacement
6. use a large reopen guard band when choosing a new local initiator ISN

That is the smallest internally consistent improvement set.

---

# L. Final recommendation

If only one principle is remembered from this document, it should be this:

Do not treat the outer fake-TCP tuple as a stable identity on the Internet.

Use:
- SYN ISN for deterministic collision handling
- liveness probing for failure detection
- explicit replacement semantics for stale same-tuple recovery

Everything else is detail on top of that.
