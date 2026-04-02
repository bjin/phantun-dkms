# phantun-kmod design flaws

This document summarizes the major real-world design flaws and operational risks in the current symmetric fixed-port kernel design.

It is intentionally focused on Internet-facing behavior: NAT, roaming, middlebox state loss, and recovery.

## Non-flaw clarification: optional peer filters

`remote_ipv4_cidr` and `remote_port` are optional policy filters, not mandatory protocol assumptions.

Current code confirms this:
- `remote_ipv4_cidr` is only enabled when a non-empty CIDR string is supplied
- `remote_port` is only enforced when non-zero
- when unspecified, neither filter constrains matching

So these are not inherent design flaws if they are used only on peers with intentionally fixed public IP/port.

## 1. NAT breaks the current simultaneous-initiation tie-break assumption

The current simultaneous-open collapse assumes both peers can rank the same endpoint pair identically.

That assumption is not valid once NAT exists between peers.

Why:
- outbound interception happens in `LOCAL_OUT` before conntrack/NAT
- the initiating side therefore reasons about its pre-NAT local tuple
- the remote side reasons about the post-NAT public tuple it actually sees

As a result, the two peers are not guaranteed to compare the same endpoint pair.

Consequences:
- the deterministic winner/loser rule is not globally deterministic anymore
- both peers can make inconsistent decisions about who keeps initiator role
- collision recovery becomes unreliable in real Internet topologies

This problem does not exist in old Phantun because old Phantun had explicit client/server roles and did not rely on symmetric tuple-based tie-breaking.

## 2. Recovery after roaming or middlebox state loss is not robust

Fake TCP is stateful, but the underlay is still a mutable Internet path.

Two important failure modes exist.

### 2.1 Tuple changes are not true flow migration

If the peer IP or observed external port changes because of roaming or NAT rebinding:
- there is no transport-independent session identity
- there is no migration of an established flow to the new outer tuple
- recovery only happens if a fresh connection is opened on the new tuple

So the design does not really support roaming; it supports eventual re-establishment on a different tuple.

### 2.2 Same-tuple stale-state recovery is fragile

If one side loses flow state but the other side still has an established flow for the same tuple:
- the recovering side may send a fresh `SYN`
- the stale side may treat that traffic as belonging to the old flow instead of replacing it cleanly
- stale state can continue blocking useful recovery traffic

Because managed ports are fixed, there is no easy escape hatch via a new local source port the way old client/server Phantun could do.

## 3. Fixed managed ports make stale-state conflicts worse

This module is centered on fixed managed listen ports.

That has an important side effect:
- a recovering peer cannot simply create a replacement fake-TCP session from a different local port
- recovery attempts are forced back onto the same tuple space
- stale entries therefore collide directly with replacement attempts

This is one of the biggest differences from old TUN-based Phantun.

## 4. No session generation / epoch concept

The design currently uses the observed fake-TCP outer tuple plus local flow state as the effective identity.

What is missing:
- no explicit connection generation
- no authenticated session epoch
- no notion of “same logical peer, newer connection instance”

Consequences:
- stale established state is hard to distinguish from a legitimate replacement attempt
- same-tuple re-establishment semantics are ambiguous
- correct stale-flow replacement rules are difficult to express

## 5. No real mobility story comparable to WireGuard

WireGuard is safe across roaming because:
- it uses UDP as transport
- it authenticates packets independently of outer endpoint stability
- it updates peer endpoint to the latest authenticated source IP:port
- it uses keepalives to preserve NAT state when needed

This module has no equivalent endpoint-update mechanism for the fake-TCP wrapper.

So while the protected UDP application may tolerate endpoint change, the wrapper transport itself does not currently have a coherent mobility model.

## 6. `idle_timeout_sec` is coarse GC, not aggressive liveness detection

The current `idle_timeout_sec` behavior is much weaker than the name suggests.

Actual behavior:
- default is 180 seconds
- zero is rejected, so the parameter is effectively mandatory internally
- expiry is checked only by a GC worker that runs every 30 seconds
- real expiration is therefore approximately in the range:
  - `idle_timeout_sec` to `idle_timeout_sec + 30s`

More importantly, the timer is refreshed by broad phantun activity, not just useful UDP exchange.

Examples that update `last_activity_jiffies`:
- successful established outbound send
- inbound payload processing
- queueing a UDP skb
- explicit `pht_flow_touch()` calls
- state transitions

Operational implication:
- this is not “seconds since last useful peer communication”
- it is “seconds since last phantun-observed activity”
- stale or wedged flows can survive longer than operators expect
- recovery attempts can refresh stale state instead of clearing it

This timeout is under-documented and too relaxed for Internet recovery use-cases.

## 7. Stale-state persistence interacts badly with recovery

Because idle cleanup is coarse and activity refresh is broad:
- a stale flow may live long enough to block replacement attempts
- packets that should perhaps trigger stale replacement may instead keep the stale flow alive
- the default 180-second timeout is especially bad for mobile/NAT-heavy environments

A real recovery design likely needs:
- much more aggressive stale detection
- or explicit replace-on-new-open rules
- or both

## 8. The outer fake-TCP tuple is being treated too much like stable identity

This is the common root cause behind many issues above.

On the real Internet:
- NAT mappings change
- UDP state expires
- middleboxes forget state
- endpoint IPs/ports move

The current design still expects the outer fake-TCP tuple to behave too much like a stable connection identifier.

That assumption is unsafe in general Internet deployment.

## 9. What needs to change conceptually

At a minimum, an Internet-safe redesign should address:

1. session identity independent of outer tuple
2. explicit stale-flow replacement rules
3. NAT-safe simultaneous-open handling, or removal of that symmetry assumption
4. a real endpoint-rebinding / mobility story
5. much clearer and likely more aggressive liveness/idle policy

Without those, the current design is best understood as workable only in relatively stable, low-churn, well-controlled topologies.
