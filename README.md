# phantun-dkms

`phantun-dkms` is a Linux kernel module that runs a Phantun-style fake-TCP transport in kernel space.

Its main goal is to let existing UDP applications, especially kernel WireGuard and `wireguard-go`, use fake TCP without a TUN device and without a separate user-space forwarding daemon.

The current design is:

- IPv4 only
- Linux kernel module + netfilter hooks
- selector-based interception of existing UDP sockets
- strict fake-TCP handshake / sequence / ACK / RST behavior
- no FIN / close state machine
- optional first-payload shaping hints

For the detailed protocol design, see `DESIGN.md`.

## What this project is

This project intercepts selected UDP traffic on the local host, translates it into fake TCP packets on the wire, and turns the peer's fake TCP packets back into UDP before local delivery.

In short:

- outbound selected UDP is stolen in `LOCAL_OUT`
- the module creates or reuses a per-flow fake-TCP session
- outbound UDP payload becomes TCP payload carried in fake TCP `ACK` packets
- inbound fake TCP is intercepted in `PRE_ROUTING` before the real TCP stack sees it
- inbound fake TCP payload is decapsulated back into UDP and reinjected into the local receive path

This lets applications keep using normal UDP sockets while the network sees TCP-looking traffic.

## How this differs from the old Phantun project

Upstream Phantun: https://github.com/dndx/phantun

The old project is a user-space client/server system built around a TUN interface and routing/NAT rules. This module is not that.

The most important differences are:

- No TUN device
  - old Phantun creates a TUN interface and depends on routing/NAT around it
  - this module intercepts existing UDP traffic directly with netfilter
- No separate client/server binaries
  - old Phantun has explicit client/server roles
  - this module is symmetric at node level; each flow has only an initiator and a responder
- Existing UDP sockets are preserved
  - old Phantun creates a separate transport topology around the TUN
  - this module works against already-existing UDP applications such as WireGuard and `wireguard-go`
- Different protocol contract
  - this module is intentionally a kernel-to-kernel protocol variant, not a compatibility mode for legacy user-space Phantun
  - optional shaping payloads are best-effort hints here, not a required verified sub-protocol
- Selector model instead of TUN endpoints
  - this module decides what it owns using `managed_local_ports` and/or `managed_remote_peers`
  - raw inbound UDP matching those selectors is dropped by default

What stays the same comes from section 2 of `DESIGN.md`: this module deliberately carries forward the fake-TCP wire semantics from old Phantun's `fake-tcp` crate.

Those carried-forward properties include:

- strict 3-way handshake
- responder only accepts `SYN` where `seq % 4095 == 0`
- data rides in `ACK` packets carrying payload
- TCP `seq` and `ack` still track payload bytes
- no FIN-based close state machine
- `RST` is the teardown/error signal

So this project keeps the core fake-TCP transport shape, but changes deployment model, interception model, and some recovery/shaping behavior.

## How it works

A basic mental model:

1. Pick which traffic the module owns.
   - by local UDP/TCP port (`managed_local_ports`)
   - by exact remote IPv4:port (`managed_remote_peers`)
   - or both at once

2. Outbound selected UDP is intercepted in `NF_INET_LOCAL_OUT`.
   - if no flow exists, the module creates one and sends a fake-TCP `SYN`
   - during handshake, it queues at most one UDP skb
   - after establishment, outbound UDP payload becomes fake-TCP payload

3. Inbound fake TCP is intercepted in `NF_INET_PRE_ROUTING`.
   - handshake packets are handled in the module state machine
   - established payload is decapsulated back into UDP
   - the real TCP stack never owns these packets

4. Decapsulated UDP is reinjected locally.
   - local UDP sockets receive it as normal inbound UDP
   - later local inbound firewall/delivery hooks still run

5. Raw inbound UDP matching the selectors is dropped in `PRE_ROUTING`.
   - this prevents ambiguous mixed delivery
   - module-reinjected UDP is not black-holed because reinjection happens after `PRE_ROUTING`

## Interception model

The module owns traffic based on two optional selectors:

- `managed_local_ports`
- `managed_remote_peers`

At least one must be non-empty.

Selector modes:

- Local-only mode
  - only `managed_local_ports` is set
  - outbound match: local source port
  - inbound fake-TCP match: local destination port
- Peer-only mode
  - only `managed_remote_peers` is set
  - outbound match: remote destination IPv4:UDP port
  - inbound fake-TCP match: remote source IPv4:TCP port
- Intersection mode
  - both are set
  - both must match

Important peer-only caveat:

- inbound TCP ownership becomes broad for that remote IPv4:port
- use peer-only mode only when that remote peer is dedicated to this translator

## Module parameters

The module is configured through normal module parameters, for example with `modprobe phantun ...`.

### Required selector parameters

At least one of these two must be provided.

| Parameter | Type | Default | Meaning |
|---|---|---:|---|
| `managed_local_ports` | array of integers, max 16 | empty | Local UDP/TCP ports owned by the translator. For WireGuard this is usually the local listen port. |
| `managed_remote_peers` | array of strings, max 16 | empty | Exact remote peers in `x.y.z.w:p` form. Each entry matches one IPv4 address and one port. |

Rules:

- `managed_local_ports` entries must be in `1..65535`
- `managed_remote_peers` entries must parse as valid `x.y.z.w:p`
- at least one selector list must be non-empty

### Optional protocol / timing parameters

| Parameter | Type | Default | Meaning |
|---|---|---:|---|
| `handshake_request` | string | empty | Optional initiator control payload sent as the first fake-TCP payload. Can be a plain string, or prefixed with `hex:` or `base64:` for binary payloads. |
| `handshake_response` | string | empty | Optional responder control payload. Can be a plain string, or prefixed with `hex:` or `base64:`. Only effective when `handshake_request` is also set. |
| `handshake_timeout_ms` | uint | `1000` | Handshake retransmit timeout in milliseconds. |
| `handshake_retries` | uint | `6` | Maximum handshake retry count before teardown with `RST`. |
| `keepalive_interval_sec` | uint | `30` | Idle interval before sending a keepalive ACK. |
| `keepalive_misses` | uint | `3` | Number of unanswered keepalives before liveness teardown. |
| `hard_idle_timeout_sec` | uint | `300` | Hard upper bound for idle flow lifetime. |
| `reopen_guard_bytes` | uint | `4194304` | Minimum sequence-space separation required for a reopened same-tuple connection. |

### Examples

Intercept a local WireGuard port only:

```bash
sudo modprobe phantun managed_local_ports=51820
```

Intercept only one exact remote peer:

```bash
sudo modprobe phantun managed_remote_peers=198.51.100.20:51820
```

Require both local port and remote peer to match:

```bash
sudo modprobe phantun \
  managed_local_ports=51820 \
  managed_remote_peers=198.51.100.20:51820
```

Enable request/response shaping hints too:

```bash
sudo modprobe phantun \
  managed_local_ports=51820 \
  managed_remote_peers=198.51.100.20:51820 \
  handshake_request=HELLO \
  handshake_response=WORLD
```

## Exposed stats in `/sys/module/phantun/stats`

The module exports counters under:

```text
/sys/module/phantun/stats/
```

Each file contains a single integer.

Example:

```bash
cat /sys/module/phantun/stats/flows_created
cat /sys/module/phantun/stats/rst_sent
```

### Stats reference

| Stat file | Meaning |
|---|---|
| `flows_created` | Count of flow objects inserted into the flow table. |
| `flows_established` | Count of transitions into `ESTABLISHED`. |
| `request_payloads_injected` | Count of module-injected `handshake_request` payloads. |
| `response_payloads_injected` | Count of module-injected `handshake_response` payloads. |
| `collisions_won` | Count of simultaneous-initiation collisions where the local side kept the initiator role. |
| `collisions_lost` | Count of simultaneous-initiation collisions where the local side switched to responder. |
| `rst_sent` | Count of fake-TCP `RST` packets emitted by the module. |
| `udp_packets_queued` | Count of UDP packets queued for half-open/restricted flow handling. |
| `udp_packets_dropped` | Count of UDP packets dropped by module policy or queue-pressure behavior. This includes the raw inbound UDP drop path. |
| `shaping_payloads_dropped` | Count of payloads intentionally dropped because shaping logic said they should not reach the UDP app. |

## Operational notes

### Firewall policy changes

This module does not use old TUN-side NAT rules.

Think in terms of selector-matched tuples instead.

You need to allow:

- outbound and inbound fake-TCP for the selector-matched tuples
- local inbound UDP delivery for reinjected translated traffic

You should expect:

- raw inbound UDP matching the selectors is dropped in `PRE_ROUTING`
- module-reinjected UDP is exempt from that raw-wire drop path because it is injected after `PRE_ROUTING`

In practice:

- allow TCP for the tuples the module will use on the wire
- allow local UDP delivery to the application's real UDP socket after reinjection
- do not copy old Phantun TUN DNAT/SNAT recipes into this project

### MTU guidance

Replacing UDP with TCP adds TCP header overhead.

This module does not implement TCP fragmentation/resegmentation logic in v1, so managed UDP applications must run with a reduced MTU budget.

For WireGuard, reduce MTU enough to account for the extra TCP header overhead in the outer transport.

### Exact shaping semantics

`handshake_request` / `handshake_response` formatting

These parameters accept a plain string by default. For binary payloads, you can prefix the value:
- `base64:YWJj` — decodes the remaining string as Base64.
- `hex:deadbeef` — decodes the remaining string as hex.

Invalid Base64 or hex characters (or an odd-length hex string) will cause the parameter to be safely ignored, with a warning printed to the kernel log.

`handshake_request`

- if set, the initiator sends it as the first fake-TCP payload
- the responder drops the first inbound payload it sees for that flow instead of delivering it to UDP

`handshake_response`

- only matters if `handshake_request` is also set
- if both are set, the responder sends `handshake_response` as its first fake-TCP payload
- the initiator drops the first inbound responder payload it sees for that flow

Important details:

- these are shaping hints, not a verified handshake sub-protocol
- missing, delayed, duplicated, or lost shaping payloads do not by themselves fail the connection
- only payloads intentionally ignored by the shaping logic are hidden from the UDP socket

### Protocol compatibility statement

This module should be treated as a kernel-to-kernel protocol variant.

It is not a drop-in compatibility mode for legacy user-space Phantun because it changes:

- deployment model
- interception model
- node role model
- shaping semantics
- inbound raw UDP policy
- same-tuple recovery behavior

### Concise operational examples

#### Kernel WireGuard

Typical case:

- WireGuard kernel module listens on UDP port `51820`
- you want traffic for that local socket to use fake TCP

Example module load:

```bash
sudo modprobe phantun managed_local_ports=51820
```

If you only want one peer to be translated:

```bash
sudo modprobe phantun \
  managed_local_ports=51820 \
  managed_remote_peers=198.51.100.20:51820
```

#### `wireguard-go`

`wireguard-go` still uses a normal UDP socket, so the interception model is the same.

If `wireguard-go` binds local UDP port `51820`:

```bash
sudo modprobe phantun managed_local_ports=51820
```

Or restrict it to one remote peer:

```bash
sudo modprobe phantun \
  managed_local_ports=51820 \
  managed_remote_peers=198.51.100.20:51820
```

## Build and test

Bootstrap:

```bash
./autogen.sh
```

Build:

```bash
./configure
make
```

Refresh compile commands:

```bash
make compile_commands
```

Run integration tests on the host kernel:

```bash
pytest tests
```

See `TESTING.md` for the full virtme-ng test workflow.
