# phantun-dkms

[![Latest Release](https://img.shields.io/github/v/release/bjin/phantun-dkms.svg?display_name=release)](https://github.com/bjin/phantun-dkms/releases)
[![License](https://img.shields.io/github/license/bjin/phantun-dkms.svg)](https://github.com/bjin/phantun-dkms/blob/master/LICENSE)
[![GitHub branch status](https://github.com/bjin/phantun-dkms/actions/workflows/ci.yml/badge.svg)](https://github.com/bjin/phantun-dkms/actions/workflows/ci.yml)

If you already know [**Phantun**](https://github.com/dndx/phantun/): this is a **Linux kernel module implementation of Phantun's fake-TCP idea**.

Phantun runs as a **user-space client/server** pair around a **TUN interface**. `phantun-dkms` keeps the translation in the **kernel**, intercepts **existing UDP sockets** directly, and avoids the TUN topology.

## Phantun compatibility

`phantun-dkms` is **not advertised as compatible with Phantun endpoints**.

The important nuance: the **basic wire packet shape is intentionally the same**, so the TCP/UDP header overhead story is the same too. For MTU budgeting, Phantun's documentation is still the right mental model.

What changed is the **behavioral contract** around that wire format. I have not tried to make mixed `phantun` / `phantun-dkms` endpoints interoperate, and I would currently assume they **most likely will not** work seamlessly.

Main reasons:

- **Untested interoperability**: mixed deployments have not been validated.
- **Randomized initiator ISN**: `phantun-dkms` randomizes the initial sequence number; Phantun historically uses `0`, which is easier for DPI to fingerprint.
- **Symmetric role model**: `phantun-dkms` drops fixed client/server node roles and uses per-flow **initiator** / **responder** roles instead.
- **TCP-like keepalive behavior**: `phantun-dkms` sends keepalive ACKs and tears flows down after repeated misses; that is another behavior difference that may break mixed-endpoint expectations.
- **Other protocol-level improvements**: several behavior changes make accidental compatibility less likely, even though the fake-TCP packet shape stays close.

Short version: **same broad wire shape, different enough behavior that you should treat this as kernel-to-kernel only unless proven otherwise**.

## Reference

- Project: [dndx/phantun](https://github.com/dndx/phantun/)
- README: [README.md](https://github.com/dndx/phantun/blob/master/README.md)

## If you know Phantun, here are the practical differences

| Topic | Phantun | `phantun-dkms` |
|---|---|---|
| **Where it runs** | User space | Linux kernel module |
| **Traffic model** | TUN interface plus routing/NAT around it | Direct interception of selected existing UDP sockets |
| **Process model** | Separate client/server binaries | No separate daemon; same module runs on both hosts |
| **Node roles** | Fixed client and server | No node-level client/server split; each flow has initiator/responder only |
| **Application integration** | App talks through Phantun's TUN topology | App keeps its existing UDP socket |
| **Traffic selection** | Bind/listen topology around TUN endpoints | Selector-based ownership via `managed_local_ports` and/or `managed_remote_peers` |
| **Firewall/NAT plumbing** | Requires TUN-side DNAT/SNAT/masquerade setup | No Phantun-specific TUN DNAT/masquerade plumbing; module stays on the normal host path and integrates with conntrack |
| **Inbound raw UDP policy** | Ownership handled by TUN topology | Selector-matched raw inbound UDP is dropped on non-loopback ingress |
| **Liveness / keepalive** | No matching kernel-module keepalive behavior here | TCP-like keepalive ACKs plus missed-keepalive teardown |
| **Protocol compatibility** | Phantun contract | Mixed Phantun / `phantun-dkms` use is **untested and likely not seamless** |
| **Address family** | IPv4 and IPv6 | **IPv4 only** right now |

## What still feels like Phantun

The core fake-TCP shape is still familiar:

- strict 3-way handshake
- data rides in TCP `ACK` packets carrying payload
- `seq` / `ack` track payload bytes
- no FIN close state machine
- `RST` is the teardown/error signal

So if you already understand why Phantun works on the wire, you already understand most of the packet-level idea here.

## Can it coexist with Phantun?

Yes.

`phantun-dkms` explicitly ignores traffic on **loopback devices**, including UDP between local loopback endpoints. That means a local Phantun setup using `127.0.0.1` can coexist without the kernel module trying to steal it.

## How to think about this project

Instead of creating a TUN interface and routing traffic through it, `phantun-dkms` does this:

> Pick the UDP traffic to own, steal it in kernel, send fake TCP on the wire, turn inbound fake TCP back into UDP before the local app sees it.

That is the whole model.

## When this is useful

Use this when you want Phantun-like fake TCP, but you want:

- **no TUN device**
- **no user-space forwarding daemon**
- your app to keep its **real UDP socket**
- explicit control over **which local ports or remote peers** get translated

Typical target: **WireGuard** or **`wireguard-go`**.

## Quick start

### Build

```bash
./autogen.sh
./configure
make
```

If kernel autodetection fails, pass `KDIR=/path/to/kernel/build` to `make`.

### Simplest load: own one local UDP port

```bash
sudo modprobe phantun managed_local_ports=51820
```

### Own one exact remote peer instead

```bash
sudo modprobe phantun managed_remote_peers=198.51.100.20:51820
```

### Require both local port and remote peer

```bash
sudo modprobe phantun \
  managed_local_ports=51820 \
  managed_remote_peers=198.51.100.20:51820
```

## Traffic ownership model

The module only touches traffic that matches one or both selector lists.

| Selector | Meaning | Typical use |
|---|---|---|
| `managed_local_ports` | Own this local UDP/TCP port | "Translate my local WireGuard listen port" |
| `managed_remote_peers` | Own this exact remote `IPv4:port` | "Translate only traffic for this peer" |

Rules:

- **At least one** selector list must be non-empty.
- If you configure **both**, **both must match**.
- Selector ownership applies only to **non-loopback** traffic.
- Raw inbound UDP that matches the selectors is dropped on **non-loopback ingress** so traffic is not delivered both as raw UDP and translated UDP.

### Selector modes

| Mode | What you set | Tradeoff |
|---|---|---|
| **Local-only** | `managed_local_ports` | Easiest and closest to Phantun's **server-side selector model**: own traffic by local service port. |
| **Peer-only** | `managed_remote_peers` | Closest to Phantun's **client-side selector model**: own traffic by chosen remote peer. Inbound TCP ownership becomes broad for that remote `IPv4:port`, so use only when that peer is dedicated to this translator. |
| **Intersection** | Both | Most explicit and usually safest. |

## Everyday parameters

### Required selectors

| Parameter | Type | Default | Meaning |
|---|---|---:|---|
| `managed_local_ports` | integer array, max 16 | empty | Local ports the module owns. For WireGuard, usually the local listen port. |
| `managed_remote_peers` | string array, max 16 | empty | Exact peers in `x.y.z.w:p` form. |

Validation rules:

- `managed_local_ports`: `1..65535`
- `managed_remote_peers`: valid `IPv4:port`
- at least one selector list required

### Optional timing and behavior

| Parameter | Default | Meaning |
|---|---:|---|
| `handshake_request` | empty | Optional initiator payload sent as first fake-TCP payload. |
| `handshake_response` | empty | Optional responder payload; effective only when `handshake_request` is also set. |
| `handshake_timeout_ms` | `1000` | Handshake retransmit timeout. |
| `handshake_retries` | `6` | Maximum handshake retry count before `RST` teardown. |
| `keepalive_interval_sec` | `30` | Idle period before sending keepalive ACK. |
| `keepalive_misses` | `3` | Unanswered keepalives allowed before teardown. |
| `hard_idle_timeout_sec` | `300` | Hard upper bound for idle flow lifetime. |
| `reopen_guard_bytes` | `4194304` | Minimum sequence-space distance before reopening same tuple. |

### Shaping payload formats

`handshake_request` and `handshake_response` accept:

| Form | Example | Meaning |
|---|---|---|
| Plain string | `HELLO` | Send bytes as-is |
| Hex | `hex:deadbeef` | Decode remaining text as hex |
| Base64 | `base64:YWJj` | Decode remaining text as Base64 |

Invalid hex or Base64 is ignored safely, with a kernel log warning.

## Common setups

### Own a WireGuard port

```bash
sudo modprobe phantun managed_local_ports=51820
```

### Own a WireGuard port, but only for one peer

```bash
sudo modprobe phantun \
  managed_local_ports=51820 \
  managed_remote_peers=198.51.100.20:51820
```

### Add optional request/response shaping hints

```bash
sudo modprobe phantun \
  managed_local_ports=51820 \
  managed_remote_peers=198.51.100.20:51820 \
  handshake_request=HELLO \
  handshake_response=WORLD
```

### Persist across reboots

Create `/etc/modprobe.d/phantun.conf`:

```text
options phantun \
  managed_local_ports=51820 \
  managed_remote_peers=198.51.100.20:51820
```

Then:

```bash
sudo modprobe phantun
```

## Operational notes for Phantun users

| Topic | What changes here |
|---|---|
| **No TUN plumbing** | Do not copy Phantun's TUN DNAT/SNAT/masquerade setup into this project. |
| **Conntrack** | The module stays on the normal host path and integrates with conntrack instead of creating a separate TUN routing topology. |
| **Loopback** | Loopback traffic is left alone; this is why local Phantun-on-loopback setups can coexist. |
| **MTU** | Same basic fake-TCP packet overhead as Phantun; Phantun's MTU guidance still applies. |
| **Handshake buffering** | During handshake, the module queues at most **one** outbound UDP packet per flow; later packets may be dropped and must rely on normal app retransmission. |
| **Shaping semantics** | `handshake_request` / `handshake_response` are hints, not a verified sub-protocol. |
| **Keepalive** | `phantun-dkms` has TCP-like keepalive behavior; that is another reason mixed Phantun / `phantun-dkms` endpoints should not be assumed to interoperate. |

## Runtime stats

The module exports counters under:

```text
/sys/module/phantun/stats/
```

Example:

```bash
cat /sys/module/phantun/stats/flows_created
cat /sys/module/phantun/stats/rst_sent
```

### Useful counters

| Stat file | Meaning |
|---|---|
| `flows_created` | Flow objects inserted into the flow table. |
| `flows_established` | Flows that reached `ESTABLISHED`. |
| `request_payloads_injected` | `handshake_request` payloads injected by the module. |
| `response_payloads_injected` | `handshake_response` payloads injected by the module. |
| `collisions_won` | Simultaneous-initiation collisions where local side kept initiator role. |
| `collisions_lost` | Simultaneous-initiation collisions where local side switched to responder. |
| `rst_sent` | Fake-TCP `RST` packets sent by the module. |
| `udp_packets_queued` | UDP packets queued during half-open or restricted flow handling. |
| `udp_packets_dropped` | UDP packets dropped by policy or queue pressure, including raw inbound UDP dropped by selector policy. |
| `shaping_payloads_dropped` | Payloads intentionally hidden from the UDP app by shaping logic. |

## Build, reload, unload

| Task | Command |
|---|---|
| Build | `./autogen.sh && ./configure && make` |
| Refresh compile database | `make compile_commands` |
| Load module | `sudo modprobe phantun ...` |
| Unload module | `sudo rmmod phantun` |

## Limits and current status

- **IPv4 only** today.
- Mixed **Phantun** / **`phantun-dkms`** deployments are **untested** and should be treated as **likely non-seamless**.
- **No FIN close state machine**.
- This is a **kernel-to-kernel protocol variant** in practice, even though the basic packet shape stays close to Phantun.
- First payloads reserved for shaping may be intentionally hidden from the UDP application.
- Missing, delayed, duplicated, or lost shaping payloads do not by themselves fail the connection.

For protocol internals and state-machine details, see [**`DESIGN.md`**](./DESIGN.md).

## License

Project license: **GPL-2.0-or-later**, see `LICENSE` file
