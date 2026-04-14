// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/base64.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/net_namespace.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netns/generic.h>
#include <net/route.h>

#include "phantun_compat.h" // IWYU pragma: keep

#ifdef HAVE_LINUX_HEX_H
#include <linux/hex.h>
#endif

#ifdef HAVE_NET_GSO_H
#include <net/gso.h>
#endif

#include "phantun.h"
#include "phantun_flow.h"
#include "phantun_packet.h"
#include "phantun_stats.h"

#define PHANTUN_REOPEN_ISN_ATTEMPTS 1024U

static unsigned int managed_local_ports[PHANTUN_MAX_MANAGED_PORTS];
static int managed_local_ports_count;
static char *managed_remote_peers[PHANTUN_MAX_MANAGED_PEERS];
static int managed_remote_peers_count;
static char *handshake_request;
static char *handshake_response;
static unsigned int handshake_timeout_ms = PHANTUN_DEFAULT_HANDSHAKE_TIMEOUT_MS;
static unsigned int handshake_retries = PHANTUN_DEFAULT_HANDSHAKE_RETRIES;
static unsigned int keepalive_interval_sec = PHANTUN_DEFAULT_KEEPALIVE_INTERVAL_SEC;
static unsigned int keepalive_misses = PHANTUN_DEFAULT_KEEPALIVE_MISSES;
static unsigned int hard_idle_timeout_sec = PHANTUN_DEFAULT_HARD_IDLE_TIMEOUT_SEC;
static unsigned int reopen_guard_bytes = PHANTUN_DEFAULT_REOPEN_GUARD_BYTES;
static unsigned int established_window_bytes = PHANTUN_DEFAULT_ESTABLISHED_WINDOW_BYTES;
module_param_array_named(managed_local_ports, managed_local_ports, uint, &managed_local_ports_count,
                         0444);
MODULE_PARM_DESC(managed_local_ports, "Comma-separated local UDP/TCP ports managed by phantun");
module_param_array_named(managed_remote_peers, managed_remote_peers, charp,
                         &managed_remote_peers_count, 0444);
MODULE_PARM_DESC(managed_remote_peers, "Comma-separated remote IPv4:port peers managed by phantun");
module_param(handshake_request, charp, 0444);
MODULE_PARM_DESC(handshake_request,
                 "Optional initiator control payload sent as the first fake-TCP payload (plain "
                 "string, or hex/base64 if prefixed with 'hex:'/'base64:')");
module_param(handshake_response, charp, 0444);
MODULE_PARM_DESC(
    handshake_response,
    "Optional responder control payload sent as the first fake-TCP payload when handshake_request "
    "is also set (plain string, or hex/base64 if prefixed with 'hex:'/'base64:')");
module_param(handshake_timeout_ms, uint, 0444);
MODULE_PARM_DESC(handshake_timeout_ms, "Handshake retransmit timeout in milliseconds");
module_param(handshake_retries, uint, 0444);
MODULE_PARM_DESC(handshake_retries,
                 "Maximum handshake retry count before tearing a flow down with RST");
module_param(keepalive_interval_sec, uint, 0444);
MODULE_PARM_DESC(keepalive_interval_sec, "Idle time in seconds before sending a keepalive ACK");
module_param(keepalive_misses, uint, 0444);
MODULE_PARM_DESC(keepalive_misses, "Number of unanswered keepalives before flow teardown");
module_param(hard_idle_timeout_sec, uint, 0444);
MODULE_PARM_DESC(hard_idle_timeout_sec, "Maximum idle flow timeout in seconds (hard GC limit)");
module_param(reopen_guard_bytes, uint, 0444);
MODULE_PARM_DESC(reopen_guard_bytes, "Minimum sequence space separation for new connections");
module_param(established_window_bytes, uint, 0444);
MODULE_PARM_DESC(established_window_bytes,
                 "Established-state receive window in bytes; 0 disables sequence-range checks");

static struct phantun_config phantun_cfg;
static void *phantun_alloc_req;
static void *phantun_alloc_resp;
static unsigned int phantun_net_id;
static struct notifier_block phantun_inetaddr_nb;

struct phantun_net {
    struct pht_flow_table flows;
    struct notifier_block netdev_nb;
};

static unsigned int phantun_netns_id(const struct net *net) { return net ? net->ns.inum : 0; }

static struct pht_flow_table *phantun_net_flows(const struct net *net) {
    struct phantun_net *pnet;

    if (!net)
        return NULL;

    pnet = net_generic(net, phantun_net_id);
    return pnet ? &pnet->flows : NULL;
}

/* Invalidate only on topology changes that break the current source identity or
 * cached egress path outright. Route/gateway changes are intentionally ignored:
 * every transmit does a fresh route lookup, so a stable local IPv4 can migrate
 * without tearing the fake-TCP generation down.
 */
static int phantun_netdev_event(struct notifier_block *nb, unsigned long event, void *ptr) {
    struct phantun_net *pnet = container_of(nb, struct phantun_net, netdev_nb);
    struct net_device *dev = netdev_notifier_info_to_dev(ptr);
    unsigned int invalidated;

    if (!dev)
        return NOTIFY_DONE;

    switch (event) {
    case NETDEV_GOING_DOWN:
    case NETDEV_DOWN:
    case NETDEV_UNREGISTER:
        break;
    default:
        return NOTIFY_DONE;
    }

    invalidated = pht_flow_invalidate_egress_ifindex(&pnet->flows, dev->ifindex);
    if (invalidated)
        pht_pr_info("invalidated %u flow(s) on egress device %s(%d) after netdev event %lu\n",
                    invalidated, dev->name, dev->ifindex, event);

    return NOTIFY_DONE;
}

static int phantun_inetaddr_event(struct notifier_block *nb, unsigned long event, void *ptr) {
    struct in_ifaddr *ifa = ptr;
    struct net_device *dev;
    struct pht_flow_table *flows;
    unsigned int invalidated;

    if (event != NETDEV_DOWN || !ifa || !ifa->ifa_dev || !ifa->ifa_dev->dev)
        return NOTIFY_DONE;

    dev = ifa->ifa_dev->dev;
    flows = phantun_net_flows(dev_net(dev));
    if (!flows)
        return NOTIFY_DONE;

    invalidated = pht_flow_invalidate_local_addr(flows, ifa->ifa_local);
    if (invalidated)
        pht_pr_info("invalidated %u flow(s) after removing local IPv4 %pI4 on %s\n", invalidated,
                    &ifa->ifa_local, dev->name);

    return NOTIFY_DONE;
}

static int phantun_parse_managed_remote_peer(const char *peer,
                                             struct pht_managed_peer *parsed_peer) {
    char buf[32];
    char *colon;
    u8 parsed_addr[4];
    unsigned int port_host;

    if (!peer || !*peer || !parsed_peer)
        return -EINVAL;
    if (strscpy(buf, peer, sizeof(buf)) < 0)
        return -EINVAL;

    colon = strrchr(buf, ':');
    if (!colon)
        return -EINVAL;
    *colon = '\0';
    colon++;
    if (!*buf || !*colon)
        return -EINVAL;
    if (!in4_pton(buf, -1, parsed_addr, -1, NULL))
        return -EINVAL;
    if (kstrtouint(colon, 10, &port_host) || !port_host || port_host > U16_MAX)
        return -EINVAL;

    memcpy(&parsed_peer->addr, parsed_addr, sizeof(parsed_addr));
    parsed_peer->port = htons((u16)port_host);
    return 0;
}

static void phantun_account_udp_queue_result(bool queued) {
    if (queued)
        pht_stats_inc(PHT_STAT_UDP_PACKETS_QUEUED);
    else
        pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
}

static bool phantun_dev_is_loopback(const struct net_device *dev) {
    return dev && (dev->flags & IFF_LOOPBACK);
}

static bool phantun_local_out_uses_loopback_dev(const struct sk_buff *skb,
                                                const struct nf_hook_state *state) {
    const struct net_device *out_dev;

    out_dev = state->out ? state->out : skb->dev;
    return phantun_dev_is_loopback(out_dev);
}

static bool phantun_pre_routing_uses_loopback_dev(const struct sk_buff *skb,
                                                  const struct nf_hook_state *state) {
    const struct net_device *in_dev;

    in_dev = state->in ? state->in : skb->dev;
    return phantun_dev_is_loopback(in_dev);
}

/* PRE_ROUTING sees both locally delivered traffic and pure forwarding traffic.
 * The translator only owns packets that will terminate on this host/netns; it
 * must ignore transit packets even if their 4-tuple matches configured
 * selectors, otherwise a router deployment will spuriously reset or drop
 * forwarded traffic.
 */
static bool phantun_pre_routing_targets_local_host(const struct net *net, __be32 addr) {
    return net && inet_addr_type_table((struct net *)net, addr, RT_TABLE_LOCAL) == RTN_LOCAL;
}

static bool phantun_local_port_allowed(__be16 port) {
    unsigned int i;

    if (!phantun_cfg.managed_local_ports_count)
        return true;

    for (i = 0; i < phantun_cfg.managed_local_ports_count; i++) {
        if (phantun_cfg.managed_local_ports[i] == ntohs(port))
            return true;
    }

    return false;
}

static bool phantun_remote_peer_allowed(__be32 addr, __be16 port) {
    unsigned int i;

    if (!phantun_cfg.managed_remote_peers_count)
        return true;

    for (i = 0; i < phantun_cfg.managed_remote_peers_count; i++) {
        if (phantun_cfg.managed_remote_peers[i].addr == addr &&
            phantun_cfg.managed_remote_peers[i].port == port)
            return true;
    }

    return false;
}

static bool phantun_selectors_allow(__be16 local_port, __be32 remote_addr, __be16 remote_port) {
    return phantun_local_port_allowed(local_port) &&
           phantun_remote_peer_allowed(remote_addr, remote_port);
}

static void phantun_fill_udp_endpoint_pair(const struct pht_l4_view *view,
                                           struct pht_ipv4_endpoint_pair *ep) {
    ep->local_addr = view->iph->saddr;
    ep->remote_addr = view->iph->daddr;
    ep->local_port = view->udp->source;
    ep->remote_port = view->udp->dest;
}

static void phantun_fill_tcp_endpoint_pair(const struct pht_l4_view *view,
                                           struct pht_ipv4_endpoint_pair *ep) {
    ep->local_addr = view->iph->daddr;
    ep->remote_addr = view->iph->saddr;
    ep->local_port = view->tcp->dest;
    ep->remote_port = view->tcp->source;
}

static u32 phantun_random_aligned_seq(void) { return (get_random_u32() / 4095U) * 4095U; }

static u32 phantun_tcp_seq_advance(const struct tcphdr *th, unsigned int payload_len) {
    u32 advance = payload_len;

    if (th->syn)
        advance++;
    if (th->fin)
        advance++;

    return advance;
}

static bool phantun_tcp_is_bare_syn(const struct pht_l4_view *view);

static bool phantun_seq_after_eq(u32 seq1, u32 seq2) { return (s32)(seq1 - seq2) >= 0; }

static bool phantun_seq_after(u32 seq1, u32 seq2) { return (s32)(seq1 - seq2) > 0; }

static bool phantun_seq_before_eq(u32 seq1, u32 seq2) { return (s32)(seq1 - seq2) <= 0; }

static bool phantun_seq_before(u32 seq1, u32 seq2) { return (s32)(seq1 - seq2) < 0; }

static bool phantun_seq_between(u32 seq, u32 start, u32 end) {
    return phantun_seq_after_eq(seq, start) && phantun_seq_before_eq(seq, end);
}

/* Remember only the immediately previous generation on a tuple. During the
 * short quarantine window, packets that still fit that old seq/ack space are
 * dropped instead of provoking fresh RSTs after a replacement SYN wins.
 */
static void phantun_flow_arm_prev_generation_quarantine(struct pht_flow *flow, u32 prev_local_start,
                                                        u32 prev_local_end, u32 prev_remote_start,
                                                        u32 prev_remote_end) {
    if (!flow)
        return;

    spin_lock_bh(&flow->lock);
    flow->quarantine_prev_local_seq_start = prev_local_start;
    flow->quarantine_prev_local_seq_end = prev_local_end;
    flow->quarantine_prev_remote_seq_start = prev_remote_start;
    flow->quarantine_prev_remote_seq_end = prev_remote_end;
    flow->quarantine_until_jiffies = jiffies + msecs_to_jiffies(PHANTUN_REPLACEMENT_QUARANTINE_MS);
    flow->quarantine_prev_active = true;
    spin_unlock_bh(&flow->lock);
}

static bool phantun_flow_matches_quarantine_locked(const struct pht_flow *flow,
                                                   const struct pht_l4_view *view) {
    u32 seq;
    u32 ack;
    bool seq_matches;

    seq = ntohl(view->tcp->seq);
    ack = ntohl(view->tcp->ack_seq);
    seq_matches = phantun_seq_between(seq, flow->quarantine_prev_remote_seq_start,
                                      flow->quarantine_prev_remote_seq_end);
    if (!seq_matches)
        return false;

    if (view->tcp->rst && !view->tcp->ack)
        return true;
    if (!view->tcp->ack)
        return false;

    return phantun_seq_between(ack, flow->quarantine_prev_local_seq_start,
                               flow->quarantine_prev_local_seq_end);
}

static bool phantun_flow_matches_current_generation_locked(const struct pht_flow *flow,
                                                           const struct pht_l4_view *view) {
    u32 seq;
    u32 ack;
    u32 current_local_end;

    seq = ntohl(view->tcp->seq);
    ack = ntohl(view->tcp->ack_seq);
    current_local_end = flow->seq;
    if (flow->state == PHT_FLOW_STATE_SYN_RCVD)
        current_local_end = flow->local_isn + 1;

    if (!phantun_seq_between(seq, flow->peer_syn_next, flow->ack))
        return false;
    if (view->tcp->rst && !view->tcp->ack)
        return true;
    if (!view->tcp->ack)
        return false;

    return phantun_seq_between(ack, flow->local_isn, current_local_end);
}

static bool phantun_flow_should_drop_quarantined_packet(struct pht_flow *flow,
                                                        const struct pht_l4_view *view) {
    bool drop = false;

    if (!flow || !view || phantun_tcp_is_bare_syn(view))
        return false;

    spin_lock_bh(&flow->lock);
    if (!flow->quarantine_prev_active)
        goto out;
    if (time_after_eq(jiffies, flow->quarantine_until_jiffies)) {
        flow->quarantine_prev_active = false;
        goto out;
    }
    if (!phantun_flow_matches_quarantine_locked(flow, view))
        goto out;
    if (flow->state == PHT_FLOW_STATE_ESTABLISHED &&
        phantun_flow_matches_current_generation_locked(flow, view))
        goto out;
    drop = true;
out:
    spin_unlock_bh(&flow->lock);
    return drop;
}

static bool phantun_request_enabled(void) { return phantun_cfg.handshake_request_len > 0; }

static bool phantun_response_enabled(void) {
    return phantun_request_enabled() && phantun_cfg.handshake_response_len > 0;
}

/* A protocol-opening or replacement SYN really must be SYN-only. If other
 * control flags ride along, later state-machine code cannot safely treat it as
 * a clean opener and should fall back to the generic invalid-SYN path instead.
 */
static bool phantun_tcp_is_bare_syn(const struct pht_l4_view *view) {
    return view && view->tcp->syn && !view->tcp->ack && !view->tcp->rst && !view->tcp->fin &&
           !view->tcp->psh && !view->tcp->urg && view->payload_len == 0;
}

static bool phantun_tcp_is_plain_ack(const struct pht_l4_view *view) {
    return view && view->tcp->ack && !view->tcp->syn && !view->tcp->rst && !view->tcp->fin &&
           !view->tcp->psh && !view->tcp->urg;
}

static bool phantun_tcp_is_valid_final_ack(const struct pht_l4_view *view, u32 peer_syn_next) {
    u32 seq;

    if (!phantun_tcp_is_plain_ack(view))
        return false;

    seq = ntohl(view->tcp->seq);

    if (seq == peer_syn_next)
        return true;

    /* A lost ACK+payload opener can leave the responder in SYN_RCVD while the
     * initiator has already advanced to later UDP payload. Accept only
     * payload-bearing later sequence numbers here; a pure-ACK jump would
     * create a permanent future-sequence bypass before the established
     * classifier can judge the packet.
     */
    return view->payload_len > 0 && phantun_seq_after(seq, peer_syn_next);
}

/* Established-state classifier for current-generation inbound packets. The
 * fake-TCP carrier is intentionally UDP-like here: we do not attempt reliable
 * reassembly, duplicate suppression, or contiguous-gap tracking. Instead we
 * accept payload whose starting sequence remains within a bounded sliding
 * window around the highest remote sequence end we have accepted for this
 * generation.
 */
enum phantun_established_rx_class {
    PHANTUN_EST_RX_INVALID = 0,
    PHANTUN_EST_RX_SILENT_ABSORB,
    PHANTUN_EST_RX_ACK_ONLY,
    PHANTUN_EST_RX_WINDOW_PAYLOAD,
    PHANTUN_EST_RX_RESERVED_SHAPING_DROP,
    PHANTUN_EST_RX_RESPONSE_SKIP_PROOF,
    PHANTUN_EST_RX_DROP_TOO_OLD,
    PHANTUN_EST_RX_DROP_TOO_FAR,
};

/* Snapshot returned by the established classifier. ack_seq is the peer's
 * acknowledgement of locally sent bytes; seq/seq_end describe the inbound
 * payload span, if any. response_unblocked means this packet validly proves
 * the injected responder handshake_response was acknowledged or skipped, so
 * queued responder UDP may be released.
 */
struct phantun_established_rx_decision {
    enum phantun_established_rx_class rx_class;
    u32 ack_seq;
    u32 seq;
    u32 seq_end;
    bool response_unblocked;
};

static bool phantun_tcp_is_established_ack(const struct pht_l4_view *view) {
    return view && view->tcp->ack && !view->tcp->syn && !view->tcp->rst && !view->tcp->fin &&
           !view->tcp->psh && !view->tcp->urg;
}

static bool phantun_established_window_disabled(void) {
    return phantun_cfg.established_window_bytes == 0;
}

static void phantun_established_window_bounds_locked(const struct pht_flow *flow, u32 *lower,
                                                     u32 *upper) {
    if (!flow || !lower || !upper)
        return;

    *lower = flow->ack - phantun_cfg.established_window_bytes;
    *upper = flow->ack + phantun_cfg.established_window_bytes;
}

static struct phantun_established_rx_decision
phantun_classify_established_rx_locked(const struct pht_flow *flow,
                                       const struct pht_l4_view *view) {
    struct phantun_established_rx_decision decision = {
        .rx_class = PHANTUN_EST_RX_INVALID,
    };

    if (!flow || !view || !phantun_tcp_is_established_ack(view))
        return decision;

    decision.ack_seq = ntohl(view->tcp->ack_seq);
    decision.seq = ntohl(view->tcp->seq);
    decision.seq_end = decision.seq + view->payload_len;

    if (!phantun_seq_between(decision.ack_seq, flow->local_isn + 1, flow->seq))
        return decision;

    if (view->payload_len == 0) {
        bool ack_advances = phantun_seq_after(decision.ack_seq, flow->last_ack);
        bool response_ack =
            flow->response_pending_ack &&
            phantun_seq_after_eq(decision.ack_seq,
                                 flow->local_isn + 1 + phantun_cfg.handshake_response_len);

        decision.rx_class = (decision.seq == flow->ack || ack_advances || response_ack)
                                ? PHANTUN_EST_RX_ACK_ONLY
                                : PHANTUN_EST_RX_SILENT_ABSORB;
        goto done;
    }

    if (!phantun_established_window_disabled()) {
        u32 lower;
        u32 upper;

        phantun_established_window_bounds_locked(flow, &lower, &upper);
        if (phantun_seq_before(decision.seq, lower)) {
            decision.rx_class = PHANTUN_EST_RX_DROP_TOO_OLD;
            goto done;
        }
        if (phantun_seq_after(decision.seq, upper)) {
            decision.rx_class = PHANTUN_EST_RX_DROP_TOO_FAR;
            goto done;
        }
    }

    if (flow->drop_next_rx_payload && decision.seq == flow->drop_next_rx_seq) {
        decision.rx_class = PHANTUN_EST_RX_RESERVED_SHAPING_DROP;
        goto done;
    }

    if (flow->response_pending_ack && phantun_seq_after(decision.seq, flow->ack)) {
        decision.rx_class = PHANTUN_EST_RX_RESPONSE_SKIP_PROOF;
        goto done;
    }

    decision.rx_class = PHANTUN_EST_RX_WINDOW_PAYLOAD;

done:
    if (flow->response_pending_ack) {
        decision.response_unblocked =
            phantun_seq_after_eq(decision.ack_seq,
                                 flow->local_isn + 1 + phantun_cfg.handshake_response_len) ||
            decision.rx_class == PHANTUN_EST_RX_RESPONSE_SKIP_PROOF ||
            decision.rx_class == PHANTUN_EST_RX_WINDOW_PAYLOAD;
    }

    return decision;
}

static bool phantun_tcp_syn_is_aligned(const struct pht_l4_view *view) {
    return view && ntohl(view->tcp->seq) % 4095U == 0;
}

/* Local reopen chooses a new aligned ISN outside reopen_guard_bytes of the
 * previous local sequence space so delayed old-generation packets are less
 * likely to fit the new flow.
 */
static bool phantun_pick_reopen_isn(u32 prev_seq, bool has_prev_seq, u32 *init_seq) {
    unsigned int attempt;

    if (!init_seq)
        return false;

    for (attempt = 0; attempt < PHANTUN_REOPEN_ISN_ATTEMPTS; attempt++) {
        u32 candidate = phantun_random_aligned_seq();

        if (has_prev_seq) {
            u32 diff = candidate - prev_seq;
            u32 abs_diff = diff < 0x80000000U ? diff : -diff;

            if (abs_diff < phantun_cfg.reopen_guard_bytes)
                continue;
        }

        *init_seq = candidate;
        return true;
    }

    return false;
}

static int phantun_send_flow_rst(struct pht_flow *flow, struct net *net) {
    struct pht_ipv4_endpoint_pair ep;
    u32 seq;
    u32 ack;
    int ifindex;
    int ret;

    spin_lock_bh(&flow->lock);
    ep = flow->oriented;
    seq = flow->seq;
    ack = flow->ack;
    spin_unlock_bh(&flow->lock);

    ret = pht_emit_fake_tcp_v4(net, &ep, seq, ack, PHT_TCP_FLAG_RST, NULL, 0, &ifindex);
    if (!ret) {
        pht_flow_set_egress_ifindex(flow, ifindex);
        pht_stats_inc(PHT_STAT_RST_SENT);
    }
    return ret;
}

static int phantun_send_established_udp(struct pht_flow *flow,
                                        const struct pht_ipv4_endpoint_pair *ep,
                                        const struct pht_l4_view *view, const struct sk_buff *skb,
                                        struct net *net) {
    u32 seq;
    u32 ack;
    void *payload = NULL;
    int ifindex;
    int ret;

    if (view->payload_len) {
        payload = kmalloc(view->payload_len, GFP_ATOMIC);
        if (!payload)
            return -ENOMEM;

        ret = pht_copy_l4_payload(skb, view, payload, view->payload_len);
        if (ret) {
            kfree(payload);
            return ret;
        }
    }

    /* Reserve sequence space before emitting so concurrent local senders stay
     * ordered. If emit fails, roll back only when nothing advanced flow->seq
     * in the meantime.
     */
    spin_lock_bh(&flow->tx_lock);
    spin_lock_bh(&flow->lock);
    if (flow->state != PHT_FLOW_STATE_ESTABLISHED) {
        spin_unlock_bh(&flow->lock);
        spin_unlock_bh(&flow->tx_lock);
        kfree(payload);
        return -EAGAIN;
    }
    seq = flow->seq;
    ack = flow->ack;
    flow->seq += view->payload_len;
    spin_unlock_bh(&flow->lock);

    ret = pht_emit_fake_tcp_v4(net, ep, seq, ack, PHT_TCP_FLAG_ACK, payload, view->payload_len,
                               &ifindex);
    if (!ret) {
        spin_lock_bh(&flow->lock);
        if (flow->state == PHT_FLOW_STATE_ESTABLISHED) {
            flow->last_activity_jiffies = jiffies;
            flow->egress_ifindex = ifindex;
        }
        spin_unlock_bh(&flow->lock);
    } else {
        spin_lock_bh(&flow->lock);
        if (flow->state == PHT_FLOW_STATE_ESTABLISHED) {
            if (flow->seq == seq + view->payload_len)
                flow->seq = seq;
            flow->state = PHT_FLOW_STATE_DEAD;
        }
        spin_unlock_bh(&flow->lock);
    }
    spin_unlock_bh(&flow->tx_lock);

    kfree(payload);
    return ret;
}

static int phantun_send_synack(struct pht_flow *flow, struct net *net) {
    struct pht_ipv4_endpoint_pair ep;
    u32 seq;
    u32 ack;
    int ifindex;
    int ret;

    spin_lock_bh(&flow->lock);
    ep = flow->oriented;
    seq = flow->local_isn;
    ack = flow->peer_syn_next;
    spin_unlock_bh(&flow->lock);

    ret = pht_emit_fake_tcp_v4(net, &ep, seq, ack, PHT_TCP_FLAG_SYN | PHT_TCP_FLAG_ACK, NULL, 0,
                               &ifindex);
    if (!ret)
        pht_flow_set_egress_ifindex(flow, ifindex);
    return ret;
}

static int phantun_send_rstack(struct net *net, const struct pht_ipv4_endpoint_pair *ep,
                               const struct pht_l4_view *view, bool force_zero_seq) {
    u32 seq = force_zero_seq ? 0 : ntohl(view->tcp->ack_seq);
    u32 ack = ntohl(view->tcp->seq) + phantun_tcp_seq_advance(view->tcp, view->payload_len);
    int ret;

    ret =
        pht_emit_fake_tcp_v4(net, ep, seq, ack, PHT_TCP_FLAG_RST | PHT_TCP_FLAG_ACK, NULL, 0, NULL);
    if (!ret)
        pht_stats_inc(PHT_STAT_RST_SENT);
    return ret;
}

static int phantun_send_handshake_request(struct pht_flow *flow, struct net *net) {
    struct pht_ipv4_endpoint_pair ep;
    u32 seq;
    u32 ack;
    size_t req_len = phantun_cfg.handshake_request_len;
    int ifindex;
    int ret;

    spin_lock_bh(&flow->lock);
    ep = flow->oriented;
    seq = flow->local_isn + 1;
    ack = flow->ack;
    spin_unlock_bh(&flow->lock);

    ret = pht_emit_fake_tcp_v4(net, &ep, seq, ack, PHT_TCP_FLAG_ACK, phantun_cfg.handshake_request,
                               req_len, &ifindex);
    if (!ret) {
        spin_lock_bh(&flow->lock);
        flow->seq = seq + req_len;
        flow->last_activity_jiffies = jiffies;
        flow->egress_ifindex = ifindex;
        spin_unlock_bh(&flow->lock);
        pht_stats_inc(PHT_STAT_REQUEST_PAYLOADS_INJECTED);
    }
    return ret;
}

static int phantun_send_handshake_response(struct pht_flow *flow, struct net *net) {
    struct pht_ipv4_endpoint_pair ep;
    u32 seq;
    u32 ack;
    size_t resp_len = phantun_cfg.handshake_response_len;
    int ifindex;
    int ret;

    spin_lock_bh(&flow->lock);
    ep = flow->oriented;
    seq = flow->local_isn + 1;
    ack = flow->ack;
    spin_unlock_bh(&flow->lock);

    ret = pht_emit_fake_tcp_v4(net, &ep, seq, ack, PHT_TCP_FLAG_ACK, phantun_cfg.handshake_response,
                               resp_len, &ifindex);
    if (!ret) {
        spin_lock_bh(&flow->lock);
        flow->seq = seq + resp_len;
        flow->last_activity_jiffies = jiffies;
        flow->egress_ifindex = ifindex;
        spin_unlock_bh(&flow->lock);
        pht_stats_inc(PHT_STAT_RESPONSE_PAYLOADS_INJECTED);
    }
    return ret;
}

static int phantun_send_idle_ack(struct pht_flow *flow, struct net *net) {
    struct pht_ipv4_endpoint_pair ep;
    u32 seq;
    u32 ack;
    int ifindex;
    int ret;

    spin_lock_bh(&flow->lock);
    ep = flow->oriented;
    seq = flow->seq;
    ack = flow->ack;
    spin_unlock_bh(&flow->lock);

    ret = pht_emit_fake_tcp_v4(net, &ep, seq, ack, PHT_TCP_FLAG_ACK, NULL, 0, &ifindex);
    if (!ret) {
        spin_lock_bh(&flow->lock);
        flow->last_activity_jiffies = jiffies;
        flow->egress_ifindex = ifindex;
        spin_unlock_bh(&flow->lock);
    }
    return ret;
}

static int phantun_flush_queued_udp(struct pht_flow *flow, struct net *net) {
    struct sk_buff *queued_skb;
    struct pht_l4_view qview;
    struct pht_ipv4_endpoint_pair qep;
    int ret;

    queued_skb = pht_flow_take_queued_skb(flow);
    if (!queued_skb)
        return 0;

    ret = pht_parse_ipv4_udp(queued_skb, &qview);
    if (ret) {
        kfree_skb(queued_skb);
        return ret;
    }

    phantun_fill_udp_endpoint_pair(&qview, &qep);
    ret = phantun_send_established_udp(flow, &qep, &qview, queued_skb, net);
    if (ret)
        pht_flow_set_queued_skb(flow, queued_skb);
    else
        kfree_skb(queued_skb);
    return ret;
}

static bool phantun_payload_exceeds_udp_reinject_limit(unsigned int payload_len) {
    return payload_len > PHT_V4_MAX_UDP_PAYLOAD_LEN;
}

static int phantun_reinject_inbound_payload(const struct pht_ipv4_endpoint_pair *ep,
                                            const struct sk_buff *skb,
                                            const struct pht_l4_view *view,
                                            struct net_device *dev) {
    void *payload;
    int ret;

    if (!view->payload_len)
        return 0;

    payload = kmalloc(view->payload_len, GFP_ATOMIC);
    if (!payload)
        return -ENOMEM;

    ret = pht_copy_l4_payload(skb, view, payload, view->payload_len);
    if (!ret)
        ret = pht_reinject_udp_payload_v4(dev, ep, payload, view->payload_len);
    kfree(payload);
    return ret;
}

static void phantun_refresh_inbound_progress(struct pht_flow *flow, const struct pht_l4_view *view,
                                             bool *allow_flush) {
    u32 seq_end = ntohl(view->tcp->seq) + view->payload_len;

    spin_lock_bh(&flow->lock);
    /* Reserved shaping payloads can arrive after higher-sequence real data.
     * Keep our advertised ACK monotonic when we silently drop that delayed
     * control packet.
     */
    if (phantun_seq_after_eq(seq_end, flow->ack))
        flow->ack = seq_end;
    flow->last_activity_jiffies = jiffies;
    flow->last_inbound_jiffies = jiffies;
    flow->keepalives_sent = 0;
    if (allow_flush)
        *allow_flush = !flow->response_pending_ack;
    spin_unlock_bh(&flow->lock);
}

static void phantun_note_inbound_payload(struct pht_flow *flow, const struct pht_l4_view *view) {
    phantun_refresh_inbound_progress(flow, view, NULL);
}

/* Apply the state-machine side effects of one established classifier result.
 * Payload reinjection is kept outside the lock so each call site shows
 * exactly when bytes are delivered to UDP versus when we only absorb wire
 * state changes.
 */
static void phantun_apply_established_rx(struct pht_flow *flow,
                                         const struct phantun_established_rx_decision *decision,
                                         bool *allow_flush) {
    bool refresh_liveness;

    if (!flow || !decision)
        return;

    refresh_liveness = decision->rx_class == PHANTUN_EST_RX_ACK_ONLY ||
                       decision->rx_class == PHANTUN_EST_RX_WINDOW_PAYLOAD ||
                       decision->rx_class == PHANTUN_EST_RX_RESERVED_SHAPING_DROP ||
                       decision->rx_class == PHANTUN_EST_RX_RESPONSE_SKIP_PROOF;

    spin_lock_bh(&flow->lock);
    if (decision->response_unblocked) {
        flow->response_pending_ack = false;
        if (allow_flush)
            *allow_flush = true;
    } else if (allow_flush) {
        *allow_flush = !flow->response_pending_ack;
    }

    if (phantun_seq_after(decision->ack_seq, flow->last_ack))
        flow->last_ack = decision->ack_seq;

    switch (decision->rx_class) {
    case PHANTUN_EST_RX_WINDOW_PAYLOAD:
    case PHANTUN_EST_RX_RESPONSE_SKIP_PROOF:
    case PHANTUN_EST_RX_RESERVED_SHAPING_DROP:
        if (phantun_seq_after_eq(decision->seq_end, flow->ack))
            flow->ack = decision->seq_end;
        break;
    default:
        break;
    }

    if (refresh_liveness) {
        flow->last_activity_jiffies = jiffies;
        flow->last_inbound_jiffies = jiffies;
        flow->keepalives_sent = 0;
    }
    spin_unlock_bh(&flow->lock);
}

static int phantun_finalize_established_rx(
    struct pht_flow *flow, const struct pht_ipv4_endpoint_pair *ep, const struct sk_buff *skb,
    const struct pht_l4_view *view, const struct phantun_established_rx_decision *decision,
    struct net *net, struct net_device *dev, bool reinject_payload, bool send_idle_ack) {
    bool allow_flush = false;
    int ret = 0;

    /* Oversized inbound payload is a protocol violation for this translator.
     * We cannot truthfully repackage it into a local UDP skb within our fixed
     * packet budget, so reject it before any ACK/liveness state is refreshed
     * or any large atomic allocation is attempted.
     */
    if (view->payload_len && phantun_payload_exceeds_udp_reinject_limit(view->payload_len)) {
        pht_stats_inc(PHT_STAT_OVERSIZED_PAYLOADS_DROPPED);
        return -EMSGSIZE;
    }

    phantun_apply_established_rx(flow, decision, &allow_flush);

    if (reinject_payload) {
        ret = phantun_reinject_inbound_payload(ep, skb, view, dev);
        if (ret)
            return ret;
    }

    if (allow_flush) {
        ret = phantun_flush_queued_udp(flow, net);
        if (ret)
            return ret;
    }

    if (send_idle_ack && view->payload_len)
        ret = phantun_send_idle_ack(flow, net);
    return ret;
}

static int phantun_finalize_responder_open_payload(
    struct pht_flow *flow, const struct pht_ipv4_endpoint_pair *ep, const struct sk_buff *skb,
    const struct pht_l4_view *view, const struct phantun_established_rx_decision *decision,
    struct net *net, struct net_device *dev) {
    bool reinject_payload;

    if (!decision)
        return -EPROTO;

    switch (decision->rx_class) {
    case PHANTUN_EST_RX_SILENT_ABSORB:
        return 0;
    case PHANTUN_EST_RX_DROP_TOO_OLD:
        pht_stats_inc(PHT_STAT_RX_WINDOW_TOO_OLD_DROPPED);
        return 0;
    case PHANTUN_EST_RX_DROP_TOO_FAR:
        pht_stats_inc(PHT_STAT_RX_WINDOW_TOO_FAR_DROPPED);
        return 0;
    case PHANTUN_EST_RX_RESERVED_SHAPING_DROP:
        pht_stats_inc(PHT_STAT_SHAPING_PAYLOADS_DROPPED);
        reinject_payload = false;
        break;
    case PHANTUN_EST_RX_WINDOW_PAYLOAD:
    case PHANTUN_EST_RX_RESPONSE_SKIP_PROOF:
        reinject_payload = true;
        break;
    default:
        return -EPROTO;
    }

    return phantun_finalize_established_rx(flow, ep, skb, view, decision, net, dev,
                                           reinject_payload, true);
}

static int phantun_confirm_outbound_udp_conntrack(struct sk_buff *skb) {
    enum ip_conntrack_info ctinfo;
    struct nf_conn *ct;
    int verdict;

    ct = nf_ct_get(skb, &ctinfo);
    if (!ct || ctinfo == IP_CT_UNTRACKED)
        return 0;

    /* LOCAL_OUT conntrack must survive our NF_STOLEN verdict so translated
     * inbound UDP replies can match ESTABLISHED host-firewall policy.
     */
    verdict = nf_conntrack_confirm(skb);
    if (verdict != NF_ACCEPT)
        return verdict == NF_DROP ? -EINVAL : -EIO;

    return 0;
}

/* LOCAL_OUT owns selector-matched outbound UDP. ESTABLISHED flows send
 * immediately, half-open flows keep only one queued skb, and DEAD flows are
 * reopened from scratch with a guarded ISN.
 */
static unsigned int phantun_local_out(void *priv, struct sk_buff *skb,
                                      const struct nf_hook_state *state) {
    struct pht_l4_view view;
    struct pht_ipv4_endpoint_pair ep;
    struct pht_flow_table *flows;
    struct pht_flow *flow;
    struct pht_flow *new_flow;
    enum pht_flow_state state_now;
    u32 init_seq;
    u32 prev_seq = 0;
    bool has_prev_seq = false;
    int ret;
    bool queued;

    if (!state || !skb)
        return NF_ACCEPT;

    flows = phantun_net_flows(state->net);
    if (!flows)
        return NF_ACCEPT;

    ret = pht_parse_ipv4_udp(skb, &view);
    if (ret)
        return NF_ACCEPT;

    if (phantun_local_out_uses_loopback_dev(skb, state))
        return NF_ACCEPT;

    if (!phantun_selectors_allow(view.udp->source, view.iph->daddr, view.udp->dest))
        return NF_ACCEPT;

    ret = phantun_confirm_outbound_udp_conntrack(skb);
    if (ret) {
        pht_pr_warn_rl("failed to confirm outbound UDP conntrack before translation: %d\n", ret);
        kfree_skb(skb);
        return NF_STOLEN;
    }

    phantun_fill_udp_endpoint_pair(&view, &ep);

retry_lookup:
    flow = pht_flow_lookup_oriented(flows, &ep);
    if (flow) {
        spin_lock_bh(&flow->lock);
        state_now = flow->state;
        spin_unlock_bh(&flow->lock);

        if (state_now == PHT_FLOW_STATE_ESTABLISHED) {
            bool hold_responder_data;

            spin_lock_bh(&flow->lock);
            hold_responder_data =
                flow->role == PHT_FLOW_ROLE_RESPONDER && flow->response_pending_ack;
            spin_unlock_bh(&flow->lock);
            /* Responder-owned UDP must wait while an injected
             * handshake_response still needs peer acknowledgement or later
             * initiator data to prove the reserved control slot was
             * skipped.
             */
            if (hold_responder_data) {
                queued = pht_flow_queue_skb_if_empty(flow, skb);
                if (!queued)
                    kfree_skb(skb);
                phantun_account_udp_queue_result(queued);
                pht_flow_put(flow);
                return NF_STOLEN;
            }

            ret = phantun_send_established_udp(flow, &ep, &view, skb, state->net);
            if (ret) {
                pht_pr_warn("failed to emit fake-TCP payload for established flow: %d\n", ret);
                phantun_send_flow_rst(flow, state->net);
                pht_flow_remove(flow);
            }
            pht_flow_put(flow);
            kfree_skb(skb);
            return NF_STOLEN;
        }

        if (pht_flow_state_is_half_open(state_now)) {
            queued = pht_flow_queue_skb_if_empty(flow, skb);
            if (!queued)
                kfree_skb(skb);
            phantun_account_udp_queue_result(queued);
            pht_flow_put(flow);
            return NF_STOLEN;
        }

        /* DEAD still occupies the canonical slot until we unhash it. Drop
         * that generation and retry so a fresh initiator flow can inherit
         * the reopen guard from the old sequence space.
         */
        if (state_now == PHT_FLOW_STATE_DEAD) {
            prev_seq = flow->seq;
            has_prev_seq = true;
            pht_flow_detach(flow);
            pht_flow_put(flow);
            goto retry_lookup;
        }

        pht_flow_put(flow);
        kfree_skb(skb);
        return NF_STOLEN;
    }

    new_flow = pht_flow_create(flows, &ep, PHT_FLOW_ROLE_INITIATOR, PHT_FLOW_STATE_SYN_SENT);
    if (IS_ERR(new_flow)) {
        pht_pr_warn("failed to create initiator flow: %ld\n", PTR_ERR(new_flow));
        kfree_skb(skb);
        return NF_STOLEN;
    }

    if (!phantun_pick_reopen_isn(prev_seq, has_prev_seq, &init_seq)) {
        pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
        pht_pr_warn("failed to choose reopen ISN for new flow\n");
        pht_flow_put(new_flow);
        kfree_skb(skb);
        return NF_STOLEN;
    }

    spin_lock_bh(&new_flow->lock);
    new_flow->seq = init_seq;
    new_flow->ack = 0;
    new_flow->last_ack = 0;
    new_flow->local_isn = init_seq;
    new_flow->peer_syn_next = 0;
    spin_unlock_bh(&new_flow->lock);
    pht_flow_set_queued_skb(new_flow, skb);

    ret = pht_flow_insert(flows, new_flow);
    /* Another CPU won the canonical-tuple race. Reuse its flow instead of
     * creating a parallel generation.
     */
    if (ret == -EEXIST) {
        skb = pht_flow_take_queued_skb(new_flow);
        pht_flow_put(new_flow);
        goto retry_lookup;
    }
    if (ret) {
        pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
        pht_pr_warn("failed to insert initiator flow: %d\n", ret);
        pht_flow_put(new_flow);
        return NF_STOLEN;
    }
    pht_stats_inc(PHT_STAT_UDP_PACKETS_QUEUED);

    {
        int ifindex;

        ret =
            pht_emit_fake_tcp_v4(state->net, &ep, init_seq, 0, PHT_TCP_FLAG_SYN, NULL, 0, &ifindex);
        if (!ret)
            pht_flow_set_egress_ifindex(new_flow, ifindex);
    }
    if (ret) {
        pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
        pht_pr_warn("failed to emit fake-TCP SYN: %d\n", ret);
        pht_flow_remove(new_flow);
        return NF_STOLEN;
    }

    return NF_STOLEN;
}

static unsigned int phantun_pre_routing(void *priv, struct sk_buff *skb,
                                        const struct nf_hook_state *state);

/* GRO can merge multiple fake-TCP packets into one skb before PRE_ROUTING.
 * Our translator relies on per-packet boundaries, so segment managed TCP GSO
 * skbs back into individual packets before running the state machine.
 */
static unsigned int phantun_pre_routing_segment_gso(void *priv, struct sk_buff *skb,
                                                    const struct nf_hook_state *state) {
    netdev_features_t features = NETIF_F_SG | NETIF_F_IP_CSUM;
    struct sk_buff *segs;
    struct sk_buff *seg;
    struct sk_buff *next;
    long err;

    if (!skb_is_gso(skb) || !skb_is_gso_tcp(skb))
        return NF_ACCEPT;

    segs = __skb_gso_segment(skb, features, false);
    if (IS_ERR_OR_NULL(segs)) {
        err = IS_ERR(segs) ? PTR_ERR(segs) : -EINVAL;
        pht_pr_warn("failed to segment inbound TCP GRO skb: %ld\n", err);
        return NF_DROP;
    }

    consume_skb(skb);

    skb_list_walk_safe(segs, seg, next) {
        unsigned int verdict;

        skb_mark_not_on_list(seg);
        verdict = phantun_pre_routing(priv, seg, state);
        if (verdict == NF_ACCEPT)
            pht_pr_warn_rl("segmented inbound TCP packet unexpectedly escaped fake-TCP handler\n");
        kfree_skb(seg);
    }

    return NF_STOLEN;
}

/* Selector-matched raw inbound UDP is dropped before local delivery so a
 * tuple is owned either by fake-TCP translation or by nothing. Reinject-marked
 * UDP is exempt because it already came out of the translator.
 */
static unsigned int phantun_pre_routing_udp_drop(void *priv, struct sk_buff *skb,
                                                 const struct nf_hook_state *state) {
    struct pht_l4_view view;
    int ret;

    if (!state || !skb)
        return NF_ACCEPT;

    if (skb->mark == PHANTUN_REINJECT_MARK) {
        skb->mark = 0;
        return NF_ACCEPT;
    }

    if (phantun_pre_routing_uses_loopback_dev(skb, state))
        return NF_ACCEPT;

    ret = pht_parse_ipv4_udp(skb, &view);
    if (ret)
        return NF_ACCEPT;

    if (!phantun_pre_routing_targets_local_host(state->net, view.iph->daddr))
        return NF_ACCEPT;

    if (!phantun_selectors_allow(view.udp->dest, view.iph->saddr, view.udp->source))
        return NF_ACCEPT;

    pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
    kfree_skb(skb);
    return NF_STOLEN;
}

/* PRE_ROUTING owns selector-matched fake-TCP before the real TCP stack sees
 * it. Unknown owned packets are rejected unless they are valid bare SYNs that
 * create a new responder flow.
 */
static unsigned int phantun_pre_routing(void *priv, struct sk_buff *skb,
                                        const struct nf_hook_state *state) {
    struct pht_l4_view view;
    struct pht_ipv4_endpoint_pair ep;
    struct pht_flow_table *flows;
    struct pht_flow *flow;
    struct pht_flow *new_flow;
    struct sk_buff *queued_skb;
    enum pht_flow_state state_now;
    struct net_device *in_dev;
    u32 expected_ack;
    u32 responder_seq;
    u32 local_isn;
    u32 peer_syn_next;
    enum pht_flow_role role_now;
    u32 quarantine_prev_local_seq_start = 0;
    u32 quarantine_prev_local_seq_end = 0;
    u32 quarantine_prev_remote_seq_start = 0;
    u32 quarantine_prev_remote_seq_end = 0;
    bool carry_quarantine = false;
    bool had_queued;
    int ret;

    if (!state || !skb)
        return NF_ACCEPT;

    if (phantun_pre_routing_uses_loopback_dev(skb, state))
        return NF_ACCEPT;

    flows = phantun_net_flows(state->net);
    if (!flows)
        return NF_DROP;

    ret = pht_parse_ipv4_tcp(skb, &view);
    if (ret)
        return NF_ACCEPT;

    if (!phantun_pre_routing_targets_local_host(state->net, view.iph->daddr))
        return NF_ACCEPT;

    if (!phantun_selectors_allow(view.tcp->dest, view.iph->saddr, view.tcp->source))
        return NF_ACCEPT;

    ret = phantun_pre_routing_segment_gso(priv, skb, state);
    if (ret != NF_ACCEPT)
        return ret;

    ret = pht_validate_ipv4_tcp_checksums(skb, &view);
    if (ret)
        return NF_DROP;

    phantun_fill_tcp_endpoint_pair(&view, &ep);
    in_dev = state->in ? state->in : skb->dev;

    flow = pht_flow_lookup_oriented(flows, &ep);
    if (flow) {
        spin_lock_bh(&flow->lock);
        state_now = flow->state;
        spin_unlock_bh(&flow->lock);

        if (state_now == PHT_FLOW_STATE_DEAD) {
            pht_flow_detach(flow);
            pht_flow_put(flow);
            flow = NULL;
        }
    }

    if (!flow) {
        if (view.tcp->rst)
            return NF_DROP;

        if (!phantun_tcp_is_bare_syn(&view)) {
            ret = phantun_send_rstack(state->net, &ep, &view, view.tcp->syn);
            if (ret)
                pht_pr_warn_rl("failed to emit RST|ACK for unknown packet: %d\n", ret);
            return NF_DROP;
        }

        if (!phantun_tcp_syn_is_aligned(&view)) {
            ret = phantun_send_rstack(state->net, &ep, &view, true);
            if (ret)
                pht_pr_warn_rl("failed to emit RST|ACK for misaligned SYN: %d\n", ret);
            return NF_DROP;
        }
        /* Only a bare aligned SYN is allowed to create responder state for an
         * otherwise unknown owned tuple.
         */
    process_as_new_syn:
        new_flow = pht_flow_create(flows, &ep, PHT_FLOW_ROLE_RESPONDER, PHT_FLOW_STATE_SYN_RCVD);
        if (IS_ERR(new_flow)) {
            pht_pr_warn("failed to create responder flow: %ld\n", PTR_ERR(new_flow));
            return NF_DROP;
        }

        responder_seq = get_random_u32();
        spin_lock_bh(&new_flow->lock);
        new_flow->seq = responder_seq;
        new_flow->ack = ntohl(view.tcp->seq) + 1;
        new_flow->last_ack = new_flow->ack;
        new_flow->local_isn = responder_seq;
        new_flow->peer_syn_next = new_flow->ack;
        spin_unlock_bh(&new_flow->lock);
        if (carry_quarantine) {
            phantun_flow_arm_prev_generation_quarantine(
                new_flow, quarantine_prev_local_seq_start, quarantine_prev_local_seq_end,
                quarantine_prev_remote_seq_start, quarantine_prev_remote_seq_end);
            carry_quarantine = false;
        }

        ret = pht_flow_insert(flows, new_flow);
        if (ret) {
            pht_flow_put(new_flow);
            return NF_DROP;
        }

        ret = phantun_send_synack(new_flow, state->net);
        if (ret) {
            pht_pr_warn("failed to emit SYN|ACK: %d\n", ret);
            pht_flow_remove(new_flow);
        }
        return NF_DROP;
    }

    spin_lock_bh(&flow->lock);
    state_now = flow->state;
    expected_ack = flow->local_isn + 1;
    local_isn = flow->local_isn;
    peer_syn_next = flow->peer_syn_next;
    role_now = flow->role;
    had_queued = flow->queued_skb != NULL;
    spin_unlock_bh(&flow->lock);

    if (view.tcp->rst) {
        if (phantun_flow_should_drop_quarantined_packet(flow, &view)) {
            pht_flow_put(flow);
            return NF_DROP;
        }
        pht_flow_remove(flow);
        pht_flow_put(flow);
        return NF_DROP;
    }

    /* Initiator half-open state: accept only collision SYNs, the matching
     * SYN|ACK, or RST. Simultaneous initiation collapses by comparing ISNs.
     */
    if (state_now == PHT_FLOW_STATE_SYN_SENT) {
        if (phantun_tcp_is_bare_syn(&view)) {
            u32 peer_isn;

            if (!phantun_tcp_syn_is_aligned(&view)) {
                ret = phantun_send_rstack(state->net, &ep, &view, true);
                if (ret)
                    pht_pr_warn_rl("failed to emit RST|ACK for misaligned colliding SYN: %d\n",
                                   ret);
                pht_flow_put(flow);
                return NF_DROP;
            }

            peer_isn = ntohl(view.tcp->seq);

            if (local_isn == peer_isn) {
                /* Exact match is extremely rare. Drop to
                 * resolve via timeout */
                pht_flow_put(flow);
                return NF_DROP;
            }

            if (local_isn < peer_isn) {
                pht_pr_info("collision on tuple; keeping initiator role\n");
                pht_flow_touch_inbound(flow);
                pht_stats_inc(PHT_STAT_COLLISIONS_WON);
                pht_flow_put(flow);
                return NF_DROP;
            }

            pht_pr_info("collision on tuple; switching to responder role\n");
            pht_stats_inc(PHT_STAT_COLLISIONS_LOST);
            queued_skb = pht_flow_take_queued_skb(flow);
            pht_flow_detach(flow);
            pht_flow_put(flow);

            new_flow =
                pht_flow_create(flows, &ep, PHT_FLOW_ROLE_RESPONDER, PHT_FLOW_STATE_SYN_RCVD);
            if (IS_ERR(new_flow)) {
                kfree_skb(queued_skb);
                return NF_DROP;
            }

            responder_seq = get_random_u32();
            spin_lock_bh(&new_flow->lock);
            new_flow->seq = responder_seq;
            new_flow->ack = ntohl(view.tcp->seq) + 1;
            new_flow->last_ack = new_flow->ack;
            new_flow->local_isn = responder_seq;
            new_flow->peer_syn_next = new_flow->ack;
            spin_unlock_bh(&new_flow->lock);
            if (queued_skb)
                pht_flow_set_queued_skb(new_flow, queued_skb);

            ret = pht_flow_insert(flows, new_flow);
            if (ret) {
                pht_flow_put(new_flow);
                return NF_DROP;
            }

            ret = phantun_send_synack(new_flow, state->net);
            if (ret) {
                pht_pr_warn("failed to emit SYN|ACK after collision handoff: %d\n", ret);
                pht_flow_remove(new_flow);
            }
            return NF_DROP;
        }

        if (view.tcp->syn && view.tcp->ack && view.payload_len == 0 &&
            ntohl(view.tcp->ack_seq) == expected_ack) {
            /* Handshake establishment is complete even if the responder later
             * sends an injected handshake_response. Reserve responder_seq + 1
             * so that optional control payload is ignored by sequence instead
             * of being treated as required handshake data.
             */
            spin_lock_bh(&flow->lock);
            flow->seq = flow->local_isn + 1;
            flow->ack = ntohl(view.tcp->seq) + 1;
            flow->peer_syn_next = flow->ack;
            flow->last_ack = flow->local_isn + 1;
            flow->drop_next_rx_seq = flow->ack;
            flow->drop_next_rx_payload = phantun_response_enabled();
            flow->response_pending_ack = false;
            spin_unlock_bh(&flow->lock);

            if (phantun_request_enabled()) {
                ret = phantun_send_handshake_request(flow, state->net);
                if (ret) {
                    pht_pr_warn("failed to emit handshake request: %d\n", ret);
                    pht_flow_remove(flow);
                    pht_flow_put(flow);
                    return NF_DROP;
                }
            }

            pht_flow_touch_inbound(flow);
            pht_flow_update_state(flow, PHT_FLOW_STATE_ESTABLISHED);
            ret = phantun_flush_queued_udp(flow, state->net);
            if (!ret && !had_queued && !phantun_request_enabled())
                ret = phantun_send_idle_ack(flow, state->net);
            if (ret) {
                pht_pr_warn("failed to finalize initiator open: %d\n", ret);
                pht_flow_remove(flow);
            }
            pht_flow_put(flow);
            return NF_DROP;
        }

        ret = phantun_send_rstack(state->net, &ep, &view, false);
        if (ret)
            pht_pr_warn_rl("failed to emit RST|ACK for unexpected SYN_SENT packet: %d\n", ret);
        pht_flow_remove(flow);
        pht_flow_put(flow);
        return NF_DROP;
    }

    if (state_now == PHT_FLOW_STATE_SYN_RCVD && phantun_tcp_is_bare_syn(&view) &&
        phantun_tcp_syn_is_aligned(&view) && ntohl(view.tcp->seq) + 1 == peer_syn_next) {
        ret = phantun_send_synack(flow, state->net);
        if (ret)
            pht_pr_warn("failed to re-emit SYN|ACK: %d\n", ret);
        pht_flow_put(flow);
        return NF_DROP;
    }

    /* Responder half-open state: duplicate SYN retransmits SYN|ACK. The final
     * ACK may carry payload at peer_syn_next or later if an earlier opener
     * payload was lost, but a pure-ACK sequence jump is still invalid.
     */
    if (state_now == PHT_FLOW_STATE_SYN_RCVD) {
        if (!phantun_tcp_is_valid_final_ack(&view, peer_syn_next) ||
            ntohl(view.tcp->ack_seq) != expected_ack) {
            if (phantun_flow_should_drop_quarantined_packet(flow, &view)) {
                pht_flow_put(flow);
                return NF_DROP;
            }
            ret = phantun_send_rstack(state->net, &ep, &view, false);
            if (ret)
                pht_pr_warn_rl("failed to emit RST|ACK for bad final ACK: %d\n", ret);
            pht_flow_remove(flow);
            pht_flow_put(flow);
            return NF_DROP;
        }

        /* request shaping reserves initiator_seq + 1. If the final ACK already
         * carries payload at that exact sequence, drop it now; otherwise arm
         * the ignore slot for the later packet with that starting sequence.
         */
        spin_lock_bh(&flow->lock);
        flow->seq = flow->local_isn + 1;
        flow->ack = flow->peer_syn_next;
        flow->last_ack = flow->local_isn + 1;
        flow->drop_next_rx_seq = flow->ack;
        flow->drop_next_rx_payload = phantun_request_enabled();
        flow->response_pending_ack = false;
        spin_unlock_bh(&flow->lock);

        {
            struct phantun_established_rx_decision open_decision;

            /* Injected handshake_response occupies responder_seq + 1.
             * Keep responder-owned UDP blocked until the peer ACKs that
             * range or later initiator payload proves the control slot was
             * skipped.
             */
            if (phantun_response_enabled()) {
                ret = phantun_send_handshake_response(flow, state->net);
                if (ret) {
                    pht_pr_warn("failed to emit handshake response: %d\n", ret);
                    pht_flow_remove(flow);
                    pht_flow_put(flow);
                    return NF_DROP;
                }

                spin_lock_bh(&flow->lock);
                flow->response_pending_ack = true;
                spin_unlock_bh(&flow->lock);
            }

            if (view.payload_len == 0) {
                pht_flow_touch_inbound(flow);
                pht_flow_update_state(flow, PHT_FLOW_STATE_ESTABLISHED);
                if (!phantun_response_enabled()) {
                    ret = phantun_flush_queued_udp(flow, state->net);
                    if (ret) {
                        pht_pr_warn("failed to flush responder queue: %d\n", ret);
                        pht_flow_remove(flow);
                    }
                }
                pht_flow_put(flow);
                return NF_DROP;
            }

            pht_flow_update_state(flow, PHT_FLOW_STATE_ESTABLISHED);

            spin_lock_bh(&flow->lock);
            open_decision = phantun_classify_established_rx_locked(flow, &view);
            spin_unlock_bh(&flow->lock);

            ret = phantun_finalize_responder_open_payload(flow, &ep, skb, &view, &open_decision,
                                                          state->net, in_dev);
            if (ret) {
                pht_pr_warn("failed to process responder open payload: %d\n", ret);
                if (ret == -EMSGSIZE || ret == -EPROTO)
                    phantun_send_rstack(state->net, &ep, &view, false);
                pht_flow_remove(flow);
            }
            pht_flow_put(flow);
            return NF_DROP;
        }
    }

    /* ESTABLISHED handling still prioritizes flags over payload. Once RST/SYN
     * cases are handled, the remaining traffic is classified against the
     * current generation's sliding receive window and local send frontier.
     */
    if (state_now == PHT_FLOW_STATE_ESTABLISHED) {
        struct phantun_established_rx_decision decision;
        bool reinject_payload;

        if (phantun_flow_should_drop_quarantined_packet(flow, &view)) {
            pht_flow_put(flow);
            return NF_DROP;
        }

        if (view.tcp->syn) {
            if (flow->role == PHT_FLOW_ROLE_INITIATOR && view.tcp->ack && view.payload_len == 0 &&
                ntohl(view.tcp->ack_seq) == flow->local_isn + 1 &&
                ntohl(view.tcp->seq) + 1 == flow->peer_syn_next) {
                ret = phantun_send_idle_ack(flow, state->net);
                if (ret)
                    pht_pr_warn("failed to ACK duplicate current-generation SYN|ACK: %d\n", ret);
                pht_flow_put(flow);
                return NF_DROP;
            }
            if (phantun_tcp_is_bare_syn(&view) && phantun_tcp_syn_is_aligned(&view)) {
                if (role_now == PHT_FLOW_ROLE_RESPONDER &&
                    ntohl(view.tcp->seq) + 1 == peer_syn_next) {
                    ret = phantun_send_synack(flow, state->net);
                    if (ret)
                        pht_pr_warn("failed to re-emit SYN|ACK for duplicate established SYN: %d\n",
                                    ret);
                    pht_flow_put(flow);
                    return NF_DROP;
                }
                /* Accept bare replacement SYN as a new generation. Preserve
                 * only the just-replaced seq/ack window so delayed old packets
                 * are dropped quietly during the quarantine window.
                 */
                spin_lock_bh(&flow->lock);
                quarantine_prev_local_seq_start = flow->local_isn;
                quarantine_prev_local_seq_end = flow->seq;
                quarantine_prev_remote_seq_start = flow->peer_syn_next;
                quarantine_prev_remote_seq_end = flow->ack;
                spin_unlock_bh(&flow->lock);
                carry_quarantine = true;
                pht_pr_info("received bare SYN on ESTABLISHED tuple, replacing generation\n");
                queued_skb = pht_flow_take_queued_skb(flow);
                if (queued_skb)
                    kfree_skb(queued_skb);
                pht_flow_detach(flow);
                pht_flow_put(flow);
                goto process_as_new_syn;
            }
            pht_pr_warn_rl("received invalid SYN on ESTABLISHED tuple, destroying\n");
            phantun_send_rstack(state->net, &ep, &view, true);
            pht_flow_remove(flow);
            pht_flow_put(flow);
            return NF_DROP;
        }

        spin_lock_bh(&flow->lock);
        decision = phantun_classify_established_rx_locked(flow, &view);
        spin_unlock_bh(&flow->lock);

        /* The classifier only returns INVALID once RST/SYN handling is out of
         * the way, so this packet has no truthful interpretation within the
         * current generation. Fail hard instead of letting it refresh or skew
         * state.
         */
        if (decision.rx_class == PHANTUN_EST_RX_INVALID) {
            ret = phantun_send_rstack(state->net, &ep, &view, false);
            if (ret)
                pht_pr_warn_rl("failed to emit RST|ACK for invalid established packet: %d\n", ret);
            pht_flow_remove(flow);
            pht_flow_put(flow);
            return NF_DROP;
        }

        if (decision.rx_class == PHANTUN_EST_RX_SILENT_ABSORB) {
            pht_flow_put(flow);
            return NF_DROP;
        }

        if (decision.rx_class == PHANTUN_EST_RX_DROP_TOO_OLD) {
            pht_stats_inc(PHT_STAT_RX_WINDOW_TOO_OLD_DROPPED);
            pht_flow_put(flow);
            return NF_DROP;
        }

        if (decision.rx_class == PHANTUN_EST_RX_DROP_TOO_FAR) {
            pht_stats_inc(PHT_STAT_RX_WINDOW_TOO_FAR_DROPPED);
            pht_flow_put(flow);
            return NF_DROP;
        }

        if (decision.rx_class == PHANTUN_EST_RX_RESERVED_SHAPING_DROP)
            pht_stats_inc(PHT_STAT_SHAPING_PAYLOADS_DROPPED);

        reinject_payload = decision.rx_class == PHANTUN_EST_RX_WINDOW_PAYLOAD ||
                           decision.rx_class == PHANTUN_EST_RX_RESPONSE_SKIP_PROOF;
        ret = phantun_finalize_established_rx(flow, &ep, skb, &view, &decision, state->net, in_dev,
                                              reinject_payload, true);
        if (ret) {
            pht_pr_warn("failed to process established inbound payload: %d\n", ret);
            if (ret == -EMSGSIZE)
                phantun_send_rstack(state->net, &ep, &view, false);
            pht_flow_remove(flow);
        }
        pht_flow_put(flow);
        return NF_DROP;
    }

    pht_flow_put(flow);
    return NF_DROP;
}

static struct nf_hook_ops phantun_nf_ops[] = {
    {
        .hook = phantun_local_out,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_LOCAL_OUT,
        /* Let LOCAL_OUT conntrack observe the original UDP before we steal
         * it, so translated inbound replies can match ESTABLISHED policy.
         */
        .priority = PHANTUN_LOCAL_OUT_PRIORITY,
    },
    {
        .hook = phantun_pre_routing_udp_drop,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = PHANTUN_PRE_ROUTING_PRIORITY,
    },
    {
        .hook = phantun_pre_routing,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = PHANTUN_PRE_ROUTING_PRIORITY,
    },
};

static int __net_init phantun_net_init(struct net *net) {
    struct phantun_net *pnet = net_generic(net, phantun_net_id);
    struct pht_flow_table *flows;
    int ret;

    if (!pnet)
        return -EINVAL;

    flows = &pnet->flows;
    ret = pht_flow_table_init(flows, net, &phantun_cfg);
    if (ret) {
        pht_pr_err("failed to initialize flow table: %d\n", ret);
        return ret;
    }

    pnet->netdev_nb.notifier_call = phantun_netdev_event;
    ret = register_netdevice_notifier_net(net, &pnet->netdev_nb);
    if (ret) {
        pht_pr_err("failed to register netdevice notifier: %d\n", ret);
        pht_flow_table_destroy(flows);
        return ret;
    }

    ret = nf_register_net_hooks(net, phantun_nf_ops, ARRAY_SIZE(phantun_nf_ops));
    if (ret) {
        pht_pr_err("failed to register netfilter hooks: %d\n", ret);
        unregister_netdevice_notifier_net(net, &pnet->netdev_nb);
        pht_flow_table_destroy(flows);
        return ret;
    }

    pht_pr_info("registered IPv4 LOCAL_OUT/PRE_ROUTING hooks and topology notifiers: netns %u\n",
                phantun_netns_id(net));
    return 0;
}

static void __net_exit phantun_net_exit(struct net *net) {
    struct phantun_net *pnet = net_generic(net, phantun_net_id);
    struct pht_flow_table *flows;

    if (!pnet)
        return;

    flows = &pnet->flows;
    nf_unregister_net_hooks(net, phantun_nf_ops, ARRAY_SIZE(phantun_nf_ops));
    unregister_netdevice_notifier_net(net, &pnet->netdev_nb);
    pht_flow_table_destroy(flows);
    pht_pr_info("unregistered netfilter hooks and topology notifiers: netns %u\n",
                phantun_netns_id(net));
}

static struct pernet_operations phantun_pernet_ops = {
    .id = &phantun_net_id,
    .size = sizeof(struct phantun_net),
    .init = phantun_net_init,
    .exit = phantun_net_exit,
};

static int phantun_validate_config(void) {
    unsigned int i;
    int ret;

    if (!managed_local_ports_count && !managed_remote_peers_count) {
        pht_pr_err("at least one selector entry is required\n");
        return -EINVAL;
    }

    for (i = 0; i < managed_local_ports_count; i++) {
        if (!managed_local_ports[i] || managed_local_ports[i] > U16_MAX) {
            pht_pr_err("managed_local_ports[%u] must be between 1 and 65535\n", i);
            return -EINVAL;
        }
    }

    for (i = 0; i < managed_remote_peers_count; i++) {
        struct pht_managed_peer parsed_peer;

        ret = phantun_parse_managed_remote_peer(managed_remote_peers[i], &parsed_peer);
        if (ret) {
            pht_pr_err("managed_remote_peers[%u] must be valid x.y.z.w:p\n", i);
            return ret;
        }
    }

    if (!handshake_timeout_ms) {
        pht_pr_err("handshake_timeout_ms must be greater than zero\n");
        return -EINVAL;
    }

    if (!handshake_retries) {
        pht_pr_err("handshake_retries must be greater than zero\n");
        return -EINVAL;
    }

    if (!keepalive_interval_sec) {
        pht_pr_err("keepalive_interval_sec must be greater than zero\n");
        return -EINVAL;
    }

    if (!keepalive_misses) {
        pht_pr_err("keepalive_misses must be greater than zero\n");
        return -EINVAL;
    }

    if (!hard_idle_timeout_sec) {
        pht_pr_err("hard_idle_timeout_sec must be greater than zero\n");
        return -EINVAL;
    }

    if (reopen_guard_bytes >= 0x80000000U) {
        pht_pr_err("reopen_guard_bytes must be smaller than 2147483648\n");
        return -EINVAL;
    }
    if (established_window_bytes >= 0x80000000U) {
        pht_pr_err("established_window_bytes must be smaller than 2147483648\n");
        return -EINVAL;
    }
    return 0;
}

static int phantun_base64_decode(const char *src, size_t srclen, u8 **out_dst,
                                 unsigned int *out_len) {
    u8 *dst;
    int decoded_len;

    if (srclen % 4 != 0)
        return -EINVAL;

    dst = kmalloc((srclen / 4) * 3, GFP_KERNEL);
    if (!dst)
        return -ENOMEM;

    decoded_len = BASE64_DECODE_COMPAT(src, srclen, dst);

    if (decoded_len < 0) {
        kfree(dst);
        return -EINVAL;
    }

    *out_dst = dst;
    *out_len = decoded_len;
    return 0;
}

static int phantun_parse_payload_param(const char *raw_str, void **out_buf, unsigned int *out_len) {
    size_t len;
    int ret;

    *out_buf = NULL;
    *out_len = 0;

    if (!raw_str || !*raw_str)
        return 0;

    len = strlen(raw_str);

    if (len >= 7 && strncmp(raw_str, "base64:", 7) == 0) {
        raw_str += 7;
        len -= 7;
        if (len == 0)
            return 0;

        ret = phantun_base64_decode(raw_str, len, (u8 **)out_buf, out_len);
        if (ret == -ENOMEM)
            return -ENOMEM;
        if (ret) {
            pht_pr_warn("failed to base64 decode parameter, ignoring\n");
            *out_buf = NULL;
            *out_len = 0;
        }
        return 0;
    }

    if (len >= 4 && strncmp(raw_str, "hex:", 4) == 0) {
        raw_str += 4;
        len -= 4;

        if (len == 0)
            return 0;

        if (len % 2 != 0) {
            pht_pr_warn("hex parameter must have an even length, ignoring\n");
            return 0;
        }

        *out_buf = kmalloc(len / 2, GFP_KERNEL);
        if (!*out_buf)
            return -ENOMEM;

        if (hex2bin(*out_buf, raw_str, len / 2)) {
            pht_pr_warn("invalid hex characters in parameter, ignoring\n");
            kfree(*out_buf);
            *out_buf = NULL;
            return 0;
        }

        *out_len = len / 2;
        return 0;
    }

    /* Plain string fallback */
    *out_buf = kmalloc(len, GFP_KERNEL);
    if (!*out_buf)
        return -ENOMEM;
    memcpy(*out_buf, raw_str, len);
    *out_len = len;

    return 0;
}

static int phantun_snapshot_config(void) {
    unsigned int i;
    int ret;

    memset(&phantun_cfg, 0, sizeof(phantun_cfg));
    phantun_cfg.managed_local_ports_count = managed_local_ports_count;
    for (i = 0; i < managed_local_ports_count; i++)
        phantun_cfg.managed_local_ports[i] = (u16)managed_local_ports[i];
    phantun_cfg.managed_remote_peers_count = managed_remote_peers_count;
    for (i = 0; i < managed_remote_peers_count; i++) {
        if (phantun_parse_managed_remote_peer(managed_remote_peers[i],
                                              &phantun_cfg.managed_remote_peers[i])) {
            /* Config was validated earlier; keep impossible parse
             * failures from leaking uninitialized data into the hot
             * path.
             */
            memset(&phantun_cfg.managed_remote_peers[i], 0,
                   sizeof(phantun_cfg.managed_remote_peers[i]));
        }
    }
    ret = phantun_parse_payload_param(handshake_request, &phantun_alloc_req,
                                      &phantun_cfg.handshake_request_len);
    if (ret)
        return ret;
    phantun_cfg.handshake_request = phantun_alloc_req;

    ret = phantun_parse_payload_param(handshake_response, &phantun_alloc_resp,
                                      &phantun_cfg.handshake_response_len);
    if (ret) {
        kfree(phantun_alloc_req);
        phantun_alloc_req = NULL;
        return ret;
    }
    phantun_cfg.handshake_response = phantun_alloc_resp;
    phantun_cfg.handshake_timeout_ms = handshake_timeout_ms;
    phantun_cfg.handshake_retries = handshake_retries;
    phantun_cfg.keepalive_interval_sec = keepalive_interval_sec;
    phantun_cfg.keepalive_misses = keepalive_misses;
    phantun_cfg.hard_idle_timeout_sec = hard_idle_timeout_sec;
    phantun_cfg.reopen_guard_bytes = reopen_guard_bytes;
    phantun_cfg.established_window_bytes = established_window_bytes;

    return 0;
}

static void phantun_log_config(void) {
    unsigned int i;

    pht_pr_info("loading with %u managed local port(s), %u managed remote peer(s), "
                "handshake_timeout_ms=%u, handshake_retries=%u, "
                "keepalive_interval_sec=%u, keepalive_misses=%u, "
                "hard_idle_timeout_sec=%u, reopen_guard_bytes=%u, established_window_bytes=%u\n",
                phantun_cfg.managed_local_ports_count, phantun_cfg.managed_remote_peers_count,
                phantun_cfg.handshake_timeout_ms, phantun_cfg.handshake_retries,
                phantun_cfg.keepalive_interval_sec, phantun_cfg.keepalive_misses,
                phantun_cfg.hard_idle_timeout_sec, phantun_cfg.reopen_guard_bytes,
                phantun_cfg.established_window_bytes);

    for (i = 0; i < phantun_cfg.managed_local_ports_count; i++)
        pht_pr_info("managed_local_ports[%u]=%u\n", i, phantun_cfg.managed_local_ports[i]);
    for (i = 0; i < phantun_cfg.managed_remote_peers_count; i++)
        pht_pr_info("managed_remote_peers[%u]=%pI4:%u\n", i,
                    &phantun_cfg.managed_remote_peers[i].addr,
                    ntohs(phantun_cfg.managed_remote_peers[i].port));
}

static int __init phantun_init(void) {
    int ret;

    pht_pr_info(PHANTUN_MODULE_NAME " %s loaded\n", PACKAGE_VERSION);

    ret = phantun_validate_config();
    if (ret)
        return ret;

    ret = phantun_snapshot_config();
    if (ret)
        goto err_alloc;

    phantun_log_config();
    pht_stats_reset();
    ret = pht_stats_init_sysfs();
    if (ret)
        goto err_alloc;

    ret = register_pernet_subsys(&phantun_pernet_ops);
    if (ret)
        goto err_sysfs;

    phantun_inetaddr_nb.notifier_call = phantun_inetaddr_event;
    ret = register_inetaddr_notifier(&phantun_inetaddr_nb);
    if (ret)
        goto err_pernet;

    return 0;

err_pernet:
    unregister_pernet_subsys(&phantun_pernet_ops);
err_sysfs:
    pht_stats_exit_sysfs();
err_alloc:
    kfree(phantun_alloc_req);
    kfree(phantun_alloc_resp);
    return ret;
}

static void __exit phantun_exit(void) {
    unregister_inetaddr_notifier(&phantun_inetaddr_nb);
    unregister_pernet_subsys(&phantun_pernet_ops);
    pht_stats_exit_sysfs();
    kfree(phantun_alloc_req);
    kfree(phantun_alloc_resp);
    pht_pr_info(PHANTUN_MODULE_NAME " unloaded\n");
}

module_init(phantun_init);
module_exit(phantun_exit);

// SPDX-License-Identifier: GPL-2.0-or-later
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bin Jin");
MODULE_DESCRIPTION(
    "Kernel module re-implementation of phantun, transform UDP streams into fake-TCP streams");
MODULE_VERSION(PACKAGE_VERSION);
