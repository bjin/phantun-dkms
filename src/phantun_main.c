// SPDX-License-Identifier: GPL-2.0-or-later
//
// Copyright (C) 2026 Bin Jin. All Rights Reserved.
#include <linux/in.h>
#include <linux/inetdevice.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/net_namespace.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/string.h>

#include <net/inet_sock.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/route.h>
#include <net/sock.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <net/addrconf.h>
#include <net/ipv6.h>
#endif

#include "phantun_compat.h" // IWYU pragma: keep

#ifdef HAVE_NET_GSO_H
#include <net/gso.h>
#endif

#include "phantun.h"
#include "phantun_flow.h"
#include "phantun_packet.h"
#include "phantun_stats.h"

#define PHANTUN_REOPEN_ISN_ATTEMPTS 1024U

static void phantun_account_udp_queue_result(bool queued) {
    if (queued) {
        pht_stats_inc(PHT_STAT_UDP_PACKETS_QUEUED);
        return;
    }

    pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
    pht_stats_inc(PHT_STAT_UDP_QUEUE_FULL_DROPPED);
}

static void phantun_account_udp_translation_failure(void) {
    pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
    pht_stats_inc(PHT_STAT_UDP_TRANSLATION_FAILED_DROPPED);
}

static bool phantun_io_error_is_transient(int ret) {
    return ret == NET_XMIT_DROP || ret == -ENOBUFS || ret == -ENOMEM || ret == -EMSGSIZE;
}

static void phantun_account_tcp_protocol_rejected(void) {
    pht_stats_inc(PHT_STAT_TCP_PROTOCOL_REJECTED);
}

static void phantun_account_tcp_misaligned_syn_rejected(void) {
    pht_stats_inc(PHT_STAT_TCP_PROTOCOL_REJECTED);
    pht_stats_inc(PHT_STAT_TCP_MISALIGNED_SYN_REJECTED);
}

static void phantun_account_tcp_unknown_tuple_rejected(void) {
    pht_stats_inc(PHT_STAT_TCP_PROTOCOL_REJECTED);
    pht_stats_inc(PHT_STAT_TCP_UNKNOWN_TUPLE_REJECTED);
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
static bool phantun_pre_routing_targets_local_host(const struct net *net,
                                                   const struct pht_addr *addr) {
    if (!net || !addr)
        return false;

    switch (addr->family) {
    case AF_INET:
        return inet_addr_type_table((struct net *)net, addr->v4, RT_TABLE_LOCAL) == RTN_LOCAL;
#if IS_ENABLED(CONFIG_IPV6)
    case AF_INET6:
        return ipv6_chk_addr((struct net *)net, &addr->v6, NULL, 0);
#endif
    default:
        return false;
    }
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

static bool phantun_remote_peer_allowed(const struct pht_addr *addr, __be16 port) {
    unsigned int i;

    if (!phantun_cfg.managed_remote_peers_count)
        return true;

    for (i = 0; i < phantun_cfg.managed_remote_peers_count; i++) {
        if (pht_addr_equal(&phantun_cfg.managed_remote_peers[i].addr, addr) &&
            phantun_cfg.managed_remote_peers[i].port == port)
            return true;
    }

    return false;
}

static bool phantun_selectors_allow(__be16 local_port, const struct pht_addr *remote_addr,
                                    __be16 remote_port) {
    return phantun_local_port_allowed(local_port) &&
           phantun_remote_peer_allowed(remote_addr, remote_port);
}

static void phantun_fill_udp_endpoint_pair(const struct pht_l4_view *view,
                                           struct pht_endpoint_pair *ep) {
    memset(ep, 0, sizeof(*ep));
    ep->local_port = view->udp->source;
    ep->remote_port = view->udp->dest;
    if (view->family == AF_INET) {
        ep->local_addr.family = AF_INET;
        ep->local_addr.v4 = view->iph->saddr;
        ep->remote_addr.family = AF_INET;
        ep->remote_addr.v4 = view->iph->daddr;
    } else {
        ep->local_addr.family = AF_INET6;
        ep->local_addr.v6 = view->ip6h->saddr;
        ep->remote_addr.family = AF_INET6;
        ep->remote_addr.v6 = view->ip6h->daddr;
    }
}

static void phantun_fill_tcp_endpoint_pair(const struct pht_l4_view *view,
                                           struct pht_endpoint_pair *ep) {
    memset(ep, 0, sizeof(*ep));
    ep->local_port = view->tcp->dest;
    ep->remote_port = view->tcp->source;
    if (view->family == AF_INET) {
        ep->local_addr.family = AF_INET;
        ep->local_addr.v4 = view->iph->daddr;
        ep->remote_addr.family = AF_INET;
        ep->remote_addr.v4 = view->iph->saddr;
    } else {
        ep->local_addr.family = AF_INET6;
        ep->local_addr.v6 = view->ip6h->daddr;
        ep->remote_addr.family = AF_INET6;
        ep->remote_addr.v6 = view->ip6h->saddr;
    }
}

#if IS_ENABLED(CONFIG_IPV6)
static void phantun_fill_endpoint_scope_ifindex(struct pht_endpoint_pair *ep,
                                                const struct net_device *dev) {
    if (!ep || !dev || ep->remote_addr.family != AF_INET6)
        return;

    ep->scope_ifindex = (int)ipv6_iface_scope_id(&ep->remote_addr.v6, dev->ifindex);
}
#else
static void phantun_fill_endpoint_scope_ifindex(struct pht_endpoint_pair *ep,
                                                const struct net_device *dev) {}
#endif

static void phantun_tx_meta_from_view(const struct sk_buff *skb, const struct pht_l4_view *view,
                                      bool use_oif, struct pht_tx_meta *meta) {
    const struct sock *sk;

    pht_tx_meta_init(meta);
    if (!meta || !skb || !view)
        return;

    meta->mark = skb->mark;
    meta->priority = skb->priority;

    /*
     * TCP control skbs may carry a TIME_WAIT or request socket. Normalize
     * that owner before reading full-socket fields: a TIME_WAIT socket has
     * only the sock_common prefix, so sk_uid would otherwise be out of bounds.
     */
    sk = skb_to_full_sk(skb);
    if (sk && sk_fullsock(sk)) {
        meta->uid = sk->sk_uid;
        if (use_oif && sk->sk_bound_dev_if > 0)
            meta->oif = sk->sk_bound_dev_if;
    }
    /* state->out/skb->dev are route results, not explicit policy inputs. Do
     * not feed them back as flowi oif, or a mark/TOS change made before our
     * LOCAL_OUT hook can be pinned to the pre-policy route.
     */

    if (view->family == AF_INET) {
        meta->v4_tos = view->iph->tos;
        return;
    }

#if IS_ENABLED(CONFIG_IPV6)
    if (view->family == AF_INET6) {
        meta->v6_priority = view->ip6h->priority;
        memcpy(meta->v6_flow_lbl, view->ip6h->flow_lbl, sizeof(meta->v6_flow_lbl));
    }
#endif
}

static bool phantun_addr_unsupported_for_endpoint(const struct pht_addr *addr) {
#if IS_ENABLED(CONFIG_IPV6)
    if (addr && addr->family == AF_INET6 && (ipv6_addr_type(&addr->v6) & IPV6_ADDR_LINKLOCAL))
        return true;
#endif

    return false;
}

static bool phantun_endpoint_uses_unsupported_addr(const struct pht_endpoint_pair *ep) {
    return ep && (phantun_addr_unsupported_for_endpoint(&ep->local_addr) ||
                  phantun_addr_unsupported_for_endpoint(&ep->remote_addr));
}

static bool phantun_addr_pair_uses_unsupported_addr(const struct pht_addr *local_addr,
                                                    const struct pht_addr *remote_addr) {
    return phantun_addr_unsupported_for_endpoint(local_addr) ||
           phantun_addr_unsupported_for_endpoint(remote_addr);
}

static bool phantun_family_enabled(u8 family) {
    if (family == AF_INET)
        return !!(phantun_cfg.enabled_families & PHT_FAMILY_IPV4);
    if (family == AF_INET6)
        return !!(phantun_cfg.enabled_families & PHT_FAMILY_IPV6);
    return false;
}

static int phantun_parse_udp_skb(struct sk_buff *skb, struct pht_l4_view *view) {
    int ret;

    if (skb->protocol == htons(ETH_P_IP))
        return pht_parse_ipv4_udp(skb, view);
    if (skb->protocol == htons(ETH_P_IPV6))
        return pht_parse_ipv6_udp(skb, view);

    ret = pht_parse_ipv4_udp(skb, view);
    if (!ret)
        return 0;
    return pht_parse_ipv6_udp(skb, view);
}

static int phantun_validate_tcp_checksums(const struct sk_buff *skb,
                                          const struct pht_l4_view *view) {
    if (view->family == AF_INET)
        return pht_validate_ipv4_tcp_checksums(skb, view);
    if (view->family == AF_INET6)
        return pht_validate_ipv6_tcp_checksums(skb, view);
    return -EINVAL;
}

static void phantun_view_remote_addr(const struct pht_l4_view *view, bool tcp,
                                     struct pht_addr *addr) {
    memset(addr, 0, sizeof(*addr));
    if (view->family == AF_INET) {
        addr->family = AF_INET;
        addr->v4 = tcp ? view->iph->saddr : view->iph->daddr;
    } else {
        addr->family = AF_INET6;
        addr->v6 = tcp ? view->ip6h->saddr : view->ip6h->daddr;
    }
}

static void phantun_view_local_addr(const struct pht_l4_view *view, bool tcp,
                                    struct pht_addr *addr) {
    memset(addr, 0, sizeof(*addr));
    if (view->family == AF_INET) {
        addr->family = AF_INET;
        addr->v4 = tcp ? view->iph->daddr : view->iph->saddr;
    } else {
        addr->family = AF_INET6;
        addr->v6 = tcp ? view->ip6h->daddr : view->ip6h->saddr;
    }
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
static const u32 PHANTUN_SEQ_MAX_SIGNED_WINDOW = 0x7fffffffU;

static bool phantun_seq_after_eq(u32 seq1, u32 seq2) { return (s32)(seq1 - seq2) >= 0; }

static bool phantun_seq_before_eq(u32 seq1, u32 seq2) { return (s32)(seq1 - seq2) <= 0; }

static bool phantun_seq_between(u32 seq, u32 start, u32 end) {
    return phantun_seq_after_eq(seq, start) && phantun_seq_before_eq(seq, end);
}

/* These lower edges are deliberately stateful instead of recomputing from
 * local_isn/peer_syn_next on demand. Once a generation sends or receives more
 * than one full u32 wrap of sequence space, (end - initial_base) can look small
 * again, so a pure modulo calculation would reopen an over-wide signed compare
 * window. Advancing the stored edge monotonically preserves the bounded window
 * invariant for arbitrarily long-lived flows.
 */
static u32 phantun_seq_window_lower_edge(u32 lower_edge, u32 end) {
    if (end - lower_edge > PHANTUN_SEQ_MAX_SIGNED_WINDOW)
        return end - PHANTUN_SEQ_MAX_SIGNED_WINDOW;
    return lower_edge;
}

static void phantun_flow_refresh_local_seq_window_locked(struct pht_flow *flow) {
    flow->local_seq_window_start =
        phantun_seq_window_lower_edge(flow->local_seq_window_start, flow->seq);
}

static void phantun_flow_refresh_remote_seq_window_locked(struct pht_flow *flow) {
    flow->remote_seq_window_start =
        phantun_seq_window_lower_edge(flow->remote_seq_window_start, flow->ack);
}

/* Remember only the immediately previous generation on a tuple. During the
 * configured quarantine window, packets that still fit that old seq/ack
 * space are dropped instead of provoking fresh RSTs after a replacement SYN
 * wins.
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
    flow->quarantine_until_jiffies =
        jiffies + msecs_to_jiffies(phantun_cfg.replacement_quarantine_ms);
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
    seq = ntohl(view->tcp->seq);
    ack = ntohl(view->tcp->ack_seq);

    if (!phantun_seq_between(seq, flow->remote_seq_window_start, flow->ack))
        return false;
    if (view->tcp->rst && !view->tcp->ack)
        return true;
    if (!view->tcp->ack)
        return false;

    return phantun_seq_between(ack, flow->local_seq_window_start, flow->seq);
}

static bool phantun_flow_should_drop_quarantined_packet_locked(struct pht_flow *flow,
                                                               const struct pht_l4_view *view) {
    lockdep_assert_held(&flow->lock);
    if (phantun_tcp_is_bare_syn(view) || !flow->quarantine_prev_active)
        return false;
    if (time_after_eq(jiffies, flow->quarantine_until_jiffies)) {
        flow->quarantine_prev_active = false;
        return false;
    }
    if (!phantun_flow_matches_quarantine_locked(flow, view))
        return false;
    if (flow->state == PHT_FLOW_STATE_ESTABLISHED &&
        phantun_flow_matches_current_generation_locked(flow, view))
        return false;
    return true;
}

static bool phantun_flow_should_drop_quarantined_packet(struct pht_flow *flow,
                                                        const struct pht_l4_view *view) {
    bool drop;

    if (!flow || !view || phantun_tcp_is_bare_syn(view))
        return false;
    spin_lock_bh(&flow->lock);
    drop = phantun_flow_should_drop_quarantined_packet_locked(flow, view);
    spin_unlock_bh(&flow->lock);
    if (drop)
        pht_stats_inc(PHT_STAT_REPLACEMENT_QUARANTINE_DROPPED);
    return drop;
}

/* A protocol-opening or replacement SYN really must be SYN-only. If other
 * control flags ride along, later state-machine code cannot safely treat it as
 * a clean opener and should fall back to the generic invalid-SYN path instead.
 */
static bool phantun_tcp_is_bare_syn(const struct pht_l4_view *view) {
    return view && view->tcp->syn && !view->tcp->ack && !view->tcp->rst && !view->tcp->fin &&
           !view->tcp->psh && !view->tcp->urg && view->payload_len == 0;
}

/* Completing the initiator half-open handshake only accepts a clean SYN|ACK.
 * PSH is rejected here because this packet shape is control-only; no payload or
 * payload-signalling flags are meaningful until the final ACK path.
 */
static bool phantun_tcp_is_clean_synack(const struct pht_l4_view *view, u32 expected_ack) {
    return view && view->tcp->syn && view->tcp->ack && ntohl(view->tcp->ack_seq) == expected_ack &&
           view->payload_len == 0 && !view->tcp->rst && !view->tcp->fin && !view->tcp->psh &&
           !view->tcp->urg;
}

/* Established fake-TCP is only an ACK-shaped UDP carrier. PSH is tolerated with
 * ACK because it does not consume sequence space and some peers mark data with
 * it; FIN and URG require TCP semantics this module does not implement.
 */
static bool phantun_tcp_is_established_ack(const struct pht_l4_view *view) {
    return view && view->tcp->ack && !view->tcp->syn && !view->tcp->rst && !view->tcp->fin &&
           !view->tcp->urg;
}

/* The responder's final handshake step may carry payload and PSH. Keep this
 * aligned with opener validation: control flags that consume sequence space or
 * require unsupported semantics must not complete SYN_RCVD just by guessing the
 * right ACK number.
 */
static bool phantun_tcp_is_syn_rcvd_final_ack(const struct pht_l4_view *view, u32 expected_ack) {
    return view && view->tcp->ack && ntohl(view->tcp->ack_seq) == expected_ack && !view->tcp->syn &&
           !view->tcp->rst && !view->tcp->fin && !view->tcp->urg;
}

static bool phantun_tcp_syn_is_aligned(const struct pht_l4_view *view) {
    return view && ntohl(view->tcp->seq) % 4095U == 0;
}

static bool phantun_flow_should_drop_protected_replacement_syn(struct pht_flow *flow,
                                                               const struct pht_l4_view *view) {
    unsigned long now;
    bool drop = false;

    if (!flow || !view || !phantun_tcp_is_bare_syn(view) || !phantun_tcp_syn_is_aligned(view))
        return false;

    now = jiffies;
    spin_lock_bh(&flow->lock);
    if (flow->state != PHT_FLOW_STATE_ESTABLISHED || flow->role != PHT_FLOW_ROLE_INITIATOR ||
        !flow->replacement_protect_active)
        goto out;
    if (time_before(now, flow->replacement_protect_until_jiffies)) {
        drop = true;
        goto out;
    }
    flow->replacement_protect_active = false;

out:
    spin_unlock_bh(&flow->lock);
    if (drop)
        pht_stats_inc(PHT_STAT_REPLACEMENT_PROTECT_DROPPED);
    return drop;
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

static bool phantun_request_enabled(void) { return phantun_cfg.handshake_request_len > 0; }

static bool phantun_response_enabled(void) {
    return phantun_request_enabled() && phantun_cfg.handshake_response_len > 0;
}

static int phantun_send_flow_rst(struct pht_flow *flow, struct net *net) {
    struct pht_endpoint_pair ep;
    struct pht_tx_meta meta;
    u32 seq;
    u32 ack;
    int ifindex;
    int ret;

    spin_lock_bh(&flow->lock);
    ep = flow->endpoints;
    seq = flow->seq;
    ack = flow->ack;
    meta = flow->local_tx_meta;
    spin_unlock_bh(&flow->lock);

    ret = pht_emit_fake_tcp(net, &ep, seq, ack, PHT_TCP_FLAG_RST, NULL, 0, &meta, &ifindex);
    if (!ret) {
        pht_flow_set_egress_ifindex(flow, ifindex);
        pht_stats_inc(PHT_STAT_RST_SENT);
    }
    return ret;
}

/* Returns 0 for a successful emit, a stale-generation drop, or a transient
 * local I/O drop where the UDP skb is intentionally consumed. In-flight
 * -EMSGSIZE is consumed as a per-packet oversized drop. Any other error owns
 * terminal established-send teardown before returning.
 */
static int phantun_send_established_udp(struct pht_flow *flow, const struct pht_endpoint_pair *ep,
                                        const struct pht_l4_view *view, const struct sk_buff *skb,
                                        const struct pht_tx_meta *meta, struct net *net,
                                        bool persist_meta, bool send_rst_on_fatal_failure,
                                        bool *emitted_payload) {
    u32 local_seq_window_start;
    bool fatal_failure = false;
    u32 seq;
    u32 ack;
    int ifindex;
    int ret;

    if (emitted_payload)
        *emitted_payload = false;

    if (view->payload_len > pht_fake_tcp_max_payload_len(view->family)) {
        pht_stats_inc(PHT_STAT_OVERSIZED_PAYLOADS_DROPPED);
        pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
        return -EMSGSIZE;
    }

    /* Reserve sequence space before emitting so concurrent local senders stay
     * ordered. Stale-generation and terminal failures roll the reservation back
     * when safe; transient local pressure consumes the sequence range exactly
     * like on-path packet loss.
     *
     * For immediate local-out sends, the current UDP skb's metadata is also the
     * best local transmit policy context for later synthetic packets. Queued
     * skb metadata remains per-skb only; replaying an older queued packet must
     * not overwrite a newer local_tx_meta learned while the queue was full.
     */
    spin_lock_bh(&flow->tx_lock);
    spin_lock_bh(&flow->lock);
    if (flow->state != PHT_FLOW_STATE_ESTABLISHED) {
        spin_unlock_bh(&flow->lock);
        spin_unlock_bh(&flow->tx_lock);
        return 0;
    }
    if (persist_meta && meta)
        flow->local_tx_meta = *meta;
    seq = flow->seq;
    ack = flow->ack;
    local_seq_window_start = flow->local_seq_window_start;
    flow->seq += view->payload_len;
    phantun_flow_refresh_local_seq_window_locked(flow);
    spin_unlock_bh(&flow->lock);

    ret = pht_flow_emit_established_payload(flow, net, ep, seq, ack, skb, view->payload_offset,
                                            view->payload_len, meta, &ifindex);
    if (!ret) {
        spin_lock_bh(&flow->lock);
        if (flow->state == PHT_FLOW_STATE_ESTABLISHED) {
            flow->last_activity_jiffies = jiffies;
            flow->last_established_payload_tx_jiffies = get_jiffies_64();
            flow->egress_ifindex = ifindex;
            if (persist_meta && meta)
                flow->local_tx_meta = *meta;
        }
        spin_unlock_bh(&flow->lock);
        if (emitted_payload)
            *emitted_payload = true;
    } else {
        bool stale_generation = ret == -EAGAIN;
        bool transient_failure = phantun_io_error_is_transient(ret);

        spin_lock_bh(&flow->lock);
        if (!transient_failure && flow->state == PHT_FLOW_STATE_ESTABLISHED &&
            flow->seq == seq + view->payload_len) {
            flow->seq = seq;
            flow->local_seq_window_start = local_seq_window_start;
        }
        if (!stale_generation && !transient_failure) {
            flow->state = PHT_FLOW_STATE_DEAD;
            fatal_failure = true;
        }
        spin_unlock_bh(&flow->lock);
        /* -EAGAIN is the emit helper's generation guard: the flow stopped
         * matching this packet while the skb/dst was being prepared. Transient
         * queue/memory pressure and path-MTU refusal consume only this UDP
         * payload; the established generation remains live and later packets
         * continue in sequence.
         */
        if (stale_generation) {
            ret = 0;
        } else if (ret == -EMSGSIZE) {
            pht_stats_inc(PHT_STAT_OVERSIZED_PAYLOADS_DROPPED);
            pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
            ret = 0;
        } else if (transient_failure) {
            phantun_account_udp_translation_failure();
            ret = 0;
        }
    }
    spin_unlock_bh(&flow->tx_lock);

    if (fatal_failure) {
        if (send_rst_on_fatal_failure)
            phantun_send_flow_rst(flow, net);
        pht_flow_remove(flow);
    }

    return ret;
}

/* @reply_meta is an emission-only override for responder replies generated
 * directly from an inbound fake-TCP packet. When NULL, use the cached local
 * outbound policy context for retransmits and other synthetic packets.
 */
static int phantun_send_synack(struct pht_flow *flow, struct net *net,
                               const struct pht_tx_meta *reply_meta) {
    struct pht_endpoint_pair ep;
    struct pht_tx_meta meta;
    u32 seq;
    u32 ack;
    int ifindex;
    int ret;

    spin_lock_bh(&flow->lock);
    ep = flow->endpoints;
    seq = flow->local_isn;
    ack = flow->peer_syn_next;
    meta = reply_meta ? *reply_meta : flow->local_tx_meta;
    spin_unlock_bh(&flow->lock);

    ret = pht_emit_fake_tcp(net, &ep, seq, ack, PHT_TCP_FLAG_SYN | PHT_TCP_FLAG_ACK, NULL, 0, &meta,
                            &ifindex);
    if (!ret)
        pht_flow_set_egress_ifindex(flow, ifindex);
    return ret;
}

static int phantun_send_rstack(struct net *net, const struct pht_endpoint_pair *ep,
                               const struct pht_l4_view *view, const struct pht_tx_meta *meta) {
    /* RFC 793 reset generation: a RST answering a segment with ACK set takes
     * its sequence from that ack_seq; an ACK-less segment gets seq 0.
     */
    u32 seq = view->tcp->ack ? ntohl(view->tcp->ack_seq) : 0;
    u32 ack = ntohl(view->tcp->seq) + phantun_tcp_seq_advance(view->tcp, view->payload_len);
    int ret;

    ret = pht_emit_fake_tcp(net, ep, seq, ack, PHT_TCP_FLAG_RST | PHT_TCP_FLAG_ACK, NULL, 0, meta,
                            NULL);
    if (!ret)
        pht_stats_inc(PHT_STAT_RST_SENT);
    return ret;
}

static int phantun_send_handshake_request(struct pht_flow *flow, struct net *net) {
    struct pht_endpoint_pair ep;
    struct pht_tx_meta meta;
    u32 seq;
    u32 ack;
    size_t req_len = phantun_cfg.handshake_request_len;
    int ifindex;
    int ret;

    spin_lock_bh(&flow->lock);
    ep = flow->endpoints;
    seq = flow->local_isn + 1;
    ack = flow->ack;
    meta = flow->local_tx_meta;
    spin_unlock_bh(&flow->lock);

    ret = pht_emit_fake_tcp(net, &ep, seq, ack, PHT_TCP_FLAG_ACK, phantun_cfg.handshake_request,
                            req_len, &meta, &ifindex);
    if (!ret) {
        spin_lock_bh(&flow->lock);
        if (flow->state != PHT_FLOW_STATE_DEAD) {
            flow->last_activity_jiffies = jiffies;
            flow->egress_ifindex = ifindex;
        }
        spin_unlock_bh(&flow->lock);
        pht_stats_inc(PHT_STAT_REQUEST_PAYLOADS_INJECTED);
    }
    return ret;
}

/* Same reply-scoped metadata rule as phantun_send_synack(). */
static int phantun_send_handshake_response(struct pht_flow *flow, struct net *net,
                                           const struct pht_tx_meta *reply_meta) {
    struct pht_endpoint_pair ep;
    struct pht_tx_meta meta;
    u32 seq;
    u32 ack;
    size_t resp_len = phantun_cfg.handshake_response_len;
    int ifindex;
    int ret;

    spin_lock_bh(&flow->lock);
    ep = flow->endpoints;
    seq = flow->local_isn + 1;
    ack = flow->ack;
    meta = reply_meta ? *reply_meta : flow->local_tx_meta;
    spin_unlock_bh(&flow->lock);

    ret = pht_emit_fake_tcp(net, &ep, seq, ack, PHT_TCP_FLAG_ACK, phantun_cfg.handshake_response,
                            resp_len, &meta, &ifindex);
    if (!ret) {
        spin_lock_bh(&flow->lock);
        if (flow->state != PHT_FLOW_STATE_DEAD) {
            flow->last_activity_jiffies = jiffies;
            flow->egress_ifindex = ifindex;
        }
        spin_unlock_bh(&flow->lock);
        pht_stats_inc(PHT_STAT_RESPONSE_PAYLOADS_INJECTED);
    }
    return ret;
}

static int phantun_send_idle_ack(struct pht_flow *flow, struct net *net,
                                 const struct pht_tx_meta *reply_meta) {
    struct pht_endpoint_pair ep;
    struct pht_tx_meta meta;
    u32 seq;
    u32 ack;
    int ifindex;
    int ret;

    spin_lock_bh(&flow->lock);
    ep = flow->endpoints;
    seq = flow->seq;
    ack = flow->ack;
    meta = reply_meta ? *reply_meta : flow->local_tx_meta;
    spin_unlock_bh(&flow->lock);

    ret = pht_emit_fake_tcp(net, &ep, seq, ack, PHT_TCP_FLAG_ACK, NULL, 0, &meta, &ifindex);
    if (!ret) {
        spin_lock_bh(&flow->lock);
        if (flow->state != PHT_FLOW_STATE_DEAD) {
            flow->last_activity_jiffies = jiffies;
            flow->egress_ifindex = ifindex;
        }
        spin_unlock_bh(&flow->lock);
    }
    return ret;
}

static int phantun_flush_queued_udp(struct pht_flow *flow, struct net *net, bool *emitted_payload) {
    struct sk_buff *queued_skb;
    struct pht_l4_view qview;
    struct pht_endpoint_pair qep;
    struct pht_tx_meta meta;
    bool payload_emitted = false;
    int ret;

    if (emitted_payload)
        *emitted_payload = false;

    queued_skb = pht_flow_take_queued_skb(flow, &meta);
    if (!queued_skb)
        return 0;

    ret = phantun_parse_udp_skb(queued_skb, &qview);
    if (ret) {
        phantun_account_udp_translation_failure();
        kfree_skb(queued_skb);
        return ret;
    }

    if (!qview.payload_len) {
        pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
        kfree_skb(queued_skb);
        return 0;
    }

    phantun_fill_udp_endpoint_pair(&qview, &qep);
    qep.scope_ifindex = flow->endpoints.scope_ifindex;
    ret = phantun_send_established_udp(flow, &qep, &qview, queued_skb, &meta, net, false, false,
                                       &payload_emitted);
    if (ret && ret != -EMSGSIZE) {
        phantun_account_udp_translation_failure();
        kfree_skb(queued_skb);
        return ret;
    }

    if (payload_emitted && emitted_payload)
        *emitted_payload = true;

    /* The payload left the box as fake TCP; freeing the original UDP skb is
     * consumption, not a drop, so keep it out of drop monitors.
     */
    if (payload_emitted)
        consume_skb(queued_skb);
    else
        kfree_skb(queued_skb);
    return 0;
}

static void phantun_discard_queued_udp_translation_failure(struct pht_flow *flow) {
    struct sk_buff *queued_skb = pht_flow_take_queued_skb(flow, NULL);

    if (!queued_skb)
        return;

    phantun_account_udp_translation_failure();
    kfree_skb(queued_skb);
}

static bool phantun_payload_exceeds_udp_reinject_limit(const struct pht_l4_view *view) {
    if (view->family == AF_INET)
        return view->payload_len > PHT_V4_MAX_UDP_PAYLOAD_LEN;
    if (view->family == AF_INET6)
        return view->payload_len > PHT_V6_MAX_UDP_PAYLOAD_LEN;
    return true;
}

static int phantun_reinject_inbound_payload(const struct pht_endpoint_pair *ep,
                                            const struct sk_buff *skb,
                                            const struct pht_l4_view *view, struct net *net,
                                            struct net_device *dev) {
    struct pht_flow_table *flows;

    if (!view->payload_len)
        return 0;

    /* netif_rx() derives receive namespace from skb->dev.  PRE_ROUTING
     * should hand us an ingress device from state->net; make that contract
     * explicit before manufacturing a UDP packet for local delivery.
     */
    if (!net || !dev || dev_net(dev) != net)
        return -EINVAL;

    flows = phantun_net_hook_flows(net);
    if (!flows)
        return -EINVAL;

    return pht_reinject_udp_payload_from_skb(dev, ep, skb, view->payload_offset, view->payload_len,
                                             flows->reinject_mark);
}

enum phantun_rx_action_kind {
    PHT_RX_DONE,
    PHT_RX_DELIVER,
    PHT_RX_REJECT_OVERSIZED,
    PHT_RX_QUARANTINED,
};

/* Prepared under flow->lock and executed without it. The hook keeps its flow
 * reference across both phases; this record owns no skb or dst reference.
 */
struct phantun_rx_action {
    enum phantun_rx_action_kind kind;
    bool reinject_payload;
    bool shaping_dropped;
};

static void phantun_refresh_inbound_progress_locked(struct pht_flow *flow,
                                                    const struct pht_l4_view *view) {
    u32 seq_end = ntohl(view->tcp->seq) + view->payload_len;

    lockdep_assert_held(&flow->lock);
    /* Reserved shaping payloads can arrive after higher-sequence real data.
     * Keep our advertised ACK monotonic when we silently drop that delayed
     * control packet.
     */
    if (phantun_seq_after_eq(seq_end, flow->ack))
        flow->ack = seq_end;
    /* Best-effort early retirement of a never-consumed slot. Lost sequence
     * history can hide this boundary; reused sequence numbers remain ambiguous,
     * but the one-shot exception can suppress at most one candidate.
     */
    if (flow->one_shot_shaping_rx_pending &&
        flow->ack - flow->one_shot_shaping_rx_seq > PHANTUN_SEQ_MAX_SIGNED_WINDOW) {
        flow->one_shot_shaping_rx_pending = false;
    }
    phantun_flow_refresh_remote_seq_window_locked(flow);
    pht_flow_touch_inbound_locked(flow);
}

static void phantun_note_inbound_payload(struct pht_flow *flow, const struct pht_l4_view *view) {
    spin_lock_bh(&flow->lock);
    phantun_refresh_inbound_progress_locked(flow, view);
    spin_unlock_bh(&flow->lock);
}

/* Consume the one-shot exception under the same lock as RX classification. */
static bool phantun_consume_one_shot_shaping_payload_locked(struct pht_flow *flow,
                                                            const struct pht_l4_view *view) {
    lockdep_assert_held(&flow->lock);
    if (!view->payload_len || !flow->one_shot_shaping_rx_pending ||
        ntohl(view->tcp->seq) != flow->one_shot_shaping_rx_seq)
        return false;
    flow->one_shot_shaping_rx_pending = false;
    return true;
}

/* Immediate inbound-data ACK suppression is deliberately a short, local
 * bidirectional burst optimization.  Expire stale timestamps under the flow
 * lock so old local sends cannot re-enter the window after jiffies wrap.
 */
static bool phantun_should_suppress_idle_ack(struct pht_flow *flow) {
    u64 last_tx;
    u64 now;
    unsigned long window;
    u64 deadline;
    bool suppress;

    spin_lock_bh(&flow->lock);
    last_tx = flow->last_established_payload_tx_jiffies;
    suppress = false;
    if (last_tx != 0) {
        now = get_jiffies_64();
        window = flow->table->idle_ack_suppression_window_jiffies;
        deadline = last_tx + window;
        suppress = time_after_eq64(now, last_tx) && time_before64(now, deadline);
        if (!suppress && time_after_eq64(now, deadline))
            flow->last_established_payload_tx_jiffies = 0;
    }
    spin_unlock_bh(&flow->lock);

    return suppress;
}

/* The caller classified a live established generation under this same lock.
 * Oversized payloads must not advance ACK/liveness state or attempt allocation.
 */
static void phantun_prepare_payload_locked(struct pht_flow *flow, const struct pht_l4_view *view,
                                           bool reinject, struct phantun_rx_action *action) {
    lockdep_assert_held(&flow->lock);
    if (view->payload_len && phantun_payload_exceeds_udp_reinject_limit(view)) {
        action->kind = PHT_RX_REJECT_OVERSIZED;
        return;
    }
    action->kind = PHT_RX_DELIVER;
    action->reinject_payload = reinject;
    phantun_refresh_inbound_progress_locked(flow, view);
}

static int phantun_finalize_established_rx(
    struct pht_flow *flow, const struct pht_endpoint_pair *ep, const struct sk_buff *skb,
    const struct pht_l4_view *view, struct net *net, struct net_device *dev,
    const struct phantun_rx_action *action, const struct pht_tx_meta *reply_meta) {
    int ret = 0;

    if (action->reinject_payload) {
        ret = phantun_reinject_inbound_payload(ep, skb, view, net, dev);
        if (ret == -ENOBUFS || ret == -ENOMEM) {
            pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
            pht_stats_inc(PHT_STAT_UDP_REINJECT_FAILED_DROPPED);
            ret = 0;
        } else if (ret) {
            return ret;
        }
    }

    if (view->payload_len) {
        /* The one suppressed hint still requires a prompt pure ACK; recent
         * application output must not suppress this control acknowledgement.
         */
        if (action->reinject_payload && phantun_should_suppress_idle_ack(flow)) {
            pht_stats_inc(PHT_STAT_IDLE_ACKS_SUPPRESSED);
        } else {
            ret = phantun_send_idle_ack(flow, net, reply_meta);
            if (phantun_io_error_is_transient(ret))
                ret = 0;
        }
    }
    return ret;
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

/* UDP GSO superframes reach LOCAL_OUT before software/device segmentation.
 * Split owned UDP_L4 skbs here so each datagram follows the normal fake-TCP
 * translation path and half-open one-skb queue contract independently.
 */
static unsigned int phantun_local_out_segment_gso(void *priv, struct sk_buff *skb,
                                                  const struct nf_hook_state *state) {
    netdev_features_t features = NETIF_F_SG | NETIF_F_IP_CSUM;
    struct sk_buff *segs;
    struct sk_buff *seg;
    struct sk_buff *next;
    long err;

    if (!skb_is_gso(skb))
        return NF_ACCEPT;
    if (!(skb_shinfo(skb)->gso_type & SKB_GSO_UDP_L4)) {
        pht_pr_warn_rl("dropping outbound UDP skb with unexpected gso_type %#x\n",
                       skb_shinfo(skb)->gso_type);
        phantun_account_udp_translation_failure();
        return NF_DROP;
    }
    if (skb->protocol == htons(ETH_P_IPV6))
        features = NETIF_F_SG | NETIF_F_IPV6_CSUM;

    segs = __skb_gso_segment(skb, features, true);
    if (IS_ERR_OR_NULL(segs)) {
        err = IS_ERR(segs) ? PTR_ERR(segs) : -EINVAL;
        pht_pr_warn_rl("failed to segment outbound UDP GSO skb: %ld\n", err);
        phantun_account_udp_translation_failure();
        return NF_DROP;
    }

    consume_skb(skb);

    skb_list_walk_safe(segs, seg, next) {
        unsigned int verdict;

        skb_mark_not_on_list(seg);
        /* LOCAL_OUT consumes owned skbs on every normal path. If a segment
         * escapes that contract, keep ownership here and drop it explicitly.
         */
        verdict = phantun_local_out(priv, seg, state);
        if (verdict != NF_STOLEN) {
            pht_pr_warn_rl("segmented outbound UDP packet unexpectedly escaped fake-TCP handler\n");
            kfree_skb(seg);
        }
    }

    return NF_STOLEN;
}

/* Per-packet LOCAL_OUT translation input. @view borrows the owned UDP skb's
 * headers; @tx_meta is that skb's transmit policy, used for the fake-TCP
 * packets it produces and persisted as the flow's local_tx_meta.
 */
struct phantun_local_out_ctx {
    struct net *net;
    struct pht_flow_table *flows;
    struct pht_l4_view view;
    struct pht_endpoint_pair ep;
    struct pht_tx_meta tx_meta;
};

/* Hand @skb to the live generation using the caller's locked state snapshot.
 * Return it untouched for redispatch if the half-open snapshot became stale;
 * otherwise consume it or transfer it to the handshake queue.
 */
static struct sk_buff *phantun_local_out_live_flow(const struct phantun_local_out_ctx *ctx,
                                                   struct pht_flow *flow, struct sk_buff *skb,
                                                   enum pht_flow_state state_now) {
    enum pht_flow_queue_result queued;
    bool payload_emitted = false;
    int ret;

    if (state_now == PHT_FLOW_STATE_ESTABLISHED) {
        ret = phantun_send_established_udp(flow, &ctx->ep, &ctx->view, skb, &ctx->tx_meta, ctx->net,
                                           true, true, &payload_emitted);
        if (ret && ret != -EMSGSIZE) {
            phantun_account_udp_translation_failure();
            pht_pr_warn_rl("failed to emit fake-TCP payload for established flow: %d\n", ret);
        }
        /* Freeing the original UDP skb after its payload was emitted as
         * fake TCP is consumption, not a drop.
         */
        if (payload_emitted)
            consume_skb(skb);
        else
            kfree_skb(skb);
        return NULL;
    }

    if (!pht_flow_state_is_half_open(state_now)) {
        kfree_skb(skb);
        return NULL;
    }

    queued = pht_flow_queue_half_open_skb(flow, skb, &ctx->tx_meta);
    if (queued == PHT_FLOW_QUEUE_RETRY)
        return skb;
    if (queued == PHT_FLOW_QUEUE_FULL)
        kfree_skb(skb);
    phantun_account_udp_queue_result(queued == PHT_FLOW_QUEUE_QUEUED);
    return NULL;
}

/* Open a SYN_SENT initiator generation whose one-skb queue carries @skb until
 * the handshake completes. @dead_flow, when set, is the hashed DEAD tombstone
 * to replace atomically; it stays owned by the caller. When @has_prev_seq, the
 * new ISN keeps reopen_guard_bytes away from @prev_seq.
 *
 * Returns @skb, still owned by the caller, when another CPU published the
 * tuple first; otherwise consumes @skb and returns NULL.
 */
static struct sk_buff *phantun_local_out_open_initiator(const struct phantun_local_out_ctx *ctx,
                                                        struct sk_buff *skb,
                                                        struct pht_flow *dead_flow, u32 prev_seq,
                                                        bool has_prev_seq) {
    struct pht_flow *new_flow;
    u32 init_seq;
    int ifindex;
    int ret;

    new_flow =
        pht_flow_create(ctx->flows, &ctx->ep, PHT_FLOW_ROLE_INITIATOR, PHT_FLOW_STATE_SYN_SENT);
    if (IS_ERR(new_flow)) {
        phantun_account_udp_translation_failure();
        pht_pr_warn_rl("failed to create initiator flow: %ld\n", PTR_ERR(new_flow));
        kfree_skb(skb);
        return NULL;
    }

    if (!phantun_pick_reopen_isn(prev_seq, has_prev_seq, &init_seq)) {
        phantun_account_udp_translation_failure();
        pht_pr_warn_rl("failed to choose reopen ISN for new flow\n");
        pht_flow_put(new_flow);
        kfree_skb(skb);
        return NULL;
    }

    spin_lock_bh(&new_flow->lock);
    new_flow->seq = init_seq;
    new_flow->ack = 0;
    new_flow->local_isn = init_seq;
    new_flow->peer_syn_next = 0;
    new_flow->local_seq_window_start = new_flow->local_isn;
    new_flow->remote_seq_window_start = new_flow->peer_syn_next;
    new_flow->local_tx_meta = ctx->tx_meta;
    spin_unlock_bh(&new_flow->lock);
    pht_flow_set_queued_skb(new_flow, skb, &ctx->tx_meta);

    if (dead_flow)
        ret = pht_flow_replace_dead(ctx->flows, dead_flow, new_flow);
    else
        ret = pht_flow_insert(ctx->flows, new_flow);
    /* Another CPU won the canonical-tuple race. Reuse its flow instead of
     * creating a parallel generation. new_flow was never published, so its
     * queue still holds @skb.
     */
    if (ret == -EEXIST || (dead_flow && ret == -EAGAIN)) {
        skb = pht_flow_take_queued_skb(new_flow, NULL);
        pht_flow_put(new_flow);
        return skb;
    }
    if (ret) {
        /* -ENOSPC is half-open admission pressure, not a translation failure. */
        if (ret == -ENOSPC)
            pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
        else
            phantun_account_udp_translation_failure();
        pht_pr_warn_rl("failed to insert initiator flow: %d\n", ret);
        /* Freeing the unpublished flow also frees @skb from its queue. */
        pht_flow_put(new_flow);
        return NULL;
    }
    pht_stats_inc(PHT_STAT_UDP_PACKETS_QUEUED);

    ret = pht_emit_fake_tcp(ctx->net, &ctx->ep, init_seq, 0, PHT_TCP_FLAG_SYN, NULL, 0,
                            &ctx->tx_meta, &ifindex);
    if (!ret) {
        pht_flow_set_egress_ifindex(new_flow, ifindex);
    } else {
        pht_pr_warn_rl("failed to emit fake-TCP SYN: %d\n", ret);
        /* Transient local drops leave the SYN to the handshake retransmit timer. */
        if (!phantun_io_error_is_transient(ret)) {
            phantun_account_udp_translation_failure();
            pht_flow_detach(new_flow);
        }
    }
    pht_flow_put(new_flow);
    return NULL;
}

/* Hand one owned UDP datagram to the generation published on its tuple, or
 * publish a new initiator generation for it. Always consumes @skb.
 */
static void phantun_local_out_dispatch(const struct phantun_local_out_ctx *ctx,
                                       struct sk_buff *skb) {
    enum pht_flow_state state_now;
    struct pht_flow *dead_flow;
    struct pht_flow *flow;
    bool has_prev_seq = false;
    u32 prev_seq = 0;

    /* Publish losers and stale half-open queue snapshots retain @skb; look
     * up the current generation and retry without duplicating ownership.
     */
    do {
        dead_flow = NULL;
        flow = pht_flow_lookup(ctx->flows, &ctx->ep);
        if (flow) {
            spin_lock_bh(&flow->lock);
            state_now = flow->state;
            if (state_now == PHT_FLOW_STATE_DEAD)
                prev_seq = flow->seq;
            spin_unlock_bh(&flow->lock);

            if (state_now != PHT_FLOW_STATE_DEAD) {
                skb = phantun_local_out_live_flow(ctx, flow, skb, state_now);
                pht_flow_put(flow);
                continue;
            }

            /* A hashed DEAD flow is only the allocation-failure tombstone
             * from terminal teardown. Keep it visible until the guarded
             * replacement is published, so competing openers always see a
             * previous-generation sequence source or the new live flow.
             */
            has_prev_seq = true;
            dead_flow = flow;
        } else if (!has_prev_seq) {
            has_prev_seq = pht_flow_lookup_retired_seq(ctx->flows, &ctx->ep, &prev_seq);
        }

        skb = phantun_local_out_open_initiator(ctx, skb, dead_flow, prev_seq, has_prev_seq);
        pht_flow_put(dead_flow);
    } while (skb);
}

static bool phantun_outbound_destination_is_nonunicast(const struct sk_buff *skb,
                                                       const struct pht_addr *addr) {
    if (addr->family == AF_INET) {
        const struct rtable *rt = skb_rtable(skb);

        /* The existing output route knows subnet-directed broadcasts; do
         * not infer them from address bits or perform another route lookup.
         */
        return ipv4_is_multicast(addr->v4) || ipv4_is_lbcast(addr->v4) ||
               (rt && (rt->rt_flags & RTCF_BROADCAST));
    }
#if IS_ENABLED(CONFIG_IPV6)
    if (addr->family == AF_INET6)
        return ipv6_addr_is_multicast(&addr->v6);
#endif
    return false;
}

/* LOCAL_OUT owns selector-matched outbound UDP. ESTABLISHED flows send
 * immediately, half-open flows keep only one queued skb, and DEAD flows are
 * reopened from scratch with a guarded ISN.
 */
unsigned int phantun_local_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct phantun_local_out_ctx ctx;
    struct pht_addr remote_addr;
    unsigned int verdict;
    int ret;

    if (!state || !skb)
        return NF_ACCEPT;

    ctx.flows = phantun_net_hook_flows(state->net);
    if (!ctx.flows)
        return NF_ACCEPT;

    ret = phantun_parse_udp_skb(skb, &ctx.view);
    if (ret)
        return NF_ACCEPT;
    if (!phantun_family_enabled(ctx.view.family))
        return NF_ACCEPT;

    if (phantun_local_out_uses_loopback_dev(skb, state))
        return NF_ACCEPT;

    phantun_view_remote_addr(&ctx.view, false, &remote_addr);
    if (!phantun_selectors_allow(ctx.view.udp->source, &remote_addr, ctx.view.udp->dest))
        return NF_ACCEPT;

    if (phantun_outbound_destination_is_nonunicast(skb, &remote_addr)) {
        pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
        pht_pr_warn_rl("rejecting outbound UDP with non-unicast destination\n");
        return NF_DROP;
    }

    ctx.net = state->net;
    phantun_fill_udp_endpoint_pair(&ctx.view, &ctx.ep);
    phantun_fill_endpoint_scope_ifindex(&ctx.ep, state->out ? state->out : skb->dev);
    phantun_tx_meta_from_view(skb, &ctx.view, true, &ctx.tx_meta);
    if (phantun_endpoint_uses_unsupported_addr(&ctx.ep)) {
        pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
        pht_pr_warn_rl("rejecting outbound UDP with unsupported endpoint address\n");
        return NF_DROP;
    }

    verdict = phantun_local_out_segment_gso(priv, skb, state);
    if (verdict != NF_ACCEPT)
        return verdict;

    if (!ctx.view.payload_len) {
        /* Zero-payload fake-TCP ACKs are control/liveness frames, so the
         * current wire protocol has no lossless representation for an empty
         * UDP datagram.
         */
        pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
        kfree_skb(skb);
        return NF_STOLEN;
    }

    ret = phantun_confirm_outbound_udp_conntrack(skb);
    if (ret) {
        phantun_account_udp_translation_failure();
        pht_pr_warn_rl("failed to confirm outbound UDP conntrack before translation: %d\n", ret);
        kfree_skb(skb);
        return NF_STOLEN;
    }

    phantun_local_out_dispatch(&ctx, skb);
    return NF_STOLEN;
}

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
    if (skb->protocol == htons(ETH_P_IPV6))
        features = NETIF_F_SG | NETIF_F_IPV6_CSUM;

    segs = __skb_gso_segment(skb, features, false);
    if (IS_ERR_OR_NULL(segs)) {
        err = IS_ERR(segs) ? PTR_ERR(segs) : -EINVAL;
        pht_pr_warn_rl("failed to segment inbound TCP GRO skb: %ld\n", err);
        return NF_DROP;
    }

    consume_skb(skb);

    skb_list_walk_safe(segs, seg, next) {
        unsigned int verdict;

        skb_mark_not_on_list(seg);
        /* The dispatcher owns NF_STOLEN segments; the loop releases every
         * other verdict exactly once, including unexpected unowned traffic.
         */
        verdict = phantun_pre_routing(priv, seg, state);
        if (verdict == NF_ACCEPT)
            pht_pr_warn_rl("segmented inbound TCP packet unexpectedly escaped fake-TCP handler\n");
        if (verdict != NF_STOLEN)
            kfree_skb(seg);
    }

    return NF_STOLEN;
}

/* The dispatcher has already handled the reinjection exemption and supplied
 * a validated UDP view. Only locally delivered selector-owned UDP is dropped.
 */
static unsigned int phantun_pre_routing_udp_drop(struct sk_buff *skb,
                                                 const struct nf_hook_state *state,
                                                 const struct pht_l4_view *view) {
    struct pht_addr local_addr;
    struct pht_addr remote_addr;

    phantun_view_remote_addr(view, true, &remote_addr);
    /* Reject unmatched traffic before the potentially expensive local FIB
     * lookup, just as on the fake-TCP branch.
     */
    if (!phantun_selectors_allow(view->udp->dest, &remote_addr, view->udp->source))
        return NF_ACCEPT;
    phantun_view_local_addr(view, true, &local_addr);
    if (!phantun_pre_routing_targets_local_host(state->net, &local_addr))
        return NF_ACCEPT;

    if (phantun_addr_pair_uses_unsupported_addr(&local_addr, &remote_addr)) {
        pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
        pht_pr_warn_rl("dropping inbound UDP with unsupported endpoint address\n");
        kfree_skb(skb);
        return NF_STOLEN;
    }

    pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
    pht_stats_inc(PHT_STAT_UDP_RAW_INBOUND_DROPPED);
    kfree_skb(skb);
    return NF_STOLEN;
}

/* Per-packet PRE_ROUTING input shared by the fake-TCP handlers. @skb and
 * @view borrow the hooked packet; @tx_meta is reply-scoped metadata for
 * packets answering it directly and must not be persisted in a flow. Every
 * packet that reaches the handlers ends in NF_DROP, so they only produce side
 * effects.
 */
struct phantun_pre_routing_ctx {
    struct net *net;
    struct net_device *in_dev;
    struct pht_flow_table *flows;
    const struct sk_buff *skb;
    struct pht_l4_view view;
    struct pht_endpoint_pair ep;
    struct pht_tx_meta tx_meta;
};

/* Half-open and control-packet slow paths need a snapshot. Established ACK/data
 * instead commits classification and progress under the initial flow lock.
 * Handshake completion still revalidates its expected state under that lock.
 */
struct phantun_pre_routing_snapshot {
    enum pht_flow_state state;
    enum pht_flow_role role;
    u32 local_isn;
    u32 peer_syn_next;
    bool had_queued;
};

/* Sequence windows of an ESTABLISHED generation displaced by a replacement
 * bare SYN; the new generation quarantines them.
 */
struct phantun_prev_generation {
    u32 local_seq_start;
    u32 local_seq_end;
    u32 remote_seq_start;
    u32 remote_seq_end;
};

static void phantun_pre_routing_send_rstack(const struct phantun_pre_routing_ctx *ctx,
                                            const char *what) {
    int ret = phantun_send_rstack(ctx->net, &ctx->ep, &ctx->view, &ctx->tx_meta);

    if (ret)
        pht_pr_warn_rl("failed to emit RST|ACK for %s: %d\n", what, ret);
}

/* Flush the flow's queued local UDP datagram. On failure, drop anything queued
 * since the flush took its skb and end the generation; returns false then.
 */
static bool phantun_pre_routing_flush_queue(const struct phantun_pre_routing_ctx *ctx,
                                            struct pht_flow *flow) {
    int ret = phantun_flush_queued_udp(flow, ctx->net, NULL);

    if (!ret)
        return true;

    phantun_discard_queued_udp_translation_failure(flow);
    pht_pr_warn_rl("failed to flush responder queue: %d\n", ret);
    pht_flow_remove(flow);
    return false;
}

/* Execute a committed RX decision without holding flow->lock. A concurrent
 * sender can make the immediate application-data ACK unnecessary.
 */
static void phantun_pre_routing_finish_rx(const struct phantun_pre_routing_ctx *ctx,
                                          struct pht_flow *flow,
                                          const struct phantun_rx_action *action,
                                          const char *what) {
    int ret;

    if (action->shaping_dropped)
        pht_stats_inc(PHT_STAT_SHAPING_PAYLOADS_DROPPED);
    switch (action->kind) {
    case PHT_RX_DONE:
        return;
    case PHT_RX_QUARANTINED:
        pht_stats_inc(PHT_STAT_REPLACEMENT_QUARANTINE_DROPPED);
        return;
    case PHT_RX_REJECT_OVERSIZED:
        pht_stats_inc(PHT_STAT_OVERSIZED_PAYLOADS_DROPPED);
        ret = -EMSGSIZE;
        break;
    case PHT_RX_DELIVER:
        ret = phantun_finalize_established_rx(flow, &ctx->ep, ctx->skb, &ctx->view, ctx->net,
                                              ctx->in_dev, action, &ctx->tx_meta);
        if (!ret)
            return;
        break;
    default:
        return;
    }

    pht_pr_warn_rl("failed to process %s: %d\n", what, ret);
    if (ret == -EMSGSIZE) {
        phantun_account_tcp_protocol_rejected();
        phantun_send_rstack(ctx->net, &ctx->ep, &ctx->view, &ctx->tx_meta);
    }
    pht_flow_remove(flow);
}

/* The winning responder completion has already classified its opening shaping
 * slot. Only commit payload progress here, not the ordinary ACK/replay policy.
 */
static void phantun_pre_routing_deliver(const struct phantun_pre_routing_ctx *ctx,
                                        struct pht_flow *flow, bool reinject, const char *what) {
    struct phantun_rx_action action = {.kind = PHT_RX_DONE};

    spin_lock_bh(&flow->lock);
    if (flow->state == PHT_FLOW_STATE_ESTABLISHED)
        phantun_prepare_payload_locked(flow, &ctx->view, reinject, &action);
    spin_unlock_bh(&flow->lock);
    phantun_pre_routing_finish_rx(ctx, flow, &action, what);
}

/* Allocate an unpublished SYN_RCVD responder generation answering the bare
 * SYN in @ctx.
 */
static struct pht_flow *
phantun_pre_routing_new_responder(const struct phantun_pre_routing_ctx *ctx) {
    struct pht_flow *flow;
    u32 responder_seq;

    flow = pht_flow_create(ctx->flows, &ctx->ep, PHT_FLOW_ROLE_RESPONDER, PHT_FLOW_STATE_SYN_RCVD);
    if (IS_ERR(flow))
        return flow;

    responder_seq = get_random_u32();
    spin_lock_bh(&flow->lock);
    flow->seq = responder_seq;
    flow->ack = ntohl(ctx->view.tcp->seq) + 1;
    flow->local_isn = responder_seq;
    flow->peer_syn_next = flow->ack;
    flow->local_seq_window_start = flow->local_isn;
    flow->remote_seq_window_start = flow->peer_syn_next;
    spin_unlock_bh(&flow->lock);
    return flow;
}

/* Publish a responder generation for the bare aligned SYN in @ctx and answer
 * it with SYN|ACK. @dead_flow, when set, is a hashed DEAD tombstone to replace
 * atomically. @prev, when set, describes the ESTABLISHED generation this SYN
 * just displaced. Both stay owned by the caller.
 */
static void phantun_pre_routing_accept_syn(const struct phantun_pre_routing_ctx *ctx,
                                           struct pht_flow *dead_flow,
                                           const struct phantun_prev_generation *prev) {
    struct pht_flow *new_flow;
    int ret;

    new_flow = phantun_pre_routing_new_responder(ctx);
    if (IS_ERR(new_flow)) {
        pht_pr_warn_rl("failed to create responder flow: %ld\n", PTR_ERR(new_flow));
        return;
    }
    if (prev)
        phantun_flow_arm_prev_generation_quarantine(new_flow, prev->local_seq_start,
                                                    prev->local_seq_end, prev->remote_seq_start,
                                                    prev->remote_seq_end);

    if (dead_flow)
        ret = pht_flow_replace_dead(ctx->flows, dead_flow, new_flow);
    else
        ret = pht_flow_insert(ctx->flows, new_flow);
    if (ret) {
        pht_flow_put(new_flow);
        return;
    }

    ret = phantun_send_synack(new_flow, ctx->net, &ctx->tx_meta);
    if (ret) {
        pht_pr_warn_rl("failed to emit SYN|ACK: %d\n", ret);
        /* Transient local drops leave SYN|ACK to the handshake retransmit timer. */
        if (!phantun_io_error_is_transient(ret))
            pht_flow_detach(new_flow);
    } else if (prev) {
        pht_stats_inc(PHT_STAT_REPLACEMENTS_ACCEPTED);
    }
    pht_flow_put(new_flow);
}

/* No live generation owns the tuple: there is no flow, or only a hashed DEAD
 * tombstone (@dead_flow, borrowed) kept as the previous-sequence source. Only
 * a bare aligned SYN may create responder state; RST is dropped silently and
 * anything else is answered with RST|ACK.
 */
static void phantun_pre_routing_unknown_tuple(const struct phantun_pre_routing_ctx *ctx,
                                              struct pht_flow *dead_flow) {
    if (ctx->view.tcp->rst)
        return;

    if (!phantun_tcp_is_bare_syn(&ctx->view)) {
        phantun_account_tcp_unknown_tuple_rejected();
        phantun_pre_routing_send_rstack(ctx, "unknown packet");
        return;
    }

    if (!phantun_tcp_syn_is_aligned(&ctx->view)) {
        phantun_account_tcp_misaligned_syn_rejected();
        phantun_pre_routing_send_rstack(ctx, "misaligned SYN");
        return;
    }

    phantun_pre_routing_accept_syn(ctx, dead_flow, NULL);
}

/* Simultaneous open lost on ISN tie-break: retire this SYN_SENT generation
 * and answer the peer's SYN as responder. The queued first datagram moves to
 * the new generation together with its exact metadata.
 */
static void phantun_pre_routing_yield_initiator(const struct phantun_pre_routing_ctx *ctx,
                                                struct pht_flow *flow) {
    struct pht_flow *new_flow;
    int ret;

    new_flow = phantun_pre_routing_new_responder(ctx);
    if (IS_ERR(new_flow))
        return;

    ret = pht_flow_yield_initiator(ctx->flows, flow, new_flow);
    if (ret) {
        pht_flow_put(new_flow);
        return;
    }
    pht_pr_info_rl("collision on tuple; switching to responder role\n");
    pht_stats_inc(PHT_STAT_COLLISIONS_LOST);

    ret = phantun_send_synack(new_flow, ctx->net, &ctx->tx_meta);
    if (ret) {
        pht_pr_warn_rl("failed to emit SYN|ACK after collision handoff: %d\n", ret);
        if (!phantun_io_error_is_transient(ret))
            pht_flow_detach(new_flow);
    }
    pht_flow_put(new_flow);
}

/* Bare SYN while SYN_SENT: both ends opened the tuple at once. The lower ISN
 * keeps the initiator role.
 */
static void phantun_pre_routing_collision(const struct phantun_pre_routing_ctx *ctx,
                                          struct pht_flow *flow,
                                          const struct phantun_pre_routing_snapshot *snap) {
    u32 peer_isn;

    if (!phantun_tcp_syn_is_aligned(&ctx->view)) {
        phantun_account_tcp_misaligned_syn_rejected();
        phantun_pre_routing_send_rstack(ctx, "misaligned colliding SYN");
        return;
    }

    peer_isn = ntohl(ctx->view.tcp->seq);
    /* Exact match is extremely rare. Drop to resolve via timeout. */
    if (snap->local_isn == peer_isn)
        return;

    if (snap->local_isn < peer_isn) {
        pht_pr_info_rl("collision on tuple; keeping initiator role\n");
        pht_flow_touch_inbound(flow);
        pht_stats_inc(PHT_STAT_COLLISIONS_WON);
        return;
    }

    phantun_pre_routing_yield_initiator(ctx, flow);
}

/* Matching SYN|ACK: complete SYN_SENT, inject the optional handshake_request,
 * and release the queued first datagram. A bare final ACK is sent only when
 * neither the request nor flushed queued payload carries it.
 */
static void
phantun_pre_routing_complete_initiator(const struct phantun_pre_routing_ctx *ctx,
                                       struct pht_flow *flow,
                                       const struct phantun_pre_routing_snapshot *snap) {
    const u32 ack = ntohl(ctx->view.tcp->seq) + 1;
    struct pht_flow_handshake_complete_args complete_args = {
        .expected_state = PHT_FLOW_STATE_SYN_SENT,
        .local_seq_start = snap->local_isn + 1,
        .ack = ack,
        .peer_syn_next = ack,
        .remote_payload_seq = ntohl(ctx->view.tcp->seq),
        .remote_payload_len = ctx->view.payload_len,
        .local_control_len = phantun_request_enabled() ? phantun_cfg.handshake_request_len : 0,
        .reserve_one_shot_shaping_rx = phantun_response_enabled(),
    };
    enum pht_flow_complete_result complete;
    bool flushed_payload = false;
    int ret;

    complete = pht_flow_complete_handshake(flow, &complete_args, NULL);
    if (complete == PHT_FLOW_COMPLETE_STALE)
        return;
    if (complete == PHT_FLOW_COMPLETE_ALREADY_ESTABLISHED) {
        ret = phantun_send_idle_ack(flow, ctx->net, &ctx->tx_meta);
        if (ret)
            pht_pr_warn_rl("failed to ACK duplicate SYN|ACK: %d\n", ret);
        return;
    }

    pht_flow_touch_inbound(flow);
    if (phantun_request_enabled()) {
        ret = phantun_send_handshake_request(flow, ctx->net);
        if (ret) {
            pht_pr_warn_rl("failed to emit handshake request: %d\n", ret);
            if (!phantun_io_error_is_transient(ret)) {
                pht_flow_remove(flow);
                return;
            }
        }
    }

    ret = phantun_flush_queued_udp(flow, ctx->net, &flushed_payload);
    if (!ret && !phantun_request_enabled() && (!snap->had_queued || !flushed_payload)) {
        ret = phantun_send_idle_ack(flow, ctx->net, &ctx->tx_meta);
        if (phantun_io_error_is_transient(ret))
            ret = 0;
    }
    if (ret) {
        phantun_discard_queued_udp_translation_failure(flow);
        pht_pr_warn_rl("failed to finalize initiator open: %d\n", ret);
        pht_flow_remove(flow);
    }
}

/* Initiator half-open state: exact completion wins over stale ACK/data.
 * Ordinary ACK-shaped traffic is silently ignored without touching the queue,
 * retry budget or lifetime. Other unexpected controls retain strict rejection.
 */
static void phantun_pre_routing_syn_sent(const struct phantun_pre_routing_ctx *ctx,
                                         struct pht_flow *flow,
                                         const struct phantun_pre_routing_snapshot *snap) {
    if (phantun_tcp_is_bare_syn(&ctx->view)) {
        phantun_pre_routing_collision(ctx, flow, snap);
        return;
    }

    if (phantun_tcp_is_clean_synack(&ctx->view, snap->local_isn + 1)) {
        phantun_pre_routing_complete_initiator(ctx, flow, snap);
        return;
    }

    if (phantun_flow_should_drop_quarantined_packet(flow, &ctx->view) ||
        phantun_tcp_is_established_ack(&ctx->view))
        return;

    phantun_account_tcp_protocol_rejected();
    phantun_pre_routing_send_rstack(ctx, "unexpected SYN_SENT packet");
    pht_flow_remove(flow);
}

/* Commit ACK/data classification and progress in one critical section. The
 * handshake loser uses the same transaction but retains final-ACK replay
 * suppression and its existing bypass of previous-generation quarantine.
 * False means the generation is no longer established; no state was changed.
 */
static bool phantun_prepare_established_data_locked(struct pht_flow *flow,
                                                    const struct pht_l4_view *view,
                                                    bool raced_final_ack,
                                                    struct phantun_rx_action *action) {
    bool raced_replay = false;

    lockdep_assert_held(&flow->lock);
    if (flow->state != PHT_FLOW_STATE_ESTABLISHED)
        return false;
    *action = (struct phantun_rx_action){.kind = PHT_RX_DONE};
    if (!raced_final_ack && phantun_flow_should_drop_quarantined_packet_locked(flow, view)) {
        action->kind = PHT_RX_QUARANTINED;
        return true;
    }
    action->shaping_dropped = phantun_consume_one_shot_shaping_payload_locked(flow, view);
    if (raced_final_ack && view->payload_len > 0) {
        u32 payload_seq = ntohl(view->tcp->seq);
        u32 payload_end = payload_seq + view->payload_len;

        raced_replay =
            (flow->opening_rx_payload_claimed && payload_seq == flow->opening_rx_seq_start &&
             payload_end == flow->opening_rx_seq_end) ||
            phantun_seq_after_eq(flow->ack, payload_end);
    }
    if (raced_replay && !action->shaping_dropped)
        return true;
    if (!view->payload_len) {
        pht_flow_touch_inbound_locked(flow);
        return true;
    }

    phantun_prepare_payload_locked(flow, view, !action->shaping_dropped, action);
    return true;
}

/* Exact final ACK in SYN_RCVD: reserve optional response sequence space,
 * emit that hint, release queued UDP, and deliver the final ACK's payload.
 * Neither a response ACK nor another client datagram is required.
 */
static void
phantun_pre_routing_complete_responder(const struct phantun_pre_routing_ctx *ctx,
                                       struct pht_flow *flow,
                                       const struct phantun_pre_routing_snapshot *snap) {
    struct pht_flow_handshake_complete_args complete_args = {
        .expected_state = PHT_FLOW_STATE_SYN_RCVD,
        .local_seq_start = snap->local_isn + 1,
        .ack = snap->peer_syn_next,
        .peer_syn_next = snap->peer_syn_next,
        .remote_payload_seq = ntohl(ctx->view.tcp->seq),
        .remote_payload_len = ctx->view.payload_len,
        .local_control_len = phantun_response_enabled() ? phantun_cfg.handshake_response_len : 0,
        .reserve_one_shot_shaping_rx = phantun_request_enabled(),
    };
    enum pht_flow_complete_result complete;
    bool drop_open_payload;
    int ret;

    complete = pht_flow_complete_handshake(flow, &complete_args, &drop_open_payload);
    if (complete == PHT_FLOW_COMPLETE_STALE)
        return;
    if (complete == PHT_FLOW_COMPLETE_ALREADY_ESTABLISHED) {
        struct phantun_rx_action action;
        bool prepared;

        /* Recheck under the commit lock in case this generation was detached
         * after handshake completion reported the winner on another CPU.
         */
        spin_lock_bh(&flow->lock);
        prepared = phantun_prepare_established_data_locked(flow, &ctx->view, true, &action);
        spin_unlock_bh(&flow->lock);
        if (prepared)
            phantun_pre_routing_finish_rx(ctx, flow, &action, "raced responder payload");
        return;
    }

    if (drop_open_payload) {
        phantun_note_inbound_payload(flow, &ctx->view);
        pht_stats_inc(PHT_STAT_SHAPING_PAYLOADS_DROPPED);
    }

    if (phantun_response_enabled()) {
        /* Completion reserved this range before publishing ESTABLISHED.
         * Losing the optional output cannot block ordinary UDP.
         */
        ret = phantun_send_handshake_response(flow, ctx->net, &ctx->tx_meta);
        if (ret) {
            pht_pr_warn_rl("failed to emit handshake response: %d\n", ret);
            if (!phantun_io_error_is_transient(ret)) {
                pht_flow_remove(flow);
                return;
            }
        }
    }

    pht_flow_touch_inbound(flow);

    /* This is the only responder queue flush: stale LOCAL_OUT snapshots retry
     * rather than enqueue after this point.
     */
    if (!phantun_pre_routing_flush_queue(ctx, flow))
        return;

    if (ctx->view.payload_len == 0)
        return;

    phantun_pre_routing_deliver(ctx, flow, !drop_open_payload, "responder open payload");
}

/* Responder half-open state: duplicate SYN retransmits SYN|ACK, and only
 * the exact final ACK can complete the handshake.
 */
static void phantun_pre_routing_syn_rcvd(const struct phantun_pre_routing_ctx *ctx,
                                         struct pht_flow *flow,
                                         const struct phantun_pre_routing_snapshot *snap) {
    const struct pht_l4_view *view = &ctx->view;
    int ret;

    if (phantun_tcp_is_bare_syn(view) && phantun_tcp_syn_is_aligned(view) &&
        ntohl(view->tcp->seq) + 1 == snap->peer_syn_next) {
        ret = phantun_send_synack(flow, ctx->net, &ctx->tx_meta);
        if (ret)
            pht_pr_warn_rl("failed to re-emit SYN|ACK: %d\n", ret);
        return;
    }

    if (phantun_tcp_is_syn_rcvd_final_ack(view, snap->local_isn + 1)) {
        phantun_pre_routing_complete_responder(ctx, flow, snap);
        return;
    }

    if (phantun_flow_should_drop_quarantined_packet(flow, view))
        return;

    if (phantun_tcp_is_established_ack(view))
        return;

    if (phantun_tcp_is_bare_syn(view) && !phantun_tcp_syn_is_aligned(view)) {
        phantun_account_tcp_misaligned_syn_rejected();
        phantun_pre_routing_send_rstack(ctx, "misaligned SYN_RCVD SYN");
    } else {
        phantun_account_tcp_protocol_rejected();
        phantun_pre_routing_send_rstack(ctx, "bad final ACK");
    }
    pht_flow_remove(flow);
}

/* SYN on an ESTABLISHED tuple: retransmitted opening segments of this
 * generation are answered again, a bare aligned SYN outside replacement
 * protection opens a new responder generation, and any other SYN is fatal.
 */
static void phantun_pre_routing_established_syn(const struct phantun_pre_routing_ctx *ctx,
                                                struct pht_flow *flow,
                                                const struct phantun_pre_routing_snapshot *snap) {
    const struct pht_l4_view *view = &ctx->view;
    struct phantun_prev_generation prev;
    int ret;

    if (snap->role == PHT_FLOW_ROLE_INITIATOR &&
        phantun_tcp_is_clean_synack(view, snap->local_isn + 1) &&
        ntohl(view->tcp->seq) + 1 == snap->peer_syn_next) {
        ret = phantun_send_idle_ack(flow, ctx->net, &ctx->tx_meta);
        if (ret)
            pht_pr_warn_rl("failed to ACK duplicate current-generation SYN|ACK: %d\n", ret);
        return;
    }

    if (!phantun_tcp_is_bare_syn(view) || !phantun_tcp_syn_is_aligned(view)) {
        pht_pr_warn_rl("received invalid SYN on ESTABLISHED tuple, destroying\n");
        if (phantun_tcp_is_bare_syn(view))
            phantun_account_tcp_misaligned_syn_rejected();
        else
            phantun_account_tcp_protocol_rejected();
        phantun_pre_routing_send_rstack(ctx, "invalid established SYN");
        pht_flow_remove(flow);
        return;
    }

    if (snap->role == PHT_FLOW_ROLE_RESPONDER && ntohl(view->tcp->seq) + 1 == snap->peer_syn_next) {
        ret = phantun_send_synack(flow, ctx->net, &ctx->tx_meta);
        if (ret)
            pht_pr_warn_rl("failed to re-emit SYN|ACK for duplicate established SYN: %d\n", ret);
        return;
    }

    if (phantun_flow_should_drop_protected_replacement_syn(flow, view))
        return;

    /* Accept bare replacement SYN as a new generation. Preserve only the
     * just-replaced seq/ack window so delayed old packets are dropped quietly
     * during the quarantine window.
     */
    spin_lock_bh(&flow->lock);
    prev.local_seq_start = flow->local_seq_window_start;
    prev.local_seq_end = flow->seq;
    prev.remote_seq_start = flow->remote_seq_window_start;
    prev.remote_seq_end = flow->ack;
    spin_unlock_bh(&flow->lock);
    pht_pr_info_rl("received bare SYN on ESTABLISHED tuple, replacing generation\n");
    kfree_skb(pht_flow_take_queued_skb(flow, NULL));
    pht_flow_detach(flow);
    phantun_pre_routing_accept_syn(ctx, NULL, &prev);
}

/* Classify an owned packet against the flow hashed on its tuple. @flow is
 * borrowed; the hook drops the lookup reference.
 */
static void phantun_pre_routing_dispatch(const struct phantun_pre_routing_ctx *ctx,
                                         struct pht_flow *flow) {
    struct phantun_pre_routing_snapshot snap;
    struct phantun_rx_action action;
    bool quarantined = false;

    spin_lock_bh(&flow->lock);
    if (phantun_tcp_is_established_ack(&ctx->view) &&
        phantun_prepare_established_data_locked(flow, &ctx->view, false, &action)) {
        spin_unlock_bh(&flow->lock);
        phantun_pre_routing_finish_rx(ctx, flow, &action, "established inbound payload");
        return;
    }
    snap.state = flow->state;
    snap.role = flow->role;
    snap.local_isn = flow->local_isn;
    snap.peer_syn_next = flow->peer_syn_next;
    snap.had_queued = flow->queued_skb != NULL;
    if (snap.state == PHT_FLOW_STATE_ESTABLISHED)
        quarantined = phantun_flow_should_drop_quarantined_packet_locked(flow, &ctx->view);
    spin_unlock_bh(&flow->lock);
    if (quarantined) {
        pht_stats_inc(PHT_STAT_REPLACEMENT_QUARANTINE_DROPPED);
        return;
    }

    /* Allocation-failure tombstone: keep it hashed as the previous sequence
     * source unless this packet publishes a replacement SYN.
     */
    if (snap.state == PHT_FLOW_STATE_DEAD) {
        phantun_pre_routing_unknown_tuple(ctx, flow);
        return;
    }

    /* RST ends a live generation unless it fits the quarantined previous one. */
    if (ctx->view.tcp->rst) {
        if (snap.state == PHT_FLOW_STATE_ESTABLISHED ||
            !phantun_flow_should_drop_quarantined_packet(flow, &ctx->view))
            pht_flow_remove(flow);
        return;
    }

    switch (snap.state) {
    case PHT_FLOW_STATE_SYN_SENT:
        phantun_pre_routing_syn_sent(ctx, flow, &snap);
        break;
    case PHT_FLOW_STATE_SYN_RCVD:
        phantun_pre_routing_syn_rcvd(ctx, flow, &snap);
        break;
    case PHT_FLOW_STATE_ESTABLISHED:
        /* Valid ACK/data already committed above. The remaining established
         * packets are SYN controls or unsupported flags; RST was handled first.
         */
        if (ctx->view.tcp->syn) {
            phantun_pre_routing_established_syn(ctx, flow, &snap);
        } else {
            phantun_account_tcp_protocol_rejected();
            phantun_pre_routing_send_rstack(ctx, "unsupported established flags");
            pht_flow_remove(flow);
        }
        break;
    default:
        break;
    }
}

/* Parse ingress once, then enforce raw-UDP ownership or process fake TCP
 * before the real transport stack sees it. A private mark exempts UDP only;
 * an externally marked TCP packet must still pass fake-TCP validation.
 */
unsigned int phantun_pre_routing(void *priv, struct sk_buff *skb,
                                 const struct nf_hook_state *state) {
    struct phantun_pre_routing_ctx ctx;
    struct pht_addr local_addr;
    struct pht_addr remote_addr;
    struct pht_flow *flow;
    unsigned int verdict;
    bool reinjected;
    int ret;

    if (!state || !skb)
        return NF_ACCEPT;

    ctx.flows = phantun_net_hook_flows(state->net);
    /* Fail open if hook state exists before the flow table is attached;
     * NF_DROP here would blackhole every inbound non-loopback packet.
     */
    if (!ctx.flows)
        return NF_ACCEPT;

    reinjected = skb->mark == ctx.flows->reinject_mark;
    if (reinjected)
        skb->mark = 0;
    if (phantun_pre_routing_uses_loopback_dev(skb, state))
        return NF_ACCEPT;

    /* Netfilter selected the family before invoking this hook; do not infer
     * it again from skb metadata or probe an unrelated IP parser.
     */
    switch (state->pf) {
    case NFPROTO_IPV4:
        ret = pht_parse_ipv4_transport(skb, &ctx.view);
        break;
    case NFPROTO_IPV6:
        ret = pht_parse_ipv6_transport(skb, &ctx.view);
        break;
    default:
        return NF_ACCEPT;
    }
    if (ret)
        return NF_ACCEPT;
    if (!phantun_family_enabled(ctx.view.family))
        return NF_ACCEPT;
    if (ctx.view.protocol == IPPROTO_UDP)
        return reinjected ? NF_ACCEPT : phantun_pre_routing_udp_drop(skb, state, &ctx.view);

    phantun_view_remote_addr(&ctx.view, true, &remote_addr);
    /* Selector matching is cheap cached config; test it before local-delivery
     * checks that may require a FIB lookup.
     */
    if (!phantun_selectors_allow(ctx.view.tcp->dest, &remote_addr, ctx.view.tcp->source))
        return NF_ACCEPT;

    phantun_view_local_addr(&ctx.view, true, &local_addr);
    if (!phantun_pre_routing_targets_local_host(state->net, &local_addr))
        return NF_ACCEPT;

    ctx.net = state->net;
    ctx.in_dev = state->in ? state->in : skb->dev;
    ctx.skb = skb;
    phantun_fill_tcp_endpoint_pair(&ctx.view, &ctx.ep);
    phantun_fill_endpoint_scope_ifindex(&ctx.ep, ctx.in_dev);
    phantun_tx_meta_from_view(skb, &ctx.view, false, &ctx.tx_meta);
    if (phantun_endpoint_uses_unsupported_addr(&ctx.ep)) {
        pht_pr_warn_rl("rejecting inbound fake-TCP with unsupported endpoint address\n");
        return NF_DROP;
    }

    /* From here the packet is owned and cannot resume normal IPv6 extension
     * processing. Supply the TCP offset expected by segmentation helpers.
     */
    skb_set_transport_header(skb, ctx.view.ip_hdr_len);
    verdict = phantun_pre_routing_segment_gso(priv, skb, state);
    if (verdict != NF_ACCEPT)
        return verdict;

    ret = phantun_validate_tcp_checksums(skb, &ctx.view);
    if (ret)
        return NF_DROP;

    /* Owned fake TCP never reaches the TCP stack: payload leaves as a freshly
     * built UDP skb, so every path from here drops the original. Handlers
     * borrow the lookup reference.
     */
    flow = pht_flow_lookup(ctx.flows, &ctx.ep);
    if (flow) {
        phantun_pre_routing_dispatch(&ctx, flow);
        pht_flow_put(flow);
    } else {
        phantun_pre_routing_unknown_tuple(&ctx, NULL);
    }
    return NF_DROP;
}

static int __init phantun_init(void) {
    int ret;

    pht_pr_info(PHANTUN_MODULE_NAME " %s loaded\n", PACKAGE_VERSION);

    ret = phantun_config_init();
    if (ret)
        return ret;

    pht_stats_reset();
    ret = pht_stats_init_sysfs();
    if (ret)
        goto err_config;

    ret = phantun_netns_init();
    if (ret)
        goto err_sysfs;
    return 0;

err_sysfs:
    pht_stats_exit_sysfs();
err_config:
    phantun_config_exit();
    return ret;
}

static void __exit phantun_exit(void) {
    phantun_netns_exit();
    pht_stats_exit_sysfs();
    phantun_config_exit();
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
