// SPDX-License-Identifier: GPL-2.0-or-later
//
// Copyright (C) 2026 Bin Jin. All Rights Reserved.
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/if_ether.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/uidgid.h>

#include <net/dst.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/tcp.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <net/ip6_checksum.h>
#include <net/ip6_route.h>
#include <net/ipv6.h>
#endif

#include "phantun_compat.h" // IWYU pragma: keep
#include "phantun_packet.h"
#include "phantun_stats.h"

unsigned int pht_fake_tcp_max_payload_len(u8 family) {
    switch (family) {
    case AF_INET:
        return PHT_V4_MAX_TCP_PAYLOAD_LEN;
#if IS_ENABLED(CONFIG_IPV6)
    case AF_INET6:
        return PHT_V6_MAX_TCP_PAYLOAD_LEN;
#endif
    default:
        return 0;
    }
}

unsigned int pht_udp_max_payload_len(u8 family) {
    switch (family) {
    case AF_INET:
        return PHT_V4_MAX_UDP_PAYLOAD_LEN;
#if IS_ENABLED(CONFIG_IPV6)
    case AF_INET6:
        return PHT_V6_MAX_UDP_PAYLOAD_LEN;
#endif
    default:
        return 0;
    }
}

void pht_tx_meta_init(struct pht_tx_meta *meta) {
    if (!meta)
        return;

    memset(meta, 0, sizeof(*meta));
    meta->uid = GLOBAL_ROOT_UID;
}

static u32 pht_tx_meta_mark(const struct pht_tx_meta *meta) { return meta ? meta->mark : 0; }

static u32 pht_tx_meta_priority(const struct pht_tx_meta *meta) {
    return meta ? meta->priority : 0;
}

static int pht_tx_meta_oif(const struct pht_tx_meta *meta) { return meta ? meta->oif : 0; }

static kuid_t pht_tx_meta_uid(const struct pht_tx_meta *meta) {
    return meta ? meta->uid : GLOBAL_ROOT_UID;
}

static void pht_tx_meta_apply_skb(struct sk_buff *skb, const struct pht_tx_meta *meta) {
    if (!skb)
        return;

    skb->mark = pht_tx_meta_mark(meta);
    skb->priority = pht_tx_meta_priority(meta);
}

static void pht_tx_meta_apply_ipv4_header(struct sk_buff *skb, const struct pht_tx_meta *meta) {
    struct iphdr *iph;

    if (!skb || !meta)
        return;

    iph = ip_hdr(skb);
    if (!iph || iph->tos == meta->v4_tos)
        return;

    iph->tos = meta->v4_tos;
    iph->check = 0;
    ip_send_check(iph);
}

#if IS_ENABLED(CONFIG_IPV6)

static void pht_tx_meta_apply_ipv6_header(struct sk_buff *skb, const struct pht_tx_meta *meta) {
    struct ipv6hdr *ip6h;

    if (!skb || !meta)
        return;

    ip6h = ipv6_hdr(skb);
    if (!ip6h)
        return;

    ip6h->priority = meta->v6_priority & 0x0f;
    memcpy(ip6h->flow_lbl, meta->v6_flow_lbl, sizeof(ip6h->flow_lbl));
}
#endif

static bool pht_tx_addr_equal(const struct pht_addr *a, const struct pht_addr *b) {
    if (!a || !b || a->family != b->family)
        return false;

    switch (a->family) {
    case AF_INET:
        return a->v4 == b->v4;
    case AF_INET6:
        return !memcmp(&a->v6, &b->v6, sizeof(a->v6));
    default:
        return false;
    }
}

int pht_tx_route_key_init(struct pht_tx_route_key *key, const struct pht_endpoint_pair *ep,
                          const struct pht_tx_meta *meta) {
    if (!key || !ep)
        return -EINVAL;
    if (ep->local_addr.family != ep->remote_addr.family)
        return -EINVAL;

    memset(key, 0, sizeof(*key));
    key->family = ep->local_addr.family;
    key->local_addr = ep->local_addr;
    key->remote_addr = ep->remote_addr;
    key->local_port = ep->local_port;
    key->remote_port = ep->remote_port;
    key->scope_ifindex = ep->scope_ifindex;
    key->mark = pht_tx_meta_mark(meta);
    key->oif = pht_tx_meta_oif(meta);
    key->uid = pht_tx_meta_uid(meta);

    switch (key->family) {
    case AF_INET:
        key->v4_tos = meta ? meta->v4_tos : 0;
        return 0;
#if IS_ENABLED(CONFIG_IPV6)
    case AF_INET6:
        if (meta) {
            key->v6.priority = meta->v6_priority;
            memcpy(key->v6.flow_lbl, meta->v6_flow_lbl, sizeof(key->v6.flow_lbl));
        }
        return 0;
#endif
    default:
        return -EAFNOSUPPORT;
    }
}

bool pht_tx_route_key_equal(const struct pht_tx_route_key *a, const struct pht_tx_route_key *b) {
    if (!a || !b)
        return false;
    if (a->family != b->family || a->local_port != b->local_port ||
        a->remote_port != b->remote_port || a->scope_ifindex != b->scope_ifindex ||
        a->mark != b->mark || a->oif != b->oif || !uid_eq(a->uid, b->uid) ||
        !pht_tx_addr_equal(&a->local_addr, &b->local_addr) ||
        !pht_tx_addr_equal(&a->remote_addr, &b->remote_addr))
        return false;

    switch (a->family) {
    case AF_INET:
        return a->v4_tos == b->v4_tos;
    case AF_INET6:
        return a->v6.priority == b->v6.priority &&
               !memcmp(a->v6.flow_lbl, b->v6.flow_lbl, sizeof(a->v6.flow_lbl));
    default:
        return false;
    }
}

static int pht_tx_fake_tcp_route_v4(struct net *net, const struct pht_tx_route_key *key,
                                    struct pht_tx_route_result *route) {
    struct flowi4 fl4;
    struct rtable *rt;

    if (!net || !key || !route || key->family != AF_INET)
        return -EINVAL;

    memset(route, 0, sizeof(*route));
    memset(&fl4, 0, sizeof(fl4));
    flowi4_init_output(&fl4, key->oif, key->mark, key->v4_tos, RT_SCOPE_UNIVERSE, IPPROTO_TCP, 0,
                       key->remote_addr.v4, key->local_addr.v4, key->remote_port, key->local_port,
                       key->uid);
    rt = ip_route_output_key(net, &fl4);
    if (IS_ERR(rt))
        return PTR_ERR(rt);

    route->dst = &rt->dst;
    route->cookie = 0;
    route->ifindex = rt->dst.dev ? rt->dst.dev->ifindex : 0;
    return 0;
}

#if IS_ENABLED(CONFIG_IPV6)
static __be32 pht_tx_route_key_v6_flowlabel(const struct pht_tx_route_key *key) {
    if (!key)
        return 0;

    return htonl(((u32)(key->v6.priority & 0x0f) << 24) | ((u32)key->v6.flow_lbl[0] << 16) |
                 ((u32)key->v6.flow_lbl[1] << 8) | key->v6.flow_lbl[2]) &
           IPV6_FLOWINFO_MASK;
}

static int pht_tx_fake_tcp_route_v6(struct net *net, const struct pht_tx_route_key *key,
                                    struct pht_tx_route_result *route) {
    struct flowi6 fl6;
    struct dst_entry *dst;
    int ret;

    if (!net || !key || !route || key->family != AF_INET6)
        return -EINVAL;

    memset(route, 0, sizeof(*route));
    memset(&fl6, 0, sizeof(fl6));
    fl6.flowi6_proto = IPPROTO_TCP;
    fl6.flowi6_oif = key->oif ? key->oif : key->scope_ifindex;
    fl6.flowi6_mark = key->mark;
    fl6.flowi6_uid = key->uid;
    fl6.flowlabel = pht_tx_route_key_v6_flowlabel(key);
    fl6.daddr = key->remote_addr.v6;
    fl6.saddr = key->local_addr.v6;
    fl6.fl6_dport = key->remote_port;
    fl6.fl6_sport = key->local_port;

    dst = ip6_route_output(net, NULL, &fl6);
    ret = dst->error;
    if (ret) {
        dst_release(dst);
        return ret;
    }

    route->dst = dst;
    route->cookie = rt6_get_cookie(dst_rt6_info(dst));
    route->ifindex = dst->dev ? dst->dev->ifindex : 0;
    return 0;
}
#else
static int pht_tx_fake_tcp_route_v6(struct net *net, const struct pht_tx_route_key *key,
                                    struct pht_tx_route_result *route) {
    return -EAFNOSUPPORT;
}
#endif

int pht_tx_fake_tcp_route(struct net *net, const struct pht_tx_route_key *key,
                          struct pht_tx_route_result *route) {
    if (!key)
        return -EINVAL;

    switch (key->family) {
    case AF_INET:
        return pht_tx_fake_tcp_route_v4(net, key, route);
    case AF_INET6:
        return pht_tx_fake_tcp_route_v6(net, key, route);
    default:
        return -EAFNOSUPPORT;
    }
}

int pht_tx_fake_tcp_with_dst(struct net *net, struct sk_buff *skb, u8 family,
                             struct dst_entry *dst) {
    int ret;

    if (!net || !skb || !dst) {
        dst_release(dst);
        kfree_skb(skb);
        return -EINVAL;
    }

    skb_dst_set(skb, dst);
    skb->dev = dst->dev;
    switch (family) {
    case AF_INET:
        skb->protocol = htons(ETH_P_IP);
        ret = ip_local_out(net, NULL, skb);
        return net_xmit_eval(ret);
#if IS_ENABLED(CONFIG_IPV6)
    case AF_INET6:
        skb->protocol = htons(ETH_P_IPV6);
        ret = ip6_local_out(net, NULL, skb);
        return net_xmit_eval(ret);
#endif
    default:
        kfree_skb(skb);
        return -EAFNOSUPPORT;
    }
}

static int pht_tx_apply_fake_tcp_meta(struct sk_buff *skb, u8 family,
                                      const struct pht_tx_meta *meta) {
    switch (family) {
    case AF_INET:
        pht_tx_meta_apply_ipv4_header(skb, meta);
        break;
#if IS_ENABLED(CONFIG_IPV6)
    case AF_INET6:
        pht_tx_meta_apply_ipv6_header(skb, meta);
        break;
#endif
    default:
        return -EAFNOSUPPORT;
    }

    pht_tx_meta_apply_skb(skb, meta);
    return 0;
}

static int pht_parse_ipv4_l4(struct sk_buff *skb, u8 protocol, unsigned int min_l4_len,
                             struct pht_l4_view *view) {
    struct iphdr *iph;
    unsigned int ip_hdr_len;
    unsigned int total_len;

    if (!skb || !view)
        return -EINVAL;

    memset(view, 0, sizeof(*view));

    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return -EINVAL;

    iph = ip_hdr(skb);
    if (!iph || iph->version != 4 || iph->ihl < 5)
        return -EINVAL;

    ip_hdr_len = iph->ihl * 4;
    if (!pskb_may_pull(skb, ip_hdr_len + min_l4_len))
        return -EINVAL;

    iph = ip_hdr(skb);
    total_len = ntohs(iph->tot_len);
    if (iph->protocol != protocol)
        return -EPROTO;
    if (iph->frag_off & htons(IP_MF | IP_OFFSET))
        return -EINVAL;
    if (skb->len < total_len || total_len < ip_hdr_len + min_l4_len)
        return -EINVAL;

    skb_set_transport_header(skb, ip_hdr_len);
    view->iph = iph;
    view->family = AF_INET;
    view->ip_hdr_len = ip_hdr_len;
    return 0;
}

int pht_parse_ipv4_udp(struct sk_buff *skb, struct pht_l4_view *view) {
    struct iphdr *iph;
    struct udphdr *uh;
    unsigned int udp_len;
    int ret;

    ret = pht_parse_ipv4_l4(skb, IPPROTO_UDP, sizeof(struct udphdr), view);
    if (ret)
        return ret;

    iph = view->iph;
    uh = udp_hdr(skb);
    udp_len = ntohs(uh->len);
    if (udp_len < sizeof(*uh) || view->ip_hdr_len + udp_len > ntohs(iph->tot_len))
        return -EINVAL;

    view->udp = uh;
    view->l4_hdr_len = sizeof(*uh);
    view->payload_offset = view->ip_hdr_len + sizeof(*uh);
    view->payload_len = udp_len - sizeof(*uh);
    return 0;
}

int pht_parse_ipv4_tcp(struct sk_buff *skb, struct pht_l4_view *view) {
    struct iphdr *iph;
    struct tcphdr *th;
    unsigned int tcp_len;
    unsigned int total_len;
    int ret;

    ret = pht_parse_ipv4_l4(skb, IPPROTO_TCP, sizeof(struct tcphdr), view);
    if (ret)
        return ret;

    iph = view->iph;
    th = tcp_hdr(skb);
    tcp_len = th->doff * 4;
    total_len = ntohs(iph->tot_len);
    if (tcp_len < sizeof(*th))
        return -EINVAL;
    if (!pskb_may_pull(skb, view->ip_hdr_len + tcp_len))
        return -EINVAL;

    iph = ip_hdr(skb);
    th = tcp_hdr(skb);
    total_len = ntohs(iph->tot_len);
    if (view->ip_hdr_len + tcp_len > total_len)
        return -EINVAL;

    view->iph = iph;
    view->tcp = th;
    view->l4_hdr_len = tcp_len;
    view->payload_offset = view->ip_hdr_len + tcp_len;
    view->payload_len = total_len - view->payload_offset;
    return 0;
}

int pht_validate_ipv4_tcp_checksums(const struct sk_buff *skb, const struct pht_l4_view *view) {
    unsigned int ip_tot_len, tcp_len;
    __wsum csum;

    if (!skb || !view || !view->iph || !view->tcp)
        return -EINVAL;

    /*
     * Skip software TCP checksum verification if the stack/NIC has already
     * validated the checksum for this packet.
     *
     * CHECKSUM_PARTIAL is accepted here only for plain outer IPv4/TCP packets,
     * where the skb checksum state is known to refer to this TCP header.
     */
    if (skb_csum_unnecessary(skb) || skb->ip_summed == CHECKSUM_PARTIAL)
        return 0;

    ip_tot_len = ntohs(view->iph->tot_len);
    if (ip_tot_len < view->ip_hdr_len || ip_tot_len > skb->len) {
        pht_stats_inc(PHT_STAT_BAD_CHECKSUM_DROPPED);
        return -EBADMSG;
    }

    tcp_len = ip_tot_len - view->ip_hdr_len;
    csum = skb_checksum(skb, view->ip_hdr_len, tcp_len, 0);
    if (tcp_v4_check(tcp_len, view->iph->saddr, view->iph->daddr, csum)) {
        pht_stats_inc(PHT_STAT_BAD_CHECKSUM_DROPPED);
        return -EBADMSG;
    }
    return 0;
}

#if IS_ENABLED(CONFIG_IPV6)
static int pht_parse_ipv6_l4(struct sk_buff *skb, u8 protocol, unsigned int min_l4_len,
                             struct pht_l4_view *view) {
    struct ipv6hdr *ip6h;
    unsigned int total_len;
    int offset = sizeof(struct ipv6hdr);
    unsigned short frag_off = 0;
    int flags = 0;
    int nexthdr;

    if (!skb || !view)
        return -EINVAL;

    memset(view, 0, sizeof(*view));

    if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
        return -EINVAL;

    ip6h = ipv6_hdr(skb);
    if (!ip6h || ip6h->version != 6)
        return -EINVAL;

    total_len = sizeof(*ip6h) + ntohs(ip6h->payload_len);
    if (skb->len < total_len || total_len < sizeof(*ip6h) + min_l4_len)
        return -EINVAL;

    if (ip6h->nexthdr == protocol) {
        nexthdr = protocol;
    } else {
        nexthdr = ipv6_find_hdr(skb, &offset, protocol, &frag_off, &flags);
        if (nexthdr < 0)
            return nexthdr;
        if (nexthdr != protocol)
            return -EPROTO;
        if (flags & IP6_FH_F_FRAG)
            return -EINVAL;
    }
    if (offset < sizeof(*ip6h) || !pskb_may_pull(skb, offset + min_l4_len))
        return -EINVAL;

    ip6h = ipv6_hdr(skb);
    skb_set_transport_header(skb, offset);
    view->ip6h = ip6h;
    view->family = AF_INET6;
    view->ip_hdr_len = offset;
    return 0;
}

int pht_parse_ipv6_udp(struct sk_buff *skb, struct pht_l4_view *view) {
    struct udphdr *uh;
    unsigned int udp_len;
    unsigned int total_len;
    int ret;

    ret = pht_parse_ipv6_l4(skb, IPPROTO_UDP, sizeof(struct udphdr), view);
    if (ret)
        return ret;

    uh = udp_hdr(skb);
    udp_len = ntohs(uh->len);
    total_len = sizeof(*view->ip6h) + ntohs(view->ip6h->payload_len);
    if (udp_len < sizeof(*uh) || view->ip_hdr_len + udp_len > total_len)
        return -EINVAL;

    view->udp = uh;
    view->l4_hdr_len = sizeof(*uh);
    view->payload_offset = view->ip_hdr_len + sizeof(*uh);
    view->payload_len = udp_len - sizeof(*uh);
    return 0;
}

int pht_parse_ipv6_tcp(struct sk_buff *skb, struct pht_l4_view *view) {
    struct tcphdr *th;
    unsigned int tcp_len;
    unsigned int total_len;
    int ret;

    ret = pht_parse_ipv6_l4(skb, IPPROTO_TCP, sizeof(struct tcphdr), view);
    if (ret)
        return ret;

    th = tcp_hdr(skb);
    tcp_len = th->doff * 4;
    if (tcp_len < sizeof(*th))
        return -EINVAL;
    if (!pskb_may_pull(skb, view->ip_hdr_len + tcp_len))
        return -EINVAL;

    th = tcp_hdr(skb);
    view->ip6h = ipv6_hdr(skb);
    total_len = sizeof(*view->ip6h) + ntohs(view->ip6h->payload_len);
    if (view->ip_hdr_len + tcp_len > total_len)
        return -EINVAL;

    view->tcp = th;
    view->l4_hdr_len = tcp_len;
    view->payload_offset = view->ip_hdr_len + tcp_len;
    view->payload_len = total_len - view->payload_offset;
    return 0;
}

int pht_validate_ipv6_tcp_checksums(const struct sk_buff *skb, const struct pht_l4_view *view) {
    unsigned int total_len, tcp_len;
    __wsum csum;

    if (!skb || !view || !view->ip6h || !view->tcp)
        return -EINVAL;

    if (skb_csum_unnecessary(skb) || skb->ip_summed == CHECKSUM_PARTIAL)
        return 0;

    total_len = sizeof(*view->ip6h) + ntohs(view->ip6h->payload_len);
    if (total_len < view->ip_hdr_len || total_len > skb->len) {
        pht_stats_inc(PHT_STAT_BAD_CHECKSUM_DROPPED);
        return -EBADMSG;
    }

    tcp_len = total_len - view->ip_hdr_len;
    csum = skb_checksum(skb, view->ip_hdr_len, tcp_len, 0);
    if (tcp_v6_check(tcp_len, &view->ip6h->saddr, &view->ip6h->daddr, csum)) {
        pht_stats_inc(PHT_STAT_BAD_CHECKSUM_DROPPED);
        return -EBADMSG;
    }
    return 0;
}
#else
int pht_parse_ipv6_udp(struct sk_buff *skb, struct pht_l4_view *view) { return -EAFNOSUPPORT; }

int pht_parse_ipv6_tcp(struct sk_buff *skb, struct pht_l4_view *view) { return -EAFNOSUPPORT; }

int pht_validate_ipv6_tcp_checksums(const struct sk_buff *skb, const struct pht_l4_view *view) {
    return -EAFNOSUPPORT;
}
#endif

int pht_copy_l4_payload(const struct sk_buff *skb, const struct pht_l4_view *view, void *dst,
                        size_t dst_len) {
    if (!skb || !view)
        return -EINVAL;
    if (!view->payload_len)
        return 0;
    if (!dst)
        return -EINVAL;
    if (dst_len < view->payload_len)
        return -EMSGSIZE;

    return skb_copy_bits(skb, view->payload_offset, dst, view->payload_len);
}

void pht_ipv4_complete(struct iphdr *iph, u16 total_len, u8 protocol, __be32 saddr, __be32 daddr) {
    memset(iph, 0, sizeof(*iph));
    iph->version = 4;
    iph->ihl = sizeof(*iph) / 4;
    iph->ttl = PHT_V4_DEFAULT_TTL;
    iph->protocol = protocol;
    iph->frag_off = htons(IP_DF);
    iph->tot_len = htons(total_len);
    iph->saddr = saddr;
    iph->daddr = daddr;
    ip_send_check(iph);
}

void pht_tcp_v4_complete(struct iphdr *iph, struct tcphdr *th, u16 tcp_len) {
    th->check = 0;
    th->check = tcp_v4_check(tcp_len, iph->saddr, iph->daddr, csum_partial(th, tcp_len, 0));
}

void pht_udp_v4_complete(struct iphdr *iph, struct udphdr *uh, u16 udp_len) {
    uh->check = 0;
    uh->check = csum_tcpudp_magic(iph->saddr, iph->daddr, udp_len, IPPROTO_UDP,
                                  csum_partial(uh, udp_len, 0));
    if (!uh->check)
        uh->check = CSUM_MANGLED_0;
}

static struct sk_buff *pht_alloc_l3_skb(unsigned int l4_len, size_t payload_len) {
    unsigned int max_payload;
    unsigned int total_len;
    struct sk_buff *skb;

    if (l4_len > PHT_V4_MAX_PACKET_LEN - sizeof(struct iphdr))
        return NULL;
    max_payload = PHT_V4_MAX_PACKET_LEN - sizeof(struct iphdr) - l4_len;
    if (payload_len > max_payload)
        return NULL;

    total_len = sizeof(struct iphdr) + l4_len + (unsigned int)payload_len;
    skb = alloc_skb(LL_MAX_HEADER + total_len, GFP_ATOMIC);
    if (!skb)
        return NULL;

    skb_reserve(skb, LL_MAX_HEADER);
    skb_reset_mac_header(skb);
    skb_reset_network_header(skb);
    skb_put(skb, total_len);
    memset(skb->data, 0, total_len);
    skb_set_transport_header(skb, sizeof(struct iphdr));
    skb->protocol = htons(ETH_P_IP);
    skb->ip_summed = CHECKSUM_NONE;
    return skb;
}

static void pht_fake_tcp_v4_complete_skb(struct sk_buff *skb) {
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *th = tcp_hdr(skb);
    u16 tcp_len = ntohs(iph->tot_len) - iph->ihl * 4;

    pht_tcp_v4_complete(iph, th, tcp_len);
}

struct sk_buff *pht_build_fake_tcp_v4_uninit(const struct pht_endpoint_pair *ep, u32 seq, u32 ack,
                                             u8 flags, size_t payload_len, void **payload_ptr) {
    struct sk_buff *skb;
    struct iphdr *iph;
    struct tcphdr *th;
    u8 *payload;
    u8 *opt;
    unsigned int tcp_hdr_len;
    unsigned int tcp_len;
    bool add_wscale;

    if (payload_ptr)
        *payload_ptr = NULL;
    if (!ep)
        return NULL;
    if (ep->local_addr.family != AF_INET || ep->remote_addr.family != AF_INET)
        return NULL;
    if (payload_len > pht_fake_tcp_max_payload_len(AF_INET))
        return NULL;

    add_wscale = !!(flags & PHT_TCP_FLAG_SYN);
    tcp_hdr_len = sizeof(*th) + (add_wscale ? 4 : 0);
    tcp_len = tcp_hdr_len + payload_len;
    skb = pht_alloc_l3_skb(tcp_hdr_len, payload_len);
    if (!skb)
        return NULL;

    iph = ip_hdr(skb);
    th = tcp_hdr(skb);
    payload = skb_transport_header(skb) + tcp_hdr_len;

    pht_ipv4_complete(iph, sizeof(*iph) + tcp_len, IPPROTO_TCP, ep->local_addr.v4,
                      ep->remote_addr.v4);

    th->source = ep->local_port;
    th->dest = ep->remote_port;
    th->seq = htonl(seq);
    th->ack_seq = htonl(ack);
    th->doff = tcp_hdr_len / 4;
    th->window = htons(PHT_TCP_DEFAULT_WINDOW);
    th->fin = !!(flags & PHT_TCP_FLAG_FIN);
    th->syn = !!(flags & PHT_TCP_FLAG_SYN);
    th->rst = !!(flags & PHT_TCP_FLAG_RST);
    th->psh = !!(flags & PHT_TCP_FLAG_PSH);
    th->ack = !!(flags & PHT_TCP_FLAG_ACK);
    th->urg = !!(flags & PHT_TCP_FLAG_URG);

    if (add_wscale) {
        opt = (u8 *)(th + 1);
        opt[0] = TCPOPT_NOP;
        opt[1] = TCPOPT_WINDOW;
        opt[2] = TCPOLEN_WINDOW;
        opt[3] = PHT_TCP_WINDOW_SCALE;
    }

    if (payload_ptr)
        *payload_ptr = payload;
    return skb;
}

struct sk_buff *pht_build_fake_tcp_v4(const struct pht_endpoint_pair *ep, u32 seq, u32 ack,
                                      u8 flags, const void *payload, size_t payload_len) {
    struct sk_buff *skb;
    void *payload_ptr;

    if (payload_len && !payload)
        return NULL;

    skb = pht_build_fake_tcp_v4_uninit(ep, seq, ack, flags, payload_len, &payload_ptr);
    if (!skb)
        return NULL;

    if (payload_len)
        memcpy(payload_ptr, payload, payload_len);

    pht_fake_tcp_v4_complete_skb(skb);
    return skb;
}

struct sk_buff *pht_build_fake_tcp_syn_v4(const struct pht_endpoint_pair *ep, u32 seq) {
    return pht_build_fake_tcp_v4(ep, seq, 0, PHT_TCP_FLAG_SYN, NULL, 0);
}

struct sk_buff *pht_build_fake_tcp_synack_v4(const struct pht_endpoint_pair *ep, u32 seq, u32 ack) {
    return pht_build_fake_tcp_v4(ep, seq, ack, PHT_TCP_FLAG_SYN | PHT_TCP_FLAG_ACK, NULL, 0);
}

struct sk_buff *pht_build_fake_tcp_ack_v4(const struct pht_endpoint_pair *ep, u32 seq, u32 ack) {
    return pht_build_fake_tcp_v4(ep, seq, ack, PHT_TCP_FLAG_ACK, NULL, 0);
}

struct sk_buff *pht_build_fake_tcp_ack_payload_v4(const struct pht_endpoint_pair *ep, u32 seq,
                                                  u32 ack, const void *payload,
                                                  size_t payload_len) {
    return pht_build_fake_tcp_v4(ep, seq, ack, PHT_TCP_FLAG_ACK, payload, payload_len);
}

struct sk_buff *pht_build_fake_tcp_rst_v4(const struct pht_endpoint_pair *ep, u32 seq) {
    return pht_build_fake_tcp_v4(ep, seq, 0, PHT_TCP_FLAG_RST, NULL, 0);
}

struct sk_buff *pht_build_fake_tcp_rstack_v4(const struct pht_endpoint_pair *ep, u32 seq, u32 ack) {
    return pht_build_fake_tcp_v4(ep, seq, ack, PHT_TCP_FLAG_RST | PHT_TCP_FLAG_ACK, NULL, 0);
}

static void pht_udp_v4_complete_skb(struct sk_buff *skb) {
    struct iphdr *iph = ip_hdr(skb);
    struct udphdr *uh = udp_hdr(skb);

    pht_udp_v4_complete(iph, uh, ntohs(uh->len));
    skb->ip_summed = CHECKSUM_UNNECESSARY;
}

struct sk_buff *pht_build_udp_v4_uninit(const struct pht_endpoint_pair *ep, size_t payload_len,
                                        void **payload_ptr) {
    struct sk_buff *skb;
    struct iphdr *iph;
    struct udphdr *uh;
    void *payload;
    unsigned int udp_len;

    if (payload_ptr)
        *payload_ptr = NULL;
    if (!ep)
        return NULL;
    if (ep->local_addr.family != AF_INET || ep->remote_addr.family != AF_INET)
        return NULL;
    if (payload_len > pht_udp_max_payload_len(AF_INET))
        return NULL;

    udp_len = sizeof(*uh) + payload_len;
    skb = pht_alloc_l3_skb(sizeof(*uh), payload_len);
    if (!skb)
        return NULL;

    iph = ip_hdr(skb);
    uh = udp_hdr(skb);
    payload = skb_transport_header(skb) + sizeof(*uh);

    pht_ipv4_complete(iph, sizeof(*iph) + udp_len, IPPROTO_UDP, ep->remote_addr.v4,
                      ep->local_addr.v4);

    uh->source = ep->remote_port;
    uh->dest = ep->local_port;
    uh->len = htons(udp_len);

    if (payload_ptr)
        *payload_ptr = payload;
    return skb;
}

struct sk_buff *pht_build_udp_v4(const struct pht_endpoint_pair *ep, const void *payload,
                                 size_t payload_len) {
    struct sk_buff *skb;
    void *payload_ptr;

    if (payload_len && !payload)
        return NULL;

    skb = pht_build_udp_v4_uninit(ep, payload_len, &payload_ptr);
    if (!skb)
        return NULL;

    if (payload_len)
        memcpy(payload_ptr, payload, payload_len);

    pht_udp_v4_complete_skb(skb);
    return skb;
}

int pht_tx_fake_tcp_v4(struct net *net, struct sk_buff *skb, const struct pht_endpoint_pair *ep,
                       const struct pht_tx_meta *meta, int *out_ifindex) {
    struct pht_tx_route_key key;
    struct pht_tx_route_result route;
    int ret;

    if (out_ifindex)
        *out_ifindex = 0;

    if (!net || !skb || !ep) {
        kfree_skb(skb);
        return -EINVAL;
    }
    if (ep->local_addr.family != AF_INET || ep->remote_addr.family != AF_INET) {
        kfree_skb(skb);
        return -EINVAL;
    }

    pht_tx_meta_apply_ipv4_header(skb, meta);
    pht_tx_meta_apply_skb(skb, meta);

    ret = pht_tx_route_key_init(&key, ep, meta);
    if (ret) {
        kfree_skb(skb);
        return ret;
    }

    ret = pht_tx_fake_tcp_route(net, &key, &route);
    if (ret) {
        kfree_skb(skb);
        return ret;
    }

    if (out_ifindex)
        *out_ifindex = route.ifindex;
    return pht_tx_fake_tcp_with_dst(net, skb, AF_INET, route.dst);
}

int pht_emit_fake_tcp_v4(struct net *net, const struct pht_endpoint_pair *ep, u32 seq, u32 ack,
                         u8 flags, const void *payload, size_t payload_len,
                         const struct pht_tx_meta *meta, int *out_ifindex) {
    struct sk_buff *skb;

    if (payload_len > pht_fake_tcp_max_payload_len(AF_INET))
        return -EMSGSIZE;

    skb = pht_build_fake_tcp_v4(ep, seq, ack, flags, payload, payload_len);
    if (!skb)
        return -ENOMEM;

    return pht_tx_fake_tcp_v4(net, skb, ep, meta, out_ifindex);
}

int pht_reinject_udp_v4(struct sk_buff *skb, struct net_device *dev, u32 reinject_mark) {
    int ret;

    if (!skb || !dev || !reinject_mark) {
        kfree_skb(skb);
        return -EINVAL;
    }

    /* Re-enter through ingress so conntrack and LOCAL_IN firewall policy see
     * the packet exactly as a real receive. The PRE_ROUTING UDP drop hook
     * clears the table-private reinjection mark and skips re-capturing this
     * manufactured skb.
     */
    skb->mark = reinject_mark;
    skb->dev = dev;
    skb->skb_iif = dev->ifindex;
    skb->pkt_type = PACKET_HOST;
    skb->protocol = htons(ETH_P_IP);

    ret = netif_rx(skb);
    return ret == NET_RX_DROP ? -ENOBUFS : 0;
}

int pht_reinject_udp_payload_v4(struct net_device *dev, const struct pht_endpoint_pair *ep,
                                const void *payload, size_t payload_len, u32 reinject_mark) {
    struct sk_buff *skb;

    if (payload_len > pht_udp_max_payload_len(AF_INET))
        return -EMSGSIZE;

    skb = pht_build_udp_v4(ep, payload, payload_len);
    if (!skb)
        return -ENOMEM;

    return pht_reinject_udp_v4(skb, dev, reinject_mark);
}

int pht_reinject_udp_payload_from_skb_v4(struct net_device *dev, const struct pht_endpoint_pair *ep,
                                         const struct sk_buff *src, unsigned int payload_offset,
                                         size_t payload_len, u32 reinject_mark) {
    struct sk_buff *skb;
    void *payload;
    int ret;

    if (payload_len > pht_udp_max_payload_len(AF_INET))
        return -EMSGSIZE;
    if (payload_len && !src)
        return -EINVAL;

    skb = pht_build_udp_v4_uninit(ep, payload_len, &payload);
    if (!skb)
        return -ENOMEM;

    if (payload_len) {
        ret = skb_copy_bits(src, payload_offset, payload, (int)payload_len);
        if (ret) {
            kfree_skb(skb);
            return ret;
        }
    }

    pht_udp_v4_complete_skb(skb);
    return pht_reinject_udp_v4(skb, dev, reinject_mark);
}

#if IS_ENABLED(CONFIG_IPV6)
void pht_ipv6_complete(struct ipv6hdr *ip6h, u16 payload_len, u8 nexthdr,
                       const struct in6_addr *saddr, const struct in6_addr *daddr) {
    memset(ip6h, 0, sizeof(*ip6h));
    ip6h->version = 6;
    ip6h->payload_len = htons(payload_len);
    ip6h->nexthdr = nexthdr;
    ip6h->hop_limit = PHT_V6_DEFAULT_HOP_LIMIT;
    ip6h->saddr = *saddr;
    ip6h->daddr = *daddr;
}

void pht_tcp_v6_complete(struct ipv6hdr *ip6h, struct tcphdr *th, u16 tcp_len) {
    th->check = 0;
    th->check = tcp_v6_check(tcp_len, &ip6h->saddr, &ip6h->daddr, csum_partial(th, tcp_len, 0));
}

void pht_udp_v6_complete(struct ipv6hdr *ip6h, struct udphdr *uh, u16 udp_len) {
    uh->check = 0;
    uh->check = udp_v6_check(udp_len, &ip6h->saddr, &ip6h->daddr, csum_partial(uh, udp_len, 0));
    if (!uh->check)
        uh->check = CSUM_MANGLED_0;
}

static struct sk_buff *pht_alloc_l3_skb_v6(unsigned int l4_len, size_t payload_len) {
    unsigned int max_payload;
    unsigned int total_len;
    struct sk_buff *skb;

    if (l4_len > PHT_V6_MAX_PACKET_LEN - sizeof(struct ipv6hdr))
        return NULL;
    max_payload = PHT_V6_MAX_PACKET_LEN - sizeof(struct ipv6hdr) - l4_len;
    if (payload_len > max_payload)
        return NULL;

    total_len = sizeof(struct ipv6hdr) + l4_len + (unsigned int)payload_len;
    skb = alloc_skb(LL_MAX_HEADER + total_len, GFP_ATOMIC);
    if (!skb)
        return NULL;

    skb_reserve(skb, LL_MAX_HEADER);
    skb_reset_mac_header(skb);
    skb_reset_network_header(skb);
    skb_put(skb, total_len);
    memset(skb->data, 0, total_len);
    skb_set_transport_header(skb, sizeof(struct ipv6hdr));
    skb->protocol = htons(ETH_P_IPV6);
    skb->ip_summed = CHECKSUM_NONE;
    return skb;
}

static void pht_fake_tcp_v6_complete_skb(struct sk_buff *skb) {
    struct ipv6hdr *ip6h = ipv6_hdr(skb);
    struct tcphdr *th = tcp_hdr(skb);

    pht_tcp_v6_complete(ip6h, th, ntohs(ip6h->payload_len));
}

struct sk_buff *pht_build_fake_tcp_v6_uninit(const struct pht_endpoint_pair *ep, u32 seq, u32 ack,
                                             u8 flags, size_t payload_len, void **payload_ptr) {
    struct sk_buff *skb;
    struct ipv6hdr *ip6h;
    struct tcphdr *th;
    u8 *payload;
    u8 *opt;
    unsigned int tcp_hdr_len;
    unsigned int tcp_len;
    bool add_wscale;

    if (payload_ptr)
        *payload_ptr = NULL;
    if (!ep)
        return NULL;
    if (ep->local_addr.family != AF_INET6 || ep->remote_addr.family != AF_INET6)
        return NULL;
    if (payload_len > pht_fake_tcp_max_payload_len(AF_INET6))
        return NULL;

    add_wscale = !!(flags & PHT_TCP_FLAG_SYN);
    tcp_hdr_len = sizeof(*th) + (add_wscale ? 4 : 0);
    tcp_len = tcp_hdr_len + payload_len;
    skb = pht_alloc_l3_skb_v6(tcp_hdr_len, payload_len);
    if (!skb)
        return NULL;

    ip6h = ipv6_hdr(skb);
    th = tcp_hdr(skb);
    payload = skb_transport_header(skb) + tcp_hdr_len;

    pht_ipv6_complete(ip6h, tcp_len, IPPROTO_TCP, &ep->local_addr.v6, &ep->remote_addr.v6);

    th->source = ep->local_port;
    th->dest = ep->remote_port;
    th->seq = htonl(seq);
    th->ack_seq = htonl(ack);
    th->doff = tcp_hdr_len / 4;
    th->window = htons(PHT_TCP_DEFAULT_WINDOW);
    th->fin = !!(flags & PHT_TCP_FLAG_FIN);
    th->syn = !!(flags & PHT_TCP_FLAG_SYN);
    th->rst = !!(flags & PHT_TCP_FLAG_RST);
    th->psh = !!(flags & PHT_TCP_FLAG_PSH);
    th->ack = !!(flags & PHT_TCP_FLAG_ACK);
    th->urg = !!(flags & PHT_TCP_FLAG_URG);

    if (add_wscale) {
        opt = (u8 *)(th + 1);
        opt[0] = TCPOPT_NOP;
        opt[1] = TCPOPT_WINDOW;
        opt[2] = TCPOLEN_WINDOW;
        opt[3] = PHT_TCP_WINDOW_SCALE;
    }

    if (payload_ptr)
        *payload_ptr = payload;
    return skb;
}

struct sk_buff *pht_build_fake_tcp_v6(const struct pht_endpoint_pair *ep, u32 seq, u32 ack,
                                      u8 flags, const void *payload, size_t payload_len) {
    struct sk_buff *skb;
    void *payload_ptr;

    if (payload_len && !payload)
        return NULL;

    skb = pht_build_fake_tcp_v6_uninit(ep, seq, ack, flags, payload_len, &payload_ptr);
    if (!skb)
        return NULL;

    if (payload_len)
        memcpy(payload_ptr, payload, payload_len);

    pht_fake_tcp_v6_complete_skb(skb);
    return skb;
}

static void pht_udp_v6_complete_skb(struct sk_buff *skb) {
    struct ipv6hdr *ip6h = ipv6_hdr(skb);
    struct udphdr *uh = udp_hdr(skb);

    pht_udp_v6_complete(ip6h, uh, ntohs(uh->len));
    skb->ip_summed = CHECKSUM_UNNECESSARY;
}

struct sk_buff *pht_build_udp_v6_uninit(const struct pht_endpoint_pair *ep, size_t payload_len,
                                        void **payload_ptr) {
    struct sk_buff *skb;
    struct ipv6hdr *ip6h;
    struct udphdr *uh;
    void *payload;
    unsigned int udp_len;

    if (payload_ptr)
        *payload_ptr = NULL;
    if (!ep)
        return NULL;
    if (ep->local_addr.family != AF_INET6 || ep->remote_addr.family != AF_INET6)
        return NULL;
    if (payload_len > pht_udp_max_payload_len(AF_INET6))
        return NULL;

    udp_len = sizeof(*uh) + payload_len;
    skb = pht_alloc_l3_skb_v6(sizeof(*uh), payload_len);
    if (!skb)
        return NULL;

    ip6h = ipv6_hdr(skb);
    uh = udp_hdr(skb);
    payload = skb_transport_header(skb) + sizeof(*uh);

    pht_ipv6_complete(ip6h, udp_len, IPPROTO_UDP, &ep->remote_addr.v6, &ep->local_addr.v6);

    uh->source = ep->remote_port;
    uh->dest = ep->local_port;
    uh->len = htons(udp_len);

    if (payload_ptr)
        *payload_ptr = payload;
    return skb;
}

struct sk_buff *pht_build_udp_v6(const struct pht_endpoint_pair *ep, const void *payload,
                                 size_t payload_len) {
    struct sk_buff *skb;
    void *payload_ptr;

    if (payload_len && !payload)
        return NULL;

    skb = pht_build_udp_v6_uninit(ep, payload_len, &payload_ptr);
    if (!skb)
        return NULL;

    if (payload_len)
        memcpy(payload_ptr, payload, payload_len);

    pht_udp_v6_complete_skb(skb);
    return skb;
}

int pht_tx_fake_tcp_v6(struct net *net, struct sk_buff *skb, const struct pht_endpoint_pair *ep,
                       const struct pht_tx_meta *meta, int *out_ifindex) {
    struct pht_tx_route_key key;
    struct pht_tx_route_result route;
    int ret;

    if (out_ifindex)
        *out_ifindex = 0;

    if (!net || !skb || !ep) {
        kfree_skb(skb);
        return -EINVAL;
    }
    if (ep->local_addr.family != AF_INET6 || ep->remote_addr.family != AF_INET6) {
        kfree_skb(skb);
        return -EINVAL;
    }

    pht_tx_meta_apply_ipv6_header(skb, meta);
    pht_tx_meta_apply_skb(skb, meta);

    ret = pht_tx_route_key_init(&key, ep, meta);
    if (ret) {
        kfree_skb(skb);
        return ret;
    }

    ret = pht_tx_fake_tcp_route(net, &key, &route);
    if (ret) {
        kfree_skb(skb);
        return ret;
    }

    if (out_ifindex)
        *out_ifindex = route.ifindex;
    return pht_tx_fake_tcp_with_dst(net, skb, AF_INET6, route.dst);
}

int pht_emit_fake_tcp_v6(struct net *net, const struct pht_endpoint_pair *ep, u32 seq, u32 ack,
                         u8 flags, const void *payload, size_t payload_len,
                         const struct pht_tx_meta *meta, int *out_ifindex) {
    struct sk_buff *skb;

    if (payload_len > pht_fake_tcp_max_payload_len(AF_INET6))
        return -EMSGSIZE;

    skb = pht_build_fake_tcp_v6(ep, seq, ack, flags, payload, payload_len);
    if (!skb)
        return -ENOMEM;

    return pht_tx_fake_tcp_v6(net, skb, ep, meta, out_ifindex);
}

int pht_reinject_udp_v6(struct sk_buff *skb, struct net_device *dev, u32 reinject_mark) {
    int ret;

    if (!skb || !dev || !reinject_mark) {
        kfree_skb(skb);
        return -EINVAL;
    }

    skb->mark = reinject_mark;
    skb->dev = dev;
    skb->skb_iif = dev->ifindex;
    skb->pkt_type = PACKET_HOST;
    skb->protocol = htons(ETH_P_IPV6);

    ret = netif_rx(skb);
    return ret == NET_RX_DROP ? -ENOBUFS : 0;
}

int pht_reinject_udp_payload_v6(struct net_device *dev, const struct pht_endpoint_pair *ep,
                                const void *payload, size_t payload_len, u32 reinject_mark) {
    struct sk_buff *skb;

    if (payload_len > pht_udp_max_payload_len(AF_INET6))
        return -EMSGSIZE;

    skb = pht_build_udp_v6(ep, payload, payload_len);
    if (!skb)
        return -ENOMEM;

    return pht_reinject_udp_v6(skb, dev, reinject_mark);
}

int pht_reinject_udp_payload_from_skb_v6(struct net_device *dev, const struct pht_endpoint_pair *ep,
                                         const struct sk_buff *src, unsigned int payload_offset,
                                         size_t payload_len, u32 reinject_mark) {
    struct sk_buff *skb;
    void *payload;
    int ret;

    if (payload_len > pht_udp_max_payload_len(AF_INET6))
        return -EMSGSIZE;
    if (payload_len && !src)
        return -EINVAL;

    skb = pht_build_udp_v6_uninit(ep, payload_len, &payload);
    if (!skb)
        return -ENOMEM;

    if (payload_len) {
        ret = skb_copy_bits(src, payload_offset, payload, (int)payload_len);
        if (ret) {
            kfree_skb(skb);
            return ret;
        }
    }

    pht_udp_v6_complete_skb(skb);
    return pht_reinject_udp_v6(skb, dev, reinject_mark);
}
#else
void pht_ipv6_complete(struct ipv6hdr *ip6h, u16 payload_len, u8 nexthdr,
                       const struct in6_addr *saddr, const struct in6_addr *daddr) {}

void pht_tcp_v6_complete(struct ipv6hdr *ip6h, struct tcphdr *th, u16 tcp_len) {}

void pht_udp_v6_complete(struct ipv6hdr *ip6h, struct udphdr *uh, u16 udp_len) {}

struct sk_buff *pht_build_fake_tcp_v6(const struct pht_endpoint_pair *ep, u32 seq, u32 ack,
                                      u8 flags, const void *payload, size_t payload_len) {
    return NULL;
}

struct sk_buff *pht_build_fake_tcp_v6_uninit(const struct pht_endpoint_pair *ep, u32 seq, u32 ack,
                                             u8 flags, size_t payload_len, void **payload_ptr) {
    if (payload_ptr)
        *payload_ptr = NULL;
    return NULL;
}

struct sk_buff *pht_build_udp_v6(const struct pht_endpoint_pair *ep, const void *payload,
                                 size_t payload_len) {
    return NULL;
}

struct sk_buff *pht_build_udp_v6_uninit(const struct pht_endpoint_pair *ep, size_t payload_len,
                                        void **payload_ptr) {
    if (payload_ptr)
        *payload_ptr = NULL;
    return NULL;
}

int pht_tx_fake_tcp_v6(struct net *net, struct sk_buff *skb, const struct pht_endpoint_pair *ep,
                       const struct pht_tx_meta *meta, int *out_ifindex) {
    kfree_skb(skb);
    return -EAFNOSUPPORT;
}

int pht_emit_fake_tcp_v6(struct net *net, const struct pht_endpoint_pair *ep, u32 seq, u32 ack,
                         u8 flags, const void *payload, size_t payload_len,
                         const struct pht_tx_meta *meta, int *out_ifindex) {
    return -EAFNOSUPPORT;
}

int pht_reinject_udp_v6(struct sk_buff *skb, struct net_device *dev, u32 reinject_mark) {
    kfree_skb(skb);
    return -EAFNOSUPPORT;
}

int pht_reinject_udp_payload_v6(struct net_device *dev, const struct pht_endpoint_pair *ep,
                                const void *payload, size_t payload_len, u32 reinject_mark) {
    return -EAFNOSUPPORT;
}

int pht_reinject_udp_payload_from_skb_v6(struct net_device *dev, const struct pht_endpoint_pair *ep,
                                         const struct sk_buff *src, unsigned int payload_offset,
                                         size_t payload_len, u32 reinject_mark) {
    return -EAFNOSUPPORT;
}
#endif

int pht_prepare_fake_tcp_ack_payload_from_skb(const struct pht_endpoint_pair *ep, u32 seq, u32 ack,
                                              const struct sk_buff *src,
                                              unsigned int payload_offset, size_t payload_len,
                                              const struct pht_tx_meta *meta,
                                              struct sk_buff **out_skb) {
    struct sk_buff *skb;
    void *payload;
    int ret;

    if (out_skb)
        *out_skb = NULL;
    if (!ep || !out_skb)
        return -EINVAL;
    if (payload_len && !src)
        return -EINVAL;

    switch (ep->local_addr.family) {
    case AF_INET:
        if (payload_len > pht_fake_tcp_max_payload_len(AF_INET))
            return -EMSGSIZE;
        skb = pht_build_fake_tcp_v4_uninit(ep, seq, ack, PHT_TCP_FLAG_ACK, payload_len, &payload);
        if (!skb)
            return -ENOMEM;
        if (payload_len) {
            ret = skb_copy_bits(src, payload_offset, payload, (int)payload_len);
            if (ret) {
                kfree_skb(skb);
                return ret;
            }
        }
        pht_fake_tcp_v4_complete_skb(skb);
        ret = pht_tx_apply_fake_tcp_meta(skb, AF_INET, meta);
        break;
#if IS_ENABLED(CONFIG_IPV6)
    case AF_INET6:
        if (payload_len > pht_fake_tcp_max_payload_len(AF_INET6))
            return -EMSGSIZE;
        skb = pht_build_fake_tcp_v6_uninit(ep, seq, ack, PHT_TCP_FLAG_ACK, payload_len, &payload);
        if (!skb)
            return -ENOMEM;
        if (payload_len) {
            ret = skb_copy_bits(src, payload_offset, payload, (int)payload_len);
            if (ret) {
                kfree_skb(skb);
                return ret;
            }
        }
        pht_fake_tcp_v6_complete_skb(skb);
        ret = pht_tx_apply_fake_tcp_meta(skb, AF_INET6, meta);
        break;
#endif
    default:
        return -EAFNOSUPPORT;
    }

    if (ret) {
        kfree_skb(skb);
        return ret;
    }

    *out_skb = skb;
    return 0;
}

int pht_emit_fake_tcp(struct net *net, const struct pht_endpoint_pair *ep, u32 seq, u32 ack,
                      u8 flags, const void *payload, size_t payload_len,
                      const struct pht_tx_meta *meta, int *out_ifindex) {
    if (!ep)
        return -EINVAL;

    switch (ep->local_addr.family) {
    case AF_INET:
        return pht_emit_fake_tcp_v4(net, ep, seq, ack, flags, payload, payload_len, meta,
                                    out_ifindex);
    case AF_INET6:
        return pht_emit_fake_tcp_v6(net, ep, seq, ack, flags, payload, payload_len, meta,
                                    out_ifindex);
    default:
        return -EAFNOSUPPORT;
    }
}

int pht_reinject_udp_payload(struct net_device *dev, const struct pht_endpoint_pair *ep,
                             const void *payload, size_t payload_len, u32 reinject_mark) {
    if (!ep)
        return -EINVAL;

    switch (ep->local_addr.family) {
    case AF_INET:
        return pht_reinject_udp_payload_v4(dev, ep, payload, payload_len, reinject_mark);
    case AF_INET6:
        return pht_reinject_udp_payload_v6(dev, ep, payload, payload_len, reinject_mark);
    default:
        return -EAFNOSUPPORT;
    }
}

int pht_reinject_udp_payload_from_skb(struct net_device *dev, const struct pht_endpoint_pair *ep,
                                      const struct sk_buff *src, unsigned int payload_offset,
                                      size_t payload_len, u32 reinject_mark) {
    if (!ep)
        return -EINVAL;

    switch (ep->local_addr.family) {
    case AF_INET:
        return pht_reinject_udp_payload_from_skb_v4(dev, ep, src, payload_offset, payload_len,
                                                    reinject_mark);
    case AF_INET6:
        return pht_reinject_udp_payload_from_skb_v6(dev, ep, src, payload_offset, payload_len,
                                                    reinject_mark);
    default:
        return -EAFNOSUPPORT;
    }
}
