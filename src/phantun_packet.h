// SPDX-License-Identifier: GPL-2.0-or-later
//
// Copyright (C) 2026 Bin Jin. All Rights Reserved.
#ifndef PHANTUN_PACKET_H
#define PHANTUN_PACKET_H

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <linux/uidgid.h>

struct dst_entry;
struct net;
#define PHT_V4_DEFAULT_TTL 64
#define PHT_V4_MAX_PACKET_LEN 1500U
#define PHT_V4_MAX_TCP_PAYLOAD_LEN                                                                 \
    (PHT_V4_MAX_PACKET_LEN - sizeof(struct iphdr) - sizeof(struct tcphdr))
#define PHT_V4_MAX_UDP_PAYLOAD_LEN                                                                 \
    (PHT_V4_MAX_PACKET_LEN - sizeof(struct iphdr) - sizeof(struct udphdr))
#define PHT_V6_DEFAULT_HOP_LIMIT 64
#define PHT_V6_MAX_PACKET_LEN 1500U
#define PHT_V6_MAX_TCP_PAYLOAD_LEN                                                                 \
    (PHT_V6_MAX_PACKET_LEN - sizeof(struct ipv6hdr) - sizeof(struct tcphdr))
#define PHT_V6_MAX_UDP_PAYLOAD_LEN                                                                 \
    (PHT_V6_MAX_PACKET_LEN - sizeof(struct ipv6hdr) - sizeof(struct udphdr))
#define PHT_TCP_DEFAULT_WINDOW 0xffffU
#define PHT_TCP_WINDOW_SCALE 14U

#define PHT_TCP_FLAG_FIN 0x01U
#define PHT_TCP_FLAG_SYN 0x02U
#define PHT_TCP_FLAG_RST 0x04U
#define PHT_TCP_FLAG_PSH 0x08U
#define PHT_TCP_FLAG_ACK 0x10U
#define PHT_TCP_FLAG_URG 0x20U

struct pht_addr {
    u8 family;

    union {
        __be32 v4;
        struct in6_addr v6;
    };
};

struct pht_endpoint_pair {
    struct pht_addr local_addr;
    struct pht_addr remote_addr;
    __be16 local_port;
    __be16 remote_port;
    int scope_ifindex;
};

/*
 * Per-send transmit metadata captured at the interception point. These fields
 * are copied onto the generated fake-TCP skb and, where the kernel route lookup
 * consumes them, into pht_tx_route_key. priority stays per-skb policy state;
 * oif is only an explicit socket/device binding, not the resolved egress dev.
 */
struct pht_tx_meta {
    u32 mark;
    u32 priority;
    int oif;
    u8 v4_tos;
    u8 v6_priority;
    u8 v6_flow_lbl[3];
    kuid_t uid;
};

/*
 * Exact key for a fake-TCP route lookup. Keep this limited to flowi inputs:
 * endpoint identity, scope/oif fallback, mark, uid, IPv4 TOS, and IPv6
 * priority/flowlabel. skb->priority is applied to each emitted skb by
 * pht_tx_meta but is deliberately not a route-cache discriminator.
 */
struct pht_tx_route_key {
    u8 family;
    struct pht_addr local_addr;
    struct pht_addr remote_addr;
    __be16 local_port;
    __be16 remote_port;
    int scope_ifindex;
    u32 mark;
    int oif;
    kuid_t uid;

    union {
        u8 v4_tos;

        struct {
            u8 priority;
            u8 flow_lbl[3];
        } v6;
    };
};

/*
 * Fresh lookup result. The dst pointer owns the lookup reference until the
 * caller either attaches it to an skb or transfers it into a flow-owned cache.
 * IPv6 stores rt6_get_cookie() so dst_check() validates against the same
 * generation that produced the route; IPv4 uses cookie 0.
 */
struct pht_tx_route_result {
    struct dst_entry *dst;
    u32 cookie;
    int ifindex;
};

/*
 * Parsed L3/L4 view into an skb. Header pointers and payload offsets borrow
 * the skb's current linear/nonlinear data; callers must not keep this after
 * the skb is modified or freed. payload_offset/payload_len describe exactly
 * the bytes translated between UDP payload and fake-TCP payload.
 */
struct pht_l4_view {
    u8 family;

    union {
        struct iphdr *iph;
        struct ipv6hdr *ip6h;
    };

    union {
        struct tcphdr *tcp;
        struct udphdr *udp;
    };

    unsigned int ip_hdr_len;
    unsigned int l4_hdr_len;
    unsigned int payload_offset;
    unsigned int payload_len;
};

unsigned int pht_fake_tcp_max_payload_len(u8 family);
unsigned int pht_udp_max_payload_len(u8 family);
void pht_tx_meta_init(struct pht_tx_meta *meta);

int pht_tx_route_key_init(struct pht_tx_route_key *key, const struct pht_endpoint_pair *ep,
                          const struct pht_tx_meta *meta);
bool pht_tx_route_key_equal(const struct pht_tx_route_key *a, const struct pht_tx_route_key *b);
int pht_tx_fake_tcp_route(struct net *net, const struct pht_tx_route_key *key,
                          struct pht_tx_route_result *route);
int pht_tx_fake_tcp_with_dst(struct net *net, struct sk_buff *skb, u8 family,
                             struct dst_entry *dst);
int pht_prepare_fake_tcp_ack_payload_from_skb(const struct pht_endpoint_pair *ep, u32 seq, u32 ack,
                                              const struct sk_buff *src,
                                              unsigned int payload_offset, size_t payload_len,
                                              const struct pht_tx_meta *meta,
                                              struct sk_buff **out_skb);

int pht_parse_ipv4_udp(struct sk_buff *skb, struct pht_l4_view *view);
int pht_parse_ipv4_tcp(struct sk_buff *skb, struct pht_l4_view *view);
int pht_validate_ipv4_tcp_checksums(const struct sk_buff *skb, const struct pht_l4_view *view);
int pht_parse_ipv6_udp(struct sk_buff *skb, struct pht_l4_view *view);
int pht_parse_ipv6_tcp(struct sk_buff *skb, struct pht_l4_view *view);
int pht_validate_ipv6_tcp_checksums(const struct sk_buff *skb, const struct pht_l4_view *view);
int pht_copy_l4_payload(const struct sk_buff *skb, const struct pht_l4_view *view, void *dst,
                        size_t dst_len);

void pht_ipv4_complete(struct iphdr *iph, u16 total_len, u8 protocol, __be32 saddr, __be32 daddr);
void pht_tcp_v4_complete(struct iphdr *iph, struct tcphdr *th, u16 tcp_len);
void pht_udp_v4_complete(struct iphdr *iph, struct udphdr *uh, u16 udp_len);
void pht_ipv6_complete(struct ipv6hdr *ip6h, u16 payload_len, u8 nexthdr,
                       const struct in6_addr *saddr, const struct in6_addr *daddr);
void pht_tcp_v6_complete(struct ipv6hdr *ip6h, struct tcphdr *th, u16 tcp_len);
void pht_udp_v6_complete(struct ipv6hdr *ip6h, struct udphdr *uh, u16 udp_len);

struct sk_buff *pht_build_fake_tcp_v4(const struct pht_endpoint_pair *ep, u32 seq, u32 ack,
                                      u8 flags, const void *payload, size_t payload_len);
/* The payload region is uninitialized; caller must write exactly payload_len
 * bytes before checksum completion and transmit/reinject.
 */
struct sk_buff *pht_build_fake_tcp_v4_uninit(const struct pht_endpoint_pair *ep, u32 seq, u32 ack,
                                             u8 flags, size_t payload_len, void **payload_ptr);
struct sk_buff *pht_build_fake_tcp_syn_v4(const struct pht_endpoint_pair *ep, u32 seq);
struct sk_buff *pht_build_fake_tcp_synack_v4(const struct pht_endpoint_pair *ep, u32 seq, u32 ack);
struct sk_buff *pht_build_fake_tcp_ack_v4(const struct pht_endpoint_pair *ep, u32 seq, u32 ack);
struct sk_buff *pht_build_fake_tcp_ack_payload_v4(const struct pht_endpoint_pair *ep, u32 seq,
                                                  u32 ack, const void *payload, size_t payload_len);
struct sk_buff *pht_build_fake_tcp_rst_v4(const struct pht_endpoint_pair *ep, u32 seq);
struct sk_buff *pht_build_fake_tcp_rstack_v4(const struct pht_endpoint_pair *ep, u32 seq, u32 ack);
struct sk_buff *pht_build_udp_v4(const struct pht_endpoint_pair *ep, const void *payload,
                                 size_t payload_len);
/* The payload region is uninitialized; caller must write exactly payload_len
 * bytes before checksum completion and transmit/reinject.
 */
struct sk_buff *pht_build_udp_v4_uninit(const struct pht_endpoint_pair *ep, size_t payload_len,
                                        void **payload_ptr);

int pht_tx_fake_tcp_v4(struct net *net, struct sk_buff *skb, const struct pht_endpoint_pair *ep,
                       const struct pht_tx_meta *meta, int *out_ifindex);
int pht_emit_fake_tcp_v4(struct net *net, const struct pht_endpoint_pair *ep, u32 seq, u32 ack,
                         u8 flags, const void *payload, size_t payload_len,
                         const struct pht_tx_meta *meta, int *out_ifindex);
int pht_reinject_udp_v4(struct sk_buff *skb, struct net_device *dev, u32 reinject_mark);
int pht_reinject_udp_payload_v4(struct net_device *dev, const struct pht_endpoint_pair *ep,
                                const void *payload, size_t payload_len, u32 reinject_mark);
int pht_reinject_udp_payload_from_skb_v4(struct net_device *dev, const struct pht_endpoint_pair *ep,
                                         const struct sk_buff *src, unsigned int payload_offset,
                                         size_t payload_len, u32 reinject_mark);
struct sk_buff *pht_build_fake_tcp_v6(const struct pht_endpoint_pair *ep, u32 seq, u32 ack,
                                      u8 flags, const void *payload, size_t payload_len);
/* The payload region is uninitialized; caller must write exactly payload_len
 * bytes before checksum completion and transmit/reinject.
 */
struct sk_buff *pht_build_fake_tcp_v6_uninit(const struct pht_endpoint_pair *ep, u32 seq, u32 ack,
                                             u8 flags, size_t payload_len, void **payload_ptr);
struct sk_buff *pht_build_udp_v6(const struct pht_endpoint_pair *ep, const void *payload,
                                 size_t payload_len);
/* The payload region is uninitialized; caller must write exactly payload_len
 * bytes before checksum completion and transmit/reinject.
 */
struct sk_buff *pht_build_udp_v6_uninit(const struct pht_endpoint_pair *ep, size_t payload_len,
                                        void **payload_ptr);
int pht_tx_fake_tcp_v6(struct net *net, struct sk_buff *skb, const struct pht_endpoint_pair *ep,
                       const struct pht_tx_meta *meta, int *out_ifindex);
int pht_emit_fake_tcp_v6(struct net *net, const struct pht_endpoint_pair *ep, u32 seq, u32 ack,
                         u8 flags, const void *payload, size_t payload_len,
                         const struct pht_tx_meta *meta, int *out_ifindex);
int pht_reinject_udp_v6(struct sk_buff *skb, struct net_device *dev, u32 reinject_mark);
int pht_reinject_udp_payload_v6(struct net_device *dev, const struct pht_endpoint_pair *ep,
                                const void *payload, size_t payload_len, u32 reinject_mark);
int pht_reinject_udp_payload_from_skb_v6(struct net_device *dev, const struct pht_endpoint_pair *ep,
                                         const struct sk_buff *src, unsigned int payload_offset,
                                         size_t payload_len, u32 reinject_mark);
int pht_emit_fake_tcp(struct net *net, const struct pht_endpoint_pair *ep, u32 seq, u32 ack,
                      u8 flags, const void *payload, size_t payload_len,
                      const struct pht_tx_meta *meta, int *out_ifindex);
int pht_reinject_udp_payload(struct net_device *dev, const struct pht_endpoint_pair *ep,
                             const void *payload, size_t payload_len, u32 reinject_mark);
int pht_reinject_udp_payload_from_skb(struct net_device *dev, const struct pht_endpoint_pair *ep,
                                      const struct sk_buff *src, unsigned int payload_offset,
                                      size_t payload_len, u32 reinject_mark);

#endif
