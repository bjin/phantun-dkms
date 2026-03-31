#ifndef PHANTUN_PACKET_H
#define PHANTUN_PACKET_H

#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>

#define PHT_V4_DEFAULT_TTL 64
#define PHT_V4_MAX_PACKET_LEN 1500U
#define PHT_TCP_DEFAULT_WINDOW 0xffffU
#define PHT_TCP_WINDOW_SCALE 14U

#define PHT_TCP_FLAG_FIN 0x01U
#define PHT_TCP_FLAG_SYN 0x02U
#define PHT_TCP_FLAG_RST 0x04U
#define PHT_TCP_FLAG_PSH 0x08U
#define PHT_TCP_FLAG_ACK 0x10U
#define PHT_TCP_FLAG_URG 0x20U

struct pht_ipv4_endpoint_pair {
	__be32 local_addr;
	__be32 remote_addr;
	__be16 local_port;
	__be16 remote_port;
};

struct pht_l4_view {
	struct iphdr *iph;
	union {
		struct tcphdr *tcp;
		struct udphdr *udp;
	};
	unsigned int ip_hdr_len;
	unsigned int l4_hdr_len;
	unsigned int payload_offset;
	unsigned int payload_len;
};

int pht_parse_ipv4_udp(struct sk_buff *skb, struct pht_l4_view *view);
int pht_parse_ipv4_tcp(struct sk_buff *skb, struct pht_l4_view *view);
int pht_copy_l4_payload(const struct sk_buff *skb,
			const struct pht_l4_view *view, void *dst,
			size_t dst_len);

void pht_ipv4_complete(struct iphdr *iph, u16 total_len, u8 protocol,
		       __be32 saddr, __be32 daddr);
void pht_tcp_v4_complete(struct iphdr *iph, struct tcphdr *th, u16 tcp_len);
void pht_udp_v4_complete(struct iphdr *iph, struct udphdr *uh, u16 udp_len);

struct sk_buff *pht_build_fake_tcp_v4(const struct pht_ipv4_endpoint_pair *ep,
				      u32 seq, u32 ack, u8 flags,
				      const void *payload, size_t payload_len);
struct sk_buff *
pht_build_fake_tcp_syn_v4(const struct pht_ipv4_endpoint_pair *ep, u32 seq);
struct sk_buff *
pht_build_fake_tcp_synack_v4(const struct pht_ipv4_endpoint_pair *ep, u32 seq,
			     u32 ack);
struct sk_buff *
pht_build_fake_tcp_ack_v4(const struct pht_ipv4_endpoint_pair *ep, u32 seq,
			  u32 ack);
struct sk_buff *
pht_build_fake_tcp_ack_payload_v4(const struct pht_ipv4_endpoint_pair *ep,
				  u32 seq, u32 ack, const void *payload,
				  size_t payload_len);
struct sk_buff *
pht_build_fake_tcp_rst_v4(const struct pht_ipv4_endpoint_pair *ep, u32 seq);
struct sk_buff *
pht_build_fake_tcp_rstack_v4(const struct pht_ipv4_endpoint_pair *ep, u32 seq,
			     u32 ack);
struct sk_buff *pht_build_udp_v4(const struct pht_ipv4_endpoint_pair *ep,
				 const void *payload, size_t payload_len);

int pht_tx_fake_tcp_v4(struct net *net, struct sk_buff *skb,
		       const struct pht_ipv4_endpoint_pair *ep);
int pht_emit_fake_tcp_v4(struct net *net,
			 const struct pht_ipv4_endpoint_pair *ep, u32 seq,
			 u32 ack, u8 flags, const void *payload,
			 size_t payload_len);
int pht_reinject_udp_v4(struct sk_buff *skb, struct net_device *dev);
int pht_reinject_udp_payload_v4(struct net_device *dev,
				const struct pht_ipv4_endpoint_pair *ep,
				const void *payload, size_t payload_len);

#endif
