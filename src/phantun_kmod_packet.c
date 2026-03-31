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

#include <net/ip.h>
#include <net/route.h>
#include <net/tcp.h>

#include "phantun_kmod_packet.h"

static int pht_parse_ipv4_l4(struct sk_buff *skb, u8 protocol,
			     unsigned int min_l4_len,
			     struct pht_l4_view *view)
{
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
	if (skb->len < total_len || total_len < ip_hdr_len + min_l4_len)
		return -EINVAL;

	skb_set_transport_header(skb, ip_hdr_len);
	view->iph = iph;
	view->ip_hdr_len = ip_hdr_len;
	return 0;
}

int pht_parse_ipv4_udp(struct sk_buff *skb, struct pht_l4_view *view)
{
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

int pht_parse_ipv4_tcp(struct sk_buff *skb, struct pht_l4_view *view)
{
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

int pht_copy_l4_payload(const struct sk_buff *skb,
			const struct pht_l4_view *view,
			void *dst, size_t dst_len)
{
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

void pht_ipv4_complete(struct iphdr *iph, u16 total_len, u8 protocol,
		       __be32 saddr, __be32 daddr)
{
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

void pht_tcp_v4_complete(struct iphdr *iph, struct tcphdr *th, u16 tcp_len)
{
	th->check = 0;
	th->check = tcp_v4_check(tcp_len, iph->saddr, iph->daddr,
				csum_partial(th, tcp_len, 0));
}

void pht_udp_v4_complete(struct iphdr *iph, struct udphdr *uh, u16 udp_len)
{
	uh->check = 0;
	uh->check = csum_tcpudp_magic(iph->saddr, iph->daddr, udp_len,
				      IPPROTO_UDP,
				      csum_partial(uh, udp_len, 0));
}

static struct sk_buff *pht_alloc_l3_skb(unsigned int l4_len,
				       size_t payload_len)
{
	unsigned int total_len;
	struct sk_buff *skb;

	total_len = sizeof(struct iphdr) + l4_len + payload_len;
	if (total_len > PHT_V4_MAX_PACKET_LEN)
		return NULL;

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

struct sk_buff *pht_build_fake_tcp_v4(const struct pht_ipv4_endpoint_pair *ep,
				      u32 seq, u32 ack, u8 flags,
				      const void *payload, size_t payload_len)
{
	struct sk_buff *skb;
	struct iphdr *iph;
	struct tcphdr *th;
	u8 *payload_ptr;
	u8 *opt;
	unsigned int tcp_hdr_len;
	unsigned int tcp_len;
	bool add_wscale;

	if (!ep)
		return NULL;
	if (payload_len && !payload)
		return NULL;

	add_wscale = !!(flags & PHT_TCP_FLAG_SYN);
	tcp_hdr_len = sizeof(*th) + (add_wscale ? 4 : 0);
	tcp_len = tcp_hdr_len + payload_len;
	skb = pht_alloc_l3_skb(tcp_hdr_len, payload_len);
	if (!skb)
		return NULL;

	iph = ip_hdr(skb);
	th = tcp_hdr(skb);
	payload_ptr = skb_transport_header(skb) + tcp_hdr_len;

	pht_ipv4_complete(iph, sizeof(*iph) + tcp_len, IPPROTO_TCP,
			  ep->local_addr, ep->remote_addr);

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

	if (payload_len)
		memcpy(payload_ptr, payload, payload_len);

	pht_tcp_v4_complete(iph, th, tcp_len);
	return skb;
}

struct sk_buff *pht_build_fake_tcp_syn_v4(const struct pht_ipv4_endpoint_pair *ep,
					  u32 seq)
{
	return pht_build_fake_tcp_v4(ep, seq, 0, PHT_TCP_FLAG_SYN, NULL, 0);
}

struct sk_buff *pht_build_fake_tcp_synack_v4(const struct pht_ipv4_endpoint_pair *ep,
					     u32 seq, u32 ack)
{
	return pht_build_fake_tcp_v4(ep, seq, ack,
				     PHT_TCP_FLAG_SYN | PHT_TCP_FLAG_ACK, NULL, 0);
}

struct sk_buff *pht_build_fake_tcp_ack_v4(const struct pht_ipv4_endpoint_pair *ep,
					  u32 seq, u32 ack)
{
	return pht_build_fake_tcp_v4(ep, seq, ack, PHT_TCP_FLAG_ACK, NULL, 0);
}

struct sk_buff *pht_build_fake_tcp_ack_payload_v4(
	const struct pht_ipv4_endpoint_pair *ep, u32 seq, u32 ack,
	const void *payload, size_t payload_len)
{
	return pht_build_fake_tcp_v4(ep, seq, ack, PHT_TCP_FLAG_ACK, payload,
				     payload_len);
}

struct sk_buff *pht_build_fake_tcp_rst_v4(const struct pht_ipv4_endpoint_pair *ep,
					  u32 seq)
{
	return pht_build_fake_tcp_v4(ep, seq, 0, PHT_TCP_FLAG_RST, NULL, 0);
}

struct sk_buff *pht_build_fake_tcp_rstack_v4(const struct pht_ipv4_endpoint_pair *ep,
					     u32 seq, u32 ack)
{
	return pht_build_fake_tcp_v4(ep, seq, ack,
				     PHT_TCP_FLAG_RST | PHT_TCP_FLAG_ACK, NULL, 0);
}

struct sk_buff *pht_build_udp_v4(const struct pht_ipv4_endpoint_pair *ep,
				 const void *payload, size_t payload_len)
{
	struct sk_buff *skb;
	struct iphdr *iph;
	struct udphdr *uh;
	u8 *payload_ptr;
	unsigned int udp_len;

	if (!ep)
		return NULL;
	if (payload_len && !payload)
		return NULL;

	udp_len = sizeof(*uh) + payload_len;
	skb = pht_alloc_l3_skb(sizeof(*uh), payload_len);
	if (!skb)
		return NULL;

	iph = ip_hdr(skb);
	uh = udp_hdr(skb);
	payload_ptr = skb_transport_header(skb) + sizeof(*uh);

	pht_ipv4_complete(iph, sizeof(*iph) + udp_len, IPPROTO_UDP,
			  ep->remote_addr, ep->local_addr);

	uh->source = ep->remote_port;
	uh->dest = ep->local_port;
	uh->len = htons(udp_len);
	if (payload_len)
		memcpy(payload_ptr, payload, payload_len);

	pht_udp_v4_complete(iph, uh, udp_len);
	return skb;
}

int pht_tx_fake_tcp_v4(struct net *net, struct sk_buff *skb,
		      const struct pht_ipv4_endpoint_pair *ep)
{
	struct flowi4 fl4;
	struct rtable *rt;

	if (!net || !skb || !ep) {
		kfree_skb(skb);
		return -EINVAL;
	}

	memset(&fl4, 0, sizeof(fl4));
	flowi4_init_output(&fl4, 0, 0, 0, RT_SCOPE_UNIVERSE, IPPROTO_TCP, 0,
			   ep->remote_addr, ep->local_addr,
			   ep->remote_port, ep->local_port,
			   GLOBAL_ROOT_UID);
	rt = ip_route_output_key(net, &fl4);
	if (IS_ERR(rt)) {
		kfree_skb(skb);
		return PTR_ERR(rt);
	}

	skb_dst_set(skb, &rt->dst);
	skb->dev = rt->dst.dev;
	skb->protocol = htons(ETH_P_IP);
	return ip_local_out(net, NULL, skb);
}

int pht_emit_fake_tcp_v4(struct net *net,
		 const struct pht_ipv4_endpoint_pair *ep,
		 u32 seq, u32 ack, u8 flags,
		 const void *payload, size_t payload_len)
{
	struct sk_buff *skb;

	skb = pht_build_fake_tcp_v4(ep, seq, ack, flags, payload, payload_len);
	if (!skb)
		return -ENOMEM;

	return pht_tx_fake_tcp_v4(net, skb, ep);
}

int pht_reinject_udp_v4(struct sk_buff *skb, struct net_device *dev)
{
	if (!skb || !dev) {
		kfree_skb(skb);
		return -EINVAL;
	}

	skb->dev = dev;
	skb->skb_iif = dev->ifindex;
	skb->pkt_type = PACKET_HOST;
	skb->protocol = htons(ETH_P_IP);
	return netif_receive_skb(skb);
}

int pht_reinject_udp_payload_v4(struct net_device *dev,
			const struct pht_ipv4_endpoint_pair *ep,
			const void *payload, size_t payload_len)
{
	struct sk_buff *skb;

	skb = pht_build_udp_v4(ep, payload, payload_len);
	if (!skb)
		return -ENOMEM;

	return pht_reinject_udp_v4(skb, dev);
}
