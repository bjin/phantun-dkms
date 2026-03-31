#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/net_namespace.h>
#include <linux/skbuff.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "phantun_dkms.h"
#include "phantun_dkms_flow.h"
#include "phantun_dkms_packet.h"

static unsigned short managed_ports[PHANTUN_DKMS_MAX_MANAGED_PORTS];
static int managed_ports_count;
static char *handshake_request;
static char *handshake_response;
static unsigned int handshake_timeout_ms =
	PHANTUN_DKMS_DEFAULT_HANDSHAKE_TIMEOUT_MS;
static unsigned int handshake_retries = PHANTUN_DKMS_DEFAULT_HANDSHAKE_RETRIES;
static unsigned int idle_timeout_sec = PHANTUN_DKMS_DEFAULT_IDLE_TIMEOUT_SEC;
static char *remote_ipv4_cidr;
static unsigned short remote_port;

module_param_array_named(managed_ports, managed_ports, ushort,
	&managed_ports_count, 0644);
MODULE_PARM_DESC(managed_ports,
	"Comma-separated local UDP/TCP ports managed by phantun_dkms");
module_param(handshake_request, charp, 0644);
MODULE_PARM_DESC(handshake_request,
	"Mandatory initiator control payload sent as the first fake-TCP payload");
module_param(handshake_response, charp, 0644);
MODULE_PARM_DESC(handshake_response,
	"Mandatory responder control payload sent as the first fake-TCP payload");
module_param(handshake_timeout_ms, uint, 0644);
MODULE_PARM_DESC(handshake_timeout_ms,
	"Handshake retransmit timeout in milliseconds");
module_param(handshake_retries, uint, 0644);
MODULE_PARM_DESC(handshake_retries,
	"Maximum handshake retry count before tearing a flow down with RST");
module_param(idle_timeout_sec, uint, 0644);
MODULE_PARM_DESC(idle_timeout_sec,
	"Idle flow timeout in seconds before teardown");
module_param(remote_ipv4_cidr, charp, 0644);
MODULE_PARM_DESC(remote_ipv4_cidr,
	"Optional remote IPv4 CIDR filter (string form, parsed in later phases)");
module_param(remote_port, ushort, 0644);
MODULE_PARM_DESC(remote_port,
	"Optional remote UDP/TCP port filter; 0 disables the filter");

static struct phantun_dkms_config phantun_cfg;
static struct pht_flow_table phantun_flows;

static bool phantun_managed_port(__be16 port)
{
	unsigned int i;


	for (i = 0; i < phantun_cfg.managed_ports_count; i++) {
		if (phantun_cfg.managed_ports[i] == ntohs(port))
			return true;
	}


	return false;
}

static bool phantun_remote_port_allowed(__be16 port)
{
	return !phantun_cfg.remote_port || ntohs(port) == phantun_cfg.remote_port;
}

static void phantun_fill_udp_endpoint_pair(const struct pht_l4_view *view,
				       struct pht_ipv4_endpoint_pair *ep)
{
	ep->local_addr = view->iph->saddr;
	ep->remote_addr = view->iph->daddr;
	ep->local_port = view->udp->source;
	ep->remote_port = view->udp->dest;
}

static void phantun_fill_tcp_endpoint_pair(const struct pht_l4_view *view,
				       struct pht_ipv4_endpoint_pair *ep)
{
	ep->local_addr = view->iph->daddr;
	ep->remote_addr = view->iph->saddr;
	ep->local_port = view->tcp->dest;
	ep->remote_port = view->tcp->source;
}

static u32 phantun_random_aligned_seq(void)
{
	return (get_random_u32() / 4095U) * 4095U;
}

static u32 phantun_tcp_seq_advance(const struct tcphdr *th, unsigned int payload_len)
{
	u32 advance = payload_len;

	if (th->syn)
		advance++;
	if (th->fin)
		advance++;

	return advance;
}

static bool phantun_payload_matches(const struct sk_buff *skb,
				   const struct pht_l4_view *view,
				   const char *expected)
{
	void *payload;
	bool match;
	size_t expected_len;
	int ret;

	if (!expected)
		return false;

	expected_len = strlen(expected);
	if (view->payload_len != expected_len)
		return false;
	if (!expected_len)
		return true;

	payload = kmalloc(expected_len, GFP_ATOMIC);
	if (!payload)
		return false;

	ret = pht_copy_l4_payload(skb, view, payload, expected_len);
	match = !ret && !memcmp(payload, expected, expected_len);
	kfree(payload);
	return match;
}

static int phantun_send_established_udp(struct pht_flow *flow,
			      const struct pht_ipv4_endpoint_pair *ep,
			      const struct pht_l4_view *view,
			      const struct sk_buff *skb,
			      struct net *net)
{
	u32 seq;
	u32 ack;
	void *payload = NULL;
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

	spin_lock_bh(&flow->lock);
	if (flow->state != PHT_FLOW_STATE_ESTABLISHED) {
		spin_unlock_bh(&flow->lock);
		kfree(payload);
		return -EAGAIN;
	}
	seq = flow->seq;
	ack = flow->ack;
	spin_unlock_bh(&flow->lock);

	ret = pht_emit_fake_tcp_v4(net, ep, seq, ack, PHT_TCP_FLAG_ACK, payload,
				 view->payload_len);
	if (!ret) {
		spin_lock_bh(&flow->lock);
		if (flow->state == PHT_FLOW_STATE_ESTABLISHED) {
			flow->seq += view->payload_len;
			flow->last_activity_jiffies = jiffies;
		}
		spin_unlock_bh(&flow->lock);
	}

	kfree(payload);
	return ret;
}

static int phantun_send_synack(struct pht_flow *flow, struct net *net)
{
	struct pht_ipv4_endpoint_pair ep;
	u32 seq;
	u32 ack;

	spin_lock_bh(&flow->lock);
	ep = flow->oriented;
	seq = flow->local_isn;
	ack = flow->peer_syn_next;
	spin_unlock_bh(&flow->lock);

	return pht_emit_fake_tcp_v4(net, &ep, seq, ack,
				 PHT_TCP_FLAG_SYN | PHT_TCP_FLAG_ACK, NULL, 0);
}

static int phantun_send_rstack(struct net *net,
			     const struct pht_ipv4_endpoint_pair *ep,
			     const struct pht_l4_view *view, bool force_zero_seq)
{
	u32 seq = force_zero_seq ? 0 : ntohl(view->tcp->ack_seq);
	u32 ack = ntohl(view->tcp->seq) +
		  phantun_tcp_seq_advance(view->tcp, view->payload_len);

	return pht_emit_fake_tcp_v4(net, ep, seq, ack,
				 PHT_TCP_FLAG_RST | PHT_TCP_FLAG_ACK, NULL, 0);
}

static int phantun_send_handshake_request(struct pht_flow *flow, struct net *net)
{
	struct pht_ipv4_endpoint_pair ep;
	u32 seq;
	u32 ack;
	size_t req_len = phantun_cfg.handshake_request_len;
	int ret;

	spin_lock_bh(&flow->lock);
	ep = flow->oriented;
	seq = flow->local_isn + 1;
	ack = flow->ack;
	spin_unlock_bh(&flow->lock);

	ret = pht_emit_fake_tcp_v4(net, &ep, seq, ack, PHT_TCP_FLAG_ACK,
				 phantun_cfg.handshake_request, req_len);
	if (!ret) {
		spin_lock_bh(&flow->lock);
		flow->seq = seq + req_len;
		flow->last_ack = ack;
		flow->last_activity_jiffies = jiffies;
		spin_unlock_bh(&flow->lock);
	}
	return ret;
}

static int phantun_send_handshake_response(struct pht_flow *flow, struct net *net)
{
	struct pht_ipv4_endpoint_pair ep;
	u32 seq;
	u32 ack;
	size_t resp_len = phantun_cfg.handshake_response_len;
	int ret;

	spin_lock_bh(&flow->lock);
	ep = flow->oriented;
	seq = flow->local_isn + 1;
	ack = flow->ack;
	spin_unlock_bh(&flow->lock);

	ret = pht_emit_fake_tcp_v4(net, &ep, seq, ack, PHT_TCP_FLAG_ACK,
				 phantun_cfg.handshake_response, resp_len);
	if (!ret) {
		spin_lock_bh(&flow->lock);
		flow->seq = seq + resp_len;
		flow->last_ack = ack;
		flow->last_activity_jiffies = jiffies;
		spin_unlock_bh(&flow->lock);
	}
	return ret;
}

static int phantun_send_idle_ack(struct pht_flow *flow, struct net *net)
{
	struct pht_ipv4_endpoint_pair ep;
	u32 seq;
	u32 ack;
	int ret;

	spin_lock_bh(&flow->lock);
	ep = flow->oriented;
	seq = flow->seq;
	ack = flow->ack;
	spin_unlock_bh(&flow->lock);

	ret = pht_emit_fake_tcp_v4(net, &ep, seq, ack, PHT_TCP_FLAG_ACK, NULL, 0);
	if (!ret) {
		spin_lock_bh(&flow->lock);
		flow->last_ack = ack;
		flow->last_activity_jiffies = jiffies;
		spin_unlock_bh(&flow->lock);
	}
	return ret;
}

static int phantun_flush_queued_udp(struct pht_flow *flow, struct net *net)
{
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

static int phantun_reinject_inbound_payload(const struct pht_ipv4_endpoint_pair *ep,
				       const struct sk_buff *skb,
				       const struct pht_l4_view *view,
				       struct net_device *dev)
{
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

static int phantun_respond_handshake_request(struct pht_flow *flow,
				      const struct sk_buff *skb,
				      const struct pht_l4_view *view,
				      struct net *net)
{
	if (!phantun_payload_matches(skb, view, phantun_cfg.handshake_request))
		return -EPROTO;

	spin_lock_bh(&flow->lock);
	flow->ack = ntohl(view->tcp->seq) + view->payload_len;
	flow->last_ack = flow->ack;
	flow->handshake_flags |= PHT_FLOW_HS_REQ_VERIFIED;
	spin_unlock_bh(&flow->lock);

	if (phantun_send_handshake_response(flow, net))
		return -EIO;

	pht_flow_update_state(flow, PHT_FLOW_STATE_HS_RESP_SENT);
	return 0;
}

static int phantun_finalize_established_rx(struct pht_flow *flow,
				       const struct pht_ipv4_endpoint_pair *ep,
				       const struct sk_buff *skb,
				       const struct pht_l4_view *view,
				       struct net *net,
				       struct net_device *dev,
				       bool send_idle_ack)
{
	int ret;

	spin_lock_bh(&flow->lock);
	flow->ack = ntohl(view->tcp->seq) + view->payload_len;
	flow->last_ack = flow->ack;
	flow->last_activity_jiffies = jiffies;
	flow->handshake_flags |= PHT_FLOW_HS_RESP_VERIFIED;
	spin_unlock_bh(&flow->lock);

	ret = phantun_reinject_inbound_payload(ep, skb, view, dev);
	if (ret)
		return ret;

	ret = phantun_flush_queued_udp(flow, net);
	if (ret)
		return ret;
	if (send_idle_ack && view->payload_len)
		ret = phantun_send_idle_ack(flow, net);
	return ret;
}

static unsigned int phantun_local_out(void *priv, struct sk_buff *skb,
				      const struct nf_hook_state *state)
{
	struct pht_l4_view view;
	struct pht_ipv4_endpoint_pair ep;
	struct pht_flow *flow;
	struct pht_flow *new_flow;
	enum pht_flow_state state_now;
	u32 init_seq;
	int ret;
	bool queued;

	if (!state || !skb)
		return NF_ACCEPT;

	ret = pht_parse_ipv4_udp(skb, &view);
	if (ret)
		return NF_ACCEPT;

	if (!phantun_managed_port(view.udp->source))
		return NF_ACCEPT;
	if (!phantun_remote_port_allowed(view.udp->dest))
		return NF_ACCEPT;

	phantun_fill_udp_endpoint_pair(&view, &ep);

retry_lookup:
	flow = pht_flow_lookup_oriented(&phantun_flows, &ep);
	if (flow) {
		spin_lock_bh(&flow->lock);
		state_now = flow->state;
		spin_unlock_bh(&flow->lock);

		if (state_now == PHT_FLOW_STATE_ESTABLISHED) {
			ret = phantun_send_established_udp(flow, &ep, &view, skb,
						 state->net);
			if (ret)
				pht_pr_warn("failed to emit fake-TCP payload for established flow: %d\n", ret);
			pht_flow_put(flow);
			kfree_skb(skb);
			return NF_STOLEN;
		}

		if (pht_flow_state_is_half_open(state_now)) {
			queued = pht_flow_queue_skb_if_empty(flow, skb);
			if (!queued)
				kfree_skb(skb);
			pht_flow_put(flow);
			return NF_STOLEN;
		}

		if (state_now == PHT_FLOW_STATE_DEAD) {
			pht_flow_remove(flow);
			pht_flow_put(flow);
			goto retry_lookup;
		}

		pht_flow_put(flow);
		kfree_skb(skb);
		return NF_STOLEN;
	}

	new_flow = pht_flow_create(&phantun_flows, &ep, PHT_FLOW_ROLE_INITIATOR,
				  PHT_FLOW_STATE_SYN_SENT);
	if (IS_ERR(new_flow)) {
		pht_pr_warn("failed to create initiator flow: %ld\n", PTR_ERR(new_flow));
		kfree_skb(skb);
		return NF_STOLEN;
	}

	init_seq = phantun_random_aligned_seq();
	spin_lock_bh(&new_flow->lock);
	new_flow->seq = init_seq;
	new_flow->ack = 0;
	new_flow->last_ack = 0;
	new_flow->local_isn = init_seq;
	new_flow->peer_syn_next = 0;
	spin_unlock_bh(&new_flow->lock);
	pht_flow_set_queued_skb(new_flow, skb);

	ret = pht_flow_insert(&phantun_flows, new_flow);
	if (ret == -EEXIST) {
		pht_flow_put(new_flow);
		goto retry_lookup;
	}
	if (ret) {
		pht_pr_warn("failed to insert initiator flow: %d\n", ret);
		pht_flow_put(new_flow);
		return NF_STOLEN;
	}

	ret = pht_emit_fake_tcp_v4(state->net, &ep, init_seq, 0, PHT_TCP_FLAG_SYN,
				 NULL, 0);
	if (ret) {
		pht_pr_warn("failed to emit fake-TCP SYN: %d\n", ret);
		pht_flow_remove(new_flow);
		return NF_STOLEN;
	}

	return NF_STOLEN;
}

static unsigned int phantun_pre_routing(void *priv, struct sk_buff *skb,
				       const struct nf_hook_state *state)
{
	struct pht_l4_view view;
	struct pht_ipv4_endpoint_pair ep;
	struct pht_flow *flow;
	struct pht_flow *new_flow;
	struct sk_buff *queued_skb;
	enum pht_flow_state state_now;
	struct net_device *in_dev;
	u32 expected_ack;
	u32 responder_seq;
	u32 control_ack;
	size_t req_len = phantun_cfg.handshake_request_len;
	size_t resp_len = phantun_cfg.handshake_response_len;
	bool local_is_low;
	bool had_queued;
	int ret;


	if (!state || !skb)
		return NF_ACCEPT;


	ret = pht_parse_ipv4_tcp(skb, &view);
	if (ret)
		return NF_ACCEPT;


	if (!phantun_managed_port(view.tcp->dest))
		return NF_ACCEPT;
	if (!phantun_remote_port_allowed(view.tcp->source))
		return NF_ACCEPT;


	phantun_fill_tcp_endpoint_pair(&view, &ep);
	in_dev = state->in ? state->in : skb->dev;


	flow = pht_flow_lookup_oriented(&phantun_flows, &ep);
	if (!flow) {
		if (view.tcp->rst)
			return NF_STOLEN;


		if (!view.tcp->syn) {
			ret = phantun_send_rstack(state->net, &ep, &view, false);
			if (ret)
				pht_pr_warn("failed to emit RST|ACK for unknown packet: %d\n", ret);
			return NF_STOLEN;
		}


		if (ntohl(view.tcp->seq) % 4095U != 0) {
			ret = phantun_send_rstack(state->net, &ep, &view, true);
			if (ret)
				pht_pr_warn("failed to emit RST|ACK for misaligned SYN: %d\n", ret);
			return NF_STOLEN;
		}


		new_flow = pht_flow_create(&phantun_flows, &ep, PHT_FLOW_ROLE_RESPONDER,
					  PHT_FLOW_STATE_SYN_RCVD);
		if (IS_ERR(new_flow)) {
			pht_pr_warn("failed to create responder flow: %ld\n", PTR_ERR(new_flow));
			return NF_STOLEN;
		}


		responder_seq = get_random_u32();
		spin_lock_bh(&new_flow->lock);
		new_flow->seq = responder_seq;
		new_flow->ack = ntohl(view.tcp->seq) + 1;
		new_flow->last_ack = new_flow->ack;
		new_flow->local_isn = responder_seq;
		new_flow->peer_syn_next = new_flow->ack;
		spin_unlock_bh(&new_flow->lock);


		ret = pht_flow_insert(&phantun_flows, new_flow);
		if (ret) {
			pht_flow_put(new_flow);
			return NF_STOLEN;
		}


		ret = phantun_send_synack(new_flow, state->net);
		if (ret) {
			pht_pr_warn("failed to emit SYN|ACK: %d\n", ret);
			pht_flow_remove(new_flow);
		}
		return NF_STOLEN;
	}


	spin_lock_bh(&flow->lock);
	state_now = flow->state;
	expected_ack = flow->local_isn + 1;
	local_is_low = flow->local_is_low;
	had_queued = flow->queued_skb != NULL;
	spin_unlock_bh(&flow->lock);


	if (view.tcp->rst) {
		pht_flow_remove(flow);
		pht_flow_put(flow);
		return NF_STOLEN;
	}


	if (state_now == PHT_FLOW_STATE_SYN_SENT) {
		if (view.tcp->syn && !view.tcp->ack && view.payload_len == 0) {
			if (local_is_low) {
				pht_pr_info("collision on tuple; keeping initiator role\n");
				pht_flow_touch(flow);
				pht_flow_put(flow);
				return NF_STOLEN;
			}


			pht_pr_info("collision on tuple; switching to responder role\n");
			queued_skb = pht_flow_take_queued_skb(flow);
			pht_flow_remove(flow);
			pht_flow_put(flow);


			if (ntohl(view.tcp->seq) % 4095U != 0) {
				ret = phantun_send_rstack(state->net, &ep, &view, true);
				if (ret)
					pht_pr_warn("failed to emit RST|ACK for misaligned colliding SYN: %d\n", ret);
				kfree_skb(queued_skb);
				return NF_STOLEN;
			}


			new_flow = pht_flow_create(&phantun_flows, &ep, PHT_FLOW_ROLE_RESPONDER,
					  PHT_FLOW_STATE_SYN_RCVD);
			if (IS_ERR(new_flow)) {
				kfree_skb(queued_skb);
				return NF_STOLEN;
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


			ret = pht_flow_insert(&phantun_flows, new_flow);
			if (ret) {
				pht_flow_put(new_flow);
				return NF_STOLEN;
			}


			ret = phantun_send_synack(new_flow, state->net);
			if (ret) {
				pht_pr_warn("failed to emit SYN|ACK after collision handoff: %d\n", ret);
				pht_flow_remove(new_flow);
			}
			return NF_STOLEN;
		}


		if (view.tcp->syn && view.tcp->ack && view.payload_len == 0 &&
		    ntohl(view.tcp->ack_seq) == expected_ack) {
			spin_lock_bh(&flow->lock);
			flow->ack = ntohl(view.tcp->seq) + 1;
			flow->peer_syn_next = flow->ack;
			flow->last_ack = flow->ack;
			spin_unlock_bh(&flow->lock);
			ret = phantun_send_handshake_request(flow, state->net);
			if (ret) {
				pht_pr_warn("failed to emit handshake request: %d\n", ret);
				pht_flow_remove(flow);
				pht_flow_put(flow);
				return NF_STOLEN;
			}
			pht_flow_update_state(flow, PHT_FLOW_STATE_HS_REQ_SENT);
			pht_flow_put(flow);
			return NF_STOLEN;
		}


		ret = phantun_send_rstack(state->net, &ep, &view, false);
		if (ret)
			pht_pr_warn("failed to emit RST|ACK for unexpected SYN_SENT packet: %d\n", ret);
		pht_flow_remove(flow);
		pht_flow_put(flow);
		return NF_STOLEN;
	}


	if ((state_now == PHT_FLOW_STATE_SYN_RCVD ||
	     state_now == PHT_FLOW_STATE_AWAIT_HS_REQ) &&
	    view.tcp->syn && !view.tcp->ack && view.payload_len == 0) {
		ret = phantun_send_synack(flow, state->net);
		if (ret)
			pht_pr_warn("failed to re-emit SYN|ACK: %d\n", ret);
		pht_flow_put(flow);
		return NF_STOLEN;
	}


	if (state_now == PHT_FLOW_STATE_SYN_RCVD) {
		if (!view.tcp->ack || ntohl(view.tcp->ack_seq) != expected_ack) {
			ret = phantun_send_rstack(state->net, &ep, &view, false);
			if (ret)
				pht_pr_warn("failed to emit RST|ACK for bad final ACK: %d\n", ret);
			pht_flow_remove(flow);
			pht_flow_put(flow);
			return NF_STOLEN;
		}


		spin_lock_bh(&flow->lock);
		flow->seq = flow->local_isn + 1;
		flow->ack = flow->peer_syn_next;
		flow->last_ack = flow->ack;
		spin_unlock_bh(&flow->lock);


		if (view.payload_len == 0) {
			pht_flow_update_state(flow, PHT_FLOW_STATE_AWAIT_HS_REQ);
			pht_flow_put(flow);
			return NF_STOLEN;
		}


		ret = phantun_respond_handshake_request(flow, skb, &view, state->net);
		if (ret == -EPROTO) {
			ret = phantun_send_rstack(state->net, &ep, &view, false);
			if (ret)
				pht_pr_warn("failed to emit RST|ACK for bad combined request: %d\n", ret);
			pht_flow_remove(flow);
			pht_flow_put(flow);
			return NF_STOLEN;
		}
		if (ret) {
			pht_pr_warn("failed to handle combined ACK+handshake request: %d\n", ret);
			pht_flow_remove(flow);
		}
		pht_flow_put(flow);
		return NF_STOLEN;
	}


	if (state_now == PHT_FLOW_STATE_AWAIT_HS_REQ) {
		if (!view.tcp->ack) {
			ret = phantun_send_rstack(state->net, &ep, &view, false);
			if (ret)
				pht_pr_warn("failed to emit RST|ACK in AWAIT_HS_REQ: %d\n", ret);
			pht_flow_remove(flow);
			pht_flow_put(flow);
			return NF_STOLEN;
		}


		if (view.payload_len == 0) {
			if (ntohl(view.tcp->ack_seq) == expected_ack) {
				pht_flow_touch(flow);
				pht_flow_put(flow);
				return NF_STOLEN;
			}
			ret = phantun_send_rstack(state->net, &ep, &view, false);
			if (ret)
				pht_pr_warn("failed to emit RST|ACK for duplicate ACK mismatch: %d\n", ret);
			pht_flow_remove(flow);
			pht_flow_put(flow);
			return NF_STOLEN;
		}


		if (ntohl(view.tcp->ack_seq) != expected_ack) {
			ret = phantun_send_rstack(state->net, &ep, &view, false);
			if (ret)
				pht_pr_warn("failed to emit RST|ACK for bad handshake ACK: %d\n", ret);
			pht_flow_remove(flow);
			pht_flow_put(flow);
			return NF_STOLEN;
		}


		ret = phantun_respond_handshake_request(flow, skb, &view, state->net);
		if (ret == -EPROTO) {
			ret = phantun_send_rstack(state->net, &ep, &view, false);
			if (ret)
				pht_pr_warn("failed to emit RST|ACK for bad delayed request: %d\n", ret);
			pht_flow_remove(flow);
			pht_flow_put(flow);
			return NF_STOLEN;
		}
		if (ret) {
			pht_pr_warn("failed to handle delayed handshake request: %d\n", ret);
			pht_flow_remove(flow);
		}
		pht_flow_put(flow);
		return NF_STOLEN;
	}


	if (state_now == PHT_FLOW_STATE_HS_REQ_SENT) {
		control_ack = flow->local_isn + 1 + req_len;
		if (view.tcp->syn && view.tcp->ack && view.payload_len == 0 &&
		    ntohl(view.tcp->ack_seq) == expected_ack) {
			ret = phantun_send_handshake_request(flow, state->net);
			if (ret)
				pht_pr_warn("failed to re-emit handshake request: %d\n", ret);
			pht_flow_put(flow);
			return NF_STOLEN;
		}


		if (!view.tcp->ack || ntohl(view.tcp->ack_seq) != control_ack) {
			ret = phantun_send_rstack(state->net, &ep, &view, false);
			if (ret)
				pht_pr_warn("failed to emit RST|ACK for bad handshake response ACK: %d\n", ret);
			pht_flow_remove(flow);
			pht_flow_put(flow);
			return NF_STOLEN;
		}


		if (view.payload_len == 0) {
			pht_flow_touch(flow);
			pht_flow_put(flow);
			return NF_STOLEN;
		}


		if (!phantun_payload_matches(skb, &view, phantun_cfg.handshake_response)) {
			ret = phantun_send_rstack(state->net, &ep, &view, false);
			if (ret)
				pht_pr_warn("failed to emit RST|ACK for bad handshake response payload: %d\n", ret);
			pht_flow_remove(flow);
			pht_flow_put(flow);
			return NF_STOLEN;
		}


		spin_lock_bh(&flow->lock);
		flow->ack = ntohl(view.tcp->seq) + view.payload_len;
		flow->last_ack = flow->ack;
		flow->handshake_flags |= PHT_FLOW_HS_RESP_VERIFIED;
		spin_unlock_bh(&flow->lock);
		pht_flow_update_state(flow, PHT_FLOW_STATE_ESTABLISHED);
		ret = phantun_flush_queued_udp(flow, state->net);
		if (!ret && !had_queued)
			ret = phantun_send_idle_ack(flow, state->net);
		if (ret) {
			pht_pr_warn("failed to finalize initiator handshake: %d\n", ret);
			pht_flow_remove(flow);
		}
		pht_flow_put(flow);
		return NF_STOLEN;
	}

	if (state_now == PHT_FLOW_STATE_HS_RESP_SENT) {
		control_ack = flow->local_isn + 1 + resp_len;
		if (view.payload_len == req_len &&
		    phantun_payload_matches(skb, &view, phantun_cfg.handshake_request)) {
			ret = phantun_send_handshake_response(flow, state->net);
			if (ret)
				pht_pr_warn("failed to re-emit handshake response: %d\n", ret);
			pht_flow_put(flow);
			return NF_STOLEN;
		}

		if (!view.tcp->ack || ntohl(view.tcp->ack_seq) < control_ack) {
			if (view.payload_len == 0) {
				pht_flow_touch(flow);
				pht_flow_put(flow);
				return NF_STOLEN;
			}
			ret = phantun_send_rstack(state->net, &ep, &view, false);
			if (ret)
				pht_pr_warn("failed to emit RST|ACK for pre-ack payload after response: %d\n", ret);
			pht_flow_remove(flow);
			pht_flow_put(flow);
			return NF_STOLEN;
		}

		pht_flow_update_state(flow, PHT_FLOW_STATE_ESTABLISHED);
		ret = phantun_finalize_established_rx(flow, &ep, skb, &view, state->net,
						  in_dev, false);
		if (ret) {
			pht_pr_warn("failed to finalize HS_RESP_SENT transition: %d\n", ret);
			pht_flow_remove(flow);
		}
		pht_flow_put(flow);
		return NF_STOLEN;
	}

	if (state_now == PHT_FLOW_STATE_ESTABLISHED) {
		if (view.payload_len == 0) {
			pht_flow_touch(flow);
			pht_flow_put(flow);
			return NF_STOLEN;
		}

		ret = phantun_finalize_established_rx(flow, &ep, skb, &view, state->net,
						  in_dev, true);
		if (ret) {
			pht_pr_warn("failed to process established inbound payload: %d\n", ret);
			pht_flow_remove(flow);
		}
		pht_flow_put(flow);
		return NF_STOLEN;
	}

	if (state_now == PHT_FLOW_STATE_DEAD)
		pht_flow_remove(flow);
	pht_flow_put(flow);
	return NF_STOLEN;
}

static struct nf_hook_ops phantun_nf_ops[] = {
	{
		.hook = phantun_local_out,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = PHANTUN_DKMS_CAPTURE_PRIORITY,
	},
	{
		.hook = phantun_pre_routing,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = PHANTUN_DKMS_CAPTURE_PRIORITY,
	},
};

static int phantun_validate_config(void)
{
	if (!managed_ports_count) {
		pht_pr_err("at least one managed_ports entry is required\n");
		return -EINVAL;
	}

	if (!handshake_request || !strlen(handshake_request)) {
		pht_pr_err("handshake_request must be set and non-empty\n");
		return -EINVAL;
	}

	if (!handshake_response || !strlen(handshake_response)) {
		pht_pr_err("handshake_response must be set and non-empty\n");
		return -EINVAL;
	}

	if (!handshake_timeout_ms) {
		pht_pr_err("handshake_timeout_ms must be greater than zero\n");
		return -EINVAL;
	}

	if (!handshake_retries) {
		pht_pr_err("handshake_retries must be greater than zero\n");
		return -EINVAL;
	}

	if (!idle_timeout_sec) {
		pht_pr_err("idle_timeout_sec must be greater than zero\n");
		return -EINVAL;
	}

	return 0;
}

static void phantun_snapshot_config(void)
{
	unsigned int i;

	memset(&phantun_cfg, 0, sizeof(phantun_cfg));
	phantun_cfg.managed_ports_count = managed_ports_count;
	for (i = 0; i < managed_ports_count; i++)
		phantun_cfg.managed_ports[i] = managed_ports[i];
	phantun_cfg.handshake_request = handshake_request;
	phantun_cfg.handshake_response = handshake_response;
	phantun_cfg.handshake_request_len = strlen(handshake_request);
	phantun_cfg.handshake_response_len = strlen(handshake_response);
	phantun_cfg.handshake_timeout_ms = handshake_timeout_ms;
	phantun_cfg.handshake_retries = handshake_retries;
	phantun_cfg.idle_timeout_sec = idle_timeout_sec;
	phantun_cfg.remote_ipv4_cidr = remote_ipv4_cidr;
	phantun_cfg.remote_port = remote_port;
}

static void phantun_log_config(void)
{
	unsigned int i;

	pht_pr_info("loading with %u managed port(s), handshake_timeout_ms=%u, handshake_retries=%u, idle_timeout_sec=%u\n",
		    phantun_cfg.managed_ports_count,
		    phantun_cfg.handshake_timeout_ms,
		    phantun_cfg.handshake_retries,
		    phantun_cfg.idle_timeout_sec);

	for (i = 0; i < phantun_cfg.managed_ports_count; i++)
		pht_pr_info("managed_ports[%u]=%u\n", i,
			    phantun_cfg.managed_ports[i]);

	if (phantun_cfg.remote_ipv4_cidr)
		pht_pr_info("remote_ipv4_cidr=%s\n",
			    phantun_cfg.remote_ipv4_cidr);
	if (phantun_cfg.remote_port)
		pht_pr_info("remote_port=%u\n", phantun_cfg.remote_port);
}

static int __init phantun_init(void)
{
	int ret;

	ret = phantun_validate_config();
	if (ret)
		return ret;

	phantun_snapshot_config();
	phantun_log_config();

	ret = pht_flow_table_init(&phantun_flows, &init_net, &phantun_cfg);
	if (ret) {
		pht_pr_err("failed to initialize flow table: %d\n", ret);
		return ret;
	}

	ret = nf_register_net_hooks(&init_net, phantun_nf_ops,
				    ARRAY_SIZE(phantun_nf_ops));
	if (ret) {
		pht_pr_err("failed to register netfilter hooks: %d\n", ret);
		pht_flow_table_destroy(&phantun_flows);
		return ret;
	}

	pht_pr_info("registered IPv4 LOCAL_OUT and PRE_ROUTING hooks\n");
	return 0;
}

static void __exit phantun_exit(void)
{
	nf_unregister_net_hooks(&init_net, phantun_nf_ops,
				 ARRAY_SIZE(phantun_nf_ops));
	pht_flow_table_destroy(&phantun_flows);
	pht_pr_info("unregistered netfilter hooks\n");
}

module_init(phantun_init);
module_exit(phantun_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OpenAI");
MODULE_DESCRIPTION("Kernel-mode Phantun skeleton");
MODULE_VERSION("0.1.0");
