#include <linux/errno.h>
#include <linux/jhash.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <net/ip.h>
#include <net/route.h>

#include "phantun_flow.h"
#include "phantun_stats.h"
#include "phantun_packet.h"
static u32 pht_flow_hash_key(const struct pht_flow_key *key)
{
	return jhash(key, sizeof(*key), 0) & (PHT_FLOW_BUCKETS - 1);
}

static int pht_endpoint_cmp(__be32 addr_a, __be16 port_a, __be32 addr_b,
			    __be16 port_b)
{
	if (ntohl(addr_a) < ntohl(addr_b))
		return -1;
	if (ntohl(addr_a) > ntohl(addr_b))
		return 1;
	if (ntohs(port_a) < ntohs(port_b))
		return -1;
	if (ntohs(port_a) > ntohs(port_b))
		return 1;
	return 0;
}

static void pht_flow_free(struct pht_flow *flow)
{
	kfree_skb(flow->queued_skb);
	kfree(flow);
}

static int pht_flow_send_local_rst(struct pht_flow *flow)
{
	int ret;

	if (!flow || !flow->table || !flow->table->net)
		return -EINVAL;

	ret = pht_emit_fake_tcp_v4(flow->table->net, &flow->oriented, flow->seq,
				   0, PHT_TCP_FLAG_RST, NULL, 0);
	if (!ret)
		pht_stats_inc(PHT_STAT_RST_SENT);
	return ret;
}

static int pht_flow_retransmit_now(struct pht_flow *flow)
{
	struct pht_ipv4_endpoint_pair ep;
	u32 seq;
	u32 ack;
	enum pht_flow_state state;
	u8 flags = 0;

	if (!flow || !flow->table || !flow->table->net)
		return -EINVAL;
	spin_lock_bh(&flow->lock);
	state = flow->state;
	ep = flow->oriented;
	seq = flow->seq;
	ack = flow->ack;
	if (state == PHT_FLOW_STATE_SYN_SENT) {
		seq = flow->local_isn;
		ack = 0;
		flags = PHT_TCP_FLAG_SYN;
	} else if (state == PHT_FLOW_STATE_SYN_RCVD) {
		seq = flow->local_isn;
		ack = flow->peer_syn_next;
		flags = PHT_TCP_FLAG_SYN | PHT_TCP_FLAG_ACK;
	}
	spin_unlock_bh(&flow->lock);

	if (!flags)
		return 0;

	return pht_emit_fake_tcp_v4(flow->table->net, &ep, seq, ack, flags,
				    NULL, 0);
}

static void pht_flow_gc_worker(struct work_struct *work);

static void pht_flow_retransmit_timer(struct timer_list *timer)
{
	struct pht_flow *flow =
		timer_container_of(flow, timer, retransmit_timer);
	unsigned long next;

	spin_lock_bh(&flow->lock);
	if (!flow->retransmit_armed ||
	    !pht_flow_state_is_half_open(flow->state) ||
	    flow->state == PHT_FLOW_STATE_DEAD) {
		flow->retransmit_armed = false;
		spin_unlock_bh(&flow->lock);
		pht_flow_put(flow);
		return;
	}

	if (flow->retries_done >= flow->max_retries) {
		flow->state = PHT_FLOW_STATE_DEAD;
		flow->retransmit_armed = false;
		spin_unlock_bh(&flow->lock);
		pht_flow_send_local_rst(flow);
		pht_flow_put(flow);
		return;
	}

	flow->retries_done++;
	next = jiffies + flow->table->handshake_timeout_jiffies;
	flow->retransmit_at_jiffies = next;
	spin_unlock_bh(&flow->lock);

	if (pht_flow_retransmit_now(flow))
		pht_pr_warn("failed to retransmit half-open flow packet\n");

	spin_lock_bh(&flow->lock);
	if (!flow->retransmit_armed ||
	    !pht_flow_state_is_half_open(flow->state) ||
	    flow->state == PHT_FLOW_STATE_DEAD) {
		flow->retransmit_armed = false;
		spin_unlock_bh(&flow->lock);
		pht_flow_put(flow);
		return;
	}
	spin_unlock_bh(&flow->lock);

	pht_pr_debug("half-open flow retry %u/%u scheduled\n",
		     flow->retries_done, flow->max_retries);
	mod_timer(&flow->retransmit_timer, next);
}

static void pht_flow_shutdown_retransmit_sync(struct pht_flow *flow)
{
	bool drop_ref = false;

	if (!flow)
		return;

	timer_shutdown_sync(&flow->retransmit_timer);
	spin_lock_bh(&flow->lock);
	if (flow->retransmit_armed) {
		flow->retransmit_armed = false;
		drop_ref = true;
	}
	spin_unlock_bh(&flow->lock);

	if (drop_ref)
		pht_flow_put(flow);
}

bool pht_flow_key_equal(const struct pht_flow_key *a,
			const struct pht_flow_key *b)
{
	return !memcmp(a, b, sizeof(*a));
}

void pht_flow_key_from_endpoints(struct pht_flow_key *key,
				 const struct pht_ipv4_endpoint_pair *ep,
				 bool *local_is_low)
{
	bool is_low;
	int cmp;

	cmp = pht_endpoint_cmp(ep->local_addr, ep->local_port, ep->remote_addr,
			       ep->remote_port);
	is_low = cmp <= 0;

	if (is_low) {
		key->low_addr = ep->local_addr;
		key->low_port = ep->local_port;
		key->high_addr = ep->remote_addr;
		key->high_port = ep->remote_port;
	} else {
		key->low_addr = ep->remote_addr;
		key->low_port = ep->remote_port;
		key->high_addr = ep->local_addr;
		key->high_port = ep->local_port;
	}

	if (local_is_low)
		*local_is_low = is_low;
}

bool pht_flow_state_is_half_open(enum pht_flow_state state)
{
	switch (state) {
	case PHT_FLOW_STATE_SYN_SENT:
	case PHT_FLOW_STATE_SYN_RCVD:
		return true;
	default:
		return false;
	}
}

int pht_flow_table_init(struct pht_flow_table *table, struct net *net,
			const struct phantun_config *cfg)
{
	unsigned int i;

	if (!table || !cfg)
		return -EINVAL;

	memset(table, 0, sizeof(*table));
	for (i = 0; i < PHT_FLOW_BUCKETS; i++) {
		spin_lock_init(&table->buckets[i].lock);
		INIT_HLIST_HEAD(&table->buckets[i].head);
	}

	table->handshake_timeout_jiffies =
		msecs_to_jiffies(cfg->handshake_timeout_ms);
	table->keepalive_interval_jiffies =
		msecs_to_jiffies(cfg->keepalive_interval_sec * 1000U);
	table->keepalive_misses = cfg->keepalive_misses;
	table->hard_idle_timeout_jiffies =
		msecs_to_jiffies(cfg->hard_idle_timeout_sec * 1000U);
	table->reopen_guard_bytes = cfg->reopen_guard_bytes;
	table->gc_interval_jiffies =
		msecs_to_jiffies(PHT_FLOW_GC_INTERVAL_SEC * 1000U);
	if (table->keepalive_interval_jiffies > 0) {
		unsigned long min_gc = table->keepalive_interval_jiffies / 2;
		if (min_gc < table->gc_interval_jiffies)
			table->gc_interval_jiffies = min_gc;
		if (table->gc_interval_jiffies == 0)
			table->gc_interval_jiffies = 1;
	}
	table->handshake_retries = cfg->handshake_retries;
	table->net = net;
	table->cfg = cfg;
	INIT_DELAYED_WORK(&table->gc_work, pht_flow_gc_worker);
	schedule_delayed_work(&table->gc_work, table->gc_interval_jiffies);
	return 0;
}

static void pht_flow_detach_all(struct pht_flow_table *table,
				struct list_head *expired)

{
	unsigned int i;

	for (i = 0; i < PHT_FLOW_BUCKETS; i++) {
		struct pht_flow_bucket *bucket = &table->buckets[i];
		struct pht_flow *flow;
		struct hlist_node *tmp;

		spin_lock_bh(&bucket->lock);
		hlist_for_each_entry_safe(flow, tmp, &bucket->head, hnode)
		{
			hlist_del_init(&flow->hnode);
			spin_lock(&flow->lock);
			flow->state = PHT_FLOW_STATE_DEAD;
			spin_unlock(&flow->lock);
			list_add_tail(&flow->gc_node, expired);
		}
		spin_unlock_bh(&bucket->lock);
	}
}

static bool pht_flow_gc_detach_expired(struct pht_flow_table *table,
				       struct list_head *expired,
				       struct sk_buff_head *reinject_list)
{
	unsigned int i;
	unsigned long now = jiffies;
	bool found = false;

	for (i = 0; i < PHT_FLOW_BUCKETS; i++) {
		struct pht_flow_bucket *bucket = &table->buckets[i];
		struct pht_flow *flow;
		struct hlist_node *tmp;

		spin_lock_bh(&bucket->lock);
		hlist_for_each_entry_safe(flow, tmp, &bucket->head, hnode)
		{
			bool expired_flow = false;
			bool send_keepalive = false;
			bool is_liveness_failure = false;

			spin_lock(&flow->lock);
			if (flow->state == PHT_FLOW_STATE_DEAD) {
				if (time_after_eq(
					    now,
					    flow->last_activity_jiffies +
						    table->hard_idle_timeout_jiffies)) {
					expired_flow = true;
				}
			} else {
				bool hard_expired = time_after_eq(
					now,
					flow->last_activity_jiffies +
						table->hard_idle_timeout_jiffies);
				bool liveness_failed =
					table->keepalive_interval_jiffies > 0 &&
					time_after_eq(
						now,
						flow->last_inbound_jiffies +
							(table->keepalive_interval_jiffies *
							 table->keepalive_misses));
				if (hard_expired) {
					expired_flow = true;
					flow->hard_expired = true;
				} else if (liveness_failed) {
					expired_flow = true;
					flow->state = PHT_FLOW_STATE_DEAD;
					flow->liveness_failed = true;
					is_liveness_failure = true;
				} else if (
					table->keepalive_interval_jiffies > 0 &&
					time_after_eq(
						now,
						flow->last_inbound_jiffies +
							table->keepalive_interval_jiffies *
								(flow->keepalives_sent +
								 1))) {
					send_keepalive = true;
					flow->keepalives_sent++;
				}
			}

			if (expired_flow)
				flow->state = PHT_FLOW_STATE_DEAD;
			spin_unlock(&flow->lock);

			if (is_liveness_failure) {
				struct sk_buff *queued_skb;

				queued_skb = pht_flow_take_queued_skb(flow);
				if (queued_skb)
					__skb_queue_tail(reinject_list,
							 queued_skb);
			}

			if (send_keepalive && !expired_flow &&
			    !is_liveness_failure) {
				/* Send a pure ACK as keepalive */
				spin_lock(&flow->lock);
				if (flow->table && flow->table->net) {
					pht_emit_fake_tcp_v4(
						flow->table->net,
						&flow->oriented, flow->seq,
						flow->ack, PHT_TCP_FLAG_ACK,
						NULL, 0);
				}
				spin_unlock(&flow->lock);
			}

			if (!expired_flow)
				continue;

			hlist_del_init(&flow->hnode);
			list_add_tail(&flow->gc_node, expired);
			found = true;
		}
		spin_unlock_bh(&bucket->lock);
	}

	return found;
}

static void pht_flow_gc_worker(struct work_struct *work)
{
	struct pht_flow_table *table = container_of(
		to_delayed_work(work), struct pht_flow_table, gc_work);
	LIST_HEAD(expired);
	struct sk_buff_head reinject_list;
	struct sk_buff *skb;
	struct pht_flow *flow;
	struct pht_flow *tmp;

	__skb_queue_head_init(&reinject_list);

	pht_flow_gc_detach_expired(table, &expired, &reinject_list);
	list_for_each_entry_safe(flow, tmp, &expired, gc_node)
	{
		list_del_init(&flow->gc_node);
		pht_flow_shutdown_retransmit_sync(flow);
		pht_flow_put(flow);
	}

	while ((skb = __skb_dequeue(&reinject_list)) != NULL) {
		if (table->net)
			ip_local_out(table->net, NULL, skb);
		else
			kfree_skb(skb);
	}

	schedule_delayed_work(&table->gc_work, table->gc_interval_jiffies);
}

void pht_flow_table_destroy(struct pht_flow_table *table)
{
	LIST_HEAD(expired);
	struct pht_flow *flow;
	struct pht_flow *tmp;

	if (!table)
		return;

	cancel_delayed_work_sync(&table->gc_work);
	pht_flow_detach_all(table, &expired);

	list_for_each_entry_safe(flow, tmp, &expired, gc_node)
	{
		list_del_init(&flow->gc_node);
		pht_flow_send_local_rst(flow);
		pht_flow_shutdown_retransmit_sync(flow);
		pht_flow_put(flow);
	}
}

void pht_flow_get(struct pht_flow *flow)
{
	refcount_inc(&flow->refs);
}

void pht_flow_put(struct pht_flow *flow)
{
	if (flow && refcount_dec_and_test(&flow->refs))
		pht_flow_free(flow);
}

struct pht_flow *pht_flow_lookup(struct pht_flow_table *table,
				 const struct pht_flow_key *key)
{
	struct pht_flow_bucket *bucket;
	struct pht_flow *flow;
	u32 idx;

	if (!table || !key)
		return NULL;

	idx = pht_flow_hash_key(key);
	bucket = &table->buckets[idx];
	spin_lock_bh(&bucket->lock);
	hlist_for_each_entry(flow, &bucket->head, hnode)
	{
		if (!pht_flow_key_equal(&flow->key, key))
			continue;
		if (!refcount_inc_not_zero(&flow->refs))
			continue;
		spin_unlock_bh(&bucket->lock);
		return flow;
	}
	spin_unlock_bh(&bucket->lock);
	return NULL;
}

struct pht_flow *
pht_flow_lookup_oriented(struct pht_flow_table *table,
			 const struct pht_ipv4_endpoint_pair *ep)
{
	struct pht_flow_key key;

	if (!ep)
		return NULL;

	pht_flow_key_from_endpoints(&key, ep, NULL);
	return pht_flow_lookup(table, &key);
}

struct pht_flow *pht_flow_create(struct pht_flow_table *table,
				 const struct pht_ipv4_endpoint_pair *ep,
				 enum pht_flow_role role,
				 enum pht_flow_state state)
{
	struct pht_flow *flow;

	if (!table || !ep)
		return ERR_PTR(-EINVAL);

	flow = kzalloc(sizeof(*flow), GFP_ATOMIC);
	if (!flow)
		return ERR_PTR(-ENOMEM);

	refcount_set(&flow->refs, 1);
	spin_lock_init(&flow->lock);
	spin_lock_init(&flow->tx_lock);
	INIT_HLIST_NODE(&flow->hnode);
	INIT_LIST_HEAD(&flow->gc_node);
	timer_setup(&flow->retransmit_timer, pht_flow_retransmit_timer, 0);
	flow->table = table;
	flow->oriented = *ep;
	flow->role = role;
	flow->state = state;
	flow->max_retries = table->handshake_retries;
	flow->last_activity_jiffies = jiffies;
	flow->last_inbound_jiffies = jiffies;
	flow->keepalives_sent = 0;
	flow->retransmit_at_jiffies = jiffies;
	flow->retransmit_armed = false;
	pht_flow_key_from_endpoints(&flow->key, ep, &flow->local_is_low);
	return flow;
}

int pht_flow_insert(struct pht_flow_table *table, struct pht_flow *flow)
{
	struct pht_flow_bucket *bucket;
	struct pht_flow *iter;
	u32 idx;

	if (!table || !flow)
		return -EINVAL;

	idx = pht_flow_hash_key(&flow->key);
	bucket = &table->buckets[idx];
	spin_lock_bh(&bucket->lock);
	hlist_for_each_entry(iter, &bucket->head, hnode)
	{
		if (pht_flow_key_equal(&iter->key, &flow->key)) {
			spin_unlock_bh(&bucket->lock);
			return -EEXIST;
		}
	}
	hlist_add_head(&flow->hnode, &bucket->head);
	spin_unlock_bh(&bucket->lock);

	pht_stats_inc(PHT_STAT_FLOWS_CREATED);
	if (pht_flow_state_is_half_open(flow->state))
		pht_flow_arm_retransmit(flow);

	return 0;
}

void pht_flow_detach(struct pht_flow *flow)
{
	struct pht_flow_bucket *bucket;
	u32 idx;
	bool removed = false;

	if (!flow || !flow->table)
		return;

	idx = pht_flow_hash_key(&flow->key);
	bucket = &flow->table->buckets[idx];
	spin_lock_bh(&bucket->lock);
	if (!hlist_unhashed(&flow->hnode)) {
		hlist_del_init(&flow->hnode);
		removed = true;
	}
	spin_unlock_bh(&bucket->lock);

	if (!removed)
		return;

	pht_flow_cancel_retransmit(flow);
	pht_flow_put(flow);
}

void pht_flow_remove(struct pht_flow *flow)
{
	if (!flow)
		return;

	spin_lock_bh(&flow->lock);
	flow->state = PHT_FLOW_STATE_DEAD;
	spin_unlock_bh(&flow->lock);

	pht_flow_cancel_retransmit(flow);
}

void pht_flow_touch_inbound(struct pht_flow *flow)
{
	if (!flow)
		return;

	spin_lock_bh(&flow->lock);
	flow->last_inbound_jiffies = jiffies;
	flow->last_activity_jiffies = jiffies;
	flow->keepalives_sent = 0;
	spin_unlock_bh(&flow->lock);
}

void pht_flow_touch(struct pht_flow *flow)
{
	if (!flow)
		return;

	spin_lock_bh(&flow->lock);
	flow->last_activity_jiffies = jiffies;
	spin_unlock_bh(&flow->lock);
}

bool pht_flow_queue_skb_if_empty(struct pht_flow *flow, struct sk_buff *skb)
{
	bool queued = false;

	if (!flow) {
		kfree_skb(skb);
		return false;
	}

	spin_lock_bh(&flow->lock);
	if (!flow->queued_skb) {
		flow->queued_skb = skb;
		flow->last_activity_jiffies = jiffies;
		queued = true;
	}
	spin_unlock_bh(&flow->lock);

	return queued;
}

void pht_flow_set_queued_skb(struct pht_flow *flow, struct sk_buff *skb)
{
	struct sk_buff *old;

	if (!flow) {
		kfree_skb(skb);
		return;
	}

	spin_lock_bh(&flow->lock);
	old = flow->queued_skb;
	flow->queued_skb = skb;
	spin_unlock_bh(&flow->lock);

	kfree_skb(old);
}

struct sk_buff *pht_flow_take_queued_skb(struct pht_flow *flow)
{
	struct sk_buff *skb;

	if (!flow)
		return NULL;

	spin_lock_bh(&flow->lock);
	skb = flow->queued_skb;
	flow->queued_skb = NULL;
	spin_unlock_bh(&flow->lock);
	return skb;
}

void pht_flow_update_state(struct pht_flow *flow, enum pht_flow_state state)
{
	bool half_open;
	enum pht_flow_state old_state;

	if (!flow)
		return;

	spin_lock_bh(&flow->lock);
	old_state = flow->state;
	flow->state = state;
	flow->last_activity_jiffies = jiffies;
	flow->retries_done = 0;
	half_open = pht_flow_state_is_half_open(state);
	spin_unlock_bh(&flow->lock);

	if (state == PHT_FLOW_STATE_ESTABLISHED &&
	    old_state != PHT_FLOW_STATE_ESTABLISHED)
		pht_stats_inc(PHT_STAT_FLOWS_ESTABLISHED);
	if (half_open)
		pht_flow_arm_retransmit(flow);
	else
		pht_flow_cancel_retransmit(flow);
}

void pht_flow_arm_retransmit(struct pht_flow *flow)
{
	unsigned long when;
	bool take_ref = false;

	if (!flow || !flow->table)
		return;

	spin_lock_bh(&flow->lock);
	if (!pht_flow_state_is_half_open(flow->state) ||
	    flow->state == PHT_FLOW_STATE_DEAD) {
		spin_unlock_bh(&flow->lock);
		return;
	}
	if (!flow->retransmit_armed) {
		flow->retransmit_armed = true;
		take_ref = true;
	}
	when = jiffies + flow->table->handshake_timeout_jiffies;
	flow->retransmit_at_jiffies = when;
	spin_unlock_bh(&flow->lock);

	if (take_ref)
		pht_flow_get(flow);
	mod_timer(&flow->retransmit_timer, when);
}

void pht_flow_cancel_retransmit(struct pht_flow *flow)
{
	bool drop_ref = false;
	int deleted;

	if (!flow)
		return;

	spin_lock_bh(&flow->lock);
	if (flow->retransmit_armed) {
		flow->retransmit_armed = false;
		drop_ref = true;
	}
	spin_unlock_bh(&flow->lock);

	deleted = timer_delete(&flow->retransmit_timer);
	if (deleted > 0 && drop_ref)
		pht_flow_put(flow);
}
