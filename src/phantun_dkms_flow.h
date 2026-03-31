#ifndef PHANTUN_DKMS_FLOW_H
#define PHANTUN_DKMS_FLOW_H

#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/refcount.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include "phantun_dkms.h"
#include "phantun_dkms_packet.h"

#define PHT_FLOW_BUCKETS 256U
#define PHT_FLOW_GC_INTERVAL_SEC 30U

#define PHT_FLOW_HS_REQ_VERIFIED BIT(0)
#define PHT_FLOW_HS_RESP_VERIFIED BIT(1)

enum pht_flow_role {
	PHT_FLOW_ROLE_INITIATOR = 0,
	PHT_FLOW_ROLE_RESPONDER,
};

enum pht_flow_state {
	PHT_FLOW_STATE_SYN_SENT = 0,
	PHT_FLOW_STATE_SYN_RCVD,
	PHT_FLOW_STATE_AWAIT_HS_REQ,
	PHT_FLOW_STATE_HS_REQ_SENT,
	PHT_FLOW_STATE_HS_RESP_SENT,
	PHT_FLOW_STATE_ESTABLISHED,
	PHT_FLOW_STATE_DEAD,
};

struct pht_flow_key {
	__be32 low_addr;
	__be32 high_addr;
	__be16 low_port;
	__be16 high_port;
};

struct net;
struct pht_flow_table;

struct pht_flow {
	refcount_t refs;
	spinlock_t lock;
	struct hlist_node hnode;
	struct list_head gc_node;
	struct work_struct timeout_work;
	struct timer_list retransmit_timer;
	struct pht_flow_table *table;
	struct pht_flow_key key;
	struct pht_ipv4_endpoint_pair oriented;
	enum pht_flow_role role;
	enum pht_flow_state state;
	u32 seq;
	u32 ack;
	u32 last_ack;
	u32 local_isn;
	u32 peer_syn_next;
	struct sk_buff *queued_skb;
	u8 handshake_flags;
	unsigned int retries_done;
	unsigned int max_retries;
	unsigned long last_activity_jiffies;
	unsigned long retransmit_at_jiffies;
	bool local_is_low;
};

struct pht_flow_bucket {
	spinlock_t lock;
	struct hlist_head head;
};

struct pht_flow_table {
	struct pht_flow_bucket buckets[PHT_FLOW_BUCKETS];
	struct delayed_work gc_work;
	unsigned long idle_timeout_jiffies;
	unsigned long handshake_timeout_jiffies;
	unsigned long gc_interval_jiffies;
	unsigned int handshake_retries;
	struct net *net;
	const struct phantun_dkms_config *cfg;
};

bool pht_flow_key_equal(const struct pht_flow_key *a,
		const struct pht_flow_key *b);
void pht_flow_key_from_endpoints(struct pht_flow_key *key,
			 const struct pht_ipv4_endpoint_pair *ep,
			 bool *local_is_low);
bool pht_flow_state_is_half_open(enum pht_flow_state state);

int pht_flow_table_init(struct pht_flow_table *table, struct net *net,
		const struct phantun_dkms_config *cfg);
void pht_flow_table_destroy(struct pht_flow_table *table);

struct pht_flow *pht_flow_lookup(struct pht_flow_table *table,
		 const struct pht_flow_key *key);
struct pht_flow *pht_flow_lookup_oriented(struct pht_flow_table *table,
				  const struct pht_ipv4_endpoint_pair *ep);
struct pht_flow *pht_flow_create(struct pht_flow_table *table,
		 const struct pht_ipv4_endpoint_pair *ep,
		 enum pht_flow_role role,
		 enum pht_flow_state state);
int pht_flow_insert(struct pht_flow_table *table, struct pht_flow *flow);
void pht_flow_remove(struct pht_flow *flow);

void pht_flow_get(struct pht_flow *flow);
void pht_flow_put(struct pht_flow *flow);
void pht_flow_touch(struct pht_flow *flow);
bool pht_flow_queue_skb_if_empty(struct pht_flow *flow, struct sk_buff *skb);
void pht_flow_set_queued_skb(struct pht_flow *flow, struct sk_buff *skb);
struct sk_buff *pht_flow_take_queued_skb(struct pht_flow *flow);
void pht_flow_update_state(struct pht_flow *flow, enum pht_flow_state state);
void pht_flow_arm_retransmit(struct pht_flow *flow);
void pht_flow_cancel_retransmit(struct pht_flow *flow);

#endif
