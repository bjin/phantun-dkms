// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef PHANTUN_FLOW_H
#define PHANTUN_FLOW_H

#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/refcount.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include "phantun.h"
#include "phantun_packet.h"

#define PHT_FLOW_BUCKETS 256U
#define PHT_FLOW_GC_INTERVAL_SEC 30U

/* Role is per flow generation, not per node. */
enum pht_flow_role {
    /* Local outbound UDP created the flow and emitted the opening SYN. */
    PHT_FLOW_ROLE_INITIATOR = 0,
    /* Inbound bare SYN created the flow and this host answered with SYN|ACK. */
    PHT_FLOW_ROLE_RESPONDER,
};

enum pht_flow_state {
    /* Local SYN sent; waiting for a valid SYN|ACK or a tie-break SYN collision. */
    PHT_FLOW_STATE_SYN_SENT = 0,
    /* Remote bare SYN accepted; SYN|ACK sent; waiting for the final ACK. */
    PHT_FLOW_STATE_SYN_RCVD,
    /* Three-way handshake complete; UDP <-> fake-TCP translation is live. */
    PHT_FLOW_STATE_ESTABLISHED,
    /* Local tombstone while detach/GC drops ownership and outstanding refs. */
    PHT_FLOW_STATE_DEAD,
};

/* Canonical tuple key: endpoints are sorted lexicographically so outbound UDP
 * creation and inbound bare SYN handling land in the same flow slot.
 */
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
    /*
     * lock protects mutable protocol state: state/seq/ack tracking,
     * quarantine/drop-next shaping flags, the one-skb queue, retry counters,
     * timestamps, and retransmit bookkeeping.
     *
     * It does not protect refs, hash/list membership, the timer object itself,
     * or immutable identity/config fields set at create time.
     */
    spinlock_t lock;
    /* Serializes established-state transmit so flow->seq reservation and
     * rollback happen in wire order. This supplements, not replaces, @lock.
     */
    spinlock_t tx_lock;
    struct hlist_node hnode;
    struct list_head gc_node;
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
    /* Next remote sequence immediately after the peer's opening SYN. */
    u32 peer_syn_next;
    /* Sequence window of the immediately previous generation on this tuple.
     * Used only to absorb delayed packets after ESTABLISHED accepts a
     * replacement bare SYN.
     */
    u32 quarantine_prev_local_seq_start;
    u32 quarantine_prev_local_seq_end;
    u32 quarantine_prev_remote_seq_start;
    u32 quarantine_prev_remote_seq_end;
    /* Bounded one-skb queue used while a flow is half-open or responder data
     * is waiting for the injected handshake_response to clear.
     */
    struct sk_buff *queued_skb;
    unsigned int retries_done;
    unsigned int max_retries;
    unsigned long last_activity_jiffies;
    unsigned long last_inbound_jiffies;
    unsigned long retransmit_at_jiffies;
    unsigned long quarantine_until_jiffies;
    unsigned int keepalives_sent;
    /* Last successful routed egress device toward the remote peer. Used only
     * for best-effort invalidation when that device goes away.
     */
    int egress_ifindex;
    /* True when the local endpoint occupies key.low_{addr,port}. */
    bool local_is_low;
    /* Optional first-payload shaping state. drop_next_rx_* suppresses exactly
     * one reserved inbound payload sequence; response_pending_ack blocks
     * responder-owned local UDP until the injected response is ACKed or
     * bypassed by later initiator traffic.
     */
    u32 drop_next_rx_seq;
    bool drop_next_rx_payload;
    bool response_pending_ack;
    bool retransmit_armed;
    bool quarantine_prev_active;
    bool half_open_tracked;
    /* Latched GC reason for the generation that just died. */
    bool hard_expired;
    bool liveness_failed;
};

struct pht_flow_bucket {
    spinlock_t lock;
    struct hlist_head head;
};

struct pht_flow_table {
    struct pht_flow_bucket buckets[PHT_FLOW_BUCKETS];
    struct delayed_work gc_work;
    unsigned long keepalive_interval_jiffies;
    unsigned long hard_idle_timeout_jiffies;
    unsigned long handshake_timeout_jiffies;
    unsigned long gc_interval_jiffies;
    unsigned int keepalive_misses;
    unsigned int handshake_retries;
    unsigned int reopen_guard_bytes;
    unsigned int half_open_limit;
    unsigned int half_open_current;
    /* Per-table jhash seed keeps bucket selection stable for one table instance
     * while preventing a fixed, attacker-known collision set across netns or
     * module reloads.
     */
    u32 hash_seed;
    /* Serializes half-open admission and exact insert->established/dead
     * accounting so SYN_SENT/SYN_RCVD pressure is bounded per netns.
     */
    spinlock_t half_open_lock;
    struct net *net;
    const struct phantun_config *cfg;
};

bool pht_flow_key_equal(const struct pht_flow_key *a, const struct pht_flow_key *b);
void pht_flow_key_from_endpoints(struct pht_flow_key *key, const struct pht_ipv4_endpoint_pair *ep,
                                 bool *local_is_low);
bool pht_flow_state_is_half_open(enum pht_flow_state state);

int pht_flow_table_init(struct pht_flow_table *table, struct net *net,
                        const struct phantun_config *cfg);
void pht_flow_table_destroy(struct pht_flow_table *table);

struct pht_flow *pht_flow_lookup(struct pht_flow_table *table, const struct pht_flow_key *key);
struct pht_flow *pht_flow_lookup_oriented(struct pht_flow_table *table,
                                          const struct pht_ipv4_endpoint_pair *ep);
struct pht_flow *pht_flow_create(struct pht_flow_table *table,
                                 const struct pht_ipv4_endpoint_pair *ep, enum pht_flow_role role,
                                 enum pht_flow_state state);
int pht_flow_insert(struct pht_flow_table *table, struct pht_flow *flow);
void pht_flow_remove(struct pht_flow *flow);
void pht_flow_detach(struct pht_flow *flow);

void pht_flow_get(struct pht_flow *flow);
void pht_flow_put(struct pht_flow *flow);
void pht_flow_touch(struct pht_flow *flow);
void pht_flow_touch_inbound(struct pht_flow *flow);
void pht_flow_set_egress_ifindex(struct pht_flow *flow, int ifindex);
bool pht_flow_queue_skb_if_empty(struct pht_flow *flow, struct sk_buff *skb);
void pht_flow_set_queued_skb(struct pht_flow *flow, struct sk_buff *skb);
struct sk_buff *pht_flow_take_queued_skb(struct pht_flow *flow);
void pht_flow_update_state(struct pht_flow *flow, enum pht_flow_state state);
void pht_flow_arm_retransmit(struct pht_flow *flow);
void pht_flow_cancel_retransmit(struct pht_flow *flow);
unsigned int pht_flow_invalidate_egress_ifindex(struct pht_flow_table *table, int ifindex);
unsigned int pht_flow_invalidate_local_addr(struct pht_flow_table *table, __be32 local_addr);

#endif
