// SPDX-License-Identifier: GPL-2.0-or-later
//
// Copyright (C) 2026 Bin Jin. All Rights Reserved.
#include <linux/errno.h>
#include <linux/jhash.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <net/dst.h>
#include <net/ip.h>
#include <net/route.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <net/ipv6.h>
#endif

#include "phantun_compat.h" // IWYU pragma: keep

#include "phantun_flow.h"
#include "phantun_packet.h"
#include "phantun_stats.h"

/* Terminal teardown normally frees the full flow immediately. This tiny
 * per-bucket cache is the only state kept behind: enough for local reopen to
 * choose an ISN outside the previous generation's sequence window.
 */
struct pht_retired_flow {
    struct hlist_node hnode;
    struct pht_endpoint_pair endpoints;
    u32 prev_seq;
    unsigned long expires_jiffies;
};

static void pht_flow_tx_dst_cache_init(struct pht_flow_tx_dst_cache *cache);
static void pht_flow_tx_dst_cache_reset(struct pht_flow_tx_dst_cache *cache);
static struct dst_entry *pht_flow_tx_dst_cache_reset_locked(struct pht_flow_tx_dst_cache *cache);

static u32 pht_addr_hash(const struct pht_addr *addr, u32 seed) {
    if (!addr)
        return seed;

    seed = jhash(&addr->family, sizeof(addr->family), seed);
    switch (addr->family) {
    case AF_INET:
        return jhash(&addr->v4, sizeof(addr->v4), seed);
#if IS_ENABLED(CONFIG_IPV6)
    case AF_INET6:
        return jhash(&addr->v6, sizeof(addr->v6), seed);
#endif
    default:
        return seed;
    }
}

static bool pht_addr_equal_local(const struct pht_addr *a, const struct pht_addr *b) {
    if (!a || !b || a->family != b->family)
        return false;

    switch (a->family) {
    case AF_INET:
        return a->v4 == b->v4;
#if IS_ENABLED(CONFIG_IPV6)
    case AF_INET6:
        return ipv6_addr_equal(&a->v6, &b->v6);
#endif
    default:
        return false;
    }
}

static bool pht_endpoint_pair_equal(const struct pht_endpoint_pair *a,
                                    const struct pht_endpoint_pair *b) {
    return a && b && a->local_port == b->local_port && a->remote_port == b->remote_port &&
           a->scope_ifindex == b->scope_ifindex &&
           pht_addr_equal_local(&a->local_addr, &b->local_addr) &&
           pht_addr_equal_local(&a->remote_addr, &b->remote_addr);
}

static u32 pht_flow_hash_key(const struct pht_flow_table *table,
                             const struct pht_endpoint_pair *ep) {
    u32 hash;

    hash = pht_addr_hash(&ep->local_addr, table->hash_seed);
    hash = pht_addr_hash(&ep->remote_addr, hash);
    hash = jhash(&ep->local_port, sizeof(ep->local_port), hash);
    hash = jhash(&ep->remote_port, sizeof(ep->remote_port), hash);
    hash = jhash(&ep->scope_ifindex, sizeof(ep->scope_ifindex), hash);
    return hash & (PHT_FLOW_BUCKETS - 1);
}

static void pht_flow_reset_tx_dst_cache(struct pht_flow *flow) {
    struct dst_entry *dst;

    if (!flow)
        return;

    spin_lock_bh(&flow->lock);
    dst = pht_flow_tx_dst_cache_reset_locked(&flow->tx_dst_cache);
    spin_unlock_bh(&flow->lock);
    dst_release(dst);
}

static void pht_flow_free(struct pht_flow *flow) {
    pht_flow_tx_dst_cache_reset(&flow->tx_dst_cache);
    kfree_skb(flow->queued_skb);
    kfree(flow);
}

static int pht_flow_send_local_rst(struct pht_flow *flow) {
    struct pht_endpoint_pair ep;
    struct pht_tx_meta meta;
    u32 seq;
    int ifindex;
    int ret;

    if (!flow || !flow->table || !flow->table->net)
        return -EINVAL;

    spin_lock_bh(&flow->lock);
    ep = flow->endpoints;
    meta = flow->local_tx_meta;
    seq = flow->seq;
    spin_unlock_bh(&flow->lock);

    ret = pht_emit_fake_tcp(flow->table->net, &ep, seq, 0, PHT_TCP_FLAG_RST, NULL, 0, &meta,
                            &ifindex);
    if (!ret) {
        pht_flow_set_egress_ifindex(flow, ifindex);
        pht_stats_inc(PHT_STAT_RST_SENT);
    }
    return ret;
}

static int pht_flow_retransmit_now(struct pht_flow *flow) {
    struct pht_endpoint_pair ep;
    struct pht_tx_meta meta;
    u32 seq;
    u32 ack;
    enum pht_flow_state state;
    u8 flags = 0;

    if (!flow || !flow->table || !flow->table->net)
        return -EINVAL;
    spin_lock_bh(&flow->lock);
    state = flow->state;
    ep = flow->endpoints;
    meta = flow->local_tx_meta;
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

    {
        int ifindex;
        int ret;

        ret = pht_emit_fake_tcp(flow->table->net, &ep, seq, ack, flags, NULL, 0, &meta, &ifindex);
        if (!ret)
            pht_flow_set_egress_ifindex(flow, ifindex);
        return ret;
    }
}

static bool pht_flow_unhash_and_queue_finalize(struct pht_flow *flow, bool send_rst);
static void pht_flow_queue_finalize(struct pht_flow *flow, bool send_rst);

static void pht_flow_finalize_worker(struct work_struct *work);
static void pht_flow_gc_worker(struct work_struct *work);
static void pht_flow_untrack_half_open(struct pht_flow *flow);

/* Only half-open flows use the retransmit timer. Exhausting the retry budget
 * is a handshake failure, so we fail locally with RST and leave reopen to the
 * normal packet path.
 */
static void pht_flow_retransmit_timer(struct timer_list *timer) {
    struct pht_flow *flow = timer_container_of(flow, timer, retransmit_timer);
    unsigned long next;

    spin_lock_bh(&flow->lock);
    if (!flow->retransmit_armed || !pht_flow_state_is_half_open(flow->state) ||
        flow->state == PHT_FLOW_STATE_DEAD) {
        flow->retransmit_armed = false;
        spin_unlock_bh(&flow->lock);
        pht_flow_put(flow);
        return;
    }

    if (flow->retries_done >= flow->max_retries) {
        flow->state = PHT_FLOW_STATE_DEAD;
        flow->finalize_send_rst = true;
        flow->retransmit_armed = false;
        spin_unlock_bh(&flow->lock);

        pht_stats_inc(PHT_STAT_HANDSHAKE_RETRIES_EXHAUSTED);

        pht_flow_untrack_half_open(flow);
        pht_flow_unhash_and_queue_finalize(flow, true);
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
    if (!flow->retransmit_armed || !pht_flow_state_is_half_open(flow->state) ||
        flow->state == PHT_FLOW_STATE_DEAD) {
        flow->retransmit_armed = false;
        spin_unlock_bh(&flow->lock);
        pht_flow_put(flow);
        return;
    }

    pht_pr_debug("half-open flow retry %u/%u scheduled\n", flow->retries_done, flow->max_retries);
    mod_timer(&flow->retransmit_timer, next);
    spin_unlock_bh(&flow->lock);
}

static void pht_flow_shutdown_retransmit_sync(struct pht_flow *flow) {
    bool drop_ref = false;

    if (!flow)
        return;

    /* Callers mark the flow DEAD before teardown. The callback also re-arms
     * under flow->lock, so once teardown owns the lock it cannot race a final
     * unchecked mod_timer() on old timer_delete_sync()-only kernels.
     */
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

bool pht_flow_state_is_half_open(enum pht_flow_state state) {
    switch (state) {
    case PHT_FLOW_STATE_SYN_SENT:
    case PHT_FLOW_STATE_SYN_RCVD:
        return true;
    default:
        return false;
    }
}

static void pht_flow_untrack_half_open(struct pht_flow *flow) {
    if (!flow || !flow->table)
        return;

    spin_lock_bh(&flow->table->half_open_lock);
    if (flow->half_open_tracked) {
        flow->half_open_tracked = false;
        if (flow->table->half_open_current > 0)
            flow->table->half_open_current--;
    }
    spin_unlock_bh(&flow->table->half_open_lock);
}

static void pht_flow_retired_delete_locked(struct pht_flow_bucket *bucket,
                                           const struct pht_endpoint_pair *ep) {
    struct pht_retired_flow *retired;
    struct hlist_node *tmp;

    hlist_for_each_entry_safe(retired, tmp, &bucket->retired_head, hnode) {
        if (ep && !pht_endpoint_pair_equal(&retired->endpoints, ep))
            continue;

        hlist_del(&retired->hnode);
        kfree(retired);
    }
}

static void pht_flow_retired_purge_expired_locked(struct pht_flow_bucket *bucket,
                                                  unsigned long now) {
    struct pht_retired_flow *retired;
    struct hlist_node *tmp;

    hlist_for_each_entry_safe(retired, tmp, &bucket->retired_head, hnode) {
        if (!time_after_eq(now, retired->expires_jiffies))
            continue;

        hlist_del(&retired->hnode);
        kfree(retired);
    }
}

static void pht_flow_retired_purge_all(struct pht_flow_table *table) {
    unsigned int i;

    if (!table)
        return;

    for (i = 0; i < PHT_FLOW_BUCKETS; i++) {
        struct pht_flow_bucket *bucket = &table->buckets[i];

        spin_lock_bh(&bucket->lock);
        pht_flow_retired_delete_locked(bucket, NULL);
        spin_unlock_bh(&bucket->lock);
    }
}

static void pht_flow_retired_publish_locked(struct pht_flow_bucket *bucket,
                                            struct pht_retired_flow *record,
                                            const struct pht_endpoint_pair *ep, u32 prev_seq,
                                            unsigned long expires_jiffies) {
    struct pht_retired_flow *retired;

    hlist_for_each_entry(retired, &bucket->retired_head, hnode) {
        if (!pht_endpoint_pair_equal(&retired->endpoints, ep))
            continue;

        retired->prev_seq = prev_seq;
        retired->expires_jiffies = expires_jiffies;
        kfree(record);
        return;
    }

    record->endpoints = *ep;
    record->prev_seq = prev_seq;
    record->expires_jiffies = expires_jiffies;
    INIT_HLIST_NODE(&record->hnode);
    hlist_add_head(&record->hnode, &bucket->retired_head);
}

/* Detach callers have already made the flow unreachable from the hash table.
 * Queue the former table reference here; callers keep and release any lookup
 * reference separately. Coalescing is safe because all finalization requests
 * require the same timer shutdown/free path, and send_rst is latched.
 */
static void pht_flow_queue_finalize(struct pht_flow *flow, bool send_rst) {
    struct pht_flow_table *table;
    bool queue = false;

    if (!flow || !flow->table)
        return;

    table = flow->table;
    spin_lock_bh(&flow->lock);
    flow->finalize_send_rst |= send_rst;
    spin_unlock_bh(&flow->lock);

    spin_lock_bh(&table->finalize_lock);
    if (list_empty(&flow->finalize_node)) {
        list_add_tail(&flow->finalize_node, &table->finalize_list);
        queue = true;
    }
    spin_unlock_bh(&table->finalize_lock);

    if (queue)
        queue_work(system_wq, &table->finalize_work);
}

/* Runs only from process context (GC, destroy, or finalize_work). */
static void pht_flow_finalize_one(struct pht_flow *flow) {
    bool send_rst;

    if (!flow)
        return;

    spin_lock_bh(&flow->lock);
    send_rst = flow->finalize_send_rst;
    flow->finalize_send_rst = false;
    spin_unlock_bh(&flow->lock);

    if (send_rst)
        pht_flow_send_local_rst(flow);
    pht_flow_reset_tx_dst_cache(flow);
    pht_flow_shutdown_retransmit_sync(flow);
    pht_flow_put(flow);
}

static void pht_flow_finalize_worker(struct work_struct *work) {
    struct pht_flow_table *table = container_of(work, struct pht_flow_table, finalize_work);

    for (;;) {
        struct pht_flow *flow;

        spin_lock_bh(&table->finalize_lock);
        if (list_empty(&table->finalize_list)) {
            spin_unlock_bh(&table->finalize_lock);
            return;
        }
        flow = list_first_entry(&table->finalize_list, struct pht_flow, finalize_node);
        list_del_init(&flow->finalize_node);
        spin_unlock_bh(&table->finalize_lock);

        pht_flow_finalize_one(flow);
    }
}

int pht_flow_table_init(struct pht_flow_table *table, struct net *net,
                        const struct phantun_config *cfg) {
    unsigned int i;

    if (!table || !cfg)
        return -EINVAL;

    memset(table, 0, sizeof(*table));
    for (i = 0; i < PHT_FLOW_BUCKETS; i++) {
        spin_lock_init(&table->buckets[i].lock);
        INIT_HLIST_HEAD(&table->buckets[i].head);
        INIT_HLIST_HEAD(&table->buckets[i].retired_head);
    }
    spin_lock_init(&table->half_open_lock);
    spin_lock_init(&table->finalize_lock);
    INIT_LIST_HEAD(&table->finalize_list);

    table->handshake_timeout_jiffies = msecs_to_jiffies(cfg->handshake_timeout_ms);
    table->replacement_protect_jiffies = msecs_to_jiffies(cfg->effective_replacement_protect_ms);
    table->keepalive_interval_jiffies = msecs_to_jiffies(cfg->keepalive_interval_sec * 1000U);
    table->keepalive_misses = cfg->keepalive_misses;
    table->hard_idle_timeout_jiffies = msecs_to_jiffies(cfg->hard_idle_timeout_sec * 1000U);
    table->reopen_guard_bytes = cfg->reopen_guard_bytes;
    table->half_open_limit = cfg->half_open_limit;
    table->half_open_current = 0;
    table->hash_seed = get_random_u32();
    table->reinject_mark = get_random_u32() | BIT(31);
    table->gc_interval_jiffies = msecs_to_jiffies(PHT_FLOW_GC_INTERVAL_SEC * 1000U);
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
    INIT_WORK(&table->finalize_work, pht_flow_finalize_worker);
    schedule_delayed_work(&table->gc_work, table->gc_interval_jiffies);
    return 0;
}

static void pht_flow_detach_all(struct pht_flow_table *table, struct list_head *expired)

{
    unsigned int i;

    for (i = 0; i < PHT_FLOW_BUCKETS; i++) {
        struct pht_flow_bucket *bucket = &table->buckets[i];
        struct pht_flow *flow;
        struct hlist_node *tmp;

        spin_lock_bh(&bucket->lock);
        hlist_for_each_entry_safe(flow, tmp, &bucket->head, hnode) {
            hlist_del_init(&flow->hnode);
            pht_stats_dec(PHT_STAT_FLOWS_CURRENT);
            spin_lock(&flow->lock);
            flow->state = PHT_FLOW_STATE_DEAD;
            spin_unlock(&flow->lock);
            pht_flow_untrack_half_open(flow);
            list_add_tail(&flow->gc_node, expired);
        }
        spin_unlock_bh(&bucket->lock);
    }
}

/* GC also drives keepalive/liveness policy. On liveness failure, preserve the
 * single queued outbound UDP skb by reinjecting it through LOCAL_OUT so the
 * next pass can reopen the tuple instead of silently dropping the caller's
 * trigger packet. The matching RST is sent later, after the flow is detached
 * and no bucket or flow lock is held.
 */
static bool pht_flow_gc_detach_expired(struct pht_flow_table *table, struct list_head *expired,
                                       struct list_head *keepalives,
                                       struct sk_buff_head *reinject_list) {
    unsigned int i;
    unsigned long now = jiffies;
    bool found = false;

    for (i = 0; i < PHT_FLOW_BUCKETS; i++) {
        struct pht_flow_bucket *bucket = &table->buckets[i];
        struct pht_flow *flow;
        struct hlist_node *tmp;

        spin_lock_bh(&bucket->lock);
        pht_flow_retired_purge_expired_locked(bucket, now);
        hlist_for_each_entry_safe(flow, tmp, &bucket->head, hnode) {
            bool expired_flow = false;
            bool send_keepalive = false;
            bool is_liveness_failure = false;
            bool established_liveness_failure = false;
            spin_lock(&flow->lock);
            if (flow->state == PHT_FLOW_STATE_DEAD) {
                if (time_after_eq(now,
                                  flow->last_activity_jiffies + table->hard_idle_timeout_jiffies)) {
                    expired_flow = true;
                }
            } else {
                bool hard_expired = time_after_eq(now, flow->last_activity_jiffies +
                                                           table->hard_idle_timeout_jiffies);
                bool liveness_failed = table->keepalive_interval_jiffies > 0 &&
                                       time_after_eq(now, flow->last_inbound_jiffies +
                                                              (table->keepalive_interval_jiffies *
                                                               table->keepalive_misses));
                if (hard_expired) {
                    expired_flow = true;
                    flow->hard_expired = true;
                } else if (liveness_failed) {
                    expired_flow = true;
                    flow->liveness_failed = flow->state == PHT_FLOW_STATE_ESTABLISHED;
                    established_liveness_failure = flow->liveness_failed;
                    flow->state = PHT_FLOW_STATE_DEAD;
                    is_liveness_failure = true;
                } else if (flow->state == PHT_FLOW_STATE_ESTABLISHED &&
                           table->keepalive_interval_jiffies > 0 &&
                           time_after_eq(now, flow->last_inbound_jiffies +
                                                  table->keepalive_interval_jiffies *
                                                      (flow->keepalives_sent + 1))) {
                    send_keepalive = true;
                    flow->keepalives_sent++;
                }
            }

            if (expired_flow)
                flow->state = PHT_FLOW_STATE_DEAD;
            spin_unlock(&flow->lock);

            if (expired_flow)
                pht_flow_untrack_half_open(flow);
            if (established_liveness_failure)
                pht_stats_inc(PHT_STAT_ESTABLISHED_LIVENESS_TIMEOUTS);

            if (is_liveness_failure) {
                struct sk_buff *queued_skb;

                queued_skb = pht_flow_take_queued_skb(flow, NULL);
                if (queued_skb)
                    __skb_queue_tail(reinject_list, queued_skb);
            }

            if (send_keepalive && !expired_flow && !is_liveness_failure) {
                pht_flow_get(flow);
                list_add_tail(&flow->keepalive_node, keepalives);
            }

            if (!expired_flow)
                continue;

            hlist_del_init(&flow->hnode);
            pht_stats_dec(PHT_STAT_FLOWS_CURRENT);
            list_add_tail(&flow->gc_node, expired);
            found = true;
        }
        spin_unlock_bh(&bucket->lock);
    }

    return found;
}

/* Keepalive candidates are collected with a temporary ref while bucket locks
 * are held, then transmitted here lockless. The revalidation after emit avoids
 * writing route state into a detached/replaced generation.
 */
static void pht_flow_emit_keepalives(struct pht_flow_table *table, struct list_head *keepalives) {
    while (!list_empty(keepalives)) {
        struct pht_endpoint_pair ep;
        struct pht_tx_meta meta;
        struct pht_flow *flow = list_first_entry(keepalives, struct pht_flow, keepalive_node);
        u32 seq;
        u32 ack;
        int ifindex;
        int ret;
        bool live;

        list_del_init(&flow->keepalive_node);

        spin_lock_bh(&flow->lock);
        live = flow->state == PHT_FLOW_STATE_ESTABLISHED && flow->table == table;
        if (live) {
            ep = flow->endpoints;
            seq = flow->seq;
            ack = flow->ack;
            meta = flow->local_tx_meta;
        }
        spin_unlock_bh(&flow->lock);

        if (live && table->net) {
            ret = pht_emit_fake_tcp(table->net, &ep, seq, ack, PHT_TCP_FLAG_ACK, NULL, 0, &meta,
                                    &ifindex);
            if (!ret) {
                spin_lock_bh(&flow->lock);
                if (flow->state == PHT_FLOW_STATE_ESTABLISHED && flow->table == table)
                    flow->egress_ifindex = ifindex;
                spin_unlock_bh(&flow->lock);
            }
        }

        pht_flow_put(flow);
    }
}

static void pht_flow_gc_worker(struct work_struct *work) {
    struct pht_flow_table *table =
        container_of(to_delayed_work(work), struct pht_flow_table, gc_work);
    LIST_HEAD(expired);
    LIST_HEAD(keepalives);
    struct sk_buff_head reinject_list;
    struct sk_buff *skb;
    struct pht_flow *flow;
    struct pht_flow *tmp;

    __skb_queue_head_init(&reinject_list);

    pht_flow_gc_detach_expired(table, &expired, &keepalives, &reinject_list);
    pht_flow_emit_keepalives(table, &keepalives);
    list_for_each_entry_safe(flow, tmp, &expired, gc_node) {
        bool send_liveness_rst;

        list_del_init(&flow->gc_node);
        spin_lock_bh(&flow->lock);
        send_liveness_rst = flow->liveness_failed;
        flow->finalize_send_rst |= send_liveness_rst;
        spin_unlock_bh(&flow->lock);
        pht_flow_finalize_one(flow);
    }

    while ((skb = __skb_dequeue(&reinject_list)) != NULL) {
        if (!table->net) {
            kfree_skb(skb);
            continue;
        }

        switch (ntohs(skb->protocol)) {
        case ETH_P_IP:
            ip_local_out(table->net, NULL, skb);
            break;
#if IS_ENABLED(CONFIG_IPV6)
        case ETH_P_IPV6:
            ip6_local_out(table->net, NULL, skb);
            break;
#endif
        default:
            kfree_skb(skb);
            break;
        }
    }

    schedule_delayed_work(&table->gc_work, table->gc_interval_jiffies);
}

void pht_flow_table_destroy(struct pht_flow_table *table) {
    LIST_HEAD(expired);
    struct pht_flow *flow;
    struct pht_flow *tmp;

    if (!table)
        return;

    cancel_delayed_work_sync(&table->gc_work);
    flush_work(&table->finalize_work);
    pht_flow_detach_all(table, &expired);
    pht_flow_retired_purge_all(table);

    list_for_each_entry_safe(flow, tmp, &expired, gc_node) {
        list_del_init(&flow->gc_node);
        spin_lock_bh(&flow->lock);
        flow->finalize_send_rst = true;
        spin_unlock_bh(&flow->lock);
        pht_flow_finalize_one(flow);
    }

    /* A retransmit callback can race the first flush and queue finalization
     * while destroy is detaching still-hashed flows. The loop above has shut
     * those timers down, so a second flush drains the last table-owned refs
     * before netns storage can disappear.
     */
    flush_work(&table->finalize_work);
}

void pht_flow_get(struct pht_flow *flow) { refcount_inc(&flow->refs); }

void pht_flow_put(struct pht_flow *flow) {
    if (flow && refcount_dec_and_test(&flow->refs))
        pht_flow_free(flow);
}

/*
 * tx_dst_cache refcount invariant:
 * - cache owns exactly one dst reference while valid;
 * - a cache hit calls dst_check() and dst_hold() under flow->lock for the skb;
 * - a miss performs fresh lookup without holding flow->lock;
 * - successful publish transfers the lookup reference into the cache and uses
 *   dst_clone() for the skb;
 * - reset/replacement returns the old cache ref and releases it after unlock.
 */
static void pht_flow_tx_dst_cache_init(struct pht_flow_tx_dst_cache *cache) {
    if (!cache)
        return;

    memset(cache, 0, sizeof(*cache));
}

static struct dst_entry *pht_flow_tx_dst_cache_reset_locked(struct pht_flow_tx_dst_cache *cache) {
    struct dst_entry *old;

    if (!cache)
        return NULL;

    old = cache->dst;
    cache->dst = NULL;
    memset(&cache->key, 0, sizeof(cache->key));
    cache->cookie = 0;
    cache->ifindex = 0;
    cache->valid = false;
    return old;
}

static void pht_flow_tx_dst_cache_reset(struct pht_flow_tx_dst_cache *cache) {
    struct dst_entry *old = pht_flow_tx_dst_cache_reset_locked(cache);

    dst_release(old);
}

static struct dst_entry *pht_flow_tx_dst_cache_get_locked(struct pht_flow_tx_dst_cache *cache,
                                                          const struct pht_tx_route_key *key,
                                                          struct dst_entry **stale_dst,
                                                          int *out_ifindex) {
    struct dst_entry *dst;

    if (stale_dst)
        *stale_dst = NULL;
    if (out_ifindex)
        *out_ifindex = 0;
    if (!cache || !cache->valid || !cache->dst || !pht_tx_route_key_equal(&cache->key, key))
        return NULL;

    dst = dst_check(cache->dst, cache->cookie);
    if (!dst) {
        dst = pht_flow_tx_dst_cache_reset_locked(cache);
        if (stale_dst)
            *stale_dst = dst;
        else
            dst_release(dst);
        return NULL;
    }

    dst_hold(dst);
    if (out_ifindex)
        *out_ifindex = cache->ifindex;
    return dst;
}

static struct dst_entry *
pht_flow_tx_dst_cache_store_locked(struct pht_flow_tx_dst_cache *cache,
                                   const struct pht_tx_route_key *key,
                                   const struct pht_tx_route_result *route) {
    struct dst_entry *old;

    if (!cache || !key || !route || !route->dst)
        return NULL;

    old = cache->dst;
    cache->dst = route->dst;
    cache->key = *key;
    cache->cookie = route->cookie;
    cache->ifindex = route->ifindex;
    cache->valid = true;
    return old;
}

static bool pht_flow_tx_cache_key_matches_flow_locked(const struct pht_flow *flow,
                                                      const struct pht_tx_route_key *key) {
    struct pht_endpoint_pair ep;

    if (!flow || !key)
        return false;

    ep.local_addr = key->local_addr;
    ep.remote_addr = key->remote_addr;
    ep.local_port = key->local_port;
    ep.remote_port = key->remote_port;
    ep.scope_ifindex = key->scope_ifindex;
    return pht_endpoint_pair_equal(&flow->endpoints, &ep);
}

static bool pht_flow_tx_cache_generation_matches_locked(const struct pht_flow *flow,
                                                        const struct pht_tx_route_key *key) {
    return flow && flow->state == PHT_FLOW_STATE_ESTABLISHED &&
           pht_flow_tx_cache_key_matches_flow_locked(flow, key);
}

int pht_flow_emit_established_payload(struct pht_flow *flow, struct net *net,
                                      const struct pht_endpoint_pair *ep, u32 seq, u32 ack,
                                      const struct sk_buff *src, unsigned int payload_offset,
                                      size_t payload_len, const struct pht_tx_meta *meta,
                                      int *out_ifindex) {
    struct pht_tx_route_result route;
    struct pht_tx_route_key key;
    struct dst_entry *old_dst = NULL;
    struct dst_entry *send_dst;
    struct sk_buff *skb;
    int ifindex = 0;
    int ret;

    if (out_ifindex)
        *out_ifindex = 0;
    if (!flow || !net || !ep)
        return -EINVAL;

    ret = pht_prepare_fake_tcp_ack_payload_from_skb(ep, seq, ack, src, payload_offset, payload_len,
                                                    meta, &skb);
    if (ret)
        return ret;

    ret = pht_tx_route_key_init(&key, ep, meta);
    if (ret) {
        kfree_skb(skb);
        return ret;
    }

    /* The local-out caller resolved @flow from @ep before reserving sequence
     * space. Recheck after skb construction and after lookup publication so a
     * racing teardown or future tuple-mismatched caller drops this packet as a
     * stale generation instead of publishing a dst under the wrong flow.
     */
    spin_lock_bh(&flow->lock);
    if (!pht_flow_tx_cache_generation_matches_locked(flow, &key)) {
        spin_unlock_bh(&flow->lock);
        kfree_skb(skb);
        return -EAGAIN;
    }
    send_dst = pht_flow_tx_dst_cache_get_locked(&flow->tx_dst_cache, &key, &old_dst, &ifindex);
    spin_unlock_bh(&flow->lock);
    dst_release(old_dst);
    old_dst = NULL;
    if (send_dst) {
        pht_stats_inc(PHT_STAT_ROUTE_CACHE_HITS);
        if (out_ifindex)
            *out_ifindex = ifindex;
        return pht_tx_fake_tcp_with_dst(net, skb, key.family, send_dst);
    }

    pht_stats_inc(PHT_STAT_ROUTE_CACHE_MISSES);
    ret = pht_tx_fake_tcp_route(net, &key, &route);
    if (ret) {
        kfree_skb(skb);
        return ret;
    }

    send_dst = NULL;
    spin_lock_bh(&flow->lock);
    if (pht_flow_tx_cache_generation_matches_locked(flow, &key)) {
        old_dst = pht_flow_tx_dst_cache_store_locked(&flow->tx_dst_cache, &key, &route);
        send_dst = dst_clone(route.dst);
        ifindex = route.ifindex;
        route.dst = NULL;
    }
    spin_unlock_bh(&flow->lock);
    dst_release(old_dst);

    if (!send_dst) {
        dst_release(route.dst);
        kfree_skb(skb);
        return -EAGAIN;
    }

    if (out_ifindex)
        *out_ifindex = ifindex;
    return pht_tx_fake_tcp_with_dst(net, skb, key.family, send_dst);
}

struct pht_flow *pht_flow_lookup(struct pht_flow_table *table, const struct pht_endpoint_pair *ep) {
    struct pht_flow_bucket *bucket;
    struct pht_flow *flow;
    u32 idx;

    if (!table || !ep)
        return NULL;

    idx = pht_flow_hash_key(table, ep);
    bucket = &table->buckets[idx];
    spin_lock_bh(&bucket->lock);
    hlist_for_each_entry(flow, &bucket->head, hnode) {
        if (!pht_endpoint_pair_equal(&flow->endpoints, ep))
            continue;
        if (!refcount_inc_not_zero(&flow->refs))
            continue;
        spin_unlock_bh(&bucket->lock);
        return flow;
    }
    spin_unlock_bh(&bucket->lock);
    return NULL;
}

bool pht_flow_lookup_retired_seq(struct pht_flow_table *table, const struct pht_endpoint_pair *ep,
                                 u32 *prev_seq) {
    struct pht_flow_bucket *bucket;
    struct pht_retired_flow *retired;
    unsigned long now = jiffies;
    bool found = false;
    u32 idx;

    if (!table || !ep || !prev_seq)
        return false;

    idx = pht_flow_hash_key(table, ep);
    bucket = &table->buckets[idx];

    spin_lock_bh(&bucket->lock);
    pht_flow_retired_purge_expired_locked(bucket, now);
    hlist_for_each_entry(retired, &bucket->retired_head, hnode) {
        if (!pht_endpoint_pair_equal(&retired->endpoints, ep))
            continue;

        *prev_seq = retired->prev_seq;
        found = true;
        break;
    }
    spin_unlock_bh(&bucket->lock);

    return found;
}

struct pht_flow *pht_flow_create(struct pht_flow_table *table, const struct pht_endpoint_pair *ep,
                                 enum pht_flow_role role, enum pht_flow_state state) {
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
    INIT_LIST_HEAD(&flow->keepalive_node);
    INIT_LIST_HEAD(&flow->finalize_node);
    timer_setup(&flow->retransmit_timer, pht_flow_retransmit_timer, 0);
    flow->table = table;
    flow->endpoints = *ep;
    pht_tx_meta_init(&flow->local_tx_meta);
    pht_flow_tx_dst_cache_init(&flow->tx_dst_cache);
    pht_tx_meta_init(&flow->queued_tx_meta);
    flow->role = role;
    flow->state = state;
    flow->max_retries = table->handshake_retries;
    flow->last_activity_jiffies = jiffies;
    flow->last_inbound_jiffies = jiffies;
    flow->keepalives_sent = 0;
    flow->retransmit_at_jiffies = jiffies;
    flow->retransmit_armed = false;
    flow->half_open_tracked = false;
    return flow;
}

static bool pht_flow_unhash_and_queue_finalize(struct pht_flow *flow, bool send_rst) {
    struct pht_flow_bucket *bucket;
    u32 idx;
    bool removed = false;

    if (!flow || !flow->table)
        return false;

    idx = pht_flow_hash_key(flow->table, &flow->endpoints);
    bucket = &flow->table->buckets[idx];
    spin_lock_bh(&bucket->lock);
    if (!hlist_unhashed(&flow->hnode)) {
        hlist_del_init(&flow->hnode);
        pht_stats_dec(PHT_STAT_FLOWS_CURRENT);
        pht_flow_queue_finalize(flow, send_rst);
        removed = true;
    }
    spin_unlock_bh(&bucket->lock);

    return removed;
}

static int pht_flow_admit_half_open_locked(struct pht_flow_table *table, struct pht_flow *flow) {
    if (!pht_flow_state_is_half_open(flow->state) || flow->half_open_tracked)
        return 0;

    spin_lock(&table->half_open_lock);
    if (table->half_open_current >= table->half_open_limit) {
        spin_unlock(&table->half_open_lock);
        pht_stats_inc(PHT_STAT_HALF_OPEN_REJECTED);
        return -ENOSPC;
    }

    table->half_open_current++;
    flow->half_open_tracked = true;
    spin_unlock(&table->half_open_lock);
    return 0;
}

static void pht_flow_publish_locked(struct pht_flow_bucket *bucket, struct pht_flow *flow) {
    /*
     * The creator keeps its own reference across the post-insert first
     * transmit. The table takes a distinct ref before publishing so a
     * concurrent lookup/detach cannot free the flow out from under the creator.
     */
    pht_flow_get(flow);
    pht_stats_inc(PHT_STAT_FLOWS_CURRENT);
    hlist_add_head(&flow->hnode, &bucket->head);
    pht_flow_retired_delete_locked(bucket, &flow->endpoints);
}

static void pht_flow_finish_publish(struct pht_flow *flow) {
    pht_stats_inc(PHT_STAT_FLOWS_CREATED);
    if (pht_flow_state_is_half_open(flow->state))
        pht_flow_arm_retransmit(flow);
}

int pht_flow_insert(struct pht_flow_table *table, struct pht_flow *flow) {
    struct pht_flow_bucket *bucket;
    struct pht_flow *iter;
    int ret;
    u32 idx;

    if (!table || !flow)
        return -EINVAL;

    idx = pht_flow_hash_key(table, &flow->endpoints);
    bucket = &table->buckets[idx];
    spin_lock_bh(&bucket->lock);
    hlist_for_each_entry(iter, &bucket->head, hnode) {
        if (pht_endpoint_pair_equal(&iter->endpoints, &flow->endpoints)) {
            spin_unlock_bh(&bucket->lock);
            return -EEXIST;
        }
    }

    ret = pht_flow_admit_half_open_locked(table, flow);
    if (ret) {
        spin_unlock_bh(&bucket->lock);
        return ret;
    }

    pht_flow_publish_locked(bucket, flow);
    spin_unlock_bh(&bucket->lock);

    pht_flow_finish_publish(flow);
    return 0;
}

int pht_flow_replace_dead(struct pht_flow_table *table, struct pht_flow *dead_flow,
                          struct pht_flow *new_flow) {
    struct pht_flow_bucket *bucket;
    struct pht_flow *iter;
    enum pht_flow_state state;
    int ret;
    u32 idx;

    if (!table || !dead_flow || !new_flow)
        return -EINVAL;
    if (dead_flow->table != table || new_flow->table != table ||
        !pht_endpoint_pair_equal(&dead_flow->endpoints, &new_flow->endpoints))
        return -EINVAL;

    idx = pht_flow_hash_key(table, &new_flow->endpoints);
    bucket = &table->buckets[idx];

    spin_lock_bh(&bucket->lock);
    if (hlist_unhashed(&dead_flow->hnode) ||
        !pht_endpoint_pair_equal(&dead_flow->endpoints, &new_flow->endpoints)) {
        spin_unlock_bh(&bucket->lock);
        return -EAGAIN;
    }

    spin_lock(&dead_flow->lock);
    state = dead_flow->state;
    spin_unlock(&dead_flow->lock);
    if (state != PHT_FLOW_STATE_DEAD) {
        spin_unlock_bh(&bucket->lock);
        return -EAGAIN;
    }

    hlist_for_each_entry(iter, &bucket->head, hnode) {
        if (iter != dead_flow && pht_endpoint_pair_equal(&iter->endpoints, &new_flow->endpoints)) {
            spin_unlock_bh(&bucket->lock);
            return -EEXIST;
        }
    }

    pht_flow_untrack_half_open(dead_flow);
    ret = pht_flow_admit_half_open_locked(table, new_flow);
    if (ret) {
        spin_unlock_bh(&bucket->lock);
        return ret;
    }

    hlist_del_init(&dead_flow->hnode);
    pht_stats_dec(PHT_STAT_FLOWS_CURRENT);
    pht_flow_queue_finalize(dead_flow, false);
    pht_flow_publish_locked(bucket, new_flow);
    spin_unlock_bh(&bucket->lock);

    pht_flow_finish_publish(new_flow);
    return 0;
}

/* Idempotent detach: once a flow leaves the table, mark it DEAD immediately
 * so later lookups cannot use the generation. The table-owned reference is
 * transferred to finalize_work because timer_shutdown_sync() may block and
 * packet hooks must not sleep.
 */
void pht_flow_detach(struct pht_flow *flow) {
    if (!flow || !flow->table)
        return;

    spin_lock_bh(&flow->lock);
    flow->state = PHT_FLOW_STATE_DEAD;
    spin_unlock_bh(&flow->lock);
    pht_flow_untrack_half_open(flow);

    pht_flow_unhash_and_queue_finalize(flow, false);
}

/* Terminal teardown normally moves only reopen-guard sequence metadata into the
 * retired cache and drops the full flow from the canonical hash. If the tiny
 * GFP_ATOMIC cache allocation fails, keep a hashed DEAD tombstone so reopen ISN
 * selection still has a durable previous-generation sequence source.
 */
void pht_flow_remove(struct pht_flow *flow) {
    struct pht_retired_flow *retired;
    struct pht_flow_table *table;
    struct pht_flow_bucket *bucket;
    struct pht_endpoint_pair ep;
    unsigned long expires_jiffies;
    u32 prev_seq;
    u32 idx;

    if (!flow || !flow->table)
        return;

    table = flow->table;
    retired = kzalloc(sizeof(*retired), GFP_ATOMIC);
    idx = pht_flow_hash_key(table, &flow->endpoints);
    bucket = &table->buckets[idx];

    spin_lock_bh(&bucket->lock);
    spin_lock(&flow->lock);
    flow->state = PHT_FLOW_STATE_DEAD;
    ep = flow->endpoints;
    prev_seq = flow->seq;
    expires_jiffies = flow->last_activity_jiffies + table->hard_idle_timeout_jiffies;
    spin_unlock(&flow->lock);

    if (hlist_unhashed(&flow->hnode)) {
        spin_unlock_bh(&bucket->lock);
        kfree(retired);
        return;
    }

    pht_flow_untrack_half_open(flow);
    if (!retired) {
        spin_unlock_bh(&bucket->lock);
        pht_flow_reset_tx_dst_cache(flow);
        pht_pr_warn_rl("keeping DEAD flow tombstone after retired metadata allocation failure\n");
        pht_flow_cancel_retransmit(flow);
        return;
    }

    pht_flow_retired_publish_locked(bucket, retired, &ep, prev_seq, expires_jiffies);
    hlist_del_init(&flow->hnode);
    pht_stats_dec(PHT_STAT_FLOWS_CURRENT);
    pht_flow_queue_finalize(flow, false);
    spin_unlock_bh(&bucket->lock);
}

void pht_flow_touch_inbound(struct pht_flow *flow) {
    if (!flow)
        return;

    spin_lock_bh(&flow->lock);
    flow->last_inbound_jiffies = jiffies;
    flow->last_activity_jiffies = jiffies;
    flow->keepalives_sent = 0;
    spin_unlock_bh(&flow->lock);
}

void pht_flow_touch(struct pht_flow *flow) {
    if (!flow)
        return;

    spin_lock_bh(&flow->lock);
    flow->last_activity_jiffies = jiffies;
    spin_unlock_bh(&flow->lock);
}

void pht_flow_set_egress_ifindex(struct pht_flow *flow, int ifindex) {
    if (!flow)
        return;

    spin_lock_bh(&flow->lock);
    flow->egress_ifindex = ifindex;
    spin_unlock_bh(&flow->lock);
}

/* Queue metadata is exact per-skb metadata. The persistent local transmit
 * context is updated by every intercepted local outbound UDP packet before the
 * queue decision, including packets dropped because the bounded queue is full.
 */
static void pht_flow_store_queued_tx_meta_locked(struct pht_flow *flow,
                                                 const struct pht_tx_meta *meta) {
    if (meta)
        flow->queued_tx_meta = *meta;
    else
        pht_tx_meta_init(&flow->queued_tx_meta);
}

/* On success the flow takes ownership of @skb. On failure the caller still
 * owns @skb and must decide whether to free or reuse it.
 */
bool pht_flow_queue_skb_if_empty(struct pht_flow *flow, struct sk_buff *skb,
                                 const struct pht_tx_meta *meta) {
    bool queued = false;

    if (!flow)
        return false;

    spin_lock_bh(&flow->lock);
    if (meta)
        flow->local_tx_meta = *meta;
    if (!flow->queued_skb) {
        flow->queued_skb = skb;
        pht_flow_store_queued_tx_meta_locked(flow, meta);
        flow->last_activity_jiffies = jiffies;
        queued = true;
    }
    spin_unlock_bh(&flow->lock);

    return queued;
}

/* The flow takes ownership of @skb. Any previously queued skb is released
 * here so callers do not need a second free path. This may requeue or transfer
 * an existing skb, so true local-out callers update local_tx_meta explicitly.
 */
void pht_flow_set_queued_skb(struct pht_flow *flow, struct sk_buff *skb,
                             const struct pht_tx_meta *meta) {
    struct sk_buff *old;

    if (!flow) {
        kfree_skb(skb);
        return;
    }

    spin_lock_bh(&flow->lock);
    old = flow->queued_skb;
    flow->queued_skb = skb;
    pht_flow_store_queued_tx_meta_locked(flow, meta);
    spin_unlock_bh(&flow->lock);

    kfree_skb(old);
}

struct sk_buff *pht_flow_take_queued_skb(struct pht_flow *flow, struct pht_tx_meta *meta) {
    struct sk_buff *skb;

    if (meta)
        pht_tx_meta_init(meta);
    if (!flow)
        return NULL;

    spin_lock_bh(&flow->lock);
    skb = flow->queued_skb;
    if (skb && meta)
        *meta = flow->queued_tx_meta;
    flow->queued_skb = NULL;
    pht_tx_meta_init(&flow->queued_tx_meta);
    spin_unlock_bh(&flow->lock);
    return skb;
}

void pht_flow_update_state(struct pht_flow *flow, enum pht_flow_state state) {
    bool half_open;
    enum pht_flow_state old_state;
    unsigned long now;

    if (!flow)
        return;

    spin_lock_bh(&flow->lock);
    now = jiffies;
    old_state = flow->state;
    if (state == PHT_FLOW_STATE_ESTABLISHED && old_state == PHT_FLOW_STATE_SYN_SENT &&
        flow->role == PHT_FLOW_ROLE_INITIATOR && flow->table &&
        flow->table->replacement_protect_jiffies) {
        flow->replacement_protect_until_jiffies = now + flow->table->replacement_protect_jiffies;
        flow->replacement_protect_active = true;
    } else if (state != PHT_FLOW_STATE_ESTABLISHED || flow->role != PHT_FLOW_ROLE_INITIATOR) {
        flow->replacement_protect_active = false;
    }
    flow->state = state;
    flow->last_activity_jiffies = now;
    flow->retries_done = 0;
    half_open = pht_flow_state_is_half_open(state);
    spin_unlock_bh(&flow->lock);

    if (state == PHT_FLOW_STATE_ESTABLISHED && old_state != PHT_FLOW_STATE_ESTABLISHED)
        pht_stats_inc(PHT_STAT_FLOWS_ESTABLISHED);
    if (pht_flow_state_is_half_open(old_state) && !half_open)
        pht_flow_untrack_half_open(flow);
    if (half_open)
        pht_flow_arm_retransmit(flow);
    else
        pht_flow_cancel_retransmit(flow);
}

void pht_flow_arm_retransmit(struct pht_flow *flow) {
    unsigned long when;

    if (!flow || !flow->table)
        return;

    spin_lock_bh(&flow->lock);
    if (!pht_flow_state_is_half_open(flow->state) || flow->state == PHT_FLOW_STATE_DEAD) {
        spin_unlock_bh(&flow->lock);
        return;
    }
    if (!flow->retransmit_armed) {
        pht_flow_get(flow);
        flow->retransmit_armed = true;
    }
    when = jiffies + flow->table->handshake_timeout_jiffies;
    flow->retransmit_at_jiffies = when;
    mod_timer(&flow->retransmit_timer, when);
    spin_unlock_bh(&flow->lock);
}

void pht_flow_cancel_retransmit(struct pht_flow *flow) {
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

struct pht_flow_invalidate_match {
    int egress_ifindex;
    struct pht_addr local_addr;
};

static bool pht_flow_matches_egress_ifindex_locked(const struct pht_flow *flow,
                                                   const struct pht_flow_invalidate_match *match) {
    return (flow->egress_ifindex > 0 && flow->egress_ifindex == match->egress_ifindex) ||
           (flow->tx_dst_cache.valid && flow->tx_dst_cache.ifindex > 0 &&
            flow->tx_dst_cache.ifindex == match->egress_ifindex);
}

static bool pht_flow_matches_local_addr_locked(const struct pht_flow *flow,
                                               const struct pht_flow_invalidate_match *match) {
    return pht_addr_equal_local(&flow->endpoints.local_addr, &match->local_addr);
}

/* Topology-driven invalidation is best-effort local cleanup: the path or
 * source identity already changed underneath us, so unhash silently and let
 * the next packet build a fresh generation instead of fabricating an RST from
 * a dead path.
 */
static unsigned int
pht_flow_invalidate_matching(struct pht_flow_table *table,
                             bool (*matches_locked)(const struct pht_flow *flow,
                                                    const struct pht_flow_invalidate_match *match),
                             const struct pht_flow_invalidate_match *match) {
    unsigned int count = 0;
    unsigned int i;

    if (!table || !matches_locked || !match)
        return 0;

    for (i = 0; i < PHT_FLOW_BUCKETS; i++) {
        struct pht_flow_bucket *bucket = &table->buckets[i];
        struct pht_flow *flow;
        struct hlist_node *tmp;

        spin_lock_bh(&bucket->lock);
        hlist_for_each_entry_safe(flow, tmp, &bucket->head, hnode) {
            struct dst_entry *dead_dst = NULL;
            bool matched;

            spin_lock(&flow->lock);
            matched = flow->state != PHT_FLOW_STATE_DEAD && matches_locked(flow, match);
            if (matched) {
                flow->state = PHT_FLOW_STATE_DEAD;
                dead_dst = pht_flow_tx_dst_cache_reset_locked(&flow->tx_dst_cache);
            }
            spin_unlock(&flow->lock);
            dst_release(dead_dst);
            if (!matched)
                continue;

            pht_flow_untrack_half_open(flow);
            hlist_del_init(&flow->hnode);
            pht_stats_dec(PHT_STAT_FLOWS_CURRENT);
            pht_flow_queue_finalize(flow, false);
            count++;
        }
        spin_unlock_bh(&bucket->lock);
    }

    return count;
}

unsigned int pht_flow_invalidate_egress_ifindex(struct pht_flow_table *table, int ifindex) {
    struct pht_flow_invalidate_match match = {
        .egress_ifindex = ifindex,
    };

    if (ifindex <= 0)
        return 0;

    return pht_flow_invalidate_matching(table, pht_flow_matches_egress_ifindex_locked, &match);
}

unsigned int pht_flow_invalidate_local_addr(struct pht_flow_table *table,
                                            const struct pht_addr *addr) {
    struct pht_flow_invalidate_match match;

    if (!addr)
        return 0;

    memset(&match, 0, sizeof(match));
    match.local_addr = *addr;
    return pht_flow_invalidate_matching(table, pht_flow_matches_local_addr_locked, &match);
}
