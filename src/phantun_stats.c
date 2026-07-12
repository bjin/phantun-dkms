// SPDX-License-Identifier: GPL-2.0-or-later
//
// Copyright (C) 2026 Bin Jin. All Rights Reserved.
#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/sysfs.h>

#include "phantun.h"
#include "phantun_stats.h"

static atomic64_t pht_stats[PHT_STAT_COUNT];
static struct kobject *pht_stats_kobj;

#define PHT_STAT_ATTR(_name, _id)                                                                  \
    static ssize_t _name##_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {    \
        return sysfs_emit(buf, "%llu\n", (unsigned long long)atomic64_read(&pht_stats[_id]));      \
    }                                                                                              \
    static struct kobj_attribute _name##_attr = __ATTR_RO(_name)

PHT_STAT_ATTR(flows_created, PHT_STAT_FLOWS_CREATED);
PHT_STAT_ATTR(flows_established, PHT_STAT_FLOWS_ESTABLISHED);
PHT_STAT_ATTR(flows_current, PHT_STAT_FLOWS_CURRENT);
PHT_STAT_ATTR(half_open_rejected, PHT_STAT_HALF_OPEN_REJECTED);
PHT_STAT_ATTR(handshake_retries_exhausted, PHT_STAT_HANDSHAKE_RETRIES_EXHAUSTED);
PHT_STAT_ATTR(established_liveness_timeouts, PHT_STAT_ESTABLISHED_LIVENESS_TIMEOUTS);
PHT_STAT_ATTR(replacements_accepted, PHT_STAT_REPLACEMENTS_ACCEPTED);
PHT_STAT_ATTR(replacement_quarantine_dropped, PHT_STAT_REPLACEMENT_QUARANTINE_DROPPED);
PHT_STAT_ATTR(replacement_protect_dropped, PHT_STAT_REPLACEMENT_PROTECT_DROPPED);
PHT_STAT_ATTR(retired_evicted, PHT_STAT_RETIRED_EVICTED);
PHT_STAT_ATTR(collisions_won, PHT_STAT_COLLISIONS_WON);
PHT_STAT_ATTR(collisions_lost, PHT_STAT_COLLISIONS_LOST);
PHT_STAT_ATTR(request_payloads_injected, PHT_STAT_REQUEST_PAYLOADS_INJECTED);
PHT_STAT_ATTR(response_payloads_injected, PHT_STAT_RESPONSE_PAYLOADS_INJECTED);
PHT_STAT_ATTR(shaping_payloads_dropped, PHT_STAT_SHAPING_PAYLOADS_DROPPED);
PHT_STAT_ATTR(rst_sent, PHT_STAT_RST_SENT);
PHT_STAT_ATTR(idle_acks_suppressed, PHT_STAT_IDLE_ACKS_SUPPRESSED);
PHT_STAT_ATTR(route_cache_hits, PHT_STAT_ROUTE_CACHE_HITS);
PHT_STAT_ATTR(route_cache_misses, PHT_STAT_ROUTE_CACHE_MISSES);
PHT_STAT_ATTR(udp_packets_queued, PHT_STAT_UDP_PACKETS_QUEUED);
PHT_STAT_ATTR(udp_packets_dropped, PHT_STAT_UDP_PACKETS_DROPPED);
PHT_STAT_ATTR(udp_queue_full_dropped, PHT_STAT_UDP_QUEUE_FULL_DROPPED);
PHT_STAT_ATTR(udp_raw_inbound_dropped, PHT_STAT_UDP_RAW_INBOUND_DROPPED);
PHT_STAT_ATTR(udp_translation_failed_dropped, PHT_STAT_UDP_TRANSLATION_FAILED_DROPPED);
PHT_STAT_ATTR(udp_reinject_failed_dropped, PHT_STAT_UDP_REINJECT_FAILED_DROPPED);
PHT_STAT_ATTR(tcp_protocol_rejected, PHT_STAT_TCP_PROTOCOL_REJECTED);
PHT_STAT_ATTR(tcp_misaligned_syn_rejected, PHT_STAT_TCP_MISALIGNED_SYN_REJECTED);
PHT_STAT_ATTR(tcp_unknown_tuple_rejected, PHT_STAT_TCP_UNKNOWN_TUPLE_REJECTED);
PHT_STAT_ATTR(bad_checksum_dropped, PHT_STAT_BAD_CHECKSUM_DROPPED);
PHT_STAT_ATTR(oversized_payloads_dropped, PHT_STAT_OVERSIZED_PAYLOADS_DROPPED);

static struct attribute *pht_stats_attrs[] = {
    &flows_created_attr.attr,
    &flows_established_attr.attr,
    &flows_current_attr.attr,
    &half_open_rejected_attr.attr,
    &handshake_retries_exhausted_attr.attr,
    &established_liveness_timeouts_attr.attr,
    &replacements_accepted_attr.attr,
    &replacement_quarantine_dropped_attr.attr,
    &replacement_protect_dropped_attr.attr,
    &retired_evicted_attr.attr,
    &collisions_won_attr.attr,
    &collisions_lost_attr.attr,
    &request_payloads_injected_attr.attr,
    &response_payloads_injected_attr.attr,
    &shaping_payloads_dropped_attr.attr,
    &rst_sent_attr.attr,
    &idle_acks_suppressed_attr.attr,
    &route_cache_hits_attr.attr,
    &route_cache_misses_attr.attr,
    &udp_packets_queued_attr.attr,
    &udp_packets_dropped_attr.attr,
    &udp_queue_full_dropped_attr.attr,
    &udp_raw_inbound_dropped_attr.attr,
    &udp_translation_failed_dropped_attr.attr,
    &udp_reinject_failed_dropped_attr.attr,
    &tcp_protocol_rejected_attr.attr,
    &tcp_misaligned_syn_rejected_attr.attr,
    &tcp_unknown_tuple_rejected_attr.attr,
    &bad_checksum_dropped_attr.attr,
    &oversized_payloads_dropped_attr.attr,
    NULL,
};

static const struct attribute_group pht_stats_group = {
    .name = "stats",
    .attrs = pht_stats_attrs,
};

void pht_stats_reset(void) {
    unsigned int i;

    for (i = 0; i < PHT_STAT_COUNT; i++)
        atomic64_set(&pht_stats[i], 0);
}

void pht_stats_inc(enum pht_stat_id id) {
    if (id >= PHT_STAT_COUNT)
        return;

    atomic64_inc(&pht_stats[id]);
}

void pht_stats_dec(enum pht_stat_id id) {
    if (id >= PHT_STAT_COUNT)
        return;

    atomic64_dec(&pht_stats[id]);
}

int pht_stats_init_sysfs(void) {
    int ret;

    pht_stats_kobj = &THIS_MODULE->mkobj.kobj;
    ret = sysfs_create_group(pht_stats_kobj, &pht_stats_group);
    if (ret)
        pht_pr_err("failed to create stats sysfs group: %d\n", ret);
    return ret;
}

void pht_stats_exit_sysfs(void) {
    if (!pht_stats_kobj)
        return;

    sysfs_remove_group(pht_stats_kobj, &pht_stats_group);
    pht_stats_kobj = NULL;
}
