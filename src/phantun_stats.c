#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/sysfs.h>

#include "phantun.h"
#include "phantun_stats.h"

static atomic64_t pht_stats[PHT_STAT_COUNT];
static struct kobject *pht_stats_kobj;

#define PHT_STAT_ATTR(_name, _id)                                              \
    static ssize_t _name##_show(struct kobject *kobj,                          \
                                struct kobj_attribute *attr, char *buf) {      \
        return sysfs_emit(buf, "%llu\n",                                       \
                          (unsigned long long)atomic64_read(&pht_stats[_id])); \
    }                                                                          \
    static struct kobj_attribute _name##_attr = __ATTR_RO(_name)

PHT_STAT_ATTR(flows_created, PHT_STAT_FLOWS_CREATED);
PHT_STAT_ATTR(flows_established, PHT_STAT_FLOWS_ESTABLISHED);
PHT_STAT_ATTR(request_payloads_injected, PHT_STAT_REQUEST_PAYLOADS_INJECTED);
PHT_STAT_ATTR(response_payloads_injected, PHT_STAT_RESPONSE_PAYLOADS_INJECTED);
PHT_STAT_ATTR(collisions_won, PHT_STAT_COLLISIONS_WON);
PHT_STAT_ATTR(collisions_lost, PHT_STAT_COLLISIONS_LOST);
PHT_STAT_ATTR(rst_sent, PHT_STAT_RST_SENT);
PHT_STAT_ATTR(udp_packets_queued, PHT_STAT_UDP_PACKETS_QUEUED);
PHT_STAT_ATTR(udp_packets_dropped, PHT_STAT_UDP_PACKETS_DROPPED);
PHT_STAT_ATTR(shaping_payloads_dropped, PHT_STAT_SHAPING_PAYLOADS_DROPPED);

static struct attribute *pht_stats_attrs[] = {
    &flows_created_attr.attr,
    &flows_established_attr.attr,
    &request_payloads_injected_attr.attr,
    &response_payloads_injected_attr.attr,
    &collisions_won_attr.attr,
    &collisions_lost_attr.attr,
    &rst_sent_attr.attr,
    &udp_packets_queued_attr.attr,
    &udp_packets_dropped_attr.attr,
    &shaping_payloads_dropped_attr.attr,
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

void pht_stats_add(enum pht_stat_id id, u64 delta) {
    if (id >= PHT_STAT_COUNT || !delta)
        return;

    atomic64_add(delta, &pht_stats[id]);
}

u64 pht_stats_read(enum pht_stat_id id) {
    if (id >= PHT_STAT_COUNT)
        return 0;

    return atomic64_read(&pht_stats[id]);
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
