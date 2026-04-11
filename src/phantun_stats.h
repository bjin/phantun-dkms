// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef PHANTUN_STATS_H
#define PHANTUN_STATS_H

#include <linux/types.h>

enum pht_stat_id {
    PHT_STAT_FLOWS_CREATED = 0,
    PHT_STAT_FLOWS_ESTABLISHED,
    PHT_STAT_REQUEST_PAYLOADS_INJECTED,
    PHT_STAT_RESPONSE_PAYLOADS_INJECTED,
    PHT_STAT_COLLISIONS_WON,
    PHT_STAT_COLLISIONS_LOST,
    PHT_STAT_RST_SENT,
    PHT_STAT_UDP_PACKETS_QUEUED,
    PHT_STAT_UDP_PACKETS_DROPPED,
    PHT_STAT_SHAPING_PAYLOADS_DROPPED,
    PHT_STAT_COUNT,
};

void pht_stats_reset(void);
void pht_stats_inc(enum pht_stat_id id);
void pht_stats_add(enum pht_stat_id id, u64 delta);
u64 pht_stats_read(enum pht_stat_id id);
int pht_stats_init_sysfs(void);
void pht_stats_exit_sysfs(void);

#endif
