// SPDX-License-Identifier: GPL-2.0-or-later
//
// Copyright (C) 2026 Bin Jin. All Rights Reserved.
#ifndef PHANTUN_H
#define PHANTUN_H

#include "phantun_packet.h"
#include <linux/kernel.h>
#include <linux/types.h>

#define PHANTUN_MODULE_NAME "phantun"
#define PHANTUN_MAX_MANAGED_PORTS 64
#define PHANTUN_MAX_MANAGED_PEERS 64
#define PHANTUN_DEFAULT_HANDSHAKE_TIMEOUT_MS 1000U
#define PHANTUN_DEFAULT_HANDSHAKE_RETRIES 6U
#define PHANTUN_DEFAULT_KEEPALIVE_INTERVAL_SEC 30U
#define PHANTUN_DEFAULT_KEEPALIVE_MISSES 3U
#define PHANTUN_DEFAULT_HARD_IDLE_TIMEOUT_SEC 300U
#define PHANTUN_DEFAULT_REOPEN_GUARD_BYTES 4194304U
#define PHANTUN_MAX_REOPEN_GUARD_BYTES 0x40000000U
#define PHANTUN_DEFAULT_HALF_OPEN_LIMIT 4096U
#define PHANTUN_DEFAULT_REPLACEMENT_QUARANTINE_MS 3000U
#define PHANTUN_DEFAULT_REPLACEMENT_PROTECT_MS 0U
/* PRE_ROUTING uses -399 so IPv4/IPv6 defrag at -400 runs first. The
 * raw-UDP drop and fake-TCP hooks intentionally share this priority and
 * depend on registration order in src/phantun_netns.c.
 */
#define PHANTUN_PRE_ROUTING_PRIORITY (-399)
#define PHANTUN_LOCAL_OUT_PRIORITY (-199)
#define PHT_FAMILY_IPV4 BIT(0)
#define PHT_FAMILY_IPV6 BIT(1)

#define pht_pr_err(fmt, ...) pr_err(PHANTUN_MODULE_NAME ": " fmt, ##__VA_ARGS__)
#define pht_pr_warn(fmt, ...) pr_warn(PHANTUN_MODULE_NAME ": " fmt, ##__VA_ARGS__)
#define pht_pr_warn_rl(fmt, ...) pr_warn_ratelimited(PHANTUN_MODULE_NAME ": " fmt, ##__VA_ARGS__)
#define pht_pr_info(fmt, ...) pr_info(PHANTUN_MODULE_NAME ": " fmt, ##__VA_ARGS__)
#define pht_pr_debug(fmt, ...) pr_debug(PHANTUN_MODULE_NAME ": " fmt, ##__VA_ARGS__)

enum pht_managed_netns {
    PHT_MANAGED_NETNS_INIT,
    PHT_MANAGED_NETNS_ALL,
};

struct pht_managed_peer {
    struct pht_addr addr;
    __be16 port;
};

struct phantun_config {
    enum pht_managed_netns managed_netns;
    unsigned int enabled_families;
    u16 managed_local_ports[PHANTUN_MAX_MANAGED_PORTS];
    unsigned int managed_local_ports_count;
    u16 reserved_local_ports[PHANTUN_MAX_MANAGED_PORTS];
    unsigned int reserved_local_ports_count;
    struct pht_managed_peer managed_remote_peers[PHANTUN_MAX_MANAGED_PEERS];
    unsigned int managed_remote_peers_count;
    const char *handshake_request;
    const char *handshake_response;
    unsigned int handshake_request_len;
    unsigned int handshake_response_len;
    unsigned int handshake_timeout_ms;
    unsigned int handshake_retries;
    unsigned int keepalive_interval_sec;
    unsigned int keepalive_misses;
    unsigned int hard_idle_timeout_sec;
    unsigned int reopen_guard_bytes;
    unsigned int half_open_limit;
    unsigned int replacement_quarantine_ms;
    unsigned int replacement_protect_ms;
    unsigned int effective_replacement_protect_ms;
};

/* Constructed before namespace attachment; immutable until all users detach. */
extern struct phantun_config phantun_cfg;
int phantun_config_init(void);
void phantun_config_exit(void);

struct pht_flow_table;
struct nf_hook_state;

int phantun_netns_init(void);
void phantun_netns_exit(void);
struct pht_flow_table *phantun_net_hook_flows(const struct net *net);

unsigned int phantun_local_out(void *priv, struct sk_buff *skb,
                               const struct nf_hook_state *state);
unsigned int phantun_pre_routing(void *priv, struct sk_buff *skb,
                                 const struct nf_hook_state *state);
unsigned int phantun_pre_routing_udp_drop(void *priv, struct sk_buff *skb,
                                          const struct nf_hook_state *state);

#endif
