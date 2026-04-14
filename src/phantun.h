// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef PHANTUN_H
#define PHANTUN_H

#include <linux/kernel.h>
#include <linux/types.h>

#define PHANTUN_MODULE_NAME "phantun"
#define PHANTUN_MAX_MANAGED_PORTS 16
#define PHANTUN_MAX_MANAGED_PEERS 16
#define PHANTUN_DEFAULT_HANDSHAKE_TIMEOUT_MS 1000U
#define PHANTUN_DEFAULT_HANDSHAKE_RETRIES 6U
#define PHANTUN_DEFAULT_KEEPALIVE_INTERVAL_SEC 30U
#define PHANTUN_DEFAULT_KEEPALIVE_MISSES 3U
#define PHANTUN_DEFAULT_HARD_IDLE_TIMEOUT_SEC 300U
#define PHANTUN_DEFAULT_REOPEN_GUARD_BYTES 4194304U
#define PHANTUN_DEFAULT_ESTABLISHED_WINDOW_BYTES 1048576U
#define PHANTUN_DEFAULT_REPLACEMENT_QUARANTINE_MS 3000U
#define PHANTUN_PRE_ROUTING_PRIORITY (-400)
#define PHANTUN_LOCAL_OUT_PRIORITY (-199)
/* Marks reinjected UDP so PRE_ROUTING accepts it without recapturing it. */
#define PHANTUN_REINJECT_MARK 0x50485455U

#define pht_pr_err(fmt, ...) pr_err(PHANTUN_MODULE_NAME ": " fmt, ##__VA_ARGS__)
#define pht_pr_warn(fmt, ...) pr_warn(PHANTUN_MODULE_NAME ": " fmt, ##__VA_ARGS__)
#define pht_pr_warn_rl(fmt, ...) pr_warn_ratelimited(PHANTUN_MODULE_NAME ": " fmt, ##__VA_ARGS__)
#define pht_pr_info(fmt, ...) pr_info(PHANTUN_MODULE_NAME ": " fmt, ##__VA_ARGS__)
#define pht_pr_debug(fmt, ...) pr_debug(PHANTUN_MODULE_NAME ": " fmt, ##__VA_ARGS__)

struct pht_managed_peer {
    __be32 addr;
    __be16 port;
};

struct phantun_config {
    u16 managed_local_ports[PHANTUN_MAX_MANAGED_PORTS];
    unsigned int managed_local_ports_count;
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
    unsigned int established_window_bytes;
    unsigned int replacement_quarantine_ms;
};

#endif
