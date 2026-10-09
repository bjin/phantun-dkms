// SPDX-License-Identifier: GPL-2.0-or-later
//
// Copyright (C) 2026 Bin Jin. All Rights Reserved.
#include <linux/inet.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "phantun_compat.h"
#if PHANTUN_HAVE_BASE64_DECODE
#include <linux/base64.h>
#endif
#ifdef HAVE_LINUX_HEX_H
#include <linux/hex.h>
#endif

#include "phantun.h"

static unsigned int managed_local_ports[PHANTUN_MAX_MANAGED_PORTS];
static int managed_local_ports_count;
static char *managed_remote_peers[PHANTUN_MAX_MANAGED_PEERS];
static int managed_remote_peers_count;
static char *reserved_local_ports;
static char *ip_families = "both";
static char *managed_netns = "init";
static char *handshake_request;
static char *handshake_response;
static unsigned int handshake_timeout_ms = PHANTUN_DEFAULT_HANDSHAKE_TIMEOUT_MS;
static unsigned int handshake_retries = PHANTUN_DEFAULT_HANDSHAKE_RETRIES;
static unsigned int keepalive_interval_sec = PHANTUN_DEFAULT_KEEPALIVE_INTERVAL_SEC;
static unsigned int keepalive_misses = PHANTUN_DEFAULT_KEEPALIVE_MISSES;
static unsigned int hard_idle_timeout_sec = PHANTUN_DEFAULT_HARD_IDLE_TIMEOUT_SEC;
static unsigned int reopen_guard_bytes = PHANTUN_DEFAULT_REOPEN_GUARD_BYTES;
static unsigned int half_open_limit = PHANTUN_DEFAULT_HALF_OPEN_LIMIT;
static unsigned int replacement_quarantine_ms = PHANTUN_DEFAULT_REPLACEMENT_QUARANTINE_MS;
static unsigned int replacement_protect_ms = PHANTUN_DEFAULT_REPLACEMENT_PROTECT_MS;
module_param_array_named(managed_local_ports, managed_local_ports, uint, &managed_local_ports_count,
                         0444);
MODULE_PARM_DESC(managed_local_ports, "Comma-separated local UDP/TCP ports managed by phantun");
module_param_array_named(managed_remote_peers, managed_remote_peers, charp,
                         &managed_remote_peers_count, 0444);
MODULE_PARM_DESC(
    managed_remote_peers,
    "Comma-separated remote IPv4:port or bracketed [IPv6]:port peers managed by phantun");
module_param(reserved_local_ports, charp, 0444);
MODULE_PARM_DESC(reserved_local_ports,
                 "Optional local-only TCP reservation set: empty or 'off' disables, "
                 "comma-separated ports reserve up to 64 managed_local_ports entries, and 'all' "
                 "reserves every managed_local_ports entry");
module_param(ip_families, charp, 0444);
MODULE_PARM_DESC(ip_families, "IP families to translate: both, ipv4, or ipv6");
module_param(managed_netns, charp, 0444);
MODULE_PARM_DESC(managed_netns,
                 "Network namespaces to attach to: init (initial netns only) or all");
module_param(handshake_request, charp, 0444);
MODULE_PARM_DESC(handshake_request,
                 "Optional initiator control payload sent as the first fake-TCP payload (plain "
                 "string, or hex/base64 if prefixed with 'hex:'/'base64:'; base64 requires kernel "
                 "support)");
module_param(handshake_response, charp, 0444);
MODULE_PARM_DESC(
    handshake_response,
    "Optional responder control payload sent as the first fake-TCP payload when handshake_request "
    "is also set (plain string, or hex/base64 if prefixed with 'hex:'/'base64:'; base64 requires "
    "kernel support)");
module_param(handshake_timeout_ms, uint, 0444);
MODULE_PARM_DESC(handshake_timeout_ms, "Handshake retransmit timeout in milliseconds");
module_param(handshake_retries, uint, 0444);
MODULE_PARM_DESC(handshake_retries,
                 "Maximum handshake retry count before tearing a flow down with RST");
module_param(keepalive_interval_sec, uint, 0444);
MODULE_PARM_DESC(keepalive_interval_sec, "Periodic keepalive ACK interval in seconds");
module_param(keepalive_misses, uint, 0444);
MODULE_PARM_DESC(keepalive_misses, "Inbound-silence interval budget (minimum effective budget: two)");
module_param(hard_idle_timeout_sec, uint, 0444);
MODULE_PARM_DESC(hard_idle_timeout_sec, "Maximum idle flow timeout in seconds (hard GC limit)");
module_param(reopen_guard_bytes, uint, 0444);
MODULE_PARM_DESC(reopen_guard_bytes, "Minimum sequence space separation for new connections");
module_param(half_open_limit, uint, 0444);
MODULE_PARM_DESC(half_open_limit,
                 "Total half-open ceiling per netns; reserve max(1, limit/4) for local origin "
                 "when limit > 1");
module_param(replacement_quarantine_ms, uint, 0444);
MODULE_PARM_DESC(replacement_quarantine_ms,
                 "Previous-generation quarantine window in milliseconds after tuple replacement");
module_param(replacement_protect_ms, uint, 0444);
MODULE_PARM_DESC(replacement_protect_ms,
                 "Established initiator bare-SYN replacement protection window in milliseconds; "
                 "0 uses auto formula");

struct phantun_config phantun_cfg;

static int phantun_parse_managed_remote_peer(const char *peer,
                                             struct pht_managed_peer *parsed_peer) {
    char buf[80];
    char *host;
    char *port;
    char *end;
    u8 parsed_addr[sizeof(struct in6_addr)];
    unsigned int port_host;

    if (!peer || !*peer || !parsed_peer)
        return -EINVAL;
    if (strscpy(buf, peer, sizeof(buf)) < 0)
        return -EINVAL;

    memset(parsed_peer, 0, sizeof(*parsed_peer));
    if (buf[0] == '[') {
        host = buf + 1;
        end = strchr(host, ']');
        if (!end || end[1] != ':' || !end[2])
            return -EINVAL;
        *end = '\0';
        port = end + 2;
        if (!*host || !in6_pton(host, -1, parsed_addr, -1, NULL))
            return -EINVAL;
        parsed_peer->addr.family = AF_INET6;
        memcpy(&parsed_peer->addr.v6, parsed_addr, sizeof(parsed_peer->addr.v6));
    } else {
        host = buf;
        port = strrchr(buf, ':');
        if (!port || port != strchr(buf, ':'))
            return -EINVAL;
        *port = '\0';
        port++;
        if (!*host || !*port || !in4_pton(host, -1, parsed_addr, -1, NULL))
            return -EINVAL;
        parsed_peer->addr.family = AF_INET;
        memcpy(&parsed_peer->addr.v4, parsed_addr, sizeof(parsed_peer->addr.v4));
    }

    if (kstrtouint(port, 10, &port_host) || !port_host || port_host > U16_MAX)
        return -EINVAL;
    parsed_peer->port = htons((u16)port_host);
    return 0;
}

static bool phantun_managed_local_port_configured(u16 port) {
    unsigned int i;

    for (i = 0; i < managed_local_ports_count; i++) {
        if ((u16)managed_local_ports[i] == port)
            return true;
    }

    return false;
}

static void phantun_append_unique_port(u16 *ports, unsigned int *count, u16 port) {
    unsigned int i;

    for (i = 0; i < *count; i++) {
        if (ports[i] == port)
            return;
    }

    ports[*count] = port;
    (*count)++;
}

static int phantun_parse_reserved_local_ports_param(const char *raw_str, u16 *ports,
                                                    unsigned int *count, bool *all_requested) {
    char *copy;
    char *cursor;
    char *token;
    unsigned int index = 0;

    *count = 0;
    *all_requested = false;

    if (!raw_str || !*raw_str || strcmp(raw_str, "off") == 0)
        return 0;

    if (strcmp(raw_str, "all") == 0) {
        *all_requested = true;
        return 0;
    }

    copy = kstrdup(raw_str, GFP_KERNEL);
    if (!copy)
        return -ENOMEM;

    cursor = copy;
    while ((token = strsep(&cursor, ",")) != NULL) {
        unsigned int port;
        int ret;

        token = strim(token);
        if (!*token) {
            pht_pr_err("reserved_local_ports[%u] must be a decimal port between 1 and 65535\n",
                       index);
            kfree(copy);
            return -EINVAL;
        }

        if (index >= PHANTUN_MAX_MANAGED_PORTS) {
            pht_pr_err("reserved_local_ports supports at most %u comma-separated entries\n",
                       PHANTUN_MAX_MANAGED_PORTS);
            kfree(copy);
            return -EINVAL;
        }

        ret = kstrtouint(token, 10, &port);
        if (ret || !port || port > U16_MAX) {
            pht_pr_err("reserved_local_ports[%u] must be a decimal port between 1 and 65535\n",
                       index);
            kfree(copy);
            return -EINVAL;
        }

        ports[index++] = (u16)port;
    }

    *count = index;
    kfree(copy);
    return 0;
}

static int phantun_snapshot_reserved_local_ports(struct phantun_config *cfg) {
    u16 requested_ports[PHANTUN_MAX_MANAGED_PORTS];
    unsigned int requested_count;
    bool all_requested;
    unsigned int i;
    int ret;

    ret = phantun_parse_reserved_local_ports_param(reserved_local_ports, requested_ports,
                                                   &requested_count, &all_requested);
    if (ret)
        return ret;

    if (!reserved_local_ports || !*reserved_local_ports || strcmp(reserved_local_ports, "off") == 0)
        return 0;

    if (!managed_local_ports_count || managed_remote_peers_count) {
        pht_pr_info("reserved_local_ports=%s ignored because it only applies when "
                    "managed_local_ports is set and managed_remote_peers is empty\n",
                    reserved_local_ports);
        return 0;
    }

    if (all_requested) {
        for (i = 0; i < managed_local_ports_count; i++)
            phantun_append_unique_port(cfg->reserved_local_ports, &cfg->reserved_local_ports_count,
                                       (u16)managed_local_ports[i]);
        return 0;
    }

    for (i = 0; i < requested_count; i++) {
        u16 port = requested_ports[i];

        if (!phantun_managed_local_port_configured(port)) {
            pht_pr_info("reserved_local_ports[%u]=%u ignored because it is not present in "
                        "managed_local_ports\n",
                        i, port);
            continue;
        }

        phantun_append_unique_port(cfg->reserved_local_ports, &cfg->reserved_local_ports_count,
                                   port);
    }

    return 0;
}

static const char *phantun_managed_netns_name(enum pht_managed_netns mode) {
    switch (mode) {
    case PHT_MANAGED_NETNS_INIT:
        return "init";
    case PHT_MANAGED_NETNS_ALL:
        return "all";
    default:
        return "unknown";
    }
}

static int phantun_parse_managed_netns(enum pht_managed_netns *mode) {
    if (!mode)
        return -EINVAL;

    if (!managed_netns || strcmp(managed_netns, "init") == 0) {
        *mode = PHT_MANAGED_NETNS_INIT;
        return 0;
    }

    if (strcmp(managed_netns, "all") == 0) {
        *mode = PHT_MANAGED_NETNS_ALL;
        return 0;
    }

    pht_pr_err("managed_netns must be one of: init, all\n");
    return -EINVAL;
}

static int phantun_parse_ip_families(unsigned int *families) {
    if (!ip_families || strcmp(ip_families, "both") == 0) {
#if IS_ENABLED(CONFIG_IPV6)
        *families = PHT_FAMILY_IPV4 | PHT_FAMILY_IPV6;
#else
        *families = PHT_FAMILY_IPV4;
        pht_pr_warn(
            "ip_families=both requested but kernel IPv6 support is unavailable; using ipv4\n");
#endif
        return 0;
    }

    if (strcmp(ip_families, "ipv4") == 0) {
        *families = PHT_FAMILY_IPV4;
        return 0;
    }

    if (strcmp(ip_families, "ipv6") == 0) {
#if IS_ENABLED(CONFIG_IPV6)
        *families = PHT_FAMILY_IPV6;
        return 0;
#else
        pht_pr_err("ip_families=ipv6 requires kernel IPv6 support\n");
        return -EOPNOTSUPP;
#endif
    }

    pht_pr_err("ip_families must be one of: both, ipv4, ipv6\n");
    return -EINVAL;
}

static unsigned int phantun_enabled_fake_tcp_payload_limit(unsigned int enabled_families) {
    if (enabled_families & PHT_FAMILY_IPV6)
        return pht_fake_tcp_max_payload_len(AF_INET6);
    if (enabled_families & PHT_FAMILY_IPV4)
        return pht_fake_tcp_max_payload_len(AF_INET);
    return 0;
}

static int phantun_validate_second_param(const char *name, unsigned int value) {
    if (value > UINT_MAX / 1000U) {
        pht_pr_err("%s is too large; maximum is %u seconds\n", name, UINT_MAX / 1000U);
        return -EINVAL;
    }
    return 0;
}

static int phantun_validate_keepalive_jiffies(void) {
    unsigned long interval;

    interval = msecs_to_jiffies(keepalive_interval_sec * 1000U);
    if (interval && max_t(u64, 2, keepalive_misses) > LONG_MAX / interval) {
        pht_pr_err("keepalive_interval_sec * max(2, keepalive_misses) exceeds signed jiffies range\n");
        return -EINVAL;
    }
    return 0;
}

static int phantun_parse_config(struct phantun_config *cfg) {
    unsigned int i;
    int ret;

    ret = phantun_parse_managed_netns(&cfg->managed_netns);
    if (ret)
        return ret;

    ret = phantun_parse_ip_families(&cfg->enabled_families);
    if (ret)
        return ret;
    if (!managed_local_ports_count && !managed_remote_peers_count) {
        pht_pr_err("at least one selector entry is required\n");
        return -EINVAL;
    }

    for (i = 0; i < managed_local_ports_count; i++) {
        if (!managed_local_ports[i] || managed_local_ports[i] > U16_MAX) {
            pht_pr_err("managed_local_ports[%u] must be between 1 and 65535\n", i);
            return -EINVAL;
        }
        cfg->managed_local_ports[i] = (u16)managed_local_ports[i];
    }
    cfg->managed_local_ports_count = managed_local_ports_count;

    ret = phantun_snapshot_reserved_local_ports(cfg);
    if (ret)
        return ret;

    for (i = 0; i < managed_remote_peers_count; i++) {
        struct pht_managed_peer *parsed_peer = &cfg->managed_remote_peers[i];

        ret = phantun_parse_managed_remote_peer(managed_remote_peers[i], parsed_peer);
        if (ret) {
            pht_pr_err("managed_remote_peers[%u] must be valid x.y.z.w:p or [IPv6]:p\n", i);
            return ret;
        }
        if (parsed_peer->addr.family == AF_INET && !(cfg->enabled_families & PHT_FAMILY_IPV4)) {
            pht_pr_err("managed_remote_peers[%u] is IPv4 but ip_families disables IPv4\n", i);
            return -EINVAL;
        }
        if (parsed_peer->addr.family == AF_INET6 && !(cfg->enabled_families & PHT_FAMILY_IPV6)) {
            pht_pr_err("managed_remote_peers[%u] is IPv6 but ip_families disables IPv6\n", i);
            return -EINVAL;
        }
    }
    cfg->managed_remote_peers_count = managed_remote_peers_count;

    if (!handshake_timeout_ms) {
        pht_pr_err("handshake_timeout_ms must be greater than zero\n");
        return -EINVAL;
    }

    if (!handshake_retries) {
        pht_pr_err("handshake_retries must be greater than zero\n");
        return -EINVAL;
    }

    if (!keepalive_interval_sec) {
        pht_pr_err("keepalive_interval_sec must be greater than zero\n");
        return -EINVAL;
    }
    ret = phantun_validate_second_param("keepalive_interval_sec", keepalive_interval_sec);
    if (ret)
        return ret;

    if (!keepalive_misses) {
        pht_pr_err("keepalive_misses must be greater than zero\n");
        return -EINVAL;
    }
    ret = phantun_validate_keepalive_jiffies();
    if (ret)
        return ret;

    if (!hard_idle_timeout_sec) {
        pht_pr_err("hard_idle_timeout_sec must be greater than zero\n");
        return -EINVAL;
    }
    ret = phantun_validate_second_param("hard_idle_timeout_sec", hard_idle_timeout_sec);
    if (ret)
        return ret;

    if (reopen_guard_bytes >= PHANTUN_MAX_REOPEN_GUARD_BYTES) {
        pht_pr_err("reopen_guard_bytes must be smaller than 1073741824\n");
        return -EINVAL;
    }

    if (!half_open_limit) {
        pht_pr_err("half_open_limit must be greater than zero\n");
        return -EINVAL;
    }

    if (!replacement_quarantine_ms) {
        pht_pr_err("replacement_quarantine_ms must be greater than zero\n");
        return -EINVAL;
    }
    return 0;
}

#if PHANTUN_HAVE_BASE64_DECODE
static int phantun_base64_decode(const char *src, size_t srclen, u8 **out_dst,
                                 unsigned int *out_len) {
    u8 *dst;
    int decoded_len;

    if (srclen % 4 != 0)
        return -EINVAL;

    dst = kmalloc((srclen / 4) * 3, GFP_KERNEL);
    if (!dst)
        return -ENOMEM;

    decoded_len = BASE64_DECODE_COMPAT(src, srclen, dst);

    if (decoded_len < 0) {
        kfree(dst);
        return -EINVAL;
    }

    *out_dst = dst;
    *out_len = decoded_len;
    return 0;
}
#endif

static int phantun_parse_payload_param(const char *raw_str, void **out_buf, unsigned int *out_len) {
    size_t len;

    *out_buf = NULL;
    *out_len = 0;

    if (!raw_str || !*raw_str)
        return 0;

    len = strlen(raw_str);

    if (len >= 7 && strncmp(raw_str, "base64:", 7) == 0) {
        raw_str += 7;
        len -= 7;
        if (len == 0)
            return 0;

#if !PHANTUN_HAVE_BASE64_DECODE
        pht_pr_warn("base64 parameter is unsupported by this kernel, ignoring\n");
        return 0;
#else
        int ret;
        ret = phantun_base64_decode(raw_str, len, (u8 **)out_buf, out_len);
        if (ret == -ENOMEM)
            return -ENOMEM;
        if (ret) {
            pht_pr_err("failed to base64 decode parameter\n");
            return -EINVAL;
        }
        return 0;
#endif
    }

    if (len >= 4 && strncmp(raw_str, "hex:", 4) == 0) {
        raw_str += 4;
        len -= 4;

        if (len == 0)
            return 0;

        if (len % 2 != 0) {
            pht_pr_err("hex parameter must have an even length\n");
            return -EINVAL;
        }

        *out_buf = kmalloc(len / 2, GFP_KERNEL);
        if (!*out_buf)
            return -ENOMEM;

        if (hex2bin(*out_buf, raw_str, len / 2)) {
            kfree(*out_buf);
            *out_buf = NULL;
            *out_len = 0;
            pht_pr_err("invalid hex characters in parameter\n");
            return -EINVAL;
        }

        *out_len = len / 2;
        return 0;
    }

    /* Plain string fallback */
    *out_buf = kmalloc(len, GFP_KERNEL);
    if (!*out_buf)
        return -ENOMEM;
    memcpy(*out_buf, raw_str, len);
    *out_len = len;

    return 0;
}

static int phantun_validate_handshake_payload_lengths(const struct phantun_config *cfg) {
    unsigned int limit;

    if (!cfg)
        return -EINVAL;

    limit = phantun_enabled_fake_tcp_payload_limit(cfg->enabled_families);
    if (!limit)
        return -EINVAL;

    if (cfg->handshake_request_len > limit) {
        pht_pr_err("handshake_request length %u exceeds fake-TCP payload limit %u\n",
                   cfg->handshake_request_len, limit);
        return -EINVAL;
    }
    if (cfg->handshake_response_len > limit) {
        pht_pr_err("handshake_response length %u exceeds fake-TCP payload limit %u\n",
                   cfg->handshake_response_len, limit);
        return -EINVAL;
    }
    return 0;
}

static unsigned int phantun_compute_effective_replacement_protect_ms(void) {
    unsigned int retry_budget;
    unsigned int handshake_budget_ms;

    if (replacement_protect_ms)
        return replacement_protect_ms;

    retry_budget = max(1U, handshake_retries / 2U);
    if (handshake_timeout_ms > UINT_MAX / retry_budget)
        handshake_budget_ms = UINT_MAX;
    else
        handshake_budget_ms = handshake_timeout_ms * retry_budget;

    return min(replacement_quarantine_ms, handshake_budget_ms);
}

static int phantun_build_config(void) {
    void *payload;
    int ret;

    /* No hook or namespace reader exists until module initialization attaches
     * them after this function succeeds. Keep decoded payload ownership here.
     */
    memset(&phantun_cfg, 0, sizeof(phantun_cfg));
    ret = phantun_parse_config(&phantun_cfg);
    if (ret)
        return ret;

    ret = phantun_parse_payload_param(handshake_request, &payload,
                                      &phantun_cfg.handshake_request_len);
    if (ret)
        return ret;
    phantun_cfg.handshake_request = payload;

    ret = phantun_parse_payload_param(handshake_response, &payload,
                                      &phantun_cfg.handshake_response_len);
    if (ret)
        return ret;
    phantun_cfg.handshake_response = payload;
    ret = phantun_validate_handshake_payload_lengths(&phantun_cfg);
    if (ret)
        return ret;

    phantun_cfg.handshake_timeout_ms = handshake_timeout_ms;
    phantun_cfg.handshake_retries = handshake_retries;
    phantun_cfg.keepalive_interval_sec = keepalive_interval_sec;
    phantun_cfg.keepalive_misses = keepalive_misses;
    phantun_cfg.hard_idle_timeout_sec = hard_idle_timeout_sec;
    phantun_cfg.reopen_guard_bytes = reopen_guard_bytes;
    phantun_cfg.half_open_limit = half_open_limit;
    phantun_cfg.replacement_quarantine_ms = replacement_quarantine_ms;
    phantun_cfg.replacement_protect_ms = replacement_protect_ms;
    phantun_cfg.effective_replacement_protect_ms =
        phantun_compute_effective_replacement_protect_ms();

    return 0;
}

static void phantun_log_config(void) {
    unsigned int i;

    pht_pr_info("loading with %u managed local port(s) and %u managed remote peers(s):\n",
                phantun_cfg.managed_local_ports_count, phantun_cfg.managed_remote_peers_count);

    for (i = 0; i < phantun_cfg.managed_local_ports_count; i++)
        pht_pr_info("  managed_local_ports[%u] = %u\n", i, phantun_cfg.managed_local_ports[i]);

    for (i = 0; i < phantun_cfg.managed_remote_peers_count; i++) {
        const struct pht_managed_peer *peer = &phantun_cfg.managed_remote_peers[i];

        if (peer->addr.family == AF_INET)
            pht_pr_info("  managed_remote_peers[%u] = %pI4:%u\n", i, &peer->addr.v4,
                        ntohs(peer->port));
        else
            pht_pr_info("  managed_remote_peers[%u] = [%pI6c]:%u\n", i, &peer->addr.v6,
                        ntohs(peer->port));
    }

    if (phantun_cfg.managed_local_ports_count && !phantun_cfg.managed_remote_peers_count) {
        pht_pr_info("  reserved_local_ports = %s\n", reserved_local_ports && *reserved_local_ports
                                                         ? reserved_local_ports
                                                         : "<disabled>");
    }

    pht_pr_info("  managed_netns = %s\n", phantun_managed_netns_name(phantun_cfg.managed_netns));
    pht_pr_info("  ip_families = %s\n", ip_families ? ip_families : "both");
    pht_pr_info("  handshake_timeout_ms = %u\n", phantun_cfg.handshake_timeout_ms);
    pht_pr_info("  handshake_retries = %u\n", phantun_cfg.handshake_retries);
    pht_pr_info("  keepalive_interval_sec = %u\n", phantun_cfg.keepalive_interval_sec);
    pht_pr_info("  keepalive_misses = %u\n", phantun_cfg.keepalive_misses);
    pht_pr_info("  hard_idle_timeout_sec = %u\n", phantun_cfg.hard_idle_timeout_sec);
    pht_pr_info("  reopen_guard_bytes = %u\n", phantun_cfg.reopen_guard_bytes);
    pht_pr_info("  half_open_limit = %u\n", phantun_cfg.half_open_limit);
    pht_pr_info("  replacement_quarantine_ms = %u\n", phantun_cfg.replacement_quarantine_ms);
    if (phantun_cfg.replacement_protect_ms == 0)
        pht_pr_info("  replacement_protect_ms = 0 (auto effective %u)\n",
                    phantun_cfg.effective_replacement_protect_ms);
    else
        pht_pr_info("  replacement_protect_ms = %u (effective %u)\n",
                    phantun_cfg.replacement_protect_ms,
                    phantun_cfg.effective_replacement_protect_ms);
}

void phantun_config_exit(void) {
    kfree(phantun_cfg.handshake_response);
    phantun_cfg.handshake_response = NULL;
    phantun_cfg.handshake_response_len = 0;
    kfree(phantun_cfg.handshake_request);
    phantun_cfg.handshake_request = NULL;
    phantun_cfg.handshake_request_len = 0;
}

int phantun_config_init(void) {
    int ret = phantun_build_config();

    if (ret) {
        phantun_config_exit();
        return ret;
    }
    phantun_log_config();
    return 0;
}
