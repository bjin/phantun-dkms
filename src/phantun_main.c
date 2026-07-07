// SPDX-License-Identifier: GPL-2.0-or-later
//
// Copyright (C) 2026 Bin Jin. All Rights Reserved.
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/net.h>
#include <linux/net_namespace.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <linux/netfilter_ipv6.h>
#endif
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <net/netfilter/ipv6/nf_defrag_ipv6.h>
#endif
#include <net/netns/generic.h>
#include <net/route.h>
#include <net/sock.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <net/addrconf.h>
#include <net/ipv6.h>
#endif

#include "phantun_compat.h" // IWYU pragma: keep
#if PHANTUN_HAVE_BASE64_DECODE
#include <linux/base64.h>
#endif

#ifdef HAVE_LINUX_HEX_H
#include <linux/hex.h>
#endif

#ifdef HAVE_NET_GSO_H
#include <net/gso.h>
#endif

#include "phantun.h"
#include "phantun_flow.h"
#include "phantun_packet.h"
#include "phantun_stats.h"

#define PHANTUN_REOPEN_ISN_ATTEMPTS 1024U

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
MODULE_PARM_DESC(keepalive_interval_sec, "Idle time in seconds before sending a keepalive ACK");
module_param(keepalive_misses, uint, 0444);
MODULE_PARM_DESC(keepalive_misses, "Number of unanswered keepalives before flow teardown");
module_param(hard_idle_timeout_sec, uint, 0444);
MODULE_PARM_DESC(hard_idle_timeout_sec, "Maximum idle flow timeout in seconds (hard GC limit)");
module_param(reopen_guard_bytes, uint, 0444);
MODULE_PARM_DESC(reopen_guard_bytes, "Minimum sequence space separation for new connections");
module_param(half_open_limit, uint, 0444);
MODULE_PARM_DESC(half_open_limit, "Maximum concurrent half-open flows per network namespace");
module_param(replacement_quarantine_ms, uint, 0444);
MODULE_PARM_DESC(replacement_quarantine_ms,
                 "Previous-generation quarantine window in milliseconds after tuple replacement");
module_param(replacement_protect_ms, uint, 0444);
MODULE_PARM_DESC(replacement_protect_ms,
                 "Established initiator bare-SYN replacement protection window in milliseconds; "
                 "0 uses auto formula");

static struct phantun_config phantun_cfg;
static void *phantun_alloc_req;
static void *phantun_alloc_resp;
static unsigned int phantun_net_id;
static struct notifier_block phantun_inetaddr_nb;
#if IS_ENABLED(CONFIG_IPV6)
static struct notifier_block phantun_inet6addr_nb;
#endif

struct phantun_net {
    struct pht_flow_table flows;
    struct notifier_block netdev_nb;
    bool flow_table_ready;
    bool active;
    bool netdev_notifier_registered;
    bool hooks_v4_registered;
    bool defrag_v4_enabled;
#if IS_ENABLED(CONFIG_IPV6)
    bool hooks_v6_registered;
    bool defrag_v6_enabled;
#endif
    struct socket *reserved_local_socks_v4[PHANTUN_MAX_MANAGED_PORTS];
#if IS_ENABLED(CONFIG_IPV6)
    struct socket *reserved_local_socks_v6[PHANTUN_MAX_MANAGED_PORTS];
#endif
};

static unsigned int phantun_netns_id(const struct net *net) { return net ? net->ns.inum : 0; }

static struct pht_flow_table *phantun_net_flows(const struct net *net) {
    struct phantun_net *pnet;

    if (!net)
        return NULL;

    pnet = net_generic(net, phantun_net_id);
    return pnet && pnet->active ? &pnet->flows : NULL;
}

static struct pht_flow_table *phantun_net_hook_flows(const struct net *net) {
    struct phantun_net *pnet;

    if (!net)
        return NULL;

    pnet = net_generic(net, phantun_net_id);
    return pnet && pnet->flow_table_ready ? &pnet->flows : NULL;
}

static bool phantun_netns_selected(const struct net *net) {
    if (!net)
        return false;

    switch (phantun_cfg.managed_netns) {
    case PHT_MANAGED_NETNS_ALL:
        return true;
    case PHT_MANAGED_NETNS_INIT:
        return net_eq(net, &init_net);
    default:
        return false;
    }
}

/* Route/gateway changes keep the fake-TCP generation alive: cached dst reuse is
 * gated by exact route-key equality and dst_check(), so stale routes fall back
 * to lookup. Topology/source-identity events still invalidate the flow
 * generation itself because a vanished egress device or local address makes any
 * final RST best-effort at best.
 */
static int phantun_netdev_event(struct notifier_block *nb, unsigned long event, void *ptr) {
    struct phantun_net *pnet = container_of(nb, struct phantun_net, netdev_nb);
    struct net_device *dev = netdev_notifier_info_to_dev(ptr);
    unsigned int invalidated;

    if (!dev)
        return NOTIFY_DONE;

    switch (event) {
    case NETDEV_GOING_DOWN:
    case NETDEV_DOWN:
    case NETDEV_UNREGISTER:
        break;
    default:
        return NOTIFY_DONE;
    }

    invalidated = pht_flow_invalidate_egress_ifindex(&pnet->flows, dev->ifindex);
    if (invalidated)
        pht_pr_info("invalidated %u flow(s) on egress device %s(%d) after netdev event %lu\n",
                    invalidated, dev->name, dev->ifindex, event);

    return NOTIFY_DONE;
}

static int phantun_inetaddr_event(struct notifier_block *nb, unsigned long event, void *ptr) {
    struct in_ifaddr *ifa = ptr;
    struct net_device *dev;
    struct pht_flow_table *flows;
    unsigned int invalidated;

    if (event != NETDEV_DOWN || !ifa || !ifa->ifa_dev || !ifa->ifa_dev->dev)
        return NOTIFY_DONE;

    dev = ifa->ifa_dev->dev;
    flows = phantun_net_flows(dev_net(dev));
    if (!flows)
        return NOTIFY_DONE;

    {
        struct pht_addr addr = {
            .family = AF_INET,
            .v4 = ifa->ifa_local,
        };

        invalidated = pht_flow_invalidate_local_addr(flows, &addr);
    }
    if (invalidated)
        pht_pr_info("invalidated %u flow(s) after removing local IPv4 %pI4 on %s\n", invalidated,
                    &ifa->ifa_local, dev->name);

    return NOTIFY_DONE;
}

#if IS_ENABLED(CONFIG_IPV6)
static int phantun_inet6addr_event(struct notifier_block *nb, unsigned long event, void *ptr) {
    struct inet6_ifaddr *ifa = ptr;
    struct net_device *dev;
    struct pht_flow_table *flows;
    struct pht_addr addr;
    unsigned int invalidated;

    if (event != NETDEV_DOWN || !ifa || !ifa->idev || !ifa->idev->dev)
        return NOTIFY_DONE;

    dev = ifa->idev->dev;
    flows = phantun_net_flows(dev_net(dev));
    if (!flows)
        return NOTIFY_DONE;

    memset(&addr, 0, sizeof(addr));
    addr.family = AF_INET6;
    addr.v6 = ifa->addr;
    invalidated = pht_flow_invalidate_local_addr(flows, &addr);
    if (invalidated)
        pht_pr_info("invalidated %u flow(s) after removing local IPv6 %pI6c on %s\n", invalidated,
                    &ifa->addr, dev->name);

    return NOTIFY_DONE;
}
#endif

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

static void phantun_release_reserved_local_tcp_socket(struct socket **sockp) {
    if (!sockp || !*sockp)
        return;

    sock_release(*sockp);
    *sockp = NULL;
}

static void phantun_release_reserved_local_tcp_ports(struct phantun_net *pnet) {
    unsigned int i;

    if (!pnet)
        return;

    for (i = 0; i < ARRAY_SIZE(pnet->reserved_local_socks_v4); i++)
        phantun_release_reserved_local_tcp_socket(&pnet->reserved_local_socks_v4[i]);
#if IS_ENABLED(CONFIG_IPV6)
    for (i = 0; i < ARRAY_SIZE(pnet->reserved_local_socks_v6); i++)
        phantun_release_reserved_local_tcp_socket(&pnet->reserved_local_socks_v6[i]);
#endif
}

static void phantun_reserve_local_tcp_port_v4(struct phantun_net *pnet, struct net *net,
                                              unsigned int slot, u16 port) {
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(port),
    };
    struct socket *sock = NULL;
    int ret;

    ret = sock_create_kern(net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
    if (ret) {
        pht_pr_warn("failed to create reservation socket for local TCP port %u in netns %u: %d\n",
                    port, phantun_netns_id(net), ret);
        return;
    }

    ret = KERNEL_BIND_COMPAT(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret) {
        if (ret == -EADDRINUSE) {
            pht_pr_info(
                "local TCP port %u is already occupied in netns %u, leaving it unreserved\n", port,
                phantun_netns_id(net));
        } else {
            pht_pr_warn("failed to reserve local TCP port %u in netns %u: %d\n", port,
                        phantun_netns_id(net), ret);
        }
        sock_release(sock);
        return;
    }

    pnet->reserved_local_socks_v4[slot] = sock;
}

#if IS_ENABLED(CONFIG_IPV6)
static void phantun_reserve_local_tcp_port_v6(struct phantun_net *pnet, struct net *net,
                                              unsigned int slot, u16 port) {
    struct sockaddr_in6 addr = {
        .sin6_family = AF_INET6,
        .sin6_addr = IN6ADDR_ANY_INIT,
        .sin6_port = htons(port),
    };
    struct socket *sock = NULL;
    int ret;

    ret = sock_create_kern(net, AF_INET6, SOCK_STREAM, IPPROTO_TCP, &sock);
    if (ret) {
        pht_pr_warn(
            "failed to create IPv6 reservation socket for local TCP port %u in netns %u: %d\n",
            port, phantun_netns_id(net), ret);
        return;
    }

    sock->sk->sk_ipv6only = true;

    ret = KERNEL_BIND_COMPAT(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret) {
        if (ret == -EADDRINUSE)
            pht_pr_info(
                "local IPv6 TCP port %u is already occupied in netns %u, leaving it unreserved\n",
                port, phantun_netns_id(net));
        else
            pht_pr_warn("failed to reserve local IPv6 TCP port %u in netns %u: %d\n", port,
                        phantun_netns_id(net), ret);
        sock_release(sock);
        return;
    }

    pnet->reserved_local_socks_v6[slot] = sock;
}
#endif

static void phantun_reserve_configured_local_tcp_ports(struct phantun_net *pnet, struct net *net) {
    unsigned int i;

    for (i = 0; i < phantun_cfg.reserved_local_ports_count; i++) {
        if (phantun_cfg.enabled_families & PHT_FAMILY_IPV4)
            phantun_reserve_local_tcp_port_v4(pnet, net, i, phantun_cfg.reserved_local_ports[i]);
#if IS_ENABLED(CONFIG_IPV6)
        if (phantun_cfg.enabled_families & PHT_FAMILY_IPV6)
            phantun_reserve_local_tcp_port_v6(pnet, net, i, phantun_cfg.reserved_local_ports[i]);
#endif
    }
}

static void phantun_account_udp_queue_result(bool queued) {
    if (queued) {
        pht_stats_inc(PHT_STAT_UDP_PACKETS_QUEUED);
        return;
    }

    pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
    pht_stats_inc(PHT_STAT_UDP_QUEUE_FULL_DROPPED);
}

static void phantun_account_udp_translation_failure(void) {
    pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
    pht_stats_inc(PHT_STAT_UDP_TRANSLATION_FAILED_DROPPED);
}

static bool phantun_io_error_is_transient(int ret) {
    return ret == NET_XMIT_DROP || ret == -ENOBUFS || ret == -ENOMEM;
}

static void phantun_account_tcp_protocol_rejected(void) {
    pht_stats_inc(PHT_STAT_TCP_PROTOCOL_REJECTED);
}

static void phantun_account_tcp_misaligned_syn_rejected(void) {
    pht_stats_inc(PHT_STAT_TCP_PROTOCOL_REJECTED);
    pht_stats_inc(PHT_STAT_TCP_MISALIGNED_SYN_REJECTED);
}

static void phantun_account_tcp_unknown_tuple_rejected(void) {
    pht_stats_inc(PHT_STAT_TCP_PROTOCOL_REJECTED);
    pht_stats_inc(PHT_STAT_TCP_UNKNOWN_TUPLE_REJECTED);
}

static bool phantun_dev_is_loopback(const struct net_device *dev) {
    return dev && (dev->flags & IFF_LOOPBACK);
}

static bool phantun_local_out_uses_loopback_dev(const struct sk_buff *skb,
                                                const struct nf_hook_state *state) {
    const struct net_device *out_dev;

    out_dev = state->out ? state->out : skb->dev;
    return phantun_dev_is_loopback(out_dev);
}

static bool phantun_pre_routing_uses_loopback_dev(const struct sk_buff *skb,
                                                  const struct nf_hook_state *state) {
    const struct net_device *in_dev;

    in_dev = state->in ? state->in : skb->dev;
    return phantun_dev_is_loopback(in_dev);
}

/* PRE_ROUTING sees both locally delivered traffic and pure forwarding traffic.
 * The translator only owns packets that will terminate on this host/netns; it
 * must ignore transit packets even if their 4-tuple matches configured
 * selectors, otherwise a router deployment will spuriously reset or drop
 * forwarded traffic.
 */
static bool phantun_pre_routing_targets_local_host(const struct net *net,
                                                   const struct pht_addr *addr) {
    if (!net || !addr)
        return false;

    switch (addr->family) {
    case AF_INET:
        return inet_addr_type_table((struct net *)net, addr->v4, RT_TABLE_LOCAL) == RTN_LOCAL;
#if IS_ENABLED(CONFIG_IPV6)
    case AF_INET6:
        return ipv6_chk_addr((struct net *)net, &addr->v6, NULL, 0);
#endif
    default:
        return false;
    }
}

static bool phantun_local_port_allowed(__be16 port) {
    unsigned int i;

    if (!phantun_cfg.managed_local_ports_count)
        return true;

    for (i = 0; i < phantun_cfg.managed_local_ports_count; i++) {
        if (phantun_cfg.managed_local_ports[i] == ntohs(port))
            return true;
    }

    return false;
}

static bool phantun_addr_equal(const struct pht_addr *a, const struct pht_addr *b) {
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

static bool phantun_remote_peer_allowed(const struct pht_addr *addr, __be16 port) {
    unsigned int i;

    if (!phantun_cfg.managed_remote_peers_count)
        return true;

    for (i = 0; i < phantun_cfg.managed_remote_peers_count; i++) {
        if (phantun_addr_equal(&phantun_cfg.managed_remote_peers[i].addr, addr) &&
            phantun_cfg.managed_remote_peers[i].port == port)
            return true;
    }

    return false;
}

static bool phantun_selectors_allow(__be16 local_port, const struct pht_addr *remote_addr,
                                    __be16 remote_port) {
    return phantun_local_port_allowed(local_port) &&
           phantun_remote_peer_allowed(remote_addr, remote_port);
}

static void phantun_fill_udp_endpoint_pair(const struct pht_l4_view *view,
                                           struct pht_endpoint_pair *ep) {
    memset(ep, 0, sizeof(*ep));
    ep->local_port = view->udp->source;
    ep->remote_port = view->udp->dest;
    if (view->family == AF_INET) {
        ep->local_addr.family = AF_INET;
        ep->local_addr.v4 = view->iph->saddr;
        ep->remote_addr.family = AF_INET;
        ep->remote_addr.v4 = view->iph->daddr;
    } else {
        ep->local_addr.family = AF_INET6;
        ep->local_addr.v6 = view->ip6h->saddr;
        ep->remote_addr.family = AF_INET6;
        ep->remote_addr.v6 = view->ip6h->daddr;
    }
}

static void phantun_fill_tcp_endpoint_pair(const struct pht_l4_view *view,
                                           struct pht_endpoint_pair *ep) {
    memset(ep, 0, sizeof(*ep));
    ep->local_port = view->tcp->dest;
    ep->remote_port = view->tcp->source;
    if (view->family == AF_INET) {
        ep->local_addr.family = AF_INET;
        ep->local_addr.v4 = view->iph->daddr;
        ep->remote_addr.family = AF_INET;
        ep->remote_addr.v4 = view->iph->saddr;
    } else {
        ep->local_addr.family = AF_INET6;
        ep->local_addr.v6 = view->ip6h->daddr;
        ep->remote_addr.family = AF_INET6;
        ep->remote_addr.v6 = view->ip6h->saddr;
    }
}

#if IS_ENABLED(CONFIG_IPV6)
static void phantun_fill_endpoint_scope_ifindex(struct pht_endpoint_pair *ep,
                                                const struct net_device *dev) {
    if (!ep || !dev || ep->remote_addr.family != AF_INET6)
        return;

    ep->scope_ifindex = (int)ipv6_iface_scope_id(&ep->remote_addr.v6, dev->ifindex);
}
#else
static void phantun_fill_endpoint_scope_ifindex(struct pht_endpoint_pair *ep,
                                                const struct net_device *dev) {}
#endif

static void phantun_tx_meta_from_view(const struct sk_buff *skb, const struct pht_l4_view *view,
                                      bool use_oif, struct pht_tx_meta *meta) {
    const struct sock *sk;

    pht_tx_meta_init(meta);
    if (!meta || !skb || !view)
        return;

    meta->mark = skb->mark;
    meta->priority = skb->priority;

    sk = skb->sk;
    if (sk) {
        meta->uid = sk->sk_uid;
        if (use_oif && sk->sk_bound_dev_if > 0)
            meta->oif = sk->sk_bound_dev_if;
    }
    /* state->out/skb->dev are route results, not explicit policy inputs. Do
     * not feed them back as flowi oif, or a mark/TOS change made before our
     * LOCAL_OUT hook can be pinned to the pre-policy route.
     */

    if (view->family == AF_INET) {
        meta->v4_tos = view->iph->tos;
        return;
    }

#if IS_ENABLED(CONFIG_IPV6)
    if (view->family == AF_INET6) {
        meta->v6_priority = view->ip6h->priority;
        memcpy(meta->v6_flow_lbl, view->ip6h->flow_lbl, sizeof(meta->v6_flow_lbl));
    }
#endif
}

static bool phantun_addr_unsupported_for_endpoint(const struct pht_addr *addr) {
#if IS_ENABLED(CONFIG_IPV6)
    if (addr && addr->family == AF_INET6 && (ipv6_addr_type(&addr->v6) & IPV6_ADDR_LINKLOCAL))
        return true;
#endif

    return false;
}

static bool phantun_endpoint_uses_unsupported_addr(const struct pht_endpoint_pair *ep) {
    return ep && (phantun_addr_unsupported_for_endpoint(&ep->local_addr) ||
                  phantun_addr_unsupported_for_endpoint(&ep->remote_addr));
}

static bool phantun_addr_pair_uses_unsupported_addr(const struct pht_addr *local_addr,
                                                    const struct pht_addr *remote_addr) {
    return phantun_addr_unsupported_for_endpoint(local_addr) ||
           phantun_addr_unsupported_for_endpoint(remote_addr);
}

static bool phantun_family_enabled(u8 family) {
    if (family == AF_INET)
        return !!(phantun_cfg.enabled_families & PHT_FAMILY_IPV4);
    if (family == AF_INET6)
        return !!(phantun_cfg.enabled_families & PHT_FAMILY_IPV6);
    return false;
}

static int phantun_parse_udp_skb(struct sk_buff *skb, struct pht_l4_view *view) {
    int ret;

    if (skb->protocol == htons(ETH_P_IP))
        return pht_parse_ipv4_udp(skb, view);
    if (skb->protocol == htons(ETH_P_IPV6))
        return pht_parse_ipv6_udp(skb, view);

    ret = pht_parse_ipv4_udp(skb, view);
    if (!ret)
        return 0;
    return pht_parse_ipv6_udp(skb, view);
}

static int phantun_parse_tcp_skb(struct sk_buff *skb, struct pht_l4_view *view) {
    int ret;

    if (skb->protocol == htons(ETH_P_IP))
        return pht_parse_ipv4_tcp(skb, view);
    if (skb->protocol == htons(ETH_P_IPV6))
        return pht_parse_ipv6_tcp(skb, view);

    ret = pht_parse_ipv4_tcp(skb, view);
    if (!ret)
        return 0;
    return pht_parse_ipv6_tcp(skb, view);
}

static int phantun_validate_tcp_checksums(const struct sk_buff *skb,
                                          const struct pht_l4_view *view) {
    if (view->family == AF_INET)
        return pht_validate_ipv4_tcp_checksums(skb, view);
    if (view->family == AF_INET6)
        return pht_validate_ipv6_tcp_checksums(skb, view);
    return -EINVAL;
}

static void phantun_view_remote_addr(const struct pht_l4_view *view, bool tcp,
                                     struct pht_addr *addr) {
    memset(addr, 0, sizeof(*addr));
    if (view->family == AF_INET) {
        addr->family = AF_INET;
        addr->v4 = tcp ? view->iph->saddr : view->iph->daddr;
    } else {
        addr->family = AF_INET6;
        addr->v6 = tcp ? view->ip6h->saddr : view->ip6h->daddr;
    }
}

static void phantun_view_local_addr(const struct pht_l4_view *view, bool tcp,
                                    struct pht_addr *addr) {
    memset(addr, 0, sizeof(*addr));
    if (view->family == AF_INET) {
        addr->family = AF_INET;
        addr->v4 = tcp ? view->iph->daddr : view->iph->saddr;
    } else {
        addr->family = AF_INET6;
        addr->v6 = tcp ? view->ip6h->daddr : view->ip6h->saddr;
    }
}

static u32 phantun_random_aligned_seq(void) { return (get_random_u32() / 4095U) * 4095U; }

static u32 phantun_tcp_seq_advance(const struct tcphdr *th, unsigned int payload_len) {
    u32 advance = payload_len;

    if (th->syn)
        advance++;
    if (th->fin)
        advance++;

    return advance;
}

static bool phantun_tcp_is_bare_syn(const struct pht_l4_view *view);
static const u32 PHANTUN_SEQ_MAX_SIGNED_WINDOW = 0x7fffffffU;

static bool phantun_seq_after_eq(u32 seq1, u32 seq2) { return (s32)(seq1 - seq2) >= 0; }

static bool phantun_seq_before_eq(u32 seq1, u32 seq2) { return (s32)(seq1 - seq2) <= 0; }

static bool phantun_seq_between(u32 seq, u32 start, u32 end) {
    return phantun_seq_after_eq(seq, start) && phantun_seq_before_eq(seq, end);
}

/* These lower edges are deliberately stateful instead of recomputing from
 * local_isn/peer_syn_next on demand. Once a generation sends or receives more
 * than one full u32 wrap of sequence space, (end - initial_base) can look small
 * again, so a pure modulo calculation would reopen an over-wide signed compare
 * window. Advancing the stored edge monotonically preserves the bounded window
 * invariant for arbitrarily long-lived flows.
 */
static u32 phantun_seq_window_lower_edge(u32 lower_edge, u32 end) {
    if (end - lower_edge > PHANTUN_SEQ_MAX_SIGNED_WINDOW)
        return end - PHANTUN_SEQ_MAX_SIGNED_WINDOW;
    return lower_edge;
}

static void phantun_flow_refresh_local_seq_window_locked(struct pht_flow *flow) {
    flow->local_seq_window_start =
        phantun_seq_window_lower_edge(flow->local_seq_window_start, flow->seq);
}

static void phantun_flow_refresh_remote_seq_window_locked(struct pht_flow *flow) {
    flow->remote_seq_window_start =
        phantun_seq_window_lower_edge(flow->remote_seq_window_start, flow->ack);
}

/* Remember only the immediately previous generation on a tuple. During the
 * configured quarantine window, packets that still fit that old seq/ack
 * space are dropped instead of provoking fresh RSTs after a replacement SYN
 * wins.
 */
static void phantun_flow_arm_prev_generation_quarantine(struct pht_flow *flow, u32 prev_local_start,
                                                        u32 prev_local_end, u32 prev_remote_start,
                                                        u32 prev_remote_end) {
    if (!flow)
        return;

    spin_lock_bh(&flow->lock);
    flow->quarantine_prev_local_seq_start = prev_local_start;
    flow->quarantine_prev_local_seq_end = prev_local_end;
    flow->quarantine_prev_remote_seq_start = prev_remote_start;
    flow->quarantine_prev_remote_seq_end = prev_remote_end;
    flow->quarantine_until_jiffies =
        jiffies + msecs_to_jiffies(phantun_cfg.replacement_quarantine_ms);
    flow->quarantine_prev_active = true;
    spin_unlock_bh(&flow->lock);
}

static bool phantun_flow_matches_quarantine_locked(const struct pht_flow *flow,
                                                   const struct pht_l4_view *view) {
    u32 seq;
    u32 ack;
    bool seq_matches;

    seq = ntohl(view->tcp->seq);
    ack = ntohl(view->tcp->ack_seq);
    seq_matches = phantun_seq_between(seq, flow->quarantine_prev_remote_seq_start,
                                      flow->quarantine_prev_remote_seq_end);
    if (!seq_matches)
        return false;

    if (view->tcp->rst && !view->tcp->ack)
        return true;
    if (!view->tcp->ack)
        return false;

    return phantun_seq_between(ack, flow->quarantine_prev_local_seq_start,
                               flow->quarantine_prev_local_seq_end);
}

static bool phantun_flow_matches_current_generation_locked(const struct pht_flow *flow,
                                                           const struct pht_l4_view *view) {
    u32 seq;
    u32 ack;
    seq = ntohl(view->tcp->seq);
    ack = ntohl(view->tcp->ack_seq);

    if (!phantun_seq_between(seq, flow->remote_seq_window_start, flow->ack))
        return false;
    if (view->tcp->rst && !view->tcp->ack)
        return true;
    if (!view->tcp->ack)
        return false;

    return phantun_seq_between(ack, flow->local_seq_window_start, flow->seq);
}

static bool phantun_flow_should_drop_quarantined_packet(struct pht_flow *flow,
                                                        const struct pht_l4_view *view) {
    bool drop = false;

    if (!flow || !view || phantun_tcp_is_bare_syn(view))
        return false;

    spin_lock_bh(&flow->lock);
    if (!flow->quarantine_prev_active)
        goto out;
    if (time_after_eq(jiffies, flow->quarantine_until_jiffies)) {
        flow->quarantine_prev_active = false;
        goto out;
    }
    if (!phantun_flow_matches_quarantine_locked(flow, view))
        goto out;
    if (flow->state == PHT_FLOW_STATE_ESTABLISHED &&
        phantun_flow_matches_current_generation_locked(flow, view))
        goto out;
    drop = true;
out:
    spin_unlock_bh(&flow->lock);
    if (drop)
        pht_stats_inc(PHT_STAT_REPLACEMENT_QUARANTINE_DROPPED);
    return drop;
}

/* A protocol-opening or replacement SYN really must be SYN-only. If other
 * control flags ride along, later state-machine code cannot safely treat it as
 * a clean opener and should fall back to the generic invalid-SYN path instead.
 */
static bool phantun_tcp_is_bare_syn(const struct pht_l4_view *view) {
    return view && view->tcp->syn && !view->tcp->ack && !view->tcp->rst && !view->tcp->fin &&
           !view->tcp->psh && !view->tcp->urg && view->payload_len == 0;
}

/* Completing the initiator half-open handshake only accepts a clean SYN|ACK.
 * PSH is rejected here because this packet shape is control-only; no payload or
 * payload-signalling flags are meaningful until the final ACK path.
 */
static bool phantun_tcp_is_clean_synack(const struct pht_l4_view *view, u32 expected_ack) {
    return view && view->tcp->syn && view->tcp->ack && ntohl(view->tcp->ack_seq) == expected_ack &&
           view->payload_len == 0 && !view->tcp->rst && !view->tcp->fin && !view->tcp->psh &&
           !view->tcp->urg;
}

/* Established fake-TCP is only an ACK-shaped UDP carrier. PSH is tolerated with
 * ACK because it does not consume sequence space and some peers mark data with
 * it; FIN and URG require TCP semantics this module does not implement.
 */
static bool phantun_tcp_is_established_ack(const struct pht_l4_view *view) {
    return view && view->tcp->ack && !view->tcp->syn && !view->tcp->rst && !view->tcp->fin &&
           !view->tcp->urg;
}

/* The responder's final handshake step may carry payload and PSH. Keep this
 * aligned with opener validation: control flags that consume sequence space or
 * require unsupported semantics must not complete SYN_RCVD just by guessing the
 * right ACK number.
 */
static bool phantun_tcp_is_syn_rcvd_final_ack(const struct pht_l4_view *view, u32 expected_ack) {
    return view && view->tcp->ack && ntohl(view->tcp->ack_seq) == expected_ack && !view->tcp->syn &&
           !view->tcp->rst && !view->tcp->fin && !view->tcp->urg;
}

static bool phantun_tcp_syn_is_aligned(const struct pht_l4_view *view) {
    return view && ntohl(view->tcp->seq) % 4095U == 0;
}

static bool phantun_flow_should_drop_protected_replacement_syn(struct pht_flow *flow,
                                                               const struct pht_l4_view *view) {
    unsigned long now;
    bool drop = false;

    if (!flow || !view || !phantun_tcp_is_bare_syn(view) || !phantun_tcp_syn_is_aligned(view))
        return false;

    now = jiffies;
    spin_lock_bh(&flow->lock);
    if (flow->state != PHT_FLOW_STATE_ESTABLISHED || flow->role != PHT_FLOW_ROLE_INITIATOR ||
        !flow->replacement_protect_active)
        goto out;
    if (time_before(now, flow->replacement_protect_until_jiffies)) {
        drop = true;
        goto out;
    }
    flow->replacement_protect_active = false;

out:
    spin_unlock_bh(&flow->lock);
    if (drop)
        pht_stats_inc(PHT_STAT_REPLACEMENT_PROTECT_DROPPED);
    return drop;
}

/* Local reopen chooses a new aligned ISN outside reopen_guard_bytes of the
 * previous local sequence space so delayed old-generation packets are less
 * likely to fit the new flow.
 */
static bool phantun_pick_reopen_isn(u32 prev_seq, bool has_prev_seq, u32 *init_seq) {
    unsigned int attempt;

    if (!init_seq)
        return false;

    for (attempt = 0; attempt < PHANTUN_REOPEN_ISN_ATTEMPTS; attempt++) {
        u32 candidate = phantun_random_aligned_seq();

        if (has_prev_seq) {
            u32 diff = candidate - prev_seq;
            u32 abs_diff = diff < 0x80000000U ? diff : -diff;

            if (abs_diff < phantun_cfg.reopen_guard_bytes)
                continue;
        }

        *init_seq = candidate;
        return true;
    }

    return false;
}

static bool phantun_request_enabled(void) { return phantun_cfg.handshake_request_len > 0; }

static bool phantun_response_enabled(void) {
    return phantun_request_enabled() && phantun_cfg.handshake_response_len > 0;
}

static int phantun_send_flow_rst(struct pht_flow *flow, struct net *net) {
    struct pht_endpoint_pair ep;
    struct pht_tx_meta meta;
    u32 seq;
    u32 ack;
    int ifindex;
    int ret;

    spin_lock_bh(&flow->lock);
    ep = flow->endpoints;
    seq = flow->seq;
    ack = flow->ack;
    meta = flow->local_tx_meta;
    spin_unlock_bh(&flow->lock);

    ret = pht_emit_fake_tcp(net, &ep, seq, ack, PHT_TCP_FLAG_RST, NULL, 0, &meta, &ifindex);
    if (!ret) {
        pht_flow_set_egress_ifindex(flow, ifindex);
        pht_stats_inc(PHT_STAT_RST_SENT);
    }
    return ret;
}

/* Returns 0 for a successful emit, a stale-generation drop, or a transient
 * local I/O drop where the UDP skb is intentionally consumed. -EMSGSIZE is
 * non-terminal. Any other error owns terminal established-send teardown before
 * returning.
 */
static int phantun_send_established_udp(struct pht_flow *flow, const struct pht_endpoint_pair *ep,
                                        const struct pht_l4_view *view, const struct sk_buff *skb,
                                        const struct pht_tx_meta *meta, struct net *net,
                                        bool persist_meta, bool send_rst_on_fatal_failure,
                                        bool *emitted_payload) {
    u32 local_seq_window_start;
    bool fatal_failure = false;
    u32 seq;
    u32 ack;
    int ifindex;
    int ret;

    if (emitted_payload)
        *emitted_payload = false;

    if (view->payload_len > pht_fake_tcp_max_payload_len(view->family)) {
        pht_stats_inc(PHT_STAT_OVERSIZED_PAYLOADS_DROPPED);
        pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
        return -EMSGSIZE;
    }

    /* Reserve sequence space before emitting so concurrent local senders stay
     * ordered. Stale-generation and terminal failures roll the reservation back
     * when safe; transient local pressure consumes the sequence range exactly
     * like on-path packet loss.
     *
     * For immediate local-out sends, the current UDP skb's metadata is also the
     * best local transmit policy context for later synthetic packets. Queued
     * skb metadata remains per-skb only; replaying an older queued packet must
     * not overwrite a newer local_tx_meta learned while the queue was full.
     */
    spin_lock_bh(&flow->tx_lock);
    spin_lock_bh(&flow->lock);
    if (flow->state != PHT_FLOW_STATE_ESTABLISHED) {
        spin_unlock_bh(&flow->lock);
        spin_unlock_bh(&flow->tx_lock);
        return 0;
    }
    if (persist_meta && meta)
        flow->local_tx_meta = *meta;
    seq = flow->seq;
    ack = flow->ack;
    local_seq_window_start = flow->local_seq_window_start;
    flow->seq += view->payload_len;
    phantun_flow_refresh_local_seq_window_locked(flow);
    spin_unlock_bh(&flow->lock);

    ret = pht_flow_emit_established_payload(flow, net, ep, seq, ack, skb, view->payload_offset,
                                            view->payload_len, meta, &ifindex);
    if (!ret) {
        unsigned long now = jiffies;
        u64 now64 = get_jiffies_64();
        spin_lock_bh(&flow->lock);
        if (flow->state == PHT_FLOW_STATE_ESTABLISHED) {
            flow->last_activity_jiffies = now;
            flow->last_established_payload_tx_jiffies = now64;
            flow->egress_ifindex = ifindex;
            if (persist_meta && meta)
                flow->local_tx_meta = *meta;
        }
        spin_unlock_bh(&flow->lock);
        if (emitted_payload)
            *emitted_payload = true;
    } else {
        bool stale_generation = ret == -EAGAIN;
        bool transient_failure = phantun_io_error_is_transient(ret);

        spin_lock_bh(&flow->lock);
        if (!transient_failure && flow->state == PHT_FLOW_STATE_ESTABLISHED &&
            flow->seq == seq + view->payload_len) {
            flow->seq = seq;
            flow->local_seq_window_start = local_seq_window_start;
        }
        if (!stale_generation && !transient_failure) {
            flow->state = PHT_FLOW_STATE_DEAD;
            fatal_failure = true;
        }
        spin_unlock_bh(&flow->lock);
        /* -EAGAIN is the emit helper's generation guard: the flow stopped
         * matching this packet while the skb/dst was being prepared. Transient
         * queue/memory pressure consumes only this UDP payload; the established
         * generation remains live and later packets continue in sequence.
         */
        if (stale_generation) {
            ret = 0;
        } else if (transient_failure) {
            phantun_account_udp_translation_failure();
            ret = 0;
        }
    }
    spin_unlock_bh(&flow->tx_lock);

    if (fatal_failure) {
        if (send_rst_on_fatal_failure)
            phantun_send_flow_rst(flow, net);
        pht_flow_remove(flow);
    }

    return ret;
}

/* @reply_meta is an emission-only override for responder replies generated
 * directly from an inbound fake-TCP packet. When NULL, use the cached local
 * outbound policy context for retransmits and other synthetic packets.
 */
static int phantun_send_synack(struct pht_flow *flow, struct net *net,
                               const struct pht_tx_meta *reply_meta) {
    struct pht_endpoint_pair ep;
    struct pht_tx_meta meta;
    u32 seq;
    u32 ack;
    int ifindex;
    int ret;

    spin_lock_bh(&flow->lock);
    ep = flow->endpoints;
    seq = flow->local_isn;
    ack = flow->peer_syn_next;
    meta = reply_meta ? *reply_meta : flow->local_tx_meta;
    spin_unlock_bh(&flow->lock);

    ret = pht_emit_fake_tcp(net, &ep, seq, ack, PHT_TCP_FLAG_SYN | PHT_TCP_FLAG_ACK, NULL, 0, &meta,
                            &ifindex);
    if (!ret)
        pht_flow_set_egress_ifindex(flow, ifindex);
    return ret;
}

static int phantun_send_rstack(struct net *net, const struct pht_endpoint_pair *ep,
                               const struct pht_l4_view *view, const struct pht_tx_meta *meta,
                               bool force_zero_seq) {
    u32 seq = force_zero_seq ? 0 : ntohl(view->tcp->ack_seq);
    u32 ack = ntohl(view->tcp->seq) + phantun_tcp_seq_advance(view->tcp, view->payload_len);
    int ret;

    ret = pht_emit_fake_tcp(net, ep, seq, ack, PHT_TCP_FLAG_RST | PHT_TCP_FLAG_ACK, NULL, 0, meta,
                            NULL);
    if (!ret)
        pht_stats_inc(PHT_STAT_RST_SENT);
    return ret;
}

static int phantun_send_handshake_request(struct pht_flow *flow, struct net *net) {
    struct pht_endpoint_pair ep;
    struct pht_tx_meta meta;
    u32 seq;
    u32 ack;
    size_t req_len = phantun_cfg.handshake_request_len;
    int ifindex;
    int ret;

    spin_lock_bh(&flow->lock);
    ep = flow->endpoints;
    seq = flow->local_isn + 1;
    ack = flow->ack;
    meta = flow->local_tx_meta;
    spin_unlock_bh(&flow->lock);

    ret = pht_emit_fake_tcp(net, &ep, seq, ack, PHT_TCP_FLAG_ACK, phantun_cfg.handshake_request,
                            req_len, &meta, &ifindex);
    if (!ret) {
        spin_lock_bh(&flow->lock);
        flow->last_ack = ack;
        flow->last_activity_jiffies = jiffies;
        flow->egress_ifindex = ifindex;
        spin_unlock_bh(&flow->lock);
        pht_stats_inc(PHT_STAT_REQUEST_PAYLOADS_INJECTED);
    }
    return ret;
}

/* Same reply-scoped metadata rule as phantun_send_synack(). */
static int phantun_send_handshake_response(struct pht_flow *flow, struct net *net,
                                           const struct pht_tx_meta *reply_meta) {
    struct pht_endpoint_pair ep;
    struct pht_tx_meta meta;
    u32 seq;
    u32 ack;
    size_t resp_len = phantun_cfg.handshake_response_len;
    int ifindex;
    int ret;

    spin_lock_bh(&flow->lock);
    ep = flow->endpoints;
    seq = flow->local_isn + 1;
    ack = flow->ack;
    meta = reply_meta ? *reply_meta : flow->local_tx_meta;
    spin_unlock_bh(&flow->lock);

    ret = pht_emit_fake_tcp(net, &ep, seq, ack, PHT_TCP_FLAG_ACK, phantun_cfg.handshake_response,
                            resp_len, &meta, &ifindex);
    if (!ret) {
        spin_lock_bh(&flow->lock);
        flow->last_ack = ack;
        flow->last_activity_jiffies = jiffies;
        flow->egress_ifindex = ifindex;
        spin_unlock_bh(&flow->lock);
        pht_stats_inc(PHT_STAT_RESPONSE_PAYLOADS_INJECTED);
    }
    return ret;
}

static int phantun_send_idle_ack(struct pht_flow *flow, struct net *net,
                                 const struct pht_tx_meta *reply_meta) {
    struct pht_endpoint_pair ep;
    struct pht_tx_meta meta;
    u32 seq;
    u32 ack;
    int ifindex;
    int ret;

    spin_lock_bh(&flow->lock);
    ep = flow->endpoints;
    seq = flow->seq;
    ack = flow->ack;
    meta = reply_meta ? *reply_meta : flow->local_tx_meta;
    spin_unlock_bh(&flow->lock);

    ret = pht_emit_fake_tcp(net, &ep, seq, ack, PHT_TCP_FLAG_ACK, NULL, 0, &meta, &ifindex);
    if (!ret) {
        spin_lock_bh(&flow->lock);
        flow->last_ack = ack;
        flow->last_activity_jiffies = jiffies;
        flow->egress_ifindex = ifindex;
        spin_unlock_bh(&flow->lock);
    }
    return ret;
}

static int phantun_flush_queued_udp(struct pht_flow *flow, struct net *net, bool *emitted_payload) {
    struct sk_buff *queued_skb;
    struct pht_l4_view qview;
    struct pht_endpoint_pair qep;
    struct pht_tx_meta meta;
    bool payload_emitted = false;
    int ret;

    if (emitted_payload)
        *emitted_payload = false;

    queued_skb = pht_flow_take_queued_skb(flow, &meta);
    if (!queued_skb)
        return 0;

    ret = phantun_parse_udp_skb(queued_skb, &qview);
    if (ret) {
        phantun_account_udp_translation_failure();
        kfree_skb(queued_skb);
        return ret;
    }

    if (!qview.payload_len) {
        pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
        kfree_skb(queued_skb);
        return 0;
    }

    phantun_fill_udp_endpoint_pair(&qview, &qep);
    qep.scope_ifindex = flow->endpoints.scope_ifindex;
    ret = phantun_send_established_udp(flow, &qep, &qview, queued_skb, &meta, net, false, false,
                                       &payload_emitted);
    if (ret && ret != -EMSGSIZE) {
        phantun_account_udp_translation_failure();
        kfree_skb(queued_skb);
        return ret;
    }

    if (payload_emitted && emitted_payload)
        *emitted_payload = true;

    kfree_skb(queued_skb);
    return 0;
}

static void phantun_discard_queued_udp_translation_failure(struct pht_flow *flow) {
    struct sk_buff *queued_skb = pht_flow_take_queued_skb(flow, NULL);

    if (!queued_skb)
        return;

    phantun_account_udp_translation_failure();
    kfree_skb(queued_skb);
}

static bool phantun_payload_exceeds_udp_reinject_limit(const struct pht_l4_view *view) {
    if (view->family == AF_INET)
        return view->payload_len > PHT_V4_MAX_UDP_PAYLOAD_LEN;
    if (view->family == AF_INET6)
        return view->payload_len > PHT_V6_MAX_UDP_PAYLOAD_LEN;
    return true;
}

static int phantun_reinject_inbound_payload(const struct pht_endpoint_pair *ep,
                                            const struct sk_buff *skb,
                                            const struct pht_l4_view *view, struct net *net,
                                            struct net_device *dev) {
    struct pht_flow_table *flows;

    if (!view->payload_len)
        return 0;

    /* netif_rx() derives receive namespace from skb->dev.  PRE_ROUTING
     * should hand us an ingress device from state->net; make that contract
     * explicit before manufacturing a UDP packet for local delivery.
     */
    if (!net || !dev || dev_net(dev) != net)
        return -EINVAL;

    flows = phantun_net_hook_flows(net);
    if (!flows)
        return -EINVAL;

    return pht_reinject_udp_payload_from_skb(dev, ep, skb, view->payload_offset, view->payload_len,
                                             flows->reinject_mark);
}

static void phantun_refresh_inbound_progress(struct pht_flow *flow, const struct pht_l4_view *view,
                                             bool *allow_flush) {
    u32 seq_end = ntohl(view->tcp->seq) + view->payload_len;

    spin_lock_bh(&flow->lock);
    /* Reserved shaping payloads can arrive after higher-sequence real data.
     * Keep our advertised ACK monotonic when we silently drop that delayed
     * control packet.
     */
    if (phantun_seq_after_eq(seq_end, flow->ack))
        flow->ack = seq_end;
    phantun_flow_refresh_remote_seq_window_locked(flow);
    flow->last_ack = flow->ack;
    flow->last_activity_jiffies = jiffies;
    flow->last_inbound_jiffies = jiffies;
    flow->keepalives_sent = 0;
    if (allow_flush)
        *allow_flush = !flow->response_pending_ack;
    spin_unlock_bh(&flow->lock);
}

static void phantun_note_inbound_payload(struct pht_flow *flow, const struct pht_l4_view *view) {
    phantun_refresh_inbound_progress(flow, view, NULL);
}

/* Caller holds flow->lock. */
static bool phantun_consume_drop_next_rx_payload_locked(struct pht_flow *flow,
                                                        const struct pht_l4_view *view) {
    if (!view->payload_len || !flow->drop_next_rx_payload ||
        ntohl(view->tcp->seq) != flow->drop_next_rx_seq)
        return false;

    flow->drop_next_rx_payload = false;
    flow->drop_next_rx_seq = 0;
    return true;
}

/* Immediate inbound-data ACK suppression is deliberately a short, local
 * bidirectional burst optimization.  Expire stale timestamps under the flow
 * lock so old local sends cannot re-enter the window after jiffies wrap.
 */
static bool phantun_should_suppress_idle_ack(struct pht_flow *flow) {
    u64 last_tx;
    u64 now;
    unsigned long window;
    u64 deadline;
    bool suppress;

    spin_lock_bh(&flow->lock);
    last_tx = flow->last_established_payload_tx_jiffies;
    suppress = false;
    if (last_tx != 0) {
        now = get_jiffies_64();
        window = flow->table->idle_ack_suppression_window_jiffies;
        deadline = last_tx + window;
        suppress = time_after_eq64(now, last_tx) && time_before64(now, deadline);
        if (!suppress && time_after_eq64(now, deadline))
            flow->last_established_payload_tx_jiffies = 0;
    }
    spin_unlock_bh(&flow->lock);

    return suppress;
}

static int
phantun_finalize_established_rx(struct pht_flow *flow, const struct pht_endpoint_pair *ep,
                                const struct sk_buff *skb, const struct pht_l4_view *view,
                                struct net *net, struct net_device *dev, bool reinject_payload,
                                bool send_idle_ack, const struct pht_tx_meta *reply_meta) {
    bool allow_flush;
    int ret = 0;

    /* Oversized inbound payload is a protocol violation for this translator.
     * We cannot truthfully repackage it into a local UDP skb within our fixed
     * packet budget, so reject it before any ACK/liveness state is refreshed
     * or any large atomic allocation is attempted.
     */
    if (view->payload_len && phantun_payload_exceeds_udp_reinject_limit(view)) {
        pht_stats_inc(PHT_STAT_OVERSIZED_PAYLOADS_DROPPED);
        return -EMSGSIZE;
    }

    phantun_refresh_inbound_progress(flow, view, &allow_flush);

    if (reinject_payload) {
        ret = phantun_reinject_inbound_payload(ep, skb, view, net, dev);
        if (ret == -ENOBUFS || ret == -ENOMEM) {
            pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
            pht_stats_inc(PHT_STAT_UDP_REINJECT_FAILED_DROPPED);
            ret = 0;
        } else if (ret) {
            return ret;
        }
    }

    if (allow_flush) {
        ret = phantun_flush_queued_udp(flow, net, NULL);
        if (ret) {
            phantun_discard_queued_udp_translation_failure(flow);
            return ret;
        }
    }

    if (send_idle_ack && view->payload_len) {
        /* Reserved first-payload control drops are not application data; they
         * still need the prompt pure ACK that releases control-response state.
         */
        if (reinject_payload && phantun_should_suppress_idle_ack(flow)) {
            pht_stats_inc(PHT_STAT_IDLE_ACKS_SUPPRESSED);
        } else {
            ret = phantun_send_idle_ack(flow, net, reply_meta);
            if (phantun_io_error_is_transient(ret))
                ret = 0;
        }
    }
    return ret;
}

static int phantun_confirm_outbound_udp_conntrack(struct sk_buff *skb) {
    enum ip_conntrack_info ctinfo;
    struct nf_conn *ct;
    int verdict;

    ct = nf_ct_get(skb, &ctinfo);
    if (!ct || ctinfo == IP_CT_UNTRACKED)
        return 0;

    /* LOCAL_OUT conntrack must survive our NF_STOLEN verdict so translated
     * inbound UDP replies can match ESTABLISHED host-firewall policy.
     */
    verdict = nf_conntrack_confirm(skb);
    if (verdict != NF_ACCEPT)
        return verdict == NF_DROP ? -EINVAL : -EIO;

    return 0;
}

static unsigned int phantun_local_out(void *priv, struct sk_buff *skb,
                                      const struct nf_hook_state *state);

/* UDP GSO superframes reach LOCAL_OUT before software/device segmentation.
 * Split owned UDP_L4 skbs here so each datagram follows the normal fake-TCP
 * translation path and half-open one-skb queue contract independently.
 */
static unsigned int phantun_local_out_segment_gso(void *priv, struct sk_buff *skb,
                                                  const struct nf_hook_state *state) {
    netdev_features_t features = NETIF_F_SG | NETIF_F_IP_CSUM;
    struct sk_buff *segs;
    struct sk_buff *seg;
    struct sk_buff *next;
    long err;

    if (!skb_is_gso(skb))
        return NF_ACCEPT;
    if (!(skb_shinfo(skb)->gso_type & SKB_GSO_UDP_L4)) {
        pht_pr_warn_rl("dropping outbound UDP skb with unexpected gso_type %#x\n",
                       skb_shinfo(skb)->gso_type);
        phantun_account_udp_translation_failure();
        return NF_DROP;
    }
    if (skb->protocol == htons(ETH_P_IPV6))
        features = NETIF_F_SG | NETIF_F_IPV6_CSUM;

    segs = __skb_gso_segment(skb, features, true);
    if (IS_ERR_OR_NULL(segs)) {
        err = IS_ERR(segs) ? PTR_ERR(segs) : -EINVAL;
        pht_pr_warn_rl("failed to segment outbound UDP GSO skb: %ld\n", err);
        phantun_account_udp_translation_failure();
        return NF_DROP;
    }

    consume_skb(skb);

    skb_list_walk_safe(segs, seg, next) {
        unsigned int verdict;

        skb_mark_not_on_list(seg);
        /* LOCAL_OUT consumes owned skbs on every normal path. If a segment
         * escapes that contract, keep ownership here and drop it explicitly.
         */
        verdict = phantun_local_out(priv, seg, state);
        if (verdict != NF_STOLEN) {
            pht_pr_warn_rl("segmented outbound UDP packet unexpectedly escaped fake-TCP handler\n");
            kfree_skb(seg);
        }
    }

    return NF_STOLEN;
}

/* LOCAL_OUT owns selector-matched outbound UDP. ESTABLISHED flows send
 * immediately, half-open flows keep only one queued skb, and DEAD flows are
 * reopened from scratch with a guarded ISN.
 */
static unsigned int phantun_local_out(void *priv, struct sk_buff *skb,
                                      const struct nf_hook_state *state) {
    struct pht_l4_view view;
    struct pht_endpoint_pair ep;
    struct pht_addr remote_addr;
    struct pht_tx_meta tx_meta;
    struct pht_flow_table *flows;
    struct pht_flow *flow;
    struct pht_flow *new_flow;
    struct pht_flow *dead_flow = NULL;
    enum pht_flow_state state_now;
    u32 init_seq;
    u32 prev_seq = 0;
    bool has_prev_seq = false;
    int ret;
    bool queued;

    if (!state || !skb)
        return NF_ACCEPT;

    flows = phantun_net_hook_flows(state->net);
    if (!flows)
        return NF_ACCEPT;

    ret = phantun_parse_udp_skb(skb, &view);
    if (ret)
        return NF_ACCEPT;
    if (!phantun_family_enabled(view.family))
        return NF_ACCEPT;

    if (phantun_local_out_uses_loopback_dev(skb, state))
        return NF_ACCEPT;

    phantun_view_remote_addr(&view, false, &remote_addr);
    if (!phantun_selectors_allow(view.udp->source, &remote_addr, view.udp->dest))
        return NF_ACCEPT;

    phantun_fill_udp_endpoint_pair(&view, &ep);
    phantun_fill_endpoint_scope_ifindex(&ep, state->out ? state->out : skb->dev);
    phantun_tx_meta_from_view(skb, &view, true, &tx_meta);
    if (phantun_endpoint_uses_unsupported_addr(&ep)) {
        pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
        pht_pr_warn_rl("rejecting outbound UDP with unsupported endpoint address\n");
        return NF_DROP;
    }

    ret = phantun_local_out_segment_gso(priv, skb, state);
    if (ret != NF_ACCEPT)
        return ret;

    if (!view.payload_len) {
        /* Zero-payload fake-TCP ACKs are control/liveness frames, so the
         * current wire protocol has no lossless representation for an empty
         * UDP datagram.
         */
        pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
        kfree_skb(skb);
        return NF_STOLEN;
    }

    ret = phantun_confirm_outbound_udp_conntrack(skb);
    if (ret) {
        phantun_account_udp_translation_failure();
        pht_pr_warn_rl("failed to confirm outbound UDP conntrack before translation: %d\n", ret);
        kfree_skb(skb);
        return NF_STOLEN;
    }

retry_lookup:
    flow = pht_flow_lookup(flows, &ep);
    if (flow) {
        spin_lock_bh(&flow->lock);
        state_now = flow->state;
        spin_unlock_bh(&flow->lock);

        if (state_now == PHT_FLOW_STATE_ESTABLISHED) {
            bool hold_responder_data;

            spin_lock_bh(&flow->lock);
            hold_responder_data =
                flow->role == PHT_FLOW_ROLE_RESPONDER && flow->response_pending_ack;
            spin_unlock_bh(&flow->lock);
            /* Responder-owned UDP must wait while an injected
             * handshake_response still needs peer acknowledgement or later
             * initiator data to prove the reserved control slot was
             * skipped.
             */
            if (hold_responder_data) {
                queued = pht_flow_queue_skb_if_empty(flow, skb, &tx_meta);
                if (!queued)
                    kfree_skb(skb);
                phantun_account_udp_queue_result(queued);
                pht_flow_put(flow);
                return NF_STOLEN;
            }

            ret = phantun_send_established_udp(flow, &ep, &view, skb, &tx_meta, state->net, true,
                                               true, NULL);
            if (ret && ret != -EMSGSIZE) {
                phantun_account_udp_translation_failure();
                pht_pr_warn("failed to emit fake-TCP payload for established flow: %d\n", ret);
            }
            pht_flow_put(flow);
            kfree_skb(skb);
            return NF_STOLEN;
        }

        if (pht_flow_state_is_half_open(state_now)) {
            queued = pht_flow_queue_skb_if_empty(flow, skb, &tx_meta);
            if (!queued)
                kfree_skb(skb);
            phantun_account_udp_queue_result(queued);
            pht_flow_put(flow);
            return NF_STOLEN;
        }

        /* A hashed DEAD flow is only the allocation-failure tombstone from
         * terminal teardown. Keep it visible until the guarded replacement is
         * published, so competing openers always see a previous-generation
         * sequence source or the new live flow.
         */
        if (state_now == PHT_FLOW_STATE_DEAD) {
            spin_lock_bh(&flow->lock);
            prev_seq = flow->seq;
            spin_unlock_bh(&flow->lock);
            has_prev_seq = true;
            dead_flow = flow;
            goto create_initiator;
        }

        pht_flow_put(flow);
        kfree_skb(skb);
        return NF_STOLEN;
    }

    if (!has_prev_seq)
        has_prev_seq = pht_flow_lookup_retired_seq(flows, &ep, &prev_seq);

create_initiator:
    new_flow = pht_flow_create(flows, &ep, PHT_FLOW_ROLE_INITIATOR, PHT_FLOW_STATE_SYN_SENT);
    if (IS_ERR(new_flow)) {
        phantun_account_udp_translation_failure();
        pht_pr_warn("failed to create initiator flow: %ld\n", PTR_ERR(new_flow));
        kfree_skb(skb);
        if (dead_flow)
            pht_flow_put(dead_flow);
        return NF_STOLEN;
    }

    if (!phantun_pick_reopen_isn(prev_seq, has_prev_seq, &init_seq)) {
        phantun_account_udp_translation_failure();
        pht_pr_warn("failed to choose reopen ISN for new flow\n");
        pht_flow_put(new_flow);
        if (dead_flow)
            pht_flow_put(dead_flow);
        kfree_skb(skb);
        return NF_STOLEN;
    }

    spin_lock_bh(&new_flow->lock);
    new_flow->seq = init_seq;
    new_flow->ack = 0;
    new_flow->last_ack = 0;
    new_flow->local_isn = init_seq;
    new_flow->peer_syn_next = 0;
    new_flow->local_seq_window_start = new_flow->local_isn;
    new_flow->remote_seq_window_start = new_flow->peer_syn_next;
    new_flow->local_tx_meta = tx_meta;
    spin_unlock_bh(&new_flow->lock);
    pht_flow_set_queued_skb(new_flow, skb, &tx_meta);

    if (dead_flow)
        ret = pht_flow_replace_dead(flows, dead_flow, new_flow);
    else
        ret = pht_flow_insert(flows, new_flow);
    /* Another CPU won the canonical-tuple race. Reuse its flow instead of
     * creating a parallel generation.
     */
    if (ret == -EEXIST || (dead_flow && ret == -EAGAIN)) {
        skb = pht_flow_take_queued_skb(new_flow, NULL);
        pht_flow_put(new_flow);
        if (dead_flow) {
            pht_flow_put(dead_flow);
            dead_flow = NULL;
        }
        goto retry_lookup;
    }
    if (ret) {
        if (ret == -ENOSPC)
            pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
        else
            phantun_account_udp_translation_failure();
        pht_pr_warn("failed to insert initiator flow: %d\n", ret);
        pht_flow_put(new_flow);
        if (dead_flow)
            pht_flow_put(dead_flow);
        return NF_STOLEN;
    }
    pht_stats_inc(PHT_STAT_UDP_PACKETS_QUEUED);

    {
        int ifindex;

        ret = pht_emit_fake_tcp(state->net, &ep, init_seq, 0, PHT_TCP_FLAG_SYN, NULL, 0, &tx_meta,
                                &ifindex);
        if (!ret)
            pht_flow_set_egress_ifindex(new_flow, ifindex);
    }
    if (ret) {
        pht_pr_warn("failed to emit fake-TCP SYN: %d\n", ret);
        if (!phantun_io_error_is_transient(ret)) {
            phantun_account_udp_translation_failure();
            pht_flow_detach(new_flow);
            pht_flow_put(new_flow);
            if (dead_flow)
                pht_flow_put(dead_flow);
            return NF_STOLEN;
        }
    }

    pht_flow_put(new_flow);
    if (dead_flow)
        pht_flow_put(dead_flow);

    return NF_STOLEN;
}

static unsigned int phantun_pre_routing(void *priv, struct sk_buff *skb,
                                        const struct nf_hook_state *state);

/* GRO can merge multiple fake-TCP packets into one skb before PRE_ROUTING.
 * Our translator relies on per-packet boundaries, so segment managed TCP GSO
 * skbs back into individual packets before running the state machine.
 */
static unsigned int phantun_pre_routing_segment_gso(void *priv, struct sk_buff *skb,
                                                    const struct nf_hook_state *state) {
    netdev_features_t features = NETIF_F_SG | NETIF_F_IP_CSUM;
    struct sk_buff *segs;
    struct sk_buff *seg;
    struct sk_buff *next;
    long err;

    if (!skb_is_gso(skb) || !skb_is_gso_tcp(skb))
        return NF_ACCEPT;
    if (skb->protocol == htons(ETH_P_IPV6))
        features = NETIF_F_SG | NETIF_F_IPV6_CSUM;

    segs = __skb_gso_segment(skb, features, false);
    if (IS_ERR_OR_NULL(segs)) {
        err = IS_ERR(segs) ? PTR_ERR(segs) : -EINVAL;
        pht_pr_warn("failed to segment inbound TCP GRO skb: %ld\n", err);
        return NF_DROP;
    }

    consume_skb(skb);

    skb_list_walk_safe(segs, seg, next) {
        unsigned int verdict;

        skb_mark_not_on_list(seg);
        /* The recursive handler must not consume seg; the segmentation loop
         * owns every segment and frees it exactly once for NF_ACCEPT or NF_DROP.
         */
        verdict = phantun_pre_routing(priv, seg, state);
        if (verdict == NF_ACCEPT)
            pht_pr_warn_rl("segmented inbound TCP packet unexpectedly escaped fake-TCP handler\n");
        kfree_skb(seg);
    }

    return NF_STOLEN;
}

/* Selector-matched raw inbound UDP is dropped before local delivery so a
 * tuple is owned either by fake-TCP translation or by nothing. UDP carrying
 * this netns' private reinjection mark is exempt because it already came out
 * of the translator.
 */
static unsigned int phantun_pre_routing_udp_drop(void *priv, struct sk_buff *skb,
                                                 const struct nf_hook_state *state) {
    struct pht_l4_view view;
    struct pht_addr local_addr;
    struct pht_addr remote_addr;
    struct pht_flow_table *flows;
    int ret;

    if (!state || !skb)
        return NF_ACCEPT;

    flows = phantun_net_hook_flows(state->net);
    if (!flows)
        return NF_ACCEPT;

    if (skb->mark == flows->reinject_mark) {
        skb->mark = 0;
        return NF_ACCEPT;
    }

    if (phantun_pre_routing_uses_loopback_dev(skb, state))
        return NF_ACCEPT;

    ret = phantun_parse_udp_skb(skb, &view);
    if (ret)
        return NF_ACCEPT;
    if (!phantun_family_enabled(view.family))
        return NF_ACCEPT;

    phantun_view_local_addr(&view, true, &local_addr);
    if (!phantun_pre_routing_targets_local_host(state->net, &local_addr))
        return NF_ACCEPT;

    phantun_view_remote_addr(&view, true, &remote_addr);
    if (!phantun_selectors_allow(view.udp->dest, &remote_addr, view.udp->source))
        return NF_ACCEPT;

    if (phantun_addr_pair_uses_unsupported_addr(&local_addr, &remote_addr)) {
        pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
        pht_pr_warn_rl("dropping inbound UDP with unsupported endpoint address\n");
        kfree_skb(skb);
        return NF_STOLEN;
    }

    pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
    pht_stats_inc(PHT_STAT_UDP_RAW_INBOUND_DROPPED);
    kfree_skb(skb);
    return NF_STOLEN;
}

/* PRE_ROUTING owns selector-matched fake-TCP before the real TCP stack sees
 * it. Unknown owned packets are rejected unless they are valid bare SYNs that
 * create a new responder flow.
 */
static unsigned int phantun_pre_routing(void *priv, struct sk_buff *skb,
                                        const struct nf_hook_state *state) {
    struct pht_l4_view view;
    struct pht_endpoint_pair ep;
    struct pht_addr local_addr;
    struct pht_addr remote_addr;
    struct pht_tx_meta tx_meta;
    struct pht_flow_table *flows;
    struct pht_flow *flow;
    struct pht_flow *new_flow;
    struct pht_flow *dead_flow = NULL;
    struct sk_buff *queued_skb;
    struct pht_tx_meta queued_tx_meta;
    struct pht_tx_meta local_tx_meta;
    enum pht_flow_state state_now;
    struct net_device *in_dev;
    u32 expected_ack;
    u32 responder_seq;
    u32 local_isn;
    u32 peer_syn_next;
    enum pht_flow_role role_now;
    u32 quarantine_prev_local_seq_start = 0;
    u32 quarantine_prev_local_seq_end = 0;
    u32 quarantine_prev_remote_seq_start = 0;
    u32 quarantine_prev_remote_seq_end = 0;
    bool carry_quarantine = false;
    bool count_replacement_accept = false;
    bool had_queued;
    bool drop_open_payload;
    int ret;

    if (!state || !skb)
        return NF_ACCEPT;

    if (phantun_pre_routing_uses_loopback_dev(skb, state))
        return NF_ACCEPT;

    flows = phantun_net_hook_flows(state->net);
    /* Fail open if hook state exists before the flow table is attached;
     * NF_DROP here would blackhole every inbound non-loopback packet.
     */
    if (!flows)
        return NF_ACCEPT;

    ret = phantun_parse_tcp_skb(skb, &view);
    if (ret)
        return NF_ACCEPT;
    if (!phantun_family_enabled(view.family))
        return NF_ACCEPT;

    phantun_view_local_addr(&view, true, &local_addr);
    if (!phantun_pre_routing_targets_local_host(state->net, &local_addr))
        return NF_ACCEPT;

    phantun_view_remote_addr(&view, true, &remote_addr);
    if (!phantun_selectors_allow(view.tcp->dest, &remote_addr, view.tcp->source))
        return NF_ACCEPT;

    phantun_fill_tcp_endpoint_pair(&view, &ep);
    in_dev = state->in ? state->in : skb->dev;
    phantun_fill_endpoint_scope_ifindex(&ep, in_dev);
    phantun_tx_meta_from_view(skb, &view, false, &tx_meta);
    if (phantun_endpoint_uses_unsupported_addr(&ep)) {
        pht_pr_warn_rl("rejecting inbound fake-TCP with unsupported endpoint address\n");
        return NF_DROP;
    }

    ret = phantun_pre_routing_segment_gso(priv, skb, state);
    if (ret != NF_ACCEPT)
        return ret;

    ret = phantun_validate_tcp_checksums(skb, &view);
    if (ret)
        return NF_DROP;

    flow = pht_flow_lookup(flows, &ep);
    if (flow) {
        spin_lock_bh(&flow->lock);
        state_now = flow->state;
        spin_unlock_bh(&flow->lock);

        if (state_now == PHT_FLOW_STATE_DEAD) {
            /* Allocation-failure tombstone: keep it hashed as the previous
             * sequence source unless this packet publishes a replacement SYN.
             */
            dead_flow = flow;
            flow = NULL;
        }
    }

    if (!flow) {
        if (view.tcp->rst) {
            if (dead_flow)
                pht_flow_put(dead_flow);
            return NF_DROP;
        }

        if (!phantun_tcp_is_bare_syn(&view)) {
            phantun_account_tcp_unknown_tuple_rejected();
            ret = phantun_send_rstack(state->net, &ep, &view, &tx_meta, view.tcp->syn);
            if (ret)
                pht_pr_warn_rl("failed to emit RST|ACK for unknown packet: %d\n", ret);
            if (dead_flow)
                pht_flow_put(dead_flow);
            return NF_DROP;
        }

        if (!phantun_tcp_syn_is_aligned(&view)) {
            phantun_account_tcp_misaligned_syn_rejected();
            ret = phantun_send_rstack(state->net, &ep, &view, &tx_meta, true);
            if (ret)
                pht_pr_warn_rl("failed to emit RST|ACK for misaligned SYN: %d\n", ret);
            if (dead_flow)
                pht_flow_put(dead_flow);
            return NF_DROP;
        }
        /* Only a bare aligned SYN is allowed to create responder state for an
         * otherwise unknown owned tuple.
         */
    process_as_new_syn:
        new_flow = pht_flow_create(flows, &ep, PHT_FLOW_ROLE_RESPONDER, PHT_FLOW_STATE_SYN_RCVD);
        if (IS_ERR(new_flow)) {
            pht_pr_warn("failed to create responder flow: %ld\n", PTR_ERR(new_flow));
            if (dead_flow)
                pht_flow_put(dead_flow);
            return NF_DROP;
        }

        responder_seq = get_random_u32();
        spin_lock_bh(&new_flow->lock);
        new_flow->seq = responder_seq;
        new_flow->ack = ntohl(view.tcp->seq) + 1;
        new_flow->last_ack = new_flow->ack;
        new_flow->local_isn = responder_seq;
        new_flow->peer_syn_next = new_flow->ack;
        new_flow->local_seq_window_start = new_flow->local_isn;
        new_flow->remote_seq_window_start = new_flow->peer_syn_next;
        spin_unlock_bh(&new_flow->lock);
        if (carry_quarantine) {
            phantun_flow_arm_prev_generation_quarantine(
                new_flow, quarantine_prev_local_seq_start, quarantine_prev_local_seq_end,
                quarantine_prev_remote_seq_start, quarantine_prev_remote_seq_end);
            carry_quarantine = false;
        }

        if (dead_flow)
            ret = pht_flow_replace_dead(flows, dead_flow, new_flow);
        else
            ret = pht_flow_insert(flows, new_flow);
        if (ret) {
            pht_flow_put(new_flow);
            if (dead_flow)
                pht_flow_put(dead_flow);
            return NF_DROP;
        }

        ret = phantun_send_synack(new_flow, state->net, &tx_meta);
        if (ret) {
            pht_pr_warn("failed to emit SYN|ACK: %d\n", ret);
            if (!phantun_io_error_is_transient(ret))
                pht_flow_detach(new_flow);
        } else if (count_replacement_accept) {
            pht_stats_inc(PHT_STAT_REPLACEMENTS_ACCEPTED);
        }
        pht_flow_put(new_flow);
        if (dead_flow)
            pht_flow_put(dead_flow);
        return NF_DROP;
    }

    spin_lock_bh(&flow->lock);
    state_now = flow->state;
    expected_ack = flow->local_isn + 1;
    local_isn = flow->local_isn;
    peer_syn_next = flow->peer_syn_next;
    role_now = flow->role;
    had_queued = flow->queued_skb != NULL;
    spin_unlock_bh(&flow->lock);

    if (view.tcp->rst) {
        if (phantun_flow_should_drop_quarantined_packet(flow, &view)) {
            pht_flow_put(flow);
            return NF_DROP;
        }
        pht_flow_remove(flow);
        pht_flow_put(flow);
        return NF_DROP;
    }

    /* Initiator half-open state: accept only collision SYNs, the matching
     * SYN|ACK, or RST. Simultaneous initiation collapses by comparing ISNs.
     */
    if (state_now == PHT_FLOW_STATE_SYN_SENT) {
        if (phantun_tcp_is_bare_syn(&view)) {
            u32 peer_isn;

            if (!phantun_tcp_syn_is_aligned(&view)) {
                phantun_account_tcp_misaligned_syn_rejected();
                ret = phantun_send_rstack(state->net, &ep, &view, &tx_meta, true);
                if (ret)
                    pht_pr_warn_rl("failed to emit RST|ACK for misaligned colliding SYN: %d\n",
                                   ret);
                pht_flow_put(flow);
                return NF_DROP;
            }

            peer_isn = ntohl(view.tcp->seq);

            if (local_isn == peer_isn) {
                /* Exact match is extremely rare. Drop to
                 * resolve via timeout */
                pht_flow_put(flow);
                return NF_DROP;
            }

            if (local_isn < peer_isn) {
                pht_pr_info("collision on tuple; keeping initiator role\n");
                pht_flow_touch_inbound(flow);
                pht_stats_inc(PHT_STAT_COLLISIONS_WON);
                pht_flow_put(flow);
                return NF_DROP;
            }

            pht_pr_info("collision on tuple; switching to responder role\n");
            pht_stats_inc(PHT_STAT_COLLISIONS_LOST);
            pht_flow_detach(flow);
            queued_skb = pht_flow_take_queued_skb(flow, &queued_tx_meta);
            spin_lock_bh(&flow->lock);
            local_tx_meta = flow->local_tx_meta;
            spin_unlock_bh(&flow->lock);
            pht_flow_put(flow);

            new_flow =
                pht_flow_create(flows, &ep, PHT_FLOW_ROLE_RESPONDER, PHT_FLOW_STATE_SYN_RCVD);
            if (IS_ERR(new_flow)) {
                kfree_skb(queued_skb);
                return NF_DROP;
            }

            responder_seq = get_random_u32();
            spin_lock_bh(&new_flow->lock);
            new_flow->seq = responder_seq;
            new_flow->ack = ntohl(view.tcp->seq) + 1;
            new_flow->last_ack = new_flow->ack;
            new_flow->local_isn = responder_seq;
            new_flow->peer_syn_next = new_flow->ack;
            new_flow->local_seq_window_start = new_flow->local_isn;
            new_flow->remote_seq_window_start = new_flow->peer_syn_next;
            /* queued_tx_meta stays tied to the transferred skb. local_tx_meta
             * may be newer when later UDP arrived while the one-skb queue was
             * full, so preserve it separately for retransmits and keepalives.
             */
            new_flow->local_tx_meta = local_tx_meta;
            spin_unlock_bh(&new_flow->lock);
            if (queued_skb)
                pht_flow_set_queued_skb(new_flow, queued_skb, &queued_tx_meta);

            ret = pht_flow_insert(flows, new_flow);
            if (ret) {
                pht_flow_put(new_flow);
                return NF_DROP;
            }

            ret = phantun_send_synack(new_flow, state->net, &tx_meta);
            if (ret) {
                pht_pr_warn("failed to emit SYN|ACK after collision handoff: %d\n", ret);
                if (!phantun_io_error_is_transient(ret))
                    pht_flow_detach(new_flow);
            }
            pht_flow_put(new_flow);
            return NF_DROP;
        }

        if (phantun_tcp_is_clean_synack(&view, expected_ack)) {
            const u32 ack = ntohl(view.tcp->seq) + 1;
            struct pht_flow_handshake_complete_args complete_args = {
                .expected_state = PHT_FLOW_STATE_SYN_SENT,
                .local_seq_start = local_isn + 1,
                .ack = ack,
                .peer_syn_next = ack,
                .remote_payload_seq = ntohl(view.tcp->seq),
                .remote_payload_len = view.payload_len,
                .local_control_len =
                    phantun_request_enabled() ? phantun_cfg.handshake_request_len : 0,
                .arm_drop_next_rx_payload = phantun_response_enabled(),
                .response_pending_ack = false,
            };
            enum pht_flow_complete_result complete;

            complete = pht_flow_complete_handshake(flow, &complete_args, NULL);
            if (complete == PHT_FLOW_COMPLETE_STALE) {
                pht_flow_put(flow);
                return NF_DROP;
            }
            if (complete == PHT_FLOW_COMPLETE_ALREADY_ESTABLISHED) {
                ret = phantun_send_idle_ack(flow, state->net, &tx_meta);
                if (ret)
                    pht_pr_warn("failed to ACK duplicate SYN|ACK: %d\n", ret);
                pht_flow_put(flow);
                return NF_DROP;
            }

            pht_flow_touch_inbound(flow);
            if (phantun_request_enabled()) {
                ret = phantun_send_handshake_request(flow, state->net);
                if (ret) {
                    pht_pr_warn("failed to emit handshake request: %d\n", ret);
                    if (!phantun_io_error_is_transient(ret)) {
                        pht_flow_remove(flow);
                        pht_flow_put(flow);
                        return NF_DROP;
                    }
                }
            }

            {
                bool flushed_payload = false;

                ret = phantun_flush_queued_udp(flow, state->net, &flushed_payload);
                if (!ret && !phantun_request_enabled() && (!had_queued || !flushed_payload)) {
                    ret = phantun_send_idle_ack(flow, state->net, &tx_meta);
                    if (phantun_io_error_is_transient(ret))
                        ret = 0;
                }
            }
            if (ret) {
                phantun_discard_queued_udp_translation_failure(flow);
                pht_pr_warn("failed to finalize initiator open: %d\n", ret);
                pht_flow_remove(flow);
            }
            pht_flow_put(flow);
            return NF_DROP;
        }

        phantun_account_tcp_protocol_rejected();
        ret = phantun_send_rstack(state->net, &ep, &view, &tx_meta, false);
        if (ret)
            pht_pr_warn_rl("failed to emit RST|ACK for unexpected SYN_SENT packet: %d\n", ret);
        pht_flow_remove(flow);
        pht_flow_put(flow);
        return NF_DROP;
    }

    if (state_now == PHT_FLOW_STATE_SYN_RCVD && phantun_tcp_is_bare_syn(&view) &&
        phantun_tcp_syn_is_aligned(&view) && ntohl(view.tcp->seq) + 1 == peer_syn_next) {
        ret = phantun_send_synack(flow, state->net, &tx_meta);
        if (ret)
            pht_pr_warn("failed to re-emit SYN|ACK: %d\n", ret);
        pht_flow_put(flow);
        return NF_DROP;
    }

    /* Responder half-open state: duplicate SYN retransmits SYN|ACK, and only
     * the exact final ACK can complete the handshake.
     */
    if (state_now == PHT_FLOW_STATE_SYN_RCVD) {
        if (!phantun_tcp_is_syn_rcvd_final_ack(&view, expected_ack)) {
            if (phantun_flow_should_drop_quarantined_packet(flow, &view)) {
                pht_flow_put(flow);
                return NF_DROP;
            }
            if (phantun_tcp_is_bare_syn(&view) && !phantun_tcp_syn_is_aligned(&view)) {
                phantun_account_tcp_misaligned_syn_rejected();
                ret = phantun_send_rstack(state->net, &ep, &view, &tx_meta, true);
                if (ret)
                    pht_pr_warn_rl("failed to emit RST|ACK for misaligned SYN_RCVD SYN: %d\n", ret);
                pht_flow_remove(flow);
                pht_flow_put(flow);
                return NF_DROP;
            }

            phantun_account_tcp_protocol_rejected();
            ret = phantun_send_rstack(state->net, &ep, &view, &tx_meta, false);
            if (ret)
                pht_pr_warn_rl("failed to emit RST|ACK for bad final ACK: %d\n", ret);
            pht_flow_remove(flow);
            pht_flow_put(flow);
            return NF_DROP;
        }

        {
            struct pht_flow_handshake_complete_args complete_args = {
                .expected_state = PHT_FLOW_STATE_SYN_RCVD,
                .local_seq_start = local_isn + 1,
                .ack = peer_syn_next,
                .peer_syn_next = peer_syn_next,
                .remote_payload_seq = ntohl(view.tcp->seq),
                .remote_payload_len = view.payload_len,
                .local_control_len =
                    phantun_response_enabled() ? phantun_cfg.handshake_response_len : 0,
                .arm_drop_next_rx_payload = phantun_request_enabled(),
                .response_pending_ack = phantun_response_enabled(),
            };
            enum pht_flow_complete_result complete;

            complete = pht_flow_complete_handshake(flow, &complete_args, &drop_open_payload);
            if (complete == PHT_FLOW_COMPLETE_STALE) {
                pht_flow_put(flow);
                return NF_DROP;
            }
            if (complete == PHT_FLOW_COMPLETE_ALREADY_ESTABLISHED) {
                u32 payload_seq = ntohl(view.tcp->seq);
                u32 payload_end = payload_seq + view.payload_len;
                bool response_unblocked = false;
                bool duplicate_opening_payload = false;
                bool drop_payload = false;
                bool payload_already_acked = false;

                spin_lock_bh(&flow->lock);
                if (flow->response_pending_ack) {
                    if (view.tcp->ack &&
                        phantun_seq_after_eq(ntohl(view.tcp->ack_seq),
                                             flow->local_isn + 1 +
                                                 phantun_cfg.handshake_response_len)) {
                        flow->response_pending_ack = false;
                        response_unblocked = true;
                    } else if (view.payload_len > 0) {
                        flow->response_pending_ack = false;
                        response_unblocked = true;
                    }
                }
                if (view.payload_len > 0 && flow->opening_rx_payload_claimed &&
                    payload_seq == flow->opening_rx_seq_start &&
                    payload_end == flow->opening_rx_seq_end)
                    duplicate_opening_payload = true;
                if (view.payload_len > 0 && phantun_seq_after_eq(flow->ack, payload_end))
                    payload_already_acked = true;
                if (phantun_consume_drop_next_rx_payload_locked(flow, &view)) {
                    drop_payload = true;
                    pht_stats_inc(PHT_STAT_SHAPING_PAYLOADS_DROPPED);
                }
                spin_unlock_bh(&flow->lock);

                if (payload_already_acked || duplicate_opening_payload) {
                    if (response_unblocked) {
                        ret = phantun_flush_queued_udp(flow, state->net, NULL);
                        if (ret) {
                            phantun_discard_queued_udp_translation_failure(flow);
                            pht_pr_warn("failed to flush responder queue: %d\n", ret);
                            pht_flow_remove(flow);
                        }
                    }
                    pht_flow_put(flow);
                    return NF_DROP;
                }

                if (view.payload_len == 0) {
                    pht_flow_touch_inbound(flow);
                    if (response_unblocked) {
                        ret = phantun_flush_queued_udp(flow, state->net, NULL);
                        if (ret) {
                            phantun_discard_queued_udp_translation_failure(flow);
                            pht_pr_warn("failed to flush responder queue: %d\n", ret);
                            pht_flow_remove(flow);
                        }
                    }
                    pht_flow_put(flow);
                    return NF_DROP;
                }

                ret = phantun_finalize_established_rx(flow, &ep, skb, &view, state->net, in_dev,
                                                      !drop_payload, true, &tx_meta);
                if (ret) {
                    pht_pr_warn("failed to process raced responder payload: %d\n", ret);
                    if (ret == -EMSGSIZE) {
                        phantun_account_tcp_protocol_rejected();
                        phantun_send_rstack(state->net, &ep, &view, &tx_meta, false);
                    }
                    pht_flow_remove(flow);
                }
                pht_flow_put(flow);
                return NF_DROP;
            }

            /* Injected handshake_response occupies responder_seq + 1.
             * Keep responder-owned UDP blocked until the peer ACKs that
             * range or later initiator payload proves the control slot was
             * skipped.
             */
            if (phantun_response_enabled()) {
                if (drop_open_payload) {
                    phantun_note_inbound_payload(flow, &view);
                    pht_stats_inc(PHT_STAT_SHAPING_PAYLOADS_DROPPED);
                }

                ret = phantun_send_handshake_response(flow, state->net, &tx_meta);
                if (ret) {
                    pht_pr_warn("failed to emit handshake response: %d\n", ret);
                    if (!phantun_io_error_is_transient(ret)) {
                        pht_flow_remove(flow);
                        pht_flow_put(flow);
                        return NF_DROP;
                    }
                }

                if (view.payload_len == 0)
                    pht_flow_touch_inbound(flow);
                if (view.payload_len == 0 || drop_open_payload) {
                    pht_flow_put(flow);
                    return NF_DROP;
                }

                ret = phantun_finalize_established_rx(flow, &ep, skb, &view, state->net, in_dev,
                                                      true, true, &tx_meta);
                if (ret) {
                    pht_pr_warn("failed to process responder open payload: %d\n", ret);
                    if (ret == -EMSGSIZE) {
                        phantun_account_tcp_protocol_rejected();
                        phantun_send_rstack(state->net, &ep, &view, &tx_meta, false);
                    }
                    pht_flow_remove(flow);
                }
                pht_flow_put(flow);
                return NF_DROP;
            }

            pht_flow_touch_inbound(flow);

            /* The responder transitions to ESTABLISHED. We must flush any
             * queued UDP data. */
            ret = phantun_flush_queued_udp(flow, state->net, NULL);
            if (ret) {
                phantun_discard_queued_udp_translation_failure(flow);
                pht_pr_warn("failed to flush responder queue: %d\n", ret);
                pht_flow_remove(flow);
                pht_flow_put(flow);
                return NF_DROP;
            }

            if (view.payload_len == 0) {
                pht_flow_put(flow);
                return NF_DROP;
            }

            if (drop_open_payload)
                pht_stats_inc(PHT_STAT_SHAPING_PAYLOADS_DROPPED);
            ret = phantun_finalize_established_rx(flow, &ep, skb, &view, state->net, in_dev,
                                                  !drop_open_payload, true, &tx_meta);
            if (ret) {
                pht_pr_warn("failed to process responder open payload: %d\n", ret);
                if (ret == -EMSGSIZE) {
                    phantun_account_tcp_protocol_rejected();
                    phantun_send_rstack(state->net, &ep, &view, &tx_meta, false);
                }
                pht_flow_remove(flow);
            }
            pht_flow_put(flow);
            return NF_DROP;
        }
    }

    /* ESTABLISHED handling still prioritizes flags over payload. Duplicate
     * open packets are absorbed, bare SYN can replace the generation, any
     * other SYN is fatal, and plain ACK/data continues the stream.
     */
    if (state_now == PHT_FLOW_STATE_ESTABLISHED) {
        bool response_unblocked = false;
        bool drop_payload = false;

        if (phantun_flow_should_drop_quarantined_packet(flow, &view)) {
            pht_flow_put(flow);
            return NF_DROP;
        }

        if (view.tcp->syn) {
            if (role_now == PHT_FLOW_ROLE_INITIATOR &&
                phantun_tcp_is_clean_synack(&view, expected_ack) &&
                ntohl(view.tcp->seq) + 1 == peer_syn_next) {
                ret = phantun_send_idle_ack(flow, state->net, &tx_meta);
                if (ret)
                    pht_pr_warn("failed to ACK duplicate current-generation SYN|ACK: %d\n", ret);
                pht_flow_put(flow);
                return NF_DROP;
            }
            if (phantun_tcp_is_bare_syn(&view) && phantun_tcp_syn_is_aligned(&view)) {
                if (role_now == PHT_FLOW_ROLE_RESPONDER &&
                    ntohl(view.tcp->seq) + 1 == peer_syn_next) {
                    ret = phantun_send_synack(flow, state->net, &tx_meta);
                    if (ret)
                        pht_pr_warn("failed to re-emit SYN|ACK for duplicate established SYN: %d\n",
                                    ret);
                    pht_flow_put(flow);
                    return NF_DROP;
                }
                if (phantun_flow_should_drop_protected_replacement_syn(flow, &view)) {
                    pht_flow_put(flow);
                    return NF_DROP;
                }
                /* Accept bare replacement SYN as a new generation. Preserve
                 * only the just-replaced seq/ack window so delayed old packets
                 * are dropped quietly during the quarantine window.
                 */
                spin_lock_bh(&flow->lock);
                quarantine_prev_local_seq_start = flow->local_seq_window_start;
                quarantine_prev_local_seq_end = flow->seq;
                quarantine_prev_remote_seq_start = flow->remote_seq_window_start;
                quarantine_prev_remote_seq_end = flow->ack;
                spin_unlock_bh(&flow->lock);
                carry_quarantine = true;
                count_replacement_accept = true;
                pht_pr_info("received bare SYN on ESTABLISHED tuple, replacing generation\n");
                queued_skb = pht_flow_take_queued_skb(flow, NULL);
                if (queued_skb)
                    kfree_skb(queued_skb);
                pht_flow_detach(flow);
                pht_flow_put(flow);
                goto process_as_new_syn;
            }
            pht_pr_warn_rl("received invalid SYN on ESTABLISHED tuple, destroying\n");
            if (phantun_tcp_is_bare_syn(&view))
                phantun_account_tcp_misaligned_syn_rejected();
            else
                phantun_account_tcp_protocol_rejected();
            phantun_send_rstack(state->net, &ep, &view, &tx_meta, true);
            pht_flow_remove(flow);
            pht_flow_put(flow);
            return NF_DROP;
        }

        if (!phantun_tcp_is_established_ack(&view)) {
            phantun_account_tcp_protocol_rejected();
            ret = phantun_send_rstack(state->net, &ep, &view, &tx_meta, !view.tcp->ack);
            if (ret)
                pht_pr_warn_rl("failed to emit RST|ACK for unsupported established flags: %d\n",
                               ret);
            pht_flow_remove(flow);
            pht_flow_put(flow);
            return NF_DROP;
        }

        spin_lock_bh(&flow->lock);
        if (flow->response_pending_ack) {
            if (view.tcp->ack &&
                phantun_seq_after_eq(ntohl(view.tcp->ack_seq),
                                     flow->local_isn + 1 + phantun_cfg.handshake_response_len)) {
                flow->response_pending_ack = false;
                response_unblocked = true;
            } else if (view.payload_len > 0) {
                /* A lost handshake_response leaves the reserved control
                 * sequence range unseen. Once later initiator traffic
                 * arrives, release queued responder data anyway and keep
                 * the ignore slot pinned to responder_seq + 1 so a delayed
                 * handshake_response is still suppressed by sequence.
                 */
                flow->response_pending_ack = false;
                response_unblocked = true;
            }
        }
        if (phantun_consume_drop_next_rx_payload_locked(flow, &view)) {
            drop_payload = true;
            pht_stats_inc(PHT_STAT_SHAPING_PAYLOADS_DROPPED);
        }
        spin_unlock_bh(&flow->lock);

        if (view.payload_len == 0) {
            pht_flow_touch_inbound(flow);
            if (response_unblocked) {
                ret = phantun_flush_queued_udp(flow, state->net, NULL);
                if (ret) {
                    phantun_discard_queued_udp_translation_failure(flow);
                    pht_pr_warn("failed to flush responder queue: %d\n", ret);
                    pht_flow_remove(flow);
                }
            }
            pht_flow_put(flow);
            return NF_DROP;
        }

        ret = phantun_finalize_established_rx(flow, &ep, skb, &view, state->net, in_dev,
                                              !drop_payload, true, &tx_meta);
        if (ret) {
            pht_pr_warn("failed to process established inbound payload: %d\n", ret);
            if (ret == -EMSGSIZE) {
                phantun_account_tcp_protocol_rejected();
                phantun_send_rstack(state->net, &ep, &view, &tx_meta, false);
            }
            pht_flow_remove(flow);
        }
        pht_flow_put(flow);
        return NF_DROP;
    }

    pht_flow_put(flow);
    return NF_DROP;
}

static void phantun_net_disable_defrag(struct net *net, struct phantun_net *pnet) {
#if IS_ENABLED(CONFIG_IPV6)
    if (pnet->defrag_v6_enabled) {
        NF_DEFRAG_IPV6_DISABLE_COMPAT(net);
        pnet->defrag_v6_enabled = false;
    }
#endif
    if (pnet->defrag_v4_enabled) {
        NF_DEFRAG_IPV4_DISABLE_COMPAT(net);
        pnet->defrag_v4_enabled = false;
    }
}

static int phantun_net_enable_defrag(struct net *net, struct phantun_net *pnet) {
    int ret;

    if (phantun_cfg.enabled_families & PHT_FAMILY_IPV4) {
        ret = nf_defrag_ipv4_enable(net);
        if (ret) {
            pht_pr_err("failed to enable IPv4 defrag: %d\n", ret);
            return ret;
        }
        pnet->defrag_v4_enabled = true;
    }

#if IS_ENABLED(CONFIG_IPV6)
    if (phantun_cfg.enabled_families & PHT_FAMILY_IPV6) {
        ret = nf_defrag_ipv6_enable(net);
        if (ret) {
            pht_pr_err("failed to enable IPv6 defrag: %d\n", ret);
            phantun_net_disable_defrag(net, pnet);
            return ret;
        }
        pnet->defrag_v6_enabled = true;
    }
#endif

    return 0;
}

/* Linux inserts equal-priority hooks before existing entries. Register the
 * fake-TCP hook first so phantun_pre_routing_udp_drop executes before it.
 */
static struct nf_hook_ops phantun_nf_ops_v4[] = {
    {
        .hook = phantun_local_out,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_LOCAL_OUT,
        /* Let LOCAL_OUT conntrack observe the original UDP before we steal
         * it, so translated inbound replies can match ESTABLISHED policy.
         */
        .priority = PHANTUN_LOCAL_OUT_PRIORITY,
    },
    {
        .hook = phantun_pre_routing,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = PHANTUN_PRE_ROUTING_PRIORITY,
    },
    {
        .hook = phantun_pre_routing_udp_drop,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = PHANTUN_PRE_ROUTING_PRIORITY,
    },
};

#if IS_ENABLED(CONFIG_IPV6)
static struct nf_hook_ops phantun_nf_ops_v6[] = {
    {
        .hook = phantun_local_out,
        .pf = NFPROTO_IPV6,
        .hooknum = NF_INET_LOCAL_OUT,
        .priority = PHANTUN_LOCAL_OUT_PRIORITY,
    },
    {
        .hook = phantun_pre_routing,
        .pf = NFPROTO_IPV6,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = PHANTUN_PRE_ROUTING_PRIORITY,
    },
    {
        .hook = phantun_pre_routing_udp_drop,
        .pf = NFPROTO_IPV6,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = PHANTUN_PRE_ROUTING_PRIORITY,
    },
};
#endif

static int __net_init phantun_net_init(struct net *net) {
    struct phantun_net *pnet = net_generic(net, phantun_net_id);
    struct pht_flow_table *flows;
    int ret;
    if (!pnet)
        return -EINVAL;

    memset(pnet, 0, sizeof(*pnet));
    if (!phantun_netns_selected(net))
        return 0;

    flows = &pnet->flows;
    ret = pht_flow_table_init(flows, net, &phantun_cfg);
    if (ret) {
        pht_pr_err("failed to initialize flow table: %d\n", ret);
        return ret;
    }
    pnet->flow_table_ready = true;

    pnet->netdev_nb.notifier_call = phantun_netdev_event;
    ret = register_netdevice_notifier_net(net, &pnet->netdev_nb);
    if (ret) {
        pht_pr_err("failed to register netdevice notifier: %d\n", ret);
        goto err_attach;
    }
    pnet->netdev_notifier_registered = true;

    phantun_reserve_configured_local_tcp_ports(pnet, net);

    ret = phantun_net_enable_defrag(net, pnet);
    if (ret)
        goto err_attach;

    if (phantun_cfg.enabled_families & PHT_FAMILY_IPV4) {
        ret = nf_register_net_hooks(net, phantun_nf_ops_v4, ARRAY_SIZE(phantun_nf_ops_v4));
        if (ret) {
            pht_pr_err("failed to register IPv4 netfilter hooks: %d\n", ret);
            goto err_attach;
        }
        pnet->hooks_v4_registered = true;
        pht_pr_info(
            "registered IPv4 LOCAL_OUT/PRE_ROUTING hooks and topology notifiers: netns %u\n",
            phantun_netns_id(net));
    }

#if IS_ENABLED(CONFIG_IPV6)
    if (phantun_cfg.enabled_families & PHT_FAMILY_IPV6) {
        ret = nf_register_net_hooks(net, phantun_nf_ops_v6, ARRAY_SIZE(phantun_nf_ops_v6));
        if (ret) {
            pht_pr_err("failed to register IPv6 netfilter hooks: %d\n", ret);
            goto err_attach;
        }
        pnet->hooks_v6_registered = true;
        pht_pr_info(
            "registered IPv6 LOCAL_OUT/PRE_ROUTING hooks and topology notifiers: netns %u\n",
            phantun_netns_id(net));
    }
#endif
    pnet->active = true;
    return 0;

err_attach:
    pnet->active = false;
#if IS_ENABLED(CONFIG_IPV6)
    if (pnet->hooks_v6_registered) {
        nf_unregister_net_hooks(net, phantun_nf_ops_v6, ARRAY_SIZE(phantun_nf_ops_v6));
        pnet->hooks_v6_registered = false;
    }
#endif
    if (pnet->hooks_v4_registered) {
        nf_unregister_net_hooks(net, phantun_nf_ops_v4, ARRAY_SIZE(phantun_nf_ops_v4));
        pnet->hooks_v4_registered = false;
    }
    phantun_release_reserved_local_tcp_ports(pnet);
    if (pnet->netdev_notifier_registered) {
        unregister_netdevice_notifier_net(net, &pnet->netdev_nb);
        pnet->netdev_notifier_registered = false;
    }
    phantun_net_disable_defrag(net, pnet);
    if (pnet->flow_table_ready) {
        pht_flow_table_destroy(flows);
        pnet->flow_table_ready = false;
    }
    return ret;
}

static void __net_exit phantun_net_exit(struct net *net) {
    struct phantun_net *pnet = net_generic(net, phantun_net_id);
    struct pht_flow_table *flows;

    if (!pnet || !pnet->flow_table_ready)
        return;

    pnet->active = false;
#if IS_ENABLED(CONFIG_IPV6)
    if (pnet->hooks_v6_registered) {
        nf_unregister_net_hooks(net, phantun_nf_ops_v6, ARRAY_SIZE(phantun_nf_ops_v6));
        pnet->hooks_v6_registered = false;
    }
#endif
    if (pnet->hooks_v4_registered) {
        nf_unregister_net_hooks(net, phantun_nf_ops_v4, ARRAY_SIZE(phantun_nf_ops_v4));
        pnet->hooks_v4_registered = false;
    }
    phantun_net_disable_defrag(net, pnet);
    if (pnet->netdev_notifier_registered) {
        unregister_netdevice_notifier_net(net, &pnet->netdev_nb);
        pnet->netdev_notifier_registered = false;
    }
    phantun_release_reserved_local_tcp_ports(pnet);
    flows = &pnet->flows;
    pht_flow_table_destroy(flows);
    pnet->flow_table_ready = false;
    pht_pr_info("unregistered netfilter hooks and topology notifiers: netns %u\n",
                phantun_netns_id(net));
}

static struct pernet_operations phantun_pernet_ops = {
    .id = &phantun_net_id,
    .size = sizeof(struct phantun_net),
    .init = phantun_net_init,
    .exit = phantun_net_exit,
};

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
    if (interval && keepalive_misses > LONG_MAX / interval) {
        pht_pr_err("keepalive_interval_sec * keepalive_misses exceeds signed jiffies range\n");
        return -EINVAL;
    }
    return 0;
}

static int phantun_validate_config(void) {
    u16 requested_ports[PHANTUN_MAX_MANAGED_PORTS];
    unsigned int requested_count;
    bool all_requested;
    unsigned int i;
    int ret;
    unsigned int enabled_families;
    enum pht_managed_netns managed_netns_mode;

    ret = phantun_parse_managed_netns(&managed_netns_mode);
    if (ret)
        return ret;

    ret = phantun_parse_ip_families(&enabled_families);
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
    }

    ret = phantun_parse_reserved_local_ports_param(reserved_local_ports, requested_ports,
                                                   &requested_count, &all_requested);
    if (ret)
        return ret;

    for (i = 0; i < managed_remote_peers_count; i++) {
        struct pht_managed_peer parsed_peer;

        ret = phantun_parse_managed_remote_peer(managed_remote_peers[i], &parsed_peer);
        if (ret) {
            pht_pr_err("managed_remote_peers[%u] must be valid x.y.z.w:p or [IPv6]:p\n", i);
            return ret;
        }
        if (parsed_peer.addr.family == AF_INET && !(enabled_families & PHT_FAMILY_IPV4)) {
            pht_pr_err("managed_remote_peers[%u] is IPv4 but ip_families disables IPv4\n", i);
            return -EINVAL;
        }
        if (parsed_peer.addr.family == AF_INET6 && !(enabled_families & PHT_FAMILY_IPV6)) {
            pht_pr_err("managed_remote_peers[%u] is IPv6 but ip_families disables IPv6\n", i);
            return -EINVAL;
        }
    }

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

static int phantun_snapshot_config(void) {
    unsigned int i;
    int ret;

    memset(&phantun_cfg, 0, sizeof(phantun_cfg));
    ret = phantun_parse_managed_netns(&phantun_cfg.managed_netns);
    if (ret)
        return ret;

    ret = phantun_parse_ip_families(&phantun_cfg.enabled_families);
    if (ret)
        return ret;
    phantun_cfg.managed_local_ports_count = managed_local_ports_count;
    for (i = 0; i < managed_local_ports_count; i++)
        phantun_cfg.managed_local_ports[i] = (u16)managed_local_ports[i];
    phantun_cfg.managed_remote_peers_count = managed_remote_peers_count;
    for (i = 0; i < managed_remote_peers_count; i++) {
        if (phantun_parse_managed_remote_peer(managed_remote_peers[i],
                                              &phantun_cfg.managed_remote_peers[i])) {
            /* Config was validated earlier; keep impossible parse
             * failures from leaking uninitialized data into the hot
             * path.
             */
            memset(&phantun_cfg.managed_remote_peers[i], 0,
                   sizeof(phantun_cfg.managed_remote_peers[i]));
        }
    }

    ret = phantun_snapshot_reserved_local_ports(&phantun_cfg);
    if (ret)
        return ret;

    ret = phantun_parse_payload_param(handshake_request, &phantun_alloc_req,
                                      &phantun_cfg.handshake_request_len);
    if (ret)
        return ret;
    phantun_cfg.handshake_request = phantun_alloc_req;

    ret = phantun_parse_payload_param(handshake_response, &phantun_alloc_resp,
                                      &phantun_cfg.handshake_response_len);
    if (ret) {
        kfree(phantun_alloc_req);
        phantun_alloc_req = NULL;
        return ret;
    }
    phantun_cfg.handshake_response = phantun_alloc_resp;
    ret = phantun_validate_handshake_payload_lengths(&phantun_cfg);
    if (ret) {
        kfree(phantun_alloc_resp);
        phantun_alloc_resp = NULL;
        kfree(phantun_alloc_req);
        phantun_alloc_req = NULL;
        return ret;
    }

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

static int __init phantun_init(void) {
    int ret;

    pht_pr_info(PHANTUN_MODULE_NAME " %s loaded\n", PACKAGE_VERSION);

    ret = phantun_validate_config();
    if (ret)
        return ret;

    ret = phantun_snapshot_config();
    if (ret)
        goto err_alloc;

    phantun_log_config();
    pht_stats_reset();
    ret = pht_stats_init_sysfs();
    if (ret)
        goto err_alloc;

    ret = register_pernet_subsys(&phantun_pernet_ops);
    if (ret)
        goto err_sysfs;

    if (phantun_cfg.enabled_families & PHT_FAMILY_IPV4) {
        phantun_inetaddr_nb.notifier_call = phantun_inetaddr_event;
        ret = register_inetaddr_notifier(&phantun_inetaddr_nb);
        if (ret)
            goto err_pernet;
    }
#if IS_ENABLED(CONFIG_IPV6)
    if (phantun_cfg.enabled_families & PHT_FAMILY_IPV6) {
        phantun_inet6addr_nb.notifier_call = phantun_inet6addr_event;
        ret = register_inet6addr_notifier(&phantun_inet6addr_nb);
        if (ret)
            goto err_inetaddr;
    }
#endif

    return 0;

#if IS_ENABLED(CONFIG_IPV6)
err_inetaddr:
    if (phantun_cfg.enabled_families & PHT_FAMILY_IPV4)
        unregister_inetaddr_notifier(&phantun_inetaddr_nb);
#endif
err_pernet:
    unregister_pernet_subsys(&phantun_pernet_ops);
err_sysfs:
    pht_stats_exit_sysfs();
err_alloc:
    kfree(phantun_alloc_req);
    kfree(phantun_alloc_resp);
    return ret;
}

static void __exit phantun_exit(void) {
#if IS_ENABLED(CONFIG_IPV6)
    if (phantun_cfg.enabled_families & PHT_FAMILY_IPV6)
        unregister_inet6addr_notifier(&phantun_inet6addr_nb);
#endif
    if (phantun_cfg.enabled_families & PHT_FAMILY_IPV4)
        unregister_inetaddr_notifier(&phantun_inetaddr_nb);
    unregister_pernet_subsys(&phantun_pernet_ops);
    pht_stats_exit_sysfs();
    kfree(phantun_alloc_req);
    kfree(phantun_alloc_resp);
    pht_pr_info(PHANTUN_MODULE_NAME " unloaded\n");
}

module_init(phantun_init);
module_exit(phantun_exit);

// SPDX-License-Identifier: GPL-2.0-or-later
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bin Jin");
MODULE_DESCRIPTION(
    "Kernel module re-implementation of phantun, transform UDP streams into fake-TCP streams");
MODULE_VERSION(PACKAGE_VERSION);
