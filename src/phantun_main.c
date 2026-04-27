// SPDX-License-Identifier: GPL-2.0-or-later
//
// Copyright (C) 2026 Bin Jin. All Rights Reserved.
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/net.h>
#include <linux/net_namespace.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netns/generic.h>
#include <net/route.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <net/addrconf.h>
#include <net/ipv6.h>
#include <net/sock.h>
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
                 "comma-separated ports reserve up to 16 managed_local_ports entries, and 'all' "
                 "reserves every managed_local_ports entry");
module_param(ip_families, charp, 0444);
MODULE_PARM_DESC(ip_families, "IP families to translate: both, ipv4, or ipv6");
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
    return pnet ? &pnet->flows : NULL;
}

/* Invalidate only on topology changes that break the current source identity or
 * cached egress path outright. Route/gateway changes are intentionally ignored:
 * every transmit does a fresh route lookup, so a stable local IPv4 can migrate
 * without tearing the fake-TCP generation down.
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
    if (queued)
        pht_stats_inc(PHT_STAT_UDP_PACKETS_QUEUED);
    else
        pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
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

    if (ntohs(skb->protocol) == ETH_P_IP)
        return pht_parse_ipv4_udp(skb, view);
    if (ntohs(skb->protocol) == ETH_P_IPV6)
        return pht_parse_ipv6_udp(skb, view);

    ret = pht_parse_ipv4_udp(skb, view);
    if (!ret)
        return 0;
    return pht_parse_ipv6_udp(skb, view);
}

static int phantun_parse_tcp_skb(struct sk_buff *skb, struct pht_l4_view *view) {
    int ret;

    if (ntohs(skb->protocol) == ETH_P_IP)
        return pht_parse_ipv4_tcp(skb, view);
    if (ntohs(skb->protocol) == ETH_P_IPV6)
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

static bool phantun_seq_after_eq(u32 seq1, u32 seq2) { return (s32)(seq1 - seq2) >= 0; }

static bool phantun_seq_before_eq(u32 seq1, u32 seq2) { return (s32)(seq1 - seq2) <= 0; }

static bool phantun_seq_between(u32 seq, u32 start, u32 end) {
    return phantun_seq_after_eq(seq, start) && phantun_seq_before_eq(seq, end);
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
    u32 current_local_end;

    seq = ntohl(view->tcp->seq);
    ack = ntohl(view->tcp->ack_seq);
    current_local_end = flow->seq;
    if (flow->state == PHT_FLOW_STATE_SYN_RCVD)
        current_local_end = flow->local_isn + 1;

    if (!phantun_seq_between(seq, flow->peer_syn_next, flow->ack))
        return false;
    if (view->tcp->rst && !view->tcp->ack)
        return true;
    if (!view->tcp->ack)
        return false;

    return phantun_seq_between(ack, flow->local_isn, current_local_end);
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

static bool phantun_tcp_syn_is_aligned(const struct pht_l4_view *view) {
    return view && ntohl(view->tcp->seq) % 4095U == 0;
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
    u32 seq;
    u32 ack;
    int ifindex;
    int ret;

    spin_lock_bh(&flow->lock);
    ep = flow->endpoints;
    seq = flow->seq;
    ack = flow->ack;
    spin_unlock_bh(&flow->lock);

    ret = pht_emit_fake_tcp(net, &ep, seq, ack, PHT_TCP_FLAG_RST, NULL, 0, &ifindex);
    if (!ret) {
        pht_flow_set_egress_ifindex(flow, ifindex);
        pht_stats_inc(PHT_STAT_RST_SENT);
    }
    return ret;
}

static int phantun_send_established_udp(struct pht_flow *flow, const struct pht_endpoint_pair *ep,
                                        const struct pht_l4_view *view, const struct sk_buff *skb,
                                        struct net *net) {
    u32 seq;
    u32 ack;
    void *payload = NULL;
    int ifindex;
    int ret;

    if (view->payload_len) {
        payload = kmalloc(view->payload_len, GFP_ATOMIC);
        if (!payload)
            return -ENOMEM;

        ret = pht_copy_l4_payload(skb, view, payload, view->payload_len);
        if (ret) {
            kfree(payload);
            return ret;
        }
    }

    /* Reserve sequence space before emitting so concurrent local senders stay
     * ordered. If emit fails, roll back only when nothing advanced flow->seq
     * in the meantime.
     */
    spin_lock_bh(&flow->tx_lock);
    spin_lock_bh(&flow->lock);
    if (flow->state != PHT_FLOW_STATE_ESTABLISHED) {
        spin_unlock_bh(&flow->lock);
        spin_unlock_bh(&flow->tx_lock);
        kfree(payload);
        return -EAGAIN;
    }
    seq = flow->seq;
    ack = flow->ack;
    flow->seq += view->payload_len;
    spin_unlock_bh(&flow->lock);

    ret = pht_emit_fake_tcp(net, ep, seq, ack, PHT_TCP_FLAG_ACK, payload, view->payload_len,
                            &ifindex);
    if (!ret) {
        spin_lock_bh(&flow->lock);
        if (flow->state == PHT_FLOW_STATE_ESTABLISHED) {
            flow->last_activity_jiffies = jiffies;
            flow->egress_ifindex = ifindex;
        }
        spin_unlock_bh(&flow->lock);
    } else {
        spin_lock_bh(&flow->lock);
        if (flow->state == PHT_FLOW_STATE_ESTABLISHED) {
            if (flow->seq == seq + view->payload_len)
                flow->seq = seq;
            flow->state = PHT_FLOW_STATE_DEAD;
        }
        spin_unlock_bh(&flow->lock);
    }
    spin_unlock_bh(&flow->tx_lock);

    kfree(payload);
    return ret;
}

static int phantun_send_synack(struct pht_flow *flow, struct net *net) {
    struct pht_endpoint_pair ep;
    u32 seq;
    u32 ack;
    int ifindex;
    int ret;

    spin_lock_bh(&flow->lock);
    ep = flow->endpoints;
    seq = flow->local_isn;
    ack = flow->peer_syn_next;
    spin_unlock_bh(&flow->lock);

    ret = pht_emit_fake_tcp(net, &ep, seq, ack, PHT_TCP_FLAG_SYN | PHT_TCP_FLAG_ACK, NULL, 0,
                            &ifindex);
    if (!ret)
        pht_flow_set_egress_ifindex(flow, ifindex);
    return ret;
}

static int phantun_send_rstack(struct net *net, const struct pht_endpoint_pair *ep,
                               const struct pht_l4_view *view, bool force_zero_seq) {
    u32 seq = force_zero_seq ? 0 : ntohl(view->tcp->ack_seq);
    u32 ack = ntohl(view->tcp->seq) + phantun_tcp_seq_advance(view->tcp, view->payload_len);
    int ret;

    ret = pht_emit_fake_tcp(net, ep, seq, ack, PHT_TCP_FLAG_RST | PHT_TCP_FLAG_ACK, NULL, 0, NULL);
    if (!ret)
        pht_stats_inc(PHT_STAT_RST_SENT);
    return ret;
}

static int phantun_send_handshake_request(struct pht_flow *flow, struct net *net) {
    struct pht_endpoint_pair ep;
    u32 seq;
    u32 ack;
    size_t req_len = phantun_cfg.handshake_request_len;
    int ifindex;
    int ret;

    spin_lock_bh(&flow->lock);
    ep = flow->endpoints;
    seq = flow->local_isn + 1;
    ack = flow->ack;
    spin_unlock_bh(&flow->lock);

    ret = pht_emit_fake_tcp(net, &ep, seq, ack, PHT_TCP_FLAG_ACK, phantun_cfg.handshake_request,
                            req_len, &ifindex);
    if (!ret) {
        spin_lock_bh(&flow->lock);
        flow->seq = seq + req_len;
        flow->last_ack = ack;
        flow->last_activity_jiffies = jiffies;
        flow->egress_ifindex = ifindex;
        spin_unlock_bh(&flow->lock);
        pht_stats_inc(PHT_STAT_REQUEST_PAYLOADS_INJECTED);
    }
    return ret;
}

static int phantun_send_handshake_response(struct pht_flow *flow, struct net *net) {
    struct pht_endpoint_pair ep;
    u32 seq;
    u32 ack;
    size_t resp_len = phantun_cfg.handshake_response_len;
    int ifindex;
    int ret;

    spin_lock_bh(&flow->lock);
    ep = flow->endpoints;
    seq = flow->local_isn + 1;
    ack = flow->ack;
    spin_unlock_bh(&flow->lock);

    ret = pht_emit_fake_tcp(net, &ep, seq, ack, PHT_TCP_FLAG_ACK, phantun_cfg.handshake_response,
                            resp_len, &ifindex);
    if (!ret) {
        spin_lock_bh(&flow->lock);
        flow->seq = seq + resp_len;
        flow->last_ack = ack;
        flow->last_activity_jiffies = jiffies;
        flow->egress_ifindex = ifindex;
        spin_unlock_bh(&flow->lock);
        pht_stats_inc(PHT_STAT_RESPONSE_PAYLOADS_INJECTED);
    }
    return ret;
}

static int phantun_send_idle_ack(struct pht_flow *flow, struct net *net) {
    struct pht_endpoint_pair ep;
    u32 seq;
    u32 ack;
    int ifindex;
    int ret;

    spin_lock_bh(&flow->lock);
    ep = flow->endpoints;
    seq = flow->seq;
    ack = flow->ack;
    spin_unlock_bh(&flow->lock);

    ret = pht_emit_fake_tcp(net, &ep, seq, ack, PHT_TCP_FLAG_ACK, NULL, 0, &ifindex);
    if (!ret) {
        spin_lock_bh(&flow->lock);
        flow->last_ack = ack;
        flow->last_activity_jiffies = jiffies;
        flow->egress_ifindex = ifindex;
        spin_unlock_bh(&flow->lock);
    }
    return ret;
}

static int phantun_flush_queued_udp(struct pht_flow *flow, struct net *net) {
    struct sk_buff *queued_skb;
    struct pht_l4_view qview;
    struct pht_endpoint_pair qep;
    int ret;

    queued_skb = pht_flow_take_queued_skb(flow);
    if (!queued_skb)
        return 0;

    ret = phantun_parse_udp_skb(queued_skb, &qview);
    if (ret) {
        kfree_skb(queued_skb);
        return ret;
    }

    phantun_fill_udp_endpoint_pair(&qview, &qep);
    qep.scope_ifindex = flow->endpoints.scope_ifindex;
    ret = phantun_send_established_udp(flow, &qep, &qview, queued_skb, net);
    if (ret)
        pht_flow_set_queued_skb(flow, queued_skb);
    else
        kfree_skb(queued_skb);
    return ret;
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
                                            const struct pht_l4_view *view,
                                            struct net_device *dev) {
    void *payload;
    int ret;

    if (!view->payload_len)
        return 0;

    payload = kmalloc(view->payload_len, GFP_ATOMIC);
    if (!payload)
        return -ENOMEM;

    ret = pht_copy_l4_payload(skb, view, payload, view->payload_len);
    if (!ret)
        ret = pht_reinject_udp_payload(dev, ep, payload, view->payload_len);
    kfree(payload);
    return ret;
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

static int phantun_finalize_established_rx(struct pht_flow *flow,
                                           const struct pht_endpoint_pair *ep,
                                           const struct sk_buff *skb,
                                           const struct pht_l4_view *view, struct net *net,
                                           struct net_device *dev, bool reinject_payload,
                                           bool send_idle_ack) {
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
        ret = phantun_reinject_inbound_payload(ep, skb, view, dev);
        if (ret)
            return ret;
    }

    if (allow_flush) {
        ret = phantun_flush_queued_udp(flow, net);
        if (ret)
            return ret;
    }

    if (send_idle_ack && view->payload_len)
        ret = phantun_send_idle_ack(flow, net);
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

/* LOCAL_OUT owns selector-matched outbound UDP. ESTABLISHED flows send
 * immediately, half-open flows keep only one queued skb, and DEAD flows are
 * reopened from scratch with a guarded ISN.
 */
static unsigned int phantun_local_out(void *priv, struct sk_buff *skb,
                                      const struct nf_hook_state *state) {
    struct pht_l4_view view;
    struct pht_endpoint_pair ep;
    struct pht_addr remote_addr;
    struct pht_flow_table *flows;
    struct pht_flow *flow;
    struct pht_flow *new_flow;
    enum pht_flow_state state_now;
    u32 init_seq;
    u32 prev_seq = 0;
    bool has_prev_seq = false;
    int ret;
    bool queued;

    if (!state || !skb)
        return NF_ACCEPT;

    flows = phantun_net_flows(state->net);
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
    if (phantun_endpoint_uses_unsupported_addr(&ep)) {
        pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
        pht_pr_warn_rl("rejecting outbound UDP with unsupported endpoint address\n");
        return NF_DROP;
    }

    ret = phantun_confirm_outbound_udp_conntrack(skb);
    if (ret) {
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
                queued = pht_flow_queue_skb_if_empty(flow, skb);
                if (!queued)
                    kfree_skb(skb);
                phantun_account_udp_queue_result(queued);
                pht_flow_put(flow);
                return NF_STOLEN;
            }

            ret = phantun_send_established_udp(flow, &ep, &view, skb, state->net);
            if (ret) {
                pht_pr_warn("failed to emit fake-TCP payload for established flow: %d\n", ret);
                phantun_send_flow_rst(flow, state->net);
                pht_flow_remove(flow);
            }
            pht_flow_put(flow);
            kfree_skb(skb);
            return NF_STOLEN;
        }

        if (pht_flow_state_is_half_open(state_now)) {
            queued = pht_flow_queue_skb_if_empty(flow, skb);
            if (!queued)
                kfree_skb(skb);
            phantun_account_udp_queue_result(queued);
            pht_flow_put(flow);
            return NF_STOLEN;
        }

        /* DEAD still occupies the canonical slot until we unhash it. Drop
         * that generation and retry so a fresh initiator flow can inherit
         * the reopen guard from the old sequence space.
         */
        if (state_now == PHT_FLOW_STATE_DEAD) {
            prev_seq = flow->seq;
            has_prev_seq = true;
            pht_flow_detach(flow);
            pht_flow_put(flow);
            goto retry_lookup;
        }

        pht_flow_put(flow);
        kfree_skb(skb);
        return NF_STOLEN;
    }

    new_flow = pht_flow_create(flows, &ep, PHT_FLOW_ROLE_INITIATOR, PHT_FLOW_STATE_SYN_SENT);
    if (IS_ERR(new_flow)) {
        pht_pr_warn("failed to create initiator flow: %ld\n", PTR_ERR(new_flow));
        kfree_skb(skb);
        return NF_STOLEN;
    }

    if (!phantun_pick_reopen_isn(prev_seq, has_prev_seq, &init_seq)) {
        pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
        pht_pr_warn("failed to choose reopen ISN for new flow\n");
        pht_flow_put(new_flow);
        kfree_skb(skb);
        return NF_STOLEN;
    }

    spin_lock_bh(&new_flow->lock);
    new_flow->seq = init_seq;
    new_flow->ack = 0;
    new_flow->last_ack = 0;
    new_flow->local_isn = init_seq;
    new_flow->peer_syn_next = 0;
    spin_unlock_bh(&new_flow->lock);
    pht_flow_set_queued_skb(new_flow, skb);

    ret = pht_flow_insert(flows, new_flow);
    /* Another CPU won the canonical-tuple race. Reuse its flow instead of
     * creating a parallel generation.
     */
    if (ret == -EEXIST) {
        skb = pht_flow_take_queued_skb(new_flow);
        pht_flow_put(new_flow);
        goto retry_lookup;
    }
    if (ret) {
        pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
        pht_pr_warn("failed to insert initiator flow: %d\n", ret);
        pht_flow_put(new_flow);
        return NF_STOLEN;
    }
    pht_stats_inc(PHT_STAT_UDP_PACKETS_QUEUED);

    {
        int ifindex;

        ret = pht_emit_fake_tcp(state->net, &ep, init_seq, 0, PHT_TCP_FLAG_SYN, NULL, 0, &ifindex);
        if (!ret)
            pht_flow_set_egress_ifindex(new_flow, ifindex);
    }
    if (ret) {
        pht_stats_inc(PHT_STAT_UDP_PACKETS_DROPPED);
        pht_pr_warn("failed to emit fake-TCP SYN: %d\n", ret);
        pht_flow_remove(new_flow);
        return NF_STOLEN;
    }

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
    if (ntohs(skb->protocol) == ETH_P_IPV6)
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
        verdict = phantun_pre_routing(priv, seg, state);
        if (verdict == NF_ACCEPT)
            pht_pr_warn_rl("segmented inbound TCP packet unexpectedly escaped fake-TCP handler\n");
        kfree_skb(seg);
    }

    return NF_STOLEN;
}

/* Selector-matched raw inbound UDP is dropped before local delivery so a
 * tuple is owned either by fake-TCP translation or by nothing. Reinject-marked
 * UDP is exempt because it already came out of the translator.
 */
static unsigned int phantun_pre_routing_udp_drop(void *priv, struct sk_buff *skb,
                                                 const struct nf_hook_state *state) {
    struct pht_l4_view view;
    struct pht_addr local_addr;
    struct pht_addr remote_addr;
    int ret;

    if (!state || !skb)
        return NF_ACCEPT;

    if (skb->mark == PHANTUN_REINJECT_MARK) {
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
    struct pht_flow_table *flows;
    struct pht_flow *flow;
    struct pht_flow *new_flow;
    struct sk_buff *queued_skb;
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
    bool had_queued;
    int ret;

    if (!state || !skb)
        return NF_ACCEPT;

    if (phantun_pre_routing_uses_loopback_dev(skb, state))
        return NF_ACCEPT;

    flows = phantun_net_flows(state->net);
    if (!flows)
        return NF_DROP;

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
            pht_flow_detach(flow);
            pht_flow_put(flow);
            flow = NULL;
        }
    }

    if (!flow) {
        if (view.tcp->rst)
            return NF_DROP;

        if (!phantun_tcp_is_bare_syn(&view)) {
            ret = phantun_send_rstack(state->net, &ep, &view, view.tcp->syn);
            if (ret)
                pht_pr_warn_rl("failed to emit RST|ACK for unknown packet: %d\n", ret);
            return NF_DROP;
        }

        if (!phantun_tcp_syn_is_aligned(&view)) {
            ret = phantun_send_rstack(state->net, &ep, &view, true);
            if (ret)
                pht_pr_warn_rl("failed to emit RST|ACK for misaligned SYN: %d\n", ret);
            return NF_DROP;
        }
        /* Only a bare aligned SYN is allowed to create responder state for an
         * otherwise unknown owned tuple.
         */
    process_as_new_syn:
        new_flow = pht_flow_create(flows, &ep, PHT_FLOW_ROLE_RESPONDER, PHT_FLOW_STATE_SYN_RCVD);
        if (IS_ERR(new_flow)) {
            pht_pr_warn("failed to create responder flow: %ld\n", PTR_ERR(new_flow));
            return NF_DROP;
        }

        responder_seq = get_random_u32();
        spin_lock_bh(&new_flow->lock);
        new_flow->seq = responder_seq;
        new_flow->ack = ntohl(view.tcp->seq) + 1;
        new_flow->last_ack = new_flow->ack;
        new_flow->local_isn = responder_seq;
        new_flow->peer_syn_next = new_flow->ack;
        spin_unlock_bh(&new_flow->lock);
        if (carry_quarantine) {
            phantun_flow_arm_prev_generation_quarantine(
                new_flow, quarantine_prev_local_seq_start, quarantine_prev_local_seq_end,
                quarantine_prev_remote_seq_start, quarantine_prev_remote_seq_end);
            carry_quarantine = false;
        }

        ret = pht_flow_insert(flows, new_flow);
        if (ret) {
            pht_flow_put(new_flow);
            return NF_DROP;
        }

        ret = phantun_send_synack(new_flow, state->net);
        if (ret) {
            pht_pr_warn("failed to emit SYN|ACK: %d\n", ret);
            pht_flow_remove(new_flow);
        }
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
                ret = phantun_send_rstack(state->net, &ep, &view, true);
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
            queued_skb = pht_flow_take_queued_skb(flow);
            pht_flow_detach(flow);
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
            spin_unlock_bh(&new_flow->lock);
            if (queued_skb)
                pht_flow_set_queued_skb(new_flow, queued_skb);

            ret = pht_flow_insert(flows, new_flow);
            if (ret) {
                pht_flow_put(new_flow);
                return NF_DROP;
            }

            ret = phantun_send_synack(new_flow, state->net);
            if (ret) {
                pht_pr_warn("failed to emit SYN|ACK after collision handoff: %d\n", ret);
                pht_flow_remove(new_flow);
            }
            return NF_DROP;
        }

        if (view.tcp->syn && view.tcp->ack && view.payload_len == 0 &&
            ntohl(view.tcp->ack_seq) == expected_ack) {
            /* Handshake establishment is complete even if the responder later
             * sends an injected handshake_response. Reserve responder_seq + 1
             * so that optional control payload is ignored by sequence instead
             * of being treated as required handshake data.
             */
            spin_lock_bh(&flow->lock);
            flow->seq = flow->local_isn + 1;
            flow->ack = ntohl(view.tcp->seq) + 1;
            flow->peer_syn_next = flow->ack;
            flow->last_ack = flow->ack;
            flow->drop_next_rx_seq = flow->ack;
            flow->drop_next_rx_payload = phantun_response_enabled();
            flow->response_pending_ack = false;
            spin_unlock_bh(&flow->lock);

            if (phantun_request_enabled()) {
                ret = phantun_send_handshake_request(flow, state->net);
                if (ret) {
                    pht_pr_warn("failed to emit handshake request: %d\n", ret);
                    pht_flow_remove(flow);
                    pht_flow_put(flow);
                    return NF_DROP;
                }
            }

            pht_flow_touch_inbound(flow);
            pht_flow_update_state(flow, PHT_FLOW_STATE_ESTABLISHED);
            ret = phantun_flush_queued_udp(flow, state->net);
            if (!ret && !had_queued && !phantun_request_enabled())
                ret = phantun_send_idle_ack(flow, state->net);
            if (ret) {
                pht_pr_warn("failed to finalize initiator open: %d\n", ret);
                pht_flow_remove(flow);
            }
            pht_flow_put(flow);
            return NF_DROP;
        }

        ret = phantun_send_rstack(state->net, &ep, &view, false);
        if (ret)
            pht_pr_warn_rl("failed to emit RST|ACK for unexpected SYN_SENT packet: %d\n", ret);
        pht_flow_remove(flow);
        pht_flow_put(flow);
        return NF_DROP;
    }

    if (state_now == PHT_FLOW_STATE_SYN_RCVD && phantun_tcp_is_bare_syn(&view) &&
        phantun_tcp_syn_is_aligned(&view) && ntohl(view.tcp->seq) + 1 == peer_syn_next) {
        ret = phantun_send_synack(flow, state->net);
        if (ret)
            pht_pr_warn("failed to re-emit SYN|ACK: %d\n", ret);
        pht_flow_put(flow);
        return NF_DROP;
    }

    /* Responder half-open state: duplicate SYN retransmits SYN|ACK, and only
     * the exact final ACK can complete the handshake.
     */
    if (state_now == PHT_FLOW_STATE_SYN_RCVD) {
        if (!view.tcp->ack || ntohl(view.tcp->ack_seq) != expected_ack) {
            if (phantun_flow_should_drop_quarantined_packet(flow, &view)) {
                pht_flow_put(flow);
                return NF_DROP;
            }
            ret = phantun_send_rstack(state->net, &ep, &view, false);
            if (ret)
                pht_pr_warn_rl("failed to emit RST|ACK for bad final ACK: %d\n", ret);
            pht_flow_remove(flow);
            pht_flow_put(flow);
            return NF_DROP;
        }

        /* request shaping reserves initiator_seq + 1. If the final ACK already
         * carries payload at that exact sequence, drop it now; otherwise arm
         * the ignore slot for the later packet with that starting sequence.
         */
        spin_lock_bh(&flow->lock);
        flow->seq = flow->local_isn + 1;
        flow->ack = flow->peer_syn_next;
        flow->last_ack = flow->ack;
        flow->drop_next_rx_seq = flow->ack;
        flow->drop_next_rx_payload = phantun_request_enabled();
        flow->response_pending_ack = false;
        spin_unlock_bh(&flow->lock);

        {
            bool drop_open_payload = view.payload_len && phantun_request_enabled() &&
                                     ntohl(view.tcp->seq) == peer_syn_next;

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

                ret = phantun_send_handshake_response(flow, state->net);
                if (ret) {
                    pht_pr_warn("failed to emit handshake response: %d\n", ret);
                    pht_flow_remove(flow);
                    pht_flow_put(flow);
                    return NF_DROP;
                }

                spin_lock_bh(&flow->lock);
                flow->response_pending_ack = true;
                spin_unlock_bh(&flow->lock);

                if (view.payload_len == 0)
                    pht_flow_touch_inbound(flow);
                pht_flow_update_state(flow, PHT_FLOW_STATE_ESTABLISHED);
                if (view.payload_len == 0 || drop_open_payload) {
                    pht_flow_put(flow);
                    return NF_DROP;
                }

                ret = phantun_finalize_established_rx(flow, &ep, skb, &view, state->net, in_dev,
                                                      true, true);
                if (ret) {
                    pht_pr_warn("failed to process responder open payload: %d\n", ret);
                    if (ret == -EMSGSIZE)
                        phantun_send_rstack(state->net, &ep, &view, false);
                    pht_flow_remove(flow);
                }
                pht_flow_put(flow);
                return NF_DROP;
            }

            pht_flow_touch_inbound(flow);
            pht_flow_update_state(flow, PHT_FLOW_STATE_ESTABLISHED);

            /* The responder transitions to ESTABLISHED. We must flush any
             * queued UDP data. */
            ret = phantun_flush_queued_udp(flow, state->net);
            if (ret) {
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
                                                  !drop_open_payload, true);
            if (ret) {
                pht_pr_warn("failed to process responder open payload: %d\n", ret);
                if (ret == -EMSGSIZE)
                    phantun_send_rstack(state->net, &ep, &view, false);
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
            if (flow->role == PHT_FLOW_ROLE_INITIATOR && view.tcp->ack && view.payload_len == 0 &&
                ntohl(view.tcp->ack_seq) == flow->local_isn + 1 &&
                ntohl(view.tcp->seq) + 1 == flow->peer_syn_next) {
                ret = phantun_send_idle_ack(flow, state->net);
                if (ret)
                    pht_pr_warn("failed to ACK duplicate current-generation SYN|ACK: %d\n", ret);
                pht_flow_put(flow);
                return NF_DROP;
            }
            if (phantun_tcp_is_bare_syn(&view) && phantun_tcp_syn_is_aligned(&view)) {
                if (role_now == PHT_FLOW_ROLE_RESPONDER &&
                    ntohl(view.tcp->seq) + 1 == peer_syn_next) {
                    ret = phantun_send_synack(flow, state->net);
                    if (ret)
                        pht_pr_warn("failed to re-emit SYN|ACK for duplicate established SYN: %d\n",
                                    ret);
                    pht_flow_put(flow);
                    return NF_DROP;
                }
                /* Accept bare replacement SYN as a new generation. Preserve
                 * only the just-replaced seq/ack window so delayed old packets
                 * are dropped quietly during the quarantine window.
                 */
                spin_lock_bh(&flow->lock);
                quarantine_prev_local_seq_start = flow->local_isn;
                quarantine_prev_local_seq_end = flow->seq;
                quarantine_prev_remote_seq_start = flow->peer_syn_next;
                quarantine_prev_remote_seq_end = flow->ack;
                spin_unlock_bh(&flow->lock);
                carry_quarantine = true;
                pht_pr_info("received bare SYN on ESTABLISHED tuple, replacing generation\n");
                queued_skb = pht_flow_take_queued_skb(flow);
                if (queued_skb)
                    kfree_skb(queued_skb);
                pht_flow_detach(flow);
                pht_flow_put(flow);
                goto process_as_new_syn;
            }
            pht_pr_warn_rl("received invalid SYN on ESTABLISHED tuple, destroying\n");
            phantun_send_rstack(state->net, &ep, &view, true);
            pht_flow_remove(flow);
            pht_flow_put(flow);
            return NF_DROP;
        }

        spin_lock_bh(&flow->lock);
        if (flow->response_pending_ack) {
            if (view.tcp->ack && ntohl(view.tcp->ack_seq) >=
                                     flow->local_isn + 1 + phantun_cfg.handshake_response_len) {
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
        if (view.payload_len && flow->drop_next_rx_payload &&
            ntohl(view.tcp->seq) == flow->drop_next_rx_seq) {
            drop_payload = true;
            pht_stats_inc(PHT_STAT_SHAPING_PAYLOADS_DROPPED);
        }
        spin_unlock_bh(&flow->lock);

        if (view.payload_len == 0) {
            pht_flow_touch_inbound(flow);
            if (response_unblocked) {
                ret = phantun_flush_queued_udp(flow, state->net);
                if (ret) {
                    pht_pr_warn("failed to flush responder queue: %d\n", ret);
                    pht_flow_remove(flow);
                }
            }
            pht_flow_put(flow);
            return NF_DROP;
        }

        ret = phantun_finalize_established_rx(flow, &ep, skb, &view, state->net, in_dev,
                                              !drop_payload, true);
        if (ret) {
            pht_pr_warn("failed to process established inbound payload: %d\n", ret);
            if (ret == -EMSGSIZE)
                phantun_send_rstack(state->net, &ep, &view, false);
            pht_flow_remove(flow);
        }
        pht_flow_put(flow);
        return NF_DROP;
    }

    pht_flow_put(flow);
    return NF_DROP;
}

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
        .hook = phantun_pre_routing_udp_drop,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = PHANTUN_PRE_ROUTING_PRIORITY,
    },
    {
        .hook = phantun_pre_routing,
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
        .hook = phantun_pre_routing_udp_drop,
        .pf = NFPROTO_IPV6,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = PHANTUN_PRE_ROUTING_PRIORITY,
    },
    {
        .hook = phantun_pre_routing,
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

    flows = &pnet->flows;
    ret = pht_flow_table_init(flows, net, &phantun_cfg);
    if (ret) {
        pht_pr_err("failed to initialize flow table: %d\n", ret);
        return ret;
    }

    pnet->netdev_nb.notifier_call = phantun_netdev_event;
    ret = register_netdevice_notifier_net(net, &pnet->netdev_nb);
    if (ret) {
        pht_pr_err("failed to register netdevice notifier: %d\n", ret);
        pht_flow_table_destroy(flows);
        return ret;
    }

    phantun_reserve_configured_local_tcp_ports(pnet, net);

    if (phantun_cfg.enabled_families & PHT_FAMILY_IPV4) {
        ret = nf_register_net_hooks(net, phantun_nf_ops_v4, ARRAY_SIZE(phantun_nf_ops_v4));
        if (ret) {
            pht_pr_err("failed to register IPv4 netfilter hooks: %d\n", ret);
            phantun_release_reserved_local_tcp_ports(pnet);
            unregister_netdevice_notifier_net(net, &pnet->netdev_nb);
            pht_flow_table_destroy(flows);
            return ret;
        }
        pht_pr_info(
            "registered IPv4 LOCAL_OUT/PRE_ROUTING hooks and topology notifiers: netns %u\n",
            phantun_netns_id(net));
    }

#if IS_ENABLED(CONFIG_IPV6)
    if (phantun_cfg.enabled_families & PHT_FAMILY_IPV6) {
        ret = nf_register_net_hooks(net, phantun_nf_ops_v6, ARRAY_SIZE(phantun_nf_ops_v6));
        if (ret) {
            pht_pr_err("failed to register IPv6 netfilter hooks: %d\n", ret);
            if (phantun_cfg.enabled_families & PHT_FAMILY_IPV4)
                nf_unregister_net_hooks(net, phantun_nf_ops_v4, ARRAY_SIZE(phantun_nf_ops_v4));
            phantun_release_reserved_local_tcp_ports(pnet);
            unregister_netdevice_notifier_net(net, &pnet->netdev_nb);
            pht_flow_table_destroy(flows);
            return ret;
        }
        pht_pr_info(
            "registered IPv6 LOCAL_OUT/PRE_ROUTING hooks and topology notifiers: netns %u\n",
            phantun_netns_id(net));
    }
#endif
    return 0;
}

static void __net_exit phantun_net_exit(struct net *net) {
    struct phantun_net *pnet = net_generic(net, phantun_net_id);
    struct pht_flow_table *flows;

    if (!pnet)
        return;

    flows = &pnet->flows;
    if (phantun_cfg.enabled_families & PHT_FAMILY_IPV4)
        nf_unregister_net_hooks(net, phantun_nf_ops_v4, ARRAY_SIZE(phantun_nf_ops_v4));
#if IS_ENABLED(CONFIG_IPV6)
    if (phantun_cfg.enabled_families & PHT_FAMILY_IPV6)
        nf_unregister_net_hooks(net, phantun_nf_ops_v6, ARRAY_SIZE(phantun_nf_ops_v6));
#endif
    unregister_netdevice_notifier_net(net, &pnet->netdev_nb);
    pht_flow_table_destroy(flows);
    phantun_release_reserved_local_tcp_ports(pnet);
    pht_pr_info("unregistered netfilter hooks and topology notifiers: netns %u\n",
                phantun_netns_id(net));
}

static struct pernet_operations phantun_pernet_ops = {
    .id = &phantun_net_id,
    .size = sizeof(struct phantun_net),
    .init = phantun_net_init,
    .exit = phantun_net_exit,
};

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

static int phantun_validate_config(void) {
    u16 requested_ports[PHANTUN_MAX_MANAGED_PORTS];
    unsigned int requested_count;
    bool all_requested;
    unsigned int i;
    int ret;
    unsigned int enabled_families;

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

    if (!keepalive_misses) {
        pht_pr_err("keepalive_misses must be greater than zero\n");
        return -EINVAL;
    }

    if (!hard_idle_timeout_sec) {
        pht_pr_err("hard_idle_timeout_sec must be greater than zero\n");
        return -EINVAL;
    }

    if (reopen_guard_bytes >= 0x80000000U) {
        pht_pr_err("reopen_guard_bytes must be smaller than 2147483648\n");
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
            pht_pr_warn("failed to base64 decode parameter, ignoring\n");
            *out_buf = NULL;
            *out_len = 0;
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
            pht_pr_warn("hex parameter must have an even length, ignoring\n");
            return 0;
        }

        *out_buf = kmalloc(len / 2, GFP_KERNEL);
        if (!*out_buf)
            return -ENOMEM;

        if (hex2bin(*out_buf, raw_str, len / 2)) {
            pht_pr_warn("invalid hex characters in parameter, ignoring\n");
            kfree(*out_buf);
            *out_buf = NULL;
            return 0;
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

static int phantun_snapshot_config(void) {
    unsigned int i;
    int ret;

    memset(&phantun_cfg, 0, sizeof(phantun_cfg));
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
    phantun_cfg.handshake_timeout_ms = handshake_timeout_ms;
    phantun_cfg.handshake_retries = handshake_retries;
    phantun_cfg.keepalive_interval_sec = keepalive_interval_sec;
    phantun_cfg.keepalive_misses = keepalive_misses;
    phantun_cfg.hard_idle_timeout_sec = hard_idle_timeout_sec;
    phantun_cfg.reopen_guard_bytes = reopen_guard_bytes;
    phantun_cfg.half_open_limit = half_open_limit;
    phantun_cfg.replacement_quarantine_ms = replacement_quarantine_ms;

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

    pht_pr_info("  ip_families = %s\n", ip_families ? ip_families : "both");
    pht_pr_info("  handshake_timeout_ms = %u\n", phantun_cfg.handshake_timeout_ms);
    pht_pr_info("  handshake_retries = %u\n", phantun_cfg.handshake_retries);
    pht_pr_info("  keepalive_interval_sec = %u\n", phantun_cfg.keepalive_interval_sec);
    pht_pr_info("  keepalive_misses = %u\n", phantun_cfg.keepalive_misses);
    pht_pr_info("  hard_idle_timeout_sec = %u\n", phantun_cfg.hard_idle_timeout_sec);
    pht_pr_info("  reopen_guard_bytes = %u\n", phantun_cfg.reopen_guard_bytes);
    pht_pr_info("  half_open_limit = %u\n", phantun_cfg.half_open_limit);
    pht_pr_info("  replacement_quarantine_ms = %u\n", phantun_cfg.replacement_quarantine_ms);
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

    phantun_inetaddr_nb.notifier_call = phantun_inetaddr_event;
    ret = register_inetaddr_notifier(&phantun_inetaddr_nb);
    if (ret)
        goto err_pernet;
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
