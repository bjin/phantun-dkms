// SPDX-License-Identifier: GPL-2.0-or-later
//
// Copyright (C) 2026 Bin Jin. All Rights Reserved.
#include <linux/inetdevice.h>
#include <linux/net.h>
#include <linux/net_namespace.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
#include <net/netns/generic.h>
#include <net/sock.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <linux/netfilter_ipv6.h>
#include <net/addrconf.h>
#include <net/netfilter/ipv6/nf_defrag_ipv6.h>
#endif

#include "phantun.h"
#include "phantun_compat.h"
#include "phantun_flow.h"

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

struct pht_flow_table *phantun_net_hook_flows(const struct net *net) {
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
};
#endif

/* Failed attachment and normal exit quiesce hooks before destroying any
 * state they can borrow. Readiness distinguishes selected/initialized netns
 * from skipped namespaces and makes partial cleanup idempotent.
 */
static void phantun_net_cleanup(struct net *net, struct phantun_net *pnet) {
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
    pht_flow_table_destroy(&pnet->flows);
    pnet->flow_table_ready = false;
}

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
    phantun_net_cleanup(net, pnet);
    return ret;
}

static void __net_exit phantun_net_exit(struct net *net) {
    struct phantun_net *pnet = net_generic(net, phantun_net_id);

    if (!pnet || !pnet->flow_table_ready)
        return;

    phantun_net_cleanup(net, pnet);
    pht_pr_info("unregistered netfilter hooks and topology notifiers: netns %u\n",
                phantun_netns_id(net));
}

static struct pernet_operations phantun_pernet_ops = {
    .id = &phantun_net_id,
    .size = sizeof(struct phantun_net),
    .init = phantun_net_init,
    .exit = phantun_net_exit,
};

int phantun_netns_init(void) {
    int ret;

    ret = register_pernet_subsys(&phantun_pernet_ops);
    if (ret)
        return ret;

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
    return ret;
}

void phantun_netns_exit(void) {
#if IS_ENABLED(CONFIG_IPV6)
    if (phantun_cfg.enabled_families & PHT_FAMILY_IPV6)
        unregister_inet6addr_notifier(&phantun_inet6addr_nb);
#endif
    if (phantun_cfg.enabled_families & PHT_FAMILY_IPV4)
        unregister_inetaddr_notifier(&phantun_inetaddr_nb);
    unregister_pernet_subsys(&phantun_pernet_ops);
}
