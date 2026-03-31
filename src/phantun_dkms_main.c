#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/net_namespace.h>
#include <linux/skbuff.h>
#include <linux/string.h>

#include "phantun_dkms.h"

static unsigned short managed_ports[PHANTUN_DKMS_MAX_MANAGED_PORTS];
static int managed_ports_count;
static char *handshake_request;
static char *handshake_response;
static unsigned int handshake_timeout_ms =
	PHANTUN_DKMS_DEFAULT_HANDSHAKE_TIMEOUT_MS;
static unsigned int handshake_retries = PHANTUN_DKMS_DEFAULT_HANDSHAKE_RETRIES;
static unsigned int idle_timeout_sec = PHANTUN_DKMS_DEFAULT_IDLE_TIMEOUT_SEC;
static char *remote_ipv4_cidr;
static unsigned short remote_port;

module_param_array_named(managed_ports, managed_ports, ushort,
	&managed_ports_count, 0644);
MODULE_PARM_DESC(managed_ports,
	"Comma-separated local UDP/TCP ports managed by phantun_dkms");
module_param(handshake_request, charp, 0644);
MODULE_PARM_DESC(handshake_request,
	"Mandatory initiator control payload sent as the first fake-TCP payload");
module_param(handshake_response, charp, 0644);
MODULE_PARM_DESC(handshake_response,
	"Mandatory responder control payload sent as the first fake-TCP payload");
module_param(handshake_timeout_ms, uint, 0644);
MODULE_PARM_DESC(handshake_timeout_ms,
	"Handshake retransmit timeout in milliseconds");
module_param(handshake_retries, uint, 0644);
MODULE_PARM_DESC(handshake_retries,
	"Maximum handshake retry count before tearing a flow down with RST");
module_param(idle_timeout_sec, uint, 0644);
MODULE_PARM_DESC(idle_timeout_sec,
	"Idle flow timeout in seconds before teardown");
module_param(remote_ipv4_cidr, charp, 0644);
MODULE_PARM_DESC(remote_ipv4_cidr,
	"Optional remote IPv4 CIDR filter (string form, parsed in later phases)");
module_param(remote_port, ushort, 0644);
MODULE_PARM_DESC(remote_port,
	"Optional remote UDP/TCP port filter; 0 disables the filter");

static struct phantun_dkms_config phantun_cfg;

static unsigned int phantun_local_out(void *priv, struct sk_buff *skb,
				      const struct nf_hook_state *state)
{
	return NF_ACCEPT;
}

static unsigned int phantun_pre_routing(void *priv, struct sk_buff *skb,
				       const struct nf_hook_state *state)
{
	return NF_ACCEPT;
}

static struct nf_hook_ops phantun_nf_ops[] = {
	{
		.hook = phantun_local_out,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = PHANTUN_DKMS_CAPTURE_PRIORITY,
	},
	{
		.hook = phantun_pre_routing,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = PHANTUN_DKMS_CAPTURE_PRIORITY,
	},
};

static int phantun_validate_config(void)
{
	if (!managed_ports_count) {
		pht_pr_err("at least one managed_ports entry is required\n");
		return -EINVAL;
	}

	if (!handshake_request || !strlen(handshake_request)) {
		pht_pr_err("handshake_request must be set and non-empty\n");
		return -EINVAL;
	}

	if (!handshake_response || !strlen(handshake_response)) {
		pht_pr_err("handshake_response must be set and non-empty\n");
		return -EINVAL;
	}

	if (!handshake_timeout_ms) {
		pht_pr_err("handshake_timeout_ms must be greater than zero\n");
		return -EINVAL;
	}

	if (!handshake_retries) {
		pht_pr_err("handshake_retries must be greater than zero\n");
		return -EINVAL;
	}

	if (!idle_timeout_sec) {
		pht_pr_err("idle_timeout_sec must be greater than zero\n");
		return -EINVAL;
	}

	return 0;
}

static void phantun_snapshot_config(void)
{
	unsigned int i;

	memset(&phantun_cfg, 0, sizeof(phantun_cfg));
	phantun_cfg.managed_ports_count = managed_ports_count;
	for (i = 0; i < managed_ports_count; i++)
		phantun_cfg.managed_ports[i] = managed_ports[i];
	phantun_cfg.handshake_request = handshake_request;
	phantun_cfg.handshake_response = handshake_response;
	phantun_cfg.handshake_timeout_ms = handshake_timeout_ms;
	phantun_cfg.handshake_retries = handshake_retries;
	phantun_cfg.idle_timeout_sec = idle_timeout_sec;
	phantun_cfg.remote_ipv4_cidr = remote_ipv4_cidr;
	phantun_cfg.remote_port = remote_port;
}

static void phantun_log_config(void)
{
	unsigned int i;

	pht_pr_info("loading with %u managed port(s), handshake_timeout_ms=%u, handshake_retries=%u, idle_timeout_sec=%u\n",
		    phantun_cfg.managed_ports_count,
		    phantun_cfg.handshake_timeout_ms,
		    phantun_cfg.handshake_retries,
		    phantun_cfg.idle_timeout_sec);

	for (i = 0; i < phantun_cfg.managed_ports_count; i++)
		pht_pr_info("managed_ports[%u]=%u\n", i,
			    phantun_cfg.managed_ports[i]);

	if (phantun_cfg.remote_ipv4_cidr)
		pht_pr_info("remote_ipv4_cidr=%s\n",
			    phantun_cfg.remote_ipv4_cidr);
	if (phantun_cfg.remote_port)
		pht_pr_info("remote_port=%u\n", phantun_cfg.remote_port);
}

static int __init phantun_init(void)
{
	int ret;

	ret = phantun_validate_config();
	if (ret)
		return ret;

	phantun_snapshot_config();
	phantun_log_config();

	ret = nf_register_net_hooks(&init_net, phantun_nf_ops,
				    ARRAY_SIZE(phantun_nf_ops));
	if (ret) {
		pht_pr_err("failed to register netfilter hooks: %d\n", ret);
		return ret;
	}

	pht_pr_info("registered IPv4 LOCAL_OUT and PRE_ROUTING hooks\n");
	return 0;
}

static void __exit phantun_exit(void)
{
	nf_unregister_net_hooks(&init_net, phantun_nf_ops,
				 ARRAY_SIZE(phantun_nf_ops));
	pht_pr_info("unregistered netfilter hooks\n");
}

module_init(phantun_init);
module_exit(phantun_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OpenAI");
MODULE_DESCRIPTION("Kernel-mode Phantun skeleton");
MODULE_VERSION("0.1.0");
