#ifndef PHANTUN_H
#define PHANTUN_H

#include <linux/kernel.h>
#include <linux/types.h>

#define PHANTUN_MODULE_NAME "phantun"
#define PHANTUN_MAX_MANAGED_PORTS 16
#define PHANTUN_DEFAULT_HANDSHAKE_TIMEOUT_MS 1000U
#define PHANTUN_DEFAULT_HANDSHAKE_RETRIES 6U
#define PHANTUN_DEFAULT_IDLE_TIMEOUT_SEC 180U
#define PHANTUN_CAPTURE_PRIORITY (-400)

#define pht_pr_err(fmt, ...) pr_err(PHANTUN_MODULE_NAME ": " fmt, ##__VA_ARGS__)
#define pht_pr_warn(fmt, ...) \
	pr_warn(PHANTUN_MODULE_NAME ": " fmt, ##__VA_ARGS__)
#define pht_pr_info(fmt, ...) \
	pr_info(PHANTUN_MODULE_NAME ": " fmt, ##__VA_ARGS__)
#define pht_pr_debug(fmt, ...) \
	pr_debug(PHANTUN_MODULE_NAME ": " fmt, ##__VA_ARGS__)

struct phantun_config {
	u16 managed_ports[PHANTUN_MAX_MANAGED_PORTS];
	unsigned int managed_ports_count;
	const char *handshake_request;
	const char *handshake_response;
	unsigned int handshake_request_len;
	unsigned int handshake_response_len;
	unsigned int handshake_timeout_ms;
	unsigned int handshake_retries;
	unsigned int idle_timeout_sec;
	const char *remote_ipv4_cidr;
	__be32 remote_ipv4_addr;
	__be32 remote_ipv4_mask;
	u16 remote_port;
	bool remote_ipv4_enabled;
};

#endif
