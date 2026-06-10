// SPDX-License-Identifier: GPL-2.0-or-later
//
// Copyright (C) 2026 Bin Jin. All Rights Reserved.
#ifndef PHANTUN_COMPAT_H
#define PHANTUN_COMPAT_H

#include "config.h"

#ifndef HAVE_TIMER_CONTAINER_OF
#define timer_container_of(var, callback_timer, timer_fieldname)                                   \
    from_timer(var, callback_timer, timer_fieldname)
#endif

#ifndef HAVE_TIMER_SHUTDOWN_SYNC
/* Older kernels lack timer_shutdown_sync(). This module only uses the helper
 * after marking the owning flow DEAD, sharing the cancel path invariant that
 * half-open state is cleared under flow->lock before timer teardown. The
 * retransmit callback also re-arms while holding flow->lock, so
 * timer_delete_sync() provides the required quiesce semantics here.
 */
#define timer_shutdown_sync(timer) timer_delete_sync(timer)
#endif

#ifndef HAVE_TIMER_DELETE
#define timer_delete(timer) del_timer(timer)
#endif

/* kernel_bind() switched from struct sockaddr * to struct sockaddr_unsized *
 * in newer kernels. Keep one call-site API and cast at the boundary.
 */
#if defined(HAVE_KERNEL_BIND_SOCKADDR_UNSIZED)
#define KERNEL_BIND_COMPAT(sock, addr, addrlen)                                                    \
    kernel_bind((sock), (struct sockaddr_unsized *)(addr), (addrlen))
#elif defined(HAVE_KERNEL_BIND_SOCKADDR)
#define KERNEL_BIND_COMPAT(sock, addr, addrlen)                                                    \
    kernel_bind((sock), (struct sockaddr *)(addr), (addrlen))
#else
#error "kernel doesn't support kernel_bind()"
#endif

#if defined(HAVE_BASE64_DECODE_5ARGS)
#define PHANTUN_HAVE_BASE64_DECODE 1
#define BASE64_DECODE_COMPAT(src, srclen, dst)                                                     \
    base64_decode((src), (srclen), (dst), true, BASE64_STD)
#elif defined(HAVE_BASE64_DECODE_3ARGS)
#define PHANTUN_HAVE_BASE64_DECODE 1
#define BASE64_DECODE_COMPAT(src, srclen, dst) base64_decode((src), (srclen), (dst))
#else
#define PHANTUN_HAVE_BASE64_DECODE 0
#endif

/* dst_rt6_info() was added after the oldest supported IPv6 kernels. Older
 * kernels embed struct dst_entry at offset 0 in struct rt6_info and open-code
 * the same cast in their IPv6 route helpers.
 */
#ifndef HAVE_DST_RT6_INFO
#define dst_rt6_info(dst) ((struct rt6_info *)(dst))
#endif

#ifdef HAVE_NF_DEFRAG_IPV4_DISABLE
#define NF_DEFRAG_IPV4_DISABLE_COMPAT(net) nf_defrag_ipv4_disable(net)
#else
/* Older kernels expose nf_defrag_ipv4_enable() without a matching disable
 * helper. Their enable path is an idempotent per-netns registration; the defrag
 * module unregisters its hooks from its pernet exit path.
 */
#define NF_DEFRAG_IPV4_DISABLE_COMPAT(net)                                                         \
    do {                                                                                           \
        (void)(net);                                                                               \
    } while (0)
#endif

#ifdef HAVE_NF_DEFRAG_IPV6_DISABLE
#define NF_DEFRAG_IPV6_DISABLE_COMPAT(net) nf_defrag_ipv6_disable(net)
#else
/* Older kernels expose nf_defrag_ipv6_enable() without a matching disable
 * helper. Their enable path is an idempotent per-netns registration; the defrag
 * module unregisters its hooks from its pernet exit path.
 */
#define NF_DEFRAG_IPV6_DISABLE_COMPAT(net)                                                         \
    do {                                                                                           \
        (void)(net);                                                                               \
    } while (0)
#endif
#endif
