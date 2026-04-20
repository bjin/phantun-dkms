// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef PHANTUN_COMPAT_H
#define PHANTUN_COMPAT_H

#include "config.h"

#ifndef HAVE_TIMER_CONTAINER_OF
#define timer_container_of(var, callback_timer, timer_fieldname)                                   \
    from_timer(var, callback_timer, timer_fieldname)
#endif

#ifndef HAVE_TIMER_SHUTDOWN_SYNC
/* Older kernels lack timer_shutdown_sync(). This module only uses the helper
 * after marking the owning flow DEAD and detaching it from rearm paths, so
 * timer_delete_sync() provides the required quiesce semantics here.
 */
#define timer_shutdown_sync(timer) timer_delete_sync(timer)
#endif

#ifndef HAVE_TIMER_DELETE
#define timer_delete(timer) del_timer(timer)
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

#endif
