#ifndef PHANTUN_COMPAT_H
#define PHANTUN_COMPAT_H

#include "config.h"

#ifndef HAVE_TIMER_CONTAINER_OF
#define timer_container_of(var, callback_timer, timer_fieldname)                                   \
    from_timer(var, callback_timer, timer_fieldname)
#endif

#ifndef HAVE_IP_ROUTE_INPUT_DSCP
#define ip4h_dscp(ip4h) ((ip4h)->tos)
#endif

#if defined(HAVE_BASE64_DECODE_5ARGS)
#define BASE64_DECODE_COMPAT(src, srclen, dst)                                                     \
    base64_decode((src), (srclen), (dst), true, BASE64_STD)
#elif defined(HAVE_BASE64_DECODE_3ARGS)
#define BASE64_DECODE_COMPAT(src, srclen, dst) base64_decode((src), (srclen), (dst))
#else
#error "kernel doesn't support base64_decode()"
#endif

#endif
