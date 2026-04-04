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

#endif
