AC_PREREQ([2.69])
AC_INIT([phantun], [0.1.0], [bjin@protonmail.com])
AC_CONFIG_HEADERS([config.h])

AC_ARG_WITH([kernel],
  [AS_HELP_STRING([--with-kernel=DIR], [Kernel build directory])],
  [KDIR="$withval"],
  [
    KVER=`uname -r`
    KDIR=
    for d in \
      "/lib/modules/$KVER/build" \
      "/run/booted-system/kernel-modules/lib/modules/$KVER/build" \
      "/run/current-system/kernel-modules/lib/modules/$KVER/build"
    do
      if test -d "$d"; then
        KDIR="$d"
        break
      fi
    done
  ]
)

AS_IF([test -z "$KDIR"], [
  AC_MSG_ERROR([could not find a kernel build directory; use --with-kernel=DIR])
])

AS_IF([test ! -d "$KDIR"], [
  AC_MSG_ERROR([kernel build directory does not exist: $KDIR])
])

AC_SUBST([KDIR])

AC_CONFIG_SRCDIR([src/phantun_main.c])

AC_CACHE_CHECK([for timer_container_of], [ac_cv_have_timer_container_of], [
  conftest_dir="$ac_pwd/conftest-kbuild-$$"

  rm -rf "$conftest_dir" ||
    AC_MSG_FAILURE([failed to remove $conftest_dir])
  mkdir -p "$conftest_dir" ||
    AC_MSG_FAILURE([failed to create $conftest_dir])

  trap 'rm -rf "$conftest_dir"' 0 1 2 15

  cat >"$conftest_dir/Makefile" <<'EOF'
obj-m := conftest.o
EOF

  cat >"$conftest_dir/conftest.c" <<'EOF'
#include <linux/timer.h>
#include <linux/module.h>

struct my_struct {
    struct timer_list my_timer;
};

static void my_timer_func(struct timer_list *t)
{
    struct my_struct *my = NULL;
    my = timer_container_of(my, t, my_timer);
    (void)my;
}

MODULE_LICENSE("GPL");
EOF

  if ${MAKE-make} -C "$KDIR" M="$conftest_dir" modules \
      >"$conftest_dir/build.log" 2>&1; then
    ac_cv_have_timer_container_of=yes
  else
    ac_cv_have_timer_container_of=no
  fi

  rm -rf "$conftest_dir"
  trap - 0 1 2 15
])

AS_IF([test "x$ac_cv_have_timer_container_of" = xyes], [
  AC_DEFINE([HAVE_TIMER_CONTAINER_OF], [1],
            [Define to 1 if timer_container_of is available])
])

AC_CACHE_CHECK([whether ip_route_input takes DSCP], [ac_cv_have_ip_route_input_dscp], [
  conftest_dir="$ac_pwd/conftest-kbuild-$$"

  rm -rf "$conftest_dir" ||
    AC_MSG_FAILURE([failed to remove $conftest_dir])
  mkdir -p "$conftest_dir" ||
    AC_MSG_FAILURE([failed to create $conftest_dir])

  trap 'rm -rf "$conftest_dir"' 0 1 2 15

  cat >"$conftest_dir/Makefile" <<'EOF'
obj-m := conftest.o
EOF

  cat >"$conftest_dir/conftest.c" <<'EOF'
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <net/ip.h>
#include <net/route.h>

static int conftest_ip_route_input_dscp(struct sk_buff *skb,
                                        const struct iphdr *iph,
                                        struct net_device *dev)
{
    return ip_route_input(skb, iph->daddr, iph->saddr, ip4h_dscp(iph), dev);
}

MODULE_LICENSE("GPL");
EOF

  if ${MAKE-make} -C "$KDIR" M="$conftest_dir" modules \
      >"$conftest_dir/build.log" 2>&1; then
    ac_cv_have_ip_route_input_dscp=yes
  else
    ac_cv_have_ip_route_input_dscp=no
  fi

  rm -rf "$conftest_dir"
  trap - 0 1 2 15
])

AS_IF([test "x$ac_cv_have_ip_route_input_dscp" = xyes], [
  AC_DEFINE(
    [HAVE_IP_ROUTE_INPUT_DSCP], [1],
    [Define to 1 if ip_route_input takes DSCP and works with ip4h_dscp()]
  )
])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
