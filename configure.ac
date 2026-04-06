AC_PREREQ([2.69])

m4_define([PHANTUN_VERSION], m4_esyscmd([sed -n 's/^PACKAGE_VERSION="\(.*\)"/\1/p' dkms.conf | tr -d '\n']))

AC_INIT([phantun], PHANTUN_VERSION, [bjin@protonmail.com], [phantun], [https://github.com/bjin/phantun-dkms/])
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

AS_IF([test "x$ac_cv_have_ip_route_input_dscp" = xyes], [
  AC_DEFINE(
    [HAVE_IP_ROUTE_INPUT_DSCP], [1],
    [Define to 1 if ip_route_input takes DSCP and works with ip4h_dscp()]
  )
])
AC_CACHE_CHECK([whether base64_decode takes 5 arguments], [ac_cv_have_base64_decode_5args], [
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
#include <linux/base64.h>

static int conftest_base64_5args(void)
{
    u8 *dst = NULL;
    return base64_decode("YWJj", 4, dst, true, BASE64_STD);
}

module_init(conftest_base64_5args);
MODULE_LICENSE("GPL");
EOF

  if ${MAKE-make} -C "$KDIR" M="$conftest_dir" modules \
      >"$conftest_dir/build.log" 2>&1; then
    ac_cv_have_base64_decode_5args=yes
  else
    cat "$conftest_dir/build.log" >&5
    ac_cv_have_base64_decode_5args=no
  fi

  rm -rf "$conftest_dir"
  trap - 0 1 2 15
])

AS_IF([test "x$ac_cv_have_base64_decode_5args" = xyes], [
  AC_DEFINE(
    [HAVE_BASE64_DECODE_5ARGS], [1],
    [Define to 1 if base64_decode takes 5 arguments]
  )
])

AC_CACHE_CHECK([whether base64_decode takes 3 arguments], [ac_cv_have_base64_decode_3args], [
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
#include <linux/base64.h>

static int conftest_base64_3args(void)
{
    u8 *dst = NULL;
    return base64_decode("YWJj", 4, dst);
}

module_init(conftest_base64_3args);
MODULE_LICENSE("GPL");
EOF

  if ${MAKE-make} -C "$KDIR" M="$conftest_dir" modules \
      >"$conftest_dir/build.log" 2>&1; then
    ac_cv_have_base64_decode_3args=yes
  else
    cat "$conftest_dir/build.log" >&5
    ac_cv_have_base64_decode_3args=no
  fi

  rm -rf "$conftest_dir"
  trap - 0 1 2 15
])

AS_IF([test "x$ac_cv_have_base64_decode_3args" = xyes], [
  AC_DEFINE(
    [HAVE_BASE64_DECODE_3ARGS], [1],
    [Define to 1 if base64_decode takes 3 arguments]
  )
])
AS_IF([test "x$ac_cv_have_base64_decode_5args" = xno && test "x$ac_cv_have_base64_decode_3args" = xno], [
  AC_MSG_ERROR([kernel does not have a supported base64_decode interface])
])

AC_CACHE_CHECK([for linux/hex.h], [ac_cv_have_linux_hex_h], [
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
#include <linux/hex.h>

static int conftest_linux_hex_h(void)
{
    return 0;
}

module_init(conftest_linux_hex_h);
MODULE_LICENSE("GPL");
EOF

  if ${MAKE-make} -C "$KDIR" M="$conftest_dir" modules \
      >"$conftest_dir/build.log" 2>&1; then
    ac_cv_have_linux_hex_h=yes
  else
    cat "$conftest_dir/build.log" >&5
    ac_cv_have_linux_hex_h=no
  fi

  rm -rf "$conftest_dir"
  trap - 0 1 2 15
])

AS_IF([test "x$ac_cv_have_linux_hex_h" = xyes], [
  AC_DEFINE(
    [HAVE_LINUX_HEX_H], [1],
    [Define to 1 if <linux/hex.h> is available]
  )
])
AC_CACHE_CHECK([for net/gso.h], [ac_cv_have_net_gso_h], [
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
#include <net/gso.h>

static int conftest_net_gso_h(void)
{
    return 0;
}

module_init(conftest_net_gso_h);
MODULE_LICENSE("GPL");
EOF

  if ${MAKE-make} -C "$KDIR" M="$conftest_dir" modules \
      >"$conftest_dir/build.log" 2>&1; then
    ac_cv_have_net_gso_h=yes
  else
    cat "$conftest_dir/build.log" >&5
    ac_cv_have_net_gso_h=no
  fi

  rm -rf "$conftest_dir"
  trap - 0 1 2 15
])

AS_IF([test "x$ac_cv_have_net_gso_h" = xyes], [
  AC_DEFINE(
    [HAVE_NET_GSO_H], [1],
    [Define to 1 if <net/gso.h> is available]
  )
])


AC_CONFIG_FILES([Makefile])

AC_OUTPUT
