AC_DEFUN([PDNS_CHECK_NETLINK], [
  AC_CHECK_HEADER([linux/netlink.h], [
    AC_CHECK_HEADER([linux/rtnetlink.h], [
      AC_DEFINE([HAVE_RTNETLINK], [1], [Define this to 1 if you have RTNETLINK])
    ])
  ])
])
