AC_INIT([libmincrypt], [0.0.5], [mignov@gmail.com])
LT_INIT([shared])
AC_ENABLE_SHARED
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall -Werror])
#AM_INIT_AUTOMAKE([-Wno-portability])
#AM_MAINTAINER_MODE([enable])
#AC_PROG_CXX

AC_PROG_CC
AM_PROG_CC_C_O
AC_CHECK_LIB([m], [pow], [], AC_MSG_ERROR([You need libm to compile this application]))
AC_CHECK_TOOL([MKDIR], [mkdir])
AC_CHECK_TOOL([ECHO], [echo])
AC_CHECK_TOOL([RM], [rm])
AC_CHECK_TOOL([CP], [cp])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile include/Makefile])
AC_OUTPUT
LT_OUTPUT
