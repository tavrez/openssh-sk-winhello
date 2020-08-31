#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.69])
AC_INIT([winhello], [1.0.3-dev], [https://github.com/tavrez/openssh-sk-winhello/issues])
AC_CONFIG_SRCDIR([src/winhello.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIRS([m4])
AC_PREFIX_DEFAULT([/usr])
: ${CFLAGS="-O2"}

AC_DEFINE([PACKAGE_VERSION_MAJOR], [1], [Major number of build])
AC_DEFINE([PACKAGE_VERSION_MINOR], [0], [Minor number of build])
AC_DEFINE([PACKAGE_VERSION_PATCH], [3], [Patch number of build])
AC_DEFINE([PACKAGE_VERSION_DEV], [1], [Internal build])
AC_DEFINE([PACKAGE_VERSION_PRE], [0], [Pre-release build])
AC_DEFINE([PACKAGE_VERSION_BUILDNUMBER], [7], [Incremental number of build])
AC_DEFINE([SK_DEBUG], [1], [Enable output messages])

AM_INIT_AUTOMAKE([foreign])
LT_INIT([win32-dll disable-static])
LT_LANG([Windows Resource])
AM_CONDITIONAL([USE_RC], [test "x$RC" != "x"])

# Checks for programs.
AC_PROG_CC
AC_CHECK_PROGS([webauthn_dll_found], [webauthn.dll], [NA])
if test "$webauthn_dll_found" = "NA"; then
	AC_MSG_WARN([webauthn.dll is not available on this system, you can compile without it but you need it to run this project. It is available on Windows 10 version 1903 or higher.]);
fi

# Checks for libraries.
AC_CHECK_LIB([crypto], [OpenSSL_version_num], [], [AC_MSG_ERROR([libcrypto not found, OpenSSL 1.1.0+ is required.])])

# Checks for header files.
AC_CHECK_HEADERS([stddef.h stdint.h stdlib.h wchar.h string.h windows.h openssl/opensslv.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset])

AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_FILES([makefile src/makefile])
AC_OUTPUT
