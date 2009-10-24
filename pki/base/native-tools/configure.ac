# --- BEGIN COPYRIGHT BLOCK ---
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
# 
# Copyright (C) 2007 Red Hat, Inc.
# All rights reserved.
# --- END COPYRIGHT BLOCK ---

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_PREREQ(2.59)
AC_INIT([pki-native-tools], [8.0.0], [http://bugzilla.redhat.com/])
# AC_CONFIG_HEADER must be called right after AC_INIT.
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([1.9 foreign subdir-objects])
AM_MAINTAINER_MODE
AC_CANONICAL_HOST

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AM_PROG_CC_C_O
# disable static libs by default - we only use a couple
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h malloc.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/file.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STAT
AC_C_CONST
AC_HEADER_STDBOOL
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_LSTAT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MMAP
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_FUNC_STRERROR_R
AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([setrlimit endpwent ftruncate getcwd gethostbyname inet_ntoa localtime_r memmove memset mkdir munmap putenv rmdir socket strcasecmp strchr strcspn strdup strerror strncasecmp strpbrk strrchr strstr strtol tzset])

# Establish an optional "--enable-64bit" flag
AC_MSG_CHECKING(for --enable-64bit)
AC_ARG_ENABLE(64bit, [  --enable-64bit         Enable 64-bit features],
[
  AC_MSG_RESULT(yes)
  USE_64=1
],
[
  AC_MSG_RESULT(no)
  USE_64=
])

# For historical reasons, establish various "--enable-debug" flags
# for both DeBuG (yes) and OPTimized (no) builds
AC_MSG_CHECKING(for --enable-debug)
AC_ARG_ENABLE(debug, [  --enable-debug         Enable debug features],
[
  AC_MSG_RESULT(yes)
  debug_defs="-DDEBUG -UNDEBUG -DTRACING"
],
[
  AC_MSG_RESULT(no)
  debug_defs="-UDEBUG -DNDEBUG -DTRIMMED"
])
AC_SUBST([debug_defs])

AC_PREFIX_DEFAULT([/opt])

# installation paths - by default, configure will just
# use /usr as the prefix for everything, which means
# /usr/etc, /usr/opt, and /usr/var.  FHS sez to use
# /etc, /opt, and /var.
ac_default_prefix=/opt
prefix=$ac_default_prefix
exec_prefix=$prefix
# relative to prefix
confdir=/conf
readmedir=/doc
samplesdir=/samples
templatesdir=/templates
AC_SUBST(confdir)
AC_SUBST(readmedir)
AC_SUBST(samplesdir)
AC_SUBST(templatesdir)

# WINNT should be true if building on Windows system not using
# cygnus, mingw, or the like and using cmd.exe as the shell
AM_CONDITIONAL([WINNT], false)

# Deal with platform dependent defines
case $host in
  *-*-linux*)
    AC_DEFINE([XP_UNIX], [1], [UNIX])
    AC_DEFINE([linux], [1], [linux])
    AC_DEFINE([Linux], [], [Linux])
    AC_DEFINE([LINUX], [], [Linux])
    AC_DEFINE([LINUX2_0], [], [Linux 2.6])
    AC_DEFINE([LINUX2_2], [], [Linux 2.6])
    AC_DEFINE([LINUX2_4], [], [Linux 2.6])
    AC_DEFINE([LINUX2_6], [], [Linux 2.6])
    # For historical reasons, establish various "DEFINES" for NATIVE-TOOLS . . .
    AC_DEFINE([_BSD_SOURCE], [1], [_BSD_SOURCE])
    AC_DEFINE([_POSIX_SOURCE], [1], [_POSIX_SOURCE])
    AC_DEFINE([_POSIX_C_SOURCE], [199506L], [_POSIX_C_SOURCE])
    AC_DEFINE([_PR_NEED_FAKE_POLL], [], [_PR_NEED_FAKE_POLL])
    AC_DEFINE([_REENTRANT], [], [_REENTRANT])
    AC_DEFINE([_SVID_SOURCE], [1], [_SVID_SOURCE])
    AC_DEFINE([HAVE_SIGNED_CHAR], [], [HAVE_SIGNED_CHAR])
    AC_DEFINE([HAVE_SYS_BITYPES_H], [], [HAVE_SYS_BITYPES_H])
    AC_DEFINE([NEED_ENDIAN_H], [], [NEED_ENDIAN_H])
    AC_DEFINE([NEED_GETOPT_H], [], [NEED_GETOPT_H])
    AC_DEFINE([NEED_IOCTL_H], [], [NEED_IOCTL_H])
    AC_DEFINE([NEED_SYS_TIME_H], [], [NEED_SYS_TIME_H])
    AC_DEFINE([NEED_UINT_T], [], [NEED_UINT_T])
    AC_DEFINE([NET_SSL], [], [NET_SSL])
    AC_DEFINE([NO_INT64_T], [], [NO_INT64_T])
    AC_DEFINE([SW_THREADS], [], [SW_THREADS])
    AC_DEFINE([USE_NODL_TABS], [], [USE_NODL_TABS])
    platform="linux"
    ;;
  ia64-hp-hpux*)
    AC_DEFINE([XP_UNIX], [1], [UNIX])
    AC_DEFINE([hpux], [1], [HP-UX])
    AC_DEFINE([HPUX], [], [HP-UX])
    AC_DEFINE([HPUX11], [1], [HP-UX 11])
    AC_DEFINE([HPUX11_23], [1], [HP-UX 11.23])
    AC_DEFINE([CPU_ia64], [], [cpu type ia64])
    AC_DEFINE([OS_hpux], [1], [OS HP-UX])
    AC_DEFINE([_POSIX_C_SOURCE], [199506L], [POSIX revision])
    AC_DEFINE([_HPUX_SOURCE], [], [_HPUX_SOURCE])
    platform="hpux"
    ;;
  hppa*-hp-hpux*)
    AC_DEFINE([XP_UNIX], [1], [UNIX])
    AC_DEFINE([hpux], [1], [HP-UX])
    AC_DEFINE([HPUX], [], [HP-UX])
    AC_DEFINE([HPUX11], [1], [HP-UX 11])
    AC_DEFINE([HPUX11_11], [1], [HP-UX 11.11])
    AC_DEFINE([hppa], [], [HP-UX pa-risc])
    AC_DEFINE([CPU_hppa], [], [cpu type pa-risc])
    AC_DEFINE([OS_hpux], [1], [OS HP-UX])
    AC_DEFINE([_POSIX_C_SOURCE], [199506L], [POSIX revision])
    AC_DEFINE([_HPUX_SOURCE], [], [_HPUX_SOURCE])
    # For historical reasons, establish various "DEFINES" for NATIVE-TOOLS . . .
    AC_DEFINE([HPUX_SOURCE], [], [HPUX_SOURCE])
    AC_DEFINE([HAVE_STRERROR], [], [HAVE_STRERROR])
    AC_DEFINE([NET_SSL], [], [NET_SSL])
    AC_DEFINE([SW_THREADS], [], [SW_THREADS])
    platform="hpux"
    ;;
  sparc-sun-solaris*)
    AC_DEFINE([XP_UNIX], [1], [UNIX])
    AC_DEFINE([SVR4], [], [SVR4])
    AC_DEFINE([__svr4], [], [SVR4])
    AC_DEFINE([__svr4__], [], [SVR4])
    AC_DEFINE([_SVID_GETTOD], [], [SVID_GETTOD])
    AC_DEFINE([SOLARIS], [], [SOLARIS])
    AC_DEFINE([CPU_sparc], [], [cpu type sparc])
    AC_DEFINE([OS_solaris], [1], [OS SOLARIS])
    AC_DEFINE([sunos5], [1], [SunOS5])
    AC_DEFINE([OSVERSION], [509], [OS version])
    AC_DEFINE([_REENTRANT], [], [_REENTRANT])
dnl socket nsl and dl are required to link several programs
    LIBSOCKET=-lsocket
    AC_SUBST([LIBSOCKET], [$LIBSOCKET])
    LIBNSL=-lnsl
    AC_SUBST([LIBNSL], [$LIBNSL])
    LIBDL=-ldl
    AC_SUBST([LIBDL], [$LIBDL])
dnl Cstd and Crun are required to link any C++ related code
    LIBCSTD=-lCstd
    AC_SUBST([LIBCSTD], [$LIBCSTD])
    LIBCRUN=-lCrun
    AC_SUBST([LIBCRUN], [$LIBCRUN])
    # For historical reasons, establish various "DEFINES" for NATIVE-TOOLS . . .
    AC_DEFINE([_PR_NTHREAD], [], [_PR_NTHREAD])
    AC_DEFINE([HAVE_WEAK_IO_SYMBOLS], [], [HAVE_WEAK_IO_SYMBOLS])
    AC_DEFINE([NET_SSL], [], [NET_SSL])
    AC_DEFINE([NS_USE_NATIVE], [], [NS_USE_NATIVE])
    AC_DEFINE([NSPR], [], [NSPR])
    AC_DEFINE([NSPR20], [], [NSPR20])
    AC_DEFINE([SOLARIS_55_OR_GREATER], [], [SOLARIS_55_OR_GREATER])
    AC_DEFINE([SYSV], [], [SYSV])
    platform="solaris"
    ;;
  *)
    platform=""
    ;;
esac

AM_CONDITIONAL(LINUX,test "$platform" = "linux")
AM_CONDITIONAL(HPUX,test "$platform" = "hpux")
AM_CONDITIONAL(SOLARIS,test "$platform" = "solaris")

# Check for library dependencies
m4_include(m4/nspr.m4)
m4_include(m4/nss.m4)
m4_include(m4/mozldap.m4)
m4_include(m4/sasl.m4)
m4_include(m4/svrcore.m4)

# write out paths for binary components
AC_SUBST(nspr_inc)
AC_SUBST(nspr_lib)
AC_SUBST(nspr_libdir)
AC_SUBST(nss_inc)
AC_SUBST(nss_lib)
AC_SUBST(nss_libdir)
AC_SUBST(ldapsdk_inc)
AC_SUBST(ldapsdk_lib)
AC_SUBST(ldapsdk_libdir)
AC_SUBST(ldapsdk_bindir)
AC_SUBST(sasl_inc)
AC_SUBST(sasl_lib)
AC_SUBST(sasl_libdir)
AC_SUBST(svrcore_inc)
AC_SUBST(svrcore_lib)

# libtool on fedora/rhel contains some gcc-isms which cause problems
# if not using gcc (e.g. Forte on Solaris, aCC on HP-UX)
# we remove them here
if test "$GCC" != yes ; then
   AC_MSG_NOTICE([Not using gcc - fixing libtool to remove gcc-isms . . .])
   cp -p libtool libtool.orig
   cp -p libtool libtool.tmp
   # dnl note the special chars @<:@ and @:>@ - since m4 treats [ and ] specially,
   # we have to use the quadrigraph @<:@ for [ and @:>@ for ] - and you thought
   # perl produced write-only code . . .
   sed -e '/^gcc_dir/ d' \
       -e '/^gcc_ver/ d' \
       -e 's/^predep_objects=.*echo \("@<:@^"@:>@*"\).*$/predep_objects=\1/' \
       -e 's/^postdep_objects=.*echo \("@<:@^"@:>@*"\).*$/postdep_objects=\1/' \
       -e 's/^compiler_lib_search_path=.*echo \("@<:@^"@:>@*"\).*$/compiler_lib_search_path=\1/' \
       -e 's/^sys_lib_search_path_spec=.*echo \("@<:@^"@:>@*"\).*$/sys_lib_search_path_spec=\1/' \
       libtool > libtool.tmp
   cp -p libtool.tmp libtool
   rm -f libtool.tmp
fi

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
