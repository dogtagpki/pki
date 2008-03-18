dnl BEGIN COPYRIGHT BLOCK
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; version 2 of the License.
dnl 
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl 
dnl You should have received a copy of the GNU General Public License along
dnl with this program; if not, write to the Free Software Foundation, Inc.,
dnl 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
dnl 
dnl Copyright (C) 2007 Red Hat, Inc.
dnl All rights reserved.
dnl END COPYRIGHT BLOCK

AC_CHECKING(for LDAPSDK)

# check for --with-ldapsdk
AC_MSG_CHECKING(for --with-ldapsdk)
AC_ARG_WITH(ldapsdk, [  --with-ldapsdk=PATH     Mozilla LDAP SDK directory],
[
  if test -e "$withval"/include/ldap.h -a -d "$withval"/lib
  then
    AC_MSG_RESULT([using $withval])
    LDAPSDKDIR=$withval
    ldapsdk_inc="-I$LDAPSDKDIR/include"
    ldapsdk_lib="-L$LDAPSDKDIR/lib"
    ldapsdk_libdir="$LDAPSDKDIR/lib"
    ldapsdk_bindir="$LDAPSDKDIR/bin"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-ldapsdk-inc
AC_MSG_CHECKING(for --with-ldapsdk-inc)
AC_ARG_WITH(ldapsdk-inc, [  --with-ldapsdk-inc=PATH     Mozilla LDAP SDK include directory],
[
  if test -e "$withval"/ldap.h
  then
    AC_MSG_RESULT([using $withval])
    ldapsdk_inc="-I$withval"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-ldapsdk-lib
AC_MSG_CHECKING(for --with-ldapsdk-lib)
AC_ARG_WITH(ldapsdk-lib, [  --with-ldapsdk-lib=PATH     Mozilla LDAP SDK library directory],
[
  if test -d "$withval"
  then
    AC_MSG_RESULT([using $withval])
    ldapsdk_lib="-L$withval"
    ldapsdk_libdir="$withval"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# if LDAPSDK is not found yet, try pkg-config

# last resort
if test -z "$ldapsdk_inc" -o -z "$ldapsdk_lib" -o -z "$ldapsdk_libdir" -o -z "$ldapsdk_bindir"; then
  AC_PATH_PROG(PKG_CONFIG, pkg-config)
  AC_MSG_CHECKING(for mozldap with pkg-config)
  if test -n "$PKG_CONFIG"; then
    if $PKG_CONFIG --exists mozldap6; then
	mozldappkg=mozldap6
    elif $PKG_CONFIG --exists mozldap; then
	mozldappkg=mozldap
    else
      AC_MSG_ERROR([LDAPSDK not found, specify with --with-ldapsdk[-inc|-lib].])
    fi
    ldapsdk_inc=`$PKG_CONFIG --cflags-only-I $mozldappkg`
    ldapsdk_lib=`$PKG_CONFIG --libs-only-L $mozldappkg`
    ldapsdk_libdir=`$PKG_CONFIG --libs-only-L $mozldappkg | sed -e s/-L// | sed -e s/\ *$//`
    ldapsdk_bindir=`$PKG_CONFIG --variable=bindir $mozldappkg`
    AC_MSG_RESULT([using system $mozldappkg])
  fi
fi
if test -z "$ldapsdk_inc" -o -z "$ldapsdk_lib"; then
  AC_MSG_ERROR([LDAPSDK not found, specify with --with-ldapsdk[-inc|-lib].])
fi
dnl default path for the ldap c sdk tools (see [210947] for more details)
if test -z "$ldapsdk_bindir" ; then
  if [ -d $libdir/mozldap6 ] ; then
    ldapsdk_bindir=$libdir/mozldap6
  else
    ldapsdk_bindir=$libdir/mozldap
  fi
fi

dnl make sure the ldap sdk version is 6 or greater - we do not support
dnl the old 5.x or prior versions - the ldap server code expects the new
dnl ber types and other code used with version 6
save_cppflags="$CPPFLAGS"
CPPFLAGS="$ldapsdk_inc $nss_inc $nspr_inc"
AC_CHECK_HEADER([ldap.h], [isversion6=1], [isversion6=],
[#include <ldap-standard.h>
#if LDAP_VENDOR_VERSION < 600
#error The LDAP C SDK version is not supported
#endif
])
CPPFLAGS="$save_cppflags"

if test -z "$isversion6" ; then
  AC_MSG_ERROR([The LDAPSDK version in $ldapsdk_inc/ldap-standard.h is not supported])
fi
