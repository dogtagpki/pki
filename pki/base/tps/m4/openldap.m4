# BEGIN COPYRIGHT BLOCK
# Copyright (C) 2009 Red Hat, Inc.
# All rights reserved.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# END COPYRIGHT BLOCK

AC_CHECKING(for OpenLDAP)

# check for --with-openldap
AC_MSG_CHECKING(for --with-openldap)
AC_ARG_WITH(openldap, AS_HELP_STRING([--with-openldap@<:@=PATH@:>@],[Use OpenLDAP - optional PATH is path to OpenLDAP SDK]),
[
  if test "$withval" = yes
  then
    AC_MSG_RESULT([using system OpenLDAP])
  elif test "$withval" = no
  then
    AC_MSG_RESULT(no)
  elif test -e "$withval"/include/ldap.h -a -d "$withval"/lib
  then
    AC_MSG_RESULT([using $withval])
    OPENLDAPDIR=$withval
    openldap_incdir="$OPENLDAPDIR/include"
    openldap_inc="-I$openldap_incdir"
    openldap_lib="-L$OPENLDAPDIR/lib"
    openldap_libdir="$OPENLDAPDIR/lib"
    openldap_bindir="$OPENLDAPDIR/bin"
    with_openldap=yes
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-openldap-inc
AC_MSG_CHECKING(for --with-openldap-inc)
AC_ARG_WITH(openldap-inc, AS_HELP_STRING([--with-openldap-inc=PATH],[OpenLDAP SDK include directory]),
[
  if test -e "$withval"/ldap.h
  then
    AC_MSG_RESULT([using $withval])
    openldap_incdir="$withval"
    openldap_inc="-I$withval"
    with_openldap=yes
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-openldap-lib
AC_MSG_CHECKING(for --with-openldap-lib)
AC_ARG_WITH(openldap-lib, AS_HELP_STRING([--with-openldap-lib=PATH],[OpenLDAP SDK library directory]),
[
  if test -d "$withval"
  then
    AC_MSG_RESULT([using $withval])
    openldap_lib="-L$withval"
    openldap_libdir="$withval"
    with_openldap=yes
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-openldap-bin
AC_MSG_CHECKING(for --with-openldap-bin)
AC_ARG_WITH(openldap-bin, AS_HELP_STRING([--with-openldap-bin=PATH],[OpenLDAP SDK binary directory]),
[
  if test -d "$withval"
  then
    AC_MSG_RESULT([using $withval])
    openldap_bindir="$withval"
    with_openldap=yes
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# if OPENLDAP is not found yet, try pkg-config

if test "$with_openldap" = yes ; then # user wants to use openldap, but didn't specify paths
  if test -z "$openldap_inc" -o -z "$openldap_lib" -o -z "$openldap_libdir" -o -z "$openldap_bindir"; then
    AC_PATH_PROG(PKG_CONFIG, pkg-config)
    AC_MSG_CHECKING(for OpenLDAP with pkg-config)
    if test -n "$PKG_CONFIG" && $PKG_CONFIG --exists openldap; then
      openldap_inc=`$PKG_CONFIG --cflags-only-I openldap`
      openldap_lib=`$PKG_CONFIG --libs-only-L openldap`
      openldap_libdir=`$PKG_CONFIG --libs-only-L openldap | sed -e s/-L// | sed -e s/\ .*$//`
      openldap_bindir=`$PKG_CONFIG --variable=bindir openldap`
      openldap_incdir=`$PKG_CONFIG --variable=includedir openldap`
      AC_MSG_RESULT([using system OpenLDAP from pkg-config])
    else
      openldap_incdir="/usr/include"
      openldap_inc="-I$openldap_incdir"
      AC_MSG_RESULT([no OpenLDAP pkg-config files])
    fi
  fi
fi

dnl lets see if we can find the headers and libs

if test "$with_openldap" = yes ; then
  save_cppflags="$CPPFLAGS"
  CPPFLAGS="$openldap_inc $nss_inc $nspr_inc"
  AC_CHECK_HEADER([ldap_features.h], [],
    [AC_MSG_ERROR([specified with-openldap but ldap_features.h not found])])
  dnl figure out which version we're using from the header file
  ol_ver_maj=`grep LDAP_VENDOR_VERSION_MAJOR $openldap_incdir/ldap_features.h | awk '{print $3}'`
  ol_ver_min=`grep LDAP_VENDOR_VERSION_MINOR $openldap_incdir/ldap_features.h | awk '{print $3}'`
  ol_ver_pat=`grep LDAP_VENDOR_VERSION_PATCH $openldap_incdir/ldap_features.h | awk '{print $3}'`
  dnl full libname is libname-$maj.$min
  ol_libver="-${ol_ver_maj}.${ol_ver_min}"
  dnl look for ldap lib
  save_ldflags="$LDFLAGS"
  LDFLAGS="$openldap_lib $LDFLAGS"
  AC_CHECK_LIB([ldap$ol_libver], [ldap_initialize], [have_ldap_lib=1])
  if test -z "$have_ldap_lib" ; then
    AC_CHECK_LIB([ldap], [ldap_initialize], [unset ol_libver],
      [AC_MSG_ERROR([specified with-openldap but libldap not found])])
  fi
  dnl look for ldap_url_parse_ext
  AC_CHECK_LIB([ldap$ol_libver], [ldap_url_parse_ext],
    [AC_DEFINE([HAVE_LDAP_URL_PARSE_EXT], [1], [have the function ldap_url_parse_ext])])
  LDFLAGS="$save_ldflags"
  CPPFLAGS="$save_cppflags"

  AC_DEFINE([USE_OPENLDAP], [1], [If defined, using OpenLDAP for LDAP SDK])
  # where to find ldapsearch, et. al.
  ldaptool_bindir=$openldap_bindir
  # default options to pass to the tools
  # use -x because all of our scripts use simple bind
  ldaptool_opts=-x
  # get plain output from ldapsearch - no version, no comments
  plainldif_opts=-LLL
fi

