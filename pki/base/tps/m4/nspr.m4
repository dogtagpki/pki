dnl BEGIN COPYRIGHT BLOCK
dnl This library is free software; you can redistribute it and/or
dnl modify it under the terms of the GNU Lesser General Public
dnl License as published by the Free Software Foundation;
dnl version 2.1 of the License.
dnl 
dnl This library is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
dnl Lesser General Public License for more details.
dnl 
dnl You should have received a copy of the GNU Lesser General Public
dnl License along with this library; if not, write to the Free Software
dnl Foundation, Inc., 51 Franklin Street, Fifth Floor,
dnl Boston, MA  02110-1301  USA 
dnl 
dnl Copyright (C) 2007 Red Hat, Inc.
dnl All rights reserved.
dnl END COPYRIGHT BLOCK

AC_CHECKING(for NSPR)

# check for --with-nspr
AC_MSG_CHECKING(for --with-nspr)
AC_ARG_WITH(nspr, [  --with-nspr=PATH        Netscape Portable Runtime (NSPR) directory],
[
  if test -e "$withval"/include/nspr.h -a -d "$withval"/lib
  then
    AC_MSG_RESULT([using $withval])
    NSPRDIR=$withval
    nspr_inc="-I$NSPRDIR/include"
    nspr_lib="-L$NSPRDIR/lib"
    nspr_libdir="$NSPRDIR/lib"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-nspr-inc
AC_MSG_CHECKING(for --with-nspr-inc)
AC_ARG_WITH(nspr-inc, [  --with-nspr-inc=PATH        Netscape Portable Runtime (NSPR) include file directory],
[
  if test -e "$withval"/nspr.h
  then
    AC_MSG_RESULT([using $withval])
    nspr_inc="-I$withval"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-nspr-lib
AC_MSG_CHECKING(for --with-nspr-lib)
AC_ARG_WITH(nspr-lib, [  --with-nspr-lib=PATH        Netscape Portable Runtime (NSPR) library directory],
[
  if test -d "$withval"
  then
    AC_MSG_RESULT([using $withval])
    nspr_lib="-L$withval"
    nspr_libdir="$withval"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# if NSPR is not found yet, try pkg-config

# last resort
if test -z "$nspr_inc" -o -z "$nspr_lib" -o -z "$nspr_libdir"; then
  AC_PATH_PROG(PKG_CONFIG, pkg-config)
  AC_MSG_CHECKING(for nspr with pkg-config)
  if test -n "$PKG_CONFIG"; then
    if $PKG_CONFIG --exists nspr; then
      nspr_inc=`$PKG_CONFIG --cflags-only-I nspr`
      nspr_lib=`$PKG_CONFIG --libs-only-L nspr`
      nspr_libdir=`$PKG_CONFIG --libs-only-L nspr | sed -e s/-L// | sed -e s/\ *$//`
      AC_MSG_RESULT([using system NSPR])
    elif $PKG_CONFIG --exists dirsec-nspr; then
      nspr_inc=`$PKG_CONFIG --cflags-only-I dirsec-nspr`
      nspr_lib=`$PKG_CONFIG --libs-only-L dirsec-nspr`
      nspr_libdir=`$PKG_CONFIG --libs-only-L dirsec-nspr | sed -e s/-L// | sed -e s/\ *$//`
      AC_MSG_RESULT([using system dirsec NSPR])
    else
      AC_MSG_ERROR([NSPR not found, specify with --with-nspr.])
    fi
  fi
fi
