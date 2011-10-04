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

# Configure paths for SASL

dnl ========================================================
dnl = sasl is used to support various authentication mechanisms
dnl = such as DIGEST-MD5 and GSSAPI.
dnl ========================================================
dnl ========================================================
dnl = Use the sasl libraries on the system (assuming it exists)
dnl ========================================================
AC_CHECKING(for sasl)

AC_MSG_CHECKING(for --with-sasl)
AC_ARG_WITH(sasl,
    [[  --with-sasl=PATH   Use sasl from supplied path]],
    dnl = Look in the standard system locations
    [
      if test "$withval" = "yes"; then
        AC_MSG_RESULT(yes)

        dnl = Check for sasl.h in the normal locations
        if test -f /usr/include/sasl/sasl.h; then
          sasl_inc="-I/usr/include/sasl"
        elif test -f /usr/include/sasl.h; then
          sasl_inc="-I/usr/include"
        else
          AC_MSG_ERROR(sasl.h not found)
        fi

      dnl = Check the user provided location
      elif test -d "$withval" -a -d "$withval/lib" -a -d "$withval/include" ; then
        AC_MSG_RESULT([using $withval])

        if test -f "$withval/include/sasl/sasl.h"; then
          sasl_inc="-I$withval/include/sasl"
        elif test -f "$withval/include/sasl.h"; then
          sasl_inc="-I$withval/include"
        else
          AC_MSG_ERROR(sasl.h not found)
        fi

        sasl_lib="-L$withval/lib"
        sasl_libdir="$withval/lib"
      else
          AC_MSG_RESULT(yes)
          AC_MSG_ERROR([sasl not found in $withval])
      fi
    ],
    AC_MSG_RESULT(no))

AC_MSG_CHECKING(for --with-sasl-inc)
AC_ARG_WITH(sasl-inc,
    [[  --with-sasl-inc=PATH   SASL include file directory]],
    [
      if test -f "$withval"/sasl.h; then
        AC_MSG_RESULT([using $withval])
        sasl_inc="-I$withval"
      else
        echo
        AC_MSG_ERROR([$withval/sasl.h not found])
      fi
    ],
    AC_MSG_RESULT(no))

AC_MSG_CHECKING(for --with-sasl-lib)
AC_ARG_WITH(sasl-lib,
    [[  --with-sasl-lib=PATH   SASL library directory]],
    [
      if test -d "$withval"; then
        AC_MSG_RESULT([using $withval])
        sasl_lib="-L$withval"
        sasl_libdir="$withval"
      else
        echo
        AC_MSG_ERROR([$withval not found])
      fi
    ],
    AC_MSG_RESULT(no))

if test -z "$sasl_inc"; then
  AC_MSG_CHECKING(for sasl.h)
  dnl - Check for sasl in standard system locations
  if test -f /usr/include/sasl/sasl.h; then
    AC_MSG_RESULT([using /usr/include/sasl/sasl.h])
    sasl_inc="-I/usr/include/sasl"
  elif test -f /usr/include/sasl.h; then
    AC_MSG_RESULT([using /usr/include/sasl.h])
    sasl_inc="-I/usr/include"
  else
    AC_MSG_RESULT(no)
    AC_MSG_ERROR([sasl not found, specify with --with-sasl.])
  fi
fi
