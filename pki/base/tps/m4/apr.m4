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

AC_CHECKING(for Apr)

# check for --with-apr
AC_MSG_CHECKING(for --with-apr)
AC_ARG_WITH(apr, [  --with-apr=PATH        Apr directory],
[
  if test -e "$withval"/include/apr-0/apr.h -a -d "$withval"/lib -a -d "$withval"/bin
  then
    AC_MSG_RESULT([using $withval])
    APRDIR=$withval
    apr_inc="-DAPRDIR -I$APRDIR/include -I$APRDIR/include/apr-0"
    apr_lib_version="apr-0"
    case $host in
      *-*-linux*)
        if test -n "$USE_64"
        then
          apr_lib="-L$APRDIR/lib64"
          apr_libdir="$APRDIR/lib64"
        else
          apr_lib="-L$APRDIR/lib"
          apr_libdir="$APRDIR/lib"
        fi
        apr_bindir="$APRDIR/bin"
        ;;
      sparc-sun-solaris*)
        if test -n "$USE_64"
        then
          apr_lib="-L$APRDIR/lib/sparcv9"
          apr_libdir="$APRDIR/lib/sparcv9"
          apr_bindir="$APRDIR/bin/sparcv9"
        else
          apr_lib="-L$APRDIR/lib"
          apr_libdir="$APRDIR/lib"
          apr_bindir="$APRDIR/bin"
        fi
        ;;
      *)
        AC_MSG_ERROR([unconfigured platform $host])
        ;;
    esac
  elif test -e "$withval"/include/apr-1/apr.h -a -d "$withval"/lib -a -d "$withval"/bin
  then
    AC_MSG_RESULT([using $withval])
    APRDIR=$withval
    apr_inc="-DAPRDIR -I$APRDIR/include -I$APRDIR/include/apr-1"
    apr_lib_version="apr-1"
    case $host in
      *-*-linux*)
        if test -n "$USE_64"
        then
          apr_lib="-L$APRDIR/lib64"
          apr_libdir="$APRDIR/lib64"
        else
          apr_lib="-L$APRDIR/lib"
          apr_libdir="$APRDIR/lib"
        fi
        apr_bindir="$APRDIR/bin"
        ;;
      sparc-sun-solaris*)
        if test -n "$USE_64"
        then
          apr_lib="-L$APRDIR/lib/sparcv9"
          apr_libdir="$APRDIR/lib/sparcv9"
          apr_bindir="$APRDIR/bin/sparcv9"
        else
          apr_lib="-L$APRDIR/lib"
          apr_libdir="$APRDIR/lib"
          apr_bindir="$APRDIR/bin"
        fi
        ;;
      *)
        AC_MSG_ERROR([unconfigured platform $host])
        ;;
    esac
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-apr-inc
AC_MSG_CHECKING(for --with-apr-inc)
AC_ARG_WITH(apr-inc, [  --with-apr-inc=PATH        Apr include file directory],
[
  if test -e "$withval"/apr.h
  then
    AC_MSG_RESULT([using $withval])
    APRDIR=$withval/..
    apr_inc="-DAPRDIR -I$withval/.. -I$withval"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-apr-lib
AC_MSG_CHECKING(for --with-apr-lib)
AC_ARG_WITH(apr-lib, [  --with-apr-lib=PATH        Apr library directory],
[
  if test -d "$withval"
  then
    AC_MSG_RESULT([using $withval])
    apr_lib="-L$withval"
    apr_libdir="$withval"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
  if test -e "$withval/libapr-0.so"
  then
    apr_lib_version="apr-0"
  elif test -e "$withval/libapr-1.so"
  then
    apr_lib_version="apr-1"
  else
    AC_MSG_ERROR([libapr in $withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-apr-bin
AC_MSG_CHECKING(for --with-apr-bin)
AC_ARG_WITH(apr-bin, [  --with-apr-bin=PATH        Apr executables directory],
[
  if test -d "$withval"
  then
    AC_MSG_RESULT([using $withval])
    apr_bindir="$withval"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for Apr in well-known locations
# e. g. - on certain platforms, check for the presence
#         of a "Fortitude"-enabled web-server first
AC_MSG_CHECKING(for APR in well-known locations)
case $host in
  *-*-linux*)
    if test -f /usr/include/apr-0/apr.h
    then
      apr_inc="-DAPRDIR -I/usr/include -I/usr/include/apr-0"
    elif test -f /usr/include/apr-1/apr.h
    then
      apr_inc="-DAPRDIR -I/usr/include -I/usr/include/apr-1"
    else
      AC_MSG_ERROR([apr.h not found])
    fi
    if test -n "$USE_64"
    then
      if test -e /usr/lib64/libapr-0.so
      then
        apr_lib="-L/usr/lib64"
        apr_libdir="/usr/lib64"
        apr_lib_version="apr-0"
      elif test -e /usr/lib64/libapr-1.so
      then
        apr_lib="-L/usr/lib64"
        apr_libdir="/usr/lib64"
        apr_lib_version="apr-1"
      else
        AC_MSG_ERROR([libapr not found])
      fi
    else
      if test -e /usr/lib/libapr-0.so
      then
        apr_lib="-L/usr/lib"
        apr_libdir="/usr/lib"
        apr_lib_version="apr-0"
      elif test -e /usr/lib/libapr-1.so
      then
        apr_lib="-L/usr/lib"
        apr_libdir="/usr/lib"
        apr_lib_version="apr-1"
      else
        AC_MSG_ERROR([libapr not found])
      fi
    fi
    if test -x /usr/bin/apr-config
    then
      apr_bindir="/usr/bin"
    elif test -x /usr/bin/apr-1-config
    then
      apr_bindir="/usr/bin"
    else
      AC_MSG_ERROR([apr-config or apr-1-config not found])
    fi
    AC_MSG_RESULT([using system Apr in /usr])
    ;;
  sparc-sun-solaris*)
    if test -d /opt/fortitude
    then
      if test -f /opt/fortitude/include/apr-0/apr.h
      then
        apr_inc="-DAPRDIR -I/opt/fortitude/include -I/opt/fortitude/include/apr-0"
      else
        AC_MSG_ERROR([/opt/fortitude/include/apr-0/apr.h not found])
      fi
      if test -n "$USE_64"
      then
        #############################################################
        ###  NOTE:  The 64-bit Fortitude "sparcv9" libraries and  ###
        ###         programs are now under "/opt/fortitude/lib"   ###
        ###         and "/opt/fortitude/bin" rather than          ###
        ###         "/opt/fortitude/lib/sparcv9" and              ###
        ###         "/opt/fortitude/bin/sparcv9"!!!               ###
        ###                                                       ###
        ###         To help guard against any future movement     ###
        ###         of any of these libraries and/or programs,    ###
        ###         this m4 file will first check under the       ###
        ###         "sparcv9" directory, and then the directory   ###
        ###         immediately above the "sparcv9" directory.    ###
        #############################################################
        if test -e /opt/fortitude/lib/sparcv9/libapr-0.so
        then
          apr_lib="-L/opt/fortitude/lib/sparcv9"
          apr_libdir="/opt/fortitude/lib/sparcv9"
          apr_lib_version="apr-0"
        else
          if test -e /opt/fortitude/lib/libapr-0.so
          then
            apr_lib="-L/opt/fortitude/lib"
            apr_libdir="/opt/fortitude/lib"
            apr_lib_version="apr-0"
          else
            AC_MSG_ERROR([Fortitude-enabled libapr-0.so not found])
          fi
        fi
        if test -x /opt/fortitude/bin/sparcv9/apr-config
        then
          apr_bindir="/opt/fortitude/bin/sparcv9"
        else
          if test -x /opt/fortitude/bin/apr-config
          then
            apr_bindir="/opt/fortitude/bin"
          else
            AC_MSG_ERROR([Fortitude-enabled apr-config not found])
          fi
        fi
      else
        if test -e /opt/fortitude/lib/libapr-0.so
        then
          apr_lib="-L/opt/fortitude/lib"
          apr_libdir="/opt/fortitude/lib"
          apr_lib_version="apr-0"
        else
          AC_MSG_ERROR([/opt/fortitude/lib/libapr-0.so not found])
        fi
        if test -x /opt/fortitude/bin/apr-config
        then
          apr_bindir="/opt/fortitude/bin"
        else
          AC_MSG_ERROR([/opt/fortitude/bin/apr-config not found])
        fi
      fi
      AC_MSG_RESULT([using Fortitude-enabled Apr in /opt/fortitude])
    else
      if test -f /usr/local/include/apr-0/apr.h
      then
        apr_inc="-DAPRDIR -I/usr/local/include -I/usr/local/include/apr-0"
      else
        AC_MSG_ERROR([/usr/local/include/apr-0/apr.h not found])
      fi
      if test -n "$USE_64"
      then
        if test -e /usr/local/lib/sparcv9/libapr-0.so
        then
          apr_lib="-L/usr/local/lib/sparcv9"
          apr_libdir="/usr/local/lib/sparcv9"
          apr_lib_version="apr-0"
        else
          AC_MSG_ERROR([/usr/local/lib/sparcv9/libapr-0.so not found])
        fi
        if test -x /usr/local/bin/sparcv9/apr-config
        then
          apr_bindir="/usr/local/bin/sparcv9"
        else
          AC_MSG_ERROR([/usr/local/bin/sparcv9/apr-config not found])
        fi
      else
        if test -e /usr/local/lib/libapr-0.so
        then
          apr_lib="-L/usr/local/lib"
          apr_libdir="/usr/local/lib"
          apr_lib_version="apr-0"
        else
          AC_MSG_ERROR([/usr/local/lib/libapr-0.so not found])
        fi
        if test -x /usr/local/bin/apr-config
        then
          apr_bindir="/usr/local/bin"
        else
          AC_MSG_ERROR([/usr/local/bin/apr-config not found])
        fi
      fi
    fi
    AC_MSG_RESULT([using system Apr in /usr/local])
    ;;
  *)
    AC_MSG_ERROR([unconfigured platform $host])
    ;;
esac

# if Apr has not been found, print an error and exit
if test -z "$apr_inc"
then
  AC_MSG_ERROR([Apr include file directory not found, specify with --with-apr.])
fi
if test -z "$apr_lib" -o -z "$apr_libdir"
then
  AC_MSG_ERROR([Apr library directory not found, specify with --with-apr.])
fi
if test -z "$apr_bindir"
then
  AC_MSG_ERROR([Apr executables directory not found, specify with --with-apr.])
fi
if test -z "$apr_lib_version"
then
  AC_MSG_ERROR([Apr library version not found, specify with --with-apr.])
fi

