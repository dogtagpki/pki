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

AC_CHECKING(for Apache)

# check for --with-apache
AC_MSG_CHECKING(for --with-apache)
AC_ARG_WITH(apache, [  --with-apache=PATH        Apache directory],
[
  if test -e "$withval"/include/httpd/httpd.h -a -d "$withval"/lib -a -d "$withval"/sbin
  then
    AC_MSG_RESULT([using $withval])
    APACHEDIR=$withval
    apache_inc="-I$APACHEDIR/include -I$APACHEDIR/include/httpd"
    case $host in
      *-*-linux*)
        if test -n "$USE_64"
        then
          apache_lib="-L$APACHEDIR/lib64"
          apache_libdir="$APACHEDIR/lib64"
          db_lib="-L$APACHEDIR/lib64"
          db_libdir="$APACHEDIR/lib64"
        else
          apache_lib="-L$APACHEDIR/lib"
          apache_libdir="$APACHEDIR/lib"
          db_lib="-L$APACHEDIR/lib"
          db_libdir="$APACHEDIR/lib"
        fi
        apache_bindir="$APACHEDIR/sbin"
        ;;
      sparc-sun-solaris*)
        if test -n "$USE_64"
        then
          apache_lib="-L$APACHEDIR/lib/sparcv9"
          apache_libdir="$APACHEDIR/lib/sparcv9"
          db_lib="-L$APACHEDIR/lib/sparcv9"
          db_libdir="$APACHEDIR/lib/sparcv9"
          apache_bindir="$APACHEDIR/sbin/sparcv9"
        else
          apache_lib="-L$APACHEDIR/lib"
          apache_libdir="$APACHEDIR/lib"
          db_lib="-L$APACHEDIR/lib"
          db_libdir="$APACHEDIR/lib"
          apache_bindir="$APACHEDIR/sbin"
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

# check for --with-apache-inc
AC_MSG_CHECKING(for --with-apache-inc)
AC_ARG_WITH(apache-inc, [  --with-apache-inc=PATH        Apache include file directory],
[
  if test -e "$withval"/httpd.h
  then
    AC_MSG_RESULT([using $withval])
    apache_inc="-I$withval/.. -I$withval"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-apache-lib
AC_MSG_CHECKING(for --with-apache-lib)
AC_ARG_WITH(apache-lib, [  --with-apache-lib=PATH        Apache library directory],
[
  if test -d "$withval"
  then
    AC_MSG_RESULT([using $withval])
    apache_lib="-L$withval"
    apache_libdir="$withval"
    db_lib="-L$withval"
    db_libdir="$withval"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-apache-bin
AC_MSG_CHECKING(for --with-apache-bin)
AC_ARG_WITH(apache-bin, [  --with-apache-bin=PATH        Apache executables directory],
[
  if test -d "$withval"
  then
    AC_MSG_RESULT([using $withval])
    apache_bindir="$withval"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for Apache in well-known locations
# e. g. - on certain platforms, check for the presence
#         of a "Fortitude"-enabled web-server first
AC_MSG_CHECKING(for Apache in well-known locations)
case $host in
  *-*-linux*)
    if test -f /usr/include/httpd/httpd.h
    then
      apache_inc="-I/usr/include -I/usr/include/httpd"
    else
      AC_MSG_ERROR([/usr/include/httpd/httpd.h not found])
    fi
    if test -n "$USE_64"
    then
      if test -e /usr/lib64/libaprutil-0.so
      then
        apache_lib="-L/usr/lib64"
        apache_libdir="/usr/lib64"
        db_lib="-L/usr/lib64"
        db_libdir="/usr/lib64"
        apr_libutil_version="aprutil-0"
      elif test -e /usr/lib64/libaprutil-1.so
      then
        apache_lib="-L/usr/lib64"
        apache_libdir="/usr/lib64"
        db_lib="-L/usr/lib64"
        db_libdir="/usr/lib64"
        apr_libutil_version="aprutil-1"
      else
        AC_MSG_ERROR([libaprutil not found])
      fi
    else
      if test -e /usr/lib/libaprutil-0.so
      then
        apache_lib="-L/usr/lib"
        apache_libdir="/usr/lib"
        db_lib="-L/usr/lib"
        db_libdir="/usr/lib"
        apr_libutil_version="aprutil-0"
      elif test -e /usr/lib/libaprutil-1.so
      then
        apache_lib="-L/usr/lib"
        apache_libdir="/usr/lib"
        db_lib="-L/usr/lib"
        db_libdir="/usr/lib"
        apr_libutil_version="aprutil-1"
      else
        AC_MSG_ERROR([libaprutil not found])
      fi
    fi
    if test -x /usr/sbin/httpd
    then
      apache_bindir="/usr/sbin"
    else
      AC_MSG_ERROR([/usr/sbin/httpd not found])
    fi
    AC_MSG_RESULT([using system Apache in /usr])
    ;;
  sparc-sun-solaris*)
    if test -d /opt/fortitude
    then
      if test -f /opt/fortitude/include/httpd/httpd.h
      then
        apache_inc="-I/opt/fortitude/include -I/opt/fortitude/include/httpd"
      else
        AC_MSG_ERROR([/opt/fortitude/include/httpd/httpd.h not found])
      fi
      if test -n "$USE_64"
      then
        #############################################################
        ###  NOTE:  The 64-bit Fortitude "sparcv9" libraries and  ###
        ###         programs are now under "/opt/fortitude/lib"   ###
        ###         and "/opt/fortitude/sbin" rather than         ###
        ###         "/opt/fortitude/lib/sparcv9" and              ###
        ###         "/opt/fortitude/sbin/sparcv9"!!!              ###
        ###                                                       ###
        ###         The exception to this are the -ldb and the    ###
        ###         -ldb_cxx libraries which are still located    ###
        ###         under the "/opt/fortitude/lib/sparcv9"        ###
        ###         directory.                                    ###
        ###                                                       ###
        ###         To help guard against any future movement     ###
        ###         of any of these libraries and/or programs,    ###
        ###         this m4 file will first check under the       ###
        ###         "sparcv9" directory, and then the directory   ###
        ###         immediately above the "sparcv9" directory.    ###
        #############################################################
        if test -e /opt/fortitude/lib/sparcv9/libaprutil-0.so
        then
          apache_lib="-L/opt/fortitude/lib/sparcv9"
          apache_libdir="/opt/fortitude/lib/sparcv9"
          apr_libutil_version="aprutil-0"
        else
          if test -e /opt/fortitude/lib/libaprutil-0.so
          then
            apache_lib="-L/opt/fortitude/lib"
            apache_libdir="/opt/fortitude/lib"
            apr_libutil_version="aprutil-0"
          else
            AC_MSG_ERROR([Fortitude-enabled libaprutil-0.so not found])
          fi
        fi
        if test -e /opt/fortitude/lib/sparcv9/libdb-4.2.so
        then
          db_lib="-L/opt/fortitude/lib/sparcv9"
          db_libdir="/opt/fortitude/lib/sparcv9"
        else
          if test -e /opt/fortitude/lib/libdb-4.2.so
          then
            db_lib="-L/opt/fortitude/lib"
            db_libdir="/opt/fortitude/lib"
          else
            AC_MSG_ERROR([Fortitude-enabled libdb-4.2.so not found])
          fi
        fi
        if test -x /opt/fortitude/sbin/sparcv9/httpd
        then
          apache_bindir="/opt/fortitude/sbin/sparcv9"
        else
          if test -x /opt/fortitude/sbin/httpd
          then
            apache_bindir="/opt/fortitude/sbin"
          else
            AC_MSG_ERROR([Fortitude-enabled httpd not found])
          fi
        fi
      else
        if test -e /opt/fortitude/lib/libaprutil-0.so
        then
          apache_lib="-L/opt/fortitude/lib"
          apache_libdir="/opt/fortitude/lib"
          apr_libutil_version="aprutil-0"
        else
          AC_MSG_ERROR([/opt/fortitude/lib/libaprutil-0.so not found])
        fi
        if test -e /opt/fortitude/lib/libdb-4.2.so
        then
          db_lib="-L/opt/fortitude/lib"
          db_libdir="/opt/fortitude/lib"
        else
          AC_MSG_ERROR([/opt/fortitude/lib/libdb-4.2.so not found])
        fi
        if test -x /opt/fortitude/sbin/httpd
        then
          apache_bindir="/opt/fortitude/sbin"
        else
          AC_MSG_ERROR([/opt/fortitude/sbin/httpd not found])
        fi
      fi
      AC_MSG_RESULT([using Fortitude-enabled Apache in /opt/fortitude])
    else
      if test -f /usr/local/include/httpd/httpd.h
      then
        apache_inc="-I/usr/local/include -I/usr/local/include/httpd"
      else
        AC_MSG_ERROR([/usr/local/include/httpd/httpd.h not found])
      fi
      if test -n "$USE_64"
      then
        if test -e /usr/local/lib/sparcv9/libaprutil-0.so
        then
          apache_lib="-L/usr/local/lib/sparcv9"
          apache_libdir="/usr/local/lib/sparcv9"
          db_lib="-L/usr/local/lib/sparcv9"
          db_libdir="/usr/local/lib/sparcv9"
          apr_libutil_version="aprutil-0"
        else
          AC_MSG_ERROR([/usr/local/lib/sparcv9/libaprutil-0.so not found])
        fi
        if test -x /usr/local/sbin/sparcv9/httpd
        then
          apache_bindir="/usr/local/sbin/sparcv9"
        else
          AC_MSG_ERROR([/usr/local/sbin/sparcv9/httpd not found])
        fi
      else
        if test -e /usr/local/lib/libaprutil-0.so
        then
          apache_lib="-L/usr/local/lib"
          apache_libdir="/usr/local/lib"
          db_lib="-L/usr/local/lib"
          db_libdir="/usr/local/lib"
          apr_libutil_version="aprutil-0"
        else
          AC_MSG_ERROR([/usr/local/lib/libaprutil-0.so not found])
        fi
        if test -x /usr/local/sbin/httpd
        then
          apache_bindir="/usr/local/sbin"
        else
          AC_MSG_ERROR([/usr/local/sbin/httpd not found])
        fi
      fi
    fi
    AC_MSG_RESULT([using system Apache in /usr/local])
    ;;
  *)
    AC_MSG_ERROR([unconfigured platform $host])
    ;;
esac

# if Apache has not been found, print an error and exit
if test -z "$apache_inc"
then
  AC_MSG_ERROR([Apache include file directory not found, specify with --with-apache.])
fi
if test -z "$apache_lib" -o -z "$apache_libdir" -o -z "$db_lib" -o -z "db_libdir" -o -z "$apr_libutil_version"
then
  AC_MSG_ERROR([Apache library directory not found, specify with --with-apache.])
fi
if test -z "$apache_bindir"
then
  AC_MSG_ERROR([Apache executables directory not found, specify with --with-apache.])
fi
