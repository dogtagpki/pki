dnl BEGIN COPYRIGHT BLOCK
dnl This library is free software; you can redistribute it and/or
dnl modify it under the terms of the GNU Lesser General Public
dnl License as published by the Free Software Foundation; either
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

AC_CHECKING(for JSS)

# check for --with-jss
AC_MSG_CHECKING(for --with-jss)
AC_ARG_WITH(jss, [  --with-jss=PATH        JSS directory],
[
  if test -f "$withval"/jars/jss4.jar -a -d "$withval"/lib
  then
    AC_MSG_RESULT([using $withval])
    JSSDIR=$withval
    jss_jars="$JSSDIR/jars/jss4.jar"
    jss_lib="-L$JSSDIR/lib"
    jss_libdir="$JSSDIR/lib"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-jss-jars
AC_MSG_CHECKING(for --with-jss-jars)
AC_ARG_WITH(jss-jars, [  --with-jss-jars=PATH        JSS jars directory],
[
  if test -f "$withval"/jss4.jar
  then
    AC_MSG_RESULT([using $withval])
    jss_jars="$withval/jss4.jar"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-jss-lib
AC_MSG_CHECKING(for --with-jss-lib)
AC_ARG_WITH(jss-lib, [  --with-jss-lib=PATH         JSS library directory],
[
  if test -d "$withval"
  then
    AC_MSG_RESULT([using $withval])
    jss_lib="-L$withval"
    jss_libdir="$withval"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for JSS jar file and library in well-known locations
AC_MSG_CHECKING(for jss jar file and library in well-known locations)
if test -z "$jss_jars" -o -z "$jss_lib" -o -z "$jss_libdir"
then
  case $host in
    *-*-linux*)
      if test -n "$USE_64"
      then
        if test -f /usr/lib/java/jss4.jar
        then
          jss_jars="/usr/lib/java/jss4.jar"
          if test -f /usr/lib64/jss/libjss4.so
          then
            AC_MSG_RESULT([using system JSS])
            jss_lib="-L/usr/lib64/jss"
            jss_libdir="/usr/lib64/jss"
          elif test -f /usr/lib64/libjss4.so
          then
            AC_MSG_RESULT([using system JSS, original location])
            jss_lib="-L/usr/lib64"
            jss_libdir="/usr/lib64"
          else
            echo
            AC_MSG_ERROR([JSS not found, specify with --with-jss.])
          fi
        elif test -f /usr/lib/java/dirsec/jss4.jar
        then
          jss_jars="/usr/lib/java/dirsec/jss4.jar"
          if test -f /usr/lib64/dirsec/libjss4.so
          then
            AC_MSG_RESULT([using system dirsec JSS])
            jss_lib="-L/usr/lib64/dirsec"
            jss_libdir="/usr/lib64/dirsec"
          else
            echo
            AC_MSG_ERROR([JSS not found, specify with --with-jss.])
          fi
        else
          echo
          AC_MSG_ERROR([JSS not found, specify with --with-jss.])
        fi
      else
        if test -f /usr/lib/java/jss4.jar
        then
          jss_jars="/usr/lib/java/jss4.jar"
          if test -f /usr/lib/jss/libjss4.so
          then
            AC_MSG_RESULT([using system JSS])
            jss_lib="-L/usr/lib/jss"
            jss_libdir="/usr/lib/jss"
          elif test -f /usr/lib/libjss4.so
          then
            AC_MSG_RESULT([using system JSS, original location])
            jss_lib="-L/usr/lib"
            jss_libdir="/usr/lib"
          else
            echo
            AC_MSG_ERROR([JSS not found, specify with --with-jss.])
          fi
        elif test -f /usr/lib/java/dirsec/jss4.jar
        then
          jss_jars="/usr/lib/java/dirsec/jss4.jar"
          if test -f /usr/lib/dirsec/libjss4.so
          then
            AC_MSG_RESULT([using system dirsec JSS])
            jss_lib="-L/usr/lib/dirsec"
            jss_libdir="/usr/lib/dirsec"
          else
            echo
            AC_MSG_ERROR([JSS not found, specify with --with-jss.])
          fi
        else
          echo
          AC_MSG_ERROR([JSS not found, specify with --with-jss.])
        fi
      fi
      ;;
    sparc-sun-solaris*)
      if test -n "$USE_64"
      then
        if test -f /usr/lib/sparcv9/java/jss4.jar
        then
          jss_jars="/usr/lib/sparcv9/java/jss4.jar"
          if test -f /usr/lib/sparcv9/libjss4.so
          then
            AC_MSG_RESULT([using system JSS])
            jss_lib="-L/usr/lib/sparcv9"
            jss_libdir="/usr/lib/sparcv9"
          else
            echo
            AC_MSG_ERROR([JSS not found, specify with --with-jss.])
          fi
        elif test -f /usr/lib/sparcv9/java/dirsec/jss4.jar
        then
          jss_jars="/usr/lib/sparcv9/java/dirsec/jss4.jar"
          if test -f /usr/lib/sparcv9/dirsec/libjss4.so
          then
            AC_MSG_RESULT([using system dirsec JSS])
            jss_lib="-L/usr/lib/sparcv9/dirsec"
            jss_libdir="/usr/lib/sparcv9/dirsec"
          else
            echo
            AC_MSG_ERROR([JSS not found, specify with --with-jss.])
          fi
        else
          echo
          AC_MSG_ERROR([JSS not found, specify with --with-jss.])
        fi
      else
        if test -f /usr/lib/java/jss4.jar
        then
          jss_jars="/usr/lib/java/jss4.jar"
          if test -f /usr/lib/libjss4.so
          then
            AC_MSG_RESULT([using system JSS])
            jss_lib="-L/usr/lib"
            jss_libdir="/usr/lib"
          else
            echo
            AC_MSG_ERROR([JSS not found, specify with --with-jss.])
          fi
        elif test -f /usr/lib/java/dirsec/jss4.jar
        then
          jss_jars="/usr/lib/java/dirsec/jss4.jar"
          if test -f /usr/lib/dirsec/libjss4.so
          then
            AC_MSG_RESULT([using system dirsec JSS])
            jss_lib="-L/usr/lib/dirsec"
            jss_libdir="/usr/lib/dirsec"
          else
            echo
            AC_MSG_ERROR([JSS not found, specify with --with-jss.])
          fi
        else
          echo
          AC_MSG_ERROR([JSS not found, specify with --with-jss.])
        fi
      fi
      ;;
    *)
      AC_MSG_ERROR([unconfigured platform $host])
      ;;
  esac
else
  AC_MSG_RESULT(no)
fi

# if JSS has not been found, print an error and exit
if test -z "$jss_jars"
then
  echo
  AC_MSG_ERROR([JSS jars directory not found, specify with --with-jss.])
fi
if test -z "$jss_lib" -o -z "$jss_libdir"
then
  echo
  AC_MSG_ERROR([JSS library directory not found, specify with --with-jss.])
fi
