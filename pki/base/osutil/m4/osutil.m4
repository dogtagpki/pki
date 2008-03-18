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

AC_CHECKING(for pre-built Ant OSUTIL JNI Headers and Jars)

# check for --with-osutil
AC_MSG_CHECKING(for --with-osutil)
AC_ARG_WITH(osutil, [  --with-osutil=PATH        OSUTIL directory],
[
  if test -f "$withval"/include/com_netscape_osutil_OSUtil.h -a -f "$withval"/jars/osutil.jar
  then
    AC_MSG_RESULT([using $withval])
    OSUTILDIR=$withval
    osutil_inc="-I$OSUTILDIR/include"
    osutil_jars="$OSUTILDIR/jars/osutil.jar"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-osutil-inc
AC_MSG_CHECKING(for --with-osutil-inc)
AC_ARG_WITH(osutil-inc, [  --with-osutil-inc=PATH        OSUTIL (Generated JNI Headers) include file directory],
[
  if test -f "$withval"/com_netscape_osutil_OSUtil.h
  then
    AC_MSG_RESULT([using $withval])
    osutil_inc="-I$withval"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-osutil-jars
AC_MSG_CHECKING(for --with-osutil-jars)
AC_ARG_WITH(osutil-jars, [  --with-osutil-jars=PATH        OSUTIL (Jars) jars directory],
[
  if test -f "$withval"/osutil.jar
  then
    AC_MSG_RESULT([using $withval])
    osutil_jars="$withval/osutil.jar"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-jni-inc (insure use of appropriate jni.h)
AC_MSG_CHECKING(for --with-jni-inc)
AC_ARG_WITH(jni-inc, [  --with-jni-inc=PATH        OSUTIL jni.h header path],
[
  if test -f "$withval"/jni.h
  then
    AC_MSG_RESULT([using $withval])
    jni_inc="-I$withval"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
[case $host in
  *-*-linux*)
    javac_exe=`/usr/sbin/alternatives --display javac | grep link | cut -c27-`
    jni_path=`dirname $javac_exe`/../include
    jni_inc="-I$jni_path -I$jni_path/linux"
    if test -f "$jni_path"/jni.h
    then
      AC_MSG_RESULT([using $jni_inc])
    else
      echo
      AC_MSG_ERROR([$jni_inc not found])
    fi
    ;;
  sparc-sun-solaris*)
    jni_path="/usr/java/include"
    jni_inc="-I$jni_path -I$jni_path/solaris"
    if test -f "$jni_path"/jni.h
    then
      AC_MSG_RESULT([using $jni_inc])
    else
      echo
      AC_MSG_ERROR([$jni_inc not found])
    fi
    ;;
  *)
    AC_MSG_ERROR([unconfigured platform $host])
    ;;
esac])

# check for OSUTIL generated headers and jar file in well-known locations
AC_MSG_CHECKING(for osutil JNI headers and jars in well-known locations)
if test -z "$osutil_inc" -o -z "$osutil_jars"
then
  if test -f $srcdir/build/include/com_netscape_osutil_OSUtil.h
  then
    osutil_inc="-I$srcdir/build/include"
  else
    echo
    AC_MSG_ERROR([use Ant to create $srcdir/build/include/com_netscape_osutil_OSUtil.h first])
  fi
  if test -f $srcdir/build/jars/osutil.jar
  then
    osutil_jars="$srcdir/build/jars/osutil.jar"
  else
    echo
    AC_MSG_ERROR([use Ant to create $srcdir/build/jars/osutil.jar first])
  fi
  if test -d $srcdir/build/include -a -f $osutil_jars
  then
    AC_MSG_RESULT([using pre-built Ant osutil JNI generated headers and Jar file])
  else
    AC_MSG_RESULT(no)
  fi
else
  AC_MSG_RESULT(no)
fi

# if osutil Java portions have not been found, print an error and exit
if test -z "$osutil_inc"
then
  echo
  AC_MSG_ERROR([OSUTIL generated JNI headers include file directory not found, specify with --with-osutil.])
fi
if test -z "$osutil_jars"
then
  echo
  AC_MSG_ERROR([OSUTIL jars directory not found, specify with --with-osutil.])
fi
