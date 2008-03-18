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

AC_CHECKING(for pre-built Ant SYMKEY JNI Headers and Jars)

# check for --with-symkey
AC_MSG_CHECKING(for --with-symkey)
AC_ARG_WITH(symkey, [  --with-symkey=PATH        SYMKEY directory],
[
  if test -f "$withval"/include/com_netscape_symkey_SessionKey.h -a -f "$withval"/jars/symkey.jar
  then
    AC_MSG_RESULT([using $withval])
    SYMKEYDIR=$withval
    symkey_inc="-I$SYMKEYDIR/include"
    symkey_jars="$SYMKEYDIR/jars/symkey.jar"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-symkey-inc
AC_MSG_CHECKING(for --with-symkey-inc)
AC_ARG_WITH(symkey-inc, [  --with-symkey-inc=PATH        SYMKEY (Generated JNI Headers) include file directory],
[
  if test -f "$withval"/com_netscape_symkey_SessionKey.h
  then
    AC_MSG_RESULT([using $withval])
    symkey_inc="-I$withval"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-symkey-jars
AC_MSG_CHECKING(for --with-symkey-jars)
AC_ARG_WITH(symkey-jars, [  --with-symkey-jars=PATH        SYMKEY (Jars) jars directory],
[
  if test -f "$withval"/symkey.jar
  then
    AC_MSG_RESULT([using $withval])
    symkey_jars="$withval/symkey.jar"
  else
    echo
    AC_MSG_ERROR([$withval not found])
  fi
],
AC_MSG_RESULT(no))

# check for --with-jni-inc (insure use of appropriate jni.h)
AC_MSG_CHECKING(for --with-jni-inc)
AC_ARG_WITH(jni-inc, [  --with-jni-inc=PATH        SYMKEY jni.h header path],
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

# check for SYMKEY generated headers and jar file in well-known locations
AC_MSG_CHECKING(for symkey JNI headers and jars in well-known locations)
if test -z "$symkey_inc" -o -z "$symkey_jars"
then
  if test -f $srcdir/build/include/com_netscape_symkey_SessionKey.h
  then
    symkey_inc="-I$srcdir/build/include"
  else
    echo
    AC_MSG_ERROR([use Ant to create $srcdir/build/include/com_netscape_symkey_SessionKey.h first])
  fi
  if test -f $srcdir/build/jars/symkey.jar
  then
    symkey_jars="$srcdir/build/jars/symkey.jar"
  else
    echo
    AC_MSG_ERROR([use Ant to create $srcdir/build/jars/symkey.jar first])
  fi
  if test -d $srcdir/build/include -a -f $symkey_jars
  then
    AC_MSG_RESULT([using pre-built Ant symkey JNI generated headers and Jar file])
  else
    AC_MSG_RESULT(no)
  fi
else
  AC_MSG_RESULT(no)
fi

# if symkey Java portions have not been found, print an error and exit
if test -z "$symkey_inc"
then
  echo
  AC_MSG_ERROR([SYMKEY generated JNI headers include file directory not found, specify with --with-symkey.])
fi
if test -z "$symkey_jars"
then
  echo
  AC_MSG_ERROR([SYMKEY jars directory not found, specify with --with-symkey.])
fi
