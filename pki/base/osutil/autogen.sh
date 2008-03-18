#!/bin/sh
# --- BEGIN COPYRIGHT BLOCK ---
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor,
# Boston, MA  02110-1301  USA 
# 
# Copyright (C) 2007 Red Hat, Inc.
# All rights reserved.
# --- END COPYRIGHT BLOCK ---

# Check autoconf version
AC_VERSION=`autoconf --version | grep '^autoconf' | sed 's/.*) *//'`
case $AC_VERSION in
'' | 0.* | 1.* | 2.[0-4]* | 2.[0-9] | 2.5[0-8]* )
    echo "You must have autoconf version 2.59 or later installed (found version $AC_VERSION)."
    exit 1
    ;;
* )
    echo "Found autoconf version $AC_VERSION"
    ;;
esac

# Check automake version
AM_VERSION=`automake --version | grep '^automake' | sed 's/.*) *//'`
case $AM_VERSION in
'' | 0.* | 1.[0-8].* | 1.9.[0-5]* )
    echo "You must have automake version 1.9.6 or later installed (found version $AM_VERSION)."
    exit 1
    ;;
* )
    echo "Found automake version $AM_VERSION"
    ;;
esac

# Check libtool version
LT_VERSION=`libtool --version | grep ' libtool)' | sed 's/.*) \([0-9][0-9.]*\)[^ ]* .*/\1/'`
case $LT_VERSION in
'' | 0.* | 1.[0-4]* | 1.5.[0-9] | 1.5.[0-1]* | 1.5.2[0-1]* )
    echo "You must have libtool version 1.5.22 or later installed (found version $LT_VERSION)."
    exit 1
    ;;
* )
    echo "Found libtool version $LT_VERSION"
    ;;
esac

# Run autoreconf
echo "Running autoreconf -fvi"
autoreconf -fvi
