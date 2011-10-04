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

# look for included m4 files in the ./m4/ directory
ACLOCAL_AMFLAGS = -I m4

#------------------------
# Compiler Flags
#------------------------
DEBUG_DEFINES = @debug_defs@
OSUTIL_INCLUDES = @jni_inc@ -I$(srcdir)/build/include
# These paths are dependent on the settings of prefix and exec_prefix
# which may be specified at make time.  So we cannot use AC_DEFINE in
# the configure.ac because that would set the values prior to their
# being defined.  Defining them here ensures that they are properly
# expanded before use.  See create_instance.h for more details. The
# quoting ensures that the values are # quoted for the shell command,
# and the value expands to a quoted string value in the header file
# (e.g. - #define LOCALSTATEDIR "/var"; without the quotes, it would
#         be #define LOCALSTATEDIR /var which would be an error).
PATH_DEFINES = -DLOCALSTATEDIR="\"$(localstatedir)\"" \
	-DSYSCONFDIR="\"$(sysconfdir)\"" -DLIBDIR="\"$(libdir)\"" \
	-DBINDIR="\"$(bindir)\"" -DDATADIR="\"$(datadir)\"" \
	-DDOCDIR="\"$(docdir)\"" -DLIBEXECDIR="\"$(libexecdir)\""
AM_CPPFLAGS = $(DEBUG_DEFINES) $(OSUTIL_INCLUDES) $(PATH_DEFINES)
# We need to make sure that libpthread is linked before libc on HP-UX.
if HPUX
AM_LDFLAGS = -lpthread
endif

#------------------------
# Linker Flags
#------------------------
NSS_LINK = @nss_lib@ -lnss3 -lssl3 -lsmime3 -lsoftokn3
NSPR_LINK = @nspr_lib@ -lplc4 -lplds4 -lnspr4

LIBSOCKET=@LIBSOCKET@
LIBNSL=@LIBNSL@
LIBDL=@LIBDL@

#------------------------
# Install Paths
#------------------------
licensedir = $(prefix)@licensedir@
osutil_jardir = $(prefix)@osutil_jardir@


#------------------------
# Build Products
#------------------------
lib_LTLIBRARIES =	libosutil.la

#------------------------
# Installed Files
#------------------------
license_DATA =  $(srcdir)/LICENSE

osutil_jar_SCRIPTS = $(srcdir)/build/jars/osutil.jar


#////////////////////////////////////////////////////////////////
#
#   Dynamic Libraries
#
#////////////////////////////////////////////////////////////////

#------------------------
# libtokendb
#------------------------
libosutil_la_SOURCES =	src/com/netscape/osutil/LibC.c                  \
						src/com/netscape/osutil/ResourceLimit.c         \
						src/com/netscape/osutil/Signal.c                \
						src/com/netscape/osutil/UserID.c                \
						src/com/netscape/osutil/OSUtil.c

libosutil_la_CPPFLAGS = $(AM_CPPFLAGS) @nss_inc@ @nspr_inc@
libosutil_la_LDFLAGS = $(AM_LDFLAGS) -avoid-version
libosutil_la_LIBADD = $(NSS_LINK) $(NSPR_LINK) $(LIBNSL) $(LIBSOCKET) \
	$(LIBDL) $(LIBCSTD) $(LIBCRUN)


#////////////////////////////////////////////////////////////////
#
#   Programs
#
#////////////////////////////////////////////////////////////////



#////////////////////////////////////////////////////////////////
#
#   Wrappers
#
#////////////////////////////////////////////////////////////////

