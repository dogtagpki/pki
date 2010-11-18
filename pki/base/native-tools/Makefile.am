# --- BEGIN COPYRIGHT BLOCK ---
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
AM_CPPFLAGS = $(DEBUG_DEFINES) $(PATH_DEFINES)
# We need to make sure that libpthread is linked before libc on HP-UX.
if HPUX
AM_LDFLAGS = -lpthread
endif

#------------------------
# Linker Flags
#------------------------
LDAPSDK_LINK = @ldapsdk_lib@ -lldap -lldap_r -llber
SVRCORE_LINK = @svrcore_lib@ -lsvrcore
SASL_LINK = @sasl_lib@ -lsasl2
NSS_LINK = @nss_lib@ -lnss3 -lssl3 -lsmime3 -lsoftokn3
NSPR_LINK = @nspr_lib@ -lplc4 -lplds4 -lnspr4

LIBSOCKET=@LIBSOCKET@
LIBNSL=@LIBNSL@
LIBDL=@LIBDL@
LIBCSTD=@LIBCSTD@
LIBCRUN=@LIBCRUN@

#------------------------
# Install Paths
#------------------------
confdir = $(prefix)@confdir@
readmedir = $(prefix)@readmedir@
samplesdir = $(prefix)@samplesdir@
templatesdir = $(prefix)@templatesdir@

#------------------------
# Build Products
#------------------------
libexec_PROGRAMS =	bulkissuance \
					p7tool       \
					revoker      \
					setpin       \
					sslget       \
					tkstool


#------------------------
# Installed Files
#------------------------
bin_SCRIPTS =	wrappers/bulkissuance \
				wrappers/p7tool       \
				wrappers/revoker      \
				wrappers/setpin       \
				wrappers/sslget       \
				wrappers/tkstool

conf_DATA =	$(srcdir)/src/setpin/setpin.conf

readme_DATA =	$(srcdir)/LICENSE \
				$(srcdir)/doc/README

samples_DATA =	$(srcdir)/src/bulkissuance/bulkissuance.data

templates_DATA =	$(srcdir)/templates/pki_instance_command_wrapper \
					$(srcdir)/templates/pki_subsystem_command_wrapper


#////////////////////////////////////////////////////////////////
#
#   Dynamic Libraries
#
#////////////////////////////////////////////////////////////////



#////////////////////////////////////////////////////////////////
#
#   Programs
#
#////////////////////////////////////////////////////////////////

#------------------------
# bulkissuance
#------------------------
#
# REMINDER:  Link order is significant!
#
bulkissuance_SOURCES =	src/bulkissuance/bulkissuance.c \
						src/bulkissuance/getopt.c

bulkissuance_CPPFLAGS = $(AM_CPPFLAGS) @nss_inc@ @nspr_inc@
bulkissuance_LDADD = $(NSS_LINK) $(NSPR_LINK) $(LIBNSL) $(LIBSOCKET) $(LIBDL) \
	$(LIBCSTD) $(LIBCRUN)


#------------------------
# p7tool
#------------------------
#
# REMINDER:  Link order is significant!
#
p7tool_SOURCES =	src/p7tool/secerror.c \
					src/p7tool/secpwd.c   \
					src/p7tool/secutil.c  \
					src/p7tool/pppolicy.c \
					src/p7tool/p7tool.c

p7tool_CPPFLAGS = $(AM_CPPFLAGS) @nss_inc@ @nspr_inc@
p7tool_LDADD = $(NSS_LINK) $(NSPR_LINK) $(LIBNSL) $(LIBSOCKET) $(LIBDL) \
	$(LIBCSTD) $(LIBCRUN)


#------------------------
# revoker
#------------------------
#
# REMINDER:  Link order is significant!
#
revoker_SOURCES =	src/revoker/revoker.c \
					src/revoker/getopt.c

revoker_CPPFLAGS = $(AM_CPPFLAGS) @nss_inc@ @nspr_inc@
revoker_LDADD = $(NSS_LINK) $(NSPR_LINK) $(LIBNSL) $(LIBSOCKET) $(LIBDL) \
	$(LIBCSTD) $(LIBCRUN)


#------------------------
# setpin
#------------------------
#
# REMINDER:  Link order is significant!
#
setpin_SOURCES =	src/setpin/b64.c     \
					src/setpin/options.c \
					src/setpin/setpin.c  \
					src/setpin/setpin_options.c

setpin_CPPFLAGS = $(AM_CPPFLAGS) @ldapsdk_inc@ @svrcore_inc@ \
	@sasl_inc@ @nss_inc@ @nspr_inc@
setpin_LDADD = $(LDAPSDK_LINK) $(SVRCORE_LINK) $(SASL_LINK)  \
	$(NSS_LINK) $(NSPR_LINK) $(LIBNSL) $(LIBSOCKET) $(LIBDL) \
	$(LIBCSTD) $(LIBCRUN)


#------------------------
# sslget
#------------------------
#
# REMINDER:  Link order is significant!
#
sslget_SOURCES =	src/sslget/sslget.c \
					src/sslget/getopt.c

sslget_CPPFLAGS = $(AM_CPPFLAGS) @nss_inc@ @nspr_inc@
sslget_LDADD = $(NSS_LINK) $(NSPR_LINK) $(LIBNSL) $(LIBSOCKET) $(LIBDL) \
	$(LIBCSTD) $(LIBCRUN)


#------------------------
# tkstool
#------------------------
#
# REMINDER:  Link order is significant!
#
tkstool_SOURCES =	src/tkstool/delete.c   \
					src/tkstool/file.c     \
					src/tkstool/find.c     \
					src/tkstool/help.c     \
					src/tkstool/key.c      \
					src/tkstool/list.c     \
					src/tkstool/modules.c  \
					src/tkstool/random.c   \
					src/tkstool/retrieve.c \
					src/tkstool/util.c     \
					src/tkstool/version.c  \
					src/tkstool/tkstool.c  \
					src/tkstool/secutil.c  \
					src/tkstool/secpwd.c   \
					src/tkstool/secerror.c \
					src/tkstool/pppolicy.c

tkstool_CPPFLAGS = $(AM_CPPFLAGS) @ldapsdk_inc@ @svrcore_inc@ \
	@sasl_inc@ @nss_inc@ @nspr_inc@
tkstool_LDADD = $(LDAPSDK_LINK) $(SVRCORE_LINK) $(SASL_LINK)  \
	$(NSS_LINK) $(NSPR_LINK) $(LIBNSL) $(LIBSOCKET) $(LIBDL)  \
	$(LIBCSTD) $(LIBCRUN)


#////////////////////////////////////////////////////////////////
#
#   Wrappers
#
#////////////////////////////////////////////////////////////////

create_wrapper = sed                              \
	-e "s|\@ldapsdk_libdir\@|$(ldapsdk_libdir)|g" \
	-e "s|\@libexecdir\@|$(libexecdir)|g"         \
	-e "s|\@nspr_libdir\@|$(nspr_libdir)|g"       \
	-e "s|\@nss_libdir\@|$(nss_libdir)|g"         \
	-e "s|\@sasl_libdir\@|$(sasl_libdir)|g"

%: %.in
	mkdir -p $(dir $@)
	$(create_wrapper) $^ > $@

