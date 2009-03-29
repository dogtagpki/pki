# --- BEGIN COPYRIGHT BLOCK ---
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation;
# version 2.1 of the License.
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
TPS_INCLUDES = -I$(srcdir)/src/include
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
AM_CPPFLAGS = $(DEBUG_DEFINES) $(TPS_INCLUDES) $(PATH_DEFINES)
# We need to make sure that libpthread is linked before libc on HP-UX.
if HPUX
AM_LDFLAGS = -lpthread -lz
endif
if LINUX
AM_LDFLAGS = -lz
endif
if SOLARIS
AM_LDFLAGS = -lz
endif

#------------------------
# Linker Flags
#------------------------
APR_LINK = @apr_lib@ -l@apr_lib_version@
LDAPSDK_LINK = @ldapsdk_lib@ -lssldap60 -lprldap60 -lldap60 -lldif60
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
aliasdir = $(prefix)@aliasdir@
apache_modulesdir = $(prefix)@apache_modulesdir@
appletsdir = $(prefix)@appletsdir@
cgibin_demodir = $(prefix)@cgibin_demodir@
cgibin_homedir = $(prefix)@cgibin_homedir@
cgibin_sodir = $(prefix)@cgibin_sodir@
cgibin_sowdir = $(prefix)@cgibin_sowdir@
confdir = $(prefix)@confdir@
docrootdir = $(prefix)@docrootdir@
docroot_demodir = $(prefix)@docroot_demodir@
docroot_homedir = $(prefix)@docroot_homedir@
docroot_sodir = $(prefix)@docroot_sodir@
docroot_sowdir = $(prefix)@docroot_sowdir@
docroot_tokendbdir = $(prefix)@docroot_tokendbdir@
docroot_tps_configdir = $(prefix)@docroot_tps_configdir@
docroot_tps_imgdir = $(prefix)@docroot_tps_imgdir@
docroot_tps_jsdir = $(prefix)@docroot_tps_jsdir@
initddir = $(sysconfdir)@initddir@
licensedir = $(prefix)@licensedir@
logsdir = $(prefix)@logsdir@
perl_modulesdir = $(prefix)@perl_modulesdir@
perl_templatesdir = $(prefix)@perl_templatesdir@
samplesdir = $(prefix)@samplesdir@
scriptsdir = $(prefix)@scriptsdir@
setupdir = $(prefix)@setupdir@
templatesdir = $(prefix)@templatesdir@

#------------------------
# Build Products
#------------------------
lib_LTLIBRARIES =	libtokendb.la  \
					libtps.la      \
					libldapauth.la

apache_modules_LTLIBRARIES =	mod_tps.la \
								mod_tokendb.la

libexec_PROGRAMS =	tpsclient

#------------------------
# Installed Files
#------------------------
# create an empty 'alias' directory
alias_DATA =

applets_DATA =	$(srcdir)/applets/1.4.499dc06c.ijc \
		$(srcdir)/applets/1.3.44724DDE.ijc

bin_SCRIPTS =	wrappers/tpsclient

cgibin_demo_DATA =

cgibin_demo_SCRIPTS =	$(srcdir)/forms/esc/cgi-bin/demo/enroll.cgi \
						$(srcdir)/forms/esc/cgi-bin/demo/index.cgi

cgibin_home_DATA =

cgibin_home_SCRIPTS =	$(srcdir)/forms/esc/cgi-bin/home/enroll.cgi \
						$(srcdir)/forms/esc/cgi-bin/home/index.cgi

cgibin_so_DATA =

cgibin_so_SCRIPTS =	$(srcdir)/forms/esc/cgi-bin/so/enroll.cgi \
					$(srcdir)/forms/esc/cgi-bin/so/index.cgi

cgibin_sow_DATA =

cgibin_sow_SCRIPTS =	$(srcdir)/forms/esc/cgi-bin/sow/ajax-list.cgi   \
						$(srcdir)/forms/esc/cgi-bin/sow/cfg.pl          \
						$(srcdir)/forms/esc/cgi-bin/sow/enroll.cgi      \
						$(srcdir)/forms/esc/cgi-bin/sow/enroll_temp.cgi \
						$(srcdir)/forms/esc/cgi-bin/sow/format.cgi      \
						$(srcdir)/forms/esc/cgi-bin/sow/formatso.cgi    \
						$(srcdir)/forms/esc/cgi-bin/sow/index.cgi       \
						$(srcdir)/forms/esc/cgi-bin/sow/main.cgi        \
						$(srcdir)/forms/esc/cgi-bin/sow/noaccess.cgi    \
						$(srcdir)/forms/esc/cgi-bin/sow/read.cgi        \
						$(srcdir)/forms/esc/cgi-bin/sow/read_temp.cgi   \
						$(srcdir)/forms/esc/cgi-bin/sow/search.cgi      \
						$(srcdir)/forms/esc/cgi-bin/sow/search_temp.cgi \
						$(srcdir)/forms/esc/cgi-bin/sow/seturl.cgi      \
						$(srcdir)/forms/esc/cgi-bin/sow/welcome.cgi

conf_DATA =	$(srcdir)/apache/conf/httpd.conf      \
			$(srcdir)/apache/conf/magic           \
			$(srcdir)/apache/conf/mime.types      \
			$(srcdir)/apache/conf/nss.conf        \
			$(srcdir)/apache/conf/perl.conf       \
			$(srcdir)/apache/conf/revocator.conf  \
			$(srcdir)/doc/CS.cfg

docroot_DATA =	$(srcdir)/forms/index.html

docroot_demo_DATA =

docroot_home_DATA =

docroot_so_DATA =

docroot_sow_DATA =

docroot_tokendb_DATA =

docroot_tps_config_DATA = 

docroot_tps_img_DATA =

docroot_tps_js_DATA =

initd_SCRIPTS =	$(srcdir)/etc/init.d/httpd

license_DATA =	$(srcdir)/LICENSE

libexec_SCRIPTS =	$(srcdir)/apache/apachectl

# create an empty 'logs' directory
logs_DATA =

perl_modules_SCRIPTS =	$(srcdir)/lib/perl/PKI/TPS/AdminAuthPanel.pm         \
						$(srcdir)/lib/perl/PKI/TPS/AdminPanel.pm             \
						$(srcdir)/lib/perl/PKI/TPS/AgentAuthPanel.pm         \
						$(srcdir)/lib/perl/PKI/TPS/AuthDBPanel.pm            \
						$(srcdir)/lib/perl/PKI/TPS/BasePanel.pm              \
						$(srcdir)/lib/perl/PKI/TPS/CAInfoPanel.pm            \
						$(srcdir)/lib/perl/PKI/TPS/CertInfo.pm               \
						$(srcdir)/lib/perl/PKI/TPS/CertPrettyPrintPanel.pm   \
						$(srcdir)/lib/perl/PKI/TPS/CertRequestPanel.pm       \
						$(srcdir)/lib/perl/PKI/TPS/Common.pm                 \
						$(srcdir)/lib/perl/PKI/TPS/Config.pm                 \
						$(srcdir)/lib/perl/PKI/TPS/ConfigHSMLoginPanel.pm    \
						$(srcdir)/lib/perl/PKI/TPS/ConfigHSMPanel.pm         \
						$(srcdir)/lib/perl/PKI/TPS/DRMInfoPanel.pm           \
						$(srcdir)/lib/perl/PKI/TPS/DatabasePanel.pm          \
						$(srcdir)/lib/perl/PKI/TPS/DisplayCertChain2Panel.pm \
						$(srcdir)/lib/perl/PKI/TPS/DisplayCertChainPanel.pm  \
						$(srcdir)/lib/perl/PKI/TPS/DonePanel.pm              \
						$(srcdir)/lib/perl/PKI/TPS/GlobalVar.pm              \
						$(srcdir)/lib/perl/PKI/TPS/ImportAdminCertPanel.pm   \
						$(srcdir)/lib/perl/PKI/TPS/Login.pm                  \
						$(srcdir)/lib/perl/PKI/TPS/LoginPanel.pm             \
						$(srcdir)/lib/perl/PKI/TPS/ModulePanel.pm            \
						$(srcdir)/lib/perl/PKI/TPS/Modutil.pm                \
						$(srcdir)/lib/perl/PKI/TPS/NamePanel.pm              \
						$(srcdir)/lib/perl/PKI/TPS/ReqCertInfo.pm            \
						$(srcdir)/lib/perl/PKI/TPS/SecurityDomainPanel.pm    \
						$(srcdir)/lib/perl/PKI/TPS/SizePanel.pm              \
						$(srcdir)/lib/perl/PKI/TPS/SubsystemTypePanel.pm     \
						$(srcdir)/lib/perl/PKI/TPS/TKSInfoPanel.pm           \
						$(srcdir)/lib/perl/PKI/TPS/WelcomePanel.pm           \
						$(srcdir)/lib/perl/PKI/TPS/wizard.pm

perl_templates_SCRIPTS =	$(srcdir)/lib/perl/Template/Velocity.pm

samples_DATA =	$(srcdir)/tools/raclient/enroll.tps \
				$(srcdir)/tools/raclient/format.tps \
				$(srcdir)/tools/raclient/reset_pin.tps

scripts_DATA =	$(srcdir)/scripts/schemaMods.ldif \
				$(srcdir)/scripts/database.ldif   \
				$(srcdir)/scripts/addIndexes.ldif \
				$(srcdir)/scripts/addAgents.ldif  \
				$(srcdir)/scripts/addTokens.ldif  \
				$(srcdir)/scripts/vlvtasks.ldif   \
				$(srcdir)/scripts/addVLVIndexes.ldif

scripts_SCRIPTS =	$(srcdir)/scripts/nss_pcache

if LINUX
setup_DATA =	$(srcdir)/setup/config.desktop
endif

setup_SCRIPTS =	$(srcdir)/setup/postinstall

templates_DATA =	$(srcdir)/apache/pki_instance_command_wrapper \
					$(srcdir)/apache/pki_subsystem_command_wrapper


#////////////////////////////////////////////////////////////////
#
#   Dynamic Libraries
#
#////////////////////////////////////////////////////////////////

#------------------------
# libtokendb
#------------------------
libtokendb_la_SOURCES = src/tus/tus_db.c

libtokendb_la_CPPFLAGS = $(AM_CPPFLAGS) @ldapsdk_inc@ @svrcore_inc@ \
	@sasl_inc@ @nss_inc@ @nspr_inc@
libtokendb_la_LDFLAGS = $(AM_LDFLAGS) -avoid-version
libtokendb_la_LIBADD = $(LDAPSDK_LINK) $(SVRCORE_LINK)                    \
	$(SASL_LINK) $(NSS_LINK) $(NSPR_LINK) $(LIBNSL) $(LIBSOCKET) $(LIBDL) \
	$(LIBCSTD) $(LIBCRUN)


#------------------------
# libtps
#------------------------
libtps_la_SOURCES =	src/main/Buffer.cpp                        \
					src/main/NameValueSet.cpp                  \
					src/main/ConfigStore.cpp                   \
					src/main/Util.cpp                          \
					src/main/RA_Msg.cpp                        \
					src/main/RA_pblock.cpp                     \
					src/main/RA_Session.cpp                    \
					src/main/RA_Context.cpp                    \
					src/main/Login.cpp                         \
					src/main/SecureId.cpp                      \
					src/main/Memory.cpp                        \
					src/main/AuthenticationEntry.cpp           \
					src/main/AuthParams.cpp                    \
					src/main/Authentication.cpp                \
					src/main/AttributeSpec.cpp                 \
					src/main/ObjectSpec.cpp                    \
					src/main/PKCS11Obj.cpp                     \
					src/httpClient/httpClient.cpp              \
					src/httpClient/Cache.cpp                   \
					src/httpClient/engine.cpp                  \
					src/httpClient/http.cpp                    \
					src/httpClient/response.cpp                \
					src/httpClient/request.cpp                 \
					src/httpClient/nscperror.cpp               \
					src/cms/HttpConnection.cpp                 \
					src/cms/ConnectionInfo.cpp                 \
					src/cms/CertEnroll.cpp                     \
					src/apdu/APDU.cpp                          \
					src/apdu/Unblock_Pin_APDU.cpp              \
					src/apdu/Create_Object_APDU.cpp            \
					src/apdu/Set_Pin_APDU.cpp                  \
					src/apdu/Set_IssuerInfo_APDU.cpp           \
					src/apdu/Get_IssuerInfo_APDU.cpp           \
					src/apdu/Create_Pin_APDU.cpp               \
					src/apdu/List_Pins_APDU.cpp                \
					src/apdu/Initialize_Update_APDU.cpp        \
					src/apdu/Get_Version_APDU.cpp              \
					src/apdu/Get_Status_APDU.cpp               \
					src/apdu/Get_Data_APDU.cpp                 \
					src/apdu/External_Authenticate_APDU.cpp    \
					src/apdu/Generate_Key_APDU.cpp             \
					src/apdu/Read_Buffer_APDU.cpp              \
					src/apdu/Read_Object_APDU.cpp              \
					src/apdu/Write_Object_APDU.cpp             \
					src/apdu/Put_Key_APDU.cpp                  \
					src/apdu/Select_APDU.cpp                   \
					src/apdu/Delete_File_APDU.cpp              \
					src/apdu/Install_Applet_APDU.cpp           \
					src/apdu/Format_Muscle_Applet_APDU.cpp     \
					src/apdu/Load_File_APDU.cpp                \
					src/apdu/Install_Load_APDU.cpp             \
					src/apdu/Lifecycle_APDU.cpp                \
					src/apdu/List_Objects_APDU.cpp             \
					src/apdu/Import_Key_APDU.cpp               \
					src/apdu/Import_Key_Enc_APDU.cpp           \
					src/apdu/APDU_Response.cpp                 \
					src/msg/RA_Begin_Op_Msg.cpp                \
					src/msg/RA_End_Op_Msg.cpp                  \
					src/msg/RA_Login_Request_Msg.cpp           \
					src/msg/RA_Login_Response_Msg.cpp          \
					src/msg/RA_SecureId_Request_Msg.cpp        \
					src/msg/RA_SecureId_Response_Msg.cpp       \
					src/msg/RA_ASQ_Request_Msg.cpp             \
					src/msg/RA_ASQ_Response_Msg.cpp            \
					src/msg/RA_New_Pin_Request_Msg.cpp         \
					src/msg/RA_New_Pin_Response_Msg.cpp        \
					src/msg/RA_Token_PDU_Request_Msg.cpp       \
					src/msg/RA_Token_PDU_Response_Msg.cpp      \
					src/msg/RA_Status_Update_Request_Msg.cpp   \
					src/msg/RA_Status_Update_Response_Msg.cpp  \
					src/msg/RA_Extended_Login_Request_Msg.cpp  \
					src/msg/RA_Extended_Login_Response_Msg.cpp \
					src/channel/Channel.cpp                    \
					src/channel/Secure_Channel.cpp             \
					src/engine/RA.cpp                          \
					src/processor/RA_Processor.cpp             \
					src/processor/RA_Enroll_Processor.cpp      \
					src/processor/RA_Pin_Reset_Processor.cpp   \
					src/processor/RA_Renew_Processor.cpp       \
					src/processor/RA_Unblock_Processor.cpp     \
					src/processor/RA_Format_Processor.cpp

libtps_la_CPPFLAGS = $(AM_CPPFLAGS) @ldapsdk_inc@ @svrcore_inc@ \
	@sasl_inc@ @nss_inc@ @nspr_inc@
libtps_la_LDFLAGS = $(AM_LDFLAGS) -avoid-version
libtps_la_LIBADD = ${top_builddir}/libtokendb.la $(LDAPSDK_LINK)       \
	$(SVRCORE_LINK) $(SASL_LINK) $(NSS_LINK) $(NSPR_LINK) $(LIBNSL)    \
	$(LIBSOCKET) $(LIBDL) $(LIBCSTD) $(LIBCRUN)


#------------------------
# libldapauth
#------------------------
libldapauth_la_SOURCES =	src/authentication/LDAP_Authentication.cpp

libldapauth_la_CPPFLAGS = $(AM_CPPFLAGS) @ldapsdk_inc@ @svrcore_inc@ \
	@sasl_inc@ @nss_inc@ @nspr_inc@
libldapauth_la_LDFLAGS = $(AM_LDFLAGS) -avoid-version
libldapauth_la_LIBADD = ${top_builddir}/libtps.la $(LDAPSDK_LINK)       \
	$(SVRCORE_LINK) $(SASL_LINK) $(NSS_LINK) $(NSPR_LINK) $(LIBNSL)     \
	$(LIBSOCKET) $(LIBDL) $(LIBCSTD) $(LIBCRUN)


#------------------------
# mod_tps
#------------------------
mod_tps_la_SOURCES =	src/modules/tps/AP_Context.cpp \
						src/modules/tps/AP_Session.cpp \
						src/modules/tps/mod_tps.cpp

mod_tps_la_CPPFLAGS = $(AM_CPPFLAGS) @apr_inc@ \
	@ldapsdk_inc@ @svrcore_inc@ @sasl_inc@ @nss_inc@ @nspr_inc@
mod_tps_la_LDFLAGS = $(AM_LDFLAGS) -avoid-version -module
mod_tps_la_LIBADD = ${top_builddir}/libtps.la $(APR_LINK)                 \
	$(LDAPSDK_LINK) $(SVRCORE_LINK) $(SASL_LINK) $(NSS_LINK) $(NSPR_LINK) \
	$(LIBNSL) $(LIBSOCKET) $(LIBDL) $(LIBCSTD) $(LIBCRUN)


#------------------------
# mod_tokendb
#------------------------
mod_tokendb_la_SOURCES =	src/modules/tokendb/mod_tokendb.cpp

mod_tokendb_la_CPPFLAGS = $(AM_CPPFLAGS) @apr_inc@ \
	@ldapsdk_inc@ @svrcore_inc@ @sasl_inc@ @nss_inc@ @nspr_inc@
mod_tokendb_la_LDFLAGS = $(AM_LDFLAGS) -avoid-version -module
mod_tokendb_la_LIBADD = ${top_builddir}/libtokendb.la $(APR_LINK)         \
	$(LDAPSDK_LINK) $(SVRCORE_LINK) $(SASL_LINK) $(NSS_LINK) $(NSPR_LINK) \
	$(LIBNSL) $(LIBSOCKET) $(LIBDL) $(LIBCSTD) $(LIBCRUN)


#////////////////////////////////////////////////////////////////
#
#   Programs
#
#////////////////////////////////////////////////////////////////

#------------------------
# tpsclient
#------------------------
#
# REMINDER:  Link order is significant!
#
tpsclient_SOURCES =	tools/raclient/RA_Client.cpp               \
					tools/raclient/RA_Conn.cpp                 \
					tools/raclient/RA_Token.cpp                \
					src/main/Buffer.cpp                        \
					src/main/NameValueSet.cpp                  \
					src/main/Util.cpp                          \
					src/main/AuthParams.cpp                    \
					src/apdu/APDU.cpp                          \
					src/apdu/APDU_Response.cpp                 \
					src/apdu/Create_Object_APDU.cpp            \
					src/apdu/Create_Pin_APDU.cpp               \
					src/apdu/Delete_File_APDU.cpp              \
					src/apdu/External_Authenticate_APDU.cpp    \
					src/apdu/Format_Muscle_Applet_APDU.cpp     \
					src/apdu/Generate_Key_APDU.cpp             \
					src/apdu/Get_Data_APDU.cpp                 \
					src/apdu/Get_Status_APDU.cpp               \
					src/apdu/Get_Version_APDU.cpp              \
					src/apdu/Initialize_Update_APDU.cpp        \
					src/apdu/Install_Applet_APDU.cpp           \
					src/apdu/Install_Load_APDU.cpp             \
					src/apdu/Lifecycle_APDU.cpp                \
					src/apdu/List_Objects_APDU.cpp             \
					src/apdu/Set_IssuerInfo_APDU.cpp           \
					src/apdu/Get_IssuerInfo_APDU.cpp           \
					src/apdu/List_Pins_APDU.cpp                \
					src/apdu/Load_File_APDU.cpp                \
					src/apdu/Put_Key_APDU.cpp                  \
					src/apdu/Read_Buffer_APDU.cpp              \
					src/apdu/Read_Object_APDU.cpp              \
					src/apdu/Select_APDU.cpp                   \
					src/apdu/Set_Pin_APDU.cpp                  \
					src/apdu/Unblock_Pin_APDU.cpp              \
					src/apdu/Write_Object_APDU.cpp             \
					src/apdu/Import_Key_Enc_APDU.cpp           \
					src/main/RA_Msg.cpp                        \
					src/msg/RA_Begin_Op_Msg.cpp                \
					src/msg/RA_End_Op_Msg.cpp                  \
					src/msg/RA_Login_Request_Msg.cpp           \
					src/msg/RA_Login_Response_Msg.cpp          \
					src/msg/RA_Extended_Login_Request_Msg.cpp  \
					src/msg/RA_Extended_Login_Response_Msg.cpp \
					src/msg/RA_ASQ_Request_Msg.cpp             \
					src/msg/RA_ASQ_Response_Msg.cpp            \
					src/msg/RA_New_Pin_Request_Msg.cpp         \
					src/msg/RA_New_Pin_Response_Msg.cpp        \
					src/msg/RA_SecureId_Request_Msg.cpp        \
					src/msg/RA_SecureId_Response_Msg.cpp       \
					src/msg/RA_Status_Update_Request_Msg.cpp   \
					src/msg/RA_Status_Update_Response_Msg.cpp  \
					src/msg/RA_Token_PDU_Request_Msg.cpp       \
					src/msg/RA_Token_PDU_Response_Msg.cpp

tpsclient_CPPFLAGS = $(AM_CPPFLAGS) @ldapsdk_inc@ @svrcore_inc@ \
	@sasl_inc@ @nss_inc@ @nspr_inc@
tpsclient_LDADD = $(LDAPSDK_LINK) $(SVRCORE_LINK)                         \
	$(SASL_LINK) $(NSS_LINK) $(NSPR_LINK) $(LIBNSL) $(LIBSOCKET) $(LIBDL) \
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

