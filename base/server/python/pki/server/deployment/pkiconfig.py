#!/usr/bin/python -t
# Authors:
#     Matthew Harmsen <mharmsen@redhat.com>
#
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
# Copyright (C) 2012 Red Hat, Inc.
# All rights reserved.
#

# PKI Deployment Constants
PKI_DEPLOYMENT_DEFAULT_CLIENT_DIR_PERMISSIONS = 00755
PKI_DEPLOYMENT_DEFAULT_DIR_PERMISSIONS = 00770
PKI_DEPLOYMENT_DEFAULT_EXE_PERMISSIONS = 00770
PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS = 00660
PKI_DEPLOYMENT_DEFAULT_SECURITY_DATABASE_PERMISSIONS = 00600
PKI_DEPLOYMENT_DEFAULT_SGID_DIR_PERMISSIONS = 02770
PKI_DEPLOYMENT_DEFAULT_SYMLINK_PERMISSIONS = 00777
PKI_DEPLOYMENT_DEFAULT_UMASK = 00002

PKI_DEPLOYMENT_DEFAULT_COMMENT = "'Certificate System'"
PKI_DEPLOYMENT_DEFAULT_GID = 17
PKI_DEPLOYMENT_DEFAULT_GROUP = "pkiuser"
PKI_DEPLOYMENT_DEFAULT_SHELL = "/sbin/nologin"
PKI_DEPLOYMENT_DEFAULT_UID = 17
PKI_DEPLOYMENT_DEFAULT_USER = "pkiuser"

PKI_SUBSYSTEMS = ["CA", "KRA", "OCSP", "RA", "TKS", "TPS"]
PKI_SIGNED_AUDIT_SUBSYSTEMS = ["CA", "KRA", "OCSP", "TKS", "TPS"]
PKI_APACHE_SUBSYSTEMS = ["RA"]
PKI_TOMCAT_SUBSYSTEMS = ["CA", "KRA", "OCSP", "TKS", "TPS"]
PKI_BASE_RESERVED_NAMES = ["alias", "bin", "ca", "common", "conf", "kra",
                           "lib", "logs", "ocsp", "temp", "tks", "tps", "webapps",
                           "work"]
PKI_CONFIGURATION_RESERVED_NAMES = ["CA", "java", "nssdb", "rpm-gpg",
                                    "rsyslog", "tls"]
PKI_APACHE_REGISTRY_RESERVED_NAMES = ["ra"]
PKI_TOMCAT_REGISTRY_RESERVED_NAMES = ["ca", "kra", "ocsp", "tks", "tps"]

PKI_INDENTATION_LEVEL_0 = {'indent' : ''}
PKI_INDENTATION_LEVEL_1 = {'indent' : '... '}
PKI_INDENTATION_LEVEL_2 = {'indent' : '....... '}
PKI_INDENTATION_LEVEL_3 = {'indent' : '........... '}
PKI_INDENTATION_LEVEL_4 = {'indent' : '............... '}

PKI_DEPLOYMENT_INTERRUPT_BANNER = "-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"\
                                  "-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-"

PKI_DEPLOYMENT_SOURCE_ROOT = "/usr/share/pki"
PKI_DEPLOYMENT_BASE_ROOT = "/var/lib/pki"
# NOTE: Top-level "/etc/pki" is owned by the "filesystem" package!
PKI_DEPLOYMENT_CONFIGURATION_ROOT = "/etc/pki"
PKI_DEPLOYMENT_LOG_ROOT = "/var/log/pki"
# NOTE:  Well-known 'registry root', default 'instance', and default
#        'configuration file' names MUST be created in order to potentially
#        obtain an instance-specific configuration file
#        (presuming one has not been specified during command-line parsing)
#        because command-line parsing happens prior to reading any
#        configuration files.  Although the 'registry root' MUST remain fixed,
#        the default 'instance' name may be overridden by the value specified
#        in the configuration file (the value in the default configuration file
#        should always match the 'default' instance name specified below).
PKI_DEPLOYMENT_DEFAULT_APACHE_INSTANCE_NAME = "pki-apache"
PKI_DEPLOYMENT_DEFAULT_TOMCAT_INSTANCE_NAME = "pki-tomcat"

DEFAULT_DEPLOYMENT_CONFIGURATION = "default.cfg"
USER_DEPLOYMENT_CONFIGURATION = "deployment.cfg"

PKI_DEPLOYMENT_DEFAULT_CONFIGURATION_FILE = \
    PKI_DEPLOYMENT_CONFIGURATION_ROOT + "/" + DEFAULT_DEPLOYMENT_CONFIGURATION
PKI_DEPLOYMENT_SLOTS_CONFIGURATION_FILE = \
    PKI_DEPLOYMENT_SOURCE_ROOT + "/deployment/config/pkislots.cfg"

# subtypes of PKI subsystems
PKI_DEPLOYMENT_CLONED_PKI_SUBSYSTEM = "Cloned"
PKI_DEPLOYMENT_EXTERNAL_CA = "External"
PKI_DEPLOYMENT_SUBORDINATE_CA = "Subordinate"

# default ports (for defined selinux policy)
PKI_DEPLOYMENT_DEFAULT_TOMCAT_HTTP_PORT = 8080
PKI_DEPLOYMENT_DEFAULT_TOMCAT_HTTPS_PORT = 8443
PKI_DEPLOYMENT_DEFAULT_TOMCAT_SERVER_PORT = 8005
PKI_DEPLOYMENT_DEFAULT_TOMCAT_AJP_PORT = 8009

# PKI Deployment Global Variables
pki_install_time = None
pki_timestamp = None
pki_architecture = None
pki_hostname = None
pki_dns_domainname = None
pki_certificate_timestamp = None


# PKI Deployment Command-Line Variables
pki_deployment_executable = None

# PKI Deployment "Mandatory" Command-Line Variables
pki_subsystem = None
#     'pkispawn' ONLY
default_deployment_cfg = None
user_deployment_cfg = None
#     'pkidestroy' ONLY
pki_deployed_instance_name = None
pki_secdomain_user = None
pki_secdomain_pass = None

# PKI Deployment "Test" Command-Line Variables
pki_root_prefix = None


# PKI Deployment Helper Functions
def str2bool(string):
    return string.lower() in ("yes", "true", "t", "1")

# NOTE:  To utilize the 'preparations_for_an_external_java_debugger(master)'
#        and 'wait_to_attach_an_external_java_debugger(master)' functions,
#        change 'pki_enable_java_debugger=False' to
#        'pki_enable_java_debugger=True' in the appropriate
#        deployment configuration file.
def prepare_for_an_external_java_debugger(instance):
    print
    print PKI_DEPLOYMENT_INTERRUPT_BANNER
    print
    print "The following 'JAVA_OPTS' MUST be enabled (uncommented) in"
    print "'%s':" % instance
    print
    print "    JAVA_OPTS=\"-Xdebug -Xrunjdwp:transport=dt_socket,\""
    print "              \"address=8000,server=y,suspend\""
    print
    raw_input("Enable external java debugger 'JAVA_OPTS' "\
              "and press return to continue  . . . ")
    print
    print PKI_DEPLOYMENT_INTERRUPT_BANNER
    print
    return

def wait_to_attach_an_external_java_debugger():
    print
    print PKI_DEPLOYMENT_INTERRUPT_BANNER
    print
    print "Attach the java debugger to this process on the port specified by"
    print "the 'address' selected by 'JAVA_OPTS' (e. g. - port 8000) and"
    print "set any desired breakpoints"
    print
    raw_input("Please attach an external java debugger "\
              "and press return to continue  . . . ")
    print
    print PKI_DEPLOYMENT_INTERRUPT_BANNER
    print
    return


# PKI Deployment Logger Variables
pki_log = None
pki_log_dir = None
pki_log_name = None
pki_log_level = None
pki_console_log_level = None

# PKI Selinux Constants and parameters
PKI_INSTANCE_SELINUX_CONTEXT = "pki_tomcat_var_lib_t"
PKI_LOG_SELINUX_CONTEXT = "pki_tomcat_log_t"
PKI_CFG_SELINUX_CONTEXT = "pki_tomcat_etc_rw_t"
PKI_CERTDB_SELINUX_CONTEXT = "pki_tomcat_cert_t"
PKI_PORT_SELINUX_CONTEXT = "http_port_t"
pki_selinux_config_ports = []
