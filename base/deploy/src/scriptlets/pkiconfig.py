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

PKI_SUBSYSTEMS = ["CA","KRA","OCSP","RA","TKS","TPS"]
PKI_SIGNED_AUDIT_SUBSYSTEMS = ["CA","KRA","OCSP","TKS","TPS"]
PKI_APACHE_SUBSYSTEMS = ["RA","TPS"]
PKI_TOMCAT_SUBSYSTEMS = ["CA","KRA","OCSP","TKS"]

PKI_INDENTATION_LEVEL_0 = {'indent' : ''}
PKI_INDENTATION_LEVEL_1 = {'indent' : '... '}
PKI_INDENTATION_LEVEL_2 = {'indent' : '....... '}
PKI_INDENTATION_LEVEL_3 = {'indent' : '........... '}
PKI_INDENTATION_LEVEL_4 = {'indent' : '............... '}

PKI_DEPLOYMENT_INTERRUPT_BANNER = "-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+"\
                                  "-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-"
PKI_DEPLOYMENT_JAR_SOURCE_ROOT = "/usr/share/java"
PKI_DEPLOYMENT_HTTPCOMPONENTS_JAR_SOURCE_ROOT = "/usr/share/java/httpcomponents"
PKI_DEPLOYMENT_PKI_JAR_SOURCE_ROOT = "/usr/share/java/pki"
PKI_DEPLOYMENT_RESTEASY_JAR_SOURCE_ROOT = "/usr/share/java/resteasy"
PKI_DEPLOYMENT_SOURCE_ROOT = "/usr/share/pki"
PKI_DEPLOYMENT_SYSTEMD_ROOT = "/lib/systemd/system"
PKI_DEPLOYMENT_SYSTEMD_CONFIGURATION_ROOT = "/etc/systemd/system"
PKI_DEPLOYMENT_TOMCAT_ROOT = "/usr/share/tomcat"
PKI_DEPLOYMENT_TOMCAT_SYSTEMD = "/usr/sbin/tomcat-sysd"
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
PKI_DEPLOYMENT_REGISTRY_ROOT = "/etc/sysconfig/pki"
PKI_DEPLOYMENT_DEFAULT_ADMIN_DOMAIN_NAME = None
PKI_DEPLOYMENT_DEFAULT_APACHE_INSTANCE_NAME = "apache"
PKI_DEPLOYMENT_DEFAULT_TOMCAT_INSTANCE_NAME = "tomcat"
PKI_DEPLOYMENT_DEFAULT_CONFIGURATION_FILE = "pkideployment.cfg"
PKI_DEPLOYMENT_SLOTS_CONFIGURATION_FILE =\
    "/usr/share/pki/deployment/config/pkislots.cfg"


# PKI Deployment Jython 2.2 Constants
PKI_JYTHON_CRITICAL_LOG_LEVEL = 1
PKI_JYTHON_ERROR_LOG_LEVEL = 2
PKI_JYTHON_WARNING_LOG_LEVEL = 3
PKI_JYTHON_INFO_LOG_LEVEL = 4
PKI_JYTHON_DEBUG_LOG_LEVEL = 5


# PKI Deployment Global Variables
pki_install_time = None
pki_timestamp = None
pki_architecture = None
pki_hostname = None
pki_pin = None
pki_client_pin = None
pki_one_time_pin = None


# PKI Deployment "Mandatory" Command-Line Variables
pki_subsystem = None

# PKI Deployment "Optional" Command-Line Variables
pkideployment_cfg = "/usr/share/pki/deployment/config/pkideployment.cfg"
pki_dry_run_flag = False
pki_root_prefix = None
pki_update_flag = False

# PKI Deployment "Custom" Command-Line Variables
custom_pki_admin_domain_name = None
custom_pki_instance_name = None
custom_pki_http_port = None
custom_pki_https_port = None
custom_pki_ajp_port = None


# PKI Deployment Helper Functions
def str2bool(string):
    return string.lower() in ("yes", "true", "t", "1")

# NOTE:  To utilize the 'preparations_for_an_external_java_debugger(master)'
#        and 'wait_to_attach_an_external_java_debugger(master)' functions,
#        change 'pki_enable_java_debugger=False' to
#        'pki_enable_java_debugger=True' in the appropriate
#        'pkideployment.cfg' configuration file.
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
pki_jython_log_level = None
pki_log = None
pki_log_dir = None
pki_log_name = None
pki_log_level = None
pki_console_log_level = None


# PKI Deployment Global Dictionaries
pki_sensitive_dict = None
pki_mandatory_dict = None
pki_optional_dict = None
pki_common_dict = None
pki_web_server_dict = None
pki_subsystem_dict = None
pki_master_dict = None
pki_slots_dict = None
pki_master_jython_dict = None
