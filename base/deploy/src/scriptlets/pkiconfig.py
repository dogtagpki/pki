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

# System Imports
import logging


# PKI Deployment Constants
PKI_DEPLOYMENT_DEFAULT_DIR_PERMISSIONS = 00770
PKI_DEPLOYMENT_DEFAULT_EXE_PERMISSIONS = 00770
PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS = 00660
PKI_DEPLOYMENT_DEFAULT_SGID_DIR_PERMISSIONS = 02770
PKI_DEPLOYMENT_DEFAULT_SYMLINK_PERMISSIONS = 00777
PKI_DEPLOYMENT_DEFAULT_UMASK = 00002

PKI_SUBSYSTEMS = ["CA","KRA","OCSP","RA","TKS","TPS"]
PKI_SIGNED_AUDIT_SUBSYSTEMS = ["CA","KRA","OCSP","TKS","TPS"]
PKI_APACHE_SUBSYSTEMS = ["RA","TPS"]
PKI_TOMCAT_SUBSYSTEMS = ["CA","KRA","OCSP","TKS"]

PKI_INDENTATION_LEVEL_0 = {'indent' : ''}
PKI_INDENTATION_LEVEL_1 = {'indent' : '... '}
PKI_INDENTATION_LEVEL_2 = {'indent' : '....... '}
PKI_INDENTATION_LEVEL_3 = {'indent' : '........... '}
PKI_INDENTATION_LEVEL_4 = {'indent' : '............... '}

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
PKI_DEPLOYMENT_DEFAULT_INSTANCE_NAME = "instance"
PKI_DEPLOYMENT_DEFAULT_CONFIGURATION_FILE = "pkideployment.cfg"

# NOTE: Top-level "/etc/pki" is owned by the "filesystem" package!
PKI_SHARED_CONFIGURATION_ROOT = "/etc/pki"


# PKI Deployment Global Variables
pki_timestamp = None


# PKI Deployment "Mandatory" Command-Line Variables
pki_subsystem = None

# PKI Deployment "Optional" Command-Line Variables
pkideployment_cfg = "/usr/share/pki/deployment/config/pkideployment.cfg"
pki_dry_run_flag = False
pki_root_prefix = None
pki_update_flag = False

# PKI Deployment "Custom" Command-Line Variables
pki_instance_name = None
pki_http_port = None
pki_https_port = None
pki_ajp_port = None


# PKI Deployment Logger Variables
pki_log = None
pki_log_dir = None
pki_log_name = None
pki_log_level = logging.INFO
pki_console_log_level = logging.WARNING


# PKI Deployment Global Dictionaries
pki_common_dict = None
pki_web_server_dict = None
pki_subsystem_dict = None
pki_master_dict = None
