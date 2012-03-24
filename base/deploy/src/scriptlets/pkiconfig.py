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
# Copyright (C) 2011 Red Hat, Inc.
# All rights reserved.
#

# System Imports
import logging


# PKI Deployment Constants
PKI_DEPLOYMENT_PATH = "/usr/share/pki/deployment"
PKI_DEPLOYMENT_CONFIG_PATH = PKI_DEPLOYMENT_PATH + "/" + "config"
PKI_DEPLOYMENT_SCRIPTLETS_MODULE = "pki.deployment"
PKI_DEPLOYMENT_VERBOSITY=\
"VERBOSITY FLAGS    CONSOLE MESSAGE LEVEL       LOG MESSAGE LEVEL\n"\
"=======================================================================\n"\
"  NONE             error|warning               error|warning|info\n"\
"  -v               error|warning|info          error|warning|info\n"\
"  -vv              error|warning|info          error|warning|info|debug\n"\
"  -vvv             error|warning|info|debug    error|warning|info|debug\n"\
" "
PKI_DEPLOYMENT_DEFAULT_DIR_PERMISSIONS = 00770
PKI_DEPLOYMENT_DEFAULT_EXE_PERMISSIONS = 00770
PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS = 00660
PKI_DEPLOYMENT_DEFAULT_UMASK = 00002

PKIDESTROY_PATH = PKI_DEPLOYMENT_PATH + "/" + "destroy"
PKIDESTROY_LOG_PATH = "/var/log"
PKIDESTROY_LOG_PREFIX = "pki-"
PKIDESTROY_LOG_SUFFIX = "-destroy.log"
PKIDESTROY_LOGGER = "pkidestroy"

PKIRESPAWN_PATH = PKI_DEPLOYMENT_PATH + "/" + "spawn"
PKIRESPAWN_LOG_PATH = "/var/log"
PKIRESPAWN_LOG_PREFIX = "pki-"
PKIRESPAWN_LOG_SUFFIX = "-respawn.log"
PKIRESPAWN_LOGGER = "pkirespawn"

PKISPAWN_PATH = PKI_DEPLOYMENT_PATH + "/" + "spawn"
PKISPAWN_LOG_PATH = "/var/log"
PKISPAWN_LOG_PREFIX = "pki-"
PKISPAWN_LOG_SUFFIX = "-spawn.log"
PKISPAWN_LOGGER = "pkispawn"

PKI_SECURITY_DATABASE_DIR = "alias"
PKI_SUBSYSTEMS = ["CA","KRA","OCSP","RA","TKS","TPS"]
PKI_APACHE_SUBSYSTEMS = ["RA","TPS"]
PKI_TOMCAT_SUBSYSTEMS = ["CA","KRA","OCSP","TKS"]


# PKI Deployment "Mandatory" Command-Line Variables
pki_subsystem = None

# PKI Deployment "Optional" Command-Line Variables
pkideployment_cfg = PKI_DEPLOYMENT_CONFIG_PATH + "/" + "pkideployment.cfg"
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

