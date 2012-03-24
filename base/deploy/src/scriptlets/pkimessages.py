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

# PKI Deployment Engine Messages
PKI_CUSTOM_APACHE_INSTANCE_1 = "When a custom '%s' subsystem is being "\
                               "deployed, the 'instance', 'http_port', and "\
                               "'https_port' must ALL be specified!"
PKI_CUSTOM_TOMCAT_INSTANCE_1 = "When a custom '%s' subsystem is being "\
                               "deployed, the 'instance', 'http_port', "\
                               "'https_port', and 'ajp_port' must ALL be "\
                               "specified!"
PKI_CUSTOM_TOMCAT_AJP_PORT_1 = "When a custom '%s' subsystem is being "\
                               "deployed, ONLY the 'instance', "\
                               "'http_port', and 'https_port' MUST be "\
                               "specified; NO 'ajp_port' should be requested!"
PKI_DICTIONARY_COMMON ="\n"\
"=====================================================\n"\
"    DISPLAY CONTENTS OF PKI COMMON DICTIONARY\n"\
"====================================================="
PKI_DICTIONARY_MASTER="\n"\
"=====================================================\n"\
"    DISPLAY CONTENTS OF PKI MASTER DICTIONARY\n"\
"====================================================="
PKI_DICTIONARY_SUBSYSTEM="\n"\
"=====================================================\n"\
"    DISPLAY CONTENTS OF PKI SUBSYSTEM DICTIONARY\n"\
"====================================================="
PKI_DICTIONARY_WEB_SERVER="\n"\
"=====================================================\n"\
"    DISPLAY CONTENTS OF PKI WEB SERVER DICTIONARY\n"\
"====================================================="
PKI_DIRECTORY_ALREADY_EXISTS_1 = "Directory '%s' already exists!"
PKI_DIRECTORY_ALREADY_EXISTS_NOT_A_DIRECTORY_1 = "Directory '%s' already "\
                                                 "exists BUT it is NOT a "\
                                                 "directory!"
PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 = "Directory '%s' is either "\
                                             "missing or is NOT a directory!"
PKI_FILE_MISSING_OR_NOT_A_FILE_1 = "File '%s' is either missing "\
                                   "or is NOT a regular file!"
PKI_UNABLE_TO_PARSE_1 = "'Could not parse:  '%s'"
PKI_UNABLE_TO_CREATE_LOG_DIRECTORY_1 = "Could not create log directory '%s'!"
PKI_VERBOSITY_LEVELS_MESSAGE = "Only up to 3 levels of verbosity are supported!"


# PKI Deployment 'pkispawn' and 'pkidestroy' Messages
PKIDESTROY_BEGIN_MESSAGE_2 = "BEGIN destroying subsystem '%s' of "\
                             "instance '%s' . . ."
PKIDESTROY_END_MESSAGE_2 = "END destroying subsystem '%s' of "\
                           "instance '%s'."
PKIRESPAWN_BEGIN_MESSAGE_2 = "BEGIN respawning subsystem '%s' of "\
                             "instance '%s' . . ."
PKIRESPAWN_END_MESSAGE_2 = "END respawning subsystem '%s' of "\
                           "instance '%s'."
PKISPAWN_BEGIN_MESSAGE_2 = "BEGIN spawning subsystem '%s' of "\
                           "instance '%s' . . ."
PKISPAWN_END_MESSAGE_2 = "END spawning subsystem '%s' of "\
                         "instance '%s'."


# PKI Deployment "Scriptlet" Messages
INSTANCE_DESTROY_1 = "    depopulating '%s'"
INSTANCE_RESPAWN_1 = "    repopulating '%s'"
INSTANCE_SPAWN_1 = "    populating '%s'"
INSTANCE_SPAWN_MKDIR_1 = "        mkdir '%s'"
SECURITY_DATABASES_DESTROY_1 = "    removing '%s'"
SECURITY_DATABASES_RESPAWN_1 = "    regenerating '%s'"
SECURITY_DATABASES_SPAWN_1 = "    generating '%s'"

