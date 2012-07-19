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

# PKI Deployment Engine Messages
PKI_DICTIONARY_MANDATORY ="\n"\
"=====================================================\n"\
"    DISPLAY CONTENTS OF PKI MANDATORY DICTIONARY\n"\
"====================================================="
PKI_DICTIONARY_OPTIONAL ="\n"\
"=====================================================\n"\
"    DISPLAY CONTENTS OF PKI OPTIONAL DICTIONARY\n"\
"====================================================="
PKI_DICTIONARY_COMMON ="\n"\
"=====================================================\n"\
"    DISPLAY CONTENTS OF PKI COMMON DICTIONARY\n"\
"====================================================="
PKI_DICTIONARY_MASTER="\n"\
"=====================================================\n"\
"    DISPLAY CONTENTS OF PKI MASTER DICTIONARY\n"\
"====================================================="
PKI_DICTIONARY_SLOTS="\n"\
"=====================================================\n"\
"    DISPLAY CONTENTS OF PKI SLOTS DICTIONARY\n"\
"====================================================="
PKI_DICTIONARY_SUBSYSTEM="\n"\
"=====================================================\n"\
"    DISPLAY CONTENTS OF PKI SUBSYSTEM DICTIONARY\n"\
"====================================================="
PKI_DICTIONARY_WEB_SERVER="\n"\
"=====================================================\n"\
"    DISPLAY CONTENTS OF PKI WEB SERVER DICTIONARY\n"\
"====================================================="
# NEVER print out 'sensitive' data dictionary!!!


# PKI Deployment Log Messages
PKI_VERBOSITY=\
"VERBOSITY FLAGS    CONSOLE MESSAGE LEVEL       LOG MESSAGE LEVEL\n"\
"=======================================================================\n"\
"  NONE             error|warning               error|warning|info\n"\
"  -v               error|warning|info          error|warning|info\n"\
"  -vv              error|warning|info          error|warning|info|debug\n"\
"  -vvv             error|warning|info|debug    error|warning|info|debug\n"\
" "

# PKI Deployment Error Messages
PKI_BADZIPFILE_ERROR_1 = "zipfile.BadZipFile:  %s!"
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
PKI_DIRECTORY_ALREADY_EXISTS_1 = "Directory '%s' already exists!"
PKI_DIRECTORY_ALREADY_EXISTS_NOT_A_DIRECTORY_1 = "Directory '%s' already "\
                                                 "exists BUT it is NOT a "\
                                                 "directory!"
PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 = "Directory '%s' is either "\
                                             "missing or is NOT a directory!"
PKI_FILE_ALREADY_EXISTS_1 = "File '%s' already exists!"
PKI_FILE_ALREADY_EXISTS_NOT_A_FILE_1 = "File '%s' already "\
                                       "exists BUT it is NOT a "\
                                       "file!"
PKI_FILE_MISSING_OR_NOT_A_FILE_1 = "File '%s' is either missing "\
                                   "or is NOT a regular file!"
PKI_FILE_NOT_A_WAR_FILE_1 = "File '%s' is NOT a war file!"
PKI_SECURITY_DATABASES_ALREADY_EXIST_3 = "Security databases '%s', '%s', "\
                                         "and/or '%s' already exist!"
PKI_SECURITY_DATABASES_DO_NOT_EXIST_3 = "Security databases '%s', '%s', "\
                                        "and/or '%s' do NOT exist!"
PKI_SUBSYSTEM_ALREADY_EXISTS_2 = "PKI subsystem '%s' for instance '%s' "\
                                 "already exists!"
PKI_SUBSYSTEM_DOES_NOT_EXIST_2 = "PKI subsystem '%s' for instance '%s' "\
                                 "does NOT exist!"

PKI_IOERROR_1 = "IOError:  %s!"
PKI_KEYERROR_1 = "KeyError:  %s!"
PKI_LARGEZIPFILE_ERROR_1 = "zipfile.LargeZipFile:  %s!"
PKI_MANIFEST_MESSAGE_1 = "generating manifest file called '%s'"
PKI_OSERROR_1 = "OSError:  %s!"
PKI_SHUTIL_ERROR_1 = "shutil.Error:  %s!"
PKI_SUBPROCESS_ERROR_1 = "subprocess.CalledProcessError:  %s!"
PKI_SYMLINK_ALREADY_EXISTS_1 = "Symlink '%s' already exists!"
PKI_SYMLINK_ALREADY_EXISTS_NOT_A_SYMLINK_1 = "Symlink '%s' already "\
                                             "exists BUT it is NOT a "\
                                             "symlink!"
PKI_SYMLINK_MISSING_OR_NOT_A_SYMLINK_1 = "Symlink '%s' is either missing "\
                                         "or is NOT a symbolic link!"
PKI_UNABLE_TO_PARSE_1 = "'Could not parse:  '%s'"
PKI_UNABLE_TO_CREATE_LOG_DIRECTORY_1 = "Could not create log directory '%s'!"
PKI_VERBOSITY_LEVELS_MESSAGE = "Only up to 3 levels of verbosity are supported!"


# PKI Deployment 'pkispawn' and 'pkidestroy' Messages
PKIDESTROY_BEGIN_MESSAGE_2 = "BEGIN destroying subsystem '%s' of "\
                             "instance '%s' . . ."
PKIDESTROY_END_MESSAGE_2 = "END destroying subsystem '%s' of "\
                           "instance '%s'"
PKIRESPAWN_BEGIN_MESSAGE_2 = "BEGIN respawning subsystem '%s' of "\
                             "instance '%s' . . ."
PKIRESPAWN_END_MESSAGE_2 = "END respawning subsystem '%s' of "\
                           "instance '%s'"
PKISPAWN_BEGIN_MESSAGE_2 = "BEGIN spawning subsystem '%s' of "\
                           "instance '%s' . . ."
PKISPAWN_END_MESSAGE_2 = "END spawning subsystem '%s' of "\
                         "instance '%s'"


# PKI Deployment "Helper" Messages
PKIHELPER_APACHE_INSTANCES_2 = "instance '%s' contains '%d' "\
                               "Apache PKI subsystems"
PKIHELPER_APPLY_SLOT_SUBSTITUTION_1 = "applying in-place "\
                                      "slot substitutions on '%s'"
PKIHELPER_CERTUTIL_MISSING_ISSUER_NAME = "certutil:  Missing "\
                                         "'-c issuer-name' option!"
PKIHELPER_CERTUTIL_MISSING_NICKNAME = "certutil:  Missing "\
                                      "'-n nickname' option!"
PKIHELPER_CERTUTIL_MISSING_NOISE_FILE = "certutil:  Missing "\
                                        "'-z noise-file' option!"
PKIHELPER_CERTUTIL_MISSING_PATH = "certutil:  Missing '-d path' option!"
PKIHELPER_CERTUTIL_MISSING_SERIAL_NUMBER = "certutil:  Missing "\
                                           "'-m serial-number' option!"
PKIHELPER_CERTUTIL_MISSING_SUBJECT = "certutil:  Missing '-s subject' option!"
PKIHELPER_CERTUTIL_MISSING_TOKEN = "certutil:  Missing '-h token' option!"
PKIHELPER_CERTUTIL_MISSING_TRUSTARGS = "certutil:  Missing "\
                                       "'-t trustargs' option!"
PKIHELPER_CERTUTIL_MISSING_VALIDITY_PERIOD = "certutil:  Missing "\
                                             "'-v months-valid' option!"
PKIHELPER_CERTUTIL_SELF_SIGNED_CERTIFICATE_1 = "executing '%s'"
PKIHELPER_CHMOD_2 = "chmod %o %s"
PKIHELPER_CHOWN_3 = "chown %s:%s %s"
PKIHELPER_CHOWN_H_3 = "chown -h %s:%s %s"
PKIHELPER_COPY_WITH_SLOT_SUBSTITUTION_2 = "copying '%s' --> '%s' "\
                                          "with slot substitution"
PKIHELPER_CP_P_2 = "cp -p %s %s"
PKIHELPER_CP_RP_2 = "cp -rp %s %s"
PKIHELPER_CREATE_SECURITY_DATABASES_1 = "executing '%s'"
PKIHELPER_DANGLING_SYMLINK_2 = "Dangling symlink '%s'-->'%s'"
PKIHELPER_DICTIONARY_MASTER_MISSING_KEY_1 = "KeyError:  Master dictionary "\
                                            "is missing the key called '%s'!"
PKIHELPER_DIRECTORY_IS_EMPTY_1 = "directory '%s' is empty"
PKIHELPER_DIRECTORY_IS_NOT_EMPTY_1 = "directory '%s' is NOT empty"
PKIHELPER_GID_2 = "GID of '%s' is %s"
PKIHELPER_GROUP_1 = "retrieving GID for '%s' . . ."
PKIHELPER_GROUP_ADD_2 = "adding GID '%s' for group '%s' . . ."
PKIHELPER_GROUP_ADD_DEFAULT_2 = "adding default GID '%s' for group '%s' . . ."
PKIHELPER_GROUP_ADD_GID_KEYERROR_1 = "KeyError:  pki_gid %s"
PKIHELPER_GROUP_ADD_KEYERROR_1 = "KeyError:  pki_group %s"
PKIHELPER_INVOKE_JYTHON_3 = "executing 'export %s;"\
                            "jython %s %s <master_dictionary>'"
PKIHELPER_IS_A_DIRECTORY_1 = "'%s' is a directory"
PKIHELPER_IS_A_FILE_1 = "'%s' is a file"
PKIHELPER_IS_A_SYMLINK_1 = "'%s' is a symlink"
PKIHELPER_JAR_XF_C_2 = "jar -xf %s -C %s"
PKIHELPER_LINK_S_2 = "ln -s %s %s"
PKIHELPER_MKDIR_1 = "mkdir -p %s"
PKIHELPER_MODIFY_DIR_1 = "modifying '%s'"
PKIHELPER_MODIFY_FILE_1 = "modifying '%s'"
PKIHELPER_MODIFY_SYMLINK_1 = "modifying '%s'"
PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_EXTERNAL_CA = "cloned CAs and external "\
                                                 "CAs MUST be MUTUALLY "\
                                                 "EXCLUSIVE in '%s'"
PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_EXTERNAL_SUB_CA = "cloned CAs, external "\
                                                     "CAs, and subordinate CAs"\
                                                     "MUST ALL be MUTUALLY "\
                                                     "EXCLUSIVE in '%s'"
PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_SUB_CA = "cloned CAs and subordinate "\
                                            "CAs MUST be MUTUALLY "\
                                            "EXCLUSIVE in '%s'"
PKIHELPER_MUTUALLY_EXCLUSIVE_EXTERNAL_SUB_CA = "external CAs and subordinate "\
                                               "CAs MUST be MUTUALLY "\
                                               "EXCLUSIVE in '%s'"
PKIHELPER_NOISE_FILE_2 = "generating noise file called '%s' and "\
                         "filling it with '%d' random bytes"
PKIHELPER_PASSWORD_CONF_1 = "generating '%s'"
PKIHELPER_PKI_SUBSYSTEM_INSTANCES_2 = "instance '%s' contains '%d' "\
                                      "PKI subsystems"
PKIHELPER_REMOVE_FILTER_SECTION_1 = "removing filter section from '%s'"
PKIHELPER_RM_F_1 = "rm -f %s"
PKIHELPER_RM_RF_1 = "rm -rf %s"
PKIHELPER_RMDIR_1 = "rmdir %s"
PKIHELPER_SET_MODE_1 = "setting ownerships, permissions, and acls on '%s'"
PKIHELPER_SLOT_SUBSTITUTION_2 = "slot substitution: '%s' ==> '%s'"
PKIHELPER_SYSTEMD_COMMAND_1 = "executing '%s'"
PKIHELPER_TOMCAT_INSTANCES_2 = "instance '%s' contains '%d' "\
                               "Tomcat PKI subsystems"
PKIHELPER_TOUCH_1 = "touch %s"
PKIHELPER_UID_2 = "UID of '%s' is %s"
PKIHELPER_UNDEFINED_ADMIN_PASSWORD_1 =\
    "A value for 'pki_admin_password' MUST be defined in '%s'"
PKIHELPER_UNDEFINED_BACKUP_PASSWORD_1 =\
    "A value for 'pki_backup_password' MUST be defined in '%s'"
PKIHELPER_UNDEFINED_CLIENT_PKCS12_PASSWORD_1 =\
    "A value for 'pki_client_pkcs12_password' MUST be defined in '%s'"
PKIHELPER_UNDEFINED_DS_PASSWORD_1 =\
    "A value for 'pki_ds_password' MUST be defined in '%s'"
PKIHELPER_UNDEFINED_PKCS12_PASSWORD_1 =\
    "A value for 'pki_pkcs12_password' MUST be defined in '%s'"
PKIHELPER_UNDEFINED_SECURITY_DOMAIN_PASSWORD_1 =\
    "A value for 'pki_security_domain_password' MUST be defined in '%s'"
PKIHELPER_USER_1 = "retrieving UID for '%s' . . ."
PKIHELPER_USER_ADD_2 = "adding UID '%s' for user '%s' . . ."
PKIHELPER_USER_ADD_DEFAULT_2 = "adding default UID '%s' for user '%s' . . ."
PKIHELPER_USER_ADD_KEYERROR_1 = "KeyError:  pki_user %s"
PKIHELPER_USER_ADD_UID_KEYERROR_1 = "KeyError:  pki_uid %s"


# PKI Deployment Jython "Scriptlet" Messages
# (MUST contain NO embedded formats since Jython 2.2 does not support logging!)
PKI_JYTHON_ADMIN_CERT_EXPORT = "exporting Admin Certificate from "\
                               "NSS client security database:"
PKI_JYTHON_ADMIN_CERT_IMPORT = "importing Admin Certificate into "\
                               "NSS client security database:"
PKI_JYTHON_ADMIN_CERT_SAVE = "saving Admin Certificate to file:"
PKI_JYTHON_CDATA_TAG = "tag:"
PKI_JYTHON_CDATA_CERT = "cert:"
PKI_JYTHON_CDATA_REQUEST = "request:"
PKI_JYTHON_CHMOD = "performing chmod:"
PKI_JYTHON_CLONED_PKI_SUBSYSTEM = "Cloned"
PKI_JYTHON_CONFIGURING_PKI_DATA = "configuring PKI configuration data for"
PKI_JYTHON_CONSTRUCTING_PKI_DATA = "constructing PKI configuration data for"
PKI_JYTHON_CRMF_SUPPORT_ONLY = "only the 'crmf' certificate request type "\
                               "is currently supported"
PKI_JYTHON_IS_DUALKEY = "dualkey = true"
PKI_JYTHON_EXCEPTION_PARSER = "Problem parsing"
PKI_JYTHON_EXTERNAL_CA = "External"
PKI_JYTHON_INDENTATION_0 = "pkispawn    : JYTHON  "
PKI_JYTHON_INDENTATION_1 = "pkispawn    : JYTHON   ..."
PKI_JYTHON_INDENTATION_2 = "pkispawn    : JYTHON   ......."
PKI_JYTHON_INDENTATION_3 = "pkispawn    : JYTHON   ..........."
PKI_JYTHON_INDENTATION_4 = "pkispawn    : JYTHON   ..............."
PKI_JYTHON_INITIALIZATION_ERROR = "INITIALIZATION ERROR:"
PKI_JYTHON_INITIALIZING_REST_CLIENT = "initializing REST client via"
PKI_JYTHON_INITIALIZING_TOKEN = "initializing token located in"
PKI_JYTHON_JAVA_CONFIGURATION_EXCEPTION =\
    "Exception from Java Configuration Servlet:"
PKI_JYTHON_LOG_INTO_TOKEN = "logging into token located in"
PKI_JYTHON_LOGIN_EXCEPTION = "login Exception:"
PKI_JYTHON_RESPONSE_ADMIN_CERT = "adminCert:"
PKI_JYTHON_RESPONSE_STATUS = "status:"
PKI_JYTHON_TOKEN_LOGIN_EXCEPTION = "Exception in logging into token:"
PKI_JYTHON_NOT_YET_IMPLEMENTED = "NOT YET IMPLEMENTED"
PKI_JYTHON_SUBORDINATE_CA = "Subordinate"


# PKI Deployment "Scriptlet" Messages
ADMIN_DOMAIN_DESTROY_1 = "depopulating '%s'"
ADMIN_DOMAIN_RESPAWN_1 = "repopulating '%s'"
ADMIN_DOMAIN_SPAWN_1 = "populating '%s'"
CONFIGURATION_DESTROY_1 = "unconfiguring '%s'"
CONFIGURATION_RESPAWN_1 = "reconfiguring '%s'"
CONFIGURATION_SPAWN_1 = "configuring '%s'"
FINALIZATION_DESTROY_1 = "finalizing '%s'"
FINALIZATION_RESPAWN_1 = "finalizing '%s'"
FINALIZATION_SPAWN_1 = "finalizing '%s'"
INITIALIZATION_DESTROY_1 = "initializing '%s'"
INITIALIZATION_RESPAWN_1 = "initializing '%s'"
INITIALIZATION_SPAWN_1 = "initializing '%s'"
INSTANCE_DESTROY_1 = "depopulating '%s'"
INSTANCE_RESPAWN_1 = "repopulating '%s'"
INSTANCE_SPAWN_1 = "populating '%s'"
RESIDUAL_DESTROY_1 = "depopulating '%s'"
RESIDUAL_RESPAWN_1 = "repopulating '%s'"
RESIDUAL_SPAWN_1 = "populating '%s'"
SECURITY_DATABASES_DESTROY_1 = "removing '%s'"
SECURITY_DATABASES_RESPAWN_1 = "regenerating '%s'"
SECURITY_DATABASES_SPAWN_1 = "generating '%s'"
SLOT_ASSIGNMENT_DESTROY_1 = "unassigning slots for '%s'"
SLOT_ASSIGNMENT_RESPAWN_1 = "reassigning slots for '%s'"
SLOT_ASSIGNMENT_SPAWN_1 = "assigning slots for '%s'"
SUBSYSTEM_DESTROY_1 = "depopulating '%s'"
SUBSYSTEM_RESPAWN_1 = "repopulating '%s'"
SUBSYSTEM_SPAWN_1 = "populating '%s'"
WAR_EXPLOSION_DESTROY_1 = "removing '%s'"
WAR_EXPLOSION_RESPAWN_1 = "redeploying '%s'"
WAR_EXPLOSION_SPAWN_1 = "deploying '%s'"
