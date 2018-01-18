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
PKI_DICTIONARY_DEFAULT = '''
=====================================================
    DISPLAY CONTENTS OF PKI DEFAULT DICTIONARY
=====================================================
'''
PKI_DICTIONARY_MASTER = '''
=====================================================
    DISPLAY CONTENTS OF PKI MASTER DICTIONARY
=====================================================
'''
PKI_DICTIONARY_SLOTS = '''
=====================================================
    DISPLAY CONTENTS OF PKI SLOTS DICTIONARY
=====================================================
'''
PKI_DICTIONARY_SUBSYSTEM = '''
=====================================================
    DISPLAY CONTENTS OF PKI SUBSYSTEM DICTIONARY
=====================================================
'''
PKI_DICTIONARY_WEB_SERVER = '''
=====================================================
    DISPLAY CONTENTS OF PKI WEB SERVER DICTIONARY
=====================================================
'''
# NEVER print out 'sensitive' data dictionary!!!


# PKI Deployment Log Messages
PKI_VERBOSITY = '''
VERBOSITY FLAGS    CONSOLE MESSAGE LEVEL       LOG MESSAGE LEVEL
=======================================================================
  NONE             error|warning               error|warning|info|debug
  -v               error|warning|info          error|warning|info|debug
  -vv              error|warning|info|debug    error|warning|info|debug

'''


# PKI Deployment Error Messages
PKI_BADZIPFILE_ERROR_1 = "zipfile.BadZipFile:  %s!"
PKI_RUN_INSTALLATION_STEP_TWO = '''
      Please obtain the necessary certificate(s) for this subsystem,
      and run installation step two.'''
PKI_DIRECTORY_ALREADY_EXISTS_1 = "Directory '%s' already exists!"
PKI_DIRECTORY_ALREADY_EXISTS_NOT_A_DIRECTORY_1 = \
    "Directory '%s' already exists BUT it is NOT a directory!"
PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 = \
    "Directory '%s' is either missing or is NOT a directory!"
PKI_DNS_DOMAIN_NOT_SET = \
    "DNS domain name has not been set - using the hostname instead."
PKI_FILE_ALREADY_EXISTS_1 = "File '%s' already exists!"
PKI_FILE_ALREADY_EXISTS_NOT_A_FILE_1 = \
    "File '%s' already exists BUT it is NOT a file!"
PKI_FILE_MISSING_OR_NOT_A_FILE_1 = \
    "File '%s' is either missing or is NOT a regular file!"
PKI_FILE_NOT_A_WAR_FILE_1 = "File '%s' is NOT a war file!"
PKI_INSTANCE_DOES_NOT_EXIST_1 = "PKI instance '%s' does NOT exist!"
PKI_SECURITY_DATABASES_ALREADY_EXIST_3 = \
    "Security databases '%s', '%s', and/or '%s' already exist!"
PKI_SECURITY_DATABASES_DO_NOT_EXIST_3 = \
    "Security databases '%s', '%s', and/or '%s' do NOT exist!"
PKI_SUBSYSTEM_NOT_INSTALLED_1 = "Package pki-%s is NOT installed!"
PKI_SUBSYSTEM_ALREADY_EXISTS_2 = \
    "PKI subsystem '%s' for instance '%s' already exists!"
PKI_SUBSYSTEM_DOES_NOT_EXIST_2 = \
    "PKI subsystem '%s' for instance '%s' does NOT exist!"
PKI_EXTERNAL_UNSUPPORTED_1 = \
    "PKI '%s' subsystems do NOT support the 'pki_external' parameter!"
PKI_EXTERNAL_STEP_TWO_UNSUPPORTED_1 = \
    "PKI '%s' subsystems do NOT support the 'pki_external_step_two' parameter!"
PKI_STANDALONE_UNSUPPORTED_1 = \
    "PKI '%s' subsystems do NOT support the 'pki_standalone' parameter!"
PKI_SUBORDINATE_UNSUPPORTED_1 = \
    "PKI '%s' subsystems do NOT support the 'pki_subordinate' parameter!"

PKI_IOERROR_1 = "IOError:  %s!"
PKI_KEYERROR_1 = "KeyError:  %s!"
PKI_LARGEZIPFILE_ERROR_1 = "zipfile.LargeZipFile:  %s!"
PKI_ARCHIVE_CONFIG_MESSAGE_1 = "archiving configuration into '%s'"
PKI_ARCHIVE_MANIFEST_MESSAGE_1 = "archiving manifest into '%s'"
PKI_OSERROR_1 = "OSError:  %s!"
PKI_SHUTIL_ERROR_1 = "shutil.Error:  %s!"
PKI_SUBPROCESS_ERROR_1 = "subprocess.CalledProcessError:  %s!"
PKI_SYMLINK_ALREADY_EXISTS_1 = "Symlink '%s' already exists!"
PKI_SYMLINK_ALREADY_EXISTS_NOT_A_SYMLINK_1 = \
    "Symlink '%s' already exists BUT it is NOT a symlink!"
PKI_SYMLINK_MISSING_OR_NOT_A_SYMLINK_1 = \
    "Symlink '%s' is either missing or is NOT a symbolic link!"
PKI_UNABLE_TO_PARSE_1 = "'Could not parse:  '%s'"
PKI_UNABLE_TO_CREATE_LOG_DIRECTORY_1 = "Could not create log directory '%s'!"


# PKI Deployment 'pkispawn' and 'pkidestroy' Messages
PKIDESTROY_BEGIN_MESSAGE_2 = \
    "BEGIN destroying subsystem '%s' of instance '%s' . . ."
PKIDESTROY_END_MESSAGE_2 = "END destroying subsystem '%s' of instance '%s'"
PKIDESTROY_EPILOG = '''
REMINDER:

    The default PKI instance path will be calculated and placed in front
    of the mandatory '-i <instance>' parameter, and the values that reside
    in deployment configuration file that was most recently used
    by this instance's 'pkispawn' (or 'pkispawn -u') command will be
    utilized by 'pkidestroy' to remove this instance.

    Finally, if an optional '-p <prefix>' is defined, this value WILL be
    prepended to the default PKI instance path which is placed in front
    of the specified '-i <instance>' parameter.
''' + PKI_VERBOSITY
PKISPAWN_BEGIN_MESSAGE_2 = \
    "BEGIN spawning subsystem '%s' of instance '%s' . . ."
PKISPAWN_END_MESSAGE_2 = \
    "END spawning subsystem '%s' of instance '%s'"
PKISPAWN_EPILOG = """
REMINDER:

    If two or more Tomcat PKI 'instances' are specified via
    separate configuration files, remember that the following parameters
    MUST differ between PKI 'instances':

        Tomcat:  'pki_instance_name', 'pki_http_port', 'pki_https_port',
                 'pki_ajp_port', and 'pki_tomcat_server_port'

    Finally, if an optional '-p <prefix>' is defined, this value WILL NOT
    be prepended in front of the mandatory '-f <configuration_file>'.
""" + PKI_VERBOSITY
PKISPAWN_INTERACTIVE_INSTALLATION = '''
IMPORTANT:

    Interactive installation currently only exists for very basic deployments!

    For example, deployments intent upon using advanced features such as:

        * Cloning,
        * Elliptic Curve Cryptography (ECC),
        * External CA,
        * Hardware Security Module (HSM),
        * Subordinate CA,
        * etc.,

    must provide the necessary override parameters in a separate
    configuration file.

    Run 'man pkispawn' for details.
'''


# PKI Deployment "Helper" Messages
PKIHELPER_APPLY_SLOT_SUBSTITUTION_1 = \
    "applying in-place slot substitutions on '%s'"
PKIHELPER_CERTUTIL_GENERATE_CSR_1 = "executing '%s'"
PKIHELPER_CERTUTIL_INVALID_KEY_TYPE_1 = \
    "certutil:  Invalid key type '%s'; valid types are 'ecc' or 'rsa'!"
PKIHELPER_CERTUTIL_MISSING_INPUT_FILE = \
    "certutil:  Missing '-i input-file' option!"
PKIHELPER_CERTUTIL_MISSING_ISSUER_NAME = \
    "certutil:  Missing '-c issuer-name' option!"
PKIHELPER_CERTUTIL_MISSING_KEY_TYPE = \
    "certutil:  Missing '-k key-type-or-id' option (must be 'ecc' or 'rsa')!"
PKIHELPER_CERTUTIL_MISSING_KEY_SIZE = \
    "certutil:  Missing '-g keysize' option!"
PKIHELPER_CERTUTIL_MISSING_CURVE_NAME = \
    "certutil:  Missing '-q curve-name' option!"
PKIHELPER_CERTUTIL_MISSING_NICKNAME = \
    "certutil:  Missing '-n nickname' option!"
PKIHELPER_CERTUTIL_MISSING_NOISE_FILE = \
    "certutil:  Missing '-z noise-file' option!"
PKIHELPER_CERTUTIL_MISSING_PASSWORD_FILE = \
    "certutil:  Missing '-f password-file' option!"
PKIHELPER_CERTUTIL_MISSING_PATH = "certutil:  Missing '-d path' option!"
PKIHELPER_CERTUTIL_MISSING_SERIAL_NUMBER = \
    "certutil:  Missing '-m serial-number' option!"
PKIHELPER_CERTUTIL_MISSING_SUBJECT = "certutil:  Missing '-s subject' option!"
PKIHELPER_CERTUTIL_MISSING_TOKEN = "certutil:  Missing '-h token' option!"
PKIHELPER_CERTUTIL_MISSING_TRUSTARGS = \
    "certutil:  Missing '-t trustargs' option!"
PKIHELPER_CERTUTIL_MISSING_VALIDITY_PERIOD = \
    "certutil:  Missing '-v months-valid' option!"
PKIHELPER_CERTUTIL_SELF_SIGNED_CERTIFICATE_1 = "executing '%s'"
PKIHELPER_CHMOD_2 = "chmod %o %s"
PKIHELPER_CHOWN_3 = "chown %s:%s %s"
PKIHELPER_CHOWN_H_3 = "chown -h %s:%s %s"
PKIHELPER_COMMAND_LINE_PARAMETER_MISMATCH_2 = \
    "the command-line parameter '%s' DOES NOT match the "\
    "configuration file value '%s'!"
PKIHELPER_COPY_WITH_SLOT_SUBSTITUTION_2 = \
    "copying '%s' --> '%s' with slot substitution"
PKIHELPER_CP_P_2 = "cp -p %s %s"
PKIHELPER_CP_RP_2 = "cp -rp %s %s"
PKIHELPER_CREATE_SECURITY_DATABASES_1 = "executing '%s'"
PKIHELPER_DANGLING_SYMLINK_2 = "Dangling symlink '%s'-->'%s'"
PKIHELPER_DICTIONARY_MASTER_MISSING_KEY_1 = \
    "KeyError:  Master dictionary is missing the key called '%s'!"
PKIHELPER_DICTIONARY_INTERPOLATION_1 = \
    "Deployment file could not be parsed correctly.  This might be because of "\
    "unescaped '%%' characters.  You must escape '%%' characters in deployment"\
    " files (example - 'setting=foo%%%%bar')."
PKIHELPER_DICTIONARY_INTERPOLATION_2 = "Interpolation error (%s)"
PKIHELPER_DIRECTORY_IS_EMPTY_1 = "directory '%s' is empty"
PKIHELPER_DIRECTORY_IS_NOT_EMPTY_1 = "directory '%s' is NOT empty"
PKIHELPER_GID_2 = "GID of '%s' is %s"
PKIHELPER_GROUP_1 = "retrieving GID for '%s' . . ."
PKIHELPER_GROUP_ADD_2 = "adding GID '%s' for group '%s' . . ."
PKIHELPER_GROUP_ADD_DEFAULT_2 = "adding default GID '%s' for group '%s' . . ."
PKIHELPER_GROUP_ADD_GID_KEYERROR_1 = "KeyError:  pki_gid %s"
PKIHELPER_GROUP_ADD_KEYERROR_1 = "KeyError:  pki_group %s"
PKIHELPER_FIPS_MODE_IS_ENABLED = "FIPS mode is enabled on this operating "\
    "system."
PKIHELPER_FIPS_MODE_IS_NOT_ENABLED = "FIPS mode is NOT enabled on this "\
    "operating system."
PKIHELPER_HSM_CLONES_MUST_SHARE_HSM_MASTER_PRIVATE_KEYS = \
    "Since clones using Hardware Security Modules (HSMs) must share their "\
    "master's private keys, the 'pki_clone_pkcs12_path' and "\
    "'pki_clone_pkcs12_password' variables may not be utilized with HSMs."
PKIHELPER_HSM_KEYS_CANNOT_BE_BACKED_UP_TO_PKCS12_FILES = \
    "Since Hardware Security Modules (HSMs) do not allow their private keys "\
    "to be extracted to PKCS #12 files, the 'pki_backup_keys' and "\
    "'pki_backup_password' variables may not be utilized with HSMs.\n"\
    "Please contact the HSM vendor regarding their specific backup mechanism."
PKIHELPER_INVALID_SELINUX_CONTEXT_FOR_PORT = \
    "port %s has invalid selinux context %s"
PKIHELPER_IS_A_DIRECTORY_1 = "'%s' is a directory"
PKIHELPER_IS_A_FILE_1 = "'%s' is a file"
PKIHELPER_IS_A_SYMLINK_1 = "'%s' is a symlink"
PKIHELPER_JAR_XF_C_2 = "jar -xf %s -C %s"
PKIHELPER_KRACONNECTOR_UPDATE_CONTACT = \
    "contacting the CA to update the KRA connector"
PKIHELPER_KRACONNECTOR_UPDATE_FAILURE = "Failed to update KRA connector on CA"
PKIHELPER_KRACONNECTOR_UPDATE_FAILURE_2 = \
    "Failed to update KRA connector for %s:%s"
PKIHELPER_KRACONNECTOR_DEREGISTER_FAILURE_4 = \
    "Failed to deregister KRA connector %s:%s from CA %s:%s"
PKIHELPER_LINK_S_2 = "ln -s %s %s"
PKIHELPER_MKDIR_1 = "mkdir -p %s"
PKIHELPER_MODIFY_DIR_1 = "modifying '%s'"
PKIHELPER_MODIFY_FILE_1 = "modifying '%s'"
PKIHELPER_MODIFY_SYMLINK_1 = "modifying '%s'"
PKIHELPER_MODUTIL_MISSING_LIBFILE = \
    "modutil:  Missing '-libfile libfile' option!"
PKIHELPER_MODUTIL_MISSING_MODULENAME = \
    "modutil:  Missing '-add modulename' option!"
PKIHELPER_MODUTIL_MISSING_PATH = "modutil:  Missing '-dbdir path' option!"
PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_EXTERNAL_CA = \
    "cloned CAs and external CAs MUST be MUTUALLY EXCLUSIVE in '%s'"
PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_EXTERNAL_SUB_CA = \
    "cloned CAs, external CAs, and subordinate CAs MUST ALL be MUTUALLY "\
    "EXCLUSIVE in '%s'"
PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_STANDALONE_PKI = \
    "cloned PKIs and stand-alone PKIs MUST be MUTUALLY EXCLUSIVE in '%s'"
PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_SUB_CA = \
    "cloned CAs and subordinate CAs MUST be MUTUALLY EXCLUSIVE in '%s'"
PKIHELPER_MUTUALLY_EXCLUSIVE_EXTERNAL_SUB_CA = \
    "external CAs and subordinate CAs MUST be MUTUALLY EXCLUSIVE in '%s'"
PKIHELPER_NAMESPACE_COLLISION_2 = \
    "PKI instance '%s' would produce a namespace collision with '%s'!"
PKIHELPER_NAMESPACE_RESERVED_NAME_2 = \
    "PKI instance '%s' is already a reserved name under '%s'!"
PKIHELPER_NCIPHER_RESTART_1 = "executing '%s'"
PKIHELPER_NOISE_FILE_2 = \
    "generating noise file called '%s' and filling it with '%d' random bytes"
PKIHELPER_PASSWORD_CONF_1 = "generating '%s'"
PKIHELPER_PASSWORD_NOT_FOUND_1 = "no password found for '%s'!"
PKIHELPER_PK12UTIL_MISSING_DBPWFILE = \
    "pk12util missing -k db-password-file option!"
PKIHELPER_PK12UTIL_MISSING_NICKNAME = \
    "pk12util missing -n nickname option!"
PKIHELPER_PK12UTIL_MISSING_OUTFILE = \
    "pk12util missing -o output-file option!"
PKIHELPER_PK12UTIL_MISSING_PWFILE = \
    "pk12util missing -w pw-file option!"
PKIHELPER_REGISTER_SECURITY_MODULE_1 = "executing '%s'"
PKIHELPER_REGISTERED_SECURITY_MODULE_CHECK_1 = "executing '%s'"
PKIHELPER_REGISTERED_SECURITY_MODULE_1 = \
    "security module '%s' is already registered."
PKIHELPER_UNREGISTERED_SECURITY_MODULE_1 = \
    "security module '%s' is not registered."

PKIHELPER_PKI_INSTANCE_SUBSYSTEMS_2 = \
    "instance '%s' contains '%d' PKI subsystems"
PKIHELPER_REMOVE_FILTER_SECTION_1 = "removing filter section from '%s'"
PKIHELPER_RM_F_1 = "rm -f %s"
PKIHELPER_RM_RF_1 = "rm -rf %s"
PKIHELPER_RMDIR_1 = "rmdir %s"
PKIHELPER_SECURITY_DOMAIN_CONTACT_1 = \
    "contacting the security domain master to update security domain '%s'"
PKIHELPER_SECURITY_DOMAIN_GET_TOKEN_FAILURE_2 = \
    "Failed to get installation token from security domain '%s:%s'"
PKIHELPER_SECURITY_DOMAIN_UNDEFINED = \
    "No security domain defined.\n"\
    "If this is an unconfigured instance, then that is OK.\n"\
    "Otherwise, manually delete the entry from the security domain master."
PKIHELPER_SECURITY_DOMAIN_UNREACHABLE_1 = \
    "security domain '%s' may be offline or unreachable!"
PKIHELPER_SECURITY_DOMAIN_UNREGISTERED_2 = \
    "this '%s' entry may not be registered with security domain '%s'!"
PKIHELPER_SECURITY_DOMAIN_UPDATE_FAILURE_2 = \
    "this '%s' entry will NOT be deleted from security domain '%s'!"
PKIHELPER_SECURITY_DOMAIN_UPDATE_FAILURE_3 = \
    "updateDomainXML FAILED to delete this '%s' entry from "\
    "security domain '%s': '%s'"
PKIHELPER_SECURITY_DOMAIN_UPDATE_SUCCESS_2 = \
    "updateDomainXML SUCCESSFULLY deleted this '%s' entry from "\
    "security domain '%s'"
PKIHELPER_SELINUX_DISABLED = "Selinux is disabled.  Not checking port contexts"
PKIHELPER_SERVERCERTNICK_CONF_2 = "Overwriting contents of '%s' with '%s'"
PKIHELPER_SET_MODE_1 = "setting ownerships, permissions, and acls on '%s'"
PKIHELPER_SLOT_SUBSTITUTION_2 = "slot substitution: '%s' ==> '%s'"
PKIHELPER_SSLGET_OUTPUT_1 = '''
    Dump of 'sslget' output:
    =====================================================
    %s
    =====================================================
'''
PKIHELPER_SYSTEMD_COMMAND_1 = "executing '%s'"
PKIHELPER_TOMCAT_INSTANCE_SUBSYSTEMS_2 = \
    "instance '%s' contains '%d' Tomcat PKI subsystems"
PKIHELPER_TOMCAT_INSTANCES_2 = \
    "PKI Tomcat registry '%s' contains '%d' Tomcat PKI instances"
PKIHELPER_TOUCH_1 = "touch %s"
PKIHELPER_TPSCONNECTOR_UPDATE_CONTACT = \
    "contacting the TKS to update the TPS connector"
PKIHELPER_TPSCONNECTOR_UPDATE_FAILURE = "Failed to update TPS connector on TKS"
PKIHELPER_TPSCONNECTOR_UPDATE_FAILURE_2 = \
    "Failed to update TPS connector for %s:%s"
PKIHELPER_UID_2 = "UID of '%s' is %s"
PKIHELPER_UNDEFINED_CA_HOST_PORT = "CA Host or Port is undefined"
PKIHELPER_UNDEFINED_CLIENT_DATABASE_PASSWORD_2 = \
    "Either a value for '%s' MUST be defined in '%s', or "\
    "the randomly generated client pin MUST be used"
PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 = \
    "A value for '%s' MUST be defined in '%s'"
PKIHELPER_UNDEFINED_HSM_TOKEN = \
    "A value other than 'internal' MUST be defined for 'pki_token_name'"
PKIHELPER_UNDEFINED_SUBSYSTEM_NICKNAME = "subsystem nickname not defined"
PKIHELPER_UNDEFINED_TKS_HOST_PORT = "TKS Host or Port is undefined"
PKIHELPER_UNDEFINED_TOKEN_PASSWD_1 = "Password for token '%s' not defined"
PKIHELPER_USER_1 = "retrieving UID for '%s' . . ."
PKIHELPER_USER_ADD_2 = "adding UID '%s' for user '%s' . . ."
PKIHELPER_USER_ADD_DEFAULT_2 = "adding default UID '%s' for user '%s' . . ."
PKIHELPER_USER_ADD_KEYERROR_1 = "KeyError:  pki_user %s"
PKIHELPER_USER_ADD_UID_KEYERROR_1 = "KeyError:  pki_uid %s"

PKI_CONFIG_ADMIN_CERT_SAVE_2 = "saving %s Admin Certificate to file: %s"
PKI_CONFIG_ADMIN_CERT_ATOB_1 = "converting %s Admin Certificate to binary:"
PKI_CONFIG_CDATA_TAG = "tag:"
PKI_CONFIG_CDATA_CERT = "cert:"
PKI_CONFIG_CDATA_REQUEST = "request:"
PKI_CONFIG_CONFIGURING_PKI_DATA = "configuring PKI configuration data."
PKI_CONFIG_CONSTRUCTING_PKI_DATA = "constructing PKI configuration data."
PKI_CONFIG_PKCS10_SUPPORT_ONLY = \
    "only the 'pkcs10' certificate request type is currently supported"
PKI_CONFIG_EXTERNAL_CA_LOAD = \
    "loading external CA signing certificate from file:"
PKI_CONFIG_EXTERNAL_CA_CHAIN_LOAD = \
    "loading external CA signing certificate chain from file:"
PKI_CONFIG_EXTERNAL_CERT_LOAD_KRA_STORAGE = \
    "loading external CA signed KRA Storage certificate from file:"
PKI_CONFIG_EXTERNAL_CERT_LOAD_KRA_TRANSPORT = \
    "loading external CA signed KRA Transport certificate from file:"
PKI_CONFIG_EXTERNAL_CERT_LOAD_OCSP_SIGNING = \
    "loading external CA signed OCSP Signing certificate from file:"
PKI_CONFIG_EXTERNAL_CERT_LOAD_PKI_SSLSERVER_1 = \
    "loading external CA signed %s SSL Server certificate from file:"
PKI_CONFIG_EXTERNAL_CERT_LOAD_PKI_SUBSYSTEM_1 = \
    "loading external CA signed %s Subsystem certificate from file:"
PKI_CONFIG_EXTERNAL_CERT_LOAD_PKI_AUDIT_SIGNING_1 = \
    "loading external CA signed %s Audit Signing certificate from file:"
PKI_CONFIG_EXTERNAL_CSR_SAVE = "saving CA Signing CSR to file:"
PKI_CONFIG_EXTERNAL_CSR_SAVE_KRA_STORAGE_1 = (
    "saving KRA Storage CSR to file: %s")
PKI_CONFIG_EXTERNAL_CSR_SAVE_KRA_TRANSPORT_1 = (
    "saving KRA Transport CSR to file: %s")
PKI_CONFIG_EXTERNAL_CSR_SAVE_OCSP_SIGNING_1 = (
    "saving OCSP Signing CSR to file: %s")
PKI_CONFIG_EXTERNAL_CSR_SAVE_PKI_ADMIN_2 = "saving %s Admin CSR to file: '%s'"
PKI_CONFIG_EXTERNAL_CSR_SAVE_PKI_AUDIT_SIGNING_2 = \
    "saving %s Audit Signing CSR to file: %s"
PKI_CONFIG_EXTERNAL_CSR_SAVE_PKI_SSLSERVER_2 = (
    "saving %s SSL Server CSR to file: %s")
PKI_CONFIG_EXTERNAL_CSR_SAVE_PKI_SUBSYSTEM_2 = (
    "saving %s Subsystem CSR to file: %s")
PKI_CONFIG_JAVA_CONFIGURATION_EXCEPTION = \
    "Exception from Java Configuration Servlet:"
PKI_CONFIG_RESPONSE_ADMIN_CERT = "adminCert:"
PKI_CONFIG_RESPONSE_STATUS = "status:"
PKI_CONFIG_NOT_YET_IMPLEMENTED_1 = " %s NOT YET IMPLEMENTED"
PKI_CHECK_STATUS_MESSAGE = '''
      To check the status of the subsystem:
            systemctl status pki-tomcatd@%s.service'''
PKI_ACCESS_URL = '''
      The URL for the subsystem is:
            https://%s:%s/%s'''
PKI_INSTANCE_RESTART_MESSAGE = '''
      To restart the subsystem:
            systemctl restart pki-tomcatd@%s.service'''


PKI_SPAWN_INFORMATION_HEADER = '''
    ==========================================================================
                                INSTALLATION SUMMARY\n\
    ==========================================================================
'''

PKI_SPAWN_INFORMATION_FOOTER = '''
    ==========================================================================
'''
PKI_SYSTEM_BOOT_STATUS_MESSAGE = '''
      PKI instances will be %s upon system boot'''


# PKI Deployment "Scriptlet" Messages
ADMIN_DOMAIN_DESTROY_1 = "depopulating '%s'"
ADMIN_DOMAIN_SPAWN_1 = "populating '%s'"
CONFIGURATION_DESTROY_1 = "unconfiguring '%s'"
CONFIGURATION_SPAWN_1 = "configuring '%s'"
FINALIZATION_DESTROY_1 = "finalizing '%s'"
FINALIZATION_SPAWN_1 = "finalizing '%s'"
INITIALIZATION_DESTROY_1 = "initializing '%s'"
INITIALIZATION_SPAWN_1 = "initializing '%s'"
INSTANCE_DESTROY_1 = "depopulating '%s'"
INSTANCE_SPAWN_1 = "populating '%s'"
RESIDUAL_DESTROY_1 = "depopulating '%s'"
RESIDUAL_SPAWN_1 = "populating '%s'"
SECURITY_DATABASES_DESTROY_1 = "removing '%s'"
SECURITY_DATABASES_SPAWN_1 = "generating '%s'"
SELINUX_DESTROY_1 = "depopulating '%s'"
SELINUX_SPAWN_1 = "populating '%s'"
SELINUX_DISABLED_DESTROY_1 = "selinux disabled. skipping unlabelling '%s'"
SELINUX_DISABLED_SPAWN_1 = "selinux disabled. skipping labelling '%s'"
SLOT_ASSIGNMENT_DESTROY_1 = "unassigning slots for '%s'"
SLOT_ASSIGNMENT_SPAWN_1 = "assigning slots for '%s'"
SUBSYSTEM_DESTROY_1 = "depopulating '%s'"
SUBSYSTEM_SPAWN_1 = "populating '%s'"
WEBAPP_DEPLOYMENT_DESTROY_1 = "removing '%s'"
WEBAPP_DEPLOYMENT_SPAWN_1 = "deploying '%s'"
SKIP_ADMIN_DOMAIN_SPAWN_1 = "skip populating '%s'"
SKIP_CONFIGURATION_SPAWN_1 = "skip configuring '%s'"
SKIP_FINALIZATION_SPAWN_1 = "skip finalizing '%s'"
SKIP_INITIALIZATION_SPAWN_1 = "skip initializing '%s'"
SKIP_INSTANCE_SPAWN_1 = "skip populating '%s'"
SKIP_RESIDUAL_SPAWN_1 = "skip populating '%s'"
SKIP_SECURITY_DATABASES_SPAWN_1 = "skip generating '%s'"
SKIP_SELINUX_SPAWN_1 = "skip populating '%s'"
SKIP_SLOT_ASSIGNMENT_SPAWN_1 = "skip assigning slots for '%s'"
SKIP_SUBSYSTEM_SPAWN_1 = "skip populating '%s'"
SKIP_WEBAPP_DEPLOYMENT_SPAWN_1 = "skip deploying '%s'"
FILE_EXCLUDE_CALLBACK_2 = "file exclude callback src '%s' names '%s'"
