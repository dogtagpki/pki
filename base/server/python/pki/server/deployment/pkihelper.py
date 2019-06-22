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
from __future__ import absolute_import
from __future__ import print_function

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

import errno
import logging
import sys
import os
import re
import requests.exceptions
import shutil
import subprocess
import time
from datetime import datetime
from grp import getgrgid
from grp import getgrnam
from pwd import getpwnam
from pwd import getpwuid
import xml.etree.ElementTree as ET
import zipfile

# PKI Deployment Imports
from . import pkiconfig as config
from .pkiconfig import pki_selinux_config_ports as ports
from . import pkimanifest as manifest
from . import pkimessages as log
from .pkiparser import PKIConfigParser

import pki
import pki.nssdb
import pki.util

# special care for SELinux
import selinux
seobject = None
if selinux.is_selinux_enabled():
    try:
        import seobject
    except ImportError:
        # TODO: Fedora 22 has an incomplete Python 3 package
        # sepolgen is missing.
        if sys.version_info.major == 2:
            raise

# Retry-able connection errors, see https://pagure.io/dogtagpki/issue/2973
RETRYABLE_EXCEPTIONS = (
    requests.exceptions.ConnectionError,  # connection failed
    requests.exceptions.Timeout,  # connection or read time out
)

logger = logging.getLogger('pkihelper')


class Identity:
    """PKI Deployment Identity Class"""

    def __init__(self, deployer):
        self.mdict = deployer.mdict

    def __add_gid(self, pki_group):

        logger.info('Setting up %s group', pki_group)

        try:
            # Does the specified 'pki_group' exist?
            pki_gid = getgrnam(pki_group)[2]

            logger.info('Reusing existing %s group with GID %s', pki_group, pki_gid)

        except KeyError as exc:
            # No, group 'pki_group' does not exist!
            logger.debug(log.PKIHELPER_GROUP_ADD_KEYERROR_1, exc)
            try:
                # Is the default well-known GID already defined?
                group = getgrgid(config.PKI_DEPLOYMENT_DEFAULT_GID)[0]
                # Yes, the default well-known GID exists!
                logger.info(
                    log.PKIHELPER_GROUP_ADD_DEFAULT_2,
                    group, config.PKI_DEPLOYMENT_DEFAULT_GID)
                # Attempt to create 'pki_group' using a random GID.
                command = ["/usr/sbin/groupadd", pki_group]
            except KeyError as exc:
                # No, the default well-known GID does not exist!
                logger.debug(log.PKIHELPER_GROUP_ADD_GID_KEYERROR_1, exc)
                # Is the specified 'pki_group' the default well-known group?
                if pki_group == config.PKI_DEPLOYMENT_DEFAULT_GROUP:
                    # Yes, attempt to create the default well-known group
                    # using the default well-known GID.
                    command = ["/usr/sbin/groupadd",
                               "-g", str(config.PKI_DEPLOYMENT_DEFAULT_GID),
                               "-r", pki_group]
                else:
                    # No, attempt to create 'pki_group' using a random GID.
                    command = ["/usr/sbin/groupadd", pki_group]
            try:
                logger.debug('Command: %s', ' '.join(command))
                with open(os.devnull, "w") as fnull:
                    subprocess.check_call(command, stdout=fnull, stderr=fnull,
                                          close_fds=True)
            except subprocess.CalledProcessError as exc:
                logger.error(log.PKI_SUBPROCESS_ERROR_1, exc)
                raise
            except OSError as exc:
                logger.error(log.PKI_OSERROR_1, exc)
                raise
        return

    def __add_uid(self, pki_user, pki_group):

        logger.info('Setting up %s user', pki_user)

        try:
            # Does the specified 'pki_user' exist?
            pki_uid = getpwnam(pki_user)[2]

            logger.info('Reusing existing %s user with UID %s', pki_user, pki_uid)

        except KeyError as exc:
            # No, user 'pki_user' does not exist!
            logger.debug(log.PKIHELPER_USER_ADD_KEYERROR_1, exc)
            try:
                # Is the default well-known UID already defined?
                user = getpwuid(config.PKI_DEPLOYMENT_DEFAULT_UID)[0]
                # Yes, the default well-known UID exists!
                logger.info(
                    log.PKIHELPER_USER_ADD_DEFAULT_2,
                    user, config.PKI_DEPLOYMENT_DEFAULT_UID)
                # Attempt to create 'pki_user' using a random UID.
                command = ["/usr/sbin/useradd",
                           "-g", pki_group,
                           "-d", config.PKI_DEPLOYMENT_SOURCE_ROOT,
                           "-s", config.PKI_DEPLOYMENT_DEFAULT_SHELL,
                           "-c", config.PKI_DEPLOYMENT_DEFAULT_COMMENT,
                           pki_user]
            except KeyError as exc:
                # No, the default well-known UID does not exist!
                logger.debug(log.PKIHELPER_USER_ADD_UID_KEYERROR_1, exc)
                # Is the specified 'pki_user' the default well-known user?
                if pki_user == config.PKI_DEPLOYMENT_DEFAULT_USER:
                    # Yes, attempt to create the default well-known user
                    # using the default well-known UID.
                    command = ["/usr/sbin/useradd",
                               "-g", pki_group,
                               "-d", config.PKI_DEPLOYMENT_SOURCE_ROOT,
                               "-s", config.PKI_DEPLOYMENT_DEFAULT_SHELL,
                               "-c", config.PKI_DEPLOYMENT_DEFAULT_COMMENT,
                               "-u", str(config.PKI_DEPLOYMENT_DEFAULT_UID),
                               "-r", pki_user]
                else:
                    # No, attempt to create 'pki_user' using a random UID.
                    command = ["/usr/sbin/useradd",
                               "-g", pki_group,
                               "-d", config.PKI_DEPLOYMENT_SOURCE_ROOT,
                               "-s", config.PKI_DEPLOYMENT_DEFAULT_SHELL,
                               "-c", config.PKI_DEPLOYMENT_DEFAULT_COMMENT,
                               pki_user]
            try:
                logger.debug('Command: %s', ' '.join(command))
                with open(os.devnull, "w") as fnull:
                    subprocess.check_call(command, stdout=fnull, stderr=fnull,
                                          close_fds=True)
            except subprocess.CalledProcessError as exc:
                logger.error(log.PKI_SUBPROCESS_ERROR_1, exc)
                raise
            except OSError as exc:
                logger.error(log.PKI_OSERROR_1, exc)
                raise
        return

    def add_uid_and_gid(self, pki_user, pki_group):
        self.__add_gid(pki_group)
        self.__add_uid(pki_user, pki_group)
        return

    def get_uid(self, critical_failure=True):
        try:
            return self.mdict['pki_uid']
        except KeyError as exc:
            logger.error(log.PKI_KEYERROR_1, exc)
            if critical_failure:
                raise
            return None

    def get_gid(self, critical_failure=True):
        try:
            return self.mdict['pki_gid']
        except KeyError as exc:
            logger.error(log.PKI_KEYERROR_1, exc)
            if critical_failure:
                raise
            return None

    def set_uid(self, name, critical_failure=True):
        try:
            logger.debug(log.PKIHELPER_USER_1, name)
            # id -u <name>
            pki_uid = getpwnam(name)[2]
            self.mdict['pki_uid'] = pki_uid
            logger.debug(log.PKIHELPER_UID_2, name, pki_uid)
            return pki_uid
        except KeyError as exc:
            logger.error(log.PKI_KEYERROR_1, exc)
            if critical_failure:
                raise
            return None

    def set_gid(self, name, critical_failure=True):
        try:
            logger.debug(log.PKIHELPER_GROUP_1, name)
            # id -g <name>
            pki_gid = getgrnam(name)[2]
            self.mdict['pki_gid'] = pki_gid
            logger.debug(log.PKIHELPER_GID_2, name, pki_gid)
            return pki_gid
        except KeyError as exc:
            logger.error(log.PKI_KEYERROR_1, exc)
            if critical_failure:
                raise
            return None

    def group_exists(self, pki_group):
        try:
            getgrnam(pki_group)
        except KeyError:
            return False
        else:
            return True

    def user_exists(self, pki_user):
        try:
            getpwnam(pki_user)
        except KeyError:
            return False
        else:
            return True

    def is_user_a_member_of_group(self, pki_user, pki_group):
        if self.group_exists(pki_group) and self.user_exists(pki_user):
            # Check to see if pki_user is a member of this pki_group
            if pki_user in getgrnam(pki_group)[3]:
                return True
            else:
                return False

    def add_user_to_group(self, pki_user, pki_group):
        if not self.is_user_a_member_of_group(pki_user, pki_group):
            command = ["usermod", "-a", "-G", pki_group, pki_user]
            try:
                # Execute this "usermod" command.
                with open(os.devnull, "w") as fnull:
                    subprocess.check_call(command, stdout=fnull, stderr=fnull,
                                          close_fds=True)
            except subprocess.CalledProcessError as exc:
                logger.error(log.PKI_SUBPROCESS_ERROR_1, exc)
                raise
            except OSError as exc:
                logger.error(log.PKI_OSERROR_1, exc)
                raise
        return


class Namespace:
    """PKI Deployment Namespace Class"""

    # Silently verify that the selected 'pki_instance_name' will
    # NOT produce any namespace collisions
    def __init__(self, deployer):
        self.mdict = deployer.mdict

    def collision_detection(self):
        # Run simple checks for pre-existing namespace collisions
        if os.path.exists(self.mdict['pki_instance_path']):
            if os.path.exists(self.mdict['pki_subsystem_path']):
                # Top-Level PKI base path collision
                logger.error(
                    log.PKIHELPER_NAMESPACE_COLLISION_2,
                    self.mdict['pki_instance_name'],
                    self.mdict['pki_instance_path'])
                raise Exception(
                    log.PKIHELPER_NAMESPACE_COLLISION_2 % (
                        self.mdict['pki_instance_name'],
                        self.mdict['pki_instance_path']))
        else:
            if os.path.exists(
                    self.mdict['pki_target_tomcat_conf_instance_id']):
                # Top-Level "/etc/sysconfig" path collision
                logger.error(
                    log.PKIHELPER_NAMESPACE_COLLISION_2,
                    self.mdict['pki_instance_name'],
                    self.mdict['pki_target_tomcat_conf_instance_id'])
                raise Exception(
                    log.PKIHELPER_NAMESPACE_COLLISION_2 % (
                        self.mdict['pki_instance_name'],
                        self.mdict['pki_target_tomcat_conf_instance_id']))
            if os.path.exists(self.mdict['pki_cgroup_systemd_service']):
                # Systemd cgroup path collision
                logger.error(
                    log.PKIHELPER_NAMESPACE_COLLISION_2,
                    self.mdict['pki_instance_name'],
                    self.mdict['pki_cgroup_systemd_service_path'])
                raise Exception(
                    log.PKIHELPER_NAMESPACE_COLLISION_2 % (
                        self.mdict['pki_instance_name'],
                        self.mdict['pki_cgroup_systemd_service_path']))
            if os.path.exists(self.mdict['pki_cgroup_cpu_systemd_service']):
                # Systemd cgroup CPU path collision
                logger.error(
                    log.PKIHELPER_NAMESPACE_COLLISION_2,
                    self.mdict['pki_instance_name'],
                    self.mdict['pki_cgroup_cpu_systemd_service_path'])
                raise Exception(
                    log.PKIHELPER_NAMESPACE_COLLISION_2 % (
                        self.mdict['pki_instance_name'],
                        self.mdict['pki_cgroup_cpu_systemd_service_path']))

        if os.path.exists(self.mdict['pki_instance_log_path']) and\
           os.path.exists(self.mdict['pki_subsystem_log_path']):
            # Check if logs already exist. If so, append to it. Log it as info
            logger.info(
                log.PKIHELPER_LOG_REUSE,
                self.mdict['pki_instance_log_path'])

        if os.path.exists(self.mdict['pki_instance_configuration_path']) and\
           os.path.exists(self.mdict['pki_subsystem_configuration_path']):
            # Top-Level PKI configuration path collision
            logger.error(
                log.PKIHELPER_NAMESPACE_COLLISION_2,
                self.mdict['pki_instance_name'],
                self.mdict['pki_instance_configuration_path'])
            raise Exception(
                log.PKIHELPER_NAMESPACE_COLLISION_2 % (
                    self.mdict['pki_instance_name'],
                    self.mdict['pki_instance_configuration_path']))
        if os.path.exists(self.mdict['pki_instance_registry_path']) and\
           os.path.exists(self.mdict['pki_subsystem_registry_path']):
            # Top-Level PKI registry path collision
            logger.error(
                log.PKIHELPER_NAMESPACE_COLLISION_2,
                self.mdict['pki_instance_name'],
                self.mdict['pki_instance_registry_path'])
            raise Exception(
                log.PKIHELPER_NAMESPACE_COLLISION_2 % (
                    self.mdict['pki_instance_name'],
                    self.mdict['pki_instance_registry_path']))
        # Run simple checks for reserved name namespace collisions
        if self.mdict['pki_instance_name'] in config.PKI_BASE_RESERVED_NAMES:
            # Top-Level PKI base path reserved name collision
            logger.error(
                log.PKIHELPER_NAMESPACE_RESERVED_NAME_2,
                self.mdict['pki_instance_name'],
                self.mdict['pki_instance_path'])
            raise Exception(
                log.PKIHELPER_NAMESPACE_RESERVED_NAME_2 % (
                    self.mdict['pki_instance_name'],
                    self.mdict['pki_instance_path']))
        # No need to check for reserved name under Top-Level PKI log path
        if self.mdict['pki_instance_name'] in \
                config.PKI_CONFIGURATION_RESERVED_NAMES:
            # Top-Level PKI configuration path reserved name collision
            logger.error(
                log.PKIHELPER_NAMESPACE_RESERVED_NAME_2,
                self.mdict['pki_instance_name'],
                self.mdict['pki_instance_configuration_path'])
            raise Exception(
                log.PKIHELPER_NAMESPACE_RESERVED_NAME_2 % (
                    self.mdict['pki_instance_name'],
                    self.mdict['pki_instance_configuration_path']))

        # Top-Level Tomcat PKI registry path reserved name collision
        if self.mdict['pki_instance_name'] in\
           config.PKI_TOMCAT_REGISTRY_RESERVED_NAMES:
            logger.error(
                log.PKIHELPER_NAMESPACE_RESERVED_NAME_2,
                self.mdict['pki_instance_name'],
                self.mdict['pki_instance_registry_path'])
            raise Exception(
                log.PKIHELPER_NAMESPACE_RESERVED_NAME_2 % (
                    self.mdict['pki_instance_name'],
                    self.mdict['pki_instance_registry_path']))


class ConfigurationFile:
    """PKI Deployment Configuration File Class"""

    def __init__(self, deployer):
        self.mdict = deployer.mdict
        # set useful 'boolean' object variables for this class
        self.clone = config.str2bool(self.mdict['pki_clone'])
        # generic extension support in CSR - for external CA
        self.add_req_ext = config.str2bool(
            self.mdict['pki_req_ext_add'])
        # include SKI extension in CSR - for external CA
        self.req_ski = self.mdict.get('pki_req_ski')

        self.existing = config.str2bool(self.mdict['pki_existing'])
        self.external = config.str2bool(self.mdict['pki_external'])
        self.external_step_one = not config.str2bool(
            self.mdict['pki_external_step_two'])
        self.external_step_two = not self.external_step_one

        if self.external:
            # generic extension support in CSR - for external CA
            if self.add_req_ext:
                self.req_ext_oid = self.mdict['pki_req_ext_oid']
                self.req_ext_critical = self.mdict['pki_req_ext_critical']
                self.req_ext_data = self.mdict['pki_req_ext_data']

        self.skip_configuration = config.str2bool(
            self.mdict['pki_skip_configuration'])
        self.standalone = config.str2bool(self.mdict['pki_standalone'])
        self.subordinate = config.str2bool(self.mdict['pki_subordinate'])
        # server cert san injection support
        self.san_inject = config.str2bool(self.mdict['pki_san_inject'])
        if self.san_inject:
            self.confirm_data_exists('pki_san_for_server_cert')
            self.san_for_server_cert = self.mdict['pki_san_for_server_cert']
        # set useful 'string' object variables for this class
        self.subsystem = self.mdict['pki_subsystem']

    def confirm_external(self):
        # ALWAYS defined via 'pkiparser.py'
        if self.external:
            # Only allowed for External CA/KRA/OCSP.
            if self.subsystem not in ['CA', 'KRA', 'OCSP']:
                logger.error(
                    log.PKI_EXTERNAL_UNSUPPORTED_1,
                    self.subsystem)
                raise Exception(log.PKI_EXTERNAL_UNSUPPORTED_1,
                                self.subsystem)

    def confirm_standalone(self):
        # ALWAYS defined via 'pkiparser.py'
        if self.standalone:
            # Only allowed for Stand-alone PKI
            #
            # ADD checks for valid types of Stand-alone PKI subsystems here
            # AND to the 'private void validateData(ConfigurationRequest data)'
            # Java method located in the file called 'SystemConfigService.java'
            #
            if self.subsystem != "KRA" and self.subsystem != "OCSP":
                logger.error(
                    log.PKI_STANDALONE_UNSUPPORTED_1,
                    self.subsystem)
                raise Exception(log.PKI_STANDALONE_UNSUPPORTED_1,
                                self.subsystem)

    def confirm_subordinate(self):
        # ALWAYS defined via 'pkiparser.py'
        if self.subordinate:
            # Only allowed for Subordinate CA
            if self.subsystem != "CA":
                logger.error(
                    log.PKI_SUBORDINATE_UNSUPPORTED_1,
                    self.subsystem)
                raise Exception(log.PKI_SUBORDINATE_UNSUPPORTED_1,
                                self.subsystem)
            if config.str2bool(
                    self.mdict['pki_subordinate_create_new_security_domain']):
                self.confirm_data_exists(
                    'pki_subordinate_security_domain_name')

    def confirm_external_step_two(self):
        # ALWAYS defined via 'pkiparser.py'
        if self.external_step_two:
            # Only allowed for External CA/KRA/OCSP, or Stand-alone PKI
            if (self.subsystem not in ['CA', 'KRA', 'OCSP'] and
                    not self.standalone):
                logger.error(
                    log.PKI_EXTERNAL_STEP_TWO_UNSUPPORTED_1,
                    self.subsystem)
                raise Exception(log.PKI_EXTERNAL_STEP_TWO_UNSUPPORTED_1,
                                self.subsystem)

    def confirm_data_exists(self, param):
        if param not in self.mdict or not len(self.mdict[param]):
            logger.error(
                log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                param,
                self.mdict['pki_user_deployment_cfg'])
            raise Exception(
                log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 %
                (param, self.mdict['pki_user_deployment_cfg']))

    def confirm_file_exists(self, param):
        if not os.path.exists(self.mdict[param]) or\
           not os.path.isfile(self.mdict[param]):
            logger.error(
                log.PKI_FILE_MISSING_OR_NOT_A_FILE_1,
                self.mdict[param])
            raise Exception(log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 % param)

    def verify_sensitive_data(self):
        # Silently verify the existence of 'sensitive' data

        # Verify existence of Directory Server Password
        # (unless configuration will not be automatically executed)
        if not self.skip_configuration:
            self.confirm_data_exists("pki_ds_password")
        # Verify existence of Admin Password (except for Clones)
        if not self.clone:
            self.confirm_data_exists("pki_admin_password")
        # If HSM, verify absence of all PKCS #12 backup parameters
        if (config.str2bool(self.mdict['pki_hsm_enable']) and
                (config.str2bool(self.mdict['pki_backup_keys']) or
                 ('pki_backup_password' in self.mdict and
                  len(self.mdict['pki_backup_password'])))):
            logger.error(log.PKIHELPER_HSM_KEYS_CANNOT_BE_BACKED_UP_TO_PKCS12_FILES)
            raise Exception(
                log.PKIHELPER_HSM_KEYS_CANNOT_BE_BACKED_UP_TO_PKCS12_FILES)
        # If required, verify existence of Backup Password
        if config.str2bool(self.mdict['pki_backup_keys']):
            self.confirm_data_exists("pki_backup_password")
        # Verify existence of Client Pin for NSS client security databases
        # if not a clone.
        if not self.clone:
            self.confirm_data_exists("pki_client_database_password")
        # Verify existence of Client PKCS #12 Password for Admin Cert
        self.confirm_data_exists("pki_client_pkcs12_password")

        if self.clone:

            # Verify existence of PKCS #12 Password (ONLY for non-HSM Clones)
            if not config.str2bool(self.mdict['pki_hsm_enable']):

                # If system certificates are already provided via
                # pki_server_pkcs12, there's no need to provide
                # pki_clone_pkcs12.
                if not self.mdict['pki_server_pkcs12_path']:
                    self.confirm_data_exists("pki_clone_pkcs12_password")

            # Verify absence of all PKCS #12 clone parameters for HSMs
            elif (os.path.exists(self.mdict['pki_clone_pkcs12_path']) or
                    ('pki_clone_pkcs12_password' in self.mdict and
                     len(self.mdict['pki_clone_pkcs12_password']))):
                logger.error(log.PKIHELPER_HSM_CLONES_MUST_SHARE_HSM_MASTER_PRIVATE_KEYS)
                raise Exception(
                    log.PKIHELPER_HSM_CLONES_MUST_SHARE_HSM_MASTER_PRIVATE_KEYS)

        # Verify existence of Security Domain Password
        # (ONLY for PKI KRA, PKI OCSP, PKI TKS, PKI TPS, Clones, or
        #  Subordinate CA that will be automatically configured and
        #  are not Stand-alone PKI)
        if (self.subsystem == "KRA" or
                self.subsystem == "OCSP" or
                self.subsystem == "TKS" or
                self.subsystem == "TPS" or
                self.clone or
                self.subordinate):
            if not self.skip_configuration and not self.standalone:
                self.confirm_data_exists("pki_security_domain_password")
        # If required, verify existence of Token Password
        if config.str2bool(self.mdict['pki_hsm_enable']):
            self.confirm_data_exists("pki_hsm_libfile")
            self.confirm_data_exists("pki_hsm_modulename")
            self.confirm_data_exists("pki_token_name")
            if not pki.nssdb.normalize_token(self.mdict['pki_token_name']):
                logger.error(log.PKIHELPER_UNDEFINED_HSM_TOKEN)
                raise Exception(log.PKIHELPER_UNDEFINED_HSM_TOKEN)
        if pki.nssdb.normalize_token(self.mdict['pki_token_name']):
            self.confirm_data_exists("pki_token_password")

    def verify_mutually_exclusive_data(self):
        # Silently verify the existence of 'mutually exclusive' data
        if self.subsystem == "CA":
            if self.clone and self.external and self.subordinate:
                logger.error(
                    log.PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_EXTERNAL_SUB_CA,
                    self.mdict['pki_user_deployment_cfg'])
                raise Exception(
                    log.PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_EXTERNAL_SUB_CA %
                    self.mdict['pki_user_deployment_cfg'])
            elif self.clone and self.external:
                logger.error(
                    log.PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_EXTERNAL_CA,
                    self.mdict['pki_user_deployment_cfg'])
                raise Exception(
                    log.PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_EXTERNAL_CA %
                    self.mdict['pki_user_deployment_cfg'])
            elif self.clone and self.subordinate:
                logger.error(
                    log.PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_SUB_CA,
                    self.mdict['pki_user_deployment_cfg'])
                raise Exception(
                    log.PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_SUB_CA %
                    self.mdict['pki_user_deployment_cfg'])
            elif self.external and self.subordinate:
                logger.error(
                    log.PKIHELPER_MUTUALLY_EXCLUSIVE_EXTERNAL_SUB_CA,
                    self.mdict['pki_user_deployment_cfg'])
                raise Exception(
                    log.PKIHELPER_MUTUALLY_EXCLUSIVE_EXTERNAL_SUB_CA %
                    self.mdict['pki_user_deployment_cfg'])
        elif self.standalone:
            if self.clone:
                logger.error(
                    log.PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_STANDALONE_PKI,
                    self.mdict['pki_user_deployment_cfg'])
                raise Exception(
                    log.PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_STANDALONE_PKI %
                    self.mdict['pki_user_deployment_cfg'])

    def verify_predefined_configuration_file_data(self):
        # Silently verify the existence of any required 'predefined' data
        #
        # FUTURE:  As much as is possible, alter this routine to verify
        #          ALL name/value pairs for the requested configuration
        #          scenario.  This should include checking for the
        #          "existence" of ALL required "name" parameters, as well as
        #          the "existence", "type" (e. g. -  string, boolean, number,
        #          etc.), and "correctness" (e. g. - file, directory, boolean
        #          'True' or 'False', etc.) of ALL required "value" parameters.
        #
        self.confirm_external()
        self.confirm_standalone()
        self.confirm_subordinate()
        self.confirm_external_step_two()
        if self.clone:
            # Verify existence of clone parameters
            #
            #     NOTE:  Although this will be checked prior to getting to
            #            this method, this clone's 'pki_instance_name' MUST
            #            be different from the master's 'pki_instance_name'
            #            IF AND ONLY IF the master and clone are located on
            #            the same host!
            #
            self.confirm_data_exists("pki_ds_base_dn")
            # FUTURE:  Check for unused port value(s)
            #          (e. g. - must be different from master if the
            #                   master is located on the same host)
            self.confirm_data_exists("pki_ds_ldap_port")
            self.confirm_data_exists("pki_ds_ldaps_port")
            self.confirm_data_exists("pki_ajp_port")
            self.confirm_data_exists("pki_http_port")
            self.confirm_data_exists("pki_https_port")
            self.confirm_data_exists("pki_tomcat_server_port")

            # Check clone parameters for non-HSM clone
            if not config.str2bool(self.mdict['pki_hsm_enable']):

                # If system certificates are already provided via
                # pki_server_pkcs12, there's no need to provide
                # pki_clone_pkcs12.
                if not self.mdict['pki_server_pkcs12_path']:
                    self.confirm_data_exists("pki_clone_pkcs12_path")
                    self.confirm_file_exists("pki_clone_pkcs12_path")

            self.confirm_data_exists("pki_clone_replication_security")

        elif self.external:
            # External CA
            if not self.external_step_two:
                # External CA (Step 1)
                # The pki_ca_signing_csr_path is optional.
                # generic extension support in CSR - for external CA
                if self.add_req_ext:
                    self.confirm_data_exists("pki_req_ext_oid")
                    self.confirm_data_exists("pki_req_ext_critical")
                    self.confirm_data_exists("pki_req_ext_data")
            else:
                # External CA (Step 2)
                # The pki_cert_chain_path and
                # pki_ca_signing_cert_path are optional.
                pass
        elif not self.skip_configuration and self.standalone:

            if self.external_step_two:

                # Stand-alone PKI External CA Certificate (Step 2)
                # The pki_ca_signing_cert_path is optional.

                # Stand-alone PKI Admin Certificate (Step 2)
                self.confirm_data_exists("pki_admin_cert_path")
                self.confirm_file_exists("pki_admin_cert_path")
                # Stand-alone PKI Audit Signing Certificate (Step 2)
                self.confirm_data_exists(
                    "pki_audit_signing_cert_path")
                self.confirm_file_exists(
                    "pki_audit_signing_cert_path")
                # Stand-alone PKI SSL Server Certificate (Step 2)
                self.confirm_data_exists("pki_sslserver_cert_path")
                self.confirm_file_exists("pki_sslserver_cert_path")
                # Stand-alone PKI Subsystem Certificate (Step 2)
                self.confirm_data_exists("pki_subsystem_cert_path")
                self.confirm_file_exists("pki_subsystem_cert_path")
                # Stand-alone PKI KRA Certificates
                if self.subsystem == "KRA":
                    # Stand-alone PKI KRA Storage Certificate (Step 2)
                    self.confirm_data_exists(
                        "pki_storage_cert_path")
                    self.confirm_file_exists(
                        "pki_storage_cert_path")
                    # Stand-alone PKI KRA Transport Certificate (Step 2)
                    self.confirm_data_exists(
                        "pki_transport_cert_path")
                    self.confirm_file_exists(
                        "pki_transport_cert_path")
                # Stand-alone PKI OCSP Certificates
                if self.subsystem == "OCSP":
                    # Stand-alone PKI OCSP OCSP Signing Certificate (Step 2)
                    self.confirm_data_exists(
                        "pki_ocsp_signing_cert_path")
                    self.confirm_file_exists(
                        "pki_ocsp_signing_cert_path")

    def populate_non_default_ports(self):
        if (self.mdict['pki_http_port'] !=
                str(config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_HTTP_PORT)):
            ports.append(self.mdict['pki_http_port'])
        if (self.mdict['pki_https_port'] !=
                str(config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_HTTPS_PORT)):
            ports.append(self.mdict['pki_https_port'])
        if (self.mdict['pki_tomcat_server_port'] !=
                str(config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_SERVER_PORT)):
            ports.append(self.mdict['pki_tomcat_server_port'])
        if (self.mdict['pki_ajp_port'] !=
                str(config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_AJP_PORT)):
            ports.append(self.mdict['pki_ajp_port'])
        return

    def verify_selinux_ports(self):
        # Determine which ports still need to be labelled, and if any are
        # incorrectly labelled
        if len(ports) == 0:
            return

        if not selinux.is_selinux_enabled() or seobject is None:
            logger.error(log.PKIHELPER_SELINUX_DISABLED)
            return

        trans = seobject.semanageRecords("targeted")
        trans.start()
        portrecs = seobject.portRecords(trans).get_all()
        portlist = ports[:]
        for port in portlist:
            context = ""
            for i in portrecs:
                if (portrecs[i][0] == "unreserved_port_t" or
                        portrecs[i][0] == "reserved_port_t" or
                        i[2] != "tcp"):
                    continue
                if i[0] <= int(port) <= i[1]:
                    context = portrecs[i][0]
                    break
            if context == "":
                # port has no current context
                # leave it in list of ports to set
                continue
            elif context == config.PKI_PORT_SELINUX_CONTEXT:
                # port is already set correctly
                # remove from list of ports to set
                ports.remove(port)
            else:
                logger.error(
                    log.PKIHELPER_INVALID_SELINUX_CONTEXT_FOR_PORT,
                    port, context)
                raise Exception(
                    log.PKIHELPER_INVALID_SELINUX_CONTEXT_FOR_PORT %
                    (port, context))
        trans.finish()
        return

    def verify_ds_secure_connection_data(self):
        # Check to see if a secure connection is being used for the DS
        if config.str2bool(self.mdict['pki_ds_secure_connection']):
            # Verify existence of a local PEM file containing a
            # directory server CA certificate
            self.confirm_file_exists("pki_ds_secure_connection_ca_pem_file")
            # Verify existence of a nickname for this
            # directory server CA certificate
            self.confirm_data_exists("pki_ds_secure_connection_ca_nickname")
            # Set trustargs for this directory server CA certificate
            self.mdict['pki_ds_secure_connection_ca_trustargs'] = "CT,CT,CT"

    def verify_command_matches_configuration_file(self):
        # Silently verify that the command-line parameters match the values
        # that are present in the corresponding configuration file
        if self.mdict['pki_deployment_executable'] == 'pkidestroy':
            if self.mdict['pki_deployed_instance_name'] != \
               self.mdict['pki_instance_name']:
                logger.error(
                    log.PKIHELPER_COMMAND_LINE_PARAMETER_MISMATCH_2,
                    self.mdict['pki_deployed_instance_name'],
                    self.mdict['pki_instance_name'])
                raise Exception(
                    log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 % (
                        self.mdict['pki_deployed_instance_name'],
                        self.mdict['pki_instance_name']))
        return

# PKI Deployment XML File Class
# class xml_file:
#    def remove_filter_section_from_web_xml(self,
#                                           web_xml_source,
#                                           web_xml_target):
#        logger.info(
#            log.PKIHELPER_REMOVE_FILTER_SECTION_1,
#            self.mdict['pki_target_subsystem_web_xml'])
#        begin_filters_section = False
#        begin_servlet_section = False
#        FILE = open(web_xml_target, "w")
#        for line in fileinput.FileInput(web_xml_source):
#            if not begin_filters_section:
#                # Read and write lines until first "<filter>" tag
#                if line.count("<filter>") >= 1:
#                    # Mark filters section
#                    begin_filters_section = True
#                else:
#                    FILE.write(line)
#            elif not begin_servlet_section:
#                # Skip lines until first "<servlet>" tag
#                if line.count("<servlet>") >= 1:
#                    # Mark servlets section and write out the opening tag
#                    begin_servlet_section = True
#                    FILE.write(line)
#                else:
#                    continue
#            else:
#                # Read and write lines all lines after "<servlet>" tag
#                FILE.write(line)
#        FILE.close()


class Instance:
    """PKI Deployment Instance Class"""

    def __init__(self, deployer):
        self.mdict = deployer.mdict

    def pki_instance_subsystems(self):
        rv = 0
        try:
            # Since ALL directories within the top-level PKI infrastructure
            # SHOULD represent PKI instances, look for all possible
            # PKI instances within the top-level PKI infrastructure
            for instance in os.listdir(self.mdict['pki_path']):
                if os.path.isdir(os.path.join(self.mdict['pki_path'], instance))\
                   and not\
                   os.path.islink(os.path.join(self.mdict['pki_path'], instance)):
                    instance_dir = os.path.join(
                        self.mdict['pki_path'],
                        instance)
                    # Since ANY directory within this PKI instance COULD
                    # be a PKI subsystem, look for all possible
                    # PKI subsystems within this PKI instance
                    for name in os.listdir(instance_dir):
                        if os.path.isdir(os.path.join(instance_dir, name)) and\
                           not os.path.islink(os.path.join(instance_dir, name)):
                            if name.upper() in config.PKI_SUBSYSTEMS:
                                rv += 1
            logger.debug(
                log.PKIHELPER_PKI_INSTANCE_SUBSYSTEMS_2,
                self.mdict['pki_instance_path'], rv)
        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            raise
        return rv

    def tomcat_instance_subsystems(self):
        # Return list of PKI subsystems in the specified tomcat instance
        rv = []
        try:
            for subsystem in config.PKI_SUBSYSTEMS:
                path = os.path.join(
                    self.mdict['pki_instance_path'],
                    subsystem.lower()
                )
                if os.path.exists(path) and os.path.isdir(path):
                    rv.append(subsystem)
        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            raise
        return rv

    def tomcat_instances(self):
        rv = 0
        try:
            # Since ALL directories under the top-level PKI 'tomcat' registry
            # directory SHOULD represent PKI Tomcat instances, and there
            # shouldn't be any stray files or symbolic links at this level,
            # simply count the number of PKI 'tomcat' instances (directories)
            # present within the PKI 'tomcat' registry directory
            for instance in os.listdir(
                    self.mdict['pki_instance_type_registry_path']):
                if os.path.isdir(
                    os.path.join(
                        self.mdict['pki_instance_type_registry_path'],
                        instance)) and not\
                   os.path.islink(
                       os.path.join(
                           self.mdict['pki_instance_type_registry_path'],
                           instance)):
                    rv += 1
            logger.debug(
                log.PKIHELPER_TOMCAT_INSTANCES_2,
                self.mdict['pki_instance_type_registry_path'],
                rv)
        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            raise
        return rv

    def verify_subsystem_exists(self):
        try:
            if not os.path.exists(self.mdict['pki_subsystem_path']):
                logger.error(
                    log.PKI_SUBSYSTEM_DOES_NOT_EXIST_2,
                    self.mdict['pki_subsystem'],
                    self.mdict['pki_instance_name'])
                raise Exception(
                    log.PKI_SUBSYSTEM_DOES_NOT_EXIST_2 % (
                        self.mdict['pki_subsystem'],
                        self.mdict['pki_instance_name']))
        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            raise

    def verify_subsystem_does_not_exist(self):
        try:
            if os.path.exists(self.mdict['pki_subsystem_path']):
                raise Exception(
                    log.PKI_SUBSYSTEM_ALREADY_EXISTS_2 % (
                        self.mdict['pki_subsystem'],
                        self.mdict['pki_instance_name']))
        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            raise

    def get_instance_status(self, connection, timeout=None):

        client = pki.system.SystemStatusClient(connection)
        response = client.get_status(timeout=timeout)

        root = ET.fromstring(response)
        status = root.findtext("Status")

        logger.info('Server status: %s', status)

        return status

    def wait_for_startup(
        self,
        timeout,
        secure_connection=True,
        request_timeout=None,
    ):
        """
        Wait for Dogtag to start and become ready to serve requests.

        :param secure_connection: Whether to use HTTPS (default: True)
        :param timeout: Absolute timeout.  Unsuccessful status requests will
            be retried until this timeout is exceeded
        :param request_timeout: connect/receive timeout for each individual
            status request (default: None)

        """

        if secure_connection:
            pki_protocol = "https"
            pki_port = self.mdict['pki_https_port']
        else:
            pki_protocol = "http"
            pki_port = self.mdict['pki_http_port']

        connection = pki.client.PKIConnection(
            protocol=pki_protocol,
            hostname=self.mdict['pki_hostname'],
            port=pki_port,
            subsystem=self.mdict['pki_subsystem_type'],
            accept='application/xml',
            trust_env=False)

        logger.info('Checking server at %s', connection.serverURI)

        start_time = datetime.today()
        status = None
        counter = 0

        while status != "running":
            try:
                time.sleep(1)

                status = self.get_instance_status(
                    connection=connection,
                    timeout=request_timeout,
                )

            except requests.exceptions.SSLError as exc:
                max_retry_error = exc.args[0]
                reason = getattr(max_retry_error, 'reason')
                logger.error('Server unreachable due to SSL error: %s', reason)
                break

            except RETRYABLE_EXCEPTIONS:

                stop_time = datetime.today()
                counter = (stop_time - start_time).total_seconds()

                if counter >= timeout:

                    logger.error(
                        'Server did not start after %ds',
                        timeout)

                    break

                logger.info(
                    'Waiting for server to start (%ds)',
                    int(round(counter)))

                continue

        return status


class Directory:
    """PKI Deployment Directory Class"""

    def __init__(self, deployer):
        self.deployer = deployer
        self.mdict = deployer.mdict
        self.identity = deployer.identity

    def create(self, name, uid=None, gid=None,
               perms=config.PKI_DEPLOYMENT_DEFAULT_DIR_PERMISSIONS,
               acls=None, critical_failure=True):

        logger.info('Creating directory %s', name)

        try:
            if not os.path.exists(name):

                logger.debug('Command: mkdir -p %s', name)
                os.makedirs(name)

                logger.debug('Command: chmod %o %s', perms, name)
                os.chmod(name, perms)

                if uid is None:
                    uid = self.identity.get_uid()
                if gid is None:
                    gid = self.identity.get_gid()

                logger.debug('Command: chown %s:%s %s', uid, gid, name)
                os.chown(name, uid, gid)

                # Store record in installation manifest
                self.deployer.record(
                    name,
                    manifest.RECORD_TYPE_DIRECTORY,
                    uid,
                    gid,
                    perms,
                    acls)
            elif not os.path.isdir(name):
                logger.error(log.PKI_DIRECTORY_ALREADY_EXISTS_NOT_A_DIRECTORY_1, name)
                if critical_failure:
                    raise Exception(
                        log.PKI_DIRECTORY_ALREADY_EXISTS_NOT_A_DIRECTORY_1 %
                        name)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                pass
            else:
                logger.error(log.PKI_OSERROR_1, exc)
                if critical_failure:
                    raise
        return

    def modify(self, name, uid=None, gid=None,
               perms=config.PKI_DEPLOYMENT_DEFAULT_DIR_PERMISSIONS,
               acls=None, silent=False, critical_failure=True):

        if not silent:
            logger.info('Updating directory %s', name)

        try:
            if os.path.exists(name):
                if not os.path.isdir(name):
                    logger.error(log.PKI_DIRECTORY_ALREADY_EXISTS_NOT_A_DIRECTORY_1, name)
                    if critical_failure:
                        raise Exception(
                            log.PKI_DIRECTORY_ALREADY_EXISTS_NOT_A_DIRECTORY_1 %
                            name)

                # Always re-process each directory whether it needs it or not

                if not silent:
                    logger.debug('Command: chmod %o %s', perms, name)
                os.chmod(name, perms)

                if uid is None:
                    uid = self.identity.get_uid()
                if gid is None:
                    gid = self.identity.get_gid()

                if not silent:
                    logger.debug('Command: chown %s:%s %s', uid, gid, name)
                os.chown(name, uid, gid)

                # Store record in installation manifest
                if not silent:
                    self.deployer.record(
                        name,
                        manifest.RECORD_TYPE_DIRECTORY,
                        uid,
                        gid,
                        perms,
                        acls)
            else:
                logger.error(log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, name)
                if critical_failure:
                    raise Exception(
                        log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 % name)
        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            if critical_failure:
                raise
        return

    def delete(self, name, recursive_flag=True, critical_failure=True):

        logger.info('Removing directory %s', name)

        try:
            if not os.path.exists(name) or not os.path.isdir(name):
                # Simply issue a warning and continue
                logger.warning(log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, name)
            else:
                if recursive_flag:
                    logger.debug('Command: rm -rf %s', name)
                    shutil.rmtree(name)
                else:
                    logger.debug('Command: rmdir %s', name)
                    os.rmdir(name)
        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            if critical_failure:
                raise
        return

    def exists(self, name):
        try:
            if not os.path.exists(name) or not os.path.isdir(name):
                return False
            else:
                return True
        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            raise

    def is_empty(self, name):
        try:
            if not os.listdir(name):
                logger.debug(log.PKIHELPER_DIRECTORY_IS_EMPTY_1, name)
                return True
            else:
                logger.debug(log.PKIHELPER_DIRECTORY_IS_NOT_EMPTY_1, name)
                return False
        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            raise

    def set_mode(
            self, name, uid=None, gid=None,
            dir_perms=config.PKI_DEPLOYMENT_DEFAULT_DIR_PERMISSIONS,
            file_perms=config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS,
            symlink_perms=config.PKI_DEPLOYMENT_DEFAULT_SYMLINK_PERMISSIONS,
            dir_acls=None, file_acls=None, symlink_acls=None,
            recursive_flag=True, critical_failure=True):

        logger.info(log.PKIHELPER_SET_MODE_1, name)

        try:
            if not os.path.exists(name) or not os.path.isdir(name):
                logger.error(log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, name)
                raise Exception(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 % name)
            else:
                if uid is None:
                    uid = self.identity.get_uid()
                if gid is None:
                    gid = self.identity.get_gid()

                if recursive_flag:
                    for root, dirs, files in os.walk(name):
                        for name in files:
                            entity = os.path.join(root, name)
                            if not os.path.islink(entity):
                                temp_file = entity
                                logger.debug(log.PKIHELPER_IS_A_FILE_1, temp_file)

                                logger.debug('Command: chmod %o %s', file_perms, temp_file)
                                os.chmod(temp_file, file_perms)

                                logger.debug('Command: chown %s:%s %s', uid, gid, temp_file)
                                os.chown(temp_file, uid, gid)

                                # Store record in installation manifest
                                self.deployer.record(
                                    name,
                                    manifest.RECORD_TYPE_FILE,
                                    uid,
                                    gid,
                                    file_perms,
                                    file_acls)
                            else:
                                symlink = entity
                                logger.debug(log.PKIHELPER_IS_A_SYMLINK_1, symlink)
                                # REMINDER:  Due to POSIX compliance, 'lchmod'
                                #            is NEVER implemented on Linux
                                #            systems since 'chmod' CANNOT be
                                #            run directly against symbolic
                                #            links!

                                logger.debug('Command: chown -h %s:%s %s', uid, gid, symlink)
                                os.lchown(symlink, uid, gid)

                                # Store record in installation manifest
                                self.deployer.record(
                                    name,
                                    manifest.RECORD_TYPE_SYMLINK,
                                    uid,
                                    gid,
                                    symlink_perms,
                                    symlink_acls)

                        for name in dirs:
                            temp_dir = os.path.join(root, name)
                            logger.debug(log.PKIHELPER_IS_A_DIRECTORY_1, temp_dir)

                            logger.debug('Command: chmod %o %s', dir_perms, temp_dir)
                            os.chmod(temp_dir, dir_perms)

                            logger.debug('Command: chown %s:%s %s', uid, gid, temp_dir)
                            os.chown(temp_dir, uid, gid)

                            # Store record in installation manifest
                            self.deployer.record(
                                name,
                                manifest.RECORD_TYPE_DIRECTORY,
                                uid,
                                gid,
                                dir_perms,
                                dir_acls)

                else:
                    logger.debug(log.PKIHELPER_IS_A_DIRECTORY_1, name)

                    logger.debug('Command: chmod %o %s', dir_perms, name)
                    os.chmod(name, dir_perms)

                    logger.debug('Command: chown %s:%s %s', uid, gid, name)
                    os.chown(name, uid, gid)

                    # Store record in installation manifest
                    self.deployer.record(
                        name,
                        manifest.RECORD_TYPE_DIRECTORY,
                        uid,
                        gid,
                        dir_perms,
                        dir_acls)
        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            if critical_failure:
                raise

    def copy(self, old_name, new_name, uid=None, gid=None,
             dir_perms=config.PKI_DEPLOYMENT_DEFAULT_DIR_PERMISSIONS,
             file_perms=config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS,
             symlink_perms=config.PKI_DEPLOYMENT_DEFAULT_SYMLINK_PERMISSIONS,
             dir_acls=None, file_acls=None, symlink_acls=None,
             recursive_flag=True, overwrite_flag=False, critical_failure=True,
             ignore_cb=None):

        logger.info('Creating directory %s', new_name)

        try:

            if not os.path.exists(old_name) or not os.path.isdir(old_name):
                logger.error(log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, old_name)
                raise Exception(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 % old_name)
            else:
                if os.path.exists(new_name):
                    if not overwrite_flag:
                        logger.error(log.PKI_DIRECTORY_ALREADY_EXISTS_1, new_name)
                        raise Exception(
                            log.PKI_DIRECTORY_ALREADY_EXISTS_1 % new_name)

                if recursive_flag:
                    logger.debug('Command: cp -rp %s %s', old_name, new_name)
                    # Due to a limitation in the 'shutil.copytree()'
                    # implementation which requires that
                    # 'The destination directory must not already exist.',
                    # an OSError exception is always thrown due to the
                    # implementation's unchecked call to 'os.makedirs(dst)'.
                    # Consequently, a 'patched' local copy of this routine has
                    # been included in this file with the appropriate fix.
                    pki.util.copytree(old_name, new_name, ignore=ignore_cb)
                else:
                    logger.debug('Command: cp -p %s %s', old_name, new_name)
                    shutil.copy2(old_name, new_name)

                # set ownerships, permissions, and acls
                # of newly created top-level directory
                self.modify(new_name, uid, gid, dir_perms, dir_acls,
                            True, critical_failure)
                # set ownerships, permissions, and acls
                # of contents of newly created top-level directory
                self.set_mode(new_name, uid, gid,
                              dir_perms, file_perms, symlink_perms,
                              dir_acls, file_acls, symlink_acls,
                              recursive_flag, critical_failure)
        except (shutil.Error, OSError) as exc:
            if isinstance(exc, shutil.Error):
                msg = log.PKI_SHUTIL_ERROR_1
            else:
                msg = log.PKI_OSERROR_1
            logger.error(msg, exc)
            if critical_failure:
                raise
        return


class File:
    """PKI Deployment File Class (also used for executables)"""

    def __init__(self, deployer):
        self.deployer = deployer
        self.mdict = deployer.mdict
        self.slots = deployer.slots
        self.identity = deployer.identity

    def create(self, name, uid=None, gid=None,
               perms=config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS,
               acls=None, critical_failure=True):
        try:
            if not os.path.exists(name):

                logger.debug('Command: touch %s', name)
                open(name, "w").close()

                logger.debug('Command: chmod %o %s', perms, name)
                os.chmod(name, perms)

                if uid is None:
                    uid = self.identity.get_uid()
                if gid is None:
                    gid = self.identity.get_gid()

                logger.debug('Command: chown %s:%s %s', uid, gid, name)
                os.chown(name, uid, gid)

                # Store record in installation manifest
                self.deployer.record(
                    name,
                    manifest.RECORD_TYPE_FILE,
                    uid,
                    gid,
                    perms,
                    acls)
            elif not os.path.isfile(name):
                logger.error(log.PKI_FILE_ALREADY_EXISTS_NOT_A_FILE_1, name)
                if critical_failure:
                    raise Exception(
                        log.PKI_FILE_ALREADY_EXISTS_NOT_A_FILE_1 % name)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                pass
            else:
                logger.error(log.PKI_OSERROR_1, exc)
                if critical_failure:
                    raise
        return

    def modify(self, name, uid=None, gid=None,
               perms=config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS,
               acls=None, silent=False, critical_failure=True):

        if not silent:
            logger.info('Updating file %s', name)

        try:
            if os.path.exists(name):
                if not os.path.isfile(name):
                    logger.error(log.PKI_FILE_ALREADY_EXISTS_NOT_A_FILE_1, name)
                    if critical_failure:
                        raise Exception(
                            log.PKI_FILE_ALREADY_EXISTS_NOT_A_FILE_1 % name)

                # Always re-process each file whether it needs it or not

                if not silent:
                    logger.debug('Command: chmod %o %s', perms, name)
                os.chmod(name, perms)

                if uid is None:
                    uid = self.identity.get_uid()
                if gid is None:
                    gid = self.identity.get_gid()

                if not silent:
                    logger.debug('Command: chown %s:%s %s', uid, gid, name)
                os.chown(name, uid, gid)

                # Store record in installation manifest
                if not silent:
                    self.deployer.record(
                        name,
                        manifest.RECORD_TYPE_FILE,
                        uid,
                        gid,
                        perms,
                        acls)
            else:
                logger.error(log.PKI_FILE_MISSING_OR_NOT_A_FILE_1, name)
                if critical_failure:
                    raise Exception(
                        log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 %
                        name)
        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            if critical_failure:
                raise
        return

    def delete(self, name, critical_failure=True):

        logger.info('Removing file %s', name)

        try:
            if not os.path.exists(name) or not os.path.isfile(name):
                # Simply issue a warning and continue
                logger.warning(log.PKI_FILE_MISSING_OR_NOT_A_FILE_1, name)
                return

            logger.debug('Command: rm -f %s', name)
            os.remove(name)

        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            if critical_failure:
                raise
        return

    def exists(self, name):
        try:
            if not os.path.exists(name) or not os.path.isfile(name):
                return False
            else:
                return True
        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            raise

    def copy(self, old_name, new_name, uid=None, gid=None,
             perms=config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS, acls=None,
             overwrite_flag=False, critical_failure=True):

        logger.info('Creating file %s', new_name)

        try:
            if not os.path.exists(old_name) or not os.path.isfile(old_name):
                logger.error(log.PKI_FILE_MISSING_OR_NOT_A_FILE_1, old_name)
                raise Exception(
                    log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 %
                    old_name)
            else:
                if os.path.exists(new_name):
                    if not overwrite_flag:
                        logger.error(log.PKI_FILE_ALREADY_EXISTS_1, new_name)
                        raise Exception(
                            log.PKI_FILE_ALREADY_EXISTS_1 % new_name)

                logger.debug('Command: cp -p %s %s', old_name, new_name)
                shutil.copy2(old_name, new_name)
                if uid is None:
                    uid = self.identity.get_uid()
                if gid is None:
                    gid = self.identity.get_gid()

                logger.debug('Command: chmod %o %s', perms, new_name)
                os.chmod(new_name, perms)

                logger.debug('Command: chown %s:%s %s', uid, gid, new_name)
                os.chown(new_name, uid, gid)

                # Store record in installation manifest
                self.deployer.record(
                    new_name,
                    manifest.RECORD_TYPE_FILE,
                    uid,
                    gid,
                    perms,
                    acls)
        except (shutil.Error, OSError) as exc:
            if isinstance(exc, shutil.Error):
                msg = log.PKI_SHUTIL_ERROR_1
            else:
                msg = log.PKI_OSERROR_1
            logger.error(msg, exc)
            if critical_failure:
                raise
        return

    def copy_with_slot_substitution(
            self, old_name, new_name, uid=None, gid=None,
            perms=config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS,
            acls=None, overwrite_flag=False,
            critical_failure=True):

        logger.info('Customizing %s into %s', old_name, new_name)

        try:
            if not os.path.exists(old_name) or not os.path.isfile(old_name):
                logger.error(log.PKI_FILE_MISSING_OR_NOT_A_FILE_1, old_name)
                raise Exception(
                    log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 %
                    old_name)

            if uid is None:
                uid = self.identity.get_uid()
            if gid is None:
                gid = self.identity.get_gid()

            pki.util.copyfile(
                old_name,
                new_name,
                slots=self.slots,
                params=self.mdict,
                uid=uid,
                gid=gid,
                perms=perms,
                force=overwrite_flag)

            # Store record in installation manifest
            self.deployer.record(
                new_name,
                manifest.RECORD_TYPE_FILE,
                uid,
                gid,
                perms,
                acls)

        except (shutil.Error, OSError) as exc:
            if isinstance(exc, shutil.Error):
                msg = log.PKI_SHUTIL_ERROR_1
            else:
                msg = log.PKI_OSERROR_1
            logger.error(msg, exc)
            if critical_failure:
                raise


class Symlink:
    """PKI Deployment Symbolic Link Class"""

    def __init__(self, deployer):
        self.deployer = deployer
        self.mdict = deployer.mdict
        self.identity = deployer.identity

    def create(self, name, link, uid=None, gid=None,
               acls=None, allow_dangling_symlink=False, critical_failure=True):

        logger.info('Creating symlink %s', link)

        try:
            if not os.path.exists(link):
                if not os.path.exists(name):
                    logger.warning(log.PKIHELPER_DANGLING_SYMLINK_2, link, name)
                    if not allow_dangling_symlink:
                        raise Exception(
                            "Dangling symlink " + link + " not allowed")

                logger.debug('Command: ln -s %s %s', name, link)
                os.symlink(name, link)

                # REMINDER:  Due to POSIX compliance, 'lchmod' is NEVER
                #            implemented on Linux systems since 'chmod'
                #            CANNOT be run directly against symbolic links!

                if uid is None:
                    uid = self.identity.get_uid()
                if gid is None:
                    gid = self.identity.get_gid()

                logger.debug('Command: chown -h %s:%s %s', uid, gid, link)
                os.lchown(link, uid, gid)

                # Store record in installation manifest
                self.deployer.record(
                    link,
                    manifest.RECORD_TYPE_SYMLINK,
                    uid,
                    gid,
                    config.PKI_DEPLOYMENT_DEFAULT_SYMLINK_PERMISSIONS,
                    acls)
            elif not os.path.islink(link):
                logger.error(log.PKI_SYMLINK_ALREADY_EXISTS_NOT_A_SYMLINK_1, link)
                if critical_failure:
                    raise Exception(
                        log.PKI_SYMLINK_ALREADY_EXISTS_NOT_A_SYMLINK_1 % link)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                pass
            else:
                logger.error(log.PKI_OSERROR_1, exc)
                if critical_failure:
                    raise
        return

    def modify(self, link, uid=None, gid=None,
               acls=None, silent=False, critical_failure=True):

        if not silent:
            logger.info('Updating symlink %s', link)

        try:
            if os.path.exists(link):
                if not os.path.islink(link):
                    logger.error(log.PKI_SYMLINK_ALREADY_EXISTS_NOT_A_SYMLINK_1, link)
                    if critical_failure:
                        raise Exception(
                            log.PKI_SYMLINK_ALREADY_EXISTS_NOT_A_SYMLINK_1 %
                            link)

                # Always re-process each link whether it needs it or not

                # REMINDER:  Due to POSIX compliance, 'lchmod' is NEVER
                #            implemented on Linux systems since 'chmod'
                #            CANNOT be run directly against symbolic links!

                if uid is None:
                    uid = self.identity.get_uid()
                if gid is None:
                    gid = self.identity.get_gid()

                if not silent:
                    logger.debug('Command: chown -h %s:%s %s', uid, gid, link)
                os.lchown(link, uid, gid)

                # Store record in installation manifest
                if not silent:
                    self.deployer.record(
                        link,
                        manifest.RECORD_TYPE_SYMLINK,
                        uid,
                        gid,
                        config.PKI_DEPLOYMENT_DEFAULT_SYMLINK_PERMISSIONS,
                        acls)
            else:
                logger.error(log.PKI_SYMLINK_MISSING_OR_NOT_A_SYMLINK_1, link)
                if critical_failure:
                    raise Exception(
                        log.PKI_SYMLINK_MISSING_OR_NOT_A_SYMLINK_1 % link)
        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            if critical_failure:
                raise
        return

    def delete(self, link, critical_failure=True):

        logger.info('Removing symlink %s', link)

        try:
            if not os.path.exists(link) or not os.path.islink(link):
                # Simply issue a warning and continue
                logger.warning(log.PKI_SYMLINK_MISSING_OR_NOT_A_SYMLINK_1, link)
            else:
                logger.debug('Command: rm -f %s', link)
                os.remove(link)
        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            if critical_failure:
                raise
        return

    def exists(self, name):
        try:
            if not os.path.exists(name) or not os.path.islink(name):
                return False
            else:
                return True
        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            raise


class War:
    """PKI Deployment War File Class"""

    def __init__(self, deployer):
        self.mdict = deployer.mdict

    def explode(self, name, path, critical_failure=True):
        try:
            if os.path.exists(name) and os.path.isfile(name):
                if not zipfile.is_zipfile(name):
                    logger.error(log.PKI_FILE_NOT_A_WAR_FILE_1, name)
                    if critical_failure:
                        raise Exception(log.PKI_FILE_NOT_A_WAR_FILE_1 % name)
                if not os.path.exists(path) or not os.path.isdir(path):
                    logger.error(log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, path)
                    if critical_failure:
                        raise Exception(
                            log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1,
                            path)
                # jar -xf <name> -C <path>
                logger.info(log.PKIHELPER_JAR_XF_C_2, name, path)
                # Open war file
                war = zipfile.ZipFile(name, 'r')
                # Extract contents of war file to path
                war.extractall(path)
            else:
                logger.error(log.PKI_FILE_MISSING_OR_NOT_A_FILE_1, name)
                if critical_failure:
                    raise Exception(log.PKI_FILE_MISSING_OR_NOT_A_FILE_1, name)
        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            if critical_failure:
                raise
        except zipfile.BadZipfile as exc:
            logger.error(log.PKI_BADZIPFILE_ERROR_1, exc)
            if critical_failure:
                raise
        except zipfile.LargeZipFile as exc:
            logger.error(log.PKI_LARGEZIPFILE_ERROR_1, exc)
            if critical_failure:
                raise
        return


class Password:
    """PKI Deployment Password Class"""

    def __init__(self, deployer):
        self.mdict = deployer.mdict
        self.deployer = deployer

    def create_password_conf(self, path, pin, pin_sans_token=False,
                             overwrite_flag=False, critical_failure=True):

        try:
            if os.path.exists(path):
                if not overwrite_flag:
                    return

            if pin_sans_token:
                with open(path, 'w') as fd:
                    fd.write(str(pin))
                return

            token = self.mdict['pki_self_signed_token']
            if not pki.nssdb.normalize_token(token):
                token = pki.nssdb.INTERNAL_TOKEN_NAME

            with open(path, 'w') as fd:
                fd.write(token + '=' + str(pin))

        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            if critical_failure:
                raise
        return

    def create_client_pkcs12_password_conf(self, path, overwrite_flag=False,
                                           critical_failure=True):

        logger.info('Storing PKCS #12 password in %s', path)

        try:
            if os.path.exists(path):
                if overwrite_flag:
                    # overwrite the existing 'pkcs12_password.conf' file
                    with open(path, "w") as fd:
                        fd.write(self.mdict['pki_client_pkcs12_password'])
            else:
                # create a new 'pkcs12_password.conf' file
                with open(path, "w") as fd:
                    fd.write(self.mdict['pki_client_pkcs12_password'])
        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            if critical_failure:
                raise
        return

    def get_password(self, path, token_name):
        token_pwd = None
        if os.path.exists(path) and os.path.isfile(path) and\
           os.access(path, os.R_OK):
            tokens = PKIConfigParser.read_simple_configuration_file(path)
            hardware_token = "hardware-" + token_name
            if hardware_token in tokens:
                token_name = hardware_token
                token_pwd = tokens[hardware_token]
            elif token_name in tokens:
                token_pwd = tokens[token_name]

        if token_pwd is None or token_pwd == '':
            self.deployer.parser.read_password(
                'Password for token {}'.format(token_name),
                self.deployer.subsystem_name,
                'token_pwd')
            token_pwd = self.mdict['token_pwd']
        return token_pwd


class FIPS:
    """PKI Deployment FIPS class"""

    def __init__(self, deployer):
        self.mdict = deployer.mdict

    def is_fips_enabled(self, critical_failure=False):
        try:
            # Always initialize FIPS mode as NOT enabled
            self.mdict['pki_fips_mode_enabled'] = False

            # Check if /proc/sys/crypto/fips_enabled exists
            if not os.path.exists("/proc/sys/crypto/fips_enabled"):
                logger.info(log.PKIHELPER_FIPS_MODE_IS_NOT_ENABLED)
                return False

            # Check to see if FIPS is enabled on this system
            command = ["sysctl", "crypto.fips_enabled", "-bn"]

            # Execute this "sysctl" command.
            with open(os.devnull, "w") as fnull:
                output = subprocess.check_output(command, stderr=fnull,
                                                 close_fds=True)
                if output != "0":
                    # Set FIPS mode as enabled
                    self.mdict['pki_fips_mode_enabled'] = True
                    logger.info(log.PKIHELPER_FIPS_MODE_IS_ENABLED)
                    return True
                else:
                    logger.info(log.PKIHELPER_FIPS_MODE_IS_NOT_ENABLED)
                    return False
        except subprocess.CalledProcessError as exc:
            logger.error(log.PKI_SUBPROCESS_ERROR_1, exc)
            if critical_failure:
                raise
        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            if critical_failure:
                raise
        return False


class HSM:
    """PKI Deployment HSM class"""

    def __init__(self, deployer):
        self.mdict = deployer.mdict
        self.identity = deployer.identity
        self.file = deployer.file

    def initialize(self):
        if config.str2bool(self.mdict['pki_hsm_enable']):
            if self.mdict['pki_hsm_libfile'] == config.PKI_HSM_NCIPHER_LIB:
                self.initialize_ncipher()
        return

    def initialize_ncipher(self):
        if (self.file.exists(config.PKI_HSM_NCIPHER_EXE) and
                self.file.exists(config.PKI_HSM_NCIPHER_LIB) and
                self.identity.group_exists(config.PKI_HSM_NCIPHER_GROUP)):
            # Check if 'pki_user' is a member of the default "nCipher" group
            if not self.identity.is_user_a_member_of_group(
                    self.mdict['pki_user'], config.PKI_HSM_NCIPHER_GROUP):
                # Make 'pki_user' a member of the default "nCipher" group
                self.identity.add_user_to_group(self.mdict['pki_user'],
                                                config.PKI_HSM_NCIPHER_GROUP)
                # Restart this "nCipher" HSM
                self.restart_ncipher()
        return

    def restart_ncipher(self, critical_failure=True):
        try:
            command = [config.PKI_HSM_NCIPHER_EXE, "restart"]

            # Display this "nCipher" HSM command
            logger.info(log.PKIHELPER_NCIPHER_RESTART_1, ' '.join(command))
            # Execute this "nCipher" HSM command
            subprocess.check_call(command)
        except subprocess.CalledProcessError as exc:
            logger.error(log.PKI_SUBPROCESS_ERROR_1, exc)
            if critical_failure:
                raise
        return


class Certutil:
    """PKI Deployment NSS 'certutil' Class"""

    def __init__(self, deployer):
        self.mdict = deployer.mdict
        self.nss_db_type = deployer.nss_db_type

    def _get_dbfiles(self, path):
        if self.nss_db_type == 'sql':
            filenames = ['cert9.db', 'key4.db', 'pkcs11.txt']
        elif self.nss_db_type == 'dbm':
            filenames = ['cert8.db', 'key3.db', 'secmod.db']
        else:
            raise ValueError(self.nss_db_type)
        return [os.path.join(path, filename) for filename in filenames]

    def create_security_databases(self, path,
                                  password_file=None, prefix=None,
                                  critical_failure=True):

        logger.info('Creating NSS database in %s', path)

        cert_db, key_db, secmod_db = self._get_dbfiles(path)
        try:
            # Compose this "certutil" command
            command = ["certutil", "-N"]
            #   Provide a path to the NSS security databases
            if path:
                command.extend(["-d", path])
            else:
                logger.error(log.PKIHELPER_CERTUTIL_MISSING_PATH)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_PATH)
            if password_file is not None:
                command.extend(["-f", password_file])
            if prefix is not None:
                command.extend(["-P", prefix])
            if not os.path.exists(path):
                logger.error(log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, path)
                raise Exception(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 % path)
            if os.path.exists(cert_db) or\
               os.path.exists(key_db) or\
               os.path.exists(secmod_db):
                # Simply notify user that the security databases exist
                logger.info(
                    log.PKI_SECURITY_DATABASES_ALREADY_EXIST_3,
                    cert_db,
                    key_db,
                    secmod_db)
            else:
                if password_file is not None:
                    if not os.path.exists(password_file) or\
                       not os.path.isfile(password_file):
                        logger.error(
                            log.PKI_FILE_MISSING_OR_NOT_A_FILE_1,
                            password_file)
                        raise Exception(
                            log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 %
                            password_file)

                logger.debug('Command: %s', ' '.join(command))
                subprocess.check_call(command)

        except subprocess.CalledProcessError as exc:
            logger.error(log.PKI_SUBPROCESS_ERROR_1, exc)
            if critical_failure:
                raise
        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            if critical_failure:
                raise
        return

    def verify_certificate_exists(self, path, token, nickname,
                                  password_file=None, silent=True,
                                  critical_failure=True):
        try:
            # Compose this "certutil" command
            command = ["certutil", "-L"]
            #   Provide a path to the NSS security databases
            if path:
                command.extend(["-d", path])
            else:
                logger.error(log.PKIHELPER_CERTUTIL_MISSING_PATH)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_PATH)
            #   Specify the 'token'
            if token:
                command.extend(["-h", token])
            #   Specify the nickname of this self-signed certificate
            if nickname:
                command.extend(["-n", nickname])
            else:
                logger.error(log.PKIHELPER_CERTUTIL_MISSING_NICKNAME)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_NICKNAME)
            #   OPTIONALLY specify a password file
            if password_file is not None:
                command.extend(["-f", password_file])
            if not os.path.exists(path):
                logger.error(log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, path)
                raise Exception(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 % path)
            if password_file is not None:
                if not os.path.exists(password_file) or\
                   not os.path.isfile(password_file):
                    logger.error(log.PKI_FILE_MISSING_OR_NOT_A_FILE_1, password_file)
                    raise Exception(
                        log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 % password_file)
            # Display this "certutil" command
            logger.info('Command: %s', ' '.join(command))
            # Execute this "certutil" command
            if silent:
                # By default, execute this command silently
                with open(os.devnull, "w") as fnull:
                    subprocess.check_call(command, stdout=fnull, stderr=fnull)
            else:
                subprocess.check_call(command)
        except subprocess.CalledProcessError:
            return False
        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            if critical_failure:
                raise
        return True

    def import_cert(self, nickname, trust, input_file, password_file,
                    path=None, token=None, critical_failure=True):

        logger.info('Importing %s cert from %s', nickname, input_file)

        try:
            command = ["certutil", "-A"]
            if path:
                command.extend(["-d", path])

            if token:
                command.extend(["-h", token])

            if nickname:
                command.extend(["-n", nickname])
            else:
                logger.error(log.PKIHELPER_CERTUTIL_MISSING_NICKNAME)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_NICKNAME)

            if trust:
                command.extend(["-t", trust])
            else:
                logger.error(log.PKIHELPER_CERTUTIL_MISSING_TRUSTARGS)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_TRUSTARGS)

            if input_file:
                command.extend(["-i", input_file])
            else:
                logger.error(log.PKIHELPER_CERTUTIL_MISSING_INPUT_FILE)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_INPUT_FILE)

            if password_file:
                command.extend(["-f", password_file])
            else:
                logger.error(log.PKIHELPER_CERTUTIL_MISSING_PASSWORD_FILE)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_PASSWORD_FILE)

            logger.debug('Command: %s', ' '.join(command))
            subprocess.check_call(command)

        except subprocess.CalledProcessError as exc:
            logger.error(log.PKI_SUBPROCESS_ERROR_1, exc)
            if critical_failure:
                raise
        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            if critical_failure:
                raise
        return

    def generate_certificate_request(self, subject, key_type, key_size,
                                     password_file, noise_file,
                                     output_file=None, path=None,
                                     ascii_format=None, token=None,
                                     critical_failure=True):

        logger.info('Generating CSR for %s', subject)

        try:
            command = ["certutil", "-R"]
            if path:
                command.extend(["-d", path])
            else:
                command.extend(["-d", "."])

            if token:
                command.extend(["-h", token])

            if subject:
                command.extend(["-s", subject])
            else:
                logger.error(log.PKIHELPER_CERTUTIL_MISSING_SUBJECT)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_SUBJECT)

            if key_type:
                if key_type == "ecc":
                    command.extend(["-k", "ec"])
                    if not key_size:
                        # supply a default curve for an 'ecc' key type
                        command.extend(["-q", "nistp256"])
                elif key_type == "rsa":
                    command.extend(["-k", str(key_type)])
                else:
                    logger.error(
                        log.PKIHELPER_CERTUTIL_INVALID_KEY_TYPE_1,
                        key_type)
                    raise Exception(
                        log.PKIHELPER_CERTUTIL_INVALID_KEY_TYPE_1 % key_type)
            else:
                logger.error(log.PKIHELPER_CERTUTIL_MISSING_KEY_TYPE)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_KEY_TYPE)

            if key_size:
                if key_type == "ecc":
                    # For ECC, the key_size will actually contain the key curve
                    command.extend(["-q", str(key_size)])
                else:
                    command.extend(["-g", str(key_size)])

            if noise_file:
                command.extend(["-z", noise_file])
            else:
                logger.error(log.PKIHELPER_CERTUTIL_MISSING_NOISE_FILE)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_NOISE_FILE)

            if password_file:
                command.extend(["-f", password_file])
            else:
                logger.error(log.PKIHELPER_CERTUTIL_MISSING_PASSWORD_FILE)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_PASSWORD_FILE)

            if output_file:
                command.extend(["-o", output_file])

            # set acsii output
            if ascii_format:
                command.append("-a")

            if not os.path.exists(noise_file):
                logger.error(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1,
                    noise_file)
                raise Exception(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 % noise_file)
            if not os.path.exists(password_file) or\
               not os.path.isfile(password_file):
                logger.error(
                    log.PKI_FILE_MISSING_OR_NOT_A_FILE_1,
                    password_file)
                raise Exception(
                    log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 % password_file)

            logger.debug('Command: %s', ' '.join(command))
            with open(os.devnull, "w") as fnull:
                subprocess.check_call(command, stdout=fnull, stderr=fnull)

        except subprocess.CalledProcessError as exc:
            logger.error(log.PKI_SUBPROCESS_ERROR_1, exc)
            if critical_failure:
                raise
        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            if critical_failure:
                raise
        return


class Modutil:
    """PKI Deployment NSS 'modutil' Class"""

    def __init__(self, deployer):
        self.mdict = deployer.mdict

    def is_security_module_registered(self, path, modulename, prefix=None):

        if not path:
            logger.error(log.PKIHELPER_MODUTIL_MISSING_PATH)
            raise Exception(log.PKIHELPER_MODUTIL_MISSING_PATH)

        if not modulename:
            logger.error(log.PKIHELPER_MODUTIL_MISSING_MODULENAME)
            raise Exception(log.PKIHELPER_MODUTIL_MISSING_MODULENAME)

        command = [
            'modutil',
            '-list',
            '-dbdir', path,
            '-nocertdb']

        if prefix:
            command.extend(['--dbprefix', prefix])

        logger.info(
            log.PKIHELPER_REGISTERED_SECURITY_MODULE_CHECK_1,
            ' '.join(command))

        # execute command
        p = subprocess.Popen(command, stdout=subprocess.PIPE)
        output = p.communicate()[0]
        p.wait()
        # ignore return code due to issues with HSM
        # https://fedorahosted.org/pki/ticket/1444
        output = output.decode('utf-8')

        # find modules from lines such as '1. NSS Internal PKCS #11 Module'
        modules = re.findall(
            r'^ +\d+\. +(.*)$',
            output,
            re.MULTILINE  # pylint: disable=no-member
        )

        if modulename not in modules:
            logger.info(log.PKIHELPER_UNREGISTERED_SECURITY_MODULE_1, modulename)
            return False

        logger.info(log.PKIHELPER_REGISTERED_SECURITY_MODULE_1, modulename)
        return True

    def register_security_module(self, path, modulename, libfile,
                                 prefix=None, critical_failure=True):
        try:
            # First check if security module is already registered
            if self.is_security_module_registered(path, modulename):
                return
            # Compose this "modutil" command
            command = ["modutil"]
            #   Provide a path to the NSS security databases
            if path:
                command.extend(["-dbdir", path])
            else:
                logger.error(log.PKIHELPER_MODUTIL_MISSING_PATH)
                raise Exception(log.PKIHELPER_MODUTIL_MISSING_PATH)
            #   Add optional security database prefix
            if prefix is not None:
                command.extend(["--dbprefix", prefix])
            #   Append '-nocertdb' switch
            command.extend(["-nocertdb"])
            #   Specify a 'modulename'
            if modulename:
                command.extend(["-add", modulename])
            else:
                logger.error(log.PKIHELPER_MODUTIL_MISSING_MODULENAME)
                raise Exception(log.PKIHELPER_MODUTIL_MISSING_MODULENAME)
            #   Specify a 'libfile'
            if libfile:
                command.extend(["-libfile", libfile])
            else:
                logger.error(log.PKIHELPER_MODUTIL_MISSING_LIBFILE)
                raise Exception(log.PKIHELPER_MODUTIL_MISSING_LIBFILE)
            #   Append '-force' switch
            command.extend(["-force"])
            # Display this "modutil" command
            logger.info(
                log.PKIHELPER_REGISTER_SECURITY_MODULE_1,
                ' '.join(command))
            # Execute this "modutil" command
            subprocess.check_call(command)
        except subprocess.CalledProcessError as exc:
            logger.error(log.PKI_SUBPROCESS_ERROR_1, exc)
            if critical_failure:
                raise
        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            if critical_failure:
                raise
        return


class PK12util:
    """PKI Deployment pk12util class"""

    def __init__(self, deployer):
        self.mdict = deployer.mdict

    def create_file(self, out_file, nickname, out_pwfile,
                    db_pwfile, path=None, critical_failure=True):

        logger.info('Exporting %s cert and key into %s', nickname, out_file)

        try:
            command = ["pk12util"]
            if path:
                command.extend(["-d", path])
            if out_file:
                command.extend(["-o", out_file])
            else:
                logger.error(log.PKIHELPER_PK12UTIL_MISSING_OUTFILE)
                raise Exception(log.PKIHELPER_PK12UTIL_MISSING_OUTFILE)
            if nickname:
                command.extend(["-n", nickname])
            else:
                logger.error(log.PKIHELPER_PK12UTIL_MISSING_NICKNAME)
                raise Exception(log.PKIHELPER_PK12UTIL_MISSING_NICKNAME)
            if out_pwfile:
                command.extend(["-w", out_pwfile])
            else:
                logger.error(log.PKIHELPER_PK12UTIL_MISSING_PWFILE)
                raise Exception(log.PKIHELPER_PK12UTIL_MISSING_PWFILE)
            if db_pwfile:
                command.extend(["-k", db_pwfile])
            else:
                logger.error(log.PKIHELPER_PK12UTIL_MISSING_DBPWFILE)
                raise Exception(log.PKIHELPER_PK12UTIL_MISSING_DBPWFILE)

            logger.debug('Command: %s', ' '.join(command))
            with open(os.devnull, "w") as fnull:
                subprocess.check_call(command, stdout=fnull, stderr=fnull)

        except subprocess.CalledProcessError as exc:
            logger.error(log.PKI_SUBPROCESS_ERROR_1, exc)
            if critical_failure:
                raise
        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            if critical_failure:
                raise
        return


class KRAConnector:
    """PKI Deployment KRA Connector Class"""

    def __init__(self, deployer):
        self.mdict = deployer.mdict
        self.password = deployer.password

    def deregister(self, critical_failure=False):
        krahost = None
        kraport = None
        try:
            # this is applicable to KRAs only
            if self.mdict['pki_subsystem_type'] != "kra":
                return

            logger.info(log.PKIHELPER_KRACONNECTOR_UPDATE_CONTACT)

            cs_cfg = PKIConfigParser.read_simple_configuration_file(
                self.mdict['pki_target_cs_cfg'])
            krahost = cs_cfg.get('service.machineName')
            kraport = cs_cfg.get('pkicreate.secure_port')
            proxy_secure_port = cs_cfg.get('proxy.securePort', '')
            if proxy_secure_port != '':
                kraport = proxy_secure_port

            # retrieve subsystem nickname
            subsystemnick = cs_cfg.get('kra.cert.subsystem.nickname')
            if subsystemnick is None:
                logger.warning(log.PKIHELPER_KRACONNECTOR_UPDATE_FAILURE)
                logger.error(log.PKIHELPER_UNDEFINED_SUBSYSTEM_NICKNAME)
                if critical_failure:
                    raise Exception(log.PKIHELPER_UNDEFINED_SUBSYSTEM_NICKNAME)
                else:
                    return

            # retrieve name of token based upon type (hardware/software)
            if ':' in subsystemnick:
                token_name = subsystemnick.split(':')[0]
            else:
                token_name = pki.nssdb.INTERNAL_TOKEN_NAME

            token_pwd = self.password.get_password(
                self.mdict['pki_shared_password_conf'],
                token_name)

            if token_pwd is None or token_pwd == '':
                logger.warning(log.PKIHELPER_KRACONNECTOR_UPDATE_FAILURE)
                logger.error(
                    log.PKIHELPER_UNDEFINED_TOKEN_PASSWD_1,
                    token_name)
                if critical_failure:
                    raise Exception(
                        log.PKIHELPER_UNDEFINED_TOKEN_PASSWD_1 % token_name)
                else:
                    return

            # Note: this is a hack to resolve Trac Ticket 1113
            # We need to remove the KRA connector data from all relevant clones,
            # but we have no way of easily identifying which instances are
            # the right ones.  Instead, We will attempt to remove the KRA
            # connector from all CAs in the security domain.
            # The better - and long term solution is to store the connector
            # configuration in LDAP so that updating one clone will
            # automatically update the rest.
            # TODO(alee): Fix this logic once we move connector data to LDAP

            # get a list of all the CA's in the security domain
            # noinspection PyBroadException
            # pylint: disable=W0703
            sechost = cs_cfg.get('securitydomain.host')
            secport = cs_cfg.get('securitydomain.httpsadminport')
            try:
                ca_list = self.get_ca_list_from_security_domain(
                    sechost, secport)
            except Exception as e:
                logger.error(
                    "unable to access security domain. Continuing .. %s ",
                    e)
                ca_list = []

            for ca in ca_list:
                ca_host = ca.hostname
                ca_port = ca.secure_port

                # catching all exceptions because we do not want to break if
                # the auth is not successful or servers are down.  In the
                # worst case, we will time out anyways.
                # noinspection PyBroadException
                # pylint: disable=W0703
                try:
                    self.execute_using_pki(
                        ca_port, ca_host, subsystemnick,
                        token_pwd, krahost, kraport)
                except Exception:
                    # ignore exceptions
                    logger.warning(
                        log.PKIHELPER_KRACONNECTOR_DEREGISTER_FAILURE_4,
                        str(krahost), str(kraport), str(ca_host), str(ca_port))

        except subprocess.CalledProcessError as exc:
            logger.warning(
                log.PKIHELPER_KRACONNECTOR_UPDATE_FAILURE_2,
                str(krahost),
                str(kraport))
            logger.error(log.PKI_SUBPROCESS_ERROR_1, exc)
            if critical_failure:
                raise
        return

    @staticmethod
    def get_ca_list_from_security_domain(sechost, secport):
        sd_connection = pki.client.PKIConnection(
            protocol='https',
            hostname=sechost,
            port=secport,
            subsystem='ca',
            trust_env=False)
        sd = pki.system.SecurityDomainClient(sd_connection)
        try:
            info = sd.get_security_domain_info()
        except requests.exceptions.HTTPError as e:
            logger.warning('Unable to get CA list from security domain: %s', e)
            logger.info('Trying older interface.')
            info = sd.get_old_security_domain_info()
        return list(info.systems['CA'].hosts.values())

    def execute_using_pki(
            self, caport, cahost, subsystemnick,
            token_pwd, krahost, kraport, critical_failure=False):
        command = ["/usr/bin/pki",
                   "-p", str(caport),
                   "-h", cahost,
                   "-n", subsystemnick,
                   "-P", "https",
                   "-d", self.mdict['pki_server_database_path'],
                   "-c", token_pwd,
                   "ca-kraconnector-del",
                   "--host", krahost,
                   "--port", str(kraport)]

        output = subprocess.check_output(command,
                                         stderr=subprocess.STDOUT)
        output = output.decode('utf-8')
        error = re.findall("ClientResponseFailure:(.*?)", output)
        if error:
            logger.warning(
                log.PKIHELPER_KRACONNECTOR_UPDATE_FAILURE_2,
                str(krahost),
                str(kraport))
            logger.error(log.PKI_SUBPROCESS_ERROR_1, output)
        if critical_failure:
            raise Exception(log.PKI_SUBPROCESS_ERROR_1 % output)

    def execute_using_sslget(
            self, caport, cahost, subsystemnick,
            token_pwd, krahost, kraport):
        update_url = "/ca/rest/admin/kraconnector/remove"

        params = "host=" + str(krahost) + \
                 "&port=" + str(kraport)

        command = ["/usr/bin/sslget",
                   "-n", subsystemnick,
                   "-p", token_pwd,
                   "-d", self.mdict['pki_server_database_path'],
                   "-e", params,
                   "-v",
                   "-r", update_url, cahost + ":" + str(caport)]

        # update KRA connector
        # Execute this "sslget" command
        # Note that sslget will return non-zero value for HTTP code != 200
        # and this will raise an exception
        subprocess.check_output(command, stderr=subprocess.STDOUT)


class TPSConnector:
    """PKI Deployment TPS Connector Class"""

    def __init__(self, deployer):
        self.mdict = deployer.mdict
        self.password = deployer.password

    def deregister(self, critical_failure=False):
        tkshost = None
        tksport = None
        try:
            # this is applicable to TPSs only
            if self.mdict['pki_subsystem_type'] != "tps":
                return

            logger.info(log.PKIHELPER_TPSCONNECTOR_UPDATE_CONTACT)

            cs_cfg = PKIConfigParser.read_simple_configuration_file(
                self.mdict['pki_target_cs_cfg'])
            tpshost = cs_cfg.get('service.machineName')
            tpsport = cs_cfg.get('pkicreate.secure_port')
            tkshost = cs_cfg.get('tps.connector.tks1.host')
            tksport = cs_cfg.get('tps.connector.tks1.port')
            if tkshost is None or tksport is None:
                logger.warning(log.PKIHELPER_TPSCONNECTOR_UPDATE_FAILURE)
                logger.error(log.PKIHELPER_UNDEFINED_TKS_HOST_PORT)
                if critical_failure:
                    raise Exception(log.PKIHELPER_UNDEFINED_TKS_HOST_PORT)
                else:
                    return

            # retrieve subsystem nickname
            subsystemnick = cs_cfg.get('tps.cert.subsystem.nickname')
            if subsystemnick is None:
                logger.warning(log.PKIHELPER_TPSCONNECTOR_UPDATE_FAILURE)
                logger.error(log.PKIHELPER_UNDEFINED_SUBSYSTEM_NICKNAME)
                if critical_failure:
                    raise Exception(log.PKIHELPER_UNDEFINED_SUBSYSTEM_NICKNAME)
                else:
                    return

            # retrieve name of token based upon type (hardware/software)
            if ':' in subsystemnick:
                token_name = subsystemnick.split(':')[0]
            else:
                token_name = pki.nssdb.INTERNAL_TOKEN_NAME

            token_pwd = self.password.get_password(
                self.mdict['pki_shared_password_conf'],
                token_name)

            if token_pwd is None or token_pwd == '':
                logger.warning(log.PKIHELPER_TPSCONNECTOR_UPDATE_FAILURE)
                logger.error(
                    log.PKIHELPER_UNDEFINED_TOKEN_PASSWD_1,
                    token_name)
                if critical_failure:
                    raise Exception(
                        log.PKIHELPER_UNDEFINED_TOKEN_PASSWD_1 % token_name)
                else:
                    return

            self.execute_using_pki(
                tkshost, tksport, subsystemnick,
                token_pwd, tpshost, tpsport)

        except subprocess.CalledProcessError as exc:
            logger.warning(
                log.PKIHELPER_TPSCONNECTOR_UPDATE_FAILURE_2,
                str(tkshost),
                str(tksport))
            logger.error(log.PKI_SUBPROCESS_ERROR_1, exc)
            if critical_failure:
                raise
        return

    def execute_using_pki(
            self, tkshost, tksport, subsystemnick,
            token_pwd, tpshost, tpsport, critical_failure=False):
        command = ["/usr/bin/pki",
                   "-p", str(tksport),
                   "-h", tkshost,
                   "-n", subsystemnick,
                   "-P", "https",
                   "-d", self.mdict['pki_server_database_path'],
                   "-c", token_pwd,
                   "-t", "tks",
                   "tks-tpsconnector-del",
                   "--host", tpshost,
                   "--port", str(tpsport)]

        output = subprocess.check_output(command,
                                         stderr=subprocess.STDOUT,
                                         shell=False)
        output = output.decode('utf-8')
        error = re.findall("ClientResponseFailure:(.*?)", output)
        if error:
            logger.warning(
                log.PKIHELPER_TPSCONNECTOR_UPDATE_FAILURE_2,
                str(tpshost),
                str(tpsport))
            logger.error(log.PKI_SUBPROCESS_ERROR_1, output)
        if critical_failure:
            raise Exception(log.PKI_SUBPROCESS_ERROR_1 % output)


class SecurityDomain:
    """PKI Deployment Security Domain Class"""

    def __init__(self, deployer):
        self.mdict = deployer.mdict
        self.password = deployer.password

    def deregister(self, install_token, critical_failure=False):
        # process this PKI subsystem instance's 'CS.cfg'
        cs_cfg = PKIConfigParser.read_simple_configuration_file(
            self.mdict['pki_target_cs_cfg'])

        # assign key name/value pairs
        machinename = cs_cfg.get('service.machineName')
        sport = cs_cfg.get('service.securityDomainPort')
        ncsport = cs_cfg.get('service.non_clientauth_securePort', '')
        sechost = cs_cfg.get('securitydomain.host')
        seceeport = cs_cfg.get('securitydomain.httpseeport')
        secagentport = cs_cfg.get('securitydomain.httpsagentport')
        secadminport = cs_cfg.get('securitydomain.httpsadminport')
        secname = cs_cfg.get('securitydomain.name', 'unknown')
        adminsport = cs_cfg.get('pkicreate.admin_secure_port', '')
        typeval = cs_cfg.get('cs.type', '')
        agentsport = cs_cfg.get('pkicreate.agent_secure_port', '')

        # fix ports for proxy settings
        proxy_secure_port = cs_cfg.get('proxy.securePort', '')
        if proxy_secure_port != '':
            adminsport = proxy_secure_port
            agentsport = proxy_secure_port
            sport = proxy_secure_port
            ncsport = proxy_secure_port

        # NOTE:  Don't check for the existence of 'httpport', as this will
        #        be undefined for a Security Domain that has been migrated!
        if sechost is None or\
           seceeport is None or\
           secagentport is None or\
           secadminport is None:
            logger.warning(
                log.PKIHELPER_SECURITY_DOMAIN_UPDATE_FAILURE_2,
                typeval,
                secname)
            logger.error(log.PKIHELPER_SECURITY_DOMAIN_UNDEFINED)
            if critical_failure:
                raise Exception(log.PKIHELPER_SECURITY_DOMAIN_UNDEFINED)
            else:
                return

        logger.info(
            'Unregistering %s subsystem from %s security domain',
            typeval,
            secname)

        listval = typeval.lower() + "List"
        update_url = "/ca/agent/ca/updateDomainXML"

        params = "name=" + "\"" + self.mdict['pki_instance_path'] + "\"" + \
                 "&type=" + str(typeval) + \
                 "&list=" + str(listval) + \
                 "&host=" + str(machinename) + \
                 "&sport=" + str(sport) + \
                 "&ncsport=" + str(ncsport) + \
                 "&adminsport=" + str(adminsport) + \
                 "&agentsport=" + str(agentsport) + \
                 "&operation=remove"

        if install_token:
            try:
                # first try install token-based servlet
                params += "&sessionID=" + str(install_token)
                admin_update_url = "/ca/admin/ca/updateDomainXML"
                command = ["/usr/bin/sslget",
                           "-p", str(123456),
                           "-d", self.mdict['pki_server_database_path'],
                           "-e", params,
                           "-v",
                           "-r", admin_update_url,
                           sechost + ":" + str(secadminport)]
                output = subprocess.check_output(
                    command,
                    stderr=subprocess.STDOUT)
                output = output.decode('utf-8')
            except subprocess.CalledProcessError:
                logger.warning(
                    log.PKIHELPER_SECURITY_DOMAIN_UNREACHABLE_1,
                    secname)
                output = self.update_domain_using_agent_port(
                    typeval, secname, params, update_url, sechost, secagentport,
                    critical_failure)
        else:
            output = self.update_domain_using_agent_port(
                typeval, secname, params, update_url, sechost, secagentport,
                critical_failure)

        if not output:
            if critical_failure:
                raise Exception("Cannot update domain using agent port")
            else:
                return

        logger.debug(
            log.PKIHELPER_SSLGET_OUTPUT_1,
            output)
        # Search the output for Status
        status = re.findall('<Status>(.*?)</Status>', output)
        if not status:
            logger.warning(
                log.PKIHELPER_SECURITY_DOMAIN_UNREACHABLE_1,
                secname)
            if critical_failure:
                raise Exception(
                    log.PKIHELPER_SECURITY_DOMAIN_UNREACHABLE_1 % secname)
        elif status[0] != "0":
            error = re.findall('<Error>(.*?)</Error>', output)
            if not error:
                error = ""
            logger.warning(
                log.PKIHELPER_SECURITY_DOMAIN_UNREGISTERED_2,
                typeval,
                secname)
            logger.error(
                log.PKIHELPER_SECURITY_DOMAIN_UPDATE_FAILURE_3,
                typeval,
                secname,
                error)
            if critical_failure:
                raise Exception(log.PKIHELPER_SECURITY_DOMAIN_UPDATE_FAILURE_3
                                %
                                (typeval, secname, error))
        else:
            logger.debug(
                'Unregistered %s subsystem from %s security domain',
                typeval,
                secname)

    def update_domain_using_agent_port(
            self, typeval, secname, params,
            update_url, sechost, secagentport, critical_failure=False):
        cs_cfg = PKIConfigParser.read_simple_configuration_file(
            self.mdict['pki_target_cs_cfg'])
        # retrieve subsystem nickname
        subsystemnick_param = typeval.lower() + ".cert.subsystem.nickname"
        subsystemnick = cs_cfg.get(subsystemnick_param)
        if subsystemnick is None:
            logger.warning(
                log.PKIHELPER_SECURITY_DOMAIN_UPDATE_FAILURE_2,
                typeval,
                secname)
            logger.error(log.PKIHELPER_UNDEFINED_SUBSYSTEM_NICKNAME)
            if critical_failure:
                raise Exception(log.PKIHELPER_UNDEFINED_SUBSYSTEM_NICKNAME)
            else:
                return

        # retrieve name of token based upon type (hardware/software)
        if ':' in subsystemnick:
            token_name = subsystemnick.split(':')[0]
        else:
            token_name = pki.nssdb.INTERNAL_TOKEN_NAME

        token_pwd = self.password.get_password(
            self.mdict['pki_shared_password_conf'],
            token_name)

        if token_pwd is None or token_pwd == '':
            logger.warning(
                log.PKIHELPER_SECURITY_DOMAIN_UPDATE_FAILURE_2,
                typeval,
                secname)
            if critical_failure:
                raise Exception(
                    log.PKIHELPER_SECURITY_DOMAIN_UPDATE_FAILURE_2 %
                    (typeval, secname))
            else:
                return

        command = ["/usr/bin/sslget",
                   "-n", subsystemnick,
                   "-p", token_pwd,
                   "-d", self.mdict['pki_server_database_path'],
                   "-e", params,
                   "-v",
                   "-r", update_url, sechost + ":" + str(secagentport)]
        try:
            output = subprocess.check_output(command,
                                             stderr=subprocess.STDOUT)
            output = output.decode('utf-8')
            return output
        except subprocess.CalledProcessError as exc:
            logger.warning(
                log.PKIHELPER_SECURITY_DOMAIN_UPDATE_FAILURE_2,
                typeval,
                secname)
            logger.warning(
                log.PKIHELPER_SECURITY_DOMAIN_UNREACHABLE_1,
                secname)
            logger.error(log.PKI_SUBPROCESS_ERROR_1, exc)
            if critical_failure:
                raise

        return None


class Systemd(object):
    """PKI Deployment Execution Management Class"""

    def __init__(self, deployer):
        """PKI Deployment execution management __init__ method.

        Args:
          deployer (dictionary):  PKI Deployment name/value parameters
        """
        self.mdict = deployer.mdict
        self.deployer = deployer
        instance_name = deployer.mdict['pki_instance_name']

        unit_file = 'pki-tomcatd@%s.service' % instance_name
        systemd_link = os.path.join(
            '/etc/systemd/system/pki-tomcatd.target.wants',
            unit_file)
        override_dir = '/etc/systemd/system/pki-tomcatd@{}.service.d'.format(
            instance_name)
        self.base_override_dir = override_dir

        nuxwdog_unit_file = 'pki-tomcatd-nuxwdog@%s.service' % instance_name
        nuxwdog_systemd_link = os.path.join(
            '/etc/systemd/system/pki-tomcatd-nuxwdog.target.wants',
            nuxwdog_unit_file)
        nuxwdog_override_dir = (
            '/etc/systemd/system/pki-tomcatd-nuxwdog@{}.service.d'.format(
                instance_name))
        self.nuxwdog_override_dir = nuxwdog_override_dir

        # self.overrides will be a hash of ConfigParsers indexed by filename
        # once the overrides have been constructed, the caller should call
        # write_overrides()
        self.overrides = {}

        if os.path.exists(nuxwdog_systemd_link):
            self.is_nuxwdog_enabled = True
            self.service_name = nuxwdog_unit_file
            self.systemd_link = nuxwdog_systemd_link
            self.override_dir = nuxwdog_override_dir
        else:
            self.is_nuxwdog_enabled = False
            self.service_name = unit_file
            self.systemd_link = systemd_link
            self.override_dir = override_dir

    def create_override_directory(self):
        self.deployer.directory.create(self.override_dir, uid=0, gid=0)

    def create_override_file(self, fname):
        self.create_override_directory()
        self.deployer.file.create(
            os.path.join(self.override_dir, fname),
            uid=0, gid=0
        )

    def set_override(self, section, param, value, fname='local.conf'):
        if fname not in self.overrides:
            parser = configparser.ConfigParser()
            parser.optionxform = str
            override_file = os.path.join(self.override_dir, fname)
            if os.path.exists(override_file):
                parser.read(override_file)
            self.overrides[fname] = parser
        else:
            parser = self.overrides[fname]

        if not parser.has_section(section):
            parser.add_section(section)

        parser.set(section, param, value)

    def write_overrides(self):
        for fname, parser in self.overrides.items():
            override_file = os.path.join(self.override_dir, fname)
            if not os.path.exists(override_file):
                self.create_override_file(override_file)
            with open(override_file, 'w') as fp:
                parser.write(fp)

    def daemon_reload(self, critical_failure=True):
        """PKI Deployment execution management lifecycle function.

        Executes a 'systemd daemon-reload' system command.

        Args:
          critical_failure (boolean, optional):  Raise exception on failures;
                                                 defaults to 'True'.

        Attributes:

        Returns:

        Raises:
          subprocess.CalledProcessError:  If 'critical_failure' is 'True'.

        Examples:

        """
        try:
            # Compose this "systemd" execution management lifecycle command
            command = ["systemctl", "daemon-reload"]
            # Display this "systemd" execution management lifecycle command
            logger.debug('Command: %s', ' '.join(command))
            # Execute this "systemd" execution management lifecycle command
            subprocess.check_call(command)
        except subprocess.CalledProcessError as exc:
            logger.error(log.PKI_SUBPROCESS_ERROR_1, exc)
            if critical_failure:
                raise
        return


class ConfigClient:
    """PKI Deployment Configuration Client"""

    def __init__(self, deployer):
        self.deployer = deployer
        self.mdict = deployer.mdict
        # set useful 'boolean' object variables for this class
        self.clone = config.str2bool(self.mdict['pki_clone'])

        self.existing = config.str2bool(self.mdict['pki_existing'])
        self.external = config.str2bool(self.mdict['pki_external'])
        self.external_step_two = config.str2bool(
            self.mdict['pki_external_step_two'])

        self.standalone = config.str2bool(self.mdict['pki_standalone'])
        self.subordinate = config.str2bool(self.mdict['pki_subordinate'])
        # set useful 'string' object variables for this class
        self.subsystem = self.mdict['pki_subsystem']
        # generic extension support in CSR - for external CA
        self.add_req_ext = config.str2bool(
            self.mdict['pki_req_ext_add'])
        self.security_domain_type = self.mdict['pki_security_domain_type']
        self.san_inject = config.str2bool(self.mdict['pki_san_inject'])

    def process_admin_cert(self, admin_cert):
        logger.debug('admin cert: %s', admin_cert)

        # Store the Administration Certificate in a file
        admin_cert_file = self.mdict['pki_client_admin_cert']
        admin_cert_bin_file = admin_cert_file + ".der"
        self.save_admin_cert(admin_cert, admin_cert_file,
                             self.mdict['pki_subsystem_name'])

        # convert the cert file to binary
        command = ["AtoB", admin_cert_file, admin_cert_bin_file]
        logger.debug('Command: %s', ' '.join(command))
        try:
            subprocess.check_call(command)
        except subprocess.CalledProcessError as exc:
            logger.error(log.PKI_SUBPROCESS_ERROR_1, exc)
            raise

        os.chmod(admin_cert_file,
                 config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS)

        os.chmod(admin_cert_bin_file,
                 config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS)

        # Import the Administration Certificate
        # into the client NSS security database
        self.deployer.certutil.import_cert(
            re.sub("&#39;", "'", self.mdict['pki_admin_nickname']),
            "u,u,u",
            admin_cert_bin_file,
            self.mdict['pki_client_password_conf'],
            self.mdict['pki_client_database_dir'],
            None,
            True)

        # create directory for p12 file if it does not exist
        self.deployer.directory.create(os.path.dirname(
            self.mdict['pki_client_admin_cert_p12']))

        # Export the Administration Certificate from the
        # client NSS security database into a PKCS #12 file
        self.deployer.pk12util.create_file(
            self.mdict['pki_client_admin_cert_p12'],
            re.sub("&#39;", "'", self.mdict['pki_admin_nickname']),
            self.mdict['pki_client_pkcs12_password_conf'],
            self.mdict['pki_client_password_conf'],
            self.mdict['pki_client_database_dir'])

        os.chmod(
            self.mdict['pki_client_admin_cert_p12'],
            config.PKI_DEPLOYMENT_DEFAULT_SECURITY_DATABASE_PERMISSIONS)

    def create_config_request(self, nssdb):

        logger.info('Creating config request')

        data = pki.system.ConfigurationRequest()

        # Miscellaneous Configuration Information
        data.pin = self.mdict['pki_one_time_pin']

        # Process existing CA installation like external CA
        data.external = self.external or self.existing
        data.standAlone = self.standalone

        # Cloning parameters
        if self.clone:
            data.isClone = "true"
            data.cloneUri = self.mdict['pki_clone_uri']
        else:
            data.isClone = "false"

        # Hierarchy
        self.set_hierarchy_parameters(data)

        # Security Domain
        if self.security_domain_type != "new":
            data.securityDomainType = "existingdomain"
            self.set_existing_security_domain(data)
        else:
            # PKI CA, External CA, or Stand-alone PKI
            data.securityDomainType = "newdomain"

        if self.subordinate and \
                config.str2bool(self.mdict['pki_subordinate_create_new_security_domain']):
            data.securityDomainType = "newsubdomain"
            self.set_existing_security_domain(data)

        try:
            d = int(self.mdict['pki_security_domain_post_login_sleep_seconds'])
            if d > 0:
                data.securityDomainPostLoginSleepSeconds = d
        except (KeyError, ValueError):
            pass

        # Issuing CA Information
        self.set_issuing_ca_parameters(data)

        data.systemCertsImported = \
            self.mdict['pki_server_pkcs12_path'] != '' or \
            self.mdict['pki_clone_pkcs12_path'] != ''

        # Create system certs
        self.set_system_certs(nssdb, data)

        # TPS parameters
        if self.subsystem == "TPS":
            self.set_tps_parameters(data)

        # Misc CA parameters
        if self.subsystem == "CA":
            data.startingCRLNumber = self.mdict['pki_ca_starting_crl_number']
            data.createSigningCertRecord = (
                self.mdict['pki_ca_signing_record_create'].lower()
            )
            data.signingCertSerialNumber = (
                self.mdict['pki_ca_signing_serial_number'].lower()
            )

        return data

    def create_database_setup_request(self):

        logger.info('Creating database setup request')

        request = pki.system.DatabaseSetupRequest()

        request.pin = self.mdict['pki_one_time_pin']

        if self.clone:
            request.isClone = "true"
        else:
            request.isClone = "false"

        request.masterReplicationPort = self.mdict['pki_clone_replication_master_port']
        request.cloneReplicationPort = self.mdict['pki_clone_replication_clone_port']

        if config.str2bool(self.mdict['pki_clone_replicate_schema']):
            request.replicateSchema = "true"
        else:
            request.replicateSchema = "false"

        request.replicationSecurity = self.mdict['pki_clone_replication_security']
        request.replicationPassword = self.mdict['pki_replication_password']

        return request

    def create_admin_setup_request(self):

        logger.info('Creating admin setup request')

        request = pki.system.AdminSetupRequest()

        request.pin = self.mdict['pki_one_time_pin']

        self.set_admin_parameters(request)

        return request

    def create_key_backup_request(self):

        logger.info('Creating key backup request')

        request = pki.system.KeyBackupRequest()

        request.pin = self.mdict['pki_one_time_pin']

        self.set_backup_parameters(request)

        return request

    def save_admin_csr(self):
        logger.info(
            log.PKI_CONFIG_EXTERNAL_CSR_SAVE_PKI_ADMIN_2,
            self.subsystem,
            self.mdict['pki_admin_csr_path'])
        self.deployer.directory.create(
            os.path.dirname(self.mdict['pki_admin_csr_path']))
        with open(self.mdict['pki_admin_csr_path'], "w") as f:
            f.write("-----BEGIN CERTIFICATE REQUEST-----\n")
        with open(os.path.join(
                  self.mdict['pki_client_database_dir'],
                  "admin_pkcs10.bin.asc"), "r") as f:
            admin_certreq = f.read()
        with open(self.mdict['pki_admin_csr_path'], "a") as f:
            f.write(admin_certreq)
            f.write("-----END CERTIFICATE REQUEST-----")
        # Read in and print Admin certificate request
        with open(self.mdict['pki_admin_csr_path'], "r") as f:
            admin_certreq = f.read()
        logger.info('Admin request: %s', admin_certreq)

    def save_admin_cert(self, input_data, output_file, subsystem_name):
        logger.debug(
            log.PKI_CONFIG_ADMIN_CERT_SAVE_2,
            subsystem_name,
            output_file)
        with open(output_file, "w") as f:
            f.write(input_data)

    def save_system_csr(self, request, message, path, subsystem=None):
        if subsystem is not None:
            logger.info(message, subsystem, path)
        else:
            logger.info(message, path)
        self.deployer.directory.create(os.path.dirname(path))
        csr = pki.nssdb.convert_csr(request, 'base64', 'pem')
        with open(path, "w") as f:
            f.write(csr)
        # Print this certificate request
        logger.info('Request:\n%s', csr)

    def load_system_cert(self, nssdb, cert, nickname=None):

        if not nickname:
            nickname = cert.nickname

        logger.info('Loading system cert: %s', nickname)

        certdata = nssdb.get_cert(
            nickname=nickname,
            output_format='base64',
            output_text=True,  # JSON encoder needs text
        )
        cert.cert = certdata

    def set_system_certs(self, nssdb, data):
        systemCerts = []  # nopep8

        # Create 'CA Signing Certificate'
        if not self.clone:
            if self.subsystem == "CA" or self.standalone:
                cert1 = None

                if self.subsystem == "CA":
                    # PKI CA, Subordinate CA, or External CA
                    cert1 = self.create_system_cert("ca_signing")

                    cert1.signingAlgorithm = \
                        self.mdict['pki_ca_signing_signing_algorithm']

                    # generic extension support in CSR - for external CA
                    if self.add_req_ext:
                        cert1.req_ext_oid = \
                            self.mdict['pki_req_ext_oid']
                        cert1.req_ext_critical = \
                            self.mdict['pki_req_ext_critical']
                        cert1.req_ext_data = \
                            self.mdict['pki_req_ext_data']

                if self.external and self.external_step_two:
                    # external/existing CA step 2

                    # If specified, load the externally-signed CA cert
                    if self.mdict['pki_cert_chain_nickname']:
                        self.load_system_cert(
                            nssdb, cert1, self.mdict['pki_cert_chain_nickname'])

                    systemCerts.append(cert1)

                elif self.subsystem == "CA":
                    # PKI CA or Subordinate CA
                    systemCerts.append(cert1)

        # Create 'OCSP Signing Certificate'
        if not self.clone:
            if (self.subsystem == "OCSP" and
                    self.standalone and
                    self.external_step_two):
                # Stand-alone PKI OCSP (Step 2)
                cert2 = self.create_system_cert("ocsp_signing")
                # Load the Stand-alone PKI OCSP 'OCSP Signing Certificate'
                # (Step 2)
                self.load_system_cert(nssdb, cert2)
                cert2.signingAlgorithm = \
                    self.mdict['pki_ocsp_signing_signing_algorithm']
                systemCerts.append(cert2)
            elif self.subsystem == "CA" or self.subsystem == "OCSP":
                # External CA, Subordinate CA, PKI CA, or PKI OCSP
                cert2 = self.create_system_cert("ocsp_signing")
                cert2.signingAlgorithm = \
                    self.mdict['pki_ocsp_signing_signing_algorithm']
                systemCerts.append(cert2)

        # Create 'SSL Server Certificate'
        # all subsystems

        # create new sslserver cert only if this is a new instance
        system_list = self.deployer.instance.tomcat_instance_subsystems()
        if self.standalone and self.external_step_two:
            # Stand-alone PKI (Step 2)
            cert3 = self.create_system_cert("sslserver")
            # Load the Stand-alone PKI 'SSL Server Certificate' (Step 2)
            self.load_system_cert(nssdb, cert3)
            systemCerts.append(cert3)
        elif len(system_list) >= 2:
            # Existing PKI Instance
            data.generateServerCert = "false"
            for subsystem in system_list:
                dst = self.mdict['pki_instance_path'] + '/conf/' + \
                    subsystem.lower() + '/CS.cfg'
                if subsystem != self.subsystem and os.path.exists(dst):
                    cert3 = self.retrieve_existing_server_cert(dst)
                    systemCerts.append(cert3)
                    break
        else:
            # PKI CA, PKI KRA, PKI OCSP, PKI RA, PKI TKS, PKI TPS,
            # CA Clone, KRA Clone, OCSP Clone, TKS Clone, TPS Clone,
            # Subordinate CA, or External CA
            cert3 = self.create_system_cert("sslserver")
            systemCerts.append(cert3)

        # Create 'Subsystem Certificate'
        if not self.clone:
            if self.standalone and self.external_step_two:
                data.generateSubsystemCert = "true"
                # Stand-alone PKI (Step 2)
                cert4 = self.create_system_cert("subsystem")
                # Load the Stand-alone PKI 'Subsystem Certificate' (Step 2)
                self.load_system_cert(nssdb, cert4)
                systemCerts.append(cert4)
            elif len(system_list) >= 2:
                # Existing PKI Instance
                data.generateSubsystemCert = "false"
                for subsystem in system_list:
                    dst = self.mdict['pki_instance_path'] + '/conf/' + \
                        subsystem.lower() + '/CS.cfg'
                    if subsystem != self.subsystem and os.path.exists(dst):
                        cert4 = self.retrieve_existing_subsystem_cert(dst)
                        systemCerts.append(cert4)
                        break
            else:
                # PKI KRA, PKI OCSP, PKI RA, PKI TKS, PKI TPS,
                # Subordinate CA, or External CA
                data.generateSubsystemCert = "true"
                cert4 = self.create_system_cert("subsystem")
                systemCerts.append(cert4)

        # Create 'Audit Signing Certificate'
        if not self.clone:
            if self.standalone and self.external_step_two:
                # Stand-alone PKI (Step 2)
                cert5 = self.create_system_cert("audit_signing")
                # Load the Stand-alone PKI 'Audit Signing Certificate' (Step 2)
                self.load_system_cert(nssdb, cert5)
                cert5.signingAlgorithm = \
                    self.mdict['pki_audit_signing_signing_algorithm']
                systemCerts.append(cert5)
            elif self.subsystem != "RA":
                cert5 = self.create_system_cert("audit_signing")
                cert5.signingAlgorithm = \
                    self.mdict['pki_audit_signing_signing_algorithm']
                systemCerts.append(cert5)

        # Create 'DRM Transport Certificate' and 'DRM Storage Certificate'
        if not self.clone:
            if (self.subsystem == "KRA" and
                    self.standalone and
                    self.external_step_two):
                # Stand-alone PKI KRA Transport Certificate (Step 2)
                cert6 = self.create_system_cert("transport")
                # Load the Stand-alone PKI KRA 'Transport Certificate' (Step 2)
                self.load_system_cert(nssdb, cert6)
                systemCerts.append(cert6)
                # Stand-alone PKI KRA Storage Certificate (Step 2)
                cert7 = self.create_system_cert("storage")
                # Load the Stand-alone PKI KRA 'Storage Certificate' (Step 2)
                self.load_system_cert(nssdb, cert7)
                systemCerts.append(cert7)
            elif self.subsystem == "KRA":
                # PKI KRA Transport Certificate
                cert6 = self.create_system_cert("transport")
                systemCerts.append(cert6)
                # PKI KRA Storage Certificate
                cert7 = self.create_system_cert("storage")
                systemCerts.append(cert7)

        data.systemCerts = systemCerts

    def set_hierarchy_parameters(self, data):
        if self.subsystem == "CA":
            if self.clone:
                # Cloned CA
                data.hierarchy = "root"
            elif self.external:
                # External CA
                data.hierarchy = "join"
            elif self.subordinate:
                # Subordinate CA
                data.hierarchy = "join"
            else:
                # PKI CA
                data.hierarchy = "root"

    def set_existing_security_domain(self, data):
        data.securityDomainUri = self.mdict['pki_security_domain_uri']
        data.securityDomainUser = self.mdict['pki_security_domain_user']
        data.securityDomainPassword = self.mdict[
            'pki_security_domain_password']

    def set_backup_parameters(self, data):
        data.backupFile = self.mdict['pki_backup_keys_p12']
        data.backupPassword = self.mdict['pki_backup_password']

    def set_admin_parameters(self, data):
        data.adminEmail = self.mdict['pki_admin_email']
        data.adminName = self.mdict['pki_admin_name']
        data.adminPassword = self.mdict['pki_admin_password']
        data.adminKeyType = self.mdict['pki_admin_key_type']
        data.adminProfileID = self.mdict['pki_admin_profile_id']
        data.adminUID = self.mdict['pki_admin_uid']
        data.adminSubjectDN = self.mdict['pki_admin_subject_dn']

        if self.standalone or self.external and self.subsystem in ['KRA', 'OCSP']:
            if not self.external_step_two:
                # IMPORTANT:  ALWAYS set 'pki_import_admin_cert' FALSE for
                #             Stand-alone PKI (Step 1)
                self.mdict['pki_import_admin_cert'] = "False"
            else:
                # IMPORTANT:  ALWAYS set 'pki_import_admin_cert' TRUE for
                #             Stand-alone PKI (Step 2)
                self.mdict['pki_import_admin_cert'] = "True"

        if config.str2bool(self.mdict['pki_import_admin_cert']):
            data.importAdminCert = "true"

            client_nssdb = pki.nssdb.NSSDatabase(
                directory=self.mdict['pki_client_database_dir'],
                password=self.mdict['pki_client_database_password'])

            try:
                logger.info(
                    'Loading admin cert from client database: %s',
                    self.mdict['pki_admin_nickname'])

                data.adminCert = client_nssdb.get_cert(
                    nickname=self.mdict['pki_admin_nickname'],
                    output_format='base64',
                    output_text=True,  # JSON encoder needs text
                )

                logger.debug('Admin cert: %s', data.adminCert)

                if data.adminCert:
                    return

            finally:
                client_nssdb.close()

            if self.standalone or self.external and self.subsystem in ['KRA', 'OCSP']:

                # Stand-alone/External PKI (Step 2)
                #
                # Copy the externally-issued admin certificate into
                # 'ca_admin.cert' under the specified 'pki_client_dir'
                # stripping the certificate HEADER/FOOTER prior to saving it.

                logger.info(
                    'Loading admin cert from %s',
                    self.mdict['pki_admin_cert_path'])

                imported_admin_cert = ""
                with open(self.mdict['pki_admin_cert_path'], "r") as f:
                    for line in f:
                        if line.startswith("-----BEGIN CERTIFICATE-----"):
                            continue
                        elif line.startswith("-----END CERTIFICATE-----"):
                            continue
                        else:
                            imported_admin_cert += line

                logger.info(
                    'Storing admin cert into %s',
                    self.mdict['pki_admin_cert_file'])

                with open(self.mdict['pki_admin_cert_file'], "w") as f:
                    f.write(imported_admin_cert)

            logger.info(
                'Loading admin cert from %s',
                self.mdict['pki_admin_cert_file'])

            with open(self.mdict['pki_admin_cert_file'], "r") as f:
                b64 = f.read().replace('\n', '')

            logger.debug('Admin cert: %s', b64)

            data.adminCert = b64

        else:
            data.importAdminCert = "false"
            data.adminSubjectDN = self.mdict['pki_admin_subject_dn']
            if self.mdict['pki_admin_cert_request_type'] == "pkcs10":
                data.adminCertRequestType = "pkcs10"

                noise_file = os.path.join(
                    self.mdict['pki_client_database_dir'], "noise")

                output_file = os.path.join(
                    self.mdict['pki_client_database_dir'], "admin_pkcs10.bin")

                # note: in the function below, certutil is used to generate
                # the request for the admin cert.  The keys are generated
                # by NSS, which does not actually use the data in the noise
                # file, so it does not matter what is in this file.  Certutil
                # still requires it though, otherwise it waits for keyboard
                # input.
                with open(noise_file, 'w') as f:
                    f.write("not_so_random_data")

                self.deployer.certutil.generate_certificate_request(
                    self.mdict['pki_admin_subject_dn'],
                    self.mdict['pki_admin_key_type'],
                    self.mdict['pki_admin_key_size'],
                    self.mdict['pki_client_password_conf'],
                    noise_file,
                    output_file,
                    self.mdict['pki_client_database_dir'],
                    None, None, True)

                self.deployer.file.delete(noise_file)

                # convert output to ascii
                command = ["BtoA", output_file, output_file + ".asc"]
                logger.debug('Command: %s', ' '.join(command))
                try:
                    subprocess.check_call(command)
                except subprocess.CalledProcessError as exc:
                    logger.error(log.PKI_SUBPROCESS_ERROR_1, exc)
                    raise

                if self.standalone and not self.external_step_two:
                    # For convenience and consistency, save a copy of
                    # the Stand-alone PKI 'Admin Certificate' CSR to the
                    # specified "pki_admin_csr_path" location
                    # (Step 1)
                    self.save_admin_csr()
                    # IMPORTANT:  ALWAYS save the client database for
                    #             Stand-alone PKI (Step 1)
                    self.mdict['pki_client_database_purge'] = "False"

                with open(output_file + ".asc", "r") as f:
                    b64 = f.read().replace('\n', '')

                data.adminCertRequest = b64
            else:
                print("log.PKI_CONFIG_PKCS10_SUPPORT_ONLY")
                raise Exception(log.PKI_CONFIG_PKCS10_SUPPORT_ONLY)

    def set_issuing_ca_parameters(self, data):
        if (self.subsystem != "CA" or
                self.clone or
                self.subordinate or
                self.external):
            # PKI KRA, PKI OCSP, PKI RA, PKI TKS, PKI TPS,
            # CA Clone, KRA Clone, OCSP Clone, TKS Clone, TPS Clone,
            # Subordinate CA, External CA, or Stand-alone PKI
            data.issuingCA = self.mdict['pki_issuing_ca']

    def set_tps_parameters(self, data):
        data.caUri = self.mdict['pki_ca_uri']
        data.tksUri = self.mdict['pki_tks_uri']
        data.enableServerSideKeyGen = \
            self.mdict['pki_enable_server_side_keygen']
        if config.str2bool(self.mdict['pki_enable_server_side_keygen']):
            data.kraUri = self.mdict['pki_kra_uri']
        data.authdbHost = self.mdict['pki_authdb_hostname']
        data.authdbPort = self.mdict['pki_authdb_port']
        data.authdbBaseDN = self.mdict['pki_authdb_basedn']
        data.authdbSecureConn = self.mdict['pki_authdb_secure_conn']
        data.importSharedSecret = self.mdict['pki_import_shared_secret']

    def create_system_cert(self, tag):
        cert = pki.system.SystemCertData()
        cert.tag = self.mdict["pki_%s_tag" % tag]
        cert.keyAlgorithm = self.mdict["pki_%s_key_algorithm" % tag]
        cert.keySize = self.mdict["pki_%s_key_size" % tag]
        cert.keyType = self.mdict["pki_%s_key_type" % tag]
        cert.nickname = self.mdict["pki_%s_nickname" % tag]
        cert.subjectDN = self.mdict["pki_%s_subject_dn" % tag]
        cert.token = self.mdict["pki_%s_token" % tag]
        if tag == 'sslserver' and self.san_inject:
            cert.san_for_server_cert = \
                self.mdict['pki_san_for_server_cert']
        return cert

    def retrieve_existing_server_cert(self, cfg_file):
        cs_cfg = PKIConfigParser.read_simple_configuration_file(cfg_file)
        cstype = cs_cfg.get('cs.type').lower()
        cert = pki.system.SystemCertData()
        cert.tag = self.mdict["pki_sslserver_tag"]
        cert.keyAlgorithm = self.mdict["pki_sslserver_key_algorithm"]
        cert.keySize = self.mdict["pki_sslserver_key_size"]
        cert.keyType = self.mdict["pki_sslserver_key_type"]
        cert.nickname = cs_cfg.get(cstype + ".sslserver.nickname")
        cert.cert = cs_cfg.get(cstype + ".sslserver.cert")
        cert.request = cs_cfg.get(cstype + ".sslserver.certreq")
        cert.subjectDN = self.mdict["pki_sslserver_subject_dn"]
        cert.token = cs_cfg.get(cstype + ".sslserver.tokenname")
        return cert

    def retrieve_existing_subsystem_cert(self, cfg_file):
        cs_cfg = PKIConfigParser.read_simple_configuration_file(cfg_file)
        cstype = cs_cfg.get('cs.type').lower()
        cert = pki.system.SystemCertData()
        cert.tag = self.mdict["pki_subsystem_tag"]
        cert.keyAlgorithm = cs_cfg.get("cloning.subsystem.keyalgorithm")
        cert.keySize = self.mdict["pki_subsystem_key_size"]
        cert.keyType = cs_cfg.get("cloning.subsystem.keytype")
        cert.nickname = cs_cfg.get(cstype + ".subsystem.nickname")
        cert.cert = cs_cfg.get(cstype + ".subsystem.cert")
        cert.request = cs_cfg.get(cstype + ".subsystem.certreq")
        cert.subjectDN = cs_cfg.get("cloning.subsystem.dn")
        cert.token = cs_cfg.get(cstype + ".subsystem.tokenname")
        return cert
