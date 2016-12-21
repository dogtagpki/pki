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
import errno
import sys
import os
import fileinput
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
from lxml import etree
import zipfile

# PKI Deployment Imports
from . import pkiconfig as config
from .pkiconfig import pki_selinux_config_ports as ports
from . import pkimanifest as manifest
from . import pkimessages as log
from .pkiparser import PKIConfigParser
import pki.client
import pki.system
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


class Identity:
    """PKI Deployment Identity Class"""

    def __init__(self, deployer):
        self.mdict = deployer.mdict

    def __add_gid(self, pki_group):
        try:
            # Does the specified 'pki_group' exist?
            pki_gid = getgrnam(pki_group)[2]
            # Yes, group 'pki_group' exists!
            config.pki_log.info(log.PKIHELPER_GROUP_ADD_2, pki_group, pki_gid,
                                extra=config.PKI_INDENTATION_LEVEL_2)
        except KeyError as exc:
            # No, group 'pki_group' does not exist!
            config.pki_log.debug(log.PKIHELPER_GROUP_ADD_KEYERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            try:
                # Is the default well-known GID already defined?
                group = getgrgid(config.PKI_DEPLOYMENT_DEFAULT_GID)[0]
                # Yes, the default well-known GID exists!
                config.pki_log.info(log.PKIHELPER_GROUP_ADD_DEFAULT_2,
                                    group, config.PKI_DEPLOYMENT_DEFAULT_GID,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                # Attempt to create 'pki_group' using a random GID.
                command = ["/usr/sbin/groupadd", pki_group]
            except KeyError as exc:
                # No, the default well-known GID does not exist!
                config.pki_log.debug(log.PKIHELPER_GROUP_ADD_GID_KEYERROR_1,
                                     exc, extra=config.PKI_INDENTATION_LEVEL_2)
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
                # Execute this "groupadd" command.
                with open(os.devnull, "w") as fnull:
                    subprocess.check_call(command, stdout=fnull, stderr=fnull,
                                          close_fds=True)
            except subprocess.CalledProcessError as exc:
                config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                raise
            except OSError as exc:
                config.pki_log.error(log.PKI_OSERROR_1, exc,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                raise
        return

    def __add_uid(self, pki_user, pki_group):
        try:
            # Does the specified 'pki_user' exist?
            pki_uid = getpwnam(pki_user)[2]
            # Yes, user 'pki_user' exists!
            config.pki_log.info(log.PKIHELPER_USER_ADD_2, pki_user, pki_uid,
                                extra=config.PKI_INDENTATION_LEVEL_2)
            # NOTE:  For now, never check validity of specified 'pki_group'!
        except KeyError as exc:
            # No, user 'pki_user' does not exist!
            config.pki_log.debug(log.PKIHELPER_USER_ADD_KEYERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            try:
                # Is the default well-known UID already defined?
                user = getpwuid(config.PKI_DEPLOYMENT_DEFAULT_UID)[0]
                # Yes, the default well-known UID exists!
                config.pki_log.info(log.PKIHELPER_USER_ADD_DEFAULT_2,
                                    user, config.PKI_DEPLOYMENT_DEFAULT_UID,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                # Attempt to create 'pki_user' using a random UID.
                command = ["/usr/sbin/useradd",
                           "-g", pki_group,
                           "-d", config.PKI_DEPLOYMENT_SOURCE_ROOT,
                           "-s", config.PKI_DEPLOYMENT_DEFAULT_SHELL,
                           "-c", config.PKI_DEPLOYMENT_DEFAULT_COMMENT,
                           pki_user]
            except KeyError as exc:
                # No, the default well-known UID does not exist!
                config.pki_log.debug(log.PKIHELPER_USER_ADD_UID_KEYERROR_1,
                                     exc, extra=config.PKI_INDENTATION_LEVEL_2)
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
                # Execute this "useradd" command.
                with open(os.devnull, "w") as fnull:
                    subprocess.check_call(command, stdout=fnull, stderr=fnull,
                                          close_fds=True)
            except subprocess.CalledProcessError as exc:
                config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                raise
            except OSError as exc:
                config.pki_log.error(log.PKI_OSERROR_1, exc,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
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
            config.pki_log.error(log.PKI_KEYERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
            return None

    def get_gid(self, critical_failure=True):
        try:
            return self.mdict['pki_gid']
        except KeyError as exc:
            config.pki_log.error(log.PKI_KEYERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
            return None

    def set_uid(self, name, critical_failure=True):
        try:
            config.pki_log.debug(log.PKIHELPER_USER_1, name,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            # id -u <name>
            pki_uid = getpwnam(name)[2]
            self.mdict['pki_uid'] = pki_uid
            config.pki_log.debug(log.PKIHELPER_UID_2, name, pki_uid,
                                 extra=config.PKI_INDENTATION_LEVEL_3)
            return pki_uid
        except KeyError as exc:
            config.pki_log.error(log.PKI_KEYERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
            return None

    def set_gid(self, name, critical_failure=True):
        try:
            config.pki_log.debug(log.PKIHELPER_GROUP_1, name,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            # id -g <name>
            pki_gid = getgrnam(name)[2]
            self.mdict['pki_gid'] = pki_gid
            config.pki_log.debug(log.PKIHELPER_GID_2, name, pki_gid,
                                 extra=config.PKI_INDENTATION_LEVEL_3)
            return pki_gid
        except KeyError as exc:
            config.pki_log.error(log.PKI_KEYERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
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
                config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                raise
            except OSError as exc:
                config.pki_log.error(log.PKI_OSERROR_1, exc,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
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
                config.pki_log.error(
                    log.PKIHELPER_NAMESPACE_COLLISION_2,
                    self.mdict['pki_instance_name'],
                    self.mdict['pki_instance_path'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(
                    log.PKIHELPER_NAMESPACE_COLLISION_2 % (
                        self.mdict['pki_instance_name'],
                        self.mdict['pki_instance_path']))
        else:
            if os.path.exists(
                    self.mdict['pki_target_tomcat_conf_instance_id']):
                # Top-Level "/etc/sysconfig" path collision
                config.pki_log.error(
                    log.PKIHELPER_NAMESPACE_COLLISION_2,
                    self.mdict['pki_instance_name'],
                    self.mdict['pki_target_tomcat_conf_instance_id'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(
                    log.PKIHELPER_NAMESPACE_COLLISION_2 % (
                        self.mdict['pki_instance_name'],
                        self.mdict['pki_target_tomcat_conf_instance_id']))
            if os.path.exists(self.mdict['pki_cgroup_systemd_service']):
                # Systemd cgroup path collision
                config.pki_log.error(
                    log.PKIHELPER_NAMESPACE_COLLISION_2,
                    self.mdict['pki_instance_name'],
                    self.mdict['pki_cgroup_systemd_service_path'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(
                    log.PKIHELPER_NAMESPACE_COLLISION_2 % (
                        self.mdict['pki_instance_name'],
                        self.mdict['pki_cgroup_systemd_service_path']))
            if os.path.exists(self.mdict['pki_cgroup_cpu_systemd_service']):
                # Systemd cgroup CPU path collision
                config.pki_log.error(
                    log.PKIHELPER_NAMESPACE_COLLISION_2,
                    self.mdict['pki_instance_name'],
                    self.mdict['pki_cgroup_cpu_systemd_service_path'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(
                    log.PKIHELPER_NAMESPACE_COLLISION_2 % (
                        self.mdict['pki_instance_name'],
                        self.mdict['pki_cgroup_cpu_systemd_service_path']))
        if os.path.exists(self.mdict['pki_instance_log_path']) and\
           os.path.exists(self.mdict['pki_subsystem_log_path']):
            # Top-Level PKI log path collision
            config.pki_log.error(
                log.PKIHELPER_NAMESPACE_COLLISION_2,
                self.mdict['pki_instance_name'],
                self.mdict['pki_instance_log_path'],
                extra=config.PKI_INDENTATION_LEVEL_2)
            raise Exception(
                log.PKIHELPER_NAMESPACE_COLLISION_2 % (
                    self.mdict['pki_instance_name'],
                    self.mdict['pki_instance_log_path']))
        if os.path.exists(self.mdict['pki_instance_configuration_path']) and\
           os.path.exists(self.mdict['pki_subsystem_configuration_path']):
            # Top-Level PKI configuration path collision
            config.pki_log.error(
                log.PKIHELPER_NAMESPACE_COLLISION_2,
                self.mdict['pki_instance_name'],
                self.mdict['pki_instance_configuration_path'],
                extra=config.PKI_INDENTATION_LEVEL_2)
            raise Exception(
                log.PKIHELPER_NAMESPACE_COLLISION_2 % (
                    self.mdict['pki_instance_name'],
                    self.mdict['pki_instance_configuration_path']))
        if os.path.exists(self.mdict['pki_instance_registry_path']) and\
           os.path.exists(self.mdict['pki_subsystem_registry_path']):
            # Top-Level PKI registry path collision
            config.pki_log.error(
                log.PKIHELPER_NAMESPACE_COLLISION_2,
                self.mdict['pki_instance_name'],
                self.mdict['pki_instance_registry_path'],
                extra=config.PKI_INDENTATION_LEVEL_2)
            raise Exception(
                log.PKIHELPER_NAMESPACE_COLLISION_2 % (
                    self.mdict['pki_instance_name'],
                    self.mdict['pki_instance_registry_path']))
        # Run simple checks for reserved name namespace collisions
        if self.mdict['pki_instance_name'] in config.PKI_BASE_RESERVED_NAMES:
            # Top-Level PKI base path reserved name collision
            config.pki_log.error(
                log.PKIHELPER_NAMESPACE_RESERVED_NAME_2,
                self.mdict['pki_instance_name'],
                self.mdict['pki_instance_path'],
                extra=config.PKI_INDENTATION_LEVEL_2)
            raise Exception(
                log.PKIHELPER_NAMESPACE_RESERVED_NAME_2 % (
                    self.mdict['pki_instance_name'],
                    self.mdict['pki_instance_path']))
        # No need to check for reserved name under Top-Level PKI log path
        if self.mdict['pki_instance_name'] in \
                config.PKI_CONFIGURATION_RESERVED_NAMES:
            # Top-Level PKI configuration path reserved name collision
            config.pki_log.error(
                log.PKIHELPER_NAMESPACE_RESERVED_NAME_2,
                self.mdict['pki_instance_name'],
                self.mdict['pki_instance_configuration_path'],
                extra=config.PKI_INDENTATION_LEVEL_2)
            raise Exception(
                log.PKIHELPER_NAMESPACE_RESERVED_NAME_2 % (
                    self.mdict['pki_instance_name'],
                    self.mdict['pki_instance_configuration_path']))

        # Top-Level Tomcat PKI registry path reserved name collision
        if self.mdict['pki_instance_name'] in\
           config.PKI_TOMCAT_REGISTRY_RESERVED_NAMES:
            config.pki_log.error(
                log.PKIHELPER_NAMESPACE_RESERVED_NAME_2,
                self.mdict['pki_instance_name'],
                self.mdict['pki_instance_registry_path'],
                extra=config.PKI_INDENTATION_LEVEL_2)
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

        self.existing = config.str2bool(self.mdict['pki_existing'])
        self.external = config.str2bool(self.mdict['pki_external'])
        self.external_step_one = not config.str2bool(self.mdict['pki_external_step_two'])
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
            # Only allowed for External CA
            if self.subsystem != "CA":
                config.pki_log.error(log.PKI_EXTERNAL_UNSUPPORTED_1,
                                     self.subsystem,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
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
            if self.subsystem != "KRA":
                config.pki_log.error(log.PKI_STANDALONE_UNSUPPORTED_1,
                                     self.subsystem,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKI_STANDALONE_UNSUPPORTED_1,
                                self.subsystem)

    def confirm_subordinate(self):
        # ALWAYS defined via 'pkiparser.py'
        if self.subordinate:
            # Only allowed for Subordinate CA
            if self.subsystem != "CA":
                config.pki_log.error(log.PKI_SUBORDINATE_UNSUPPORTED_1,
                                     self.subsystem,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKI_SUBORDINATE_UNSUPPORTED_1,
                                self.subsystem)
            if config.str2bool(
                    self.mdict['pki_subordinate_create_new_security_domain']):
                self.confirm_data_exists(
                    'pki_subordinate_security_domain_name')

    def confirm_external_step_two(self):
        # ALWAYS defined via 'pkiparser.py'
        if self.external_step_two:
            # Only allowed for External CA or Stand-alone PKI
            if self.subsystem != "CA" and not self.standalone:
                config.pki_log.error(log.PKI_EXTERNAL_STEP_TWO_UNSUPPORTED_1,
                                     self.subsystem,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKI_EXTERNAL_STEP_TWO_UNSUPPORTED_1,
                                self.subsystem)

    def confirm_data_exists(self, param):
        if param not in self.mdict or not len(self.mdict[param]):
            config.pki_log.error(
                log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                param,
                self.mdict['pki_user_deployment_cfg'],
                extra=config.PKI_INDENTATION_LEVEL_2)
            raise Exception(
                log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 %
                (param, self.mdict['pki_user_deployment_cfg']))

    def confirm_missing_file(self, param):
        if os.path.exists(self.mdict[param]):
            config.pki_log.error(log.PKI_FILE_ALREADY_EXISTS_1,
                                 self.mdict[param],
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            raise Exception(log.PKI_FILE_ALREADY_EXISTS_1 % param)

    def confirm_file_exists(self, param):
        if not os.path.exists(self.mdict[param]) or\
           not os.path.isfile(self.mdict[param]):
            config.pki_log.error(log.PKI_FILE_MISSING_OR_NOT_A_FILE_1,
                                 self.mdict[param],
                                 extra=config.PKI_INDENTATION_LEVEL_2)
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
            config.pki_log.error(
                log.PKIHELPER_HSM_KEYS_CANNOT_BE_BACKED_UP_TO_PKCS12_FILES,
                extra=config.PKI_INDENTATION_LEVEL_2)
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

                # If system certificates are already provided via pki_server_pkcs12
                # there's no need to provide pki_clone_pkcs12.
                if not self.mdict['pki_server_pkcs12_path']:
                    self.confirm_data_exists("pki_clone_pkcs12_password")

            # Verify absence of all PKCS #12 clone parameters for HSMs
            elif (os.path.exists(self.mdict['pki_clone_pkcs12_path']) or
                    ('pki_clone_pkcs12_password' in self.mdict and
                     len(self.mdict['pki_clone_pkcs12_password']))):
                config.pki_log.error(
                    log.PKIHELPER_HSM_CLONES_MUST_SHARE_HSM_MASTER_PRIVATE_KEYS,
                    extra=config.PKI_INDENTATION_LEVEL_2)
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
            if self.mdict['pki_token_name'] == "internal":
                config.pki_log.error(
                    log.PKIHELPER_UNDEFINED_HSM_TOKEN,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_UNDEFINED_HSM_TOKEN)
        if not self.mdict['pki_token_name'] == "internal":
            self.confirm_data_exists("pki_token_password")

    def verify_mutually_exclusive_data(self):
        # Silently verify the existence of 'mutually exclusive' data
        if self.subsystem == "CA":
            if self.clone and self.external and self.subordinate:
                config.pki_log.error(
                    log.PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_EXTERNAL_SUB_CA,
                    self.mdict['pki_user_deployment_cfg'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(
                    log.PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_EXTERNAL_SUB_CA %
                    self.mdict['pki_user_deployment_cfg'])
            elif self.clone and self.external:
                config.pki_log.error(
                    log.PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_EXTERNAL_CA,
                    self.mdict['pki_user_deployment_cfg'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(
                    log.PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_EXTERNAL_CA %
                    self.mdict['pki_user_deployment_cfg'])
            elif self.clone and self.subordinate:
                config.pki_log.error(
                    log.PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_SUB_CA,
                    self.mdict['pki_user_deployment_cfg'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(
                    log.PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_SUB_CA %
                    self.mdict['pki_user_deployment_cfg'])
            elif self.external and self.subordinate:
                config.pki_log.error(
                    log.PKIHELPER_MUTUALLY_EXCLUSIVE_EXTERNAL_SUB_CA,
                    self.mdict['pki_user_deployment_cfg'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(
                    log.PKIHELPER_MUTUALLY_EXCLUSIVE_EXTERNAL_SUB_CA %
                    self.mdict['pki_user_deployment_cfg'])
        elif self.standalone:
            if self.clone:
                config.pki_log.error(
                    log.PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_STANDALONE_PKI,
                    self.mdict['pki_user_deployment_cfg'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
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

                # If system certificates are already provided via pki_server_pkcs12
                # there's no need to provide pki_clone_pkcs12.
                if not self.mdict['pki_server_pkcs12_path']:
                    self.confirm_data_exists("pki_clone_pkcs12_path")
                    self.confirm_file_exists("pki_clone_pkcs12_path")

            self.confirm_data_exists("pki_clone_replication_security")

        elif self.external:
            # External CA
            if not self.external_step_two:
                # External CA (Step 1)
                # The pki_external_csr_path is optional.
                # generic extension support in CSR - for external CA
                if self.add_req_ext:
                    self.confirm_data_exists("pki_req_ext_oid")
                    self.confirm_data_exists("pki_req_ext_critical")
                    self.confirm_data_exists("pki_req_ext_data")
            else:
                # External CA (Step 2)
                # The pki_external_ca_cert_chain_path and
                # pki_external_ca_cert_path are optional.
                pass
        elif not self.skip_configuration and self.standalone:
            if not self.external_step_two:
                # Stand-alone PKI Admin CSR (Step 1)
                self.confirm_data_exists("pki_external_admin_csr_path")
                self.confirm_missing_file("pki_external_admin_csr_path")
                # Stand-alone PKI Audit Signing CSR (Step 1)
                self.confirm_data_exists(
                    "pki_external_audit_signing_csr_path")
                self.confirm_missing_file(
                    "pki_external_audit_signing_csr_path")
                # Stand-alone PKI SSL Server CSR (Step 1)
                self.confirm_data_exists("pki_external_sslserver_csr_path")
                self.confirm_missing_file("pki_external_sslserver_csr_path")
                # Stand-alone PKI Subsystem CSR (Step 1)
                self.confirm_data_exists("pki_external_subsystem_csr_path")
                self.confirm_missing_file("pki_external_subsystem_csr_path")
                # Stand-alone PKI KRA CSRs
                if self.subsystem == "KRA":
                    # Stand-alone PKI KRA Storage CSR (Step 1)
                    self.confirm_data_exists(
                        "pki_external_storage_csr_path")
                    self.confirm_missing_file(
                        "pki_external_storage_csr_path")
                    # Stand-alone PKI KRA Transport CSR (Step 1)
                    self.confirm_data_exists(
                        "pki_external_transport_csr_path")
                    self.confirm_missing_file(
                        "pki_external_transport_csr_path")
                # Stand-alone PKI OCSP CSRs
                if self.subsystem == "OCSP":
                    # Stand-alone PKI OCSP OCSP Signing CSR (Step 1)
                    self.confirm_data_exists(
                        "pki_external_signing_csr_path")
                    self.confirm_missing_file(
                        "pki_external_signing_csr_path")
            else:
                # Stand-alone PKI External CA Certificate Chain (Step 2)
                self.confirm_data_exists("pki_external_ca_cert_chain_path")
                self.confirm_file_exists("pki_external_ca_cert_chain_path")
                # Stand-alone PKI External CA Certificate (Step 2)
                self.confirm_data_exists("pki_external_ca_cert_path")
                self.confirm_file_exists("pki_external_ca_cert_path")
                # Stand-alone PKI Admin Certificate (Step 2)
                self.confirm_data_exists("pki_external_admin_cert_path")
                self.confirm_file_exists("pki_external_admin_cert_path")
                # Stand-alone PKI Audit Signing Certificate (Step 2)
                self.confirm_data_exists(
                    "pki_external_audit_signing_cert_path")
                self.confirm_file_exists(
                    "pki_external_audit_signing_cert_path")
                # Stand-alone PKI SSL Server Certificate (Step 2)
                self.confirm_data_exists("pki_external_sslserver_cert_path")
                self.confirm_file_exists("pki_external_sslserver_cert_path")
                # Stand-alone PKI Subsystem Certificate (Step 2)
                self.confirm_data_exists("pki_external_subsystem_cert_path")
                self.confirm_file_exists("pki_external_subsystem_cert_path")
                # Stand-alone PKI KRA Certificates
                if self.subsystem == "KRA":
                    # Stand-alone PKI KRA Storage Certificate (Step 2)
                    self.confirm_data_exists(
                        "pki_external_storage_cert_path")
                    self.confirm_file_exists(
                        "pki_external_storage_cert_path")
                    # Stand-alone PKI KRA Transport Certificate (Step 2)
                    self.confirm_data_exists(
                        "pki_external_transport_cert_path")
                    self.confirm_file_exists(
                        "pki_external_transport_cert_path")
                # Stand-alone PKI OCSP Certificates
                if self.subsystem == "OCSP":
                    # Stand-alone PKI OCSP OCSP Signing Certificate (Step 2)
                    self.confirm_data_exists(
                        "pki_external_signing_cert_path")
                    self.confirm_file_exists(
                        "pki_external_signing_cert_path")

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
            config.pki_log.error(
                log.PKIHELPER_SELINUX_DISABLED,
                extra=config.PKI_INDENTATION_LEVEL_2)
            return

        portrecs = seobject.portRecords().get_all()
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
                config.pki_log.error(
                    log.PKIHELPER_INVALID_SELINUX_CONTEXT_FOR_PORT,
                    port, context,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(
                    log.PKIHELPER_INVALID_SELINUX_CONTEXT_FOR_PORT %
                    (port, context))
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
                config.pki_log.error(
                    log.PKIHELPER_COMMAND_LINE_PARAMETER_MISMATCH_2,
                    self.mdict['pki_deployed_instance_name'],
                    self.mdict['pki_instance_name'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
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
#        config.pki_log.info(log.PKIHELPER_REMOVE_FILTER_SECTION_1,
#            self.mdict['pki_target_subsystem_web_xml'],
#            extra=config.PKI_INDENTATION_LEVEL_2)
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
            config.pki_log.debug(log.PKIHELPER_PKI_INSTANCE_SUBSYSTEMS_2,
                                 self.mdict['pki_instance_path'], rv,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            raise
        return rv

    def tomcat_instance_subsystems(self):
        # Return list of PKI subsystems in the specified tomcat instance
        rv = []
        try:
            for subsystem in config.PKI_TOMCAT_SUBSYSTEMS:
                path = self.mdict['pki_instance_path'] + \
                    "/" + subsystem.lower()
                if os.path.exists(path) and os.path.isdir(path):
                    rv.append(subsystem)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
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
            config.pki_log.debug(log.PKIHELPER_TOMCAT_INSTANCES_2,
                                 self.mdict['pki_instance_type_registry_path'],
                                 rv,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            raise
        return rv

    def verify_subsystem_exists(self):
        try:
            if not os.path.exists(self.mdict['pki_subsystem_path']):
                config.pki_log.error(log.PKI_SUBSYSTEM_DOES_NOT_EXIST_2,
                                     self.mdict['pki_subsystem'],
                                     self.mdict['pki_instance_name'],
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(
                    log.PKI_SUBSYSTEM_DOES_NOT_EXIST_2 % (
                        self.mdict['pki_subsystem'],
                        self.mdict['pki_instance_name']))
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            raise

    def verify_subsystem_does_not_exist(self):
        try:
            if os.path.exists(self.mdict['pki_subsystem_path']):
                config.pki_log.error(log.PKI_SUBSYSTEM_ALREADY_EXISTS_2,
                                     self.mdict['pki_subsystem'],
                                     self.mdict['pki_instance_name'],
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(
                    log.PKI_SUBSYSTEM_ALREADY_EXISTS_2 % (
                        self.mdict['pki_subsystem'],
                        self.mdict['pki_instance_name']))
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            raise

    def get_instance_status(self):
        connection = pki.client.PKIConnection(
            protocol='https',
            hostname=self.mdict['pki_hostname'],
            port=self.mdict['pki_https_port'],
            subsystem=self.mdict['pki_subsystem_type'],
            accept='application/xml',
            trust_env=False)

        # catching all exceptions because we do not want to break if underlying
        # requests or urllib3 use a different exception.
        # If the connection fails, we will time out in any case
        # pylint: disable=W0703
        try:
            client = pki.system.SystemStatusClient(connection)
            response = client.get_status()
            config.pki_log.debug(
                response,
                extra=config.PKI_INDENTATION_LEVEL_3)

            root = ET.fromstring(response)
            status = root.findtext("Status")
            return status
        except Exception as exc:
            config.pki_log.debug(
                "No connection - server may still be down",
                extra=config.PKI_INDENTATION_LEVEL_3)
            config.pki_log.debug(
                "No connection - exception thrown: " + str(exc),
                extra=config.PKI_INDENTATION_LEVEL_3)
            return None

    def wait_for_startup(self, timeout):
        start_time = datetime.today()
        status = None
        while status != "running":
            status = self.get_instance_status()
            time.sleep(1)
            stop_time = datetime.today()
            if (stop_time - start_time).total_seconds() >= timeout:
                break
        return status


class Directory:
    """PKI Deployment Directory Class"""

    def __init__(self, deployer):
        self.mdict = deployer.mdict
        self.identity = deployer.identity
        self.manifest_db = deployer.manifest_db

    def create(self, name, uid=None, gid=None,
               perms=config.PKI_DEPLOYMENT_DEFAULT_DIR_PERMISSIONS,
               acls=None, critical_failure=True):
        try:
            if not os.path.exists(name):
                # mkdir -p <name>
                config.pki_log.info(log.PKIHELPER_MKDIR_1, name,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                os.makedirs(name)
                # chmod <perms> <name>
                config.pki_log.debug(log.PKIHELPER_CHMOD_2, perms, name,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
                os.chmod(name, perms)
                # chown <uid>:<gid> <name>
                if uid is None:
                    uid = self.identity.get_uid()
                if gid is None:
                    gid = self.identity.get_gid()
                config.pki_log.debug(log.PKIHELPER_CHOWN_3,
                                     uid, gid, name,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
                os.chown(name, uid, gid)
                # Store record in installation manifest
                record = manifest.Record()
                record.name = name
                record.type = manifest.RECORD_TYPE_DIRECTORY
                record.user = self.mdict['pki_user']
                record.group = self.mdict['pki_group']
                record.uid = uid
                record.gid = gid
                record.permissions = perms
                record.acls = acls
                self.manifest_db.append(record)
            elif not os.path.isdir(name):
                config.pki_log.error(
                    log.PKI_DIRECTORY_ALREADY_EXISTS_NOT_A_DIRECTORY_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure:
                    raise Exception(
                        log.PKI_DIRECTORY_ALREADY_EXISTS_NOT_A_DIRECTORY_1 %
                        name)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                pass
            else:
                config.pki_log.error(log.PKI_OSERROR_1, exc,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure:
                    raise
        return

    def modify(self, name, uid=None, gid=None,
               perms=config.PKI_DEPLOYMENT_DEFAULT_DIR_PERMISSIONS,
               acls=None, silent=False, critical_failure=True):
        try:
            if os.path.exists(name):
                if not os.path.isdir(name):
                    config.pki_log.error(
                        log.PKI_DIRECTORY_ALREADY_EXISTS_NOT_A_DIRECTORY_1,
                        name, extra=config.PKI_INDENTATION_LEVEL_2)
                    if critical_failure:
                        raise Exception(
                            log.PKI_DIRECTORY_ALREADY_EXISTS_NOT_A_DIRECTORY_1 %
                            name)
                # Always re-process each directory whether it needs it or not
                if not silent:
                    config.pki_log.info(log.PKIHELPER_MODIFY_DIR_1, name,
                                        extra=config.PKI_INDENTATION_LEVEL_2)
                # chmod <perms> <name>
                if not silent:
                    config.pki_log.debug(log.PKIHELPER_CHMOD_2, perms, name,
                                         extra=config.PKI_INDENTATION_LEVEL_3)
                os.chmod(name, perms)
                # chown <uid>:<gid> <name>
                if uid is None:
                    uid = self.identity.get_uid()
                if gid is None:
                    gid = self.identity.get_gid()
                if not silent:
                    config.pki_log.debug(log.PKIHELPER_CHOWN_3,
                                         uid, gid, name,
                                         extra=config.PKI_INDENTATION_LEVEL_3)
                os.chown(name, uid, gid)
                # Store record in installation manifest
                if not silent:
                    record = manifest.Record()
                    record.name = name
                    record.type = manifest.RECORD_TYPE_DIRECTORY
                    record.user = self.mdict['pki_user']
                    record.group = self.mdict['pki_group']
                    record.uid = uid
                    record.gid = gid
                    record.permissions = perms
                    record.acls = acls
                    self.manifest_db.append(record)
            else:
                config.pki_log.error(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure:
                    raise Exception(
                        log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 % name)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        return

    def delete(self, name, recursive_flag=True, critical_failure=True):
        try:
            if not os.path.exists(name) or not os.path.isdir(name):
                # Simply issue a warning and continue
                config.pki_log.warning(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
            else:
                if recursive_flag:
                    # rm -rf <name>
                    config.pki_log.info(log.PKIHELPER_RM_RF_1, name,
                                        extra=config.PKI_INDENTATION_LEVEL_2)
                    shutil.rmtree(name)
                else:
                    # rmdir <name>
                    config.pki_log.info(log.PKIHELPER_RMDIR_1, name,
                                        extra=config.PKI_INDENTATION_LEVEL_2)
                    os.rmdir(name)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
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
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            raise

    def is_empty(self, name):
        try:
            if not os.listdir(name):
                config.pki_log.debug(log.PKIHELPER_DIRECTORY_IS_EMPTY_1,
                                     name, extra=config.PKI_INDENTATION_LEVEL_2)
                return True
            else:
                config.pki_log.debug(log.PKIHELPER_DIRECTORY_IS_NOT_EMPTY_1,
                                     name, extra=config.PKI_INDENTATION_LEVEL_2)
                return False
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            raise

    def set_mode(
            self, name, uid=None, gid=None,
            dir_perms=config.PKI_DEPLOYMENT_DEFAULT_DIR_PERMISSIONS,
            file_perms=config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS,
            symlink_perms=config.PKI_DEPLOYMENT_DEFAULT_SYMLINK_PERMISSIONS,
            dir_acls=None, file_acls=None, symlink_acls=None,
            recursive_flag=True, critical_failure=True):
        try:
            if not os.path.exists(name) or not os.path.isdir(name):
                config.pki_log.error(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 % name)
            else:
                config.pki_log.info(
                    log.PKIHELPER_SET_MODE_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
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
                                config.pki_log.debug(
                                    log.PKIHELPER_IS_A_FILE_1, temp_file,
                                    extra=config.PKI_INDENTATION_LEVEL_3)
                                # chmod <file_perms> <name>
                                config.pki_log.debug(
                                    log.PKIHELPER_CHMOD_2,
                                    file_perms, temp_file,
                                    extra=config.PKI_INDENTATION_LEVEL_3)
                                os.chmod(temp_file, file_perms)
                                # chown <uid>:<gid> <name>
                                config.pki_log.debug(
                                    log.PKIHELPER_CHOWN_3,
                                    uid, gid, temp_file,
                                    extra=config.PKI_INDENTATION_LEVEL_3)
                                os.chown(temp_file, uid, gid)
                                # Store record in installation manifest
                                record = manifest.Record()
                                record.name = name
                                record.type = manifest.RECORD_TYPE_FILE
                                record.user = self.mdict['pki_user']
                                record.group = self.mdict['pki_group']
                                record.uid = uid
                                record.gid = gid
                                record.permissions = file_perms
                                record.acls = file_acls
                                self.manifest_db.append(record)
                            else:
                                symlink = entity
                                config.pki_log.debug(
                                    log.PKIHELPER_IS_A_SYMLINK_1, symlink,
                                    extra=config.PKI_INDENTATION_LEVEL_3)
                                # REMINDER:  Due to POSIX compliance, 'lchmod'
                                #            is NEVER implemented on Linux
                                #            systems since 'chmod' CANNOT be
                                #            run directly against symbolic
                                #            links!
                                # chown -h <uid>:<gid> <symlink>
                                config.pki_log.debug(
                                    log.PKIHELPER_CHOWN_H_3,
                                    uid, gid, symlink,
                                    extra=config.PKI_INDENTATION_LEVEL_3)
                                os.lchown(symlink, uid, gid)
                                # Store record in installation manifest
                                record = manifest.Record()
                                record.name = name
                                record.type = manifest.RECORD_TYPE_SYMLINK
                                record.user = self.mdict['pki_user']
                                record.group = self.mdict['pki_group']
                                record.uid = uid
                                record.gid = gid
                                record.permissions = symlink_perms
                                record.acls = symlink_acls
                                self.manifest_db.append(record)
                        for name in dirs:
                            temp_dir = os.path.join(root, name)
                            config.pki_log.debug(
                                log.PKIHELPER_IS_A_DIRECTORY_1, temp_dir,
                                extra=config.PKI_INDENTATION_LEVEL_3)
                            # chmod <dir_perms> <name>
                            config.pki_log.debug(
                                log.PKIHELPER_CHMOD_2,
                                dir_perms, temp_dir,
                                extra=config.PKI_INDENTATION_LEVEL_3)
                            os.chmod(temp_dir, dir_perms)
                            # chown <uid>:<gid> <name>
                            config.pki_log.debug(
                                log.PKIHELPER_CHOWN_3,
                                uid, gid, temp_dir,
                                extra=config.PKI_INDENTATION_LEVEL_3)
                            os.chown(temp_dir, uid, gid)
                            # Store record in installation manifest
                            record = manifest.Record()
                            record.name = name
                            record.type = manifest.RECORD_TYPE_DIRECTORY
                            record.user = self.mdict['pki_user']
                            record.group = self.mdict['pki_group']
                            record.uid = uid
                            record.gid = gid
                            record.permissions = dir_perms
                            record.acls = dir_acls
                            self.manifest_db.append(record)
                else:
                    config.pki_log.debug(
                        log.PKIHELPER_IS_A_DIRECTORY_1, name,
                        extra=config.PKI_INDENTATION_LEVEL_3)
                    # chmod <dir_perms> <name>
                    config.pki_log.debug(log.PKIHELPER_CHMOD_2,
                                         dir_perms, name,
                                         extra=config.PKI_INDENTATION_LEVEL_3)
                    os.chmod(name, dir_perms)
                    # chown <uid>:<gid> <name>
                    config.pki_log.debug(log.PKIHELPER_CHOWN_3,
                                         uid, gid, name,
                                         extra=config.PKI_INDENTATION_LEVEL_3)
                    os.chown(name, uid, gid)
                    # Store record in installation manifest
                    record = manifest.Record()
                    record.name = name
                    record.type = manifest.RECORD_TYPE_DIRECTORY
                    record.user = self.mdict['pki_user']
                    record.group = self.mdict['pki_group']
                    record.uid = uid
                    record.gid = gid
                    record.permissions = dir_perms
                    record.acls = dir_acls
                    self.manifest_db.append(record)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise

    def copy(self, old_name, new_name, uid=None, gid=None,
             dir_perms=config.PKI_DEPLOYMENT_DEFAULT_DIR_PERMISSIONS,
             file_perms=config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS,
             symlink_perms=config.PKI_DEPLOYMENT_DEFAULT_SYMLINK_PERMISSIONS,
             dir_acls=None, file_acls=None, symlink_acls=None,
             recursive_flag=True, overwrite_flag=False, critical_failure=True,
             ignore_cb=None):
        try:

            if not os.path.exists(old_name) or not os.path.isdir(old_name):
                config.pki_log.error(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, old_name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 % old_name)
            else:
                if os.path.exists(new_name):
                    if not overwrite_flag:
                        config.pki_log.error(
                            log.PKI_DIRECTORY_ALREADY_EXISTS_1, new_name,
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        raise Exception(
                            log.PKI_DIRECTORY_ALREADY_EXISTS_1 % new_name)
                if recursive_flag:
                    # cp -rp <old_name> <new_name>
                    config.pki_log.info(log.PKIHELPER_CP_RP_2,
                                        old_name, new_name,
                                        extra=config.PKI_INDENTATION_LEVEL_2)
                    # Due to a limitation in the 'shutil.copytree()'
                    # implementation which requires that
                    # 'The destination directory must not already exist.',
                    # an OSError exception is always thrown due to the
                    # implementation's unchecked call to 'os.makedirs(dst)'.
                    # Consequently, a 'patched' local copy of this routine has
                    # been included in this file with the appropriate fix.
                    pki.util.copytree(old_name, new_name, ignore=ignore_cb)
                else:
                    # cp -p <old_name> <new_name>
                    config.pki_log.info(log.PKIHELPER_CP_P_2,
                                        old_name, new_name,
                                        extra=config.PKI_INDENTATION_LEVEL_2)
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
            config.pki_log.error(
                msg,
                exc,
                extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        return


class File:
    """PKI Deployment File Class (also used for executables)"""

    def __init__(self, deployer):
        self.mdict = deployer.mdict
        self.slots = deployer.slots
        self.identity = deployer.identity
        self.manifest_db = deployer.manifest_db

    def create(self, name, uid=None, gid=None,
               perms=config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS,
               acls=None, critical_failure=True):
        try:
            if not os.path.exists(name):
                # touch <name>
                config.pki_log.info(log.PKIHELPER_TOUCH_1, name,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                open(name, "w").close()
                # chmod <perms> <name>
                config.pki_log.debug(log.PKIHELPER_CHMOD_2, perms, name,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
                os.chmod(name, perms)
                # chown <uid>:<gid> <name>
                if uid is None:
                    uid = self.identity.get_uid()
                if gid is None:
                    gid = self.identity.get_gid()
                config.pki_log.debug(log.PKIHELPER_CHOWN_3,
                                     uid, gid, name,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
                os.chown(name, uid, gid)
                # Store record in installation manifest
                record = manifest.Record()
                record.name = name
                record.type = manifest.RECORD_TYPE_FILE
                record.user = self.mdict['pki_user']
                record.group = self.mdict['pki_group']
                record.uid = uid
                record.gid = gid
                record.permissions = perms
                record.acls = acls
                self.manifest_db.append(record)
            elif not os.path.isfile(name):
                config.pki_log.error(
                    log.PKI_FILE_ALREADY_EXISTS_NOT_A_FILE_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure:
                    raise Exception(
                        log.PKI_FILE_ALREADY_EXISTS_NOT_A_FILE_1 % name)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                pass
            else:
                config.pki_log.error(log.PKI_OSERROR_1, exc,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure:
                    raise
        return

    def modify(self, name, uid=None, gid=None,
               perms=config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS,
               acls=None, silent=False, critical_failure=True):
        try:
            if os.path.exists(name):
                if not os.path.isfile(name):
                    config.pki_log.error(
                        log.PKI_FILE_ALREADY_EXISTS_NOT_A_FILE_1,
                        name, extra=config.PKI_INDENTATION_LEVEL_2)
                    if critical_failure:
                        raise Exception(
                            log.PKI_FILE_ALREADY_EXISTS_NOT_A_FILE_1 % name)
                # Always re-process each file whether it needs it or not
                if not silent:
                    config.pki_log.info(log.PKIHELPER_MODIFY_FILE_1, name,
                                        extra=config.PKI_INDENTATION_LEVEL_2)
                # chmod <perms> <name>
                if not silent:
                    config.pki_log.debug(log.PKIHELPER_CHMOD_2, perms, name,
                                         extra=config.PKI_INDENTATION_LEVEL_3)
                os.chmod(name, perms)
                # chown <uid>:<gid> <name>
                if uid is None:
                    uid = self.identity.get_uid()
                if gid is None:
                    gid = self.identity.get_gid()
                if not silent:
                    config.pki_log.debug(log.PKIHELPER_CHOWN_3,
                                         uid, gid, name,
                                         extra=config.PKI_INDENTATION_LEVEL_3)
                os.chown(name, uid, gid)
                # Store record in installation manifest
                if not silent:
                    record = manifest.Record()
                    record.name = name
                    record.type = manifest.RECORD_TYPE_FILE
                    record.user = self.mdict['pki_user']
                    record.group = self.mdict['pki_group']
                    record.uid = uid
                    record.gid = gid
                    record.permissions = perms
                    record.acls = acls
                    self.manifest_db.append(record)
            else:
                config.pki_log.error(
                    log.PKI_FILE_MISSING_OR_NOT_A_FILE_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure:
                    raise Exception(
                        log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 %
                        name)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        return

    def delete(self, name, critical_failure=True):
        try:
            if not os.path.exists(name) or not os.path.isfile(name):
                # Simply issue a warning and continue
                config.pki_log.warning(
                    log.PKI_FILE_MISSING_OR_NOT_A_FILE_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
            else:
                # rm -f <name>
                config.pki_log.info(log.PKIHELPER_RM_F_1, name,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                os.remove(name)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
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
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            raise

    def copy(self, old_name, new_name, uid=None, gid=None,
             perms=config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS, acls=None,
             overwrite_flag=False, critical_failure=True):
        try:
            if not os.path.exists(old_name) or not os.path.isfile(old_name):
                config.pki_log.error(
                    log.PKI_FILE_MISSING_OR_NOT_A_FILE_1, old_name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(
                    log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 %
                    old_name)
            else:
                if os.path.exists(new_name):
                    if not overwrite_flag:
                        config.pki_log.error(
                            log.PKI_FILE_ALREADY_EXISTS_1, new_name,
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        raise Exception(
                            log.PKI_FILE_ALREADY_EXISTS_1 % new_name)
                # cp -p <old_name> <new_name>
                config.pki_log.info(log.PKIHELPER_CP_P_2,
                                    old_name, new_name,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                shutil.copy2(old_name, new_name)
                if uid is None:
                    uid = self.identity.get_uid()
                if gid is None:
                    gid = self.identity.get_gid()
                # chmod <perms> <new_name>
                config.pki_log.debug(log.PKIHELPER_CHMOD_2,
                                     perms, new_name,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
                os.chmod(new_name, perms)
                # chown <uid>:<gid> <new_name>
                config.pki_log.debug(log.PKIHELPER_CHOWN_3,
                                     uid, gid, new_name,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
                os.chown(new_name, uid, gid)
                # Store record in installation manifest
                record = manifest.Record()
                record.name = new_name
                record.type = manifest.RECORD_TYPE_FILE
                record.user = self.mdict['pki_user']
                record.group = self.mdict['pki_group']
                record.uid = uid
                record.gid = gid
                record.permissions = perms
                record.acls = acls
                self.manifest_db.append(record)
        except (shutil.Error, OSError) as exc:
            if isinstance(exc, shutil.Error):
                msg = log.PKI_SHUTIL_ERROR_1
            else:
                msg = log.PKI_OSERROR_1
            config.pki_log.error(
                msg,
                exc,
                extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        return

    def apply_slot_substitution(
            self, name, uid=None, gid=None,
            perms=config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS,
            acls=None, critical_failure=True):
        try:
            if not os.path.exists(name) or not os.path.isfile(name):
                config.pki_log.error(
                    log.PKI_FILE_MISSING_OR_NOT_A_FILE_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 % name)
            # applying in-place slot substitutions on <name>
            config.pki_log.info(log.PKIHELPER_APPLY_SLOT_SUBSTITUTION_1,
                                name,
                                extra=config.PKI_INDENTATION_LEVEL_2)
            for line in fileinput.FileInput(name, inplace=1):
                for slot in self.slots:
                    if slot != '__name__' and self.slots[slot] in line:
                        config.pki_log.debug(
                            log.PKIHELPER_SLOT_SUBSTITUTION_2,
                            self.slots[slot], self.mdict[slot],
                            extra=config.PKI_INDENTATION_LEVEL_3)
                        line = line.replace(self.slots[slot], self.mdict[slot])
                print(line, end='')
            if uid is None:
                uid = self.identity.get_uid()
            if gid is None:
                gid = self.identity.get_gid()
            # chmod <perms> <name>
            config.pki_log.debug(log.PKIHELPER_CHMOD_2,
                                 perms, name,
                                 extra=config.PKI_INDENTATION_LEVEL_3)
            os.chmod(name, perms)
            # chown <uid>:<gid> <name>
            config.pki_log.debug(log.PKIHELPER_CHOWN_3,
                                 uid, gid, name,
                                 extra=config.PKI_INDENTATION_LEVEL_3)
            os.chown(name, uid, gid)
            # Store record in installation manifest
            record = manifest.Record()
            record.name = name
            record.type = manifest.RECORD_TYPE_FILE
            record.user = self.mdict['pki_user']
            record.group = self.mdict['pki_group']
            record.uid = uid
            record.gid = gid
            record.permissions = perms
            record.acls = acls
            self.manifest_db.append(record)
        except (shutil.Error, OSError) as exc:
            if isinstance(exc, shutil.Error):
                msg = log.PKI_SHUTIL_ERROR_1
            else:
                msg = log.PKI_OSERROR_1
            config.pki_log.error(
                msg,
                exc,
                extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        return

    def substitute_deployment_params(self, line):
        """
        Replace all occurrences of [param] in the line with the value of the deployment parameter.
        """

        # find the first parameter in the line
        begin = line.find('[')

        # repeat while there are parameters in the line
        while begin >= 0:

            # find the end of the parameter
            end = line.find(']', begin + 1)

            # if the end not is found not found, don't do anything
            if end < 0:
                return line

            # get parameter name
            name = line[begin + 1:end]

            try:
                # get parameter value as string
                value = str(self.mdict[name])

                config.pki_log.debug(
                    log.PKIHELPER_SLOT_SUBSTITUTION_2,
                    line[begin:end + 1], value,
                    extra=config.PKI_INDENTATION_LEVEL_3)

                # replace parameter with value, keep the rest of the line
                line = line[0:begin] + value + line[end + 1:]

                # calculate the new end position
                end = begin + len(value) + 1

            except KeyError:
                # undefined parameter, skip
                config.pki_log.debug(
                    'ignoring slot [%s]',
                    line[begin:end + 1],
                    extra=config.PKI_INDENTATION_LEVEL_3)

            # find the next parameter in the remainder of the line
            begin = line.find('[', end + 1)

        # return modified line
        return line

    def copy_with_slot_substitution(
            self, old_name, new_name, uid=None, gid=None,
            perms=config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS,
            acls=None, overwrite_flag=False,
            critical_failure=True):
        try:
            if not os.path.exists(old_name) or not os.path.isfile(old_name):
                config.pki_log.error(
                    log.PKI_FILE_MISSING_OR_NOT_A_FILE_1, old_name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(
                    log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 %
                    old_name)
            else:
                if os.path.exists(new_name):
                    if not overwrite_flag:
                        config.pki_log.error(
                            log.PKI_FILE_ALREADY_EXISTS_1, new_name,
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        raise Exception(
                            log.PKI_FILE_ALREADY_EXISTS_1 % new_name)
                # copy <old_name> to <new_name> with slot substitutions
                config.pki_log.info(log.PKIHELPER_COPY_WITH_SLOT_SUBSTITUTION_2,
                                    old_name, new_name,
                                    extra=config.PKI_INDENTATION_LEVEL_2)

                with open(new_name, "w") as FILE:
                    for line in fileinput.FileInput(old_name):

                        # substitute registered slots
                        for slot in self.slots:
                            if slot != '__name__' and self.slots[slot] in line:
                                config.pki_log.debug(
                                    log.PKIHELPER_SLOT_SUBSTITUTION_2,
                                    self.slots[slot], self.mdict[slot],
                                    extra=config.PKI_INDENTATION_LEVEL_3)
                                line = line.replace(
                                    self.slots[slot],
                                    self.mdict[slot])

                        # substitute deployment parameters
                        line = self.substitute_deployment_params(line)

                        FILE.write(line)

                if uid is None:
                    uid = self.identity.get_uid()
                if gid is None:
                    gid = self.identity.get_gid()
                # chmod <perms> <new_name>
                config.pki_log.debug(log.PKIHELPER_CHMOD_2,
                                     perms, new_name,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
                os.chmod(new_name, perms)
                # chown <uid>:<gid> <new_name>
                config.pki_log.debug(log.PKIHELPER_CHOWN_3,
                                     uid, gid, new_name,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
                os.chown(new_name, uid, gid)
                # Store record in installation manifest
                record = manifest.Record()
                record.name = new_name
                record.type = manifest.RECORD_TYPE_FILE
                record.user = self.mdict['pki_user']
                record.group = self.mdict['pki_group']
                record.uid = uid
                record.gid = gid
                record.permissions = perms
                record.acls = acls
                self.manifest_db.append(record)
        except (shutil.Error, OSError) as exc:
            if isinstance(exc, shutil.Error):
                msg = log.PKI_SHUTIL_ERROR_1
            else:
                msg = log.PKI_OSERROR_1
            config.pki_log.error(
                msg,
                exc,
                extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        return


class Symlink:
    """PKI Deployment Symbolic Link Class"""

    def __init__(self, deployer):
        self.mdict = deployer.mdict
        self.identity = deployer.identity
        self.manifest_db = deployer.manifest_db

    def create(self, name, link, uid=None, gid=None,
               acls=None, allow_dangling_symlink=False, critical_failure=True):
        try:
            if not os.path.exists(link):
                if not os.path.exists(name):
                    config.pki_log.warning(
                        log.PKIHELPER_DANGLING_SYMLINK_2, link, name,
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    if not allow_dangling_symlink:
                        raise Exception(
                            "Dangling symlink " + link + " not allowed")
                # ln -s <name> <link>
                config.pki_log.info(log.PKIHELPER_LINK_S_2, name, link,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                os.symlink(name, link)
                # REMINDER:  Due to POSIX compliance, 'lchmod' is NEVER
                #            implemented on Linux systems since 'chmod'
                #            CANNOT be run directly against symbolic links!
                # chown -h <uid>:<gid> <link>
                if uid is None:
                    uid = self.identity.get_uid()
                if gid is None:
                    gid = self.identity.get_gid()
                config.pki_log.debug(log.PKIHELPER_CHOWN_H_3,
                                     uid, gid, link,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
                os.lchown(link, uid, gid)
                # Store record in installation manifest
                record = manifest.Record()
                record.name = link
                record.type = manifest.RECORD_TYPE_SYMLINK
                record.user = self.mdict['pki_user']
                record.group = self.mdict['pki_group']
                record.uid = uid
                record.gid = gid
                record.permissions = \
                    config.PKI_DEPLOYMENT_DEFAULT_SYMLINK_PERMISSIONS
                record.acls = acls
                self.manifest_db.append(record)
            elif not os.path.islink(link):
                config.pki_log.error(
                    log.PKI_SYMLINK_ALREADY_EXISTS_NOT_A_SYMLINK_1, link,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure:
                    raise Exception(
                        log.PKI_SYMLINK_ALREADY_EXISTS_NOT_A_SYMLINK_1 % link)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                pass
            else:
                config.pki_log.error(log.PKI_OSERROR_1, exc,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure:
                    raise
        return

    def modify(self, link, uid=None, gid=None,
               acls=None, silent=False, critical_failure=True):
        try:
            if os.path.exists(link):
                if not os.path.islink(link):
                    config.pki_log.error(
                        log.PKI_SYMLINK_ALREADY_EXISTS_NOT_A_SYMLINK_1,
                        link, extra=config.PKI_INDENTATION_LEVEL_2)
                    if critical_failure:
                        raise Exception(
                            log.PKI_SYMLINK_ALREADY_EXISTS_NOT_A_SYMLINK_1 %
                            link)
                # Always re-process each link whether it needs it or not
                if not silent:
                    config.pki_log.info(log.PKIHELPER_MODIFY_SYMLINK_1, link,
                                        extra=config.PKI_INDENTATION_LEVEL_2)
                # REMINDER:  Due to POSIX compliance, 'lchmod' is NEVER
                #            implemented on Linux systems since 'chmod'
                #            CANNOT be run directly against symbolic links!
                # chown -h <uid>:<gid> <link>
                if uid is None:
                    uid = self.identity.get_uid()
                if gid is None:
                    gid = self.identity.get_gid()
                if not silent:
                    config.pki_log.debug(log.PKIHELPER_CHOWN_H_3,
                                         uid, gid, link,
                                         extra=config.PKI_INDENTATION_LEVEL_3)
                os.lchown(link, uid, gid)
                # Store record in installation manifest
                if not silent:
                    record = manifest.Record()
                    record.name = link
                    record.type = manifest.RECORD_TYPE_SYMLINK
                    record.user = self.mdict['pki_user']
                    record.group = self.mdict['pki_group']
                    record.uid = uid
                    record.gid = gid
                    record.permissions = \
                        config.PKI_DEPLOYMENT_DEFAULT_SYMLINK_PERMISSIONS
                    record.acls = acls
                    self.manifest_db.append(record)
            else:
                config.pki_log.error(
                    log.PKI_SYMLINK_MISSING_OR_NOT_A_SYMLINK_1, link,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure:
                    raise Exception(
                        log.PKI_SYMLINK_MISSING_OR_NOT_A_SYMLINK_1 % link)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        return

    def delete(self, link, critical_failure=True):
        try:
            if not os.path.exists(link) or not os.path.islink(link):
                # Simply issue a warning and continue
                config.pki_log.warning(
                    log.PKI_SYMLINK_MISSING_OR_NOT_A_SYMLINK_1, link,
                    extra=config.PKI_INDENTATION_LEVEL_2)
            else:
                # rm -f <link>
                config.pki_log.info(log.PKIHELPER_RM_F_1, link,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                os.remove(link)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
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
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            raise


class War:
    """PKI Deployment War File Class"""

    def __init__(self, deployer):
        self.mdict = deployer.mdict

    def explode(self, name, path, critical_failure=True):
        try:
            if os.path.exists(name) and os.path.isfile(name):
                if not zipfile.is_zipfile(name):
                    config.pki_log.error(
                        log.PKI_FILE_NOT_A_WAR_FILE_1,
                        name, extra=config.PKI_INDENTATION_LEVEL_2)
                    if critical_failure:
                        raise Exception(log.PKI_FILE_NOT_A_WAR_FILE_1 % name)
                if not os.path.exists(path) or not os.path.isdir(path):
                    config.pki_log.error(
                        log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1,
                        path, extra=config.PKI_INDENTATION_LEVEL_2)
                    if critical_failure:
                        raise Exception(
                            log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1,
                            path)
                # jar -xf <name> -C <path>
                config.pki_log.info(log.PKIHELPER_JAR_XF_C_2, name, path,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                # Open war file
                war = zipfile.ZipFile(name, 'r')
                # Extract contents of war file to path
                war.extractall(path)
            else:
                config.pki_log.error(
                    log.PKI_FILE_MISSING_OR_NOT_A_FILE_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure:
                    raise Exception(log.PKI_FILE_MISSING_OR_NOT_A_FILE_1, name)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        except zipfile.BadZipfile as exc:
            config.pki_log.error(log.PKI_BADZIPFILE_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        except zipfile.LargeZipFile as exc:
            config.pki_log.error(log.PKI_LARGEZIPFILE_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        return


class Password:
    """PKI Deployment Password Class"""

    def __init__(self, deployer):
        self.mdict = deployer.mdict

    def create_password_conf(self, path, pin, pin_sans_token=False,
                             overwrite_flag=False, critical_failure=True):
        try:
            if os.path.exists(path):
                if overwrite_flag:
                    config.pki_log.info(
                        log.PKIHELPER_PASSWORD_CONF_1, path,
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    # overwrite the existing 'password.conf' file
                    with open(path, "w") as fd:
                        if pin_sans_token:
                            fd.write(str(pin))
                        else:
                            fd.write(self.mdict['pki_self_signed_token'] +
                                     "=" + str(pin))
            else:
                config.pki_log.info(log.PKIHELPER_PASSWORD_CONF_1, path,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                # create a new 'password.conf' file
                with open(path, "w") as fd:
                    if pin_sans_token:
                        fd.write(str(pin))
                    else:
                        fd.write(self.mdict['pki_self_signed_token'] +
                                 "=" + str(pin))
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        return

    def create_hsm_password_conf(self, path, pin, hsm_pin,
                                 overwrite_flag=False, critical_failure=True):
        try:
            if os.path.exists(path):
                if overwrite_flag:
                    config.pki_log.info(
                        log.PKIHELPER_PASSWORD_CONF_1, path,
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    # overwrite the existing 'password.conf' file
                    with open(path, "w") as fd:
                        fd.write(self.mdict['pki_self_signed_token'] +
                                 "=" + str(pin) + "\n")
                        fd.write("hardware-" +
                                 self.mdict['pki_token_name'] +
                                 "=" + str(hsm_pin))
            else:
                config.pki_log.info(log.PKIHELPER_PASSWORD_CONF_1, path,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                # create a new 'password.conf' file
                with open(path, "w") as fd:
                    fd.write(self.mdict['pki_self_signed_token'] +
                             "=" + str(pin) + "\n")
                    fd.write("hardware-" +
                             self.mdict['pki_token_name'] +
                             "=" + str(hsm_pin))
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        return

    def create_client_pkcs12_password_conf(self, path, overwrite_flag=False,
                                           critical_failure=True):
        try:
            if os.path.exists(path):
                if overwrite_flag:
                    config.pki_log.info(
                        log.PKIHELPER_PASSWORD_CONF_1, path,
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    # overwrite the existing 'pkcs12_password.conf' file
                    with open(path, "w") as fd:
                        fd.write(self.mdict['pki_client_pkcs12_password'])
            else:
                config.pki_log.info(log.PKIHELPER_PASSWORD_CONF_1, path,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                # create a new 'pkcs12_password.conf' file
                with open(path, "w") as fd:
                    fd.write(self.mdict['pki_client_pkcs12_password'])
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        return

    def get_password(self, path, token_name, critical_failure=True):
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
            # TODO prompt for this password
            config.pki_log.error(log.PKIHELPER_PASSWORD_NOT_FOUND_1,
                                 token_name,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise Exception(
                    log.PKIHELPER_PASSWORD_NOT_FOUND_1 %
                    token_name)
            else:
                return
        return token_pwd


class HSM:
    """PKI Deployment HSM class"""

    def __init__(self, deployer):
        self.mdict = deployer.mdict
        self.identity = deployer.identity
        self.file = deployer.file

    def initialize(self):
        if config.str2bool(self.mdict['pki_hsm_enable']):
            if (self.mdict['pki_hsm_libfile'] == config.PKI_HSM_NCIPHER_LIB):
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
            config.pki_log.info(
                log.PKIHELPER_NCIPHER_RESTART_1, ' '.join(command),
                extra=config.PKI_INDENTATION_LEVEL_2)
            # Execute this "nCipher" HSM command
            subprocess.check_call(command)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        return


class Certutil:
    """PKI Deployment NSS 'certutil' Class"""

    def __init__(self, deployer):
        self.mdict = deployer.mdict

    def create_security_databases(self, path, pki_cert_database,
                                  pki_key_database, pki_secmod_database,
                                  password_file=None, prefix=None,
                                  critical_failure=True):
        try:
            # Compose this "certutil" command
            command = ["certutil", "-N"]
            #   Provide a path to the NSS security databases
            if path:
                command.extend(["-d", path])
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_PATH,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_PATH)
            if password_file is not None:
                command.extend(["-f", password_file])
            if prefix is not None:
                command.extend(["-P", prefix])
            if not os.path.exists(path):
                config.pki_log.error(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, path,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 % path)
            if os.path.exists(pki_cert_database) or\
               os.path.exists(pki_key_database) or\
               os.path.exists(pki_secmod_database):
                # Simply notify user that the security databases exist
                config.pki_log.info(
                    log.PKI_SECURITY_DATABASES_ALREADY_EXIST_3,
                    pki_cert_database,
                    pki_key_database,
                    pki_secmod_database,
                    extra=config.PKI_INDENTATION_LEVEL_2)
            else:
                if password_file is not None:
                    if not os.path.exists(password_file) or\
                       not os.path.isfile(password_file):
                        config.pki_log.error(
                            log.PKI_FILE_MISSING_OR_NOT_A_FILE_1,
                            password_file,
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        raise Exception(
                            log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 %
                            password_file)
                # Display this "certutil" command
                config.pki_log.info(
                    log.PKIHELPER_CREATE_SECURITY_DATABASES_1,
                    ' '.join(command),
                    extra=config.PKI_INDENTATION_LEVEL_2)
                # Execute this "certutil" command
                subprocess.check_call(command)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        return

    def verify_certificate_exists(self, path, pki_cert_database,
                                  pki_key_database, pki_secmod_database,
                                  token, nickname, password_file=None,
                                  silent=True, critical_failure=True):
        try:
            # Compose this "certutil" command
            command = ["certutil", "-L"]
            #   Provide a path to the NSS security databases
            if path:
                command.extend(["-d", path])
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_PATH,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_PATH)
            #   Specify the 'token'
            if token:
                command.extend(["-h", token])
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_TOKEN,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_TOKEN)
            #   Specify the nickname of this self-signed certificate
            if nickname:
                command.extend(["-n", nickname])
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_NICKNAME,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_NICKNAME)
            #   OPTIONALLY specify a password file
            if password_file is not None:
                command.extend(["-f", password_file])
            if not os.path.exists(path):
                config.pki_log.error(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, path,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 % path)
            if not os.path.exists(pki_cert_database) or\
               not os.path.exists(pki_key_database) or\
               not os.path.exists(pki_secmod_database):
                # NSS security databases MUST exist!
                config.pki_log.error(
                    log.PKI_SECURITY_DATABASES_DO_NOT_EXIST_3,
                    pki_cert_database,
                    pki_key_database,
                    pki_secmod_database,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(
                    log.PKI_SECURITY_DATABASES_DO_NOT_EXIST_3 % (
                        pki_cert_database,
                        pki_key_database,
                        pki_secmod_database))
            if password_file is not None:
                if not os.path.exists(password_file) or\
                   not os.path.isfile(password_file):
                    config.pki_log.error(
                        log.PKI_FILE_MISSING_OR_NOT_A_FILE_1,
                        password_file,
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(
                        log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 % password_file)
            # Display this "certutil" command
            config.pki_log.info(
                log.PKIHELPER_CERTUTIL_SELF_SIGNED_CERTIFICATE_1,
                ' '.join(command), extra=config.PKI_INDENTATION_LEVEL_2)
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
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        return True

    def generate_self_signed_certificate(self, path, pki_cert_database,
                                         pki_key_database, pki_secmod_database,
                                         token, nickname,
                                         subject, serial_number,
                                         validity_period, issuer_name,
                                         trustargs, noise_file,
                                         password_file=None,
                                         critical_failure=True):
        try:
            # Compose this "certutil" command
            command = ["certutil", "-S"]
            #   Provide a path to the NSS security databases
            if path:
                command.extend(["-d", path])
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_PATH,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_PATH)
            #   Specify the 'token'
            if token:
                command.extend(["-h", token])
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_TOKEN,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_TOKEN)
            #   Specify the nickname of this self-signed certificate
            if nickname:
                command.extend(["-n", nickname])
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_NICKNAME,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_NICKNAME)
            #   Specify the subject name (RFC1485)
            if subject:
                command.extend(["-s", subject])
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_SUBJECT,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_SUBJECT)
            #   Specify the serial number
            if serial_number is not None:
                command.extend(["-m", str(serial_number)])
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_SERIAL_NUMBER,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_SERIAL_NUMBER)
            #   Specify the months valid
            if validity_period is not None:
                command.extend(["-v", str(validity_period)])
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_VALIDITY_PERIOD,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_VALIDITY_PERIOD)
            #   Specify the nickname of the issuer certificate
            if issuer_name:
                command.extend(["-c", issuer_name])
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_ISSUER_NAME,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_ISSUER_NAME)
            #   Specify the certificate trust attributes
            if trustargs:
                command.extend(["-t", trustargs])
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_TRUSTARGS,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_TRUSTARGS)
            #   Specify a noise file to be used for key generation
            if noise_file:
                command.extend(["-z", noise_file])
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_NOISE_FILE,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_NOISE_FILE)
            #   OPTIONALLY specify a password file
            if password_file is not None:
                command.extend(["-f", password_file])
            #   ALWAYS self-sign this certificate
            command.append("-x")
            # Display this "certutil" command
            config.pki_log.info(
                log.PKIHELPER_CERTUTIL_SELF_SIGNED_CERTIFICATE_1,
                ' '.join(command), extra=config.PKI_INDENTATION_LEVEL_2)
            if not os.path.exists(path):
                config.pki_log.error(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, path,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 % path)
            if not os.path.exists(pki_cert_database) or\
               not os.path.exists(pki_key_database) or\
               not os.path.exists(pki_secmod_database):
                # NSS security databases MUST exist!
                config.pki_log.error(
                    log.PKI_SECURITY_DATABASES_DO_NOT_EXIST_3,
                    pki_cert_database,
                    pki_key_database,
                    pki_secmod_database,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(
                    log.PKI_SECURITY_DATABASES_DO_NOT_EXIST_3 % (
                        pki_cert_database,
                        pki_key_database,
                        pki_secmod_database))
            if not os.path.exists(noise_file):
                config.pki_log.error(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1,
                    noise_file,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 % noise_file)
            if password_file is not None:
                if not os.path.exists(password_file) or\
                   not os.path.isfile(password_file):
                    config.pki_log.error(
                        log.PKI_FILE_MISSING_OR_NOT_A_FILE_1,
                        password_file,
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(
                        log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 % password_file)
            # Execute this "certutil" command
            #
            #     NOTE:  ALWAYS mask the command-line output of this command
            #
            with open(os.devnull, "w") as fnull:
                subprocess.check_call(command, stdout=fnull, stderr=fnull)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        return

    def import_cert(self, nickname, trust, input_file, password_file,
                    path=None, token=None, critical_failure=True):
        try:
            command = ["certutil", "-A"]
            if path:
                command.extend(["-d", path])

            if token:
                command.extend(["-h", token])

            if nickname:
                command.extend(["-n", nickname])
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_NICKNAME,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_NICKNAME)

            if trust:
                command.extend(["-t", trust])
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_TRUSTARGS,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_TRUSTARGS)

            if input_file:
                command.extend(["-i", input_file])
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_INPUT_FILE,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_INPUT_FILE)

            if password_file:
                command.extend(["-f", password_file])
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_PASSWORD_FILE,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_PASSWORD_FILE)

            config.pki_log.info(
                ' '.join(command),
                extra=config.PKI_INDENTATION_LEVEL_2)
            subprocess.check_call(command)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        return

    def generate_certificate_request(self, subject, key_type, key_size,
                                     password_file, noise_file,
                                     output_file=None, path=None,
                                     ascii_format=None, token=None,
                                     critical_failure=True):
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
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_SUBJECT,
                    extra=config.PKI_INDENTATION_LEVEL_2)
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
                    config.pki_log.error(
                        log.PKIHELPER_CERTUTIL_INVALID_KEY_TYPE_1,
                        key_type,
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(
                        log.PKIHELPER_CERTUTIL_INVALID_KEY_TYPE_1 % key_type)
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_KEY_TYPE,
                    extra=config.PKI_INDENTATION_LEVEL_2)
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
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_NOISE_FILE,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_NOISE_FILE)

            if password_file:
                command.extend(["-f", password_file])
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_PASSWORD_FILE,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_PASSWORD_FILE)

            if output_file:
                command.extend(["-o", output_file])

            # set acsii output
            if ascii_format:
                command.append("-a")

            # Display this "certutil" command
            config.pki_log.info(
                log.PKIHELPER_CERTUTIL_GENERATE_CSR_1, ' '.join(command),
                extra=config.PKI_INDENTATION_LEVEL_2)
            if not os.path.exists(noise_file):
                config.pki_log.error(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1,
                    noise_file,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 % noise_file)
            if not os.path.exists(password_file) or\
               not os.path.isfile(password_file):
                config.pki_log.error(
                    log.PKI_FILE_MISSING_OR_NOT_A_FILE_1,
                    password_file,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(
                    log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 % password_file)
            # Execute this "certutil" command
            with open(os.devnull, "w") as fnull:
                subprocess.check_call(command, stdout=fnull, stderr=fnull)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        return


class Modutil:
    """PKI Deployment NSS 'modutil' Class"""

    def __init__(self, deployer):
        self.mdict = deployer.mdict

    def is_security_module_registered(self, path, modulename, prefix=None):

        if not path:
            config.pki_log.error(
                log.PKIHELPER_MODUTIL_MISSING_PATH,
                extra=config.PKI_INDENTATION_LEVEL_2)
            raise Exception(log.PKIHELPER_MODUTIL_MISSING_PATH)

        if not modulename:
            config.pki_log.error(
                log.PKIHELPER_MODUTIL_MISSING_MODULENAME,
                extra=config.PKI_INDENTATION_LEVEL_2)
            raise Exception(log.PKIHELPER_MODUTIL_MISSING_MODULENAME)

        command = [
            'modutil',
            '-list',
            '-dbdir', path,
            '-nocertdb']

        if prefix:
            command.extend(['--dbprefix', prefix])

        config.pki_log.info(
            log.PKIHELPER_REGISTERED_SECURITY_MODULE_CHECK_1,
            ' '.join(command),
            extra=config.PKI_INDENTATION_LEVEL_2)

        # execute command
        p = subprocess.Popen(command, stdout=subprocess.PIPE)
        output = p.communicate()[0]
        p.wait()
        # ignore return code due to issues with HSM
        # https://fedorahosted.org/pki/ticket/1444
        output = output.decode('utf-8')

        # find modules from lines such as '1. NSS Internal PKCS #11 Module'
        modules = re.findall(r'^ +\d+\. +(.*)$', output, re.MULTILINE)

        if modulename not in modules:
            config.pki_log.info(
                log.PKIHELPER_UNREGISTERED_SECURITY_MODULE_1, modulename,
                extra=config.PKI_INDENTATION_LEVEL_2)
            return False

        config.pki_log.info(
            log.PKIHELPER_REGISTERED_SECURITY_MODULE_1, modulename,
            extra=config.PKI_INDENTATION_LEVEL_2)
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
                config.pki_log.error(
                    log.PKIHELPER_MODUTIL_MISSING_PATH,
                    extra=config.PKI_INDENTATION_LEVEL_2)
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
                config.pki_log.error(
                    log.PKIHELPER_MODUTIL_MISSING_MODULENAME,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_MODUTIL_MISSING_MODULENAME)
            #   Specify a 'libfile'
            if libfile:
                command.extend(["-libfile", libfile])
            else:
                config.pki_log.error(
                    log.PKIHELPER_MODUTIL_MISSING_LIBFILE,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_MODUTIL_MISSING_LIBFILE)
            #   Append '-force' switch
            command.extend(["-force"])
            # Display this "modutil" command
            config.pki_log.info(
                log.PKIHELPER_REGISTER_SECURITY_MODULE_1,
                ' '.join(command),
                extra=config.PKI_INDENTATION_LEVEL_2)
            # Execute this "modutil" command
            subprocess.check_call(command)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        return


class PK12util:
    """PKI Deployment pk12util class"""

    def __init__(self, deployer):
        self.mdict = deployer.mdict

    def create_file(self, out_file, nickname, out_pwfile,
                    db_pwfile, path=None, critical_failure=True):
        try:
            command = ["pk12util"]
            if path:
                command.extend(["-d", path])
            if out_file:
                command.extend(["-o", out_file])
            else:
                config.pki_log.error(
                    log.PKIHELPER_PK12UTIL_MISSING_OUTFILE,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_PK12UTIL_MISSING_OUTFILE)
            if nickname:
                command.extend(["-n", nickname])
            else:
                config.pki_log.error(
                    log.PKIHELPER_PK12UTIL_MISSING_NICKNAME,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_PK12UTIL_MISSING_NICKNAME)
            if out_pwfile:
                command.extend(["-w", out_pwfile])
            else:
                config.pki_log.error(
                    log.PKIHELPER_PK12UTIL_MISSING_PWFILE,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_PK12UTIL_MISSING_PWFILE)
            if db_pwfile:
                command.extend(["-k", db_pwfile])
            else:
                config.pki_log.error(
                    log.PKIHELPER_PK12UTIL_MISSING_DBPWFILE,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_PK12UTIL_MISSING_DBPWFILE)

            config.pki_log.info(
                ' '.join(command),
                extra=config.PKI_INDENTATION_LEVEL_2)
            with open(os.devnull, "w") as fnull:
                subprocess.check_call(command, stdout=fnull, stderr=fnull)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        return


class ServerCertNickConf:
    """PKI Deployment serverCertNick.conf Class"""

    # In the future, this class will be used exclusively to manage the
    # creation and modification of the 'serverCertNick.conf' file
    # replacing the current 'pkispawn' method of copying a template and
    # using slot-substitution to establish its contents.
    def __init__(self, deployer):
        self.mdict = deployer.mdict
        self.hsm_enable = config.str2bool(self.mdict['pki_hsm_enable'])
        self.external = config.str2bool(self.mdict['pki_external'])
        self.nickname = self.mdict['pki_self_signed_nickname']
        self.servercertnick_conf = self.mdict['pki_target_servercertnick_conf']
        self.standalone = config.str2bool(self.mdict['pki_standalone'])
        self.step_two = config.str2bool(self.mdict['pki_external_step_two'])
        self.token_name = self.mdict['pki_token_name']

    def modify(self):
        # Modify contents of 'serverCertNick.conf'
        if self.hsm_enable and (self.external or self.standalone):
            try:
                # overwrite value inside 'serverCertNick.conf'
                with open(self.servercertnick_conf, "w") as fd:
                    ssl_server_nickname = None
                    if self.step_two:
                        # use final HSM name
                        ssl_server_nickname = (self.token_name + ":" +
                                               self.nickname)
                    else:
                        # use softokn name
                        ssl_server_nickname = self.nickname
                    fd.write(ssl_server_nickname)
                    config.pki_log.info(
                        log.PKIHELPER_SERVERCERTNICK_CONF_2,
                        self.servercertnick_conf,
                        ssl_server_nickname,
                        extra=config.PKI_INDENTATION_LEVEL_2)
            except OSError as exc:
                config.pki_log.error(log.PKI_OSERROR_1, exc,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                raise


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

            config.pki_log.info(
                log.PKIHELPER_KRACONNECTOR_UPDATE_CONTACT,
                extra=config.PKI_INDENTATION_LEVEL_2)

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
                config.pki_log.warning(
                    log.PKIHELPER_KRACONNECTOR_UPDATE_FAILURE,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                config.pki_log.error(
                    log.PKIHELPER_UNDEFINED_SUBSYSTEM_NICKNAME,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure:
                    raise Exception(log.PKIHELPER_UNDEFINED_SUBSYSTEM_NICKNAME)
                else:
                    return

            # retrieve name of token based upon type (hardware/software)
            if ':' in subsystemnick:
                token_name = subsystemnick.split(':')[0]
            else:
                token_name = "internal"

            token_pwd = self.password.get_password(
                self.mdict['pki_shared_password_conf'],
                token_name,
                critical_failure)

            if token_pwd is None or token_pwd == '':
                config.pki_log.warning(
                    log.PKIHELPER_KRACONNECTOR_UPDATE_FAILURE,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                config.pki_log.error(
                    log.PKIHELPER_UNDEFINED_TOKEN_PASSWD_1,
                    token_name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
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
                config.pki_log.error(
                    "unable to access security domain. Continuing .. " +
                    str(e),
                    extra=config.PKI_INDENTATION_LEVEL_2)
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
                    config.pki_log.warning(
                        log.PKIHELPER_KRACONNECTOR_DEREGISTER_FAILURE_4,
                        str(krahost), str(kraport), str(ca_host), str(ca_port),
                        extra=config.PKI_INDENTATION_LEVEL_2)

        except subprocess.CalledProcessError as exc:
            config.pki_log.warning(
                log.PKIHELPER_KRACONNECTOR_UPDATE_FAILURE_2,
                str(krahost),
                str(kraport),
                extra=config.PKI_INDENTATION_LEVEL_2)
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
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
            config.pki_log.info(
                "unable to access security domain through REST interface.  " +
                "Trying old interface. " + str(e),
                extra=config.PKI_INDENTATION_LEVEL_2)
            info = sd.get_old_security_domain_info()
        return list(info.systems['CA'].hosts.values())

    def execute_using_pki(
            self, caport, cahost, subsystemnick,
            token_pwd, krahost, kraport, critical_failure=False):
        command = ["/bin/pki",
                   "-p", str(caport),
                   "-h", cahost,
                   "-n", subsystemnick,
                   "-P", "https",
                   "-d", self.mdict['pki_database_path'],
                   "-c", token_pwd,
                   "ca-kraconnector-del",
                   "--host", krahost,
                   "--port", str(kraport)]

        output = subprocess.check_output(command,
                                         stderr=subprocess.STDOUT)
        output = output.decode('utf-8')
        error = re.findall("ClientResponseFailure:(.*?)", output)
        if error:
            config.pki_log.warning(
                log.PKIHELPER_KRACONNECTOR_UPDATE_FAILURE_2,
                str(krahost),
                str(kraport),
                extra=config.PKI_INDENTATION_LEVEL_2)
            config.pki_log.error(
                log.PKI_SUBPROCESS_ERROR_1, output,
                extra=config.PKI_INDENTATION_LEVEL_2)
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
                   "-d", self.mdict['pki_database_path'],
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

            config.pki_log.info(
                log.PKIHELPER_TPSCONNECTOR_UPDATE_CONTACT,
                extra=config.PKI_INDENTATION_LEVEL_2)

            cs_cfg = PKIConfigParser.read_simple_configuration_file(
                self.mdict['pki_target_cs_cfg'])
            tpshost = cs_cfg.get('service.machineName')
            tpsport = cs_cfg.get('pkicreate.secure_port')
            tkshost = cs_cfg.get('tps.connector.tks1.host')
            tksport = cs_cfg.get('tps.connector.tks1.port')
            if tkshost is None or tksport is None:
                config.pki_log.warning(
                    log.PKIHELPER_TPSCONNECTOR_UPDATE_FAILURE,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                config.pki_log.error(
                    log.PKIHELPER_UNDEFINED_TKS_HOST_PORT,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure:
                    raise Exception(log.PKIHELPER_UNDEFINED_TKS_HOST_PORT)
                else:
                    return

            # retrieve subsystem nickname
            subsystemnick = cs_cfg.get('tps.cert.subsystem.nickname')
            if subsystemnick is None:
                config.pki_log.warning(
                    log.PKIHELPER_TPSCONNECTOR_UPDATE_FAILURE,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                config.pki_log.error(
                    log.PKIHELPER_UNDEFINED_SUBSYSTEM_NICKNAME,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure:
                    raise Exception(log.PKIHELPER_UNDEFINED_SUBSYSTEM_NICKNAME)
                else:
                    return

            # retrieve name of token based upon type (hardware/software)
            if ':' in subsystemnick:
                token_name = subsystemnick.split(':')[0]
            else:
                token_name = "internal"

            token_pwd = self.password.get_password(
                self.mdict['pki_shared_password_conf'],
                token_name,
                critical_failure)

            if token_pwd is None or token_pwd == '':
                config.pki_log.warning(
                    log.PKIHELPER_TPSCONNECTOR_UPDATE_FAILURE,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                config.pki_log.error(
                    log.PKIHELPER_UNDEFINED_TOKEN_PASSWD_1,
                    token_name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure:
                    raise Exception(
                        log.PKIHELPER_UNDEFINED_TOKEN_PASSWD_1 % token_name)
                else:
                    return

            self.execute_using_pki(
                tkshost, tksport, subsystemnick,
                token_pwd, tpshost, tpsport)

        except subprocess.CalledProcessError as exc:
            config.pki_log.warning(
                log.PKIHELPER_TPSCONNECTOR_UPDATE_FAILURE_2,
                str(tkshost),
                str(tksport),
                extra=config.PKI_INDENTATION_LEVEL_2)
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        return

    def execute_using_pki(
            self, tkshost, tksport, subsystemnick,
            token_pwd, tpshost, tpsport, critical_failure=False):
        command = ["/bin/pki",
                   "-p", str(tksport),
                   "-h", tkshost,
                   "-n", subsystemnick,
                   "-P", "https",
                   "-d", self.mdict['pki_database_path'],
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
            config.pki_log.warning(
                log.PKIHELPER_TPSCONNECTOR_UPDATE_FAILURE_2,
                str(tpshost),
                str(tpsport),
                extra=config.PKI_INDENTATION_LEVEL_2)
            config.pki_log.error(
                log.PKI_SUBPROCESS_ERROR_1, output,
                extra=config.PKI_INDENTATION_LEVEL_2)
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
            config.pki_log.warning(
                log.PKIHELPER_SECURITY_DOMAIN_UPDATE_FAILURE_2,
                typeval,
                secname,
                extra=config.PKI_INDENTATION_LEVEL_2)
            config.pki_log.error(
                log.PKIHELPER_SECURITY_DOMAIN_UNDEFINED,
                extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise Exception(log.PKIHELPER_SECURITY_DOMAIN_UNDEFINED)
            else:
                return

        config.pki_log.info(log.PKIHELPER_SECURITY_DOMAIN_CONTACT_1,
                            secname,
                            extra=config.PKI_INDENTATION_LEVEL_2)
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
                           "-d", self.mdict['pki_database_path'],
                           "-e", params,
                           "-v",
                           "-r", admin_update_url,
                           sechost + ":" + str(secadminport)]
                output = subprocess.check_output(
                    command,
                    stderr=subprocess.STDOUT)
                output = output.decode('utf-8')
            except subprocess.CalledProcessError:
                config.pki_log.warning(
                    log.PKIHELPER_SECURITY_DOMAIN_UNREACHABLE_1,
                    secname,
                    extra=config.PKI_INDENTATION_LEVEL_2)
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

        config.pki_log.debug(log.PKIHELPER_SSLGET_OUTPUT_1,
                             output,
                             extra=config.PKI_INDENTATION_LEVEL_2)
        # Search the output for Status
        status = re.findall('<Status>(.*?)</Status>', output)
        if not status:
            config.pki_log.warning(
                log.PKIHELPER_SECURITY_DOMAIN_UNREACHABLE_1,
                secname,
                extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise Exception(
                    log.PKIHELPER_SECURITY_DOMAIN_UNREACHABLE_1 % secname)
        elif status[0] != "0":
            error = re.findall('<Error>(.*?)</Error>', output)
            if not error:
                error = ""
            config.pki_log.warning(
                log.PKIHELPER_SECURITY_DOMAIN_UNREGISTERED_2,
                typeval,
                secname,
                extra=config.PKI_INDENTATION_LEVEL_2)
            config.pki_log.error(
                log.PKIHELPER_SECURITY_DOMAIN_UPDATE_FAILURE_3,
                typeval,
                secname,
                error,
                extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise Exception(log.PKIHELPER_SECURITY_DOMAIN_UPDATE_FAILURE_3
                                %
                                (typeval, secname, error))
        else:
            config.pki_log.info(
                log.PKIHELPER_SECURITY_DOMAIN_UPDATE_SUCCESS_2,
                typeval,
                secname,
                extra=config.PKI_INDENTATION_LEVEL_2)

    def update_domain_using_agent_port(
            self, typeval, secname, params,
            update_url, sechost, secagentport, critical_failure=False):
        cs_cfg = PKIConfigParser.read_simple_configuration_file(
            self.mdict['pki_target_cs_cfg'])
        # retrieve subsystem nickname
        subsystemnick_param = typeval.lower() + ".cert.subsystem.nickname"
        subsystemnick = cs_cfg.get(subsystemnick_param)
        if subsystemnick is None:
            config.pki_log.warning(
                log.PKIHELPER_SECURITY_DOMAIN_UPDATE_FAILURE_2,
                typeval,
                secname,
                extra=config.PKI_INDENTATION_LEVEL_2)
            config.pki_log.error(
                log.PKIHELPER_UNDEFINED_SUBSYSTEM_NICKNAME,
                extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise Exception(log.PKIHELPER_UNDEFINED_SUBSYSTEM_NICKNAME)
            else:
                return

        # retrieve name of token based upon type (hardware/software)
        if ':' in subsystemnick:
            token_name = subsystemnick.split(':')[0]
        else:
            token_name = "internal"

        token_pwd = self.password.get_password(
            self.mdict['pki_shared_password_conf'],
            token_name,
            critical_failure)

        if token_pwd is None or token_pwd == '':
            config.pki_log.warning(
                log.PKIHELPER_SECURITY_DOMAIN_UPDATE_FAILURE_2,
                typeval,
                secname,
                extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise Exception(
                    log.PKIHELPER_SECURITY_DOMAIN_UPDATE_FAILURE_2 %
                    (typeval, secname))
            else:
                return

        command = ["/usr/bin/sslget",
                   "-n", subsystemnick,
                   "-p", token_pwd,
                   "-d", self.mdict['pki_database_path'],
                   "-e", params,
                   "-v",
                   "-r", update_url, sechost + ":" + str(secagentport)]
        try:
            output = subprocess.check_output(command,
                                             stderr=subprocess.STDOUT)
            output = output.decode('utf-8')
            return output
        except subprocess.CalledProcessError as exc:
            config.pki_log.warning(
                log.PKIHELPER_SECURITY_DOMAIN_UPDATE_FAILURE_2,
                typeval,
                secname,
                extra=config.PKI_INDENTATION_LEVEL_2)
            config.pki_log.warning(
                log.PKIHELPER_SECURITY_DOMAIN_UNREACHABLE_1,
                secname,
                extra=config.PKI_INDENTATION_LEVEL_2)
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise

        return None


class Systemd(object):
    """PKI Deployment Execution Management Class"""

    def __init__(self, deployer):
        """PKI Deployment execution management __init__ method.

        Args:
          deployer (dictionary):  PKI Deployment name/value parameters

        Attributes:

        Returns:

        Raises:

        Examples:

        """
        self.mdict = deployer.mdict

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
            # Un-defined command on Debian systems
            if pki.system.SYSTEM_TYPE == "debian":
                return
            # Compose this "systemd" execution management lifecycle command
            command = ["systemctl", "daemon-reload"]
            # Display this "systemd" execution management lifecycle command
            config.pki_log.info(
                log.PKIHELPER_SYSTEMD_COMMAND_1, ' '.join(command),
                extra=config.PKI_INDENTATION_LEVEL_2)
            # Execute this "systemd" execution management lifecycle command
            subprocess.check_call(command)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        return

    def disable(self, critical_failure=True):
        # Legacy SysVinit shutdown (kill) script on system shutdown values:
        #
        #    /etc/rc3.d/K13<TPS instance>  --> /etc/init.d/<TPS instance>
        #    /etc/rc3.d/K14<RA instance>   --> /etc/init.d/<RA instance>
        #    /etc/rc3.d/K16<TKS instance>  --> /etc/init.d/<TKS instance>
        #    /etc/rc3.d/K17<OCSP instance> --> /etc/init.d/<OCSP instance>
        #    /etc/rc3.d/K18<KRA instance>  --> /etc/init.d/<KRA instance>
        #    /etc/rc3.d/K19<CA instance>   --> /etc/init.d/<CA instance>
        #
        """PKI Deployment execution management 'disable' method.

        Executes a 'systemd disable pki-tomcatd.target' system command, or
        an 'rm /etc/rc3.d/*<instance>' system command on Debian systems.

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
            if pki.system.SYSTEM_TYPE == "debian":
                command = ["rm", "/etc/rc3.d/*" +
                           self.mdict['pki_instance_name']]
            else:
                command = ["systemctl", "disable", "pki-tomcatd.target"]

            # Display this "systemd" execution managment command
            config.pki_log.info(
                log.PKIHELPER_SYSTEMD_COMMAND_1, ' '.join(command),
                extra=config.PKI_INDENTATION_LEVEL_2)
            # Execute this "systemd" execution management command
            subprocess.check_call(command)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        return

    def enable(self, critical_failure=True):
        # Legacy SysVinit startup script on system boot values:
        #
        #    /etc/rc3.d/S81<CA instance>   --> /etc/init.d/<CA instance>
        #    /etc/rc3.d/S82<KRA instance>  --> /etc/init.d/<KRA instance>
        #    /etc/rc3.d/S83<OCSP instance> --> /etc/init.d/<OCSP instance>
        #    /etc/rc3.d/S84<TKS instance>  --> /etc/init.d/<TKS instance>
        #    /etc/rc3.d/S86<RA instance>   --> /etc/init.d/<RA instance>
        #    /etc/rc3.d/S87<TPS instance>  --> /etc/init.d/<TPS instance>
        #
        """PKI Deployment execution management 'enable' method.

           Executes a 'systemd enable pki-tomcatd.target' system command, or
           an 'ln -s /etc/init.d/pki-tomcatd /etc/rc3.d/S89<instance>'
           system command on Debian systems.

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
            if pki.system.SYSTEM_TYPE == "debian":
                command = ["ln", "-s", "/etc/init.d/pki-tomcatd",
                           "/etc/rc3.d/S89" + self.mdict['pki_instance_name']]
            else:
                command = ["systemctl", "enable", "pki-tomcatd.target"]

            # Display this "systemd" execution managment command
            config.pki_log.info(
                log.PKIHELPER_SYSTEMD_COMMAND_1, ' '.join(command),
                extra=config.PKI_INDENTATION_LEVEL_2)
            # Execute this "systemd" execution management command
            subprocess.check_call(command)
        except subprocess.CalledProcessError as exc:
            if pki.system.SYSTEM_TYPE == "debian":
                if exc.returncode == 6:
                    return
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        return

    def start(self, critical_failure=True, reload_daemon=True):
        """PKI Deployment execution management 'start' method.

           Executes a 'systemd start <service>' system command, or
           an '/etc/init.d/pki-tomcatd start <instance>' system command.
           on Debian systems.

        Args:
          critical_failure (boolean, optional):  Raise exception on failures;
                                                 defaults to 'True'.
          reload_daemon (boolean, optional):     Perform a reload of the
                                                 'systemd' daemon prior to
                                                 starting;
                                                 defaults to 'True'.

        Attributes:

        Returns:

        Raises:
          subprocess.CalledProcessError:  If 'critical_failure' is 'True'.

        Examples:

        """
        try:
            service = None
            # Execute the "systemd daemon-reload" management lifecycle command
            if reload_daemon:
                self.daemon_reload(critical_failure)
            # Compose this "systemd" execution management command
            service = "pki-tomcatd" + "@" +\
                      self.mdict['pki_instance_name'] + "." +\
                      "service"

            if pki.system.SYSTEM_TYPE == "debian":
                command = ["/etc/init.d/pki-tomcatd", "start",
                           self.mdict['pki_instance_name']]
            else:
                command = ["systemctl", "start", service]

            # Display this "systemd" execution managment command
            config.pki_log.info(
                log.PKIHELPER_SYSTEMD_COMMAND_1, ' '.join(command),
                extra=config.PKI_INDENTATION_LEVEL_2)
            # Execute this "systemd" execution management command
            subprocess.check_call(command)
        except subprocess.CalledProcessError as exc:
            if pki.system.SYSTEM_TYPE == "debian":
                if exc.returncode == 6:
                    return
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        return

    def stop(self, critical_failure=True):
        """PKI Deployment execution management 'stop' method.

        Executes a 'systemd stop <service>' system command, or
        an '/etc/init.d/pki-tomcatd stop <instance>' system command
        on Debian systems.

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
            service = None
            # Compose this "systemd" execution management command
            service = "pki-tomcatd" + "@" +\
                      self.mdict['pki_instance_name'] + "." +\
                      "service"

            if pki.system.SYSTEM_TYPE == "debian":
                command = ["/etc/init.d/pki-tomcatd", "stop",
                           self.mdict['pki_instance_name']]
            else:
                command = ["systemctl", "stop", service]

            # Display this "systemd" execution managment command
            config.pki_log.info(
                log.PKIHELPER_SYSTEMD_COMMAND_1, ' '.join(command),
                extra=config.PKI_INDENTATION_LEVEL_2)
            # Execute this "systemd" execution management command
            subprocess.check_call(command)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure:
                raise
        return

    def restart(self, critical_failure=True, reload_daemon=True):
        """PKI Deployment execution management 'restart' method.

        Executes a 'systemd restart <service>' system command, or
        an '/etc/init.d/pki-tomcatd restart <instance>' system command
        on Debian systems.

        Args:
          critical_failure (boolean, optional):  Raise exception on failures;
                                                 defaults to 'True'.
          reload_daemon (boolean, optional):     Perform a reload of the
                                                 'systemd' daemon prior to
                                                 restarting;
                                                 defaults to 'True'.

        Attributes:

        Returns:

        Raises:
          subprocess.CalledProcessError:  If 'critical_failure' is 'True'.

        Examples:

        """
        try:
            service = None
            # Compose this "systemd" execution management command
            # Execute the "systemd daemon-reload" management lifecycle command
            if reload_daemon:
                self.daemon_reload(critical_failure)

            service = "pki-tomcatd" + "@" +\
                      self.mdict['pki_instance_name'] + "." +\
                      "service"

            if pki.system.SYSTEM_TYPE == "debian":
                command = ["/etc/init.d/pki-tomcatd", "restart",
                           self.mdict['pki_instance_name']]
            else:
                command = ["systemctl", "restart", service]

            # Display this "systemd" execution managment command
            config.pki_log.info(
                log.PKIHELPER_SYSTEMD_COMMAND_1, ' '.join(command),
                extra=config.PKI_INDENTATION_LEVEL_2)
            # Execute this "systemd" execution management command
            subprocess.check_call(command)
        except subprocess.CalledProcessError as exc:
            if pki.system.SYSTEM_TYPE == "debian":
                if exc.returncode == 6:
                    return
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
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

    def configure_pki_data(self, data):
        config.pki_log.info(
            log.PKI_CONFIG_CONFIGURING_PKI_DATA,
            extra=config.PKI_INDENTATION_LEVEL_2)

        connection = pki.client.PKIConnection(
            protocol='https',
            hostname=self.mdict['pki_hostname'],
            port=self.mdict['pki_https_port'],
            subsystem=self.mdict['pki_subsystem_type'],
            trust_env=False)

        try:
            client = pki.system.SystemConfigClient(connection)
            response = client.configure(data)

            config.pki_log.debug(
                log.PKI_CONFIG_RESPONSE_STATUS + " " + str(response['status']),
                extra=config.PKI_INDENTATION_LEVEL_2)
            try:
                certs = response['systemCerts']
            except KeyError:
                # no system certs created
                config.pki_log.debug(
                    "No new system certificates generated.",
                    extra=config.PKI_INDENTATION_LEVEL_2)
                certs = []

            if not isinstance(certs, list):
                certs = [certs]
            for cdata in certs:
                if self.standalone and not self.external_step_two:
                    # Stand-alone PKI (Step 1)
                    if cdata['tag'].lower() == "audit_signing":
                        # Save Stand-alone PKI 'Audit Signing Certificate' CSR
                        # (Step 1)
                        self.save_system_csr(
                            cdata['request'],
                            log.PKI_CONFIG_EXTERNAL_CSR_SAVE_PKI_AUDIT_SIGNING_1,
                            self.mdict['pki_external_audit_signing_csr_path'],
                            self.subsystem)
                    elif cdata['tag'].lower() == "signing":
                        # Save Stand-alone PKI OCSP 'OCSP Signing Certificate'
                        # CSR (Step 1)
                        self.save_system_csr(
                            cdata['request'],
                            log.PKI_CONFIG_EXTERNAL_CSR_SAVE_OCSP_SIGNING,
                            self.mdict['pki_external_signing_csr_path'])
                    elif cdata['tag'].lower() == "sslserver":
                        # Save Stand-alone PKI 'SSL Server Certificate' CSR
                        # (Step 1)
                        self.save_system_csr(
                            cdata['request'],
                            log.PKI_CONFIG_EXTERNAL_CSR_SAVE_PKI_SSLSERVER_1,
                            self.mdict['pki_external_sslserver_csr_path'],
                            self.subsystem)
                    elif cdata['tag'].lower() == "storage":
                        # Save Stand-alone PKI KRA 'Storage Certificate' CSR
                        # (Step 1)
                        self.save_system_csr(
                            cdata['request'],
                            log.PKI_CONFIG_EXTERNAL_CSR_SAVE_KRA_STORAGE,
                            self.mdict['pki_external_storage_csr_path'])
                    elif cdata['tag'].lower() == "subsystem":
                        # Save Stand-alone PKI 'Subsystem Certificate' CSR
                        # (Step 1)
                        self.save_system_csr(
                            cdata['request'],
                            log.PKI_CONFIG_EXTERNAL_CSR_SAVE_PKI_SUBSYSTEM_1,
                            self.mdict['pki_external_subsystem_csr_path'],
                            self.subsystem)
                    elif cdata['tag'].lower() == "transport":
                        # Save Stand-alone PKI KRA 'Transport Certificate' CSR
                        # (Step 1)
                        self.save_system_csr(
                            cdata['request'],
                            log.PKI_CONFIG_EXTERNAL_CSR_SAVE_KRA_TRANSPORT,
                            self.mdict['pki_external_transport_csr_path'])
                else:
                    config.pki_log.debug(
                        log.PKI_CONFIG_CDATA_TAG + " " + cdata['tag'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    config.pki_log.debug(
                        log.PKI_CONFIG_CDATA_CERT + "\n" + cdata['cert'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    config.pki_log.debug(
                        log.PKI_CONFIG_CDATA_REQUEST + "\n" + cdata['request'],
                        extra=config.PKI_INDENTATION_LEVEL_2)

            # Cloned PKI subsystems do not return an Admin Certificate
            if not self.clone:
                if self.standalone:
                    if not self.external_step_two:
                        # NOTE:  Do nothing for Stand-alone PKI (Step 1)
                        #        as this has already been addressed
                        #        in 'set_admin_parameters()'
                        pass
                    else:
                        admin_cert = response['adminCert']['cert']
                        self.process_admin_cert(admin_cert)
                elif not config.str2bool(self.mdict['pki_import_admin_cert']):
                    admin_cert = response['adminCert']['cert']
                    self.process_admin_cert(admin_cert)

        except:

            raise

    def process_admin_cert(self, admin_cert):
        config.pki_log.debug(
            log.PKI_CONFIG_RESPONSE_ADMIN_CERT + "\n" + admin_cert,
            extra=config.PKI_INDENTATION_LEVEL_2)

        # Store the Administration Certificate in a file
        admin_cert_file = self.mdict['pki_client_admin_cert']
        admin_cert_bin_file = admin_cert_file + ".der"
        self.save_admin_cert(log.PKI_CONFIG_ADMIN_CERT_SAVE_1,
                             admin_cert, admin_cert_file,
                             self.mdict['pki_subsystem_name'])

        # convert the cert file to binary
        command = ["AtoB", admin_cert_file, admin_cert_bin_file]
        config.pki_log.info(
            ' '.join(command),
            extra=config.PKI_INDENTATION_LEVEL_2)
        try:
            subprocess.check_call(command)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
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

    def construct_pki_configuration_data(self):
        config.pki_log.info(log.PKI_CONFIG_CONSTRUCTING_PKI_DATA,
                            extra=config.PKI_INDENTATION_LEVEL_2)

        data = pki.system.ConfigurationRequest()

        # Miscellaneous Configuration Information
        data.pin = self.mdict['pki_one_time_pin']
        if config.str2bool(self.mdict['pki_hsm_enable']):
            data.token = self.mdict['pki_token_name']
            data.tokenPassword = self.mdict['pki_token_password']
        data.subsystemName = self.mdict['pki_subsystem_name']

        # Process existing CA installation like external CA
        data.external = self.external or self.existing
        data.standAlone = self.standalone

        if self.standalone:
            # standalone installation uses two-step process (ticket #1698)
            data.stepTwo = self.external_step_two

        else:
            # other installations use only one step in the configuration servlet
            data.stepTwo = False

        # Cloning parameters
        if self.mdict['pki_instance_type'] == "Tomcat":
            if self.clone:
                self.set_cloning_parameters(data)
            else:
                data.isClone = "false"

        # Hierarchy
        self.set_hierarchy_parameters(data)

        # Security Domain
        if self.security_domain_type != "new":
            self.set_existing_security_domain(data)
        else:
            # PKI CA, External CA, or Stand-alone PKI
            self.set_new_security_domain(data)

        if self.subordinate:
            self.set_subca_security_domain(data)

        # database
        if self.subsystem != "RA":
            self.set_database_parameters(data)

        # backup
        if self.mdict['pki_instance_type'] == "Tomcat":
            self.set_backup_parameters(data)

        # admin user
        if not self.clone:
            self.set_admin_parameters(data)

        data.replicationPassword = self.mdict['pki_replication_password']

        # Issuing CA Information
        self.set_issuing_ca_parameters(data)

        data.systemCertsImported = self.mdict['pki_server_pkcs12_path'] != ''

        # Create system certs
        self.set_system_certs(data)

        # TPS parameters
        if self.subsystem == "TPS":
            self.set_tps_parameters(data)

        # Misc CA parameters
        if self.subsystem == "CA":
            data.startingCRLNumber = self.mdict['pki_ca_starting_crl_number']

        return data

    def save_admin_csr(self):
        config.pki_log.info(
            log.PKI_CONFIG_EXTERNAL_CSR_SAVE_PKI_ADMIN_1 + " '" +
            self.mdict['pki_external_admin_csr_path'] + "'", self.subsystem,
            extra=config.PKI_INDENTATION_LEVEL_2)
        self.deployer.directory.create(
            os.path.dirname(self.mdict['pki_external_admin_csr_path']))
        with open(self.mdict['pki_external_admin_csr_path'], "w") as f:
            f.write("-----BEGIN CERTIFICATE REQUEST-----\n")
        admin_certreq = None
        with open(os.path.join(
                  self.mdict['pki_client_database_dir'],
                  "admin_pkcs10.bin.asc"), "r") as f:
            admin_certreq = f.read()
        with open(self.mdict['pki_external_admin_csr_path'], "a") as f:
            f.write(admin_certreq)
            f.write("-----END CERTIFICATE REQUEST-----")
        # Read in and print Admin certificate request
        with open(self.mdict['pki_external_admin_csr_path'], "r") as f:
            admin_certreq = f.read()
        config.pki_log.info(
            log.PKI_CONFIG_CDATA_REQUEST + "\n" + admin_certreq,
            extra=config.PKI_INDENTATION_LEVEL_2)

    def save_admin_cert(self, message, input_data, output_file,
                        subsystem_name):
        config.pki_log.debug(message + " '" + output_file + "'",
                             subsystem_name,
                             extra=config.PKI_INDENTATION_LEVEL_2)
        with open(output_file, "w") as f:
            f.write(input_data)

    def save_system_csr(self, csr, message, path, subsystem=None):
        if subsystem is not None:
            config.pki_log.info(message + " '" + path + "'", subsystem,
                                extra=config.PKI_INDENTATION_LEVEL_2)
        else:
            config.pki_log.info(message + " '" + path + "'",
                                extra=config.PKI_INDENTATION_LEVEL_2)
        self.deployer.directory.create(os.path.dirname(path))
        with open(path, "w") as f:
            f.write(csr)
        # Print this certificate request
        config.pki_log.info(log.PKI_CONFIG_CDATA_REQUEST + "\n" + csr,
                            extra=config.PKI_INDENTATION_LEVEL_2)

    def load_system_cert(self, cert, message, path, subsystem=None):
        if subsystem is not None:
            config.pki_log.info(message + " '" + path + "'", subsystem,
                                extra=config.PKI_INDENTATION_LEVEL_2)
        else:
            config.pki_log.info(message + " '" + path + "'",
                                extra=config.PKI_INDENTATION_LEVEL_2)
        with open(path, "r") as f:
            cert.cert = f.read()

    def load_system_cert_chain(self, cert, message, path):
        config.pki_log.info(message + " '" + path + "'",
                            extra=config.PKI_INDENTATION_LEVEL_2)
        with open(path, "r") as f:
            cert.certChain = f.read()

    def set_system_certs(self, data):
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
                    if self.mdict['pki_external_ca_cert_path']:
                        self.load_system_cert(
                            cert1,
                            log.PKI_CONFIG_EXTERNAL_CA_LOAD,
                            self.mdict['pki_external_ca_cert_path'])

                    # If specified, load the external CA cert chain
                    if self.mdict['pki_external_ca_cert_chain_path']:
                        self.load_system_cert_chain(
                            cert1,
                            log.PKI_CONFIG_EXTERNAL_CA_CHAIN_LOAD,
                            self.mdict['pki_external_ca_cert_chain_path'])

                    systemCerts.append(cert1)

                elif self.standalone and self.external_step_two:
                    # standalone KRA/OCSP step 2

                    cert1 = pki.system.SystemCertData()
                    cert1.tag = self.mdict['pki_ca_signing_tag']

                    # Load the stand-alone PKI
                    # 'External CA Signing Certificate' (Step 2)
                    self.load_system_cert(
                        cert1,
                        log.PKI_CONFIG_EXTERNAL_CA_LOAD,
                        self.mdict['pki_external_ca_cert_path'])

                    # Load the stand-alone PKI
                    # 'External CA Signing Certificate Chain' (Step 2)
                    self.load_system_cert_chain(
                        cert1,
                        log.PKI_CONFIG_EXTERNAL_CA_CHAIN_LOAD,
                        self.mdict['pki_external_ca_cert_chain_path'])

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
                self.load_system_cert(
                    cert2,
                    log.PKI_CONFIG_EXTERNAL_CERT_LOAD_OCSP_SIGNING,
                    self.mdict['pki_external_signing_cert_path'])
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
            cert3 = self.create_system_cert("ssl_server")
            # Load the Stand-alone PKI 'SSL Server Certificate' (Step 2)
            self.load_system_cert(
                cert3,
                log.PKI_CONFIG_EXTERNAL_CERT_LOAD_PKI_SSLSERVER_1,
                self.mdict['pki_external_sslserver_cert_path'],
                self.subsystem)
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
            cert3 = self.create_system_cert("ssl_server")
            systemCerts.append(cert3)

        # Create 'Subsystem Certificate'
        if not self.clone:
            if self.standalone and self.external_step_two:
                data.generateSubsystemCert = "true"
                # Stand-alone PKI (Step 2)
                cert4 = self.create_system_cert("subsystem")
                # Load the Stand-alone PKI 'Subsystem Certificate' (Step 2)
                self.load_system_cert(
                    cert4,
                    log.PKI_CONFIG_EXTERNAL_CERT_LOAD_PKI_SUBSYSTEM_1,
                    self.mdict['pki_external_subsystem_cert_path'],
                    self.subsystem)
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
                self.load_system_cert(
                    cert5,
                    log.PKI_CONFIG_EXTERNAL_CERT_LOAD_PKI_AUDIT_SIGNING_1,
                    self.mdict['pki_external_audit_signing_cert_path'],
                    self.subsystem)
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
                self.load_system_cert(
                    cert6,
                    log.PKI_CONFIG_EXTERNAL_CERT_LOAD_KRA_TRANSPORT,
                    self.mdict['pki_external_transport_cert_path'])
                systemCerts.append(cert6)
                # Stand-alone PKI KRA Storage Certificate (Step 2)
                cert7 = self.create_system_cert("storage")
                # Load the Stand-alone PKI KRA 'Storage Certificate' (Step 2)
                self.load_system_cert(
                    cert7,
                    log.PKI_CONFIG_EXTERNAL_CERT_LOAD_KRA_STORAGE,
                    self.mdict['pki_external_storage_cert_path'])
                systemCerts.append(cert7)
            elif self.subsystem == "KRA":
                # PKI KRA Transport Certificate
                cert6 = self.create_system_cert("transport")
                systemCerts.append(cert6)
                # PKI KRA Storage Certificate
                cert7 = self.create_system_cert("storage")
                systemCerts.append(cert7)

        data.systemCerts = systemCerts

    def set_cloning_parameters(self, data):
        data.isClone = "true"
        data.cloneUri = self.mdict['pki_clone_uri']

        # Set these clone parameters for non-HSM clones only
        if not config.str2bool(self.mdict['pki_hsm_enable']):
            # If system certificates are already provided via pki_server_pkcs12
            # there's no need to provide pki_clone_pkcs12.
            if not self.mdict['pki_server_pkcs12_path']:
                data.p12File = self.mdict['pki_clone_pkcs12_path']
                data.p12Password = self.mdict['pki_clone_pkcs12_password']

        if config.str2bool(self.mdict['pki_clone_replicate_schema']):
            data.replicateSchema = "true"
        else:
            data.replicateSchema = "false"
        data.replicationSecurity = \
            self.mdict['pki_clone_replication_security']
        if self.mdict['pki_clone_replication_master_port']:
            data.masterReplicationPort = \
                self.mdict['pki_clone_replication_master_port']
        if self.mdict['pki_clone_replication_clone_port']:
            data.cloneReplicationPort = \
                self.mdict['pki_clone_replication_clone_port']
        data.setupReplication = self.mdict['pki_clone_setup_replication']
        data.reindexData = self.mdict['pki_clone_reindex_data']

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
        data.securityDomainType = "existingdomain"
        data.securityDomainUri = self.mdict['pki_security_domain_uri']
        data.securityDomainUser = self.mdict['pki_security_domain_user']
        data.securityDomainPassword = self.mdict[
            'pki_security_domain_password']

    def set_new_security_domain(self, data):
        data.securityDomainType = "newdomain"
        data.securityDomainName = self.mdict['pki_security_domain_name']

    def set_subca_security_domain(self, data):
        if config.str2bool(
                self.mdict['pki_subordinate_create_new_security_domain']):
            data.securityDomainType = "newsubdomain"
            data.subordinateSecurityDomainName = (
                self.mdict['pki_subordinate_security_domain_name'])

    def set_database_parameters(self, data):
        data.dsHost = self.mdict['pki_ds_hostname']
        if config.str2bool(self.mdict['pki_ds_secure_connection']):
            data.secureConn = "true"
            data.dsPort = self.mdict['pki_ds_ldaps_port']
        else:
            data.secureConn = "false"
            data.dsPort = self.mdict['pki_ds_ldap_port']
        data.baseDN = self.mdict['pki_ds_base_dn']
        data.bindDN = self.mdict['pki_ds_bind_dn']
        data.database = self.mdict['pki_ds_database']
        data.bindpwd = self.mdict['pki_ds_password']
        if config.str2bool(self.mdict['pki_ds_create_new_db']):
            data.createNewDB = "true"
        else:
            data.createNewDB = "false"
        if config.str2bool(self.mdict['pki_ds_remove_data']):
            data.removeData = "true"
        else:
            data.removeData = "false"
        if config.str2bool(self.mdict['pki_share_db']):
            data.sharedDB = "true"
            data.sharedDBUserDN = self.mdict['pki_share_dbuser_dn']
        else:
            data.sharedDB = "false"

    def set_backup_parameters(self, data):
        if config.str2bool(self.mdict['pki_backup_keys']):
            data.backupKeys = "true"
            data.backupFile = self.mdict['pki_backup_keys_p12']
            data.backupPassword = self.mdict['pki_backup_password']
        else:
            data.backupKeys = "false"

    def set_admin_parameters(self, data):
        data.adminEmail = self.mdict['pki_admin_email']
        data.adminName = self.mdict['pki_admin_name']
        data.adminPassword = self.mdict['pki_admin_password']
        data.adminProfileID = self.mdict['pki_admin_profile_id']
        data.adminUID = self.mdict['pki_admin_uid']
        data.adminSubjectDN = self.mdict['pki_admin_subject_dn']
        if self.standalone:
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
            if self.standalone:
                # Stand-alone PKI (Step 2)
                #
                # Copy the Stand-alone PKI 'Admin Certificate'
                # (that was previously generated via an external CA) into
                # 'ca_admin.cert' under the specified 'pki_client_dir'
                # stripping the certificate HEADER/FOOTER prior to saving it.
                imported_admin_cert = ""
                with open(self.mdict['pki_external_admin_cert_path'], "r") as f:
                    for line in f:
                        if line.startswith("-----BEGIN CERTIFICATE-----"):
                            continue
                        elif line.startswith("-----END CERTIFICATE-----"):
                            continue
                        else:
                            imported_admin_cert += line
                with open(self.mdict['pki_admin_cert_file'], "w") as f:
                    f.write(imported_admin_cert)
            # read config from file
            with open(self.mdict['pki_admin_cert_file'], "r") as f:
                b64 = f.read().replace('\n', '')
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
                    self.mdict['pki_admin_keysize'],
                    self.mdict['pki_client_password_conf'],
                    noise_file,
                    output_file,
                    self.mdict['pki_client_database_dir'],
                    None, None, True)

                self.deployer.file.delete(noise_file)

                # convert output to ascii
                command = ["BtoA", output_file, output_file + ".asc"]
                config.pki_log.info(
                    ' '.join(command),
                    extra=config.PKI_INDENTATION_LEVEL_2)
                try:
                    subprocess.check_call(command)
                except subprocess.CalledProcessError as exc:
                    config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                         extra=config.PKI_INDENTATION_LEVEL_2)
                    raise

                if self.standalone and not self.external_step_two:
                    # For convenience and consistency, save a copy of
                    # the Stand-alone PKI 'Admin Certificate' CSR to the
                    # specified "pki_external_admin_csr_path" location
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
        if tag == 'ssl_server' and self.san_inject:
            cert.san_for_server_cert = \
                self.mdict['pki_san_for_server_cert']
        return cert

    def retrieve_existing_server_cert(self, cfg_file):
        cs_cfg = PKIConfigParser.read_simple_configuration_file(cfg_file)
        cstype = cs_cfg.get('cs.type').lower()
        cert = pki.system.SystemCertData()
        cert.tag = self.mdict["pki_ssl_server_tag"]
        cert.keyAlgorithm = self.mdict["pki_ssl_server_key_algorithm"]
        cert.keySize = self.mdict["pki_ssl_server_key_size"]
        cert.keyType = self.mdict["pki_ssl_server_key_type"]
        cert.nickname = cs_cfg.get(cstype + ".sslserver.nickname")
        cert.cert = cs_cfg.get(cstype + ".sslserver.cert")
        cert.request = cs_cfg.get(cstype + ".sslserver.certreq")
        cert.subjectDN = self.mdict["pki_ssl_server_subject_dn"]
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


class SystemCertificateVerifier:
    """ Verifies system certificates for a subsystem"""

    def __init__(self, instance=None, subsystem=None):
        self.instance = instance
        self.subsystem = subsystem

    def verify_certificate(self, cert_id=None):
        cmd = ['pki-server', 'subsystem-cert-validate',
               '-i', self.instance.name,
               self.subsystem]
        if cert_id is not None:
            cmd.append(cert_id)
        try:
            subprocess.check_output(
                cmd,
                stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            config.pki_log.error(
                "pki-server subsystem-cert-validate return code: " + str(e.returncode),
                extra=config.PKI_INDENTATION_LEVEL_2
            )
            config.pki_log.error(
                e.output,
                extra=config.PKI_INDENTATION_LEVEL_2)
            raise


class PKIDeployer:
    """Holds the global dictionaries and the utility objects"""

    def __init__(self):
        # Global dictionary variables
        self.mdict = {}
        self.slots = {}
        self.main_config = None
        self.user_config = None
        self.manifest_db = []

        self.identity = None
        self.namespace = None
        self.configuration_file = None
        self.instance = None
        self.directory = None
        self.file = None
        self.symlink = None
        self.war = None
        self.password = None
        self.hsm = None
        self.certutil = None
        self.modutil = None
        self.pk12util = None
        self.kra_connector = None
        self.security_domain = None
        self.servercertnick_conf = None
        self.systemd = None
        self.tps_connector = None
        self.config_client = None

    def init(self):
        # Utility objects
        self.identity = Identity(self)
        self.namespace = Namespace(self)
        self.configuration_file = ConfigurationFile(self)
        self.instance = Instance(self)
        self.directory = Directory(self)
        self.file = File(self)
        self.symlink = Symlink(self)
        self.war = War(self)
        self.password = Password(self)
        self.hsm = HSM(self)
        self.certutil = Certutil(self)
        self.modutil = Modutil(self)
        self.pk12util = PK12util(self)
        self.kra_connector = KRAConnector(self)
        self.security_domain = SecurityDomain(self)
        self.servercertnick_conf = ServerCertNickConf(self)
        self.systemd = Systemd(self)
        self.tps_connector = TPSConnector(self)
        self.config_client = ConfigClient(self)

    def deploy_webapp(self, name, doc_base, descriptor):
        """
        Deploy a web application into a Tomcat instance.

        This method will copy the specified deployment descriptor into
        <instance>/conf/Catalina/localhost/<name>.xml and point the docBase
        to the specified location. The web application will become available
        under "/<name>" URL path.

        See also: http://tomcat.apache.org/tomcat-7.0-doc/config/context.html

        :param name: Web application name.
        :type name: str
        :param doc_base: Path to web application content.
        :type doc_base: str
        :param descriptor: Path to deployment descriptor (context.xml).
        :type descriptor: str
        """
        new_descriptor = os.path.join(
            self.mdict['pki_instance_configuration_path'],
            "Catalina",
            "localhost",
            name + ".xml")

        parser = etree.XMLParser(remove_blank_text=True)
        document = etree.parse(descriptor, parser)

        context = document.getroot()
        context.set('docBase', doc_base)

        with open(new_descriptor, 'wb') as f:
            # xml as UTF-8 encoded bytes
            document.write(f, pretty_print=True, encoding='utf-8')

        os.chown(new_descriptor, self.mdict['pki_uid'], self.mdict['pki_gid'])
        os.chmod(
            new_descriptor,
            config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS)

    @staticmethod
    def create_system_cert_verifier(instance=None, subsystem=None):
        return SystemCertificateVerifier(instance, subsystem)
