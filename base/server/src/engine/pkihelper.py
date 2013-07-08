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
import errno
import sys
import os
import fileinput
import random
import re
import requests
import shutil
from shutil import Error, WindowsError
import string
import subprocess
import time
import types
from datetime import datetime
from grp import getgrgid
from grp import getgrnam
from pwd import getpwnam
from pwd import getpwuid
import xml.etree.ElementTree as ET
import zipfile
import selinux
if selinux.is_selinux_enabled():
    import seobject


# PKI Deployment Imports
from . import pkiconfig as config
from .pkiconfig import pki_selinux_config_ports as ports
from . import pkimanifest as manifest
from . import pkimessages as log
from .pkiparser import PKIConfigParser
import pki.account
import pki.client
import pki.system

# PKI Deployment Helper Functions
def pki_copytree(src, dst, symlinks=False, ignore=None):
    """Recursively copy a directory tree using copy2().

    PATCH:  This code was copied from 'shutil.py' and patched to
            allow 'The destination directory to already exist.'

    If exception(s) occur, an Error is raised with a list of reasons.

    If the optional symlinks flag is true, symbolic links in the
    source tree result in symbolic links in the destination tree; if
    it is false, the contents of the files pointed to by symbolic
    links are copied.

    The optional ignore argument is a callable. If given, it
    is called with the `src` parameter, which is the directory
    being visited by pki_copytree(), and `names` which is the list of
    `src` contents, as returned by os.listdir():

        callable(src, names) -> ignored_names

    Since pki_copytree() is called recursively, the callable will be
    called once for each directory that is copied. It returns a
    list of names relative to the `src` directory that should
    not be copied.

    *** Consider this example code rather than the ultimate tool.

    """
    names = os.listdir(src)
    if ignore is not None:
        ignored_names = ignore(src, names)
    else:
        ignored_names = set()

    # PATCH:  ONLY execute 'os.makedirs(dst)' if the top-level
    #         destination directory does NOT exist!
    if not os.path.exists(dst):
        os.makedirs(dst)
    errors = []
    for name in names:
        if name in ignored_names:
            continue
        srcname = os.path.join(src, name)
        dstname = os.path.join(dst, name)
        try:
            if symlinks and os.path.islink(srcname):
                linkto = os.readlink(srcname)
                os.symlink(linkto, dstname)
            elif os.path.isdir(srcname):
                pki_copytree(srcname, dstname, symlinks, ignore)
            else:
                # Will raise a SpecialFileError for unsupported file types
                shutil.copy2(srcname, dstname)
        # catch the Error from the recursive pki_copytree so that we can
        # continue with other files
        except Error, err:
            errors.extend(err.args[0])
        except EnvironmentError, why:
            errors.append((srcname, dstname, str(why)))
    try:
        shutil.copystat(src, dst)
    except OSError, why:
        if WindowsError is not None and isinstance(why, WindowsError):
            # Copying file access times may fail on Windows
            pass
        else:
            errors.extend((src, dst, str(why)))
    if errors:
        raise Error, errors

class Identity:
    """PKI Deployment Identity Class"""

    def __init__(self, deployer):
        self.master_dict = deployer.master_dict

    def __add_gid(self, pki_group):
        pki_gid = None
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
                command = "/usr/sbin/groupadd" + " " + \
                          pki_group + " " + \
                          "> /dev/null 2>&1"
            except KeyError as exc:
                # No, the default well-known GID does not exist!
                config.pki_log.debug(log.PKIHELPER_GROUP_ADD_GID_KEYERROR_1,
                                     exc, extra=config.PKI_INDENTATION_LEVEL_2)
                # Is the specified 'pki_group' the default well-known group?
                if pki_group == config.PKI_DEPLOYMENT_DEFAULT_GROUP:
                    # Yes, attempt to create the default well-known group
                    # using the default well-known GID.
                    command = "/usr/sbin/groupadd" + " " + \
                              "-g" + " " + \
                              str(config.PKI_DEPLOYMENT_DEFAULT_GID) + " " + \
                              "-r" + " " + \
                              pki_group + " " + \
                              "> /dev/null 2>&1"
                else:
                    # No, attempt to create 'pki_group' using a random GID.
                    command = "/usr/sbin/groupadd" + " " + \
                              pki_group + " " + \
                              "> /dev/null 2>&1"
            # Execute this "groupadd" command.
            subprocess.call(command, shell=True)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            raise
        return

    def __add_uid(self, pki_user, pki_group):
        pki_uid = None
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
                command = "/usr/sbin/useradd" + " " + \
                          "-g" + " " + \
                          pki_group + " " + \
                          "-d" + " " + \
                          config.PKI_DEPLOYMENT_SOURCE_ROOT + " " + \
                          "-s" + " " + \
                          config.PKI_DEPLOYMENT_DEFAULT_SHELL + " " + \
                          "-c" + " " + \
                          config.PKI_DEPLOYMENT_DEFAULT_COMMENT + " " + \
                          pki_user + " " + \
                          "> /dev/null 2>&1"
            except KeyError as exc:
                # No, the default well-known UID does not exist!
                config.pki_log.debug(log.PKIHELPER_USER_ADD_UID_KEYERROR_1,
                                     exc, extra=config.PKI_INDENTATION_LEVEL_2)
                # Is the specified 'pki_user' the default well-known user?
                if pki_user == config.PKI_DEPLOYMENT_DEFAULT_USER:
                    # Yes, attempt to create the default well-known user
                    # using the default well-known UID.
                    command = "/usr/sbin/useradd" + " " + \
                              "-g" + " " + \
                              pki_group + " " + \
                              "-d" + " " + \
                              config.PKI_DEPLOYMENT_SOURCE_ROOT + " " + \
                              "-s" + " " + \
                              config.PKI_DEPLOYMENT_DEFAULT_SHELL + " " + \
                              "-c" + " " + \
                              config.PKI_DEPLOYMENT_DEFAULT_COMMENT + " " + \
                              "-u" + " " + \
                              str(config.PKI_DEPLOYMENT_DEFAULT_UID) + " " + \
                              "-r" + " " + \
                              pki_user + " " + \
                              "> /dev/null 2>&1"
                else:
                    # No, attempt to create 'pki_user' using a random UID.
                    command = "/usr/sbin/useradd" + " " + \
                              "-g" + " " + \
                              pki_group + " " + \
                              "-d" + " " + \
                              config.PKI_DEPLOYMENT_SOURCE_ROOT + " " + \
                              "-s" + " " + \
                              config.PKI_DEPLOYMENT_DEFAULT_SHELL + " " + \
                              "-c" + " " + \
                              config.PKI_DEPLOYMENT_DEFAULT_COMMENT + " " + \
                              pki_user + " " + \
                              "> /dev/null 2>&1"
            # Execute this "useradd" command.
            subprocess.call(command, shell=True)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            raise
        return

    def add_uid_and_gid(self, pki_user, pki_group):
        self.__add_gid(pki_group)
        self.__add_uid(pki_user, pki_group)
        return

    def get_uid(self, critical_failure=True):
        try:
            pki_uid = self.master_dict['pki_uid']
        except KeyError as exc:
            config.pki_log.error(log.PKI_KEYERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        return pki_uid

    def get_gid(self, critical_failure=True):
        try:
            pki_gid = self.master_dict['pki_gid']
        except KeyError as exc:
            config.pki_log.error(log.PKI_KEYERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        return pki_gid

    def set_uid(self, name, critical_failure=True):
        try:
            config.pki_log.debug(log.PKIHELPER_USER_1, name,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            # id -u <name>
            pki_uid = getpwnam(name)[2]
            self.master_dict['pki_uid'] = pki_uid
            config.pki_log.debug(log.PKIHELPER_UID_2, name, pki_uid,
                                 extra=config.PKI_INDENTATION_LEVEL_3)
        except KeyError as exc:
            config.pki_log.error(log.PKI_KEYERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        return pki_uid

    def set_gid(self, name, critical_failure=True):
        try:
            config.pki_log.debug(log.PKIHELPER_GROUP_1, name,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            # id -g <name>
            pki_gid = getgrnam(name)[2]
            self.master_dict['pki_gid'] = pki_gid
            config.pki_log.debug(log.PKIHELPER_GID_2, name, pki_gid,
                                 extra=config.PKI_INDENTATION_LEVEL_3)
        except KeyError as exc:
            config.pki_log.error(log.PKI_KEYERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        return pki_gid

class Namespace:
    """PKI Deployment Namespace Class"""

    # Silently verify that the selected 'pki_instance_name' will
    # NOT produce any namespace collisions
    def __init__(self, deployer):
        self.master_dict = deployer.master_dict

    def collision_detection(self):
        # Run simple checks for pre-existing namespace collisions
        if os.path.exists(self.master_dict['pki_instance_path']):
            if os.path.exists(self.master_dict['pki_subsystem_path']):
                # Top-Level PKI base path collision
                config.pki_log.error(
                    log.PKIHELPER_NAMESPACE_COLLISION_2,
                    self.master_dict['pki_instance_name'],
                    self.master_dict['pki_instance_path'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_NAMESPACE_COLLISION_2 % (self.master_dict['pki_instance_name'],
                                                                       self.master_dict['pki_instance_path']))
        else:
            if os.path.exists(self.master_dict['pki_target_tomcat_conf_instance_id']):
                # Top-Level "/etc/sysconfig" path collision
                config.pki_log.error(
                    log.PKIHELPER_NAMESPACE_COLLISION_2,
                    self.master_dict['pki_instance_name'],
                    self.master_dict['pki_target_tomcat_conf_instance_id'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_NAMESPACE_COLLISION_2 % (self.master_dict['pki_instance_name'],
                                                                       self.master_dict['pki_target_tomcat_conf_instance_id']))
            if os.path.exists(self.master_dict['pki_cgroup_systemd_service']):
                # Systemd cgroup path collision
                config.pki_log.error(
                    log.PKIHELPER_NAMESPACE_COLLISION_2,
                    self.master_dict['pki_instance_name'],
                    self.master_dict['pki_cgroup_systemd_service_path'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_NAMESPACE_COLLISION_2 % (self.master_dict['pki_instance_name'],
                                                                       self.master_dict['pki_cgroup_systemd_service_path']))
            if os.path.exists(self.master_dict['pki_cgroup_cpu_systemd_service']):
                # Systemd cgroup CPU path collision
                config.pki_log.error(
                    log.PKIHELPER_NAMESPACE_COLLISION_2,
                    self.master_dict['pki_instance_name'],
                    self.master_dict['pki_cgroup_cpu_systemd_service_path'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_NAMESPACE_COLLISION_2 % (self.master_dict['pki_instance_name'],
                                                                       self.master_dict['pki_cgroup_cpu_systemd_service_path']))
        if os.path.exists(self.master_dict['pki_instance_log_path']) and\
           os.path.exists(self.master_dict['pki_subsystem_log_path']):
            # Top-Level PKI log path collision
            config.pki_log.error(
                log.PKIHELPER_NAMESPACE_COLLISION_2,
                self.master_dict['pki_instance_name'],
                self.master_dict['pki_instance_log_path'],
                extra=config.PKI_INDENTATION_LEVEL_2)
            raise Exception(log.PKIHELPER_NAMESPACE_COLLISION_2 % (self.master_dict['pki_instance_name'],
                                                                  self.master_dict['pki_instance_log_path']))
        if os.path.exists(self.master_dict['pki_instance_configuration_path']) and\
           os.path.exists(self.master_dict['pki_subsystem_configuration_path']):
            # Top-Level PKI configuration path collision
            config.pki_log.error(
                log.PKIHELPER_NAMESPACE_COLLISION_2,
                self.master_dict['pki_instance_name'],
                self.master_dict['pki_instance_configuration_path'],
                extra=config.PKI_INDENTATION_LEVEL_2)
            raise Exception(log.PKIHELPER_NAMESPACE_COLLISION_2 % (self.master_dict['pki_instance_name'],
                                                                  self.master_dict['pki_instance_configuration_path']))
        if os.path.exists(self.master_dict['pki_instance_registry_path']) and\
           os.path.exists(self.master_dict['pki_subsystem_registry_path']):
            # Top-Level PKI registry path collision
            config.pki_log.error(
                log.PKIHELPER_NAMESPACE_COLLISION_2,
                self.master_dict['pki_instance_name'],
                self.master_dict['pki_instance_registry_path'],
                extra=config.PKI_INDENTATION_LEVEL_2)
            raise Exception(log.PKIHELPER_NAMESPACE_COLLISION_2 % (self.master_dict['pki_instance_name'],
                                                                  self.master_dict['pki_instance_registry_path']))
        # Run simple checks for reserved name namespace collisions
        if self.master_dict['pki_instance_name'] in config.PKI_BASE_RESERVED_NAMES:
            # Top-Level PKI base path reserved name collision
            config.pki_log.error(
                log.PKIHELPER_NAMESPACE_RESERVED_NAME_2,
                self.master_dict['pki_instance_name'],
                self.master_dict['pki_instance_path'],
                extra=config.PKI_INDENTATION_LEVEL_2)
            raise Exception(log.PKIHELPER_NAMESPACE_RESERVED_NAME_2 % (self.master_dict['pki_instance_name'],
                                                                      self.master_dict['pki_instance_path']))
        # No need to check for reserved name under Top-Level PKI log path
        if self.master_dict['pki_instance_name'] in config.PKI_CONFIGURATION_RESERVED_NAMES:
            # Top-Level PKI configuration path reserved name collision
            config.pki_log.error(
                log.PKIHELPER_NAMESPACE_RESERVED_NAME_2,
                self.master_dict['pki_instance_name'],
                self.master_dict['pki_instance_configuration_path'],
                extra=config.PKI_INDENTATION_LEVEL_2)
            raise Exception(log.PKIHELPER_NAMESPACE_RESERVED_NAME_2 % (self.master_dict['pki_instance_name'],
                                                                      self.master_dict['pki_instance_configuration_path']))
        if self.master_dict['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS:
            # Top-Level Apache PKI registry path reserved name collision
            if self.master_dict['pki_instance_name'] in\
               config.PKI_APACHE_REGISTRY_RESERVED_NAMES:
                config.pki_log.error(
                    log.PKIHELPER_NAMESPACE_RESERVED_NAME_2,
                    self.master_dict['pki_instance_name'],
                    self.master_dict['pki_instance_registry_path'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_NAMESPACE_RESERVED_NAME_2 % (self.master_dict['pki_instance_name'],
                                                                          self.master_dict['pki_instance_registry_path']))
        elif self.master_dict['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            # Top-Level Tomcat PKI registry path reserved name collision
            if self.master_dict['pki_instance_name'] in\
               config.PKI_TOMCAT_REGISTRY_RESERVED_NAMES:
                config.pki_log.error(
                    log.PKIHELPER_NAMESPACE_RESERVED_NAME_2,
                    self.master_dict['pki_instance_name'],
                    self.master_dict['pki_instance_registry_path'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_NAMESPACE_RESERVED_NAME_2 % (self.master_dict['pki_instance_name'],
                                                                          self.master_dict['pki_instance_registry_path']))


class ConfigurationFile:
    """PKI Deployment Configuration File Class"""

    def __init__(self, deployer):
        self.master_dict = deployer.master_dict

    def log_configuration_url(self):
        # NOTE:  This is the one and only parameter containing a sensitive
        #        parameter that may be stored in a log file.
        config.pki_log.info(log.PKI_CONFIGURATION_WIZARD_URL_1,
                            self.master_dict['pki_configuration_url'],
                            extra=config.PKI_INDENTATION_LEVEL_2)
        config.pki_log.info(log.PKI_CONFIGURATION_WIZARD_RESTART_1,
                            self.master_dict['pki_registry_initscript_command'],
                            extra=config.PKI_INDENTATION_LEVEL_2)

    def display_configuration_url(self):
        # NOTE:  This is the one and only parameter containing a sensitive
        #        parameter that may be displayed to the screen.
        print log.PKI_CONFIGURATION_URL_1 % self.master_dict['pki_configuration_url']
        print
        print log.PKI_CONFIGURATION_RESTART_1 % \
              self.master_dict['pki_registry_initscript_command']
        print

    def verify_sensitive_data(self):
        # Silently verify the existence of 'sensitive' data
        if self.master_dict['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            # Verify existence of Directory Server Password (ALWAYS)
            if not self.master_dict.has_key('pki_ds_password') or\
               not len(self.master_dict['pki_ds_password']):
                config.pki_log.error(
                    log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                    "pki_ds_password",
                    self.master_dict['pki_user_deployment_cfg'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 % ("pki_ds_password",
                                                                                     self.master_dict['pki_user_deployment_cfg']))
            # Verify existence of Admin Password (except for Clones)
            if not config.str2bool(self.master_dict['pki_clone']):
                if not self.master_dict.has_key('pki_admin_password') or\
                   not len(self.master_dict['pki_admin_password']):
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_admin_password",
                        self.master_dict['pki_user_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 % ("pki_admin_password",
                                                                                         self.master_dict['pki_user_deployment_cfg']))
            # If required, verify existence of Backup Password
            if config.str2bool(self.master_dict['pki_backup_keys']):
                if not self.master_dict.has_key('pki_backup_password') or\
                   not len(self.master_dict['pki_backup_password']):
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_backup_password",
                        self.master_dict['pki_user_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 % ("pki_backup_password",
                                                                                         self.master_dict['pki_user_deployment_cfg']))
            # Verify existence of Client Pin for NSS client security databases
            if not self.master_dict.has_key('pki_client_database_password') or\
               not len(self.master_dict['pki_client_database_password']):
                config.pki_log.error(
                    log.PKIHELPER_UNDEFINED_CLIENT_DATABASE_PASSWORD_2,
                    "pki_client_database_password",
                    self.master_dict['pki_user_deployment_cfg'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_UNDEFINED_CLIENT_DATABASE_PASSWORD_2 % ("pki_client_database_password",
                                                                                     self.master_dict['pki_user_deployment_cfg']))
            # Verify existence of Client PKCS #12 Password for Admin Cert
            if not self.master_dict.has_key('pki_client_pkcs12_password') or\
               not len(self.master_dict['pki_client_pkcs12_password']):
                config.pki_log.error(
                    log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                    "pki_client_pkcs12_password",
                    self.master_dict['pki_user_deployment_cfg'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 % ("pki_client_pkcs12_password",
                                                                                     self.master_dict['pki_user_deployment_cfg']))
            # Verify existence of PKCS #12 Password (ONLY for Clones)
            if config.str2bool(self.master_dict['pki_clone']):
                if not self.master_dict.has_key('pki_clone_pkcs12_password') or\
                   not len(self.master_dict['pki_clone_pkcs12_password']):
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_clone_pkcs12_password",
                        self.master_dict['pki_user_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 % ("pki_clone_pkcs12_password",
                                                                                         self.master_dict['pki_user_deployment_cfg']))
            # Verify existence of Security Domain Password File
            # (ONLY for Clones, KRA, OCSP, TKS, TPS, or Subordinate CA)
            if config.str2bool(self.master_dict['pki_clone']) or\
               not self.master_dict['pki_subsystem'] == "CA" or\
               config.str2bool(self.master_dict['pki_subordinate']):
                if not self.master_dict.has_key('pki_security_domain_password') or\
                   not len(self.master_dict['pki_security_domain_password']):
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_security_domain_password",
                        self.master_dict['pki_user_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 % ("pki_security_domain_password",
                                                                                          self.master_dict['pki_user_deployment_cfg']))
            # If required, verify existence of Token Password
            if not self.master_dict['pki_token_name'] == "internal":
                if not self.master_dict.has_key('pki_token_password') or\
                   not len(self.master_dict['pki_token_password']):
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_token_password",
                        self.master_dict['pki_user_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 % ("pki_token_password",
                                                                                         self.master_dict['pki_user_deployment_cfg']))
        return

    def verify_mutually_exclusive_data(self):
        # Silently verify the existence of 'mutually exclusive' data
        if self.master_dict['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            if self.master_dict['pki_subsystem'] == "CA":
                if config.str2bool(self.master_dict['pki_clone']) and\
                   config.str2bool(self.master_dict['pki_external']) and\
                   config.str2bool(self.master_dict['pki_subordinate']):
                    config.pki_log.error(
                        log.PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_EXTERNAL_SUB_CA,
                        self.master_dict['pki_user_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(log.PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_EXTERNAL_SUB_CA % self.master_dict['pki_user_deployment_cfg'])
                elif config.str2bool(self.master_dict['pki_clone']) and\
                     config.str2bool(self.master_dict['pki_external']):
                    config.pki_log.error(
                        log.PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_EXTERNAL_CA,
                        self.master_dict['pki_user_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(log.PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_EXTERNAL_CA % self.master_dict['pki_user_deployment_cfg'])
                elif config.str2bool(self.master_dict['pki_clone']) and\
                     config.str2bool(self.master_dict['pki_subordinate']):
                    config.pki_log.error(
                        log.PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_SUB_CA,
                        self.master_dict['pki_user_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(log.PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_SUB_CA % self.master_dict['pki_user_deployment_cfg'])
                elif config.str2bool(self.master_dict['pki_external']) and\
                     config.str2bool(self.master_dict['pki_subordinate']):
                    config.pki_log.error(
                        log.PKIHELPER_MUTUALLY_EXCLUSIVE_EXTERNAL_SUB_CA,
                        self.master_dict['pki_user_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(log.PKIHELPER_MUTUALLY_EXCLUSIVE_EXTERNAL_SUB_CA % self.master_dict['pki_user_deployment_cfg'])

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
        if self.master_dict['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            if config.str2bool(self.master_dict['pki_clone']):
                # Verify existence of clone parameters
                if not self.master_dict.has_key('pki_ds_base_dn') or\
                   not len(self.master_dict['pki_ds_base_dn']):
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_ds_base_dn",
                        self.master_dict['pki_user_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 % ("pki_ds_base_dn",
                                                                                         self.master_dict['pki_user_deployment_cfg']))
                if not self.master_dict.has_key('pki_ds_ldap_port') or\
                   not len(self.master_dict['pki_ds_ldap_port']):
                    # FUTURE:  Check for unused port value
                    #          (e. g. - must be different from master if the
                    #                   master is located on the same host)
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_ds_ldap_port",
                        self.master_dict['pki_user_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 % ("pki_ds_ldap_port",
                                                                                         self.master_dict['pki_user_deployment_cfg']))
                if not self.master_dict.has_key('pki_ds_ldaps_port') or\
                   not len(self.master_dict['pki_ds_ldaps_port']):
                    # FUTURE:  Check for unused port value
                    #          (e. g. - must be different from master if the
                    #                   master is located on the same host)
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_ds_ldaps_port",
                        self.master_dict['pki_user_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 % ("pki_ds_ldaps_port",
                                                                                         self.master_dict['pki_user_deployment_cfg']))
                # NOTE:  Although this will be checked prior to getting to
                #        this method, this clone's 'pki_instance_name' MUST
                #        be different from the master's 'pki_instance_name'
                #        IF AND ONLY IF the master and clone are located on
                #        the same host!
                if not self.master_dict.has_key('pki_ajp_port') or\
                   not len(self.master_dict['pki_ajp_port']):
                    # FUTURE:  Check for unused port value
                    #          (e. g. - must be different from master if the
                    #                   master is located on the same host)
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_ajp_port",
                        self.master_dict['pki_user_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 % ("pki_ajp_port",
                                                                                         self.master_dict['pki_user_deployment_cfg']))
                if not self.master_dict.has_key('pki_http_port') or\
                   not len(self.master_dict['pki_http_port']):
                    # FUTURE:  Check for unused port value
                    #          (e. g. - must be different from master if the
                    #                   master is located on the same host)
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_http_port",
                        self.master_dict['pki_user_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 % ("pki_http_port",
                                                                                         self.master_dict['pki_user_deployment_cfg']))
                if not self.master_dict.has_key('pki_https_port') or\
                   not len(self.master_dict['pki_https_port']):
                    # FUTURE:  Check for unused port value
                    #          (e. g. - must be different from master if the
                    #                   master is located on the same host)
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_https_port",
                        self.master_dict['pki_user_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 % ("pki_https_port",
                                                                                         self.master_dict['pki_user_deployment_cfg']))
                if not self.master_dict.has_key('pki_tomcat_server_port') or\
                   not len(self.master_dict['pki_tomcat_server_port']):
                    # FUTURE:  Check for unused port value
                    #          (e. g. - must be different from master if the
                    #                   master is located on the same host)
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_tomcat_server_port",
                        self.master_dict['pki_user_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 % ("pki_tomcat_server_port",
                                                                                         self.master_dict['pki_user_deployment_cfg']))
                if not self.master_dict.has_key('pki_clone_pkcs12_path') or\
                   not len(self.master_dict['pki_clone_pkcs12_path']):
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_clone_pkcs12_path",
                        self.master_dict['pki_user_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 % ("pki_clone_pkcs12_path",
                                                                                         self.master_dict['pki_user_deployment_cfg']))
                elif not os.path.isfile(self.master_dict['pki_clone_pkcs12_path']):
                    config.pki_log.error(
                        log.PKI_FILE_ALREADY_EXISTS_NOT_A_FILE_1,
                        self.master_dict['pki_clone_pkcs12_path'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(log.PKI_FILE_ALREADY_EXISTS_NOT_A_FILE_1 % "pki_clone_pkcs12_path")
                if not self.master_dict.has_key('pki_clone_replication_security') or\
                   not len(self.master_dict['pki_clone_replication_security']):
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_clone_replication_security",
                        self.master_dict['pki_user_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 % ("pki_clone_replication_security",
                                                                                         self.master_dict['pki_user_deployment_cfg']))
                if not self.master_dict.has_key('pki_clone_uri') or\
                   not len(self.master_dict['pki_clone_uri']):
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_clone_uri",
                        self.master_dict['pki_user_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 % ("pki_clone_uri",
                                                                                         self.master_dict['pki_user_deployment_cfg']))
            elif self.master_dict['pki_subsystem'] == "CA" and\
                 config.str2bool(self.master_dict['pki_external']):
                if not self.master_dict.has_key('pki_external_step_two') or\
                   not len(self.master_dict['pki_external_step_two']):
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_external_step_two",
                        self.master_dict['pki_user_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 % ("pki_extrenal_step_two",
                                                                                          self.master_dict['pki_user_deployment_cfg']))
                if not config.str2bool(self.master_dict['pki_external_step_two']):
                    # External CA (Step 1)
                    if not self.master_dict.has_key('pki_external_csr_path') or\
                       not len(self.master_dict['pki_external_csr_path']):
                        config.pki_log.error(
                            log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                            "pki_external_csr_path",
                            self.master_dict['pki_user_deployment_cfg'],
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        raise Exception(log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 % ("pki_extrenal_csr_path",
                                                                                              self.master_dict['pki_user_deployment_cfg']))
                    elif os.path.exists(self.master_dict['pki_external_csr_path']) and\
                         not os.path.isfile(self.master_dict['pki_external_csr_path']):
                        config.pki_log.error(
                            log.PKI_FILE_ALREADY_EXISTS_NOT_A_FILE_1,
                            self.master_dict['pki_external_csr_path'],
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        raise Exception(log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 % "pki_extrenal_csr_path")
                else:
                    # External CA (Step 2)
                    if not self.master_dict.has_key('pki_external_ca_cert_chain_path') or\
                       not len(self.master_dict['pki_external_ca_cert_chain_path']):
                        config.pki_log.error(
                            log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                            "pki_external_ca_cert_chain_path",
                            self.master_dict['pki_user_deployment_cfg'],
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        raise Exception(log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 % ("pki_extrenal_ca_cert_chain_path",
                                                                                              self.master_dict['pki_user_deployment_cfg']))
                    elif os.path.exists(
                                 self.master_dict['pki_external_ca_cert_chain_path']) and\
                         not os.path.isfile(
                                 self.master_dict['pki_external_ca_cert_chain_path']):
                        config.pki_log.error(
                            log.PKI_FILE_ALREADY_EXISTS_NOT_A_FILE_1,
                            self.master_dict['pki_external_ca_cert_chain_path'],
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        raise Exception(log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 % "pki_extrenal_ca_cert_chain_path")
                    if not self.master_dict.has_key('pki_external_ca_cert_path') or\
                       not len(self.master_dict['pki_external_ca_cert_path']):
                        config.pki_log.error(
                            log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                            "pki_external_ca_cert_path",
                            self.master_dict['pki_user_deployment_cfg'],
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        raise Exception(log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 % ("pki_extrenal_ca_cert_path",
                                                                                              self.master_dict['pki_user_deployment_cfg']))
                    elif os.path.exists(self.master_dict['pki_external_ca_cert_path']) and\
                         not os.path.isfile(
                                 self.master_dict['pki_external_ca_cert_path']):
                        config.pki_log.error(
                            log.PKI_FILE_ALREADY_EXISTS_NOT_A_FILE_1,
                            self.master_dict['pki_external_ca_cert_path'],
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        raise Exception(log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 % "pki_extrenal_ca_cert_path")
        return

    def populate_non_default_ports(self):
        if (self.master_dict['pki_http_port'] !=
            str(config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_HTTP_PORT)):
            ports.append(self.master_dict['pki_http_port'])
        if (self.master_dict['pki_https_port'] !=
            str(config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_HTTPS_PORT)):
            ports.append(self.master_dict['pki_https_port'])
        if (self.master_dict['pki_tomcat_server_port'] !=
            str(config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_SERVER_PORT)):
            ports.append(self.master_dict['pki_tomcat_server_port'])
        if (self.master_dict['pki_ajp_port'] !=
            str(config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_AJP_PORT)):
            ports.append(self.master_dict['pki_ajp_port'])
        return

    def verify_selinux_ports(self):
        # Determine which ports still need to be labelled, and if any are
        # incorrectly labelled
        if len(ports) == 0:
            return

        if not bool(selinux.is_selinux_enabled()):
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
                if i[0] <= int(port) and int(port) <= i[1]:
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
                raise Exception(log.PKIHELPER_INVALID_SELINUX_CONTEXT_FOR_PORT % (port, context))
        return

    def verify_command_matches_configuration_file(self):
        # Silently verify that the command-line parameters match the values
        # that are present in the corresponding configuration file
        if self.master_dict['pki_deployment_executable'] == 'pkidestroy':
            if self.master_dict['pki_deployed_instance_name'] != \
               self.master_dict['pki_instance_name']:
                config.pki_log.error(
                    log.PKIHELPER_COMMAND_LINE_PARAMETER_MISMATCH_2,
                    self.master_dict['pki_deployed_instance_name'],
                    self.master_dict['pki_instance_name'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2 % (self.master_dict['pki_deployed_instance_name'],
                                                                                      self.master_dict['pki_instance_name']))
        return

# PKI Deployment XML File Class
# class xml_file:
#    def remove_filter_section_from_web_xml(self,
#                                           web_xml_source,
#                                           web_xml_target):
#        config.pki_log.info(log.PKIHELPER_REMOVE_FILTER_SECTION_1,
#            self.master_dict['pki_target_subsystem_web_xml'],
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
        self.master_dict = deployer.master_dict

    def apache_instance_subsystems(self):
        rv = 0
        try:
            # count number of PKI subsystems present
            # within the specified Apache instance
            for subsystem in config.PKI_APACHE_SUBSYSTEMS:
                path = self.master_dict['pki_instance_path'] + "/" + subsystem.lower()
                if os.path.exists(path) and os.path.isdir(path):
                    rv = rv + 1
            config.pki_log.debug(log.PKIHELPER_APACHE_INSTANCE_SUBSYSTEMS_2,
                                 self.master_dict['pki_instance_path'],
                                 rv, extra=config.PKI_INDENTATION_LEVEL_2)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            raise
        return rv

    def apache_instances(self):
        rv = 0
        try:
            # Since ALL directories under the top-level PKI 'apache' registry
            # directory SHOULD represent PKI Apache instances, and there
            # shouldn't be any stray files or symbolic links at this level,
            # simply count the number of PKI 'apache' instances (directories)
            # present within the PKI 'apache' registry directory
            for instance in\
                os.listdir(self.master_dict['pki_instance_type_registry_path']):
                if os.path.isdir(
                       os.path.join(self.master_dict['pki_instance_type_registry_path'],
                       instance)) and not\
                   os.path.islink(
                       os.path.join(self.master_dict['pki_instance_type_registry_path'],
                       instance)):
                    rv = rv + 1
            config.pki_log.debug(log.PKIHELPER_APACHE_INSTANCES_2,
                                 self.master_dict['pki_instance_type_registry_path'],
                                 rv,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            raise
        return rv

    def pki_instance_subsystems(self):
        rv = 0
        try:
            # Since ALL directories within the top-level PKI infrastructure
            # SHOULD represent PKI instances, look for all possible
            # PKI instances within the top-level PKI infrastructure
            for instance in os.listdir(self.master_dict['pki_path']):
                if os.path.isdir(os.path.join(self.master_dict['pki_path'], instance))\
                   and not\
                   os.path.islink(os.path.join(self.master_dict['pki_path'], instance)):
                    instance_dir = os.path.join(self.master_dict['pki_path'], instance)
                    # Since ANY directory within this PKI instance COULD
                    # be a PKI subsystem, look for all possible
                    # PKI subsystems within this PKI instance
                    for name in os.listdir(instance_dir):
                        if os.path.isdir(os.path.join(instance_dir, name)) and\
                           not os.path.islink(os.path.join(instance_dir, name)):
                            if name.upper() in config.PKI_SUBSYSTEMS:
                                rv = rv + 1
            config.pki_log.debug(log.PKIHELPER_PKI_INSTANCE_SUBSYSTEMS_2,
                                 self.master_dict['pki_instance_path'], rv,
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
                path = self.master_dict['pki_instance_path'] + "/" + subsystem.lower()
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
            for instance in\
                os.listdir(self.master_dict['pki_instance_type_registry_path']):
                if os.path.isdir(
                       os.path.join(self.master_dict['pki_instance_type_registry_path'],
                       instance)) and not\
                   os.path.islink(
                       os.path.join(self.master_dict['pki_instance_type_registry_path'],
                       instance)):
                    rv = rv + 1
            config.pki_log.debug(log.PKIHELPER_TOMCAT_INSTANCES_2,
                                 self.master_dict['pki_instance_type_registry_path'],
                                 rv,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            raise
        return rv

    def verify_subsystem_exists(self):
        try:
            if not os.path.exists(self.master_dict['pki_subsystem_path']):
                config.pki_log.error(log.PKI_SUBSYSTEM_DOES_NOT_EXIST_2,
                                     self.master_dict['pki_subsystem'],
                                     self.master_dict['pki_instance_name'],
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKI_SUBSYSTEM_DOES_NOT_EXIST_2 % (self.master_dict['pki_subsystem'],
                                                                      self.master_dict['pki_instance_name']))
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            raise

    def verify_subsystem_does_not_exist(self):
        try:
            if os.path.exists(self.master_dict['pki_subsystem_path']):
                config.pki_log.error(log.PKI_SUBSYSTEM_ALREADY_EXISTS_2,
                                     self.master_dict['pki_subsystem'],
                                     self.master_dict['pki_instance_name'],
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKI_SUBSYSTEM_DOES_NOT_EXIST_2 % (self.master_dict['pki_subsystem'],
                                                                      self.master_dict['pki_instance_name']))
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            raise

    def get_instance_status(self):
        self.connection = pki.client.PKIConnection(
            protocol='https',
            hostname=self.master_dict['pki_hostname'],
            port=self.master_dict['pki_https_port'],
            subsystem=self.master_dict['pki_subsystem_type'],
            accept='application/xml')

        try:
            client = pki.system.SystemStatusClient(self.connection)
            response = client.getStatus()
            config.pki_log.debug(response,
                extra=config.PKI_INDENTATION_LEVEL_3)

            root = ET.fromstring(response)
            status = root.findtext("Status")
            return status
        except requests.exceptions.ConnectionError:
            config.pki_log.debug("No connection",
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
        self.master_dict = deployer.master_dict
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
                if uid == None:
                    uid = self.identity.get_uid()
                if gid == None:
                    gid = self.identity.get_gid()
                config.pki_log.debug(log.PKIHELPER_CHOWN_3,
                                     uid, gid, name,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
                os.chown(name, uid, gid)
                # Store record in installation manifest
                record = manifest.Record()
                record.name = name
                record.type = manifest.RECORD_TYPE_DIRECTORY
                record.user = self.master_dict['pki_user']
                record.group = self.master_dict['pki_group']
                record.uid = uid
                record.gid = gid
                record.permissions = perms
                record.acls = acls
                self.manifest_db.append(record)
            elif not os.path.isdir(name):
                config.pki_log.error(
                    log.PKI_DIRECTORY_ALREADY_EXISTS_NOT_A_DIRECTORY_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure == True:
                    raise Exception(log.PKI_DIRECTORY_ALREADY_EXISTS_NOT_A_DIRECTORY_1 % name)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                pass
            else:
                config.pki_log.error(log.PKI_OSERROR_1, exc,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure == True:
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
                    if critical_failure == True:
                        raise Exception(log.PKI_DIRECTORY_ALREADY_EXISTS_NOT_A_DIRECTORY_1 % name)
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
                if uid == None:
                    uid = self.identity.get_uid()
                if gid == None:
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
                    record.user = self.master_dict['pki_user']
                    record.group = self.master_dict['pki_group']
                    record.uid = uid
                    record.gid = gid
                    record.permissions = perms
                    record.acls = acls
                    self.manifest_db.append(record)
            else:
                config.pki_log.error(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure == True:
                    raise Exception(log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 % name)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
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
                if recursive_flag == True:
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
            if critical_failure == True:
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

    def set_mode(self, name, uid=None, gid=None,
                 dir_perms=config.PKI_DEPLOYMENT_DEFAULT_DIR_PERMISSIONS,
                 file_perms=config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS,
                 symlink_perms=\
                     config.PKI_DEPLOYMENT_DEFAULT_SYMLINK_PERMISSIONS,
                 dir_acls=None, file_acls=None, symlink_acls=None,
                 recursive_flag=True, critical_failure=True):
        try:
            if not os.path.exists(name) or not os.path.isdir(name):
                config.pki_log.error(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 % name)
            else:
                config.pki_log.info(
                    log.PKIHELPER_SET_MODE_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if uid == None:
                    uid = self.identity.get_uid()
                if gid == None:
                    gid = self.identity.get_gid()
                if recursive_flag == True:
                    for root, dirs, files in os.walk(name):
                        for name in files:
                            entity = os.path.join(root, name)
                            if not os.path.islink(entity):
                                temp_file = entity
                                config.pki_log.debug(
                                    log.PKIHELPER_IS_A_FILE_1, temp_file,
                                    extra=config.PKI_INDENTATION_LEVEL_3)
                                # chmod <file_perms> <name>
                                config.pki_log.debug(log.PKIHELPER_CHMOD_2,
                                    file_perms, temp_file,
                                    extra=config.PKI_INDENTATION_LEVEL_3)
                                os.chmod(temp_file, file_perms)
                                # chown <uid>:<gid> <name>
                                config.pki_log.debug(log.PKIHELPER_CHOWN_3,
                                    uid, gid, temp_file,
                                    extra=config.PKI_INDENTATION_LEVEL_3)
                                os.chown(temp_file, uid, gid)
                                # Store record in installation manifest
                                record = manifest.Record()
                                record.name = name
                                record.type = manifest.RECORD_TYPE_FILE
                                record.user = self.master_dict['pki_user']
                                record.group = self.master_dict['pki_group']
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
                                config.pki_log.debug(log.PKIHELPER_CHOWN_H_3,
                                    uid, gid, symlink,
                                    extra=config.PKI_INDENTATION_LEVEL_3)
                                os.lchown(symlink, uid, gid)
                                # Store record in installation manifest
                                record = manifest.Record()
                                record.name = name
                                record.type = manifest.RECORD_TYPE_SYMLINK
                                record.user = self.master_dict['pki_user']
                                record.group = self.master_dict['pki_group']
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
                            config.pki_log.debug(log.PKIHELPER_CHMOD_2,
                                dir_perms, temp_dir,
                                extra=config.PKI_INDENTATION_LEVEL_3)
                            os.chmod(temp_dir, dir_perms)
                            # chown <uid>:<gid> <name>
                            config.pki_log.debug(log.PKIHELPER_CHOWN_3,
                                uid, gid, temp_dir,
                                extra=config.PKI_INDENTATION_LEVEL_3)
                            os.chown(temp_dir, uid, gid)
                            # Store record in installation manifest
                            record = manifest.Record()
                            record.name = name
                            record.type = manifest.RECORD_TYPE_DIRECTORY
                            record.user = self.master_dict['pki_user']
                            record.group = self.master_dict['pki_group']
                            record.uid = uid
                            record.gid = gid
                            record.permissions = dir_perms
                            record.acls = dir_acls
                            self.manifest_db.append(record)
                else:
                    config.pki_log.debug(
                        log.PKIHELPER_IS_A_DIRECTORY_1, name,
                        extra=config.PKI_INDENTATION_LEVEL_3)
                    name = os.path.join(root, name)
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
                    record.user = self.master_dict['pki_user']
                    record.group = self.master_dict['pki_group']
                    record.uid = uid
                    record.gid = gid
                    record.permissions = dir_perms
                    record.acls = dir_acls
                    self.manifest_db.append(record)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise

    def copy(self, old_name, new_name, uid=None, gid=None,
             dir_perms=config.PKI_DEPLOYMENT_DEFAULT_DIR_PERMISSIONS,
             file_perms=config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS,
             symlink_perms=config.PKI_DEPLOYMENT_DEFAULT_SYMLINK_PERMISSIONS,
             dir_acls=None, file_acls=None, symlink_acls=None,
             recursive_flag=True, overwrite_flag=False, critical_failure=True):
        try:
            if not os.path.exists(old_name) or not os.path.isdir(old_name):
                config.pki_log.error(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, old_name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 % old_name)
            else:
                if os.path.exists(new_name):
                    if not overwrite_flag:
                        config.pki_log.error(
                            log.PKI_DIRECTORY_ALREADY_EXISTS_1, new_name,
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        raise Exception(log.PKI_DIRECTORY_ALREADY_EXISTS_1 % new_name)
                if recursive_flag == True:
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
                    pki_copytree(old_name, new_name)
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
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        except shutil.Error as exc:
            config.pki_log.error(log.PKI_SHUTIL_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        return

class File:
    """PKI Deployment File Class (also used for executables)"""

    def __init__(self, deployer):
        self.master_dict = deployer.master_dict
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
                if uid == None:
                    uid = self.identity.get_uid()
                if gid == None:
                    gid = self.identity.get_gid()
                config.pki_log.debug(log.PKIHELPER_CHOWN_3,
                                     uid, gid, name,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
                os.chown(name, uid, gid)
                # Store record in installation manifest
                record = manifest.Record()
                record.name = name
                record.type = manifest.RECORD_TYPE_FILE
                record.user = self.master_dict['pki_user']
                record.group = self.master_dict['pki_group']
                record.uid = uid
                record.gid = gid
                record.permissions = perms
                record.acls = acls
                self.manifest_db.append(record)
            elif not os.path.isfile(name):
                config.pki_log.error(
                    log.PKI_FILE_ALREADY_EXISTS_NOT_A_FILE_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure == True:
                    raise Exception(log.PKI_FILE_ALREADY_EXISTS_NOT_A_FILE_1 % name)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                pass
            else:
                config.pki_log.error(log.PKI_OSERROR_1, exc,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure == True:
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
                    if critical_failure == True:
                        raise Exception(log.PKI_FILE_ALREADY_EXISTS_NOT_A_FILE_1 % name)
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
                if uid == None:
                    uid = self.identity.get_uid()
                if gid == None:
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
                    record.user = self.master_dict['pki_user']
                    record.group = self.master_dict['pki_group']
                    record.uid = uid
                    record.gid = gid
                    record.permissions = perms
                    record.acls = acls
                    self.manifest_db.append(record)
            else:
                config.pki_log.error(
                    log.PKI_FILE_MISSING_OR_NOT_A_FILE_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure == True:
                    raise Exception(log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 % name)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
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
            if critical_failure == True:
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
                raise Exception(log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 % old_name)
            else:
                if os.path.exists(new_name):
                    if not overwrite_flag:
                        config.pki_log.error(
                            log.PKI_FILE_ALREADY_EXISTS_1, new_name,
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        raise Exception(log.PKI_FILE_ALREADY_EXISTS_1 % new_name)
                # cp -p <old_name> <new_name>
                config.pki_log.info(log.PKIHELPER_CP_P_2,
                                    old_name, new_name,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                shutil.copy2(old_name, new_name)
                if uid == None:
                    uid = self.identity.get_uid()
                if gid == None:
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
                record.user = self.master_dict['pki_user']
                record.group = self.master_dict['pki_group']
                record.uid = uid
                record.gid = gid
                record.permissions = perms
                record.acls = acls
                self.manifest_db.append(record)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        except shutil.Error as exc:
            config.pki_log.error(log.PKI_SHUTIL_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
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
                            self.slots[slot], self.master_dict[slot],
                            extra=config.PKI_INDENTATION_LEVEL_3)
                        line = line.replace(self.slots[slot], self.master_dict[slot])
                sys.stdout.write(line)
            if uid == None:
                uid = self.identity.get_uid()
            if gid == None:
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
            record.user = self.master_dict['pki_user']
            record.group = self.master_dict['pki_group']
            record.uid = uid
            record.gid = gid
            record.permissions = perms
            record.acls = acls
            self.manifest_db.append(record)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        except shutil.Error as exc:
            config.pki_log.error(log.PKI_SHUTIL_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        return

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
                raise Exception(log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 % old_name)
            else:
                if os.path.exists(new_name):
                    if not overwrite_flag:
                        config.pki_log.error(
                            log.PKI_FILE_ALREADY_EXISTS_1, new_name,
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        raise Exception(log.PKI_FILE_ALREADY_EXISTS_1 % new_name)
                # copy <old_name> to <new_name> with slot substitutions
                config.pki_log.info(log.PKIHELPER_COPY_WITH_SLOT_SUBSTITUTION_2,
                                    old_name, new_name,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                with open(new_name, "w") as FILE:
                    for line in fileinput.FileInput(old_name):
                        for slot in self.slots:
                            if slot != '__name__' and self.slots[slot] in line:
                                config.pki_log.debug(
                                    log.PKIHELPER_SLOT_SUBSTITUTION_2,
                                    self.slots[slot], self.master_dict[slot],
                                    extra=config.PKI_INDENTATION_LEVEL_3)
                                line = line.replace(self.slots[slot], self.master_dict[slot])
                        FILE.write(line)
                if uid == None:
                    uid = self.identity.get_uid()
                if gid == None:
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
                record.user = self.master_dict['pki_user']
                record.group = self.master_dict['pki_group']
                record.uid = uid
                record.gid = gid
                record.permissions = perms
                record.acls = acls
                self.manifest_db.append(record)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        except shutil.Error as exc:
            config.pki_log.error(log.PKI_SHUTIL_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        return

    def generate_noise_file(self, name, random_bytes, uid=None, gid=None,
            perms=config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS,
            acls=None, critical_failure=True):
        try:
            if not os.path.exists(name):
                # generating noise file called <name> and
                # filling it with <random_bytes> random bytes
                config.pki_log.info(log.PKIHELPER_NOISE_FILE_2, name, random_bytes,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                open(name, "w").close()
                with open(name, "w") as FILE:
                    noise = ''.join(random.choice(string.ascii_letters + \
                                    string.digits) for x in range(random_bytes))
                    FILE.write(noise)
                # chmod <perms> <name>
                config.pki_log.debug(log.PKIHELPER_CHMOD_2, perms, name,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
                os.chmod(name, perms)
                # chown <uid>:<gid> <name>
                if uid == None:
                    uid = self.identity.get_uid()
                if gid == None:
                    gid = self.identity.get_gid()
                config.pki_log.debug(log.PKIHELPER_CHOWN_3,
                                     uid, gid, name,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
                os.chown(name, uid, gid)
                # Store record in installation manifest
                record = manifest.Record()
                record.name = name
                record.type = manifest.RECORD_TYPE_FILE
                record.user = self.master_dict['pki_user']
                record.group = self.master_dict['pki_group']
                record.uid = uid
                record.gid = gid
                record.permissions = perms
                record.acls = acls
                self.manifest_db.append(record)
            elif not os.path.isfile(name):
                config.pki_log.error(
                    log.PKI_FILE_ALREADY_EXISTS_NOT_A_FILE_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure == True:
                    raise Exception(log.PKI_FILE_ALREADY_EXISTS_NOT_A_FILE_1 % name)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                pass
            else:
                config.pki_log.error(log.PKI_OSERROR_1, exc,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure == True:
                    raise
        return

class Symlink:
    """PKI Deployment Symbolic Link Class"""

    def __init__(self, deployer):
        self.master_dict = deployer.master_dict
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
                        raise Exception("Dangling symlink " + link + " not allowed")
                # ln -s <name> <link>
                config.pki_log.info(log.PKIHELPER_LINK_S_2, name, link,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                os.symlink(name, link)
                # REMINDER:  Due to POSIX compliance, 'lchmod' is NEVER
                #            implemented on Linux systems since 'chmod'
                #            CANNOT be run directly against symbolic links!
                # chown -h <uid>:<gid> <link>
                if uid == None:
                    uid = self.identity.get_uid()
                if gid == None:
                    gid = self.identity.get_gid()
                config.pki_log.debug(log.PKIHELPER_CHOWN_H_3,
                                     uid, gid, link,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
                os.lchown(link, uid, gid)
                # Store record in installation manifest
                record = manifest.Record()
                record.name = link
                record.type = manifest.RECORD_TYPE_SYMLINK
                record.user = self.master_dict['pki_user']
                record.group = self.master_dict['pki_group']
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
                if critical_failure == True:
                    raise Exception(log.PKI_SYMLINK_ALREADY_EXISTS_NOT_A_SYMLINK_1 % link)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                pass
            else:
                config.pki_log.error(log.PKI_OSERROR_1, exc,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure == True:
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
                    if critical_failure == True:
                        raise Exception(log.PKI_SYMLINK_ALREADY_EXISTS_NOT_A_SYMLINK_1 % link)
                # Always re-process each link whether it needs it or not
                if not silent:
                    config.pki_log.info(log.PKIHELPER_MODIFY_SYMLINK_1, link,
                                        extra=config.PKI_INDENTATION_LEVEL_2)
                # REMINDER:  Due to POSIX compliance, 'lchmod' is NEVER
                #            implemented on Linux systems since 'chmod'
                #            CANNOT be run directly against symbolic links!
                # chown -h <uid>:<gid> <link>
                if uid == None:
                    uid = self.identity.get_uid()
                if gid == None:
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
                    record.user = self.master_dict['pki_user']
                    record.group = self.master_dict['pki_group']
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
                if critical_failure == True:
                    raise Exception(log.PKI_SYMLINK_MISSING_OR_NOT_A_SYMLINK_1 % link)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
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
            if critical_failure == True:
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
        self.master_dict = deployer.master_dict

    def explode(self, name, path, critical_failure=True):
        try:
            if os.path.exists(name) and os.path.isfile(name):
                if not zipfile.is_zipfile(name):
                    config.pki_log.error(
                        log.PKI_FILE_NOT_A_WAR_FILE_1,
                        name, extra=config.PKI_INDENTATION_LEVEL_2)
                    if critical_failure == True:
                        raise Exception(log.PKI_FILE_NOT_A_WAR_FILE_1 % name)
                if not os.path.exists(path) or not os.path.isdir(path):
                    config.pki_log.error(
                        log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1,
                        path, extra=config.PKI_INDENTATION_LEVEL_2)
                    if critical_failure == True:
                        raise Exception(log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, path)
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
                if critical_failure == True:
                    raise Exception(log.PKI_FILE_MISSING_OR_NOT_A_FILE_1, name)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        except zipfile.BadZipfile as exc:
            config.pki_log.error(log.PKI_BADZIPFILE_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        except zipfile.LargeZipFile as exc:
            config.pki_log.error(log.PKI_LARGEZIPFILE_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        return

class Password:
    """PKI Deployment Password Class"""

    def __init__(self, deployer):
        self.master_dict = deployer.master_dict

    def create_password_conf(self, path, pin, pin_sans_token=False,
                             overwrite_flag=False, critical_failure=True):
        try:
            if os.path.exists(path):
                if overwrite_flag:
                    config.pki_log.info(
                        log.PKIHELPER_PASSWORD_CONF_1, path,
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    # overwrite the existing 'password.conf' file
                    with open(path, "wt") as fd:
                        if pin_sans_token == True:
                            fd.write(str(pin))
                        elif self.master_dict['pki_subsystem'] in\
                           config.PKI_APACHE_SUBSYSTEMS:
                            fd.write(self.master_dict['pki_self_signed_token'] + \
                                     ":" + str(pin))
                        else:
                            fd.write(self.master_dict['pki_self_signed_token'] + \
                                     "=" + str(pin))
            else:
                config.pki_log.info(log.PKIHELPER_PASSWORD_CONF_1, path,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                # create a new 'password.conf' file
                with open(path, "wt") as fd:
                    if pin_sans_token == True:
                        fd.write(str(pin))
                    elif self.master_dict['pki_subsystem'] in\
                       config.PKI_APACHE_SUBSYSTEMS:
                        fd.write(self.master_dict['pki_self_signed_token'] + \
                                 ":" + str(pin))
                    else:
                        fd.write(self.master_dict['pki_self_signed_token'] + \
                                 "=" + str(pin))
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
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
                    with open(path, "wt") as fd:
                        fd.write(self.master_dict['pki_client_pkcs12_password'])
            else:
                config.pki_log.info(log.PKIHELPER_PASSWORD_CONF_1, path,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                # create a new 'pkcs12_password.conf' file
                with open(path, "wt") as fd:
                    fd.write(self.master_dict['pki_client_pkcs12_password'])
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        return

    def get_password(self, path, token_name, critical_failure=True):
        if os.path.exists(path) and os.path.isfile(path) and\
           os.access(path, os.R_OK):
            tokens = PKIConfigParser.read_simple_configuration_file(path)
            hardware_token = "hardware-" + token_name
            if tokens.has_key(hardware_token):
                token_name = hardware_token
                token_pwd = tokens[hardware_token]
            elif tokens.has_key(token_name):
                token_pwd = tokens[token_name]

        if token_pwd is None or token_pwd == '':
            # TODO prompt for this password
            config.pki_log.error(log.PKIHELPER_PASSWORD_NOT_FOUND_1,
                                 token_name,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise Exception(log.PKIHELPER_PASSWORD_NOT_FOUND_1 % token_name)
            else:
                return
        return token_pwd

class Certutil:
    """PKI Deployment NSS 'certutil' Class"""

    def __init__(self, deployer):
        self.master_dict = deployer.master_dict

    def create_security_databases(self, path, pki_cert_database,
                                  pki_key_database, pki_secmod_database,
                                  password_file=None, prefix=None,
                                  critical_failure=True):
        try:
            # Compose this "certutil" command
            command = "certutil" + " " + "-N"
            #   Provide a path to the NSS security databases
            if path:
                command = command + " " + "-d" + " " + path
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_PATH,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_PATH)
            if password_file != None:
                command = command + " " + "-f" + " " + password_file
            if prefix != None:
                command = command + " " + "-P" + " " + prefix
            if not os.path.exists(path):
                config.pki_log.error(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, path,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 % path)
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
                if password_file != None:
                    if not os.path.exists(password_file) or\
                       not os.path.isfile(password_file):
                        config.pki_log.error(
                            log.PKI_FILE_MISSING_OR_NOT_A_FILE_1,
                            password_file,
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        raise Exception(log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 % password_file)
                # Display this "certutil" command
                config.pki_log.info(
                    log.PKIHELPER_CREATE_SECURITY_DATABASES_1,
                    command,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                # Execute this "certutil" command
                subprocess.call(command, shell=True)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        return

    def verify_certificate_exists(self, path, pki_cert_database,
                                  pki_key_database, pki_secmod_database,
                                  token, nickname, password_file=None,
                                  silent=True, critical_failure=True):
        try:
            # Compose this "certutil" command
            command = "certutil" + " " + "-L"
            #   Provide a path to the NSS security databases
            if path:
                command = command + " " + "-d" + " " + path
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_PATH,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_PATH)
            #   Specify the 'token'
            if token:
                command = command + " " + "-h" + " " + "'" + token + "'"
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_TOKEN,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_TOKEN)
            #   Specify the nickname of this self-signed certificate
            if nickname:
                command = command + " " + "-n" + " " + "'" + nickname + "'"
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_NICKNAME,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_NICKNAME)
            #   OPTIONALLY specify a password file
            if password_file != None:
                command = command + " " + "-f" + " " + password_file
            #   By default, execute this command silently
            if silent != False:
                command = command + " > /dev/null 2>&1"
            if not os.path.exists(path):
                config.pki_log.error(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, path,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 % path)
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
                raise Exception(log.PKI_SECURITY_DATABASES_DO_NOT_EXIST_3 % (pki_cert_database,
                                                                             pki_key_database, pki_secmod_database))
            if password_file != None:
                if not os.path.exists(password_file) or\
                   not os.path.isfile(password_file):
                    config.pki_log.error(
                        log.PKI_FILE_MISSING_OR_NOT_A_FILE_1,
                        password_file,
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 % password_file)
            # Execute this "certutil" command
            subprocess.check_call(command, shell=True)
        except subprocess.CalledProcessError as exc:
            return False
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
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
            command = "certutil" + " " + "-S"
            #   Provide a path to the NSS security databases
            if path:
                command = command + " " + "-d" + " " + path
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_PATH,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_PATH)
            #   Specify the 'token'
            if token:
                command = command + " " + "-h" + " " + "'" + token + "'"
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_TOKEN,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_TOKEN)
            #   Specify the nickname of this self-signed certificate
            if nickname:
                command = command + " " + "-n" + " " + "'" + nickname + "'"
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_NICKNAME,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_NICKNAME)
            #   Specify the subject name (RFC1485)
            if subject:
                command = command + " " + "-s" + " " + "'" + subject + "'"
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_SUBJECT,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_SUBJECT)
            #   Specify the serial number
            if serial_number != None:
                command = command + " " + "-m" + " " + str(serial_number)
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_SERIAL_NUMBER,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_SERIAL_NUMBER)
            #   Specify the months valid
            if validity_period != None:
                command = command + " " + "-v" + " " + str(validity_period)
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_VALIDITY_PERIOD,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_VALIDITY_PERIOD)
            #   Specify the nickname of the issuer certificate
            if issuer_name:
                command = command + " " + "-c" + " " + \
                      "'" + issuer_name + "'"
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_ISSUER_NAME,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_ISSUER_NAME)
            #   Specify the certificate trust attributes
            if trustargs:
                command = command + " " + "-t" + " " + "'" + trustargs + "'"
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_TRUSTARGS,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_TRUSTARGS)
            #   Specify a noise file to be used for key generation
            if noise_file:
                command = command + " " + "-z" + " " + noise_file
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_NOISE_FILE,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKIHELPER_CERTUTIL_MISSING_NOISE_FILE)
            #   OPTIONALLY specify a password file
            if password_file != None:
                command = command + " " + "-f" + " " + password_file
            #   ALWAYS self-sign this certificate
            command = command + " " + "-x"
            #   ALWAYS mask the command-line output of this command
            command = command + " " + "> /dev/null 2>&1"
            # Display this "certutil" command
            config.pki_log.info(
                log.PKIHELPER_CERTUTIL_SELF_SIGNED_CERTIFICATE_1, command,
                extra=config.PKI_INDENTATION_LEVEL_2)
            if not os.path.exists(path):
                config.pki_log.error(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, path,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 % path)
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
                raise Exception(log.PKI_SECURITY_DATABASES_DO_NOT_EXIST_3 % (pki_cert_database,
                                                                             pki_key_database, pki_secmod_database))
            if not os.path.exists(noise_file):
                config.pki_log.error(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1,
                    noise_file,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 % noise_file)
            if password_file != None:
                if not os.path.exists(password_file) or\
                   not os.path.isfile(password_file):
                    config.pki_log.error(
                        log.PKI_FILE_MISSING_OR_NOT_A_FILE_1,
                        password_file,
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 % password_file)
            # Execute this "certutil" command
            subprocess.call(command, shell=True)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
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
                command.extend(["-n", nickname ])
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

            config.pki_log.info(command,
                extra=config.PKI_INDENTATION_LEVEL_2)
            subprocess.call(command)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        return

    def generate_certificate_request(self, subject, key_size,
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

            if key_size:
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
                log.PKIHELPER_CERTUTIL_GENERATE_CSR_1, command,
                extra=config.PKI_INDENTATION_LEVEL_2)
            if not os.path.exists(noise_file):
                config.pki_log.error(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1,
                    noise_file,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 % noise_file)
            if not os.path.exists(password_file) or\
               not os.path.isfile(password_file):
                config.pki_log.error(
                    log.PKI_FILE_MISSING_OR_NOT_A_FILE_1,
                    password_file,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                raise Exception(log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 % password_file)
            # Execute this "certutil" command
            with open(os.devnull, "w") as fnull:
                subprocess.call(command, stdout=fnull, stderr=fnull)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        return

class PK12util:
    """PKI Deployment pk12util class"""

    def __init__(self, deployer):
        self.master_dict = deployer.master_dict

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

            config.pki_log.info(command,
                    extra=config.PKI_INDENTATION_LEVEL_2)
            with open(os.devnull, "w") as fnull:
                subprocess.call(command, stdout=fnull, stderr=fnull)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        return

class KRAConnector:
    """PKI Deployment KRA Connector Class"""

    def __init__(self, deployer):
        self.master_dict = deployer.master_dict
        self.password = deployer.password

    def deregister(self, critical_failure=False):
        try:
            # this is applicable to KRAs only
            if self.master_dict['pki_subsystem_type'] != "kra":
                return

            config.pki_log.info(
                log.PKIHELPER_KRACONNECTOR_UPDATE_CONTACT,
                extra=config.PKI_INDENTATION_LEVEL_2)

            cs_cfg = PKIConfigParser.read_simple_configuration_file(
                         self.master_dict['pki_target_cs_cfg'])
            krahost = cs_cfg.get('service.machineName')
            kraport = cs_cfg.get('pkicreate.secure_port')
            cahost = cs_cfg.get('cloning.ca.hostname')
            caport = cs_cfg.get('cloning.ca.httpsport')
            if cahost is None or\
               caport is None:
                config.pki_log.warning(
                    log.PKIHELPER_KRACONNECTOR_UPDATE_FAILURE,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                config.pki_log.error(
                    log.PKIHELPER_UNDEFINED_CA_HOST_PORT,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure == True:
                    raise Exception(log.PKIHELPER_UNDEFINED_CA_HOST_PORT)
                else:
                    return

            # retrieve subsystem nickname
            subsystemnick = cs_cfg.get('kra.cert.subsystem.nickname')
            if subsystemnick is None:
                config.pki_log.warning(
                    log.PKIHELPER_KRACONNECTOR_UPDATE_FAILURE,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                config.pki_log.error(
                    log.PKIHELPER_UNDEFINED_SUBSYSTEM_NICKNAME,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure == True:
                    raise Exception(log.PKIHELPER_UNDEFINED_SUBSYSTEM_NICKNAME)
                else:
                    return

            # retrieve name of token based upon type (hardware/software)
            if ':' in subsystemnick:
                token_name = subsystemnick.split(':')[0]
            else:
                token_name = "internal"

            token_pwd = self.password.get_password(
                            self.master_dict['pki_shared_password_conf'],
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
                if critical_failure == True:
                    raise Exception(log.PKIHELPER_UNDEFINED_TOKEN_PASSWD_1 % token_name)
                else:
                    return

            self.execute_using_sslget(caport, cahost, subsystemnick,
                                 token_pwd, krahost, kraport)

        except subprocess.CalledProcessError as exc:
            config.pki_log.warning(
                log.PKIHELPER_KRACONNECTOR_UPDATE_FAILURE_2,
                str(krahost),
                str(kraport),
                extra=config.PKI_INDENTATION_LEVEL_2)
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        return

    def execute_using_pki(self, caport, cahost, subsystemnick,
      token_pwd, krahost, kraport, critical_failure=False):
        command = "/bin/pki -p '{}' -h '{}' -n '{}' -P https -d '{}' -c '{}' "\
                  "kraconnector-del {} {}".format(
                      caport, cahost, subsystemnick,
                      self.master_dict['pki_database_path'],
                      token_pwd, krahost, kraport)

        output = subprocess.check_output(command,
                                         stderr=subprocess.STDOUT,
                                         shell=True)

        error = re.findall("ClientResponseFailure:(.*?)", output)
        if error:
            config.pki_log.warning(
                log.PKIHELPER_KRACONNECTOR_UPDATE_FAILURE_2,
                str(krahost),
                str(kraport),
                extra=config.PKI_INDENTATION_LEVEL_2)
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, output,
                extra=config.PKI_INDENTATION_LEVEL_2)
        if critical_failure == True:
            raise Exception(log.PKI_SUBPROCESS_ERROR_1 % output)

    def execute_using_sslget(self, caport, cahost, subsystemnick,
      token_pwd, krahost, kraport):
        updateURL = "/ca/rest/admin/kraconnector/remove"

        params = "host=" + str(krahost) + \
                 "&port=" + str(kraport)

        command = "/usr/bin/sslget -n '{}' -p '{}' -d '{}' -e '{}' "\
                  "-v -r '{}' {}:{} 2>&1".format(
                      subsystemnick, token_pwd,
                      self.master_dict['pki_database_path'],
                      params, updateURL,
                      cahost, caport)

        # update KRA connector
        # Execute this "sslget" command
        # Note that sslget will return non-zero value for HTTP code != 200
        # and this will raise an exception
        subprocess.check_output(command,stderr=subprocess.STDOUT,
                                shell=True)

class SecurityDomain:
    """PKI Deployment Security Domain Class"""

    def __init__(self, deployer):
        self.master_dict = deployer.master_dict
        self.password = deployer.password

    def deregister(self, install_token, critical_failure=False):
        # process this PKI subsystem instance's 'CS.cfg'
        cs_cfg = PKIConfigParser.read_simple_configuration_file(
            self.master_dict['pki_target_cs_cfg'])

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
            if critical_failure == True:
                raise Exception(log.PKIHELPER_SECURITY_DOMAIN_UNDEFINED)
            else:
                return

        config.pki_log.info(log.PKIHELPER_SECURITY_DOMAIN_CONTACT_1,
                            secname,
                            extra=config.PKI_INDENTATION_LEVEL_2)
        listval = typeval.lower() + "List"
        updateURL = "/ca/agent/ca/updateDomainXML"

        params = "name=" + "\"" + self.master_dict['pki_instance_path'] + "\"" + \
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
                adminUpdateURL = "/ca/admin/ca/updateDomainXML"
                command = "/usr/bin/sslget -p 123456 -d '{}' -e '{}' "\
                          "-v -r '{}' {}:{} 2>&1".format(
                             self.master_dict['pki_database_path'],
                             params, adminUpdateURL,
                             sechost, secadminport)
                output = subprocess.check_output(command,
                                             stderr=subprocess.STDOUT,
                                             shell=True)
            except subprocess.CalledProcessError:
                config.pki_log.warning(
                    log.PKIHELPER_SECURITY_DOMAIN_UNREACHABLE_1,
                    secname,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                output = self.update_domain_using_agent_port(typeval,
                    secname, params, updateURL, sechost, secagentport,
                    critical_failure)
        else:
            output = self.update_domain_using_agent_port(typeval,
                secname, params, updateURL, sechost, secagentport,
                critical_failure)

        if not output:
            if critical_failure == True:
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
            if critical_failure == True:
                raise Exception(log.PKIHELPER_SECURITY_DOMAIN_UNREACHABLE_1 % secname)
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
            if critical_failure == True:
                raise Exception(log.PKIHELPER_SECURITY_DOMAIN_UPDATE_FAILURE_3
                                %
                                (typeval, secname, error))
        else:
            config.pki_log.info(
                log.PKIHELPER_SECURITY_DOMAIN_UPDATE_SUCCESS_2,
                typeval,
                secname,
                extra=config.PKI_INDENTATION_LEVEL_2)

    def update_domain_using_agent_port(self, typeval, secname, params,
        updateURL, sechost, secagentport, critical_failure=False):
        token_pwd = None
        cs_cfg = PKIConfigParser.read_simple_configuration_file(
            self.master_dict['pki_target_cs_cfg'])
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
            if critical_failure == True:
                raise Exception(log.PKIHELPER_UNDEFINED_SUBSYSTEM_NICKNAME)
            else:
                return

        # retrieve name of token based upon type (hardware/software)
        if ':' in subsystemnick:
            token_name = subsystemnick.split(':')[0]
        else:
            token_name = "internal"

        token_pwd = self.password.get_password(
                        self.master_dict['pki_shared_password_conf'],
                        token_name,
                        critical_failure)

        if token_pwd is None or token_pwd == '':
            config.pki_log.warning(
                log.PKIHELPER_SECURITY_DOMAIN_UPDATE_FAILURE_2,
                typeval,
                secname,
                extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise Exception(log.PKIHELPER_SECURITY_DOMAIN_UPDATE_FAILURE_2
                                %
                                (typeval, secname))
            else:
                return

        command = "/usr/bin/sslget -n '{}' -p '{}' -d '{}' -e '{}' "\
                  "-v -r '{}' {}:{} 2>&1".format(
                      subsystemnick, token_pwd,
                      self.master_dict['pki_database_path'],
                      params, updateURL,
                      sechost, secagentport)
        try:
            output = subprocess.check_output(command,
                                             stderr=subprocess.STDOUT,
                                             shell=True)
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
            if critical_failure == True:
                raise

        return None


    def get_installation_token(self, secuser, secpass, critical_failure=True):
        token = None

        if not secuser or not secpass:
            return None

        # process this PKI subsystem instance's 'CS.cfg'
        cs_cfg = PKIConfigParser.read_simple_configuration_file(
            self.master_dict['pki_target_cs_cfg'])

        # assign key name/value pairs
        machinename = cs_cfg.get('service.machineName')
        cstype = cs_cfg.get('cs.type', '')
        sechost = cs_cfg.get('securitydomain.host')
        secadminport = cs_cfg.get('securitydomain.httpsadminport')
        #secselect = cs_cfg.get('securitydomain.select') - Selected security domain

        command = "/bin/pki -p '{}' -h '{}' -P https -u '{}' -w '{}' -d '{}' "\
                  "securitydomain-get-install-token --hostname {} "\
                  "--subsystem {}".format(
                      secadminport, sechost, secuser, secpass,
                      self.master_dict['pki_database_path'],
                      machinename, cstype)
        try:
            output = subprocess.check_output(command,
                                         stderr=subprocess.STDOUT,
                                         shell=True)

            token_list = re.findall("Install token: \"(.*)\"", output)
            if not token_list:
                config.pki_log.error(
                    log.PKIHELPER_SECURITY_DOMAIN_GET_TOKEN_FAILURE_2,
                    str(sechost),
                    str(secadminport),
                    extra=config.PKI_INDENTATION_LEVEL_2)
                config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, output,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure == True:
                    raise Exception(log.PKIHELPER_SECURITY_DOMAIN_GET_TOKEN_FAILURE_2
                                    %
                                    (str(sechost), str(secadminport)))
            else:
                token = token_list[0]
                return token
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(
                log.PKIHELPER_SECURITY_DOMAIN_GET_TOKEN_FAILURE_2,
                str(sechost),
                str(secadminport),
                extra=config.PKI_INDENTATION_LEVEL_2)
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        return None

class Systemd:
    """PKI Deployment 'systemd' Execution Management Class"""

    def __init__(self, deployer):
        self.master_dict = deployer.master_dict

    def start(self, critical_failure=True):
        try:
            # Compose this "systemd" execution management command
            if self.master_dict['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS:
                command = "systemctl" + " " + \
                          "start" + " " + \
                          "pki-apached" + "@" + \
                          self.master_dict['pki_instance_name'] + "." + "service"
            elif self.master_dict['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
                command = "systemctl" + " " + \
                          "start" + " " + \
                          "pki-tomcatd" + "@" + \
                          self.master_dict['pki_instance_name'] + "." + "service"
            # Display this "systemd" execution managment command
            config.pki_log.info(
                log.PKIHELPER_SYSTEMD_COMMAND_1, command,
                extra=config.PKI_INDENTATION_LEVEL_2)
            # Execute this "systemd" execution management command
            subprocess.call(command, shell=True)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        return

    def stop(self, critical_failure=True):
        try:
            # Compose this "systemd" execution management command
            if self.master_dict['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS:
                command = "systemctl" + " " + \
                          "stop" + " " + \
                          "pki-apached" + "@" + \
                          self.master_dict['pki_instance_name'] + "." + "service"
            elif self.master_dict['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
                command = "systemctl" + " " + \
                          "stop" + " " + \
                          "pki-tomcatd" + "@" + \
                          self.master_dict['pki_instance_name'] + "." + "service"
            # Display this "systemd" execution managment command
            config.pki_log.info(
                log.PKIHELPER_SYSTEMD_COMMAND_1, command,
                extra=config.PKI_INDENTATION_LEVEL_2)
            # Execute this "systemd" execution management command
            subprocess.call(command, shell=True)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        return

    def restart(self, critical_failure=True):
        try:
            # Compose this "systemd" execution management command
            if self.master_dict['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS:
                command = "systemctl" + " " + \
                          "restart" + " " + \
                          "pki-apached" + "@" + \
                          self.master_dict['pki_instance_name'] + "." + "service"
            elif self.master_dict['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
                command = "systemctl" + " " + \
                          "restart" + " " + \
                          "pki-tomcatd" + "@" + \
                          self.master_dict['pki_instance_name'] + "." + "service"
            # Display this "systemd" execution managment command
            config.pki_log.info(
                log.PKIHELPER_SYSTEMD_COMMAND_1, command,
                extra=config.PKI_INDENTATION_LEVEL_2)
            # Execute this "systemd" execution management command
            subprocess.call(command, shell=True)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                raise
        return


class ConfigClient:
    """PKI Deployment Configuration Client"""

    def __init__(self, deployer):
        self.deployer = deployer
        self.master_dict = deployer.master_dict

    def configure_pki_data(self, data):
        config.pki_log.info(log.PKI_CONFIG_CONFIGURING_PKI_DATA,
                             extra=config.PKI_INDENTATION_LEVEL_2)

        self.connection = pki.client.PKIConnection(
            protocol='https',
            hostname=self.master_dict['pki_hostname'],
            port=self.master_dict['pki_https_port'],
            subsystem=self.master_dict['pki_subsystem_type'])

        try:
            client = pki.system.SystemConfigClient(self.connection)
            response = client.configure(data)

            config.pki_log.debug(log.PKI_CONFIG_RESPONSE_STATUS + \
                                   " " + str(response['status']),
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            try:
                certs = response['systemCerts']
            except KeyError:
                # no system certs created
                config.pki_log.debug("No new system certificates generated.",
                                      extra=config.PKI_INDENTATION_LEVEL_2)
                certs = []

            if not isinstance(certs, types.ListType):
                certs = [certs]
            for cdata in certs:
                if self.master_dict['pki_subsystem'] == "CA" and\
                   config.str2bool(self.master_dict['pki_external']) and\
                   not config.str2bool(self.master_dict['pki_external_step_two']):
                    # External CA Step 1
                    if cdata['tag'].lower() == "signing":
                        config.pki_log.info(log.PKI_CONFIG_CDATA_REQUEST + \
                            " " + cdata['request'],
                            extra=config.PKI_INDENTATION_LEVEL_2)

                        # Save 'External CA Signing Certificate' CSR (Step 1)
                        config.pki_log.info(log.PKI_CONFIG_EXTERNAL_CSR_SAVE + \
                            " '" + self.master_dict['pki_external_csr_path'] + "'",
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        self.deployer.directory.create(
                            os.path.dirname(self.master_dict['pki_external_csr_path']))
                        with open(self.master_dict['pki_external_csr_path'], "w") as f:
                            f.write(cdata['request'])
                        return
                else:
                    config.pki_log.debug(log.PKI_CONFIG_CDATA_TAG + \
                                           " " + cdata['tag'],
                                         extra=config.PKI_INDENTATION_LEVEL_2)
                    config.pki_log.debug(log.PKI_CONFIG_CDATA_CERT + \
                                           " " + cdata['cert'],
                                         extra=config.PKI_INDENTATION_LEVEL_2)
                    config.pki_log.debug(log.PKI_CONFIG_CDATA_REQUEST + \
                                           " " + cdata['request'],
                                         extra=config.PKI_INDENTATION_LEVEL_2)

            # Cloned PKI subsystems do not return an Admin Certificate
            if not config.str2bool(self.master_dict['pki_clone']) and \
               not config.str2bool(self.master_dict['pki_import_admin_cert']):
                admin_cert = response['adminCert']['cert']
                self.process_admin_cert(admin_cert)

        except Exception, e:
            if hasattr(e, 'response'):
                root = ET.fromstring(e.response.text)
                if root.tag == 'PKIException':
                    message = root.findall('.//Message')[0].text
                    if message is not None:
                        config.pki_log.error(log.PKI_CONFIG_JAVA_CONFIGURATION_EXCEPTION + " " + message,
                                         extra=config.PKI_INDENTATION_LEVEL_2)
                        raise
            config.pki_log.error(
                log.PKI_CONFIG_JAVA_CONFIGURATION_EXCEPTION + " " + str(e),
                extra=config.PKI_INDENTATION_LEVEL_2)
            raise
        return

    def process_admin_cert(self, admin_cert):
        config.pki_log.debug(log.PKI_CONFIG_RESPONSE_ADMIN_CERT + \
                             " " + admin_cert,
                             extra=config.PKI_INDENTATION_LEVEL_2)

        # Store the Administration Certificate in a file
        admin_cert_file = self.master_dict['pki_client_admin_cert']
        admin_cert_bin_file = admin_cert_file + ".der"
        config.pki_log.debug(log.PKI_CONFIG_ADMIN_CERT_SAVE + \
                               " '" + admin_cert_file + "'",
                             extra=config.PKI_INDENTATION_LEVEL_2)
        with open(admin_cert_file, "w") as f:
            f.write(admin_cert)

        # convert the cert file to binary
        command = ["AtoB", admin_cert_file, admin_cert_bin_file]
        config.pki_log.info(command,
            extra=config.PKI_INDENTATION_LEVEL_2)
        subprocess.call(command)

        os.chmod(admin_cert_file,
                 config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS)

        os.chmod(admin_cert_bin_file,
                 config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS)

        # Import the Administration Certificate
        # into the client NSS security database
        self.deployer.certutil.import_cert(
            re.sub("&#39;", "'", self.master_dict['pki_admin_nickname']),
            "u,u,u",
            admin_cert_bin_file,
            self.master_dict['pki_client_password_conf'],
            self.master_dict['pki_client_database_dir'],
            None,
            True)

        # create directory for p12 file if it does not exist
        self.deployer.directory.create(os.path.dirname(
            self.master_dict['pki_client_admin_cert_p12']))

        # Export the Administration Certificate from the
        # client NSS security database into a PKCS #12 file
        self.deployer.pk12util.create_file(
            self.master_dict['pki_client_admin_cert_p12'],
            re.sub("&#39;", "'", self.master_dict['pki_admin_nickname']),
            self.master_dict['pki_client_pkcs12_password_conf'],
            self.master_dict['pki_client_password_conf'],
            self.master_dict['pki_client_database_dir'])

        os.chmod(self.master_dict['pki_client_admin_cert_p12'],
            config.PKI_DEPLOYMENT_DEFAULT_SECURITY_DATABASE_PERMISSIONS)


    def construct_pki_configuration_data(self):
        config.pki_log.info(log.PKI_CONFIG_CONSTRUCTING_PKI_DATA,
                             extra=config.PKI_INDENTATION_LEVEL_2)

        data = pki.system.ConfigurationRequest()

        # Miscellaneous Configuration Information
        data.pin = self.master_dict['pki_one_time_pin']
        data.subsystemName = self.master_dict['pki_subsystem_name']

        # Cloning parameters
        if self.master_dict['pki_instance_type'] == "Tomcat":
            if config.str2bool(self.master_dict['pki_clone']):
                self.set_cloning_parameters(data)
            else:
                data.isClone = "false"

        # Hierarchy
        self.set_hierarchy_parameters(data)

        # Security Domain
        if self.master_dict['pki_subsystem'] != "CA" or\
           config.str2bool(self.master_dict['pki_clone']) or\
           config.str2bool(self.master_dict['pki_subordinate']):
            # PKI KRA, PKI OCSP, PKI RA, PKI TKS, PKI TPS,
            # CA Clone, KRA Clone, OCSP Clone, TKS Clone, TPS Clone, or
            # Subordinate CA
            self.set_existing_security_domain(data)
        else:
            # PKI CA or External CA
            self.set_new_security_domain(data)

        # database
        if self.master_dict['pki_subsystem'] != "RA":
            self.set_database_parameters(data)

        # backup
        if self.master_dict['pki_instance_type'] == "Tomcat":
            self.set_backup_parameters(data)

        # admin user
        if not config.str2bool(self.master_dict['pki_clone']):
            self.set_admin_parameters(data)

        # Issuing CA Information
        self.set_issuing_ca_parameters(data)

        # Create system certs
        self.set_system_certs(data)

        return data

    def set_system_certs(self, data):
        systemCerts = []

        # Create 'CA Signing Certificate'
        if self.master_dict['pki_subsystem'] == "CA":
            if not config.str2bool(self.master_dict['pki_clone']):
                cert1 = self.create_system_cert("ca_signing")
                cert1.signingAlgorithm = \
                    self.master_dict['pki_ca_signing_signing_algorithm']
                if config.str2bool(self.master_dict['pki_external_step_two']):
                    # Load the 'External CA Signing Certificate' (Step 2)
                    print(
                        log.PKI_CONFIG_EXTERNAL_CA_LOAD + " " + \
                        "'" + self.master_dict['pki_external_ca_cert_path'] + "'")
                    with open(self.master_dict['pki_external_ca_cert_path']) as f:
                        external_cert = f.read()
                    cert1.cert = external_cert

                    # Load the 'External CA Signing Certificate Chain' (Step 2)
                    print(
                        log.PKI_CONFIG_EXTERNAL_CA_CHAIN_LOAD + " " + \
                        "'" + self.master_dict['pki_external_ca_cert_chain_path'] + \
                        "'")
                    with open(self.master_dict['pki_external_ca_cert_chain_path']) as f:
                        external_cert_chain = f.read()

                    cert1.certChain = external_cert_chain
                systemCerts.append(cert1)

        # Create 'OCSP Signing Certificate'
        if not config.str2bool(self.master_dict['pki_clone']):
            if self.master_dict['pki_subsystem'] == "CA" or\
               self.master_dict['pki_subsystem'] == "OCSP":
                # External CA, Subordinate CA, PKI CA, or PKI OCSP
                cert2 = self.create_system_cert("ocsp_signing")
                cert2.signingAlgorithm = \
                    self.master_dict['pki_ocsp_signing_signing_algorithm']
                systemCerts.append(cert2)

        # Create 'SSL Server Certificate'
        # all subsystems

        # create new sslserver cert only if this is a new instance
        cert3 = None
        system_list = self.deployer.instance.tomcat_instance_subsystems()
        if len(system_list) >= 2:
            data.generateServerCert = "false"
            for subsystem in system_list:
                dst = self.master_dict['pki_instance_path'] + '/conf/' + \
                    subsystem.lower() + '/CS.cfg'
                if subsystem != self.master_dict['pki_subsystem'] and \
                   os.path.exists(dst):
                    cert3 = self.retrieve_existing_server_cert(dst)
                    break
        else:
            cert3 = self.create_system_cert("ssl_server")
        systemCerts.append(cert3)

        # Create 'Subsystem Certificate'
        if not config.str2bool(self.master_dict['pki_clone']):
            cert4 = self.create_system_cert("subsystem")
            systemCerts.append(cert4)

        # Create 'Audit Signing Certificate'
        if not config.str2bool(self.master_dict['pki_clone']):
            if self.master_dict['pki_subsystem'] != "RA":
                cert5 = self.create_system_cert("audit_signing")
                cert5.signingAlgorithm = \
                    self.master_dict['pki_audit_signing_signing_algorithm']
                systemCerts.append(cert5)

        # Create DRM Transport and storage Certificates
        if not config.str2bool(self.master_dict['pki_clone']):
            if self.master_dict['pki_subsystem'] == "KRA":
                cert6 = self.create_system_cert("transport")
                systemCerts.append(cert6)

                cert7 = self.create_system_cert("storage")
                systemCerts.append(cert7)

        data.systemCerts = systemCerts

    def set_cloning_parameters(self, data):
        data.isClone = "true"
        data.cloneUri = self.master_dict['pki_clone_uri']
        data.p12File = self.master_dict['pki_clone_pkcs12_path']
        data.p12Password = self.master_dict['pki_clone_pkcs12_password']
        data.replicateSchema = self.master_dict['pki_clone_replicate_schema']
        data.replicationSecurity = \
            self.master_dict['pki_clone_replication_security']
        if self.master_dict['pki_clone_replication_master_port']:
            data.masterReplicationPort = \
                self.master_dict['pki_clone_replication_master_port']
        if self.master_dict['pki_clone_replication_clone_port']:
            data.cloneReplicationPort = \
                self.master_dict['pki_clone_replication_clone_port']

    def set_hierarchy_parameters(self, data):
        if self.master_dict['pki_subsystem'] == "CA":
            if config.str2bool(self.master_dict['pki_clone']):
                # Cloned CA
                data.hierarchy = "root"
            elif config.str2bool(self.master_dict['pki_external']):
                # External CA
                data.hierarchy = "join"
            elif config.str2bool(self.master_dict['pki_subordinate']):
                # Subordinate CA
                data.hierarchy = "join"
            else:
                # PKI CA
                data.hierarchy = "root"

    def set_existing_security_domain(self, data):
        data.securityDomainType = "existingdomain"
        data.securityDomainUri = self.master_dict['pki_security_domain_uri']
        data.securityDomainUser = self.master_dict['pki_security_domain_user']
        data.securityDomainPassword = self.master_dict['pki_security_domain_password']

    def set_new_security_domain(self, data):
        data.securityDomainType = "newdomain"
        data.securityDomainName = self.master_dict['pki_security_domain_name']

    def set_database_parameters(self, data):
        data.dsHost = self.master_dict['pki_ds_hostname']
        data.dsPort = self.master_dict['pki_ds_ldap_port']
        data.baseDN = self.master_dict['pki_ds_base_dn']
        data.bindDN = self.master_dict['pki_ds_bind_dn']
        data.database = self.master_dict['pki_ds_database']
        data.bindpwd = self.master_dict['pki_ds_password']
        if config.str2bool(self.master_dict['pki_ds_remove_data']):
            data.removeData = "true"
        else:
            data.removeData = "false"
        if config.str2bool(self.master_dict['pki_ds_secure_connection']):
            data.secureConn = "true"
        else:
            data.secureConn = "false"

    def set_backup_parameters(self, data):
        if config.str2bool(self.master_dict['pki_backup_keys']):
            data.backupKeys = "true"
            data.backupFile = self.master_dict['pki_backup_keys_p12']
            data.backupPassword = self.master_dict['pki_backup_password']
        else:
            data.backupKeys = "false"

    def set_admin_parameters(self, data):
        data.adminEmail = self.master_dict['pki_admin_email']
        data.adminName = self.master_dict['pki_admin_name']
        data.adminPassword = self.master_dict['pki_admin_password']
        data.adminProfileID = self.master_dict['pki_admin_profile_id']
        data.adminUID = self.master_dict['pki_admin_uid']
        data.adminSubjectDN = self.master_dict['pki_admin_subject_dn']
        if config.str2bool(self.master_dict['pki_import_admin_cert']):
            data.importAdminCert = "true"
            # read config from file
            with open(self.master_dict['pki_admin_cert_file']) as f:
                b64 = f.read().replace('\n', '')
            data.adminCert = b64
        else:
            data.importAdminCert = "false"
            data.adminSubjectDN = self.master_dict['pki_admin_subject_dn']
            if self.master_dict['pki_admin_cert_request_type'] == "pkcs10":
                data.adminCertRequestType = "pkcs10"

                noise_file = os.path.join(
                    self.master_dict['pki_client_database_dir'], "noise")

                output_file = os.path.join(
                    self.master_dict['pki_client_database_dir'], "admin_pkcs10.bin")

                self.deployer.file.generate_noise_file(
                    noise_file, int(self.master_dict['pki_admin_keysize']))

                self.deployer.certutil.generate_certificate_request(
                                     self.master_dict['pki_admin_subject_dn'],
                                     self.master_dict['pki_admin_keysize'],
                                     self.master_dict['pki_client_password_conf'],
                                     noise_file,
                                     output_file,
                                     self.master_dict['pki_client_database_dir'],
                                     None, None, True)

                # convert output to ascii
                command = ["BtoA", output_file, output_file + ".asc"]
                config.pki_log.info(command,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                subprocess.call(command)

                with open(output_file + ".asc") as f:
                    b64 = f.read().replace('\n', '')

                data.adminCertRequest = b64
            else:
                print "log.PKI_CONFIG_PKCS10_SUPPORT_ONLY"
                raise Exception(log.PKI_CONFIG_PKCS10_SUPPORT_ONLY)

    def set_issuing_ca_parameters(self, data):
        if self.master_dict['pki_subsystem'] != "CA" or\
           config.str2bool(self.master_dict['pki_clone']) or\
           config.str2bool(self.master_dict['pki_subordinate']) or\
           config.str2bool(self.master_dict['pki_external']):
            # PKI KRA, PKI OCSP, PKI RA, PKI TKS, PKI TPS,
            # CA Clone, KRA Clone, OCSP Clone, TKS Clone, TPS Clone,
            # Subordinate CA, or External CA
            data.issuingCA = self.master_dict['pki_issuing_ca']
            if self.master_dict['pki_subsystem'] == "CA"  and\
               config.str2bool(self.master_dict['pki_external_step_two']):
                # External CA Step 2
                data.stepTwo = "true"

    def create_system_cert(self, tag):
        cert = pki.system.SystemCertData()
        cert.tag = self.master_dict["pki_%s_tag" % tag]
        cert.keyAlgorithm = self.master_dict["pki_%s_key_algorithm" % tag]
        cert.keySize = self.master_dict["pki_%s_key_size" % tag]
        cert.keyType = self.master_dict["pki_%s_key_type" % tag]
        cert.nickname = self.master_dict["pki_%s_nickname" % tag]
        cert.subjectDN = self.master_dict["pki_%s_subject_dn" % tag]
        cert.token = self.master_dict["pki_%s_token" % tag]
        return cert

    def retrieve_existing_server_cert(self, cfg_file):
        cs_cfg = PKIConfigParser.read_simple_configuration_file(cfg_file)
        cstype = cs_cfg.get('cs.type').lower()
        cert = pki.system.SystemCertData()
        cert.tag = self.master_dict["pki_ssl_server_tag"]
        cert.keyAlgorithm = self.master_dict["pki_ssl_server_key_algorithm"]
        cert.keySize = self.master_dict["pki_ssl_server_key_size"]
        cert.keyType = self.master_dict["pki_ssl_server_key_type"]
        cert.nickname = cs_cfg.get(cstype + ".sslserver.nickname")
        cert.cert = cs_cfg.get(cstype + ".sslserver.cert")
        cert.request = cs_cfg.get(cstype + ".sslserver.certreq")
        cert.subjectDN = self.master_dict["pki_ssl_server_subject_dn"]
        cert.token = cs_cfg.get(cstype + ".sslserver.tokenname")
        return cert

class PKIDeployer:
    """Holds the global dictionaries and the utility objects"""

    def __init__(self, pki_master_dict, pki_slots_dict=None):
        # Global dictionary variables
        self.master_dict = pki_master_dict
        self.slots = pki_slots_dict
        self.manifest_db = []

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
        self.certutil = Certutil(self)
        self.pk12util = PK12util(self)
        self.kra_connector = KRAConnector(self)
        self.security_domain = SecurityDomain(self)
        self.systemd = Systemd(self)
        self.config_client = ConfigClient(self)


