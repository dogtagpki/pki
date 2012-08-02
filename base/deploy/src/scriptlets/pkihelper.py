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
import pickle
import random
import shutil
import string
import subprocess
from grp import getgrgid
from grp import getgrnam
from pwd import getpwnam
from pwd import getpwuid
import zipfile
import seobject


# PKI Deployment Imports
import pkiconfig as config
from pkiconfig import pki_master_dict as master
from pkiconfig import pki_sensitive_dict as sensitive
from pkiconfig import pki_slots_dict as slots
from pkiconfig import pki_selinux_config_ports as ports
import pkimanifest as manifest
import pkimessages as log


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

    XXX Consider this example code rather than the ultimate tool.

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


# PKI Deployment Identity Class
class identity:
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
                command = "/usr/sbin/groupadd" + " " +\
                          pki_group + " " +\
                          "> /dev/null 2>&1"
            except KeyError as exc:
                # No, the default well-known GID does not exist!
                config.pki_log.debug(log.PKIHELPER_GROUP_ADD_GID_KEYERROR_1,
                                     exc, extra=config.PKI_INDENTATION_LEVEL_2)
                # Is the specified 'pki_group' the default well-known group?
                if pki_group == config.PKI_DEPLOYMENT_DEFAULT_GROUP:
                    # Yes, attempt to create the default well-known group
                    # using the default well-known GID.
                    command = "/usr/sbin/groupadd" + " " +\
                              "-g" + " " +\
                              str(config.PKI_DEPLOYMENT_DEFAULT_GID) + " " +\
                              "-r" + " " +\
                              pki_group + " " +\
                              "> /dev/null 2>&1"
                else:
                    # No, attempt to create 'pki_group' using a random GID.
                    command = "/usr/sbin/groupadd" + " " +\
                              pki_group + " " +\
                              "> /dev/null 2>&1"
            # Execute this "groupadd" command.
            subprocess.call(command, shell=True)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            sys.exit(1)
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
                command = "/usr/sbin/useradd" + " " +\
                          "-g" + " " +\
                          pki_group + " " +\
                          "-d" + " " +\
                          config.PKI_DEPLOYMENT_SOURCE_ROOT + " " +\
                          "-s" + " " +\
                          config.PKI_DEPLOYMENT_DEFAULT_SHELL + " " +\
                          "-c" + " " +\
                          config.PKI_DEPLOYMENT_DEFAULT_COMMENT + " " +\
                          pki_user + " " +\
                          "> /dev/null 2>&1"
            except KeyError as exc:
                # No, the default well-known UID does not exist!
                config.pki_log.debug(log.PKIHELPER_USER_ADD_UID_KEYERROR_1,
                                     exc, extra=config.PKI_INDENTATION_LEVEL_2)
                # Is the specified 'pki_user' the default well-known user?
                if pki_user == config.PKI_DEPLOYMENT_DEFAULT_USER:
                    # Yes, attempt to create the default well-known user
                    # using the default well-known UID.
                    command = "/usr/sbin/useradd" + " " +\
                              "-g" + " " +\
                              pki_group + " " +\
                              "-d" + " " +\
                              config.PKI_DEPLOYMENT_SOURCE_ROOT + " " +\
                              "-s" + " " +\
                              config.PKI_DEPLOYMENT_DEFAULT_SHELL + " " +\
                              "-c" + " " +\
                              config.PKI_DEPLOYMENT_DEFAULT_COMMENT + " " +\
                              "-u" + " " +\
                              str(config.PKI_DEPLOYMENT_DEFAULT_UID) + " " +\
                              "-r" + " " +\
                              pki_user + " " +\
                              "> /dev/null 2>&1"
                else:
                    # No, attempt to create 'pki_user' using a random UID.
                    command = "/usr/sbin/useradd" + " " +\
                              "-g" + " " +\
                              pki_group + " " +\
                              "-d" + " " +\
                              config.PKI_DEPLOYMENT_SOURCE_ROOT + " " +\
                              "-s" + " " +\
                              config.PKI_DEPLOYMENT_DEFAULT_SHELL + " " +\
                              "-c" + " " +\
                              config.PKI_DEPLOYMENT_DEFAULT_COMMENT + " " +\
                              pki_user + " " +\
                              "> /dev/null 2>&1"
            # Execute this "useradd" command.
            subprocess.call(command, shell=True)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            sys.exit(1)
        return

    def add_uid_and_gid(self, pki_user, pki_group):
        self.__add_gid(pki_group)
        self.__add_uid(pki_user, pki_group)
        return

    def get_uid(self, critical_failure=True):
        try:
            pki_uid = master['pki_uid']
        except KeyError as exc:
            config.pki_log.error(log.PKI_KEYERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
        return pki_uid

    def get_gid(self, critical_failure=True):
        try:
            pki_gid = master['pki_gid']
        except KeyError as exc:
            config.pki_log.error(log.PKI_KEYERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
        return pki_gid

    def set_uid(self, name, critical_failure=True):
        try:
            config.pki_log.debug(log.PKIHELPER_USER_1, name,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            # id -u <name>
            pki_uid = getpwnam(name)[2]
            master['pki_uid']=pki_uid
            config.pki_log.debug(log.PKIHELPER_UID_2, name, pki_uid,
                                 extra=config.PKI_INDENTATION_LEVEL_3)
        except KeyError as exc:
            config.pki_log.error(log.PKI_KEYERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
        return pki_uid

    def set_gid(self, name, critical_failure=True):
        try:
            config.pki_log.debug(log.PKIHELPER_GROUP_1, name,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            # id -g <name>
            pki_gid = getgrnam(name)[2]
            master['pki_gid']=pki_gid
            config.pki_log.debug(log.PKIHELPER_GID_2, name, pki_gid,
                                 extra=config.PKI_INDENTATION_LEVEL_3)
        except KeyError as exc:
            config.pki_log.error(log.PKI_KEYERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
        return pki_gid


# PKI Deployment Namespace Class
class namespace:
    # Silently verify that the selected 'pki_instance_name' will
    # NOT produce any namespace collisions
    def collision_detection(self):
        # Run simple checks for pre-existing namespace collisions
        if os.path.exists(master['pki_instance_path']):
            if os.path.exists(master['pki_subsystem_path']):
                # Top-Level PKI base path collision
                config.pki_log.error(
                    log.PKIHELPER_NAMESPACE_COLLISION_2,
                    master['pki_instance_id'],
                    master['pki_instance_path'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
        else:
            if os.path.exists(master['pki_target_tomcat_conf_instance_id']):
                # Top-Level "/etc/sysconfig" path collision
                config.pki_log.error(
                    log.PKIHELPER_NAMESPACE_COLLISION_2,
                    master['pki_instance_id'],
                    master['pki_target_tomcat_conf_instance_id'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
            if os.path.exists(master['pki_cgroup_systemd_service']):
                # Systemd cgroup path collision
                config.pki_log.error(
                    log.PKIHELPER_NAMESPACE_COLLISION_2,
                    master['pki_instance_id'],
                    master['pki_cgroup_systemd_service_path'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
            if os.path.exists(master['pki_cgroup_cpu_systemd_service']):
                # Systemd cgroup CPU path collision
                config.pki_log.error(
                    log.PKIHELPER_NAMESPACE_COLLISION_2,
                    master['pki_instance_id'],
                    master['pki_cgroup_cpu_systemd_service_path'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
        if os.path.exists(master['pki_instance_log_path']) and\
           os.path.exists(master['pki_subsystem_log_path']):
            # Top-Level PKI log path collision
            config.pki_log.error(
                log.PKIHELPER_NAMESPACE_COLLISION_2,
                master['pki_instance_id'],
                master['pki_instance_log_path'],
                extra=config.PKI_INDENTATION_LEVEL_2)
            sys.exit(1)
        if os.path.exists(master['pki_instance_configuration_path']) and\
           os.path.exists(master['pki_subsystem_configuration_path']):
            # Top-Level PKI configuration path collision
            config.pki_log.error(
                log.PKIHELPER_NAMESPACE_COLLISION_2,
                master['pki_instance_id'],
                master['pki_instance_configuration_path'],
                extra=config.PKI_INDENTATION_LEVEL_2)
            sys.exit(1)
        if os.path.exists(master['pki_instance_registry_path']) and\
           os.path.exists(master['pki_subsystem_registry_path']):
            # Top-Level PKI registry path collision
            config.pki_log.error(
                log.PKIHELPER_NAMESPACE_COLLISION_2,
                master['pki_instance_id'],
                master['pki_instance_registry_path'],
                extra=config.PKI_INDENTATION_LEVEL_2)
            sys.exit(1)
        # Run simple checks for reserved name namespace collisions
        if master['pki_instance_id'] in config.PKI_BASE_RESERVED_NAMES:
            # Top-Level PKI base path reserved name collision
            config.pki_log.error(
                log.PKIHELPER_NAMESPACE_RESERVED_NAME_2,
                master['pki_instance_id'],
                master['pki_instance_path'],
                extra=config.PKI_INDENTATION_LEVEL_2)
            sys.exit(1)
        # No need to check for reserved name under Top-Level PKI log path
        if master['pki_instance_id'] in config.PKI_CONFIGURATION_RESERVED_NAMES:
            # Top-Level PKI configuration path reserved name collision
            config.pki_log.error(
                log.PKIHELPER_NAMESPACE_RESERVED_NAME_2,
                master['pki_instance_id'],
                master['pki_instance_configuration_path'],
                extra=config.PKI_INDENTATION_LEVEL_2)
            sys.exit(1)
        if master['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS:
            # Top-Level Apache PKI registry path reserved name collision
            if master['pki_instance_id'] in\
               config.PKI_APACHE_REGISTRY_RESERVED_NAMES:
                config.pki_log.error(
                    log.PKIHELPER_NAMESPACE_RESERVED_NAME_2,
                    master['pki_instance_id'],
                    master['pki_instance_registry_path'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
        elif master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            # Top-Level Tomcat PKI registry path reserved name collision
            if master['pki_instance_id'] in\
               config.PKI_TOMCAT_REGISTRY_RESERVED_NAMES:
                config.pki_log.error(
                    log.PKIHELPER_NAMESPACE_RESERVED_NAME_2,
                    master['pki_instance_id'],
                    master['pki_instance_registry_path'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)


# PKI Deployment Configuration File Class
class configuration_file:
    def verify_sensitive_data(self):
        # Silently verify the existence of 'sensitive' data
        if master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            # Verify existence of Directory Server Password (ALWAYS)
            if not sensitive.has_key('pki_ds_password') or\
               not len(sensitive['pki_ds_password']):
                config.pki_log.error(
                    log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                    "pki_ds_password",
                    master['pki_deployment_cfg'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
            # Verify existence of Admin Password (except for Clones)
            if not config.str2bool(master['pki_clone']):
                if not sensitive.has_key('pki_admin_password') or\
                   not len(sensitive['pki_admin_password']):
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_admin_password",
                        master['pki_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
            # If required, verify existence of Backup Password
            if config.str2bool(master['pki_backup_keys']):
                if not sensitive.has_key('pki_backup_password') or\
                   not len(sensitive['pki_backup_password']):
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_backup_password",
                        master['pki_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
            # Verify existence of Client Pin for NSS client security databases
            if not sensitive.has_key('pki_client_database_password') or\
               not len(sensitive['pki_client_database_password']):
                config.pki_log.error(
                    log.PKIHELPER_UNDEFINED_CLIENT_DATABASE_PASSWORD_2,
                    "pki_client_database_password",
                    master['pki_deployment_cfg'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
            # Verify existence of Client PKCS #12 Password for Admin Cert
            if not sensitive.has_key('pki_client_pkcs12_password') or\
               not len(sensitive['pki_client_pkcs12_password']):
                config.pki_log.error(
                    log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                    "pki_client_pkcs12_password",
                    master['pki_deployment_cfg'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
            # Verify existence of PKCS #12 Password (ONLY for Clones)
            if config.str2bool(master['pki_clone']):
                if not sensitive.has_key('pki_clone_pkcs12_password') or\
                   not len(sensitive['pki_clone_pkcs12_password']):
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_clone_pkcs12_password",
                        master['pki_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
            # Verify existence of Security Domain Password File
            # (ONLY for Clones, KRA, OCSP, TKS, or Subordinate CA)
            if config.str2bool(master['pki_clone']) or\
               not master['pki_subsystem'] == "CA" or\
               config.str2bool(master['pki_subordinate']):
                if not sensitive.has_key('pki_security_domain_password') or\
                   not len(sensitive['pki_security_domain_password']):
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_security_domain_password",
                        master['pki_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
            # If required, verify existence of Token Password
            if not master['pki_token_name'] == "internal":
                if not sensitive.has_key('pki_token_password') or\
                   not len(sensitive['pki_token_password']):
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_token_password",
                        master['pki_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
        return

    def verify_mutually_exclusive_data(self):
        # Silently verify the existence of 'mutually exclusive' data
        if master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            if master['pki_subsystem'] == "CA":
                if config.str2bool(master['pki_clone']) and\
                   config.str2bool(master['pki_external']) and\
                   config.str2bool(master['pki_subordinate']):
                    config.pki_log.error(
                        log.PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_EXTERNAL_SUB_CA,
                        master['pki_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
                elif config.str2bool(master['pki_clone']) and\
                     config.str2bool(master['pki_external']):
                    config.pki_log.error(
                        log.PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_EXTERNAL_CA,
                        master['pki_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
                elif config.str2bool(master['pki_clone']) and\
                     config.str2bool(master['pki_subordinate']):
                    config.pki_log.error(
                        log.PKIHELPER_MUTUALLY_EXCLUSIVE_CLONE_SUB_CA,
                        master['pki_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
                elif config.str2bool(master['pki_external']) and\
                     config.str2bool(master['pki_subordinate']):
                    config.pki_log.error(
                        log.PKIHELPER_MUTUALLY_EXCLUSIVE_EXTERNAL_SUB_CA,
                        master['pki_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)

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
        if master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            if config.str2bool(master['pki_clone']):
                # Verify existence of clone parameters
                if not master.has_key('pki_ds_base_dn') or\
                   not len(master['pki_ds_base_dn']):
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_ds_base_dn",
                        master['pki_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
                if not master.has_key('pki_ds_ldap_port') or\
                   not len(master['pki_ds_ldap_port']):
                    # FUTURE:  Check for unused port value
                    #          (e. g. - must be different from master if the
                    #                   master is located on the same host)
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_ds_ldap_port",
                        master['pki_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
                if not master.has_key('pki_ds_ldaps_port') or\
                   not len(master['pki_ds_ldaps_port']):
                    # FUTURE:  Check for unused port value
                    #          (e. g. - must be different from master if the
                    #                   master is located on the same host)
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_ds_ldaps_port",
                        master['pki_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
                # NOTE:  Although this will be checked prior to getting to
                #        this method, this clone's 'pki_instance_name' MUST
                #        be different from the master's 'pki_instance_name'
                #        IF AND ONLY IF the master and clone are located on
                #        the same host!
                if not master.has_key('pki_ajp_port') or\
                   not len(master['pki_ajp_port']):
                    # FUTURE:  Check for unused port value
                    #          (e. g. - must be different from master if the
                    #                   master is located on the same host)
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_ajp_port",
                        master['pki_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
                if not master.has_key('pki_http_port') or\
                   not len(master['pki_http_port']):
                    # FUTURE:  Check for unused port value
                    #          (e. g. - must be different from master if the
                    #                   master is located on the same host)
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_http_port",
                        master['pki_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
                if not master.has_key('pki_https_port') or\
                   not len(master['pki_https_port']):
                    # FUTURE:  Check for unused port value
                    #          (e. g. - must be different from master if the
                    #                   master is located on the same host)
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_https_port",
                        master['pki_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
                if not master.has_key('pki_tomcat_server_port') or\
                   not len(master['pki_tomcat_server_port']):
                    # FUTURE:  Check for unused port value
                    #          (e. g. - must be different from master if the
                    #                   master is located on the same host)
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_tomcat_server_port",
                        master['pki_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
                if not master.has_key('pki_clone_pkcs12_path') or\
                   not len(master['pki_clone_pkcs12_path']):
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_clone_pkcs12_path",
                        master['pki_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
                elif not os.path.isfile(master['pki_clone_pkcs12_path']):
                    config.pki_log.error(
                        log.PKI_FILE_ALREADY_EXISTS_NOT_A_FILE_1,
                        master['pki_clone_pkcs12_path'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
                if not master.has_key('pki_clone_replication_security') or\
                   not len(master['pki_clone_replication_security']):
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_clone_replication_security",
                        master['pki_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
                if not master.has_key('pki_clone_uri') or\
                   not len(master['pki_clone_uri']):
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_clone_uri",
                        master['pki_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
            elif master['pki_subsystem'] == "CA" and\
                 config.str2bool(master['pki_external']):
                if not master.has_key('pki_external_step_two') or\
                   not len(master['pki_external_step_two']):
                    config.pki_log.error(
                        log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                        "pki_external_step_two",
                        master['pki_deployment_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
                if not config.str2bool(master['pki_step_two']):
                    if not master.has_key('pki_external_csr_path') or\
                       not len(master['pki_external_csr_path']):
                        config.pki_log.error(
                            log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                            "pki_external_csr_path",
                            master['pki_deployment_cfg'],
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        sys.exit(1)
                    elif not os.path.isfile(master['pki_external_csr_path']):
                        config.pki_log.error(
                            log.PKI_FILE_ALREADY_EXISTS_NOT_A_FILE_1,
                            master['pki_external_csr_path'],
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        sys.exit(1)
                else:
                    if not master.has_key('pki_external_ca_cert_chain_path') or\
                       not len(master['pki_external_ca_cert_chain_path']):
                        config.pki_log.error(
                            log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                            "pki_external_ca_cert_chain_path",
                            master['pki_deployment_cfg'],
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        sys.exit(1)
                    elif not os.path.isfile(
                                 master['pki_external_ca_cert_chain_path']):
                        config.pki_log.error(
                            log.PKI_FILE_ALREADY_EXISTS_NOT_A_FILE_1,
                            master['pki_external_ca_cert_chain_path'],
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        sys.exit(1)
                    if not master.has_key('pki_external_ca_cert_path') or\
                       not len(master['pki_external_ca_cert_path']):
                        config.pki_log.error(
                            log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                            "pki_external_ca_cert_path",
                            master['pki_deployment_cfg'],
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        sys.exit(1)
                    elif not os.path.isfile(
                                 master['pki_external_ca_cert_path']):
                        config.pki_log.error(
                            log.PKI_FILE_ALREADY_EXISTS_NOT_A_FILE_1,
                            master['pki_external_ca_cert_path'],
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        sys.exit(1)
        return

    def populate_non_default_ports(self):
        if master['pki_http_port'] != \
            str(config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_HTTP_PORT):
                ports.append(master['pki_http_port'])
        if master['pki_https_port'] != \
            str(config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_HTTPS_PORT):
                ports.append(master['pki_https_port'])
        if master['pki_tomcat_server_port'] != \
            str(config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_SERVER_PORT):
                ports.append(master['pki_tomcat_server_port'])
        if master['pki_ajp_port'] != \
            str(config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_AJP_PORT):
                ports.append(master['pki_ajp_port'])
        return

    def verify_selinux_ports(self):
        # Determine which ports still need to be labelled, and if any are
        # incorrectly labelled
        if len(ports) == 0:
            return

        portrecs = seobject.portRecords().get_all()
        portlist = ports[:]
        for port in portlist:
            context = ""
            for i in portrecs:
                if portrecs[i][0] == "unreserved_port_t" or \
                   portrecs[i][0] == "reserved_port_t" or \
                   i[2] != "tcp":
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
                sys.exit(1)
        return

    def verify_command_matches_configuration_file(self):
        # Silently verify that the command-line parameters match the values
        # that are present in the corresponding configuration file
        if master['pki_deployment_executable'] == 'pkidestroy':
            if master['pki_deployed_instance_name'] !=\
               master['pki_instance_id']:
                config.pki_log.error(
                    log.PKIHELPER_COMMAND_LINE_PARAMETER_MISMATCH_2,
                    master['pki_deployed_instance_name'],
                    master['pki_instance_id'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
        return



# PKI Deployment XML File Class
#class xml_file:
#    def remove_filter_section_from_web_xml(self,
#                                           web_xml_source,
#                                           web_xml_target):
#        config.pki_log.info(log.PKIHELPER_REMOVE_FILTER_SECTION_1,
#            master['pki_target_subsystem_web_xml'],
#            extra=config.PKI_INDENTATION_LEVEL_2)
#        if not config.pki_dry_run_flag:
#            begin_filters_section = False
#            begin_servlet_section = False
#            FILE = open(web_xml_target, "w")
#            for line in fileinput.FileInput(web_xml_source):
#                if not begin_filters_section:
#                    # Read and write lines until first "<filter>" tag
#                    if line.count("<filter>") >= 1:
#                        # Mark filters section
#                        begin_filters_section = True
#                    else:
#                        FILE.write(line)
#                elif not begin_servlet_section:
#                    # Skip lines until first "<servlet>" tag
#                    if line.count("<servlet>") >= 1:
#                        # Mark servlets section and write out the opening tag
#                        begin_servlet_section = True
#                        FILE.write(line)
#                    else:
#                        continue
#                else:
#                    # Read and write lines all lines after "<servlet>" tag
#                    FILE.write(line)
#            FILE.close()


# PKI Deployment Instance Class
class instance:
    def apache_instance_subsystems(self):
        rv = 0
        try:
            # count number of PKI subsystems present
            # within the specified Apache instance
            for subsystem in config.PKI_APACHE_SUBSYSTEMS:
                path = master['pki_instance_path'] + "/" + subsystem.lower()
                if os.path.exists(path) and os.path.isdir(path):
                    rv = rv + 1
            # always display correct information (even during dry_run)
            if config.pki_dry_run_flag and rv > 0:
                config.pki_log.debug(log.PKIHELPER_APACHE_INSTANCE_SUBSYSTEMS_2,
                                     master['pki_instance_path'], rv - 1,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
            else:
                config.pki_log.debug(log.PKIHELPER_APACHE_INSTANCE_SUBSYSTEMS_2,
                                     master['pki_instance_path'],
                                     rv, extra=config.PKI_INDENTATION_LEVEL_2)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            sys.exit(1)
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
                os.listdir(master['pki_instance_type_registry_path']):
                if os.path.isdir(
                       os.path.join(master['pki_instance_type_registry_path'],
                       instance)) and not\
                   os.path.islink(
                       os.path.join(master['pki_instance_type_registry_path'],
                       instance)):
                    rv = rv + 1
            # always display correct information (even during dry_run)
            if config.pki_dry_run_flag and rv > 0:
                config.pki_log.debug(log.PKIHELPER_APACHE_INSTANCES_2,
                                     master['pki_instance_type_registry_path'],
                                     rv - 1,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
            else:
                config.pki_log.debug(log.PKIHELPER_APACHE_INSTANCES_2,
                                     master['pki_instance_type_registry_path'],
                                     rv,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            sys.exit(1)
        return rv

    def pki_instance_subsystems(self):
        rv = 0
        try:
            # Since ALL directories within the top-level PKI infrastructure
            # SHOULD represent PKI instances, look for all possible
            # PKI instances within the top-level PKI infrastructure
            for instance in os.listdir(master['pki_path']):
                if os.path.isdir(os.path.join(master['pki_path'],instance))\
                   and not\
                   os.path.islink(os.path.join(master['pki_path'],instance)):
                    dir = os.path.join(master['pki_path'],instance)
                    # Since ANY directory within this PKI instance COULD
                    # be a PKI subsystem, look for all possible
                    # PKI subsystems within this PKI instance
                    for name in os.listdir(dir):
                        if os.path.isdir(os.path.join(dir,name)) and\
                           not os.path.islink(os.path.join(dir,name)):
                            if name.upper() in config.PKI_SUBSYSTEMS:
                                rv = rv + 1
            # always display correct information (even during dry_run)
            if config.pki_dry_run_flag and rv > 0:
                config.pki_log.debug(log.PKIHELPER_PKI_INSTANCE_SUBSYSTEMS_2,
                                     master['pki_instance_path'], rv - 1,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
            else:
                config.pki_log.debug(log.PKIHELPER_PKI_INSTANCE_SUBSYSTEMS_2,
                                     master['pki_instance_path'], rv,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            sys.exit(1)
        return rv

    def tomcat_instance_subsystems(self):
        rv = 0
        try:
            # count number of PKI subsystems present
            # within the specified Tomcat instance
            for subsystem in config.PKI_TOMCAT_SUBSYSTEMS:
                path = master['pki_instance_path'] + "/" + subsystem.lower()
                if os.path.exists(path) and os.path.isdir(path):
                    rv = rv + 1
            # always display correct information (even during dry_run)
            if config.pki_dry_run_flag and rv > 0:
                config.pki_log.debug(log.PKIHELPER_TOMCAT_INSTANCE_SUBSYSTEMS_2,
                                     master['pki_instance_path'], rv - 1,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
            else:
                config.pki_log.debug(log.PKIHELPER_TOMCAT_INSTANCE_SUBSYSTEMS_2,
                                     master['pki_instance_path'],
                                     rv, extra=config.PKI_INDENTATION_LEVEL_2)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            sys.exit(1)
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
                os.listdir(master['pki_instance_type_registry_path']):
                if os.path.isdir(
                       os.path.join(master['pki_instance_type_registry_path'],
                       instance)) and not\
                   os.path.islink(
                       os.path.join(master['pki_instance_type_registry_path'],
                       instance)):
                    rv = rv + 1
            # always display correct information (even during dry_run)
            if config.pki_dry_run_flag and rv > 0:
                config.pki_log.debug(log.PKIHELPER_TOMCAT_INSTANCES_2,
                                     master['pki_instance_type_registry_path'],
                                     rv - 1,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
            else:
                config.pki_log.debug(log.PKIHELPER_TOMCAT_INSTANCES_2,
                                     master['pki_instance_type_registry_path'],
                                     rv,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            sys.exit(1)
        return rv

    def verify_subsystem_exists(self):
        try:
            if not os.path.exists(master['pki_subsystem_path']):
                config.pki_log.error(log.PKI_SUBSYSTEM_DOES_NOT_EXIST_2,
                                     master['pki_subsystem'],
                                     master['pki_instance_id'],
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            sys.exit(1)

    def verify_subsystem_does_not_exist(self):
        try:
            if os.path.exists(master['pki_subsystem_path']):
                config.pki_log.error(log.PKI_SUBSYSTEM_ALREADY_EXISTS_2,
                                     master['pki_subsystem'],
                                     master['pki_instance_id'],
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            sys.exit(1)


# PKI Deployment Directory Class
class directory:
    def create(self, name, uid=None, gid=None,
               perms=config.PKI_DEPLOYMENT_DEFAULT_DIR_PERMISSIONS,
               acls=None, critical_failure=True):
        try:
            if not os.path.exists(name):
                # mkdir -p <name>
                config.pki_log.info(log.PKIHELPER_MKDIR_1, name,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                if not config.pki_dry_run_flag:
                    os.makedirs(name)
                # chmod <perms> <name>
                config.pki_log.debug(log.PKIHELPER_CHMOD_2, perms, name,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
                if not config.pki_dry_run_flag:
                    os.chmod(name, perms)
                # chown <uid>:<gid> <name>
                if uid == None:
                    uid = identity.get_uid()
                if gid == None:
                    gid = identity.get_gid()
                config.pki_log.debug(log.PKIHELPER_CHOWN_3,
                                     uid, gid, name,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
                if not config.pki_dry_run_flag:
                    os.chown(name, uid, gid)
                # Store record in installation manifest
                record = manifest.record()
                record.name = name
                record.type = manifest.RECORD_TYPE_DIRECTORY
                record.user = master['pki_user']
                record.group = master['pki_group']
                record.uid = uid
                record.gid = gid
                record.permissions = perms
                record.acls = acls
                manifest.database.append(record)
            elif not os.path.isdir(name):
                config.pki_log.error(
                    log.PKI_DIRECTORY_ALREADY_EXISTS_NOT_A_DIRECTORY_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure == True:
                    sys.exit(1)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                pass
            else:
                config.pki_log.error(log.PKI_OSERROR_1, exc,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure == True:
                    sys.exit(1)
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
                        sys.exit(1)
                # Always re-process each directory whether it needs it or not
                if not silent:
                    config.pki_log.info(log.PKIHELPER_MODIFY_DIR_1, name,
                                        extra=config.PKI_INDENTATION_LEVEL_2)
                # chmod <perms> <name>
                if not silent:
                    config.pki_log.debug(log.PKIHELPER_CHMOD_2, perms, name,
                                         extra=config.PKI_INDENTATION_LEVEL_3)
                if not config.pki_dry_run_flag:
                    os.chmod(name, perms)
                # chown <uid>:<gid> <name>
                if uid == None:
                    uid = identity.get_uid()
                if gid == None:
                    gid = identity.get_gid()
                if not silent:
                    config.pki_log.debug(log.PKIHELPER_CHOWN_3,
                                         uid, gid, name,
                                         extra=config.PKI_INDENTATION_LEVEL_3)
                if not config.pki_dry_run_flag:
                    os.chown(name, uid, gid)
                # Store record in installation manifest
                if not silent:
                    record = manifest.record()
                    record.name = name
                    record.type = manifest.RECORD_TYPE_DIRECTORY
                    record.user = master['pki_user']
                    record.group = master['pki_group']
                    record.uid = uid
                    record.gid = gid
                    record.permissions = perms
                    record.acls = acls
                    manifest.database.append(record)
            else:
                config.pki_log.error(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure == True:
                    sys.exit(1)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
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
                    if not config.pki_dry_run_flag:
                        shutil.rmtree(name)
                else:
                    # rmdir <name>
                    config.pki_log.info(log.PKIHELPER_RMDIR_1, name,
                                        extra=config.PKI_INDENTATION_LEVEL_2)
                    if not config.pki_dry_run_flag:
                        os.rmdir(name)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
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
            sys.exit(1)

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
            sys.exit(1)

    def set_mode(self, name, uid=None, gid=None,
                 dir_perms=config.PKI_DEPLOYMENT_DEFAULT_DIR_PERMISSIONS,
                 file_perms=config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS,
                 symlink_perms=\
                     config.PKI_DEPLOYMENT_DEFAULT_SYMLINK_PERMISSIONS,
                 dir_acls=None, file_acls=None, symlink_acls=None,
                 recursive_flag=True, critical_failure=True):
        try:
            if config.pki_dry_run_flag:
                config.pki_log.info(
                    log.PKIHELPER_SET_MODE_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
            elif not os.path.exists(name) or not os.path.isdir(name):
                config.pki_log.error(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
            else:
                config.pki_log.info(
                    log.PKIHELPER_SET_MODE_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if uid == None:
                    uid = identity.get_uid()
                if gid == None:
                    gid = identity.get_gid()
                if recursive_flag == True:
                    for root, dirs, files in os.walk(name):
                        for name in files:
                            if not os.path.islink(name):
                                file = os.path.join(root, name)
                                config.pki_log.debug(
                                    log.PKIHELPER_IS_A_FILE_1, file,
                                    extra=config.PKI_INDENTATION_LEVEL_3)
                                # chmod <file_perms> <name>
                                config.pki_log.debug(log.PKIHELPER_CHMOD_2,
                                    file_perms, file,
                                    extra=config.PKI_INDENTATION_LEVEL_3)
                                if not config.pki_dry_run_flag:
                                    os.chmod(file, file_perms)
                                # chown <uid>:<gid> <name>
                                config.pki_log.debug(log.PKIHELPER_CHOWN_3,
                                    uid, gid, file,
                                    extra=config.PKI_INDENTATION_LEVEL_3)
                                if not config.pki_dry_run_flag:
                                    os.chown(file, uid, gid)
                                # Store record in installation manifest
                                record = manifest.record()
                                record.name = name
                                record.type = manifest.RECORD_TYPE_FILE
                                record.user = master['pki_user']
                                record.group = master['pki_group']
                                record.uid = uid
                                record.gid = gid
                                record.permissions = file_perms
                                record.acls = file_acls
                                manifest.database.append(record)
                            else:
                                symlink = os.path.join(root, name)
                                config.pki_log.debug(
                                    log.PKIHELPER_IS_A_SYMLINK_1, symlink,
                                    extra=config.PKI_INDENTATION_LEVEL_3)
                                # REMINDER:  Due to POSIX compliance, 'lchmod'
                                #            is NEVER implemented on Linux
                                #            systems since 'chmod' CANNOT be
                                #            run directly against symbolic
                                #            links!
                                # chown -h <uid>:<gid> <link>
                                config.pki_log.debug(log.PKIHELPER_CHOWN_H_3,
                                    uid, gid, link,
                                    extra=config.PKI_INDENTATION_LEVEL_3)
                                if not config.pki_dry_run_flag:
                                    os.lchown(link, uid, gid)
                                # Store record in installation manifest
                                record = manifest.record()
                                record.name = name
                                record.type = manifest.RECORD_TYPE_SYMLINK
                                record.user = master['pki_user']
                                record.group = master['pki_group']
                                record.uid = uid
                                record.gid = gid
                                record.permissions = symlink_perms
                                record.acls = symlink_acls
                                manifest.database.append(record)
                        for name in dirs:
                            dir = os.path.join(root, name)
                            config.pki_log.debug(
                                log.PKIHELPER_IS_A_DIRECTORY_1, dir,
                                extra=config.PKI_INDENTATION_LEVEL_3)
                            # chmod <dir_perms> <name>
                            config.pki_log.debug(log.PKIHELPER_CHMOD_2,
                                dir_perms, dir,
                                extra=config.PKI_INDENTATION_LEVEL_3)
                            if not config.pki_dry_run_flag:
                                os.chmod(dir, dir_perms)
                            # chown <uid>:<gid> <name>
                            config.pki_log.debug(log.PKIHELPER_CHOWN_3,
                                uid, gid, dir,
                                extra=config.PKI_INDENTATION_LEVEL_3)
                            if not config.pki_dry_run_flag:
                                os.chown(dir, uid, gid)
                            # Store record in installation manifest
                            record = manifest.record()
                            record.name = name
                            record.type = manifest.RECORD_TYPE_DIRECTORY
                            record.user = master['pki_user']
                            record.group = master['pki_group']
                            record.uid = uid
                            record.gid = gid
                            record.permissions = dir_perms
                            record.acls = dir_acls
                            manifest.database.append(record)
                else:
                    config.pki_log.debug(
                        log.PKIHELPER_IS_A_DIRECTORY_1, name,
                        extra=config.PKI_INDENTATION_LEVEL_3)
                    name = os.path.join(root, name)
                    # chmod <dir_perms> <name>
                    config.pki_log.debug(log.PKIHELPER_CHMOD_2,
                                         dir_perms, name,
                                         extra=config.PKI_INDENTATION_LEVEL_3)
                    if not config.pki_dry_run_flag:
                        os.chmod(name, dir_perms)
                    # chown <uid>:<gid> <name>
                    config.pki_log.debug(log.PKIHELPER_CHOWN_3,
                                         uid, gid, name,
                                         extra=config.PKI_INDENTATION_LEVEL_3)
                    if not config.pki_dry_run_flag:
                        os.chown(name, uid, gid)
                    # Store record in installation manifest
                    record = manifest.record()
                    record.name = name
                    record.type = manifest.RECORD_TYPE_DIRECTORY
                    record.user = master['pki_user']
                    record.group = master['pki_group']
                    record.uid = uid
                    record.gid = gid
                    record.permissions = dir_perms
                    record.acls = dir_acls
                    manifest.database.append(record)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)

    def copy(self, old_name, new_name, uid=None, gid=None,
             dir_perms=config.PKI_DEPLOYMENT_DEFAULT_DIR_PERMISSIONS,
             file_perms=config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS,
             symlink_perms=config.PKI_DEPLOYMENT_DEFAULT_SYMLINK_PERMISSIONS,
             dir_acls=None, file_acls=None, symlink_acls=None,
             recursive_flag=True, overwrite_flag=False, critical_failure=True):
        try:
            if config.pki_dry_run_flag:
                if recursive_flag == True:
                    # cp -rp <old_name> <new_name>
                    config.pki_log.info(log.PKIHELPER_CP_RP_2,
                                        old_name, new_name,
                                        extra=config.PKI_INDENTATION_LEVEL_2)
                else:
                    # cp -p <old_name> <new_name>
                    config.pki_log.info(log.PKIHELPER_CP_P_2,
                                        old_name, new_name,
                                        extra=config.PKI_INDENTATION_LEVEL_2)
                config.pki_log.info(
                    log.PKIHELPER_SET_MODE_1, new_name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
            elif not os.path.exists(old_name) or not os.path.isdir(old_name):
                config.pki_log.error(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, old_name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
            else:
                if os.path.exists(new_name):
                    if not overwrite_flag:
                        config.pki_log.error(
                            log.PKI_DIRECTORY_ALREADY_EXISTS_1, new_name,
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        sys.exit(1)
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
                sys.exit(1)
        except shutil.Error as exc:
            config.pki_log.error(log.PKI_SHUTIL_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
        return


# PKI Deployment File Class (also used for executables)
class file:
    def create(self, name, uid=None, gid=None,
               perms=config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS,
               acls=None, critical_failure=True):
        try:
            if not os.path.exists(name):
                # touch <name>
                config.pki_log.info(log.PKIHELPER_TOUCH_1, name,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                if not config.pki_dry_run_flag:
                    open(name, "w").close()
                # chmod <perms> <name>
                config.pki_log.debug(log.PKIHELPER_CHMOD_2, perms, name,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
                if not config.pki_dry_run_flag:
                    os.chmod(name, perms)
                # chown <uid>:<gid> <name>
                if uid == None:
                    uid = identity.get_uid()
                if gid == None:
                    gid = identity.get_gid()
                config.pki_log.debug(log.PKIHELPER_CHOWN_3,
                                     uid, gid, name,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
                if not config.pki_dry_run_flag:
                    os.chown(name, uid, gid)
                # Store record in installation manifest
                record = manifest.record()
                record.name = name
                record.type = manifest.RECORD_TYPE_FILE
                record.user = master['pki_user']
                record.group = master['pki_group']
                record.uid = uid
                record.gid = gid
                record.permissions = perms
                record.acls = acls
                manifest.database.append(record)
            elif not os.path.isfile(name):
                config.pki_log.error(
                    log.PKI_FILE_ALREADY_EXISTS_NOT_A_FILE_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure == True:
                    sys.exit(1)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                pass
            else:
                config.pki_log.error(log.PKI_OSERROR_1, exc,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure == True:
                    sys.exit(1)
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
                        sys.exit(1)
                # Always re-process each file whether it needs it or not
                if not silent:
                    config.pki_log.info(log.PKIHELPER_MODIFY_FILE_1, name,
                                        extra=config.PKI_INDENTATION_LEVEL_2)
                # chmod <perms> <name>
                if not silent:
                    config.pki_log.debug(log.PKIHELPER_CHMOD_2, perms, name,
                                         extra=config.PKI_INDENTATION_LEVEL_3)
                if not config.pki_dry_run_flag:
                    os.chmod(name, perms)
                # chown <uid>:<gid> <name>
                if uid == None:
                    uid = identity.get_uid()
                if gid == None:
                    gid = identity.get_gid()
                if not silent:
                    config.pki_log.debug(log.PKIHELPER_CHOWN_3,
                                         uid, gid, name,
                                         extra=config.PKI_INDENTATION_LEVEL_3)
                if not config.pki_dry_run_flag:
                    os.chown(name, uid, gid)
                # Store record in installation manifest
                if not silent:
                    record = manifest.record()
                    record.name = name
                    record.type = manifest.RECORD_TYPE_FILE
                    record.user = master['pki_user']
                    record.group = master['pki_group']
                    record.uid = uid
                    record.gid = gid
                    record.permissions = perms
                    record.acls = acls
                    manifest.database.append(record)
            else:
                config.pki_log.error(
                    log.PKI_FILE_MISSING_OR_NOT_A_FILE_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure == True:
                    sys.exit(1)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
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
                if not config.pki_dry_run_flag:
                    os.remove(name)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
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
            sys.exit(1)

    def copy(self, old_name, new_name, uid=None, gid=None,
             perms=config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS, acls=None,
             overwrite_flag=False, critical_failure=True):
        try:
            if config.pki_dry_run_flag:
                # cp -p <old_name> <new_name>
                config.pki_log.info(log.PKIHELPER_CP_P_2,
                                    old_name, new_name,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                # chmod <perms> <new_name>
                config.pki_log.debug(log.PKIHELPER_CHMOD_2,
                                     perms, new_name,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
                # chown <uid>:<gid> <new_name>
                config.pki_log.debug(log.PKIHELPER_CHOWN_3,
                                     uid, gid, new_name,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
            elif not os.path.exists(old_name) or not os.path.isfile(old_name):
                config.pki_log.error(
                    log.PKI_FILE_MISSING_OR_NOT_A_FILE_1, old_name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
            else:
                if os.path.exists(new_name):
                    if not overwrite_flag:
                        config.pki_log.error(
                            log.PKI_FILE_ALREADY_EXISTS_1, new_name,
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        sys.exit(1)
                # cp -p <old_name> <new_name>
                config.pki_log.info(log.PKIHELPER_CP_P_2,
                                    old_name, new_name,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                shutil.copy2(old_name, new_name)
                if uid == None:
                    uid = identity.get_uid()
                if gid == None:
                    gid = identity.get_gid()
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
                record = manifest.record()
                record.name = new_name
                record.type = manifest.RECORD_TYPE_FILE
                record.user = master['pki_user']
                record.group = master['pki_group']
                record.uid = uid
                record.gid = gid
                record.permissions = perms
                record.acls = acls
                manifest.database.append(record)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
        except shutil.Error as exc:
            config.pki_log.error(log.PKI_SHUTIL_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
        return

    def apply_slot_substitution(
                         self, name, uid=None, gid=None,
                         perms=config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS,
                         acls=None, critical_failure=True):
        try:
            if config.pki_dry_run_flag:
                # applying in-place slot substitutions on <name>
                config.pki_log.info(log.PKIHELPER_APPLY_SLOT_SUBSTITUTION_1,
                                    name,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                # NOTE:  During dry_run, this file may not exist!
                if os.path.exists(name) and os.path.isfile(name):
                    for line in fileinput.FileInput(name, inplace=1):
                        for slot in slots:
                            if slot != '__name__' and slots[slot] in line:
                                config.pki_log.debug(
                                    log.PKIHELPER_SLOT_SUBSTITUTION_2,
                                    slots[slot], master[slot],
                                    extra=config.PKI_INDENTATION_LEVEL_3)
                # chmod <perms> <name>
                config.pki_log.debug(log.PKIHELPER_CHMOD_2,
                                     perms, name,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
                # chown <uid>:<gid> <name>
                config.pki_log.debug(log.PKIHELPER_CHOWN_3,
                                     uid, gid, name,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
            else:
                if not os.path.exists(name) or not os.path.isfile(name):
                    config.pki_log.error(
                        log.PKI_FILE_MISSING_OR_NOT_A_FILE_1, name,
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
                # applying in-place slot substitutions on <name>
                config.pki_log.info(log.PKIHELPER_APPLY_SLOT_SUBSTITUTION_1,
                                    name,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                for line in fileinput.FileInput(name, inplace=1):
                    for slot in slots:
                        if slot != '__name__' and slots[slot] in line:
                            config.pki_log.debug(
                                log.PKIHELPER_SLOT_SUBSTITUTION_2,
                                slots[slot], master[slot],
                                extra=config.PKI_INDENTATION_LEVEL_3)
                            line=line.replace(slots[slot],master[slot])
                    sys.stdout.write(line)
                if uid == None:
                    uid = identity.get_uid()
                if gid == None:
                    gid = identity.get_gid()
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
                record = manifest.record()
                record.name = name
                record.type = manifest.RECORD_TYPE_FILE
                record.user = master['pki_user']
                record.group = master['pki_group']
                record.uid = uid
                record.gid = gid
                record.permissions = perms
                record.acls = acls
                manifest.database.append(record)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
        except shutil.Error as exc:
            config.pki_log.error(log.PKI_SHUTIL_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
        return

    def copy_with_slot_substitution(
                         self, old_name, new_name, uid=None, gid=None,
                         perms=config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS,
                         acls=None, overwrite_flag=False,
                         critical_failure=True):
        try:
            if config.pki_dry_run_flag:
                # copy <old_name> to <new_name> with slot substitutions
                config.pki_log.info(log.PKIHELPER_COPY_WITH_SLOT_SUBSTITUTION_2,
                                    old_name, new_name,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                for line in fileinput.FileInput(old_name):
                    for slot in slots:
                        if slot != '__name__' and slots[slot] in line:
                            config.pki_log.debug(
                                log.PKIHELPER_SLOT_SUBSTITUTION_2,
                                slots[slot], master[slot],
                                extra=config.PKI_INDENTATION_LEVEL_3)
                # chmod <perms> <new_name>
                config.pki_log.debug(log.PKIHELPER_CHMOD_2,
                                     perms, new_name,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
                # chown <uid>:<gid> <new_name>
                config.pki_log.debug(log.PKIHELPER_CHOWN_3,
                                     uid, gid, new_name,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
            elif not os.path.exists(old_name) or not os.path.isfile(old_name):
                config.pki_log.error(
                    log.PKI_FILE_MISSING_OR_NOT_A_FILE_1, old_name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
            else:
                if os.path.exists(new_name):
                    if not overwrite_flag:
                        config.pki_log.error(
                            log.PKI_FILE_ALREADY_EXISTS_1, new_name,
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        sys.exit(1)
                # copy <old_name> to <new_name> with slot substitutions
                config.pki_log.info(log.PKIHELPER_COPY_WITH_SLOT_SUBSTITUTION_2,
                                    old_name, new_name,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                FILE = open(new_name, "w")
                for line in fileinput.FileInput(old_name):
                    for slot in slots:
                        if slot != '__name__' and slots[slot] in line:
                            config.pki_log.debug(
                                log.PKIHELPER_SLOT_SUBSTITUTION_2,
                                slots[slot], master[slot],
                                extra=config.PKI_INDENTATION_LEVEL_3)
                            line=line.replace(slots[slot],master[slot])
                    FILE.write(line)
                FILE.close()
                if uid == None:
                    uid = identity.get_uid()
                if gid == None:
                    gid = identity.get_gid()
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
                record = manifest.record()
                record.name = new_name
                record.type = manifest.RECORD_TYPE_FILE
                record.user = master['pki_user']
                record.group = master['pki_group']
                record.uid = uid
                record.gid = gid
                record.permissions = perms
                record.acls = acls
                manifest.database.append(record)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
        except shutil.Error as exc:
            config.pki_log.error(log.PKI_SHUTIL_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
        return

    def generate_noise_file(self, name, bytes, uid=None, gid=None,
            perms=config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS,
            acls=None, critical_failure=True):
        try:
            if not os.path.exists(name):
                # generating noise file called <name> and
                # filling it with <bytes> random bytes
                config.pki_log.info(log.PKIHELPER_NOISE_FILE_2, name, bytes,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                if not config.pki_dry_run_flag:
                    open(name, "w").close()
                    FILE = open(name, "w")
                    noise = ''.join(random.choice(string.ascii_letters +\
                            string.digits) for x in range(bytes))
                    FILE.write(noise)
                    FILE.close()
                # chmod <perms> <name>
                config.pki_log.debug(log.PKIHELPER_CHMOD_2, perms, name,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
                if not config.pki_dry_run_flag:
                    os.chmod(name, perms)
                # chown <uid>:<gid> <name>
                if uid == None:
                    uid = identity.get_uid()
                if gid == None:
                    gid = identity.get_gid()
                config.pki_log.debug(log.PKIHELPER_CHOWN_3,
                                     uid, gid, name,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
                if not config.pki_dry_run_flag:
                    os.chown(name, uid, gid)
                # Store record in installation manifest
                record = manifest.record()
                record.name = name
                record.type = manifest.RECORD_TYPE_FILE
                record.user = master['pki_user']
                record.group = master['pki_group']
                record.uid = uid
                record.gid = gid
                record.permissions = perms
                record.acls = acls
                manifest.database.append(record)
            elif not os.path.isfile(name):
                config.pki_log.error(
                    log.PKI_FILE_ALREADY_EXISTS_NOT_A_FILE_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure == True:
                    sys.exit(1)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                pass
            else:
                config.pki_log.error(log.PKI_OSERROR_1, exc,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure == True:
                    sys.exit(1)
        return


# PKI Deployment Symbolic Link Class
class symlink:
    def create(self, name, link, uid=None, gid=None,
               acls=None, allow_dangling_symlink=False, critical_failure=True):
        try:
            if not os.path.exists(link):
                if not config.pki_dry_run_flag:
                    if not os.path.exists(name):
                        config.pki_log.warning(
                            log.PKIHELPER_DANGLING_SYMLINK_2, link, name,
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        if not allow_dangling_symlink:
                            sys.exit(1)
                # ln -s <name> <link>
                config.pki_log.info(log.PKIHELPER_LINK_S_2, name, link,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                if not config.pki_dry_run_flag:
                    os.symlink(name, link)
                # REMINDER:  Due to POSIX compliance, 'lchmod' is NEVER
                #            implemented on Linux systems since 'chmod'
                #            CANNOT be run directly against symbolic links!
                # chown -h <uid>:<gid> <link>
                if uid == None:
                    uid = identity.get_uid()
                if gid == None:
                    gid = identity.get_gid()
                config.pki_log.debug(log.PKIHELPER_CHOWN_H_3,
                                     uid, gid, link,
                                     extra=config.PKI_INDENTATION_LEVEL_3)
                if not config.pki_dry_run_flag:
                    os.lchown(link, uid, gid)
                # Store record in installation manifest
                record = manifest.record()
                record.name = link
                record.type = manifest.RECORD_TYPE_SYMLINK
                record.user = master['pki_user']
                record.group = master['pki_group']
                record.uid = uid
                record.gid = gid
                record.permissions =\
                    config.PKI_DEPLOYMENT_DEFAULT_SYMLINK_PERMISSIONS
                record.acls = acls
                manifest.database.append(record)
            elif not os.path.islink(link):
                config.pki_log.error(
                    log.PKI_SYMLINK_ALREADY_EXISTS_NOT_A_SYMLINK_1, link,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure == True:
                    sys.exit(1)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                pass
            else:
                config.pki_log.error(log.PKI_OSERROR_1, exc,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure == True:
                    sys.exit(1)
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
                        sys.exit(1)
                # Always re-process each link whether it needs it or not
                if not silent:
                    config.pki_log.info(log.PKIHELPER_MODIFY_SYMLINK_1, link,
                                        extra=config.PKI_INDENTATION_LEVEL_2)
                # REMINDER:  Due to POSIX compliance, 'lchmod' is NEVER
                #            implemented on Linux systems since 'chmod'
                #            CANNOT be run directly against symbolic links!
                # chown -h <uid>:<gid> <link>
                if uid == None:
                    uid = identity.get_uid()
                if gid == None:
                    gid = identity.get_gid()
                if not silent:
                    config.pki_log.debug(log.PKIHELPER_CHOWN_H_3,
                                         uid, gid, link,
                                         extra=config.PKI_INDENTATION_LEVEL_3)
                if not config.pki_dry_run_flag:
                    os.lchown(link, uid, gid)
                # Store record in installation manifest
                if not silent:
                    record = manifest.record()
                    record.name = link
                    record.type = manifest.RECORD_TYPE_SYMLINK
                    record.user = master['pki_user']
                    record.group = master['pki_group']
                    record.uid = uid
                    record.gid = gid
                    record.permissions =\
                        config.PKI_DEPLOYMENT_DEFAULT_SYMLINK_PERMISSIONS
                    record.acls = acls
                    manifest.database.append(record)
            else:
                config.pki_log.error(
                    log.PKI_SYMLINK_MISSING_OR_NOT_A_SYMLINK_1, link,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure == True:
                    sys.exit(1)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
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
                if not config.pki_dry_run_flag:
                    os.remove(link)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
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
            sys.exit(1)


# PKI Deployment War File Class
class war:
    def explode(self, name, path, critical_failure=True):
        try:
            if os.path.exists(name) and os.path.isfile(name):
                if not zipfile.is_zipfile(name):
                    config.pki_log.error(
                        log.PKI_FILE_NOT_A_WAR_FILE_1,
                        name, extra=config.PKI_INDENTATION_LEVEL_2)
                    if critical_failure == True:
                        sys.exit(1)
                if not config.pki_dry_run_flag:
                    if not os.path.exists(path) or not os.path.isdir(path):
                        config.pki_log.error(
                            log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1,
                            path, extra=config.PKI_INDENTATION_LEVEL_2)
                        if critical_failure == True:
                            sys.exit(1)
                # jar -xf <name> -C <path>
                config.pki_log.info(log.PKIHELPER_JAR_XF_C_2, name, path,
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                if not config.pki_dry_run_flag:
                    # Open war file
                    war = zipfile.ZipFile(name, 'r')
                    # Extract contents of war file to path
                    war.extractall(path)
            else:
                config.pki_log.error(
                    log.PKI_FILE_MISSING_OR_NOT_A_FILE_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                if critical_failure == True:
                    sys.exit(1)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
        except zipfile.BadZipfile as exc:
            config.pki_log.error(log.PKI_BADZIPFILE_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
        except zipfile.LargeZipFile as exc:
            config.pki_log.error(log.PKI_LARGEZIPFILE_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
        return


# PKI Deployment Password Class
class password:
    def create_password_conf(self, path, pin, pin_sans_token=False,
                             overwrite_flag=False, critical_failure=True):
        try:
            if not config.pki_dry_run_flag:
                if os.path.exists(path):
                    if overwrite_flag:
                        config.pki_log.info(
                            log.PKIHELPER_PASSWORD_CONF_1, path,
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        # overwrite the existing 'password.conf' file
                        with open(path, "wt") as fd:
                            if pin_sans_token == True:
                                fd.write(str(pin))
                            elif master['pki_subsystem'] in\
                               config.PKI_APACHE_SUBSYSTEMS:
                                fd.write(master['pki_self_signed_token'] +\
                                         ":" + str(pin))
                            else:
                                fd.write(master['pki_self_signed_token'] +\
                                         "=" + str(pin))
                        fd.closed
                else:
                    config.pki_log.info(log.PKIHELPER_PASSWORD_CONF_1, path,
                                        extra=config.PKI_INDENTATION_LEVEL_2)
                    # create a new 'password.conf' file
                    with open(path, "wt") as fd:
                        if pin_sans_token == True:
                            fd.write(str(pin))
                        elif master['pki_subsystem'] in\
                           config.PKI_APACHE_SUBSYSTEMS:
                            fd.write(master['pki_self_signed_token'] +\
                                     ":" + str(pin))
                        else:
                            fd.write(master['pki_self_signed_token'] +\
                                     "=" + str(pin))
                    fd.closed
            else:
                if not os.path.exists(path) or overwrite_flag:
                    config.pki_log.info(log.PKIHELPER_PASSWORD_CONF_1, path,
                                        extra=config.PKI_INDENTATION_LEVEL_2)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
        return

    def create_client_pkcs12_password_conf(self, path, overwrite_flag=False,
                                           critical_failure=True):
        try:
            if not config.pki_dry_run_flag:
                if os.path.exists(path):
                    if overwrite_flag:
                        config.pki_log.info(
                            log.PKIHELPER_PASSWORD_CONF_1, path,
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        # overwrite the existing 'pkcs12_password.conf' file
                        with open(path, "wt") as fd:
                            fd.write(sensitive['pki_client_pkcs12_password'])
                        fd.closed
                else:
                    config.pki_log.info(log.PKIHELPER_PASSWORD_CONF_1, path,
                                        extra=config.PKI_INDENTATION_LEVEL_2)
                    # create a new 'pkcs12_password.conf' file
                    with open(path, "wt") as fd:
                        fd.write(sensitive['pki_client_pkcs12_password'])
                    fd.closed
            else:
                if not os.path.exists(path) or overwrite_flag:
                    config.pki_log.info(log.PKIHELPER_PASSWORD_CONF_1, path,
                                        extra=config.PKI_INDENTATION_LEVEL_2)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
        return


# PKI Deployment NSS 'certutil' Class
class certutil:
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
                sys.exit(1)
            if password_file != None:
                command = command + " " + "-f" + " " + password_file
            if prefix != None:
                command = command + " " + "-P" + " " + prefix
            if not config.pki_dry_run_flag:
                if not os.path.exists(path):
                    config.pki_log.error(
                        log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, path,
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
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
                            sys.exit(1)
                    # Display this "certutil" command
                    config.pki_log.info(
                        log.PKIHELPER_CREATE_SECURITY_DATABASES_1,
                        command,
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    # Execute this "certutil" command
                    subprocess.call(command, shell=True)
            else:
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
                    # Display this "certutil" command
                    config.pki_log.info(
                        log.PKIHELPER_CREATE_SECURITY_DATABASES_1,
                        command,
                        extra=config.PKI_INDENTATION_LEVEL_2)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
        return

    def verify_certificate_exists(self, path, pki_cert_database,
                                  pki_key_database, pki_secmod_database,
                                  token, nickname, password_file=None,
                                  silent=True):
        rv = 0
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
                sys.exit(1)
            #   Specify the 'token'
            if token:
                command = command + " " + "-h" + " " + "'" + token + "'"
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_TOKEN,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
            #   Specify the nickname of this self-signed certificate
            if nickname:
                command = command + " " + "-n" + " " + "'" + nickname + "'"
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_NICKNAME,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
            #   OPTIONALLY specify a password file
            if password_file != None:
                command = command + " " + "-f" + " " + password_file
            #   By default, execute this command silently
            if silent != False:
                command = command + " > /dev/null 2>&1"
            if not config.pki_dry_run_flag:
                if not os.path.exists(path):
                    config.pki_log.error(
                        log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, path,
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
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
                    sys.exit(1)
                if password_file != None:
                    if not os.path.exists(password_file) or\
                       not os.path.isfile(password_file):
                        config.pki_log.error(
                            log.PKI_FILE_MISSING_OR_NOT_A_FILE_1,
                            password_file,
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        sys.exit(1)
            else:
                # Check for first time through as dry_run
                if not os.path.exists(pki_cert_database) or\
                   not os.path.exists(pki_key_database) or\
                   not os.path.exists(pki_secmod_database):
                    return False
            # Execute this "certutil" command
            subprocess.check_call(command, shell=True)
        except subprocess.CalledProcessError as exc:
            return False
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
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
                sys.exit(1)
            #   Specify the 'token'
            if token:
                command = command + " " + "-h" + " " + "'" + token + "'"
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_TOKEN,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
            #   Specify the nickname of this self-signed certificate
            if nickname:
                command = command + " " + "-n" + " " + "'" + nickname + "'"
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_NICKNAME,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
            #   Specify the subject name (RFC1485)
            if subject:
                command = command + " " + "-s" + " " + "'" + subject + "'"
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_SUBJECT,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
            #   Specify the serial number
            if serial_number != None:
                command = command + " " + "-m" + " " + str(serial_number)
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_SERIAL_NUMBER,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
            #   Specify the months valid
            if validity_period != None:
                command = command + " " + "-v" + " " + str(validity_period)
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_VALIDITY_PERIOD,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
            #   Specify the nickname of the issuer certificate
            if issuer_name:
                command = command + " " + "-c" + " " +\
                      "'" + issuer_name + "'"
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_ISSUER_NAME,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
            #   Specify the certificate trust attributes
            if trustargs:
                command = command + " " + "-t" + " " + "'" + trustargs + "'"
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_TRUSTARGS,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
            #   Specify a noise file to be used for key generation
            if noise_file:
                command = command + " " + "-z" + " " + noise_file
            else:
                config.pki_log.error(
                    log.PKIHELPER_CERTUTIL_MISSING_NOISE_FILE,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
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
            if not config.pki_dry_run_flag:
                if not os.path.exists(path):
                    config.pki_log.error(
                        log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, path,
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
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
                    sys.exit(1)
                if not os.path.exists(noise_file):
                    config.pki_log.error(
                        log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1,
                        noise_file,
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
                if password_file != None:
                    if not os.path.exists(password_file) or\
                       not os.path.isfile(password_file):
                        config.pki_log.error(
                            log.PKI_FILE_MISSING_OR_NOT_A_FILE_1,
                            password_file,
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        sys.exit(1)
                # Execute this "certutil" command
                subprocess.call(command, shell=True)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
        return


# PKI Deployment 'systemd' Execution Management Class
class systemd:
    def start(self, critical_failure=True):
        try:
            # Compose this "systemd" execution management command
            if master['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS:
                command = "systemctl" + " " +\
                          "start" + " " +\
                          "pki-apached" + "@" +\
                          master['pki_instance_id'] + "." + "service"
            elif master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
                command = "systemctl" + " " +\
                          "start" + " " +\
                          "pki-tomcatd" + "@" +\
                          master['pki_instance_id'] + "." + "service"
            # Display this "systemd" execution managment command
            config.pki_log.info(
                log.PKIHELPER_SYSTEMD_COMMAND_1, command,
                extra=config.PKI_INDENTATION_LEVEL_2)
            if not config.pki_dry_run_flag:
                # Execute this "systemd" execution management command
                subprocess.call(command, shell=True)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
        return

    def stop(self, critical_failure=True):
        try:
            # Compose this "systemd" execution management command
            if master['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS:
                command = "systemctl" + " " +\
                          "stop" + " " +\
                          "pki-apached" + "@" +\
                          master['pki_instance_id'] + "." + "service"
            elif master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
                command = "systemctl" + " " +\
                          "stop" + " " +\
                          "pki-tomcatd" + "@" +\
                          master['pki_instance_id'] + "." + "service"
            # Display this "systemd" execution managment command
            config.pki_log.info(
                log.PKIHELPER_SYSTEMD_COMMAND_1, command,
                extra=config.PKI_INDENTATION_LEVEL_2)
            if not config.pki_dry_run_flag:
                # Execute this "systemd" execution management command
                subprocess.call(command, shell=True)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
        return

    def restart(self, critical_failure=True):
        try:
            # Compose this "systemd" execution management command
            if master['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS:
                command = "systemctl" + " " +\
                          "restart" + " " +\
                          "pki-apached" + "@" +\
                          master['pki_instance_id'] + "." + "service"
            elif master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
                command = "systemctl" + " " +\
                          "restart" + " " +\
                          "pki-tomcatd" + "@" +\
                          master['pki_instance_id'] + "." + "service"
            # Display this "systemd" execution managment command
            config.pki_log.info(
                log.PKIHELPER_SYSTEMD_COMMAND_1, command,
                extra=config.PKI_INDENTATION_LEVEL_2)
            if not config.pki_dry_run_flag:
                # Execute this "systemd" execution management command
                subprocess.call(command, shell=True)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
        return


# PKI Deployment 'jython' Class
class jython:
    def invoke(self, scriptlet, critical_failure=True):
        try:
            # From 'http://www.jython.org/archive/22/userfaq.html':
            # Setting this to false will allow Jython to provide access to
            # non-public fields, methods, and constructors of Java objects.
            property = "-Dpython.security.respectJavaAccessibility=false"
            # comment the next line out to use the "property" defined above
            property = ""
            # Compose this "jython" command
            data = pickle.dumps(master)
            sensitive_data = pickle.dumps(sensitive)
            ld_library_path = "LD_LIBRARY_PATH"
            if master['pki_architecture'] == 64:
                ld_library_path = ld_library_path + "=" +\
                                  "/usr/lib64/jss:/usr/lib64:/lib64:" +\
                                  "/usr/lib/jss:/usr/lib:/lib"
            else:
                ld_library_path = ld_library_path + "=" +\
                                  "/usr/lib/jss:/usr/lib:/lib"
            command = "export" + " " + ld_library_path + ";" + "jython" + " " +\
                      property + " " + scriptlet + " " + "\"" + data + "\"" +\
                      " " + "\"" + sensitive_data + "\""
            # Display this "jython" command
            config.pki_log.info(
                log.PKIHELPER_INVOKE_JYTHON_3,
                ld_library_path, property, scriptlet,
                extra=config.PKI_INDENTATION_LEVEL_2)
            # Invoke this "jython" command
            subprocess.call(command, shell=True)
        except subprocess.CalledProcessError as exc:
            config.pki_log.error(log.PKI_SUBPROCESS_ERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            if critical_failure == True:
                sys.exit(1)
        return


# PKI Deployment Helper Class Instances
identity = identity()
namespace = namespace()
configuration_file = configuration_file()
#xml_file = xml_file()
instance = instance()
directory = directory()
file = file()
symlink = symlink()
war = war()
password = password()
certutil = certutil()
systemd = systemd()
jython = jython()
