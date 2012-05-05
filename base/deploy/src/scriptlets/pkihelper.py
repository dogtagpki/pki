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
import shutil
import string
import subprocess
from grp import getgrnam
from pwd import getpwnam
import zipfile


# PKI Deployment Imports
import pkiconfig as config
from pkiconfig import pki_master_dict as master
from pkiconfig import pki_slots_dict as slots
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


# PKI Deployment Instance Class
class instance:
    def apache_instances(self):
        rv = 0
        try:
            if not os.path.exists(master['pki_webserver_path']) or\
               not os.path.isdir(master['pki_webserver_path']):
                config.pki_log.error(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1,
                    master['pki_webserver_path'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
            # count number of PKI subsystems present
            # within the specfied Apache instance
            for subsystem in config.PKI_APACHE_SUBSYSTEMS:
                path = master['pki_webserver_path'] + "/" + subsystem.lower()
                if os.path.exists(path) and os.path.isdir(path):
                    rv = rv + 1
            # always display correct information (even during dry_run)
            if config.pki_dry_run_flag and rv > 0:
                config.pki_log.debug(log.PKIHELPER_APACHE_INSTANCES_2,
                                     master['pki_webserver_path'], rv - 1,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
            else:
                config.pki_log.debug(log.PKIHELPER_APACHE_INSTANCES_2,
                                     master['pki_webserver_path'],
                                     rv, extra=config.PKI_INDENTATION_LEVEL_2)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            sys.exit(1)
        return rv

    def pki_subsystem_instances(self):
        rv = 0
        try:
            if not os.path.exists(master['pki_instance_path']) or\
               not os.path.isdir(master['pki_instance_path']):
                config.pki_log.error(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1,
                    master['pki_instance_path'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
            # count total number of Apache PKI subsystems present
            # within the specfied PKI instance
            for apache_subsystem in config.PKI_APACHE_SUBSYSTEMS:
                apache_path = master['pki_instance_path'] + "/" + "apache" +\
                              "/" + apache_subsystem.lower()
                if os.path.exists(apache_path) and os.path.isdir(apache_path):
                    rv = rv + 1
            # count total number of Tomcat PKI subsystems present
            # within the specfied PKI instance
            for tomcat_subsystem in config.PKI_TOMCAT_SUBSYSTEMS:
                tomcat_path = master['pki_instance_path'] + "/" + "tomcat" +\
                              "/" + tomcat_subsystem.lower()
                if os.path.exists(tomcat_path) and os.path.isdir(tomcat_path):
                    rv = rv + 1
            # always display correct information (even during dry_run)
            if config.pki_dry_run_flag and rv > 0:
                config.pki_log.debug(log.PKIHELPER_PKI_SUBSYSTEM_INSTANCES_2,
                                     master['pki_instance_path'], rv - 1,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
            else:
                config.pki_log.debug(log.PKIHELPER_PKI_SUBSYSTEM_INSTANCES_2,
                                     master['pki_instance_path'], rv,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            sys.exit(1)
        return rv

    def tomcat_instances(self):
        rv = 0
        try:
            if not os.path.exists(master['pki_webserver_path']) or\
               not os.path.isdir(master['pki_webserver_path']):
                config.pki_log.error(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1,
                    master['pki_webserver_path'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
            # count number of PKI subsystems present
            # within the specfied Tomcat instance
            for subsystem in config.PKI_TOMCAT_SUBSYSTEMS:
                path = master['pki_webserver_path'] + "/" + subsystem.lower()
                if os.path.exists(path) and os.path.isdir(path):
                    rv = rv + 1
            # always display correct information (even during dry_run)
            if config.pki_dry_run_flag and rv > 0:
                config.pki_log.debug(log.PKIHELPER_TOMCAT_INSTANCES_2,
                                     master['pki_webserver_path'], rv - 1,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
            else:
                config.pki_log.debug(log.PKIHELPER_TOMCAT_INSTANCES_2,
                                     master['pki_webserver_path'],
                                     rv, extra=config.PKI_INDENTATION_LEVEL_2)
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
                                     master['pki_instance_name'],
                                     extra=config.PKI_INDENTATION_LEVEL_1)
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
                                     master['pki_instance_name'],
                                     extra=config.PKI_INDENTATION_LEVEL_1)
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
                config.pki_log.error(
                    log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
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
                config.pki_log.error(
                    log.PKI_FILE_MISSING_OR_NOT_A_FILE_1, name,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
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
                config.pki_log.error(
                    log.PKI_SYMLINK_MISSING_OR_NOT_A_SYMLINK_1, link,
                    extra=config.PKI_INDENTATION_LEVEL_2)
                sys.exit(1)
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
    def create_password_conf(self, path, overwrite_flag=False):
        try:
            if not config.pki_dry_run_flag:
                if os.path.exists(path):
                    if overwrite_flag:
                        config.pki_log.info(
                            log.PKIHELPER_PASSWORD_CONF_1, path,
                            extra=config.PKI_INDENTATION_LEVEL_2)
                        # overwrite the existing 'password.conf' file
                        with open(path, "wt") as fd:
                            if master['pki_subsystem'] in\
                               config.PKI_APACHE_SUBSYSTEMS:
                                fd.write("internal" + ":" +\
                                         str(master['pki_pin']))
                            else:
                                fd.write("internal" + "=" +\
                                         str(master['pki_pin']))
                        fd.closed
                else:
                    config.pki_log.info(log.PKIHELPER_PASSWORD_CONF_1, path,
                                        extra=config.PKI_INDENTATION_LEVEL_2)
                    # create a new 'password.conf' file
                    with open(path, "wt") as fd:
                        if master['pki_subsystem'] in\
                           config.PKI_APACHE_SUBSYSTEMS:
                            fd.write("internal" + ":" +\
                                     str(master['pki_pin']))
                        else:
                            fd.write("internal" + "=" +\
                                     str(master['pki_pin']))
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
    def create_security_databases(self, path, password_file=None, prefix=None,
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
                if os.path.exists(master['pki_cert_database']) or\
                   os.path.exists(master['pki_key_database']) or\
                   os.path.exists(master['pki_secmod_database']):
                    # Simply notify user that the security databases exist
                    config.pki_log.info(
                        log.PKI_SECURITY_DATABASES_ALREADY_EXIST_3,
                        master['pki_cert_database'],
                        master['pki_key_database'],
                        master['pki_secmod_database'],
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
                if os.path.exists(master['pki_cert_database']) or\
                   os.path.exists(master['pki_key_database']) or\
                   os.path.exists(master['pki_secmod_database']):
                    # Simply notify user that the security databases exist
                    config.pki_log.info(
                        log.PKI_SECURITY_DATABASES_ALREADY_EXIST_3,
                        master['pki_cert_database'],
                        master['pki_key_database'],
                        master['pki_secmod_database'],
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

    def verify_certificate_exists(self, path, token, nickname,
                                  password_file=None):
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
            #   Always execute this command silently
                command = command + " > /dev/null 2>&1"
            if not config.pki_dry_run_flag:
                if not os.path.exists(path):
                    config.pki_log.error(
                        log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1, path,
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
                if not os.path.exists(master['pki_cert_database']) or\
                   not os.path.exists(master['pki_key_database']) or\
                   not os.path.exists(master['pki_secmod_database']):
                    # NSS security databases MUST exist!
                    config.pki_log.error(
                        log.PKI_SECURITY_DATABASES_DO_NOT_EXIST_3,
                        master['pki_cert_database'],
                        master['pki_key_database'],
                        master['pki_secmod_database'],
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
                if not os.path.exists(master['pki_cert_database']) or\
                   not os.path.exists(master['pki_key_database']) or\
                   not os.path.exists(master['pki_secmod_database']):
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

    def generate_self_signed_certificate(self, path, token, nickname,
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
                if not os.path.exists(master['pki_cert_database']) or\
                   not os.path.exists(master['pki_key_database']) or\
                   not os.path.exists(master['pki_secmod_database']):
                    # NSS security databases MUST exist!
                    config.pki_log.error(
                        log.PKI_SECURITY_DATABASES_DO_NOT_EXIST_3,
                        master['pki_cert_database'],
                        master['pki_key_database'],
                        master['pki_secmod_database'],
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


# PKI Deployment Helper Class Instances
identity = identity()
instance = instance()
directory = directory()
file = file()
symlink = symlink()
war = war()
password = password()
certutil = certutil()
