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
import getpass
import logging
import sys
import os
import re
import requests
import shutil
import subprocess
from grp import getgrgid
from grp import getgrnam
from pwd import getpwnam
from pwd import getpwuid

# PKI Deployment Imports
from . import pkiconfig as config
from .pkiconfig import pki_selinux_config_ports as ports
from . import pkimanifest as manifest
from . import pkimessages as log
from .pkiparser import PKIConfigParser

import pki.nssdb
import pki.server
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

logger = logging.getLogger(__name__)


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

        except KeyError as e:
            # No, group 'pki_group' does not exist!
            logger.debug(log.PKIHELPER_GROUP_ADD_KEYERROR_1, e)
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
                with open(os.devnull, "w", encoding='utf-8') as fnull:
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

        except KeyError as e:
            # No, user 'pki_user' does not exist!
            logger.debug(log.PKIHELPER_USER_ADD_KEYERROR_1, e)
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
                with open(os.devnull, "w", encoding='utf-8') as fnull:
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
                with open(os.devnull, "w", encoding='utf-8') as fnull:
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


class ConfigurationFile:
    """PKI Deployment Configuration File Class"""

    def __init__(self, deployer):
        self.deployer = deployer
        self.mdict = deployer.mdict
        # set useful 'boolean' object variables for this class
        self.clone = config.str2bool(self.mdict['pki_clone'])
        # generic extension support in CSR - for external CA
        self.add_req_ext = config.str2bool(
            self.mdict['pki_req_ext_add'])
        # include SKI extension in CSR - for external CA
        self.req_ski = self.mdict.get('pki_req_ski')

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

        # set useful 'string' object variables for this class
        self.subsystem = deployer.subsystem_type

    def confirm_external(self):
        # ALWAYS defined via 'pkiparser.py'
        if self.external:
            # Only allowed for External CA/KRA/OCSP/TKS/TPS.
            if self.subsystem not in ['CA', 'KRA', 'OCSP', 'TKS', 'TPS']:
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
            if (self.subsystem not in ['CA', 'KRA', 'OCSP', 'TKS', 'TPS'] and
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
        if self.deployer.ds_url.scheme == 'ldaps':
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


class Directory:
    """PKI Deployment Directory Class"""

    def __init__(self, deployer):
        self.deployer = deployer
        self.mdict = deployer.mdict
        self.identity = deployer.identity

    def create(self, name, uid=None, gid=None,
               perms=pki.server.DEFAULT_DIR_MODE,
               acls=None, critical_failure=True):

        logger.info('Creating %s', name)

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
               perms=pki.server.DEFAULT_DIR_MODE,
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
            dir_perms=pki.server.DEFAULT_DIR_MODE,
            file_perms=pki.server.DEFAULT_FILE_MODE,
            symlink_perms=pki.server.DEFAULT_LINK_MODE,
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
             dir_perms=pki.server.DEFAULT_DIR_MODE,
             file_perms=pki.server.DEFAULT_FILE_MODE,
             symlink_perms=pki.server.DEFAULT_LINK_MODE,
             dir_acls=None, file_acls=None, symlink_acls=None,
             recursive_flag=True, overwrite_flag=False, critical_failure=True,
             ignore_cb=None):

        logger.info('Creating %s', new_name)

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
        self.identity = deployer.identity

    def create(self, name, uid=None, gid=None,
               perms=pki.server.DEFAULT_FILE_MODE,
               acls=None, critical_failure=True):
        try:
            if not os.path.exists(name):

                logger.debug('Command: touch %s', name)
                open(name, "w", encoding='utf-8').close()

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
               perms=pki.server.DEFAULT_FILE_MODE,
               acls=None, silent=False, critical_failure=True):

        if not silent:
            logger.info('Updating %s', name)

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

        logger.info('Removing %s', name)

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
             perms=pki.server.DEFAULT_FILE_MODE,
             acls=None,
             overwrite_flag=False, critical_failure=True):

        logger.info('Creating %s', new_name)

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
            perms=pki.server.DEFAULT_FILE_MODE,
            acls=None, overwrite_flag=False,
            critical_failure=True):

        logger.info('Creating %s', new_name)

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
                params=self.mdict,
                uid=uid,
                gid=gid,
                mode=perms,
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

        logger.info('Creating %s', link)

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
                    pki.server.DEFAULT_LINK_MODE,
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
                        pki.server.DEFAULT_LINK_MODE,
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
                with open(path, 'w', encoding='utf-8') as fd:
                    fd.write(str(pin))
                return

            token = self.mdict['pki_self_signed_token']
            if pki.nssdb.internal_token(token):
                token = pki.nssdb.INTERNAL_TOKEN_NAME

            with open(path, 'w', encoding='utf-8') as fd:
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
                    with open(path, "w", encoding='utf-8') as fd:
                        fd.write(self.mdict['pki_client_pkcs12_password'])
            else:
                # create a new 'pkcs12_password.conf' file
                with open(path, "w", encoding='utf-8') as fd:
                    fd.write(self.mdict['pki_client_pkcs12_password'])
        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            if critical_failure:
                raise
        return

    def get_password(self, path, token_name):

        logger.info('Getting password for %s', token_name)

        token_pwd = None
        if os.path.exists(path) and os.path.isfile(path):

            passwords = {}

            logger.info('Loading passwords from %s:', path)
            pki.util.load_properties(path, passwords)

            for key in passwords:
                logger.info('- %s: ********', key)

            hardware_token = "hardware-" + token_name
            if hardware_token in passwords:
                token_name = hardware_token
                token_pwd = passwords[hardware_token]

            elif token_name in passwords:
                token_pwd = passwords[token_name]

        if token_pwd is None:
            token_pwd = getpass.getpass('Password for token {}'.format(token_name))

        return token_pwd


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
            logger.debug(log.PKIHELPER_NCIPHER_RESTART_1, ' '.join(command))
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

        logger.info('Creating %s', path)

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
            logger.debug('Command: %s', ' '.join(command))
            # Execute this "certutil" command
            if silent:
                # By default, execute this command silently
                with open(os.devnull, "w", encoding='utf-8') as fnull:
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

            # encrypt private keys with PKCS#5 PBES2
            command.extend(["-c", "AES-128-CBC"])
            # don't encrypt public certs
            command.extend(["-C", "NONE"])

            logger.debug('Command: %s', ' '.join(command))
            with open(os.devnull, "w", encoding='utf-8') as fnull:
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

    def deregister(self, instance, subsystem):

        # this is applicable to KRAs only
        if self.mdict['pki_subsystem_type'] != "kra":
            return

        logger.info('Removing KRA connector from all CAs subsystems')

        cs_cfg = PKIConfigParser.read_simple_configuration_file(subsystem.cs_conf)
        krahost = cs_cfg.get('machineName')

        server_config = instance.get_server_config()
        kraport = server_config.get_secure_port()

        proxy_secure_port = cs_cfg.get('proxy.securePort', '')

        if proxy_secure_port != '':
            kraport = proxy_secure_port

        # retrieve subsystem nickname
        subsystemnick = cs_cfg.get('kra.cert.subsystem.nickname')

        if subsystemnick is None:
            logger.warning(log.PKIHELPER_KRACONNECTOR_UPDATE_FAILURE)
            logger.error(log.PKIHELPER_UNDEFINED_SUBSYSTEM_NICKNAME)
            raise Exception(log.PKIHELPER_UNDEFINED_SUBSYSTEM_NICKNAME)

        # retrieve name of token based upon type (hardware/software)
        if ':' in subsystemnick:
            token_name = subsystemnick.split(':')[0]
        else:
            token_name = pki.nssdb.INTERNAL_TOKEN_NAME

        token_pwd = self.password.get_password(
            instance.password_conf,
            token_name)

        if token_pwd is None or token_pwd == '':
            logger.warning(log.PKIHELPER_KRACONNECTOR_UPDATE_FAILURE)
            logger.error(
                log.PKIHELPER_UNDEFINED_TOKEN_PASSWD_1,
                token_name)
            raise Exception(
                log.PKIHELPER_UNDEFINED_TOKEN_PASSWD_1 % token_name)

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

        logger.info('Getting security domain info from https://%s:%s', sechost, secport)

        ca_cert = os.path.join(instance.nssdb_dir, 'ca.crt')

        try:
            ca_list = self.get_ca_list_from_security_domain(
                sechost, secport, ca_cert)
        except Exception as e:
            logger.error(
                "unable to access security domain. Continuing .. %s ",
                e)
            ca_list = []

        for ca in ca_list:
            ca_host = ca.Hostname
            ca_port = ca.SecurePort

            ca_url = 'https://%s:%s' % (ca_host, ca_port)
            logger.info('Removing KRA connector from CA at %s', ca_url)

            # catching all exceptions because we do not want to break if
            # the auth is not successful or servers are down.  In the
            # worst case, we will time out anyways.
            # noinspection PyBroadException
            # pylint: disable=W0703
            try:
                result = self.execute_using_pki(
                    instance, ca_url, subsystemnick,
                    token_pwd, krahost, kraport)
                logger.debug('Output:\n%s', result.stdout.strip())
            except subprocess.CalledProcessError as e:
                # ignore exceptions
                logger.warning('Unable to remove KRA connector: %s', e.stderr.strip())
                logger.warning('To remove KRA connector manually:')
                logger.warning(
                    '$ pki -U %s -n <admin> ca-kraconnector-del --host %s --port %s',
                    ca_url,
                    krahost,
                    kraport)

    @staticmethod
    def get_ca_list_from_security_domain(sechost, secport, cert_paths):
        sd_connection = pki.client.PKIConnection(
            protocol='https',
            hostname=sechost,
            port=secport,
            trust_env=False,
            cert_paths=cert_paths)
        sd = pki.system.SecurityDomainClient(sd_connection)
        try:
            info = sd.get_domain_info()
        except requests.exceptions.HTTPError as e:
            logger.warning('Unable to get CA list from security domain: %s', e)
            logger.info('Trying older interface.')
            info = sd.get_old_domain_info()
        return list(info.subsystems['CA'].hosts.values())

    def execute_using_pki(
            self, instance, ca_url, subsystemnick,
            token_pwd, krahost, kraport):
        command = ["/usr/bin/pki",
                   "-U", ca_url,
                   "-n", subsystemnick,
                   "-P", "https",
                   "-d", instance.nssdb_dir,
                   "-c", token_pwd,
                   "--ignore-banner",
                   "ca-kraconnector-del",
                   "--host", krahost,
                   "--port", str(kraport)]

        # don't use capture_output and text params to support Python 3.6
        # https://stackoverflow.com/questions/53209127/subprocess-unexpected-keyword-argument-capture-output/53209196
        # https://stackoverflow.com/questions/52663518/python-subprocess-popen-doesnt-take-text-argument

        return subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            universal_newlines=True)


class TPSConnector:
    """PKI Deployment TPS Connector Class"""

    def __init__(self, deployer):
        self.mdict = deployer.mdict
        self.password = deployer.password

    def deregister(self, instance, subsystem):

        # this is applicable to TPSs only
        if self.mdict['pki_subsystem_type'] != "tps":
            return

        logger.info('Removing TPS connector from TKS subsystem')

        cs_cfg = PKIConfigParser.read_simple_configuration_file(subsystem.cs_conf)
        tpshost = cs_cfg.get('machineName')

        server_config = instance.get_server_config()
        tpsport = server_config.get_secure_port()

        tkshost = cs_cfg.get('tps.connector.tks1.host')
        tksport = cs_cfg.get('tps.connector.tks1.port')
        if tkshost is None or tksport is None:
            logger.warning(log.PKIHELPER_TPSCONNECTOR_UPDATE_FAILURE)
            logger.error(log.PKIHELPER_UNDEFINED_TKS_HOST_PORT)
            raise Exception(log.PKIHELPER_UNDEFINED_TKS_HOST_PORT)

        # retrieve subsystem nickname
        subsystemnick = cs_cfg.get('tps.cert.subsystem.nickname')
        if subsystemnick is None:
            logger.warning(log.PKIHELPER_TPSCONNECTOR_UPDATE_FAILURE)
            logger.error(log.PKIHELPER_UNDEFINED_SUBSYSTEM_NICKNAME)
            raise Exception(log.PKIHELPER_UNDEFINED_SUBSYSTEM_NICKNAME)

        self.execute_using_pki(
            instance, tkshost, tksport, subsystemnick,
            tpshost, tpsport)

    def execute_using_pki(
            self, instance, tkshost, tksport, subsystemnick,
            tpshost, tpsport, critical_failure=False):

        tks_url = 'https://%s:%s' % (tkshost, tksport)
        password_conf = os.path.join(
            instance.conf_dir,
            'password.conf')

        command = ["pki",
                   "-U", tks_url,
                   "-n", subsystemnick,
                   "-d", instance.nssdb_dir,
                   "-f", password_conf,
                   "--ignore-banner",
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
            with open(override_file, 'w', encoding='utf-8') as fp:
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
