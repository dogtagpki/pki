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

import getpass
import logging
import sys
import os
import subprocess
from grp import getgrgid
from grp import getgrnam
from pwd import getpwnam
from pwd import getpwuid

# PKI Deployment Imports
from . import pkiconfig as config
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

        try:
            # Does the specified 'pki_group' exist?
            pki_gid = getgrnam(pki_group)[2]

            logger.info('Reusing %s group (GID: %s)', pki_group, pki_gid)
            return

        except KeyError as e:
            # No, group 'pki_group' does not exist!
            logger.debug(log.PKIHELPER_GROUP_ADD_KEYERROR_1, e)

        logger.info('Creating %s group', pki_group)

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
                subprocess.check_call(command, stdout=fnull, stderr=fnull, close_fds=True)

        except subprocess.CalledProcessError as exc:
            logger.error(log.PKI_SUBPROCESS_ERROR_1, exc)
            raise

        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            raise

    def __add_uid(self, pki_user, pki_group):

        try:
            # Does the specified 'pki_user' exist?
            pki_uid = getpwnam(pki_user)[2]

            logger.info('Reusing %s user (UID: %s)', pki_user, pki_uid)
            return

        except KeyError as e:
            # No, user 'pki_user' does not exist!
            logger.debug(log.PKIHELPER_USER_ADD_KEYERROR_1, e)

        logger.info('Creating %s user', pki_user)

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
                subprocess.check_call(command, stdout=fnull, stderr=fnull, close_fds=True)

        except subprocess.CalledProcessError as exc:
            logger.error(log.PKI_SUBPROCESS_ERROR_1, exc)
            raise

        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            raise

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
            cmd = ['usermod', '-a', '-G', pki_group, pki_user]
            try:
                logger.debug('Command: %s', ' '.join(cmd))
                with open(os.devnull, 'w', encoding='utf-8') as fnull:
                    subprocess.check_call(cmd, stdout=fnull, stderr=fnull,
                                          close_fds=True)
            except subprocess.CalledProcessError as exc:
                logger.error(log.PKI_SUBPROCESS_ERROR_1, exc)
                raise
            except OSError as exc:
                logger.error(log.PKI_OSERROR_1, exc)
                raise
        return


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
            if self.subsystem not in ["KRA", "OCSP", "EST"]:
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
                if config.str2bool(self.mdict['pki_admin_setup']):
                    self.confirm_data_exists("pki_admin_cert_path")
                    self.confirm_file_exists("pki_admin_cert_path")
                # Stand-alone PKI Audit Signing Certificate (Step 2)
                # EST does not support audit at the moment
                if self.subsystem != "EST":
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

    def populate_selinux_ports(self, ports):

        tomcat_port = self.mdict['pki_tomcat_server_port']
        if tomcat_port != str(pki.server.DEFAULT_TOMCAT_PORT):
            ports.append(tomcat_port)

        http_port = self.mdict['pki_http_port']
        if http_port != str(pki.server.DEFAULT_TOMCAT_HTTP_PORT):
            ports.append(http_port)

        https_port = self.mdict['pki_https_port']
        if https_port != str(pki.server.DEFAULT_TOMCAT_HTTPS_PORT):
            ports.append(https_port)

        ajp_port = self.mdict['pki_ajp_port']
        if ajp_port != str(pki.server.DEFAULT_TOMCAT_AJP_PORT):
            ports.append(ajp_port)

    def verify_selinux_ports(self, ports):
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
            elif context == pki.server.PKI_PORT_SELINUX_CONTEXT:
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

        ds_url = self.deployer.get_ds_url()

        # Check to see if a secure connection is being used for the DS
        if ds_url.scheme == 'ldaps':
            # Verify existence of a local PEM file containing a
            # directory server CA certificate
            self.confirm_file_exists("pki_ds_secure_connection_ca_pem_file")
            # Verify existence of a nickname for this
            # directory server CA certificate
            self.confirm_data_exists("pki_ds_secure_connection_ca_nickname")

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

    def initialize(self):
        if config.str2bool(self.mdict['pki_hsm_enable']):
            if self.mdict['pki_hsm_libfile'] == config.PKI_HSM_NCIPHER_LIB:
                self.initialize_ncipher()
        return

    def initialize_ncipher(self):
        if (os.path.exists(config.PKI_HSM_NCIPHER_EXE) and
                os.path.exists(config.PKI_HSM_NCIPHER_LIB) and
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
        tpsport = server_config.get_https_port()

        tkshost = cs_cfg.get('tps.connector.tks1.host')
        tksport = cs_cfg.get('tps.connector.tks1.port')
        if tkshost is None or tksport is None:
            logger.warning(log.PKIHELPER_TPSCONNECTOR_UPDATE_FAILURE)
            logger.error(log.PKIHELPER_UNDEFINED_TKS_HOST_PORT)
            raise Exception(log.PKIHELPER_UNDEFINED_TKS_HOST_PORT)

        tks_url = 'https://%s:%s' % (tkshost, tksport)

        # retrieve subsystem nickname
        subsystemnick = cs_cfg.get('tps.cert.subsystem.nickname')
        if subsystemnick is None:
            logger.warning(log.PKIHELPER_TPSCONNECTOR_UPDATE_FAILURE)
            logger.error(log.PKIHELPER_UNDEFINED_SUBSYSTEM_NICKNAME)
            raise Exception(log.PKIHELPER_UNDEFINED_SUBSYSTEM_NICKNAME)

        try:
            cmd = [
                'pki',
                '-d', instance.nssdb_dir,
                '-f', instance.password_conf,
                'tks-tpsconnector-del',
                '-U', tks_url,
                '-n', subsystemnick,
                '--skip-revocation-check',
                '--ignore-banner',
                '--host', tpshost,
                '--port', str(tpsport)
            ]

            logger.debug('Command: %s', ' '.join(cmd))

            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                check=True)

            logger.debug('Output:\n%s', result.stdout.strip())

        except subprocess.CalledProcessError as e:
            # ignore exceptions
            logger.warning('Unable to remove TPS connector: %s', e.stderr.strip())


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
            cmd = ['systemctl', 'daemon-reload']

            logger.debug('Command: %s', ' '.join(cmd))
            subprocess.check_call(cmd)
        except subprocess.CalledProcessError as exc:
            logger.error(log.PKI_SUBPROCESS_ERROR_1, exc)
            if critical_failure:
                raise
        return
