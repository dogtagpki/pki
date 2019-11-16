# Authors:
# Matthew Harmsen <mharmsen@redhat.com>
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

from __future__ import absolute_import
import logging
import os

import pki
import pki.server.instance

# PKI Deployment Imports
from .. import pkiconfig as config
from .. import pkimessages as log
from .. import pkiscriptlet

logger = logging.getLogger('initialization')


# PKI Deployment Initialization Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):

    def verify_sensitive_data(self, deployer):

        # Silently verify the existence of 'sensitive' data
        configuration_file = deployer.configuration_file

        # Verify existence of Directory Server Password
        # (unless configuration will not be automatically executed)
        if not configuration_file.skip_configuration:
            configuration_file.confirm_data_exists('pki_ds_password')

        # Verify existence of Admin Password (except for Clones)
        if not configuration_file.clone:
            configuration_file.confirm_data_exists('pki_admin_password')

        # If HSM, verify absence of all PKCS #12 backup parameters
        if (config.str2bool(deployer.mdict['pki_hsm_enable']) and
                (config.str2bool(deployer.mdict['pki_backup_keys']) or
                 ('pki_backup_password' in deployer.mdict and
                  len(deployer.mdict['pki_backup_password'])))):
            logger.error(log.PKIHELPER_HSM_KEYS_CANNOT_BE_BACKED_UP_TO_PKCS12_FILES)
            raise Exception(
                log.PKIHELPER_HSM_KEYS_CANNOT_BE_BACKED_UP_TO_PKCS12_FILES)

        # If required, verify existence of Backup Password
        if config.str2bool(deployer.mdict['pki_backup_keys']):
            configuration_file.confirm_data_exists('pki_backup_password')

        # Verify existence of Client Pin for NSS client security databases
        # if not a clone.
        if not configuration_file.clone:
            configuration_file.confirm_data_exists('pki_client_database_password')

        # Verify existence of Client PKCS #12 Password for Admin Cert
        configuration_file.confirm_data_exists('pki_client_pkcs12_password')

        if configuration_file.clone:

            # Verify existence of PKCS #12 Password (ONLY for non-HSM Clones)
            if not config.str2bool(deployer.mdict['pki_hsm_enable']):

                # If system certificates are already provided via
                # pki_server_pkcs12, there's no need to provide
                # pki_clone_pkcs12.
                if not deployer.mdict['pki_server_pkcs12_path']:
                    configuration_file.confirm_data_exists('pki_clone_pkcs12_password')

            # Verify absence of all PKCS #12 clone parameters for HSMs
            elif (os.path.exists(deployer.mdict['pki_clone_pkcs12_path']) or
                    ('pki_clone_pkcs12_password' in deployer.mdict and
                     len(deployer.mdict['pki_clone_pkcs12_password']))):
                logger.error(log.PKIHELPER_HSM_CLONES_MUST_SHARE_HSM_MASTER_PRIVATE_KEYS)
                raise Exception(
                    log.PKIHELPER_HSM_CLONES_MUST_SHARE_HSM_MASTER_PRIVATE_KEYS)

        # Verify existence of Security Domain Password
        # (ONLY for PKI KRA, PKI OCSP, PKI TKS, PKI TPS, Clones, or
        #  Subordinate CA that will be automatically configured and
        #  are not Stand-alone PKI)
        if (configuration_file.subsystem == 'KRA' or
                configuration_file.subsystem == 'OCSP' or
                configuration_file.subsystem == 'TKS' or
                configuration_file.subsystem == 'TPS' or
                configuration_file.clone or
                configuration_file.subordinate):

            if not configuration_file.skip_configuration and not configuration_file.standalone:
                configuration_file.confirm_data_exists('pki_security_domain_password')

        # If required, verify existence of Token Password
        if config.str2bool(deployer.mdict['pki_hsm_enable']):
            configuration_file.confirm_data_exists('pki_hsm_libfile')
            configuration_file.confirm_data_exists('pki_hsm_modulename')
            configuration_file.confirm_data_exists('pki_token_name')
            if not pki.nssdb.normalize_token(deployer.mdict['pki_token_name']):
                logger.error(log.PKIHELPER_UNDEFINED_HSM_TOKEN)
                raise Exception(log.PKIHELPER_UNDEFINED_HSM_TOKEN)

        if pki.nssdb.normalize_token(deployer.mdict['pki_token_name']):
            configuration_file.confirm_data_exists('pki_token_password')

    def spawn(self, deployer):

        logger.info(log.PKISPAWN_BEGIN_MESSAGE_2,
                    deployer.mdict['pki_subsystem'],
                    deployer.mdict['pki_instance_name'])

        instance = pki.server.instance.PKIInstance(deployer.mdict['pki_instance_name'])
        instance.load()

        # generate random password for client database if not specified
        if not deployer.mdict['pki_client_database_password']:
            deployer.mdict['pki_client_database_password'] = pki.generate_password()

        # ALWAYS initialize 'uid' and 'gid'
        deployer.identity.add_uid_and_gid(deployer.mdict['pki_user'],
                                          deployer.mdict['pki_group'])
        # ALWAYS establish 'uid' and 'gid'
        deployer.identity.set_uid(deployer.mdict['pki_user'])
        deployer.identity.set_gid(deployer.mdict['pki_group'])

        # ALWAYS initialize HSMs (when and if present)
        deployer.hsm.initialize()
        if config.str2bool(deployer.mdict['pki_skip_installation']):
            logger.info('Skipping initialization')
            return

        else:
            logger.info('Initialization')

            # Verify that the subsystem already exists for the following cases:
            # - External CA/KRA/OCSP (Step 2)
            # - Stand-alone PKI (Step 2)
            # - Two-step installation (Step 2)

            if (deployer.subsystem_name in ['CA', 'KRA', 'OCSP'] or
                config.str2bool(deployer.mdict['pki_standalone'])) and \
                    config.str2bool(deployer.mdict['pki_external_step_two']) or \
               config.str2bool(deployer.mdict['pki_skip_installation']):
                deployer.instance.verify_subsystem_exists()
                deployer.mdict['pki_skip_installation'] = "True"

            else:
                # verify that this type of "subsystem" does NOT yet
                # exist for this "instance"
                deployer.instance.verify_subsystem_does_not_exist()
                # detect and avoid any namespace collisions
                deployer.namespace.collision_detection()
        # verify existence of SENSITIVE configuration file data
        self.verify_sensitive_data(deployer)
        # verify existence of MUTUALLY EXCLUSIVE configuration file data
        deployer.configuration_file.verify_mutually_exclusive_data()
        # verify existence of PREDEFINED configuration file data
        deployer.configuration_file.verify_predefined_configuration_file_data()
        # verify selinux context of selected ports
        deployer.configuration_file.populate_non_default_ports()
        deployer.configuration_file.verify_selinux_ports()
        # If secure DS connection is required, verify parameters
        deployer.configuration_file.verify_ds_secure_connection_data()

    def destroy(self, deployer):

        logger.info(log.PKIDESTROY_BEGIN_MESSAGE_2,
                    deployer.mdict['pki_subsystem'],
                    deployer.mdict['pki_instance_name'])

        logger.info('Initialization')

        instance = pki.server.instance.PKIInstance(deployer.mdict['pki_instance_name'])
        instance.load()

        try:
            # verify that this type of "subsystem" currently EXISTS
            # for this "instance"
            deployer.instance.verify_subsystem_exists()
            # verify that the command-line parameters match the values
            # that are present in the corresponding configuration file
            deployer.configuration_file.verify_command_matches_configuration_file()
            # establish 'uid' and 'gid'
            deployer.identity.set_uid(deployer.mdict['pki_user'])
            deployer.identity.set_gid(deployer.mdict['pki_group'])
            # get ports to remove selinux context
            deployer.configuration_file.populate_non_default_ports()

            # remove kra connector from CA if this is a KRA
            deployer.kra_connector.deregister()

            # remove tps connector from TKS if this is a TPS
            deployer.tps_connector.deregister()

            # de-register instance from its Security Domain
            #
            #     NOTE:  Since the security domain of an instance must be up
            #            and running in order to be de-registered, this step
            #            must be done PRIOR to instance shutdown because this
            #            instance's security domain may be a part of a
            #            tightly-coupled shared instance.
            #

            # Previously we obtained the token through a command line interface
            # no longer supported. Thus we assume no token and the deregister op will
            # take place without the token using an alternate method.

            deployer.security_domain.deregister(None)

        except Exception as e:  # pylint: disable=broad-except
            logger.error(str(e))
            # If it is a normal destroy, pass any exception
            if not deployer.mdict['pki_force_destroy']:
                raise

        finally:
            # ALWAYS Stop this Tomcat PKI Process
            instance.stop()
