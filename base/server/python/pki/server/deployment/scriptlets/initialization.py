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

import logging

import pki

# PKI Deployment Imports
from .. import pkiconfig as config
from .. import pkimessages as log
from .. import pkiscriptlet

logger = logging.getLogger(__name__)


# PKI Deployment Initialization Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):

    def spawn(self, deployer):

        instance = self.instance

        logger.info(log.PKISPAWN_BEGIN_MESSAGE_2,
                    deployer.subsystem_type,
                    instance.name)

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
            # - External CA/KRA/OCSP/TKS/TPS (Step 2)
            # - Stand-alone PKI (Step 2)
            # - Two-step installation (Step 2)

            if (deployer.subsystem_type in ['CA', 'KRA', 'OCSP', 'TKS', 'TPS'] or
                config.str2bool(deployer.mdict['pki_standalone'])) and \
                    config.str2bool(deployer.mdict['pki_external_step_two']) or \
               config.str2bool(deployer.mdict['pki_skip_installation']):
                deployer.verify_subsystem_exists()
                deployer.mdict['pki_skip_installation'] = "True"

        # verify existence of SENSITIVE configuration file data
        deployer.verify_sensitive_data()

        # verify existence of MUTUALLY EXCLUSIVE configuration file data
        deployer.configuration_file.verify_mutually_exclusive_data()
        # verify existence of PREDEFINED configuration file data
        deployer.configuration_file.verify_predefined_configuration_file_data()

        if config.str2bool(deployer.mdict['pki_ds_setup']):

            # verify existence of DS password
            # (unless configuration will not be automatically executed)
            if not deployer.configuration_file.skip_configuration:
                deployer.configuration_file.confirm_data_exists('pki_ds_password')

            # if secure DS connection is required, verify parameters
            deployer.configuration_file.verify_ds_secure_connection_data()

    def destroy(self, deployer):

        instance = self.instance

        logger.info(log.PKIDESTROY_BEGIN_MESSAGE_2,
                    deployer.subsystem_type,
                    instance.name)

        logger.info('Initialization')

        instance.load()

        # verify that this type of "subsystem" currently EXISTS
        # for this "instance"
        deployer.verify_subsystem_exists()

        # verify that the command-line parameters match the values
        # that are present in the corresponding configuration file
        deployer.configuration_file.verify_command_matches_configuration_file()

        # establish 'uid' and 'gid'
        deployer.identity.set_uid(instance.user)
        deployer.identity.set_gid(instance.group)
