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

from __future__ import absolute_import
import logging

# PKI Deployment Imports
from .. import pkiconfig as config
from .. import pkimessages as log
from .. import pkiscriptlet

logger = logging.getLogger(__name__)


# PKI Deployment Finalization Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):

    def spawn(self, deployer):

        external = deployer.configuration_file.external
        standalone = deployer.configuration_file.standalone
        step_one = deployer.configuration_file.external_step_one
        skip_configuration = deployer.configuration_file.skip_configuration

        if (external or standalone) and step_one or skip_configuration:
            logger.info('Skipping finalization')
            return

        logger.info('Finalizing subsystem creation')

        instance = self.instance
        instance.load()

        subsystem = instance.get_subsystem(deployer.mdict['pki_subsystem'].lower())

        if config.str2bool(deployer.mdict['pki_backup_keys']):

            # by default store the backup file in the NSS databases directory
            if not deployer.mdict['pki_backup_file']:
                deployer.mdict['pki_backup_file'] = \
                    deployer.mdict['pki_server_database_path'] + '/' + \
                    deployer.mdict['pki_subsystem'].lower() + '_backup_keys.p12'

            logger.info('Backing up keys into %s', deployer.mdict['pki_backup_file'])
            deployer.backup_keys(instance, subsystem)

        # Optionally, programmatically 'enable' the configured PKI instance
        # to be started upon system boot (default is True)
        if not config.str2bool(deployer.mdict['pki_enable_on_system_boot']):
            instance.disable()
        else:
            instance.enable()

        # Optionally, 'purge' the entire temporary client infrastructure
        # including the client NSS security databases and password files
        #
        #     WARNING:  If the PKCS #12 file containing the Admin Cert was
        #               placed under this infrastructure, it may accidentally
        #               be deleted!
        #
        if config.str2bool(deployer.mdict['pki_client_database_purge']):
            if deployer.directory.exists(
                    deployer.mdict['pki_client_subsystem_dir']):
                deployer.directory.delete(
                    deployer.mdict['pki_client_subsystem_dir'])

        # Log final process messages
        logger.info(log.PKISPAWN_END_MESSAGE_2,
                    deployer.mdict['pki_subsystem'],
                    deployer.mdict['pki_instance_name'])

    def destroy(self, deployer):

        logger.info('Finalizing subsystem removal')

        instance = self.instance
        instance.load()

        # If this is the last remaining PKI instance, ALWAYS remove the
        # link to start configured PKI instances upon system reboot
        if deployer.instance.pki_instance_subsystems() == 0:
            instance.disable()

        # Start this Tomcat PKI Process back if there are any subsystems still existing
        if len(deployer.instance.tomcat_instance_subsystems()) >= 1:
            logger.info('Starting PKI server')
            instance.start()

        logger.info(log.PKIDESTROY_END_MESSAGE_2,
                    deployer.mdict['pki_subsystem'],
                    deployer.mdict['pki_instance_name'])
