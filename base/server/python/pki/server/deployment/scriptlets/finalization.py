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

        if config.str2bool(deployer.mdict['pki_systemd_service_create']):

            # Optionally, programmatically 'enable' the configured PKI instance
            # to be started upon system boot (default is True)
            if not config.str2bool(deployer.mdict['pki_enable_on_system_boot']):
                instance.disable()
            else:
                instance.enable()

            if len(instance.get_subsystems()) == 1:
                logger.info('Starting PKI server')
                instance.start(
                    wait=True,
                    max_wait=deployer.startup_timeout,
                    timeout=deployer.request_timeout)

                logger.info('Waiting for %s subsystem', subsystem.type)
                subsystem.wait_for_startup(deployer.startup_timeout, deployer.request_timeout)

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

        if instance.get_subsystems():
            # If there's more subsystems, restart server
            logger.info('Starting PKI server')
            instance.start(
                wait=True,
                max_wait=deployer.startup_timeout,
                timeout=deployer.request_timeout)

        else:
            # If there's no more subsystems, disable server
            logger.info('Disabling PKI server')
            instance.disable()

        logger.info(log.PKIDESTROY_END_MESSAGE_2,
                    deployer.mdict['pki_subsystem'],
                    deployer.mdict['pki_instance_name'])
