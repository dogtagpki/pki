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

# PKI Deployment Imports
from .. import pkiconfig as config
from .. import pkimessages as log
from .. import pkiscriptlet


# PKI Deployment Finalization Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):

    def spawn(self, deployer):

        external = deployer.configuration_file.external
        standalone = deployer.configuration_file.standalone
        step_one = deployer.configuration_file.external_step_one
        skip_configuration = deployer.configuration_file.skip_configuration

        if (external or standalone) and step_one or skip_configuration:
            config.pki_log.info(log.SKIP_FINALIZATION_SPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            return

        config.pki_log.info(log.FINALIZATION_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)

        # Optionally, programmatically 'enable' the configured PKI instance
        # to be started upon system boot (default is True)
        if not config.str2bool(deployer.mdict['pki_enable_on_system_boot']):
            deployer.systemd.disable()
        else:
            deployer.systemd.enable()

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
        config.pki_log.info(log.PKISPAWN_END_MESSAGE_2,
                            deployer.mdict['pki_subsystem'],
                            deployer.mdict['pki_instance_name'],
                            extra=config.PKI_INDENTATION_LEVEL_0)
        deployer.file.modify(deployer.mdict['pki_spawn_log'], silent=True)

    def destroy(self, deployer):

        config.pki_log.info(log.FINALIZATION_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        deployer.file.modify(deployer.mdict['pki_destroy_log'], silent=True)
        # If this is the last remaining PKI instance, ALWAYS remove the
        # link to start configured PKI instances upon system reboot
        if deployer.mdict['pki_subsystem'] in config.PKI_SUBSYSTEMS and\
           deployer.instance.pki_instance_subsystems() == 0:
            deployer.systemd.disable()
        # Start this Tomcat PKI Process
        if len(deployer.instance.tomcat_instance_subsystems()) >= 1:
            deployer.systemd.start()
        config.pki_log.info(log.PKIDESTROY_END_MESSAGE_2,
                            deployer.mdict['pki_subsystem'],
                            deployer.mdict['pki_instance_name'],
                            extra=config.PKI_INDENTATION_LEVEL_0)
