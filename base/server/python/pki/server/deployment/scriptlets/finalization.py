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

# PKI Deployment Imports
from .. import pkiconfig as config
from .. import pkimanifest as manifest
from .. import pkimessages as log
from .. import pkiscriptlet


# PKI Deployment Finalization Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):
    rv = 0

    def spawn(self, deployer):

        # ALWAYS finalize execution of scriptlets
        config.pki_log.info(log.FINALIZATION_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # For debugging/auditing purposes, save a timestamped copy of
        # this configuration file in the subsystem archive
        deployer.file.copy(
            deployer.mdict['pki_user_deployment_cfg_replica'],
            deployer.mdict['pki_user_deployment_cfg_spawn_archive'])
        # Save a copy of the installation manifest file
        config.pki_log.info(
            log.PKI_MANIFEST_MESSAGE_1, deployer.mdict['pki_manifest'],
            extra=config.PKI_INDENTATION_LEVEL_2)
        # for record in manifest.database:
        #     print tuple(record)
        manifest_file = manifest.File(deployer.manifest_db)
        manifest_file.register(deployer.mdict['pki_manifest'])
        manifest_file.write()
        deployer.file.modify(deployer.mdict['pki_manifest'], silent=True)

        # Also, for debugging/auditing purposes, save a timestamped copy of
        # this installation manifest file
        deployer.file.copy(
            deployer.mdict['pki_manifest'],
            deployer.mdict['pki_manifest_spawn_archive'])
        # Optionally, programmatically 'enable' the configured PKI instance
        # to be started upon system boot (default is True)
        if not config.str2bool(deployer.mdict['pki_enable_on_system_boot']):
            deployer.systemd.disable()
        else:
            deployer.systemd.enable()
        # Optionally, programmatically 'restart' the configured PKI instance
        if config.str2bool(deployer.mdict['pki_restart_configured_instance']):
            deployer.systemd.restart()
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
        return self.rv

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
        return self.rv
