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

        if (deployer.master_dict['pki_subsystem'] == "CA" or
            config.str2bool(deployer.master_dict['pki_standalone'])) and\
           config.str2bool(deployer.master_dict['pki_external_step_two']):
            # For External CAs (Step 2), or Stand-alone PKIs (Step 2),
            # must check for (Step 2) installation PRIOR to
            # 'pki_skip_installation' since this value has been set to true
            # by the initialization scriptlet
            pass
        elif config.str2bool(deployer.master_dict['pki_skip_installation']):
            config.pki_log.info(log.SKIP_FINALIZATION_SPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            return self.rv
        config.pki_log.info(log.FINALIZATION_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # For debugging/auditing purposes, save a timestamped copy of
        # this configuration file in the subsystem archive
        deployer.file.copy(deployer.master_dict['pki_user_deployment_cfg_replica'],
                       deployer.master_dict['pki_user_deployment_cfg_spawn_archive'])
        # Save a copy of the installation manifest file
        config.pki_log.info(log.PKI_MANIFEST_MESSAGE_1, deployer.master_dict['pki_manifest'],
                            extra=config.PKI_INDENTATION_LEVEL_2)
        # for record in manifest.database:
        #     print tuple(record)
        manifest_file = manifest.File(deployer.manifest_db)
        manifest_file.register(deployer.master_dict['pki_manifest'])
        manifest_file.write()
        deployer.file.modify(deployer.master_dict['pki_manifest'], silent=True)

        # Also, for debugging/auditing purposes, save a timestamped copy of
        # this installation manifest file
        deployer.file.copy(deployer.master_dict['pki_manifest'],
                       deployer.master_dict['pki_manifest_spawn_archive'])
        # Optionally, programmatically 'restart' the configured PKI instance
        if config.str2bool(deployer.master_dict['pki_restart_configured_instance']):
            deployer.systemd.restart()
        # Optionally, 'purge' the entire temporary client infrastructure
        # including the client NSS security databases and password files
        #
        #     WARNING:  If the PKCS #12 file containing the Admin Cert was
        #               placed under this infrastructure, it may accidentally
        #               be deleted!
        #
        if config.str2bool(deployer.master_dict['pki_client_database_purge']):
            if deployer.directory.exists(deployer.master_dict['pki_client_subsystem_dir']):
                deployer.directory.delete(deployer.master_dict['pki_client_subsystem_dir'])
        # If instance has not been configured, print the
        # configuration URL to the log
        if config.str2bool(deployer.master_dict['pki_skip_configuration']):
            deployer.configuration_file.log_configuration_url()
        # Log final process messages
        config.pki_log.info(log.PKISPAWN_END_MESSAGE_2,
                            deployer.master_dict['pki_subsystem'],
                            deployer.master_dict['pki_instance_name'],
                            extra=config.PKI_INDENTATION_LEVEL_0)
        deployer.file.modify(deployer.master_dict['pki_spawn_log'], silent=True)
        return self.rv

    def destroy(self, deployer):

        config.pki_log.info(log.FINALIZATION_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        deployer.file.modify(deployer.master_dict['pki_destroy_log'], silent=True)
        # Start this Apache/Tomcat PKI Process
        if deployer.master_dict['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS and\
           deployer.instance.apache_instance_subsystems() >= 1:
            deployer.systemd.start()
        elif deployer.master_dict['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS and\
           len(deployer.instance.tomcat_instance_subsystems()) >= 1:
            deployer.systemd.start()
        config.pki_log.info(log.PKIDESTROY_END_MESSAGE_2,
                            deployer.master_dict['pki_subsystem'],
                            deployer.master_dict['pki_instance_name'],
                            extra=config.PKI_INDENTATION_LEVEL_0)
        return self.rv
