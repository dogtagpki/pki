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
import pkiconfig as config
from pkiconfig import pki_master_dict as master
import pkihelper as util
import pkimanifest as manifest
import pkimessages as log
import pkiscriptlet


# PKI Deployment Finalization Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):
    rv = 0

    def spawn(self):
        if config.str2bool(master['pki_skip_installation']):
            config.pki_log.info(log.SKIP_FINALIZATION_SPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            return self.rv
        config.pki_log.info(log.FINALIZATION_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # For debugging/auditing purposes, save a timestamped copy of
        # this configuration file in the subsystem archive
        util.file.copy(master['pki_default_deployment_cfg_replica'],
                       master['pki_default_deployment_cfg_spawn_archive'])
        util.file.copy(master['pki_user_deployment_cfg_replica'],
                       master['pki_user_deployment_cfg_spawn_archive'])
        # Save a copy of the installation manifest file
        config.pki_log.info(log.PKI_MANIFEST_MESSAGE_1, master['pki_manifest'],
                            extra=config.PKI_INDENTATION_LEVEL_2)
        # for record in manifest.database:
        #     print tuple(record)
        manifest.file.register(master['pki_manifest'])
        manifest.file.write()
        util.file.modify(master['pki_manifest'], silent=True)

        # Also, for debugging/auditing purposes, save a timestamped copy of
        # this installation manifest file
        util.file.copy(master['pki_manifest'],
                       master['pki_manifest_spawn_archive'])
        # Optionally, programmatically 'restart' the configured PKI instance
        if config.str2bool(master['pki_restart_configured_instance']):
            util.systemd.restart()
        # Optionally, 'purge' the entire temporary client infrastructure
        # including the client NSS security databases and password files
        #
        #     WARNING:  If the PKCS #12 file containing the Admin Cert was
        #               placed under this infrastructure, it may accidentally
        #               be deleted!
        #
        if config.str2bool(master['pki_client_database_purge']):
            if util.directory.exists(master['pki_client_subsystem_dir']):
                util.directory.delete(master['pki_client_subsystem_dir'])
        # If instance has not been configured, print the
        # configuration URL to the log
        if config.str2bool(master['pki_skip_configuration']):
            util.configuration_file.log_configuration_url()
        # Log final process messages
        config.pki_log.info(log.PKISPAWN_END_MESSAGE_2,
                            master['pki_subsystem'],
                            master['pki_instance_id'],
                            extra=config.PKI_INDENTATION_LEVEL_0)
        util.file.modify(master['pki_spawn_log'], silent=True)
        # If instance has not been configured, print the
        # configuration URL to the screen
        if config.str2bool(master['pki_skip_configuration']):
            util.configuration_file.display_configuration_url()
        return self.rv

    def respawn(self):
        config.pki_log.info(log.FINALIZATION_RESPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        return self.rv

    def destroy(self):
        config.pki_log.info(log.FINALIZATION_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        util.file.modify(master['pki_destroy_log'], silent=True)
        # Start this Apache/Tomcat PKI Process
        if master['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS and\
           util.instance.apache_instance_subsystems() >= 1:
            util.systemd.start()
        elif master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS and\
           util.instance.tomcat_instance_subsystems() >= 1:
            util.systemd.start()
        config.pki_log.info(log.PKIDESTROY_END_MESSAGE_2,
                            master['pki_subsystem'],
                            master['pki_instance_id'],
                            extra=config.PKI_INDENTATION_LEVEL_0)
        return self.rv
