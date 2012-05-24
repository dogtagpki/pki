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
        config.pki_log.info(log.FINALIZATION_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # Save a copy of the configuration file used by this process
        # (which may be used later by 'pkidestroy')
        util.file.copy(config.pkideployment_cfg,
                       master['pki_subsystem_registry_path'] +\
                       "/" + config.PKI_DEPLOYMENT_DEFAULT_CONFIGURATION_FILE)
        # Save a timestamped copy of the installation manifest file
        filename = master['pki_subsystem_registry_path'] + "/" +\
                   "spawn" + "_" + "manifest" + "." +\
                   master['pki_timestamp'] + "." + "csv"
        config.pki_log.info(log.PKI_MANIFEST_MESSAGE_1, filename,
                            extra=config.PKI_INDENTATION_LEVEL_2)
        # for record in manifest.database:
        #     print tuple(record)
        if not config.pki_dry_run_flag:
            manifest.file.register(filename)
            manifest.file.write()
            util.file.modify(filename, silent=True)
        # Log final process messages
        config.pki_log.info(log.PKISPAWN_END_MESSAGE_2,
                            master['pki_subsystem'],
                            master['pki_instance_id'],
                            extra=config.PKI_INDENTATION_LEVEL_0)
        if not config.pki_dry_run_flag:
            util.file.modify(master['pki_spawn_log'], silent=True)
        return self.rv

    def respawn(self):
        config.pki_log.info(log.FINALIZATION_RESPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # Save a copy of the configuration file used by this process
        # (which may be used later by 'pkidestroy')
        util.file.copy(config.pkideployment_cfg,
                       master['pki_subsystem_registry_path'] +\
                       "/" + config.PKI_DEPLOYMENT_DEFAULT_CONFIGURATION_FILE,
                       overwrite_flag=True)
        # Save a timestamped copy of the updated manifest file
        filename = master['pki_subsystem_registry_path'] + "/" +\
                   "respawn" + "_" + "manifest" + "." +\
                   master['pki_timestamp'] + "." + "csv"
        config.pki_log.info(log.PKI_MANIFEST_MESSAGE_1, filename,
                            extra=config.PKI_INDENTATION_LEVEL_2)
        # for record in manifest.database:
        #     print tuple(record)
        if not config.pki_dry_run_flag:
            manifest.file.register(filename)
            manifest.file.write()
            util.file.modify(filename, silent=True)
        # Log final process messages
        config.pki_log.info(log.PKIRESPAWN_END_MESSAGE_2,
                            master['pki_subsystem'],
                            master['pki_instance_id'],
                            extra=config.PKI_INDENTATION_LEVEL_0)
        if not config.pki_dry_run_flag:
            util.file.modify(master['pki_respawn_log'], silent=True)
        return self.rv

    def destroy(self):
        config.pki_log.info(log.FINALIZATION_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        config.pki_log.info(log.PKIDESTROY_END_MESSAGE_2,
                            master['pki_subsystem'],
                            master['pki_instance_id'],
                            extra=config.PKI_INDENTATION_LEVEL_0)
        if not config.pki_dry_run_flag:
            util.file.modify(master['pki_destroy_log'], silent=True)
        return self.rv
