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
import pkimessages as log
import pkiscriptlet


# PKI Deployment Instance Population Classes
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):
    rv = 0

    def spawn(self):
        config.pki_log.info(log.SUBSYSTEM_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # establish instance-based subsystem base
        util.directory.create(master['pki_subsystem_path'])
        if master['pki_subsystem'] == "CA":
            util.directory.copy(master['pki_source_emails'],
                                master['pki_subsystem_emails_path'])
            util.directory.copy(master['pki_source_profiles'],
                                master['pki_subsystem_profiles_path'])
        # establish instance-based subsystem logs
        util.directory.create(master['pki_subsystem_log_path'])
        if master['pki_subsystem'] in config.PKI_SIGNED_AUDIT_SUBSYSTEMS:
            util.directory.create(master['pki_subsystem_signed_audit_log_path'])
        # establish instance-based subsystem configuration
        util.directory.copy(master['pki_source_conf'],
                            master['pki_subsystem_configuration_path'])
        # establish instance-based subsystem registry
        util.directory.create(master['pki_subsystem_registry_path'])
        # establish convenience symbolic links
        util.symlink.create(master['pki_database_path'],
                            master['pki_subsystem_database_link'])
        util.symlink.create(master['pki_subsystem_configuration_path'],
                            master['pki_subsystem_configuration_link'])
        util.symlink.create(master['pki_subsystem_log_path'],
                            master['pki_subsystem_logs_link'])
        util.symlink.create(master['pki_webapps_path'],
                            master['pki_subsystem_webapps_link'])
        return self.rv

    def respawn(self):
        config.pki_log.info(log.SUBSYSTEM_RESPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # update instance-based subsystem base
        util.directory.modify(master['pki_subsystem_path'])
        if master['pki_subsystem'] == "CA":
            util.directory.copy(master['pki_source_emails'],
                                master['pki_subsystem_emails_path'],
                                overwrite_flag=True)
            util.directory.copy(master['pki_source_profiles'],
                                master['pki_subsystem_profiles_path'],
                                overwrite_flag=True)
        # update instance-based subsystem logs
        util.directory.modify(master['pki_subsystem_log_path'])
        if master['pki_subsystem'] in config.PKI_SIGNED_AUDIT_SUBSYSTEMS:
            util.directory.modify(master['pki_subsystem_signed_audit_log_path'])
        # update instance-based subsystem configuration
        util.directory.copy(master['pki_source_conf'],
                            master['pki_subsystem_configuration_path'],
                            overwrite_flag=True)
        # update instance-based subsystem registry
        util.directory.modify(master['pki_subsystem_registry_path'])
        # update convenience symbolic links
        util.symlink.modify(master['pki_subsystem_database_link'])
        util.symlink.modify(master['pki_subsystem_configuration_link'])
        util.symlink.modify(master['pki_subsystem_logs_link'])
        util.symlink.modify(master['pki_subsystem_webapps_link'])
        return self.rv

    def destroy(self):
        config.pki_log.info(log.SUBSYSTEM_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # remove instance-based subsystem base
        if master['pki_subsystem'] == "CA":
            util.directory.delete(master['pki_subsystem_profiles_path'])
            util.directory.delete(master['pki_subsystem_emails_path'])
        util.directory.delete(master['pki_subsystem_path'])
        # remove instance-based subsystem logs
        util.directory.delete(master['pki_subsystem_log_path'])
        # remove instance-based subsystem configuration
        util.directory.delete(master['pki_subsystem_configuration_path'])
        # remove instance-based subsystem registry
        util.directory.delete(master['pki_subsystem_registry_path'])
        return self.rv
