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
        config.pki_log.info(log.INSTANCE_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # establish instance base
        util.directory.create(master['pki_path'])
        util.directory.create(master['pki_instance_path'])
        # establish instance logs
        util.directory.create(master['pki_log_path'])
        util.directory.create(master['pki_instance_log_path'])
        # establish instance configuration
        if master['pki_configuration_path'] !=\
           config.PKI_SHARED_CONFIGURATION_ROOT:
            util.directory.create(master['pki_configuration_path'])
        util.directory.create(master['pki_instance_configuration_path'])
        # establish instance registry
        util.directory.create(master['pki_registry_path'])
        util.directory.create(master['pki_instance_registry_path'])
        # establish shared NSS security databases
        util.directory.create(master['pki_database_path'])
        # establish convenience symbolic links
        util.symlink.create(master['pki_database_path'],
                            master['pki_instance_database_link'])
        return self.rv

    def respawn(self):
        config.pki_log.info(log.INSTANCE_RESPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # update instance base
        util.directory.modify(master['pki_path'])
        util.directory.modify(master['pki_instance_path'])
        # update instance logs
        util.directory.modify(master['pki_log_path'])
        util.directory.modify(master['pki_instance_log_path'])
        # update instance configuration
        if master['pki_configuration_path'] !=\
           config.PKI_SHARED_CONFIGURATION_ROOT:
            util.directory.modify(master['pki_configuration_path'])
        util.directory.modify(master['pki_instance_configuration_path'])
        # update instance registry
        util.directory.modify(master['pki_registry_path'])
        util.directory.modify(master['pki_instance_registry_path'])
        # update shared NSS security databases
        util.directory.modify(master['pki_database_path'])
        # update convenience symbolic links
        util.symlink.modify(master['pki_instance_database_link'])
        return self.rv

    def destroy(self):
        config.pki_log.info(log.INSTANCE_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # remove instance base
        if not config.pki_dry_run_flag:
            if master['pki_subsystem'] in config.PKI_SUBSYSTEMS and\
               util.instance.pki_subsystem_instances() == 0:
                # remove instance base
                util.directory.delete(master['pki_instance_path'])
                util.directory.delete(master['pki_path'])
                # remove instance logs
                util.directory.delete(master['pki_instance_log_path'])
                util.directory.delete(master['pki_log_path'])
                # remove shared NSS security database path
                util.directory.delete(master['pki_database_path'])
                # remove instance configuration
                util.directory.delete(master['pki_instance_configuration_path'])
                if util.directory.is_empty(master['pki_configuration_path'])\
                   and master['pki_configuration_path'] !=\
                   config.PKI_SHARED_CONFIGURATION_ROOT:
                    util.directory.delete(master['pki_configuration_path'])
                # remove instance registry
                util.directory.delete(master['pki_instance_registry_path'])
                util.directory.delete(master['pki_registry_path'])
                util.file.delete(master['pki_target_tomcat_conf'])

        else:
            # ALWAYS display correct information (even during dry_run)
            if master['pki_subsystem'] in config.PKI_SUBSYSTEMS and\
               util.instance.pki_subsystem_instances() == 1:
                # remove instance base
                util.directory.delete(master['pki_instance_path'])
                util.directory.delete(master['pki_path'])
                # remove instance logs
                util.directory.delete(master['pki_instance_log_path'])
                util.directory.delete(master['pki_log_path'])
                # remove shared NSS security database path
                util.directory.delete(master['pki_database_path'])
                if util.directory.is_empty(master['pki_configuration_path'])\
                   and master['pki_configuration_path'] !=\
                   config.PKI_SHARED_CONFIGURATION_ROOT:
                    util.directory.delete(master['pki_configuration_path'])
                # remove instance registry
                util.directory.delete(master['pki_instance_registry_path'])
                util.directory.delete(master['pki_registry_path'])
                util.file.delete(master['pki_target_tomcat_conf'])
        return self.rv
