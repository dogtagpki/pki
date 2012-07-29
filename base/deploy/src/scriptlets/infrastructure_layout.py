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


# PKI Deployment Top-Level Infrastructure Layout Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):
    rv = 0

    def spawn(self):
        config.pki_log.info(log.ADMIN_DOMAIN_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # NOTE:  It was determined that since the "pkidestroy" command
        #        relies upon a symbolic link to a replica of the original
        #        "pkideployment.cfg" configuration file used by the
        #        "pkispawn" command of an instance, it is necessary to
        #        create any required instance and subsystem directories
        #        in this top-level "infrastructure_layout" scriptlet
        #        (rather than the "instance_layout" and "subsystem_layout"
        #        scriptlets) so that a copy of this configuration file can
        #        be saved, and the required symbolic link can be created.
        #
        # establish the top-level infrastructure, instance, and subsystem
        # registry directories for storage of a copy of the original
        # "pkideployment.cfg" configuration file used to spawn this instance,
        # and save a copy of this file
        util.directory.create(master['pki_registry_path'])
        util.directory.create(master['pki_instance_type_registry_path'])
        util.directory.create(master['pki_instance_registry_path'])
        util.directory.create(master['pki_subsystem_registry_path'])
        util.file.copy(master['pki_deployment_cfg'],
                       master['pki_deployment_cfg_replica'])
        # establish top-level infrastructure, instance, and subsystem
        # base directories and create the "registry" symbolic link that
        # the "pkidestroy" executable relies upon
        util.directory.create(master['pki_path'])
        util.directory.create(master['pki_instance_path'])
        util.directory.create(master['pki_subsystem_path'])
        util.symlink.create(master['pki_instance_registry_path'],
                            master['pki_subsystem_registry_link'])
        #
        # NOTE:  If "infrastructure_layout" scriptlet execution has been
        #        successfully executed to this point, the "pkidestroy" command
        #        may always be utilized to remove the entire infrastructure.
        #
        # no need to establish top-level infrastructure logs
        # since it now stores 'pkispawn'/'pkidestroy' logs
        # and will already exist
        # util.directory.create(master['pki_log_path'])
        # establish top-level infrastructure configuration
        if master['pki_configuration_path'] !=\
           config.PKI_DEPLOYMENT_CONFIGURATION_ROOT:
            util.directory.create(master['pki_configuration_path'])
        return self.rv

    def respawn(self):
        config.pki_log.info(log.ADMIN_DOMAIN_RESPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # update top-level infrastructure base
        util.directory.modify(master['pki_path'])
        # update top-level infrastructure logs
        util.directory.modify(master['pki_log_path'])
        # update top-level infrastructure configuration
        if master['pki_configuration_path'] !=\
           config.PKI_DEPLOYMENT_CONFIGURATION_ROOT:
            util.directory.modify(master['pki_configuration_path'])
        # update top-level infrastructure registry
        util.directory.modify(master['pki_registry_path'])
        return self.rv

    def destroy(self):
        config.pki_log.info(log.ADMIN_DOMAIN_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # remove top-level infrastructure base
        if not config.pki_dry_run_flag:
            if master['pki_subsystem'] in config.PKI_SUBSYSTEMS and\
               util.instance.pki_subsystem_instances() == 0:
                # remove top-level infrastructure base
                util.directory.delete(master['pki_path'])
                # do NOT remove top-level infrastructure logs
                # since it now stores 'pkispawn'/'pkidestroy' logs
                # util.directory.delete(master['pki_log_path'])
                # remove top-level infrastructure configuration
                if util.directory.is_empty(master['pki_configuration_path'])\
                   and master['pki_configuration_path'] !=\
                   config.PKI_DEPLOYMENT_CONFIGURATION_ROOT:
                    util.directory.delete(master['pki_configuration_path'])
                # remove top-level infrastructure registry
                util.directory.delete(master['pki_registry_path'])
        else:
            # ALWAYS display correct information (even during dry_run)
            if master['pki_subsystem'] in config.PKI_SUBSYSTEMS and\
               util.instance.pki_subsystem_instances() == 1:
                # remove top-level infrastructure base
                util.directory.delete(master['pki_path'])
                # do NOT remove top-level infrastructure logs
                # since it now stores 'pkispawn'/'pkidestroy' logs
                # util.directory.delete(master['pki_log_path'])
                # remove top-level infrastructure configuration
                if util.directory.is_empty(master['pki_configuration_path'])\
                   and master['pki_configuration_path'] !=\
                   config.PKI_DEPLOYMENT_CONFIGURATION_ROOT:
                    util.directory.delete(master['pki_configuration_path'])
                # remove top-level infrastructure registry
                util.directory.delete(master['pki_registry_path'])
        return self.rv
