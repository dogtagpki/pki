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
from .. import pkimessages as log
from .. import pkiscriptlet


# PKI Deployment Top-Level Infrastructure Layout Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):
    rv = 0

    def spawn(self, deployer):

        if config.str2bool(deployer.master_dict['pki_skip_installation']):
            config.pki_log.info(log.SKIP_ADMIN_DOMAIN_SPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            return self.rv
        config.pki_log.info(log.ADMIN_DOMAIN_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # NOTE:  It was determined that since the "pkidestroy" command
        #        relies upon a symbolic link to a replica of the original
        #        deployment configuration file used by the
        #        "pkispawn" command of an instance, it is necessary to
        #        create any required instance and subsystem directories
        #        in this top-level "infrastructure_layout" scriptlet
        #        (rather than the "instance_layout" and "subsystem_layout"
        #        scriptlets) so that a copy of this configuration file can
        #        be saved, and the required symbolic link can be created.
        #
        # establish the top-level infrastructure, instance, and subsystem
        # registry directories for storage of a copy of the original
        # deployment configuration file used to spawn this instance,
        # and save a copy of this file
        deployer.directory.create(deployer.master_dict['pki_registry_path'])
        deployer.directory.create(deployer.master_dict['pki_instance_type_registry_path'])
        deployer.directory.create(deployer.master_dict['pki_instance_registry_path'])
        deployer.directory.create(deployer.master_dict['pki_subsystem_registry_path'])
        deployer.file.copy(deployer.master_dict['pki_default_deployment_cfg'],
                       deployer.master_dict['pki_default_deployment_cfg_replica'])

        print "Storing deployment configuration into " + deployer.master_dict['pki_user_deployment_cfg_replica'] + "."

        # Archive the user deployment configuration excluding the sensitive parameters
        sensitive_parameters = deployer.master_dict['sensitive_parameters'].split()
        sections = config.user_config.sections()
        for s in sections:
            for k in sensitive_parameters:
                config.user_config.set(s, k, 'XXXXXXXX')
        with open(deployer.master_dict['pki_user_deployment_cfg_replica'], 'w') as f:
            config.user_config.write(f)

        # establish top-level infrastructure, instance, and subsystem
        # base directories and create the "registry" symbolic link that
        # the "pkidestroy" executable relies upon
        deployer.directory.create(deployer.master_dict['pki_path'])
        deployer.directory.create(deployer.master_dict['pki_instance_path'])
        deployer.directory.create(deployer.master_dict['pki_subsystem_path'])
        deployer.symlink.create(deployer.master_dict['pki_instance_registry_path'],
                            deployer.master_dict['pki_subsystem_registry_link'])
        #
        # NOTE:  If "infrastructure_layout" scriptlet execution has been
        #        successfully executed to this point, the "pkidestroy" command
        #        may always be utilized to remove the entire infrastructure.
        #
        # no need to establish top-level infrastructure logs
        # since it now stores 'pkispawn'/'pkidestroy' logs
        # and will already exist
        # deployer.directory.create(deployer.master_dict['pki_log_path'])
        # establish top-level infrastructure configuration
        if deployer.master_dict['pki_configuration_path'] != \
           config.PKI_DEPLOYMENT_CONFIGURATION_ROOT:
            deployer.directory.create(deployer.master_dict['pki_configuration_path'])
        return self.rv

    def destroy(self, deployer):

        config.pki_log.info(log.ADMIN_DOMAIN_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # remove top-level infrastructure base
        if deployer.master_dict['pki_subsystem'] in config.PKI_SUBSYSTEMS and\
           deployer.instance.pki_instance_subsystems() == 0:
            # remove top-level infrastructure base
            deployer.directory.delete(deployer.master_dict['pki_path'])
            # do NOT remove top-level infrastructure logs
            # since it now stores 'pkispawn'/'pkidestroy' logs
            # deployer.directory.delete(deployer.master_dict['pki_log_path'])
            # remove top-level infrastructure configuration
            if deployer.directory.is_empty(deployer.master_dict['pki_configuration_path'])\
               and deployer.master_dict['pki_configuration_path'] != \
               config.PKI_DEPLOYMENT_CONFIGURATION_ROOT:
                deployer.directory.delete(deployer.master_dict['pki_configuration_path'])
            # remove top-level infrastructure registry
            deployer.directory.delete(deployer.master_dict['pki_registry_path'])
        return self.rv
