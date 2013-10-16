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


# PKI Deployment Initialization Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):
    rv = 0

    def spawn(self, deployer):

        # begin official logging
        config.pki_log.info(log.PKISPAWN_BEGIN_MESSAGE_2,
                            deployer.master_dict['pki_subsystem'],
                            deployer.master_dict['pki_instance_name'],
                            extra=config.PKI_INDENTATION_LEVEL_0)
        if config.str2bool(deployer.master_dict['pki_skip_installation']):
            config.pki_log.info(log.SKIP_INITIALIZATION_SPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            return self.rv
        else:
            config.pki_log.info(log.INITIALIZATION_SPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            if (deployer.master_dict['pki_subsystem'] == "CA" or
                config.str2bool(deployer.master_dict['pki_standalone'])) and\
               config.str2bool(deployer.master_dict['pki_external_step_two']):
                # verify that this External CA (Step 2), or Stand-alone PKI
                # (Step 2) currently EXISTS for this "instance"
                deployer.instance.verify_subsystem_exists()
                deployer.master_dict['pki_skip_installation'] = "True"
            else:
                # verify that this type of "subsystem" does NOT yet
                # exist for this "instance"
                deployer.instance.verify_subsystem_does_not_exist()
                # detect and avoid any namespace collisions
                deployer.namespace.collision_detection()
        # initialize 'uid' and 'gid'
        deployer.identity.add_uid_and_gid(deployer.master_dict['pki_user'], deployer.master_dict['pki_group'])
        # establish 'uid' and 'gid'
        deployer.identity.set_uid(deployer.master_dict['pki_user'])
        deployer.identity.set_gid(deployer.master_dict['pki_group'])
        # verify existence of SENSITIVE configuration file data
        deployer.configuration_file.verify_sensitive_data()
        # verify existence of MUTUALLY EXCLUSIVE configuration file data
        deployer.configuration_file.verify_mutually_exclusive_data()
        # verify existence of PREDEFINED configuration file data
        deployer.configuration_file.verify_predefined_configuration_file_data()
        # verify selinux context of selected ports
        deployer.configuration_file.populate_non_default_ports()
        deployer.configuration_file.verify_selinux_ports()
        return self.rv

    def destroy(self, deployer):

        # begin official logging
        config.pki_log.info(log.PKIDESTROY_BEGIN_MESSAGE_2,
                            deployer.master_dict['pki_subsystem'],
                            deployer.master_dict['pki_instance_name'],
                            extra=config.PKI_INDENTATION_LEVEL_0)
        config.pki_log.info(log.INITIALIZATION_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # verify that this type of "subsystem" currently EXISTS
        # for this "instance"
        deployer.instance.verify_subsystem_exists()
        # verify that the command-line parameters match the values
        # that are present in the corresponding configuration file
        deployer.configuration_file.verify_command_matches_configuration_file()
        # establish 'uid' and 'gid'
        deployer.identity.set_uid(deployer.master_dict['pki_user'])
        deployer.identity.set_gid(deployer.master_dict['pki_group'])
        # get ports to remove selinux context
        deployer.configuration_file.populate_non_default_ports()

        # get deinstallation token
        token = deployer.security_domain.get_installation_token(
            config.pki_secdomain_user, config.pki_secdomain_pass)

        # remove kra connector from CA if this is a KRA
        deployer.kra_connector.deregister()

        # remove tps connector from TKS if this is a TPS
        deployer.tps_connector.deregister()

        # de-register instance from its Security Domain
        #
        #     NOTE:  Since the security domain of an instance must be up
        #            and running in order to be de-registered, this step
        #            must be done PRIOR to instance shutdown because this
        #            instance's security domain may be a part of a
        #            tightly-coupled shared instance.
        #
        deployer.security_domain.deregister(token)
        # ALWAYS Stop this Apache/Tomcat PKI Process
        deployer.systemd.stop()
        return self.rv
