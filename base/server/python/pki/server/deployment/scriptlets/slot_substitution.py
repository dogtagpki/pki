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


# PKI Deployment Slot Substitution Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):

    def spawn(self, deployer):

        if config.str2bool(deployer.mdict['pki_skip_installation']):
            config.pki_log.info(log.SKIP_SLOT_ASSIGNMENT_SPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            return

        config.pki_log.info(log.SLOT_ASSIGNMENT_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        deployer.file.copy_with_slot_substitution(
            deployer.mdict['pki_source_registry'],
            deployer.mdict['pki_target_registry'],
            overwrite_flag=True)

        # these are instance level files. Only copy for the first instance.
        if len(deployer.instance.tomcat_instance_subsystems()) == 1:
            deployer.file.copy_with_slot_substitution(
                deployer.mdict['pki_source_servercertnick_conf'],
                deployer.mdict['pki_target_servercertnick_conf'],
                overwrite_flag=True)
            deployer.file.copy_with_slot_substitution(
                deployer.mdict['pki_source_server_xml'],
                deployer.mdict['pki_target_server_xml'],
                overwrite_flag=True)

        if deployer.mdict['pki_subsystem'] == "CA":
            deployer.file.copy_with_slot_substitution(
                deployer.mdict['pki_source_proxy_conf'],
                deployer.mdict['pki_target_proxy_conf'])
        elif deployer.mdict['pki_subsystem'] == "TPS":
            deployer.file.copy_with_slot_substitution(
                deployer.mdict['pki_source_registry_cfg'],
                deployer.mdict['pki_target_registry_cfg'])
            deployer.file.copy_with_slot_substitution(
                deployer.mdict['pki_source_phone_home_xml'],
                deployer.mdict['pki_target_phone_home_xml'])

    def destroy(self, deployer):
        config.pki_log.info(log.SLOT_ASSIGNMENT_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        config.pki_log.info("NOTHING NEEDS TO BE IMPLEMENTED",
                            extra=config.PKI_INDENTATION_LEVEL_2)
