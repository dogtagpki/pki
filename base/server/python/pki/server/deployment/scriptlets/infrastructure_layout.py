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
from __future__ import print_function
import logging

# PKI Deployment Imports
from .. import pkiconfig as config
from .. import pkiscriptlet
import pki.util

logger = logging.getLogger(__name__)


# PKI Deployment Top-Level Infrastructure Layout Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):

    def spawn(self, deployer):

        if config.str2bool(deployer.mdict['pki_skip_installation']):
            logger.info('Skipping infrastructure setup')
            return

        logger.info('Setting up infrastructure')

        # Archive the user deployment configuration excluding the sensitive
        # parameters
        sensitive_parameters = deployer.mdict['sensitive_parameters'].split()
        sections = deployer.user_config.sections()
        sections.append('DEFAULT')
        for s in sections:
            for k in sensitive_parameters:
                deployer.user_config.remove_option(s, k)

        # establish top-level infrastructure, instance, and subsystem
        # base directories and create the "registry" symbolic link that
        # the "pkidestroy" executable relies upon
        if deployer.mdict['pki_path'] != "/var/lib/pki":
            logger.info('Creating %s', deployer.mdict['pki_path'])
            deployer.directory.create(deployer.mdict['pki_path'])

        # NOTE:  If "infrastructure_layout" scriptlet execution has been
        #        successfully executed to this point, the "pkidestroy" command
        #        may always be utilized to remove the entire infrastructure.
        #
        # no need to establish top-level infrastructure logs
        # since it now stores 'pkispawn'/'pkidestroy' logs
        # and will already exist
        # deployer.directory.create(deployer.mdict['pki_log_path'])
        # establish top-level infrastructure configuration
        if deployer.mdict['pki_configuration_path'] != \
           config.PKI_DEPLOYMENT_CONFIGURATION_ROOT:
            deployer.directory.create(deployer.mdict['pki_configuration_path'])

    def destroy(self, deployer):

        # if this is not the last subsystem, skip
        if deployer.instance.pki_instance_subsystems() > 0:
            return

        logger.info('Cleaning up infrastructure')

        if deployer.mdict['pki_path'] != "/var/lib/pki":
            logger.info('Removing %s', deployer.mdict['pki_path'])
            pki.util.rmtree(deployer.mdict['pki_path'],
                            deployer.force)

        # do NOT remove top-level infrastructure logs
        # since it now stores 'pkispawn'/'pkidestroy' logs
        # deployer.directory.delete(deployer.mdict['pki_log_path'])
        # remove top-level infrastructure configuration

        if deployer.directory.is_empty(deployer.mdict['pki_configuration_path']) and \
            deployer.mdict['pki_configuration_path'] != \
                config.PKI_DEPLOYMENT_CONFIGURATION_ROOT:

            logger.info('Removing %s', deployer.mdict['pki_configuration_path'])
            pki.util.rmtree(deployer.mdict['pki_configuration_path'],
                            deployer.force)
