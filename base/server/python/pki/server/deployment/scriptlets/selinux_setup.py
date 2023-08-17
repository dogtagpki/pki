# Authors:
#     Ade Lee <alee@redhat.com>
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
import logging
import selinux
import sys
import time

# PKI Deployment Imports
from .. import pkiconfig as config
from ..pkiconfig import pki_selinux_config_ports as ports
from .. import pkiscriptlet

seobject = None
if selinux.is_selinux_enabled():
    try:
        import seobject
    except ImportError:
        # TODO: Fedora 22 has an incomplete Python 3 package
        # sepolgen is missing.
        if sys.version_info.major == 2:
            raise

logger = logging.getLogger(__name__)


# PKI Deployment Selinux Setup Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):

    def spawn(self, deployer):

        if config.str2bool(deployer.mdict['pki_skip_installation']):
            logger.info('Skipping SELinux setup')
            return

        if not selinux.is_selinux_enabled() or seobject is None:
            logger.info('SELinux disabled')
            return

        instance = self.instance

        logger.info('Creating SELinux contexts')

        # A maximum of 10 tries to create the SELinux contexts
        counter = 0
        max_tries = 10
        while True:
            try:
                # check first if any transactions are required
                if len(ports) == 0 and deployer.mdict['pki_instance_name'] == \
                        config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_INSTANCE_NAME:
                    deployer.restore_selinux_contexts()
                    return

                # add SELinux contexts when adding the first subsystem
                if len(instance.get_subsystems()) == 1:
                    if deployer.mdict['pki_instance_name'] != \
                            config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_INSTANCE_NAME:
                        deployer.create_selinux_contexts()

                    deployer.restore_selinux_contexts()
                break

            except ValueError as e:
                error_message = str(e)
                logger.error(error_message)
                if error_message.strip() == \
                        "Could not start semanage transaction":
                    counter += 1
                    if counter >= max_tries:
                        raise
                    time.sleep(5)
                    logger.debug("Retrying to setup the selinux context ...")
                else:
                    raise

    def destroy(self, deployer):

        if not bool(selinux.is_selinux_enabled()):
            logger.info('SELinux disabled')
            return

        # check first if any transactions are required
        if (len(ports) == 0 and deployer.mdict['pki_instance_name'] ==
                config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_INSTANCE_NAME):
            return

        instance = self.instance

        logger.info('Removing SELinux contexts')

        # A maximum of 10 tries to delete the SELinux contexts
        max_tries = 10
        for counter in range(1, max_tries):
            try:
                # remove SELinux contexts when removing the last subsystem
                if not instance.get_subsystems():
                    if deployer.mdict['pki_instance_name'] != \
                            config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_INSTANCE_NAME:
                        deployer.remove_selinux_contexts()
                break

            except ValueError as e:
                error_message = str(e)
                logger.error(error_message)
                if error_message.strip() == \
                        "Could not start semanage transaction":
                    if counter >= max_tries:
                        raise
                    time.sleep(5)
                    logger.debug("Retrying to remove selinux context ...")
                else:
                    raise
