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

logger = logging.getLogger('selinux')


# PKI Deployment Selinux Setup Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):

    suffix = "(/.*)?"

    def restore_context(self, mdict):
        selinux.restorecon(mdict['pki_instance_path'], True)
        selinux.restorecon(config.PKI_DEPLOYMENT_LOG_ROOT, True)
        selinux.restorecon(mdict['pki_instance_log_path'], True)
        selinux.restorecon(mdict['pki_instance_configuration_path'], True)

    def spawn(self, deployer):

        if config.str2bool(deployer.mdict['pki_skip_installation']):
            logger.info('Skipping SELinux setup')
            return

        if not selinux.is_selinux_enabled() or seobject is None:
            logger.info('SELinux disabled')
            return

        logger.info('Creating SELinux contexts')

        # A maximum of 10 tries to create the SELinux contexts
        counter = 0
        max_tries = 10
        while True:
            try:
                # check first if any transactions are required
                if len(ports) == 0 and deployer.mdict['pki_instance_name'] == \
                        config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_INSTANCE_NAME:
                    self.restore_context(deployer.mdict)
                    return

                # add SELinux contexts when adding the first subsystem
                if len(deployer.instance.tomcat_instance_subsystems()) == 1:
                    trans = seobject.semanageRecords("targeted")
                    trans.start()
                    if deployer.mdict['pki_instance_name'] != \
                            config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_INSTANCE_NAME:

                        fcon = seobject.fcontextRecords(trans)

                        logger.info(
                            "adding selinux fcontext \"%s\"",
                            deployer.mdict['pki_instance_path'] + self.suffix)
                        fcon.add(
                            deployer.mdict['pki_instance_path'] + self.suffix,
                            config.PKI_INSTANCE_SELINUX_CONTEXT, "", "s0", "")

                        logger.info(
                            "adding selinux fcontext \"%s\"",
                            deployer.mdict['pki_instance_log_path'] +
                            self.suffix)
                        fcon.add(
                            deployer.mdict['pki_instance_log_path'] +
                            self.suffix,
                            config.PKI_LOG_SELINUX_CONTEXT, "", "s0", "")

                        logger.info(
                            "adding selinux fcontext \"%s\"",
                            deployer.mdict['pki_instance_configuration_path'] +
                            self.suffix)
                        fcon.add(
                            deployer.mdict['pki_instance_configuration_path'] +
                            self.suffix,
                            config.PKI_CFG_SELINUX_CONTEXT, "", "s0", "")

                        logger.info(
                            "adding selinux fcontext \"%s\"",
                            deployer.mdict['pki_server_database_path'] + self.suffix)
                        fcon.add(
                            deployer.mdict['pki_server_database_path'] + self.suffix,
                            config.PKI_CERTDB_SELINUX_CONTEXT, "", "s0", "")

                        port_records = seobject.portRecords(trans)
                        for port in ports:
                            logger.info("adding selinux port %s", port)
                            port_records.add(
                                port, "tcp", "s0",
                                config.PKI_PORT_SELINUX_CONTEXT)

                    trans.finish()

                    self.restore_context(deployer.mdict)
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

        logger.info('Removing SELinux contexts')

        # check first if any transactions are required
        if (len(ports) == 0 and deployer.mdict['pki_instance_name'] ==
                config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_INSTANCE_NAME):
            return

        # remove SELinux contexts when removing the last subsystem
        if len(deployer.instance.tomcat_instance_subsystems()) == 0 and \
                deployer.mdict['pki_instance_name'] != \
                config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_INSTANCE_NAME:

            context_to_delete = ['pki_instance_path', 'pki_instance_log_path',
                                 'pki_instance_configuration_path', 'pki_server_database_path',
                                 'ports']

            # Delete SELinux contexts
            for context in context_to_delete:

                # A maximum of 10 tries to delete 1 SELinux context
                max_tries = 10

                for counter in range(1, max_tries):

                    trans = seobject.semanageRecords("targeted")
                    try:
                        trans.start()
                        # If a port context is specified
                        if context == 'ports':
                            port_records = seobject.portRecords(trans)
                            for port in ports:
                                logger.info("deleting selinux port %s", port)
                                port_records.delete(port, "tcp")

                        # Else it's a file context
                        else:
                            fcon = seobject.fcontextRecords(trans)

                            logger.info(
                                "deleting selinux fcontext \"%s\"",
                                deployer.mdict[context] + self.suffix)
                            fcon.delete(
                                deployer.mdict[context] + self.suffix, "")
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
                            # If it is a forced destroy, there won't be any se contexts to destroy
                            if deployer.mdict['pki_force_destroy']:
                                break
                            else:
                                raise
                    finally:
                        trans.finish()
