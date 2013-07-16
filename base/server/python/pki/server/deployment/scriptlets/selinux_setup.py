#!/usr/bin/python -t
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

import selinux
import time
if selinux.is_selinux_enabled():
    import seobject

# PKI Deployment Imports
from .. import pkiconfig as config
from ..pkiconfig import pki_selinux_config_ports as ports
from .. import pkimessages as log
from .. import pkiscriptlet


# PKI Deployment Selinux Setup Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):
    rv = 0
    suffix = "(/.*)?"

    def restore_context(self, master_dict):
        selinux.restorecon(master_dict['pki_instance_path'], True)
        selinux.restorecon(config.PKI_DEPLOYMENT_LOG_ROOT, True)
        selinux.restorecon(master_dict['pki_instance_log_path'], True)
        selinux.restorecon(master_dict['pki_instance_configuration_path'], True)

    def spawn(self, deployer):

        if config.str2bool(deployer.master_dict['pki_skip_installation']):
            config.pki_log.info(log.SKIP_SELINUX_SPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            return self.rv

        if not bool(selinux.is_selinux_enabled()):
            config.pki_log.info(log.SELINUX_DISABLED_SPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            return self.rv

        config.pki_log.info(log.SELINUX_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # A maximum of 10 tries to create the SELinux contexts
        counter = 0
        max_tries = 10
        while True:
            try:
                # check first if any transactions are required
                if len(ports) == 0 and deployer.master_dict['pki_instance_name'] == \
                    config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_INSTANCE_NAME:
                    self.restore_context(deployer.master_dict)
                    return self.rv

                # add SELinux contexts when adding the first subsystem
                if deployer.master_dict['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS and\
                    deployer.instance.apache_instance_subsystems() == 1 or\
                    deployer.master_dict['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS and\
                    len(deployer.instance.tomcat_instance_subsystems()) == 1:

                    trans = seobject.semanageRecords("targeted")
                    trans.start()
                    if deployer.master_dict['pki_instance_name'] != \
                        config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_INSTANCE_NAME:

                        fcon = seobject.fcontextRecords()

                        config.pki_log.info("adding selinux fcontext \"%s\"",
                        deployer.master_dict['pki_instance_path'] + self.suffix,
                        extra=config.PKI_INDENTATION_LEVEL_2)
                        fcon.add(deployer.master_dict['pki_instance_path'] + self.suffix,
                                 config.PKI_INSTANCE_SELINUX_CONTEXT, "", "s0", "")

                        config.pki_log.info("adding selinux fcontext \"%s\"",
                                            deployer.master_dict['pki_instance_log_path'] + self.suffix,
                                            extra=config.PKI_INDENTATION_LEVEL_2)
                        fcon.add(deployer.master_dict['pki_instance_log_path'] + self.suffix,
                                 config.PKI_LOG_SELINUX_CONTEXT, "", "s0", "")

                        config.pki_log.info("adding selinux fcontext \"%s\"",
                                            deployer.master_dict['pki_instance_configuration_path'] + self.suffix,
                                            extra=config.PKI_INDENTATION_LEVEL_2)
                        fcon.add(deployer.master_dict['pki_instance_configuration_path'] + self.suffix,
                                 config.PKI_CFG_SELINUX_CONTEXT, "", "s0", "")

                        config.pki_log.info("adding selinux fcontext \"%s\"",
                                            deployer.master_dict['pki_database_path'] + self.suffix,
                                            extra=config.PKI_INDENTATION_LEVEL_2)
                        fcon.add(deployer.master_dict['pki_database_path'] + self.suffix,
                                 config.PKI_CERTDB_SELINUX_CONTEXT, "", "s0", "")

                        portRecords = seobject.portRecords()
                        for port in ports:
                            config.pki_log.info("adding selinux port %s", port,
                                                extra=config.PKI_INDENTATION_LEVEL_2)
                            portRecords.add(port, "tcp", "s0", config.PKI_PORT_SELINUX_CONTEXT)

                    trans.finish()

                    self.restore_context(deployer.master_dict)
                break
            except ValueError as e:
                error_message = str(e)
                config.pki_log.debug(error_message)
                if error_message.strip() == "Could not start semanage transaction":
                    counter = counter + 1
                    if counter >= max_tries:
                        raise
                    time.sleep(5)
                    config.pki_log.debug("Retrying to setup the selinux context ...")
                else:
                    raise

        return self.rv

    def destroy(self, deployer):

        if not bool(selinux.is_selinux_enabled()):
            config.pki_log.info(log.SELINUX_DISABLED_DESTROY_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            return self.rv
        config.pki_log.info(log.SELINUX_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)

        # check first if any transactions are required
        if (len(ports) == 0 and deployer.master_dict['pki_instance_name'] ==
            config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_INSTANCE_NAME):
            return self.rv
        # A maximum of 10 tries to delete the SELinux contexts
        counter = 1
        max_tries = 10
        while True:
            try:
                # remove SELinux contexts when removing the last subsystem
                if (deployer.master_dict['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS and
                    deployer.instance.apache_instance_subsystems() == 0 or
                    deployer.master_dict['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS and
                    len(deployer.instance.tomcat_instance_subsystems()) == 0):

                    trans = seobject.semanageRecords("targeted")
                    trans.start()

                    if deployer.master_dict['pki_instance_name'] != \
                        config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_INSTANCE_NAME:

                        fcon = seobject.fcontextRecords()

                        config.pki_log.info("deleting selinux fcontext \"%s\"",
                                     deployer.master_dict['pki_instance_path'] + self.suffix,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                        fcon.delete(deployer.master_dict['pki_instance_path'] + self.suffix , "")

                        config.pki_log.info("deleting selinux fcontext \"%s\"",
                                 deployer.master_dict['pki_instance_log_path'] + self.suffix,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
                        fcon.delete(deployer.master_dict['pki_instance_log_path'] + self.suffix, "")

                        config.pki_log.info("deleting selinux fcontext \"%s\"",
                                  deployer.master_dict['pki_instance_configuration_path'] + self.suffix,
                                  extra=config.PKI_INDENTATION_LEVEL_2)
                        fcon.delete(deployer.master_dict['pki_instance_configuration_path'] +
                                    self.suffix, "")

                        config.pki_log.info("deleting selinux fcontext \"%s\"",
                                     deployer.master_dict['pki_database_path'] + self.suffix,
                                     extra=config.PKI_INDENTATION_LEVEL_2)
                        fcon.delete(deployer.master_dict['pki_database_path'] + self.suffix , "")

                        portRecords = seobject.portRecords()
                        for port in ports:
                            config.pki_log.info("deleting selinux port %s", port,
                                                extra=config.PKI_INDENTATION_LEVEL_2)
                            portRecords.delete(port, "tcp")

                    trans.finish()
                break
            except ValueError as e:
                error_message = str(e)
                config.pki_log.debug(error_message)
                if error_message.strip() == "Could not start semanage transaction":
                    counter = counter + 1
                    if counter >= max_tries:
                        raise
                    time.sleep(5)
                    config.pki_log.debug("Retrying to remove selinux context ...")
                else:
                    raise

        return self.rv
