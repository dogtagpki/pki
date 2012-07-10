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

# PKI Deployment Imports
import pkiconfig as config
from pkiconfig import pki_master_dict as master
from pkiconfig import pki_selinux_config_ports as ports
import pkihelper as util
import pkimessages as log
import pkiscriptlet
import seobject
import selinux

# PKI Deployment Selinux Setup Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):
    rv = 0
    suffix = "(/.*)?"

    def restore_context(self):
        selinux.restorecon(master['pki_instance_path'], True)
        selinux.restorecon(master['pki_instance_log_path'], True)
        selinux.restorecon(master['pki_instance_configuration_path'], True)

    def spawn(self):
        config.pki_log.info(log.SUBSYSTEM_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)

        # check first if any transactions are required
        if len(ports) == 0 and master['pki_instance_name'] == \
           config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_INSTANCE_NAME:
               self.restore_context()
               return self.rv

        trans = seobject.semanageRecords("targeted")
        trans.start()
        if master['pki_instance_name'] != \
          config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_INSTANCE_NAME:
            fcon1 = seobject.fcontextRecords()
            fcon1.add(master['pki_instance_path'] + self.suffix,
                      config.PKI_INSTANCE_SELINUX_CONTEXT, "", "s0", "")

            fcon2 = seobject.fcontextRecords()
            fcon2.add(master['pki_instance_log_path'] + self.suffix,
                      config.PKI_LOG_SELINUX_CONTEXT, "", "s0", "")

            fcon3 = seobject.fcontextRecords()
            fcon3.add(master['pki_instance_configuration_path'] + self.suffix,
                      config.PKI_CFG_SELINUX_CONTEXT, "", "s0", "")
        for port in ports:
            port1 = seobject.portRecords()
            port1.add(port, "tcp", "s0", config.PKI_PORT_SELINUX_CONTEXT)
        trans.finish()

        self.restore_context()
        return self.rv

    def respawn(self):
        config.pki_log.info(log.SUBSYSTEM_RESPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        self.restore_context()
        return self.rv

    def destroy(self):
        config.pki_log.info(log.SUBSYSTEM_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)

        # check first if any transactions are required
        if len(ports) == 0 and master['pki_instance_name'] == \
           config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_INSTANCE_NAME:
               return self.rv

        trans = seobject.semanageRecords("targeted")
        trans.start()
        if master['pki_instance_name'] != \
          config.PKI_DEPLOYMENT_DEFAULT_TOMCAT_INSTANCE_NAME:
            fcon1 = seobject.fcontextRecords()
            fcon1.delete(master['pki_instance_path'] + self.suffix , "")

            fcon2 = seobject.fcontextRecords()
            fcon2.delete(master['pki_instance_log_path'] + self.suffix, "")

            fcon3 = seobject.fcontextRecords()
            fcon3.delete(master['pki_instance_configuration_path'] + \
                         self.suffix, "")
        for port in ports:
            port1 = seobject.portRecords()
            port1.delete(port, "tcp")
        trans.finish()
        return self.rv
