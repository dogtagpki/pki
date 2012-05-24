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


# PKI Deployment Configuration Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):
    rv = 0

    def spawn(self):
        config.pki_log.info(log.CONFIGURATION_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        if not config.pki_dry_run_flag:
            util.directory.create(master['pki_client_path'], uid=0, gid=0)
            util.password.create_password_conf(
                master['pki_client_password_conf'],
                master['pki_client_pin'])
            util.directory.create(master['pki_client_database_path'],
                                  uid=0, gid=0)
            util.certutil.create_security_databases(
                master['pki_client_database_path'],
                master['pki_client_cert_database'],
                master['pki_client_key_database'],
                master['pki_client_secmod_database'],
                password_file=master['pki_client_password_conf'])
            util.symlink.create(
                config.pki_master_dict['pki_systemd_service'],
                config.pki_master_dict['pki_systemd_service_link'])
        else:
            util.password.create_password_conf(
                master['pki_client_password_conf'],
                master['pki_client_pin'])
            util.certutil.create_security_databases(
                master['pki_client_database_path'],
                master['pki_client_cert_database'],
                master['pki_client_key_database'],
                master['pki_client_secmod_database'],
                password_file=master['pki_client_password_conf'])
        # Pass control to the Java servlet via Jython 2.2 'configuration.jy'
        util.jython.invoke(master['pki_jython_configuration_scriptlet'])
        return self.rv

    def respawn(self):
        config.pki_log.info(log.CONFIGURATION_RESPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        return self.rv

    def destroy(self):
        config.pki_log.info(log.CONFIGURATION_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        if not config.pki_dry_run_flag:
            if master['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS and\
               util.instance.apache_instances() == 1:
                util.directory.delete(master['pki_client_path'])
                util.symlink.delete(
                    config.pki_master_dict['pki_systemd_service_link'])
            elif master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS and\
                 util.instance.tomcat_instances() == 1:
                util.directory.delete(master['pki_client_path'])
                util.symlink.delete(
                    config.pki_master_dict['pki_systemd_service_link'])
        else:
            # ALWAYS display correct information (even during dry_run)
            if master['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS and\
               util.instance.apache_instances() == 0:
                util.directory.delete(master['pki_client_path'])
                util.symlink.delete(
                    config.pki_master_dict['pki_systemd_service_link'])
            elif master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS and\
                 util.instance.tomcat_instances() == 0:
                util.directory.delete(master['pki_client_path'])
                util.symlink.delete(
                    config.pki_master_dict['pki_systemd_service_link'])
        return self.rv
