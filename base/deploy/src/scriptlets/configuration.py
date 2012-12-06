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
        if config.str2bool(master['pki_skip_configuration']):
            config.pki_log.info(log.SKIP_CONFIGURATION_SPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            return self.rv
        config.pki_log.info(log.CONFIGURATION_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)

        # Place "slightly" less restrictive permissions on
        # the top-level client directory ONLY
        util.directory.create(master['pki_client_subsystem_dir'],
            uid=0, gid=0,
            perms=config.PKI_DEPLOYMENT_DEFAULT_CLIENT_DIR_PERMISSIONS)
        # Since 'certutil' does NOT strip the 'token=' portion of
        # the 'token=password' entries, create a client password file
        # which ONLY contains the 'password' for the purposes of
        # allowing 'certutil' to generate the security databases
        util.password.create_password_conf(
            master['pki_client_password_conf'],
            master['pki_client_database_password'], pin_sans_token=True)
        util.file.modify(master['pki_client_password_conf'],
                         uid=0, gid=0)
        # Similarly, create a simple password file containing the
        # PKCS #12 password used when exporting the "Admin Certificate"
        # into a PKCS #12 file
        util.password.create_client_pkcs12_password_conf(
            master['pki_client_pkcs12_password_conf'])
        util.file.modify(master['pki_client_pkcs12_password_conf'])
        util.directory.create(master['pki_client_database_dir'],
                              uid=0, gid=0)
        util.certutil.create_security_databases(
            master['pki_client_database_dir'],
            master['pki_client_cert_database'],
            master['pki_client_key_database'],
            master['pki_client_secmod_database'],
            password_file=master['pki_client_password_conf'])
        util.symlink.create(master['pki_systemd_service'],
                            master['pki_systemd_service_link'])

        # Start/Restart this Apache/Tomcat PKI Process
        if master['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS:
            apache_instance_subsystems =\
                util.instance.apache_instance_subsystems()
            if apache_instance_subsystems == 1:
                util.systemd.start()
            elif apache_instance_subsystems > 1:
                util.systemd.restart()
        elif master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            # Optionally prepare to enable a java debugger
            # (e. g. - 'eclipse'):
            if config.str2bool(master['pki_enable_java_debugger']):
                config.prepare_for_an_external_java_debugger(
                    master['pki_target_tomcat_conf_instance_id'])
            tomcat_instance_subsystems =\
                util.instance.tomcat_instance_subsystems()
            if tomcat_instance_subsystems == 1:
                util.systemd.start()
            elif tomcat_instance_subsystems > 1:
                util.systemd.restart()

        # Pass control to the Java servlet via Jython 2.2 'configuration.jy'
        util.jython.invoke(
            master['pki_jython_configuration_scriptlet'],
            master['RESTEASY_LIB'])
        return self.rv

    def respawn(self):
        config.pki_log.info(log.CONFIGURATION_RESPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        return self.rv

    def destroy(self):
        config.pki_log.info(log.CONFIGURATION_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        if master['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS and\
           util.instance.apache_instance_subsystems() == 1:
            if util.directory.exists(master['pki_client_dir']):
                util.directory.delete(master['pki_client_dir'])
            util.symlink.delete(master['pki_systemd_service_link'])
        elif master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS and\
             util.instance.tomcat_instance_subsystems() == 1:
            if util.directory.exists(master['pki_client_dir']):
                util.directory.delete(master['pki_client_dir'])
            util.symlink.delete(master['pki_systemd_service_link'])
        return self.rv
