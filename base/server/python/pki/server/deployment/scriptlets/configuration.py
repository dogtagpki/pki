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

from __future__ import absolute_import
import json

# PKI Deployment Imports
from .. import pkiconfig as config
from .. import pkimessages as log
from .. import pkiscriptlet
import pki.system
import pki.encoder


# PKI Deployment Configuration Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):
    rv = 0

    def spawn(self, deployer):

        # ALWAYS establish the following Tomcat instance symbolic link since
        # this link is required by both automatic pkispawn instance
        # configuration as well as manual browser GUI instance configuration
        deployer.symlink.create(deployer.mdict['pki_systemd_service'],
                                deployer.mdict['pki_systemd_service_link'])

        if config.str2bool(deployer.mdict['pki_skip_configuration']):
            config.pki_log.info(log.SKIP_CONFIGURATION_SPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            return self.rv
        config.pki_log.info(log.CONFIGURATION_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)

        # Place "slightly" less restrictive permissions on
        # the top-level client directory ONLY
        deployer.directory.create(
            deployer.mdict['pki_client_subsystem_dir'],
            uid=0, gid=0,
            perms=config.PKI_DEPLOYMENT_DEFAULT_CLIENT_DIR_PERMISSIONS)
        # Since 'certutil' does NOT strip the 'token=' portion of
        # the 'token=password' entries, create a client password file
        # which ONLY contains the 'password' for the purposes of
        # allowing 'certutil' to generate the security databases
        deployer.password.create_password_conf(
            deployer.mdict['pki_client_password_conf'],
            deployer.mdict['pki_client_database_password'], pin_sans_token=True)
        deployer.file.modify(
            deployer.mdict['pki_client_password_conf'],
            uid=0, gid=0)
        # Similarly, create a simple password file containing the
        # PKCS #12 password used when exporting the "Admin Certificate"
        # into a PKCS #12 file
        deployer.password.create_client_pkcs12_password_conf(
            deployer.mdict['pki_client_pkcs12_password_conf'])
        deployer.file.modify(deployer.mdict['pki_client_pkcs12_password_conf'])
        deployer.directory.create(
            deployer.mdict['pki_client_database_dir'],
            uid=0, gid=0)
        deployer.certutil.create_security_databases(
            deployer.mdict['pki_client_database_dir'],
            deployer.mdict['pki_client_cert_database'],
            deployer.mdict['pki_client_key_database'],
            deployer.mdict['pki_client_secmod_database'],
            password_file=deployer.mdict['pki_client_password_conf'])

        # Start/Restart this Tomcat PKI Process
        # Optionally prepare to enable a java debugger
        # (e. g. - 'eclipse'):
        if config.str2bool(deployer.mdict['pki_enable_java_debugger']):
            config.prepare_for_an_external_java_debugger(
                deployer.mdict['pki_target_tomcat_conf_instance_id'])
        tomcat_instance_subsystems = \
            len(deployer.instance.tomcat_instance_subsystems())
        if tomcat_instance_subsystems == 1:
            deployer.systemd.start()
        elif tomcat_instance_subsystems > 1:
            deployer.systemd.restart()

        # wait for startup
        status = deployer.instance.wait_for_startup(60)
        if status is None:
            config.pki_log.error(
                "server failed to restart",
                extra=config.PKI_INDENTATION_LEVEL_2)
            raise Exception("server failed to restart")

        # Optionally wait for debugger to attach (e. g. - 'eclipse'):
        if config.str2bool(deployer.mdict['pki_enable_java_debugger']):
            config.wait_to_attach_an_external_java_debugger()

        # Construct PKI Subsystem Configuration Data
        data = None
        if deployer.mdict['pki_instance_type'] == "Tomcat":
            # CA, KRA, OCSP, TKS, or TPS
            data = deployer.config_client.construct_pki_configuration_data()

        # Configure the subsystem
        deployer.config_client.configure_pki_data(
            json.dumps(data, cls=pki.encoder.CustomTypeEncoder))

        return self.rv

    def destroy(self, deployer):

        config.pki_log.info(log.CONFIGURATION_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        if len(deployer.instance.tomcat_instance_subsystems()) == 1:
            if deployer.directory.exists(deployer.mdict['pki_client_dir']):
                deployer.directory.delete(deployer.mdict['pki_client_dir'])
            deployer.symlink.delete(deployer.mdict['pki_systemd_service_link'])
        return self.rv
