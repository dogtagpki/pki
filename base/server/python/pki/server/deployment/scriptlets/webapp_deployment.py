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

# System Imports
import os

# PKI Deployment Imports
from .. import pkiconfig as config
from .. import pkimessages as log
from .. import pkiscriptlet


# PKI Web Application Deployment Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):
    rv = 0

    def spawn(self, deployer):

        if deployer.mdict['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            if config.str2bool(deployer.mdict['pki_skip_installation']):
                config.pki_log.info(log.SKIP_WEBAPP_DEPLOYMENT_SPAWN_1,
                                     __name__,
                                    extra=config.PKI_INDENTATION_LEVEL_1)
                return self.rv

            config.pki_log.info(log.WEBAPP_DEPLOYMENT_SPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)

            # For TPS, deploy web application directly from /usr/share/pki.
            if deployer.mdict['pki_subsystem'] == "TPS":
                deployer.file.copy(
                    os.path.join(
                        config.PKI_DEPLOYMENT_SOURCE_ROOT,
                        "tps",
                        "conf",
                        "Catalina",
                        "localhost",
                        "tps.xml"),
                    os.path.join(
                        deployer.mdict['pki_instance_configuration_path'],
                        "Catalina",
                        "localhost",
                        "tps.xml"))
                return self.rv

            # For other subsystems, deploy web application into Tomcat instance.
            deployer.directory.create(deployer.mdict['pki_tomcat_webapps_subsystem_path'])

            # Copy /usr/share/pki/<subsystem>/webapps/<subsystem>
            # to <instance>/webapps/<subsystem>
            deployer.directory.copy(
                os.path.join(
                    config.PKI_DEPLOYMENT_SOURCE_ROOT,
                    deployer.mdict['pki_subsystem'].lower(),
                    "webapps",
                    deployer.mdict['pki_subsystem'].lower()),
                deployer.mdict['pki_tomcat_webapps_subsystem_path'],
                overwrite_flag=True)

            # Copy /usr/share/pki/server/webapps/pki/admin
            # to <instance>/webapps/<subsystem>/admin
            # TODO: common templates should be deployed in common webapp
            deployer.directory.copy(
                os.path.join(
                    config.PKI_DEPLOYMENT_SOURCE_ROOT,
                    "server",
                    "webapps",
                    "pki",
                    "admin"),
                os.path.join(
                    deployer.mdict['pki_tomcat_webapps_subsystem_path'],
                    "admin"),
                overwrite_flag=True)

            deployer.directory.create(
                deployer.mdict['pki_tomcat_webapps_subsystem_webinf_classes_path'])
            deployer.directory.create(
                deployer.mdict['pki_tomcat_webapps_subsystem_webinf_lib_path'])
            # establish Tomcat webapps subsystem WEB-INF lib symbolic links
            deployer.symlink.create(deployer.mdict['pki_certsrv_jar'],
                deployer.mdict['pki_certsrv_jar_link'])
            deployer.symlink.create(deployer.mdict['pki_cmsbundle'],
                deployer.mdict['pki_cmsbundle_jar_link'])
            deployer.symlink.create(deployer.mdict['pki_cmscore'],
                deployer.mdict['pki_cmscore_jar_link'])
            deployer.symlink.create(deployer.mdict['pki_cms'],
                deployer.mdict['pki_cms_jar_link'])
            deployer.symlink.create(deployer.mdict['pki_cmsutil'],
                deployer.mdict['pki_cmsutil_jar_link'])
            deployer.symlink.create(deployer.mdict['pki_nsutil'],
                deployer.mdict['pki_nsutil_jar_link'])
            if deployer.mdict['pki_subsystem'] == "CA":
                deployer.symlink.create(deployer.mdict['pki_ca_jar'],
                                    deployer.mdict['pki_ca_jar_link'])
            elif deployer.mdict['pki_subsystem'] == "KRA":
                deployer.symlink.create(deployer.mdict['pki_kra_jar'],
                                    deployer.mdict['pki_kra_jar_link'])
            elif deployer.mdict['pki_subsystem'] == "OCSP":
                deployer.symlink.create(deployer.mdict['pki_ocsp_jar'],
                                    deployer.mdict['pki_ocsp_jar_link'])
            elif deployer.mdict['pki_subsystem'] == "TKS":
                deployer.symlink.create(deployer.mdict['pki_tks_jar'],
                                    deployer.mdict['pki_tks_jar_link'])

            # set ownerships, permissions, and acls
            deployer.directory.set_mode(deployer.mdict['pki_tomcat_webapps_subsystem_path'])

            # Copy web application context file
            # from /usr/share/pki/<subsystem>/conf/Catalina/localhost/<subsystem>.xml
            # to <instance>/conf/Catalina/localhost/<subsystem>.xml
            deployer.file.copy(
                os.path.join(
                    config.PKI_DEPLOYMENT_SOURCE_ROOT,
                    deployer.mdict['pki_subsystem'].lower(),
                    "conf",
                    "Catalina",
                    "localhost",
                    deployer.mdict['pki_subsystem'].lower() + ".xml"),
                os.path.join(
                    deployer.mdict['pki_instance_configuration_path'],
                    "Catalina",
                    "localhost",
                    deployer.mdict['pki_subsystem'].lower() + ".xml"))

        return self.rv

    def destroy(self, deployer):
        if deployer.mdict['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            config.pki_log.info(log.WEBAPP_DEPLOYMENT_DESTROY_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)

            # Delete <instance>/conf/Catalina/localhost/<subsystem>.xml
            deployer.file.delete(
                os.path.join(
                    deployer.mdict['pki_instance_configuration_path'],
                    "Catalina",
                    "localhost",
                    deployer.mdict['pki_subsystem'].lower() + ".xml"))

            # For subsystems other than TPS, delete <instance>/webapps/<subsystem>.
            if deployer.mdict['pki_subsystem'] != "TPS":
                deployer.directory.delete(deployer.mdict['pki_tomcat_webapps_subsystem_path'])

        return self.rv
