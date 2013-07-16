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

        if deployer.master_dict['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            if config.str2bool(deployer.master_dict['pki_skip_installation']):
                config.pki_log.info(log.SKIP_WEBAPP_DEPLOYMENT_SPAWN_1,
                                     __name__,
                                    extra=config.PKI_INDENTATION_LEVEL_1)
                return self.rv
            config.pki_log.info(log.WEBAPP_DEPLOYMENT_SPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)

            # Copy /usr/share/pki/server/webapps/ROOT
            # to <instance>/webapps/ROOT
            deployer.directory.create(deployer.master_dict['pki_tomcat_webapps_root_path'])
            deployer.directory.copy(
                os.path.join(
                    config.PKI_DEPLOYMENT_SOURCE_ROOT,
                    "server",
                    "webapps",
                    "ROOT"),
                deployer.master_dict['pki_tomcat_webapps_root_path'],
                overwrite_flag=True)

            deployer.directory.create(deployer.master_dict['pki_tomcat_webapps_common_path'])

            # If desired and available,
            # copy selected server theme
            # to <instance>/webapps/pki
            if config.str2bool(deployer.master_dict['pki_theme_enable']) and\
               os.path.exists(deployer.master_dict['pki_theme_server_dir']):
                deployer.directory.copy(deployer.master_dict['pki_theme_server_dir'],
                                    deployer.master_dict['pki_tomcat_webapps_common_path'],
                                    overwrite_flag=True)

            # Copy /usr/share/pki/server/webapps/pki/js
            # to <instance>/webapps/pki/js
            deployer.directory.copy(
                os.path.join(
                    config.PKI_DEPLOYMENT_SOURCE_ROOT,
                    "server",
                    "webapps",
                    "pki",
                    "js"),
                os.path.join(
                    deployer.master_dict['pki_tomcat_webapps_common_path'],
                    "js"),
                overwrite_flag=True)

            # Copy /usr/share/pki/server/webapps/pki/META-INF
            # to <instance>/webapps/pki/META-INF
            deployer.directory.copy(
                os.path.join(
                    config.PKI_DEPLOYMENT_SOURCE_ROOT,
                    "server",
                    "webapps",
                    "pki",
                    "META-INF"),
                os.path.join(
                    deployer.master_dict['pki_tomcat_webapps_common_path'],
                    "META-INF"),
                overwrite_flag=True)

            # Copy /usr/share/pki/server/webapps/pki/admin
            # to <instance>/webapps/<subsystem>/admin
            # TODO: common templates should be deployed in common webapp
            deployer.directory.create(deployer.master_dict['pki_tomcat_webapps_subsystem_path'])
            deployer.directory.copy(
                os.path.join(
                    config.PKI_DEPLOYMENT_SOURCE_ROOT,
                    "server",
                    "webapps",
                    "pki",
                    "admin"),
                os.path.join(
                    deployer.master_dict['pki_tomcat_webapps_subsystem_path'],
                    "admin"),
                overwrite_flag=True)

            # Copy /usr/share/pki/<subsystem>/webapps/<subsystem>
            # to <instance>/webapps/<subsystem>
            deployer.directory.copy(
                os.path.join(
                    config.PKI_DEPLOYMENT_SOURCE_ROOT,
                    deployer.master_dict['pki_subsystem'].lower(),
                    "webapps",
                    deployer.master_dict['pki_subsystem'].lower()),
                deployer.master_dict['pki_tomcat_webapps_subsystem_path'],
                overwrite_flag=True)

            deployer.directory.create(
                deployer.master_dict['pki_tomcat_webapps_subsystem_webinf_classes_path'])
            deployer.directory.create(
                deployer.master_dict['pki_tomcat_webapps_subsystem_webinf_lib_path'])
            # establish Tomcat webapps subsystem WEB-INF lib symbolic links
            deployer.symlink.create(deployer.master_dict['pki_certsrv_jar'],
                deployer.master_dict['pki_certsrv_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_cmsbundle'],
                deployer.master_dict['pki_cmsbundle_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_cmscore'],
                deployer.master_dict['pki_cmscore_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_cms'],
                deployer.master_dict['pki_cms_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_cmsutil'],
                deployer.master_dict['pki_cmsutil_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_nsutil'],
                deployer.master_dict['pki_nsutil_jar_link'])
            if deployer.master_dict['pki_subsystem'] == "CA":
                deployer.symlink.create(deployer.master_dict['pki_ca_jar'],
                                    deployer.master_dict['pki_ca_jar_link'])
            elif deployer.master_dict['pki_subsystem'] == "KRA":
                deployer.symlink.create(deployer.master_dict['pki_kra_jar'],
                                    deployer.master_dict['pki_kra_jar_link'])
            elif deployer.master_dict['pki_subsystem'] == "OCSP":
                deployer.symlink.create(deployer.master_dict['pki_ocsp_jar'],
                                    deployer.master_dict['pki_ocsp_jar_link'])
            elif deployer.master_dict['pki_subsystem'] == "TKS":
                deployer.symlink.create(deployer.master_dict['pki_tks_jar'],
                                    deployer.master_dict['pki_tks_jar_link'])
            elif deployer.master_dict['pki_subsystem'] == "TPS":
                deployer.symlink.create(deployer.master_dict['pki_tps_jar'],
                                    deployer.master_dict['pki_tps_jar_link'])
            # set ownerships, permissions, and acls
            deployer.directory.set_mode(deployer.master_dict['pki_tomcat_webapps_subsystem_path'])
        return self.rv

    def destroy(self, deployer):
        if deployer.master_dict['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            config.pki_log.info(log.WEBAPP_DEPLOYMENT_DESTROY_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            deployer.directory.delete(deployer.master_dict['pki_tomcat_webapps_subsystem_path'])
        return self.rv
