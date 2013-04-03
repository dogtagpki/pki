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
import pkiconfig as config
from pkiconfig import pki_master_dict as master
import pkihelper as util
import pkimessages as log
import pkiscriptlet


# PKI Web Application Deployment Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):
    rv = 0

    def spawn(self):
        if master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            if config.str2bool(master['pki_skip_installation']):
                config.pki_log.info(log.SKIP_WEBAPP_DEPLOYMENT_SPAWN_1,
                                     __name__,
                                    extra=config.PKI_INDENTATION_LEVEL_1)
                return self.rv
            config.pki_log.info(log.WEBAPP_DEPLOYMENT_SPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)

            # Copy /usr/share/pki/server/webapps/ROOT
            # to <instance>/webapps/ROOT
            util.directory.create(master['pki_tomcat_webapps_root_path'])
            util.directory.copy(
                os.path.join(
                    config.PKI_DEPLOYMENT_SOURCE_ROOT,
                    "server",
                    "webapps",
                    "ROOT"),
                master['pki_tomcat_webapps_root_path'],
                overwrite_flag=True)

            util.directory.create(master['pki_tomcat_webapps_common_path'])

            # If desired and available,
            # copy selected server theme
            # to <instance>/webapps/pki
            if config.str2bool(master['pki_theme_enable']) and\
               os.path.exists(master['pki_theme_server_dir']):
                util.directory.copy(master['pki_theme_server_dir'],
                                    master['pki_tomcat_webapps_common_path'],
                                    overwrite_flag=True)

            # Copy /usr/share/pki/server/webapps/pki/js
            # to <instance>/webapps/pki/js
            util.directory.copy(
                os.path.join(
                    config.PKI_DEPLOYMENT_SOURCE_ROOT,
                    "server",
                    "webapps",
                    "pki",
                    "js"),
                os.path.join(
                    master['pki_tomcat_webapps_common_path'],
                    "js"),
                overwrite_flag=True)

            # Copy /usr/share/pki/server/webapps/pki/META-INF
            # to <instance>/webapps/pki/META-INF
            util.directory.copy(
                os.path.join(
                    config.PKI_DEPLOYMENT_SOURCE_ROOT,
                    "server",
                    "webapps",
                    "pki",
                    "META-INF"),
                os.path.join(
                    master['pki_tomcat_webapps_common_path'],
                    "META-INF"),
                overwrite_flag=True)

            # Copy /usr/share/pki/server/webapps/pki/admin
            # to <instance>/webapps/<subsystem>/admin
            # TODO: common templates should be deployed in common webapp
            util.directory.create(master['pki_tomcat_webapps_subsystem_path'])
            util.directory.copy(
                os.path.join(
                    config.PKI_DEPLOYMENT_SOURCE_ROOT,
                    "server",
                    "webapps",
                    "pki",
                    "admin"),
                os.path.join(
                    master['pki_tomcat_webapps_subsystem_path'],
                    "admin"),
                overwrite_flag=True)

            # Copy /usr/share/pki/<subsystem>/webapps/<subsystem>
            # to <instance>/webapps/<subsystem>
            util.directory.copy(
                os.path.join(
                    config.PKI_DEPLOYMENT_SOURCE_ROOT,
                    master['pki_subsystem'].lower(),
                    "webapps",
                    master['pki_subsystem'].lower()),
                master['pki_tomcat_webapps_subsystem_path'],
                overwrite_flag=True)

            util.directory.create(
                master['pki_tomcat_webapps_subsystem_webinf_classes_path'])
            util.directory.create(
                master['pki_tomcat_webapps_subsystem_webinf_lib_path'])
            # establish Tomcat webapps subsystem WEB-INF lib symbolic links
            util.symlink.create(master['pki_certsrv_jar'],
                master['pki_certsrv_jar_link'])
            util.symlink.create(master['pki_cmsbundle'],
                master['pki_cmsbundle_jar_link'])
            util.symlink.create(master['pki_cmscore'],
                master['pki_cmscore_jar_link'])
            util.symlink.create(master['pki_cms'],
                master['pki_cms_jar_link'])
            util.symlink.create(master['pki_cmsutil'],
                master['pki_cmsutil_jar_link'])
            util.symlink.create(master['pki_nsutil'],
                master['pki_nsutil_jar_link'])
            if master['pki_subsystem'] == "CA":
                util.symlink.create(master['pki_ca_jar'],
                                    master['pki_ca_jar_link'])
            elif master['pki_subsystem'] == "KRA":
                util.symlink.create(master['pki_kra_jar'],
                                    master['pki_kra_jar_link'])
            elif master['pki_subsystem'] == "OCSP":
                util.symlink.create(master['pki_ocsp_jar'],
                                    master['pki_ocsp_jar_link'])
            elif master['pki_subsystem'] == "TKS":
                util.symlink.create(master['pki_tks_jar'],
                                    master['pki_tks_jar_link'])
            # set ownerships, permissions, and acls
            util.directory.set_mode(master['pki_tomcat_webapps_subsystem_path'])
        return self.rv

    def destroy(self):
        if master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            config.pki_log.info(log.WEBAPP_DEPLOYMENT_DESTROY_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            util.directory.delete(master['pki_tomcat_webapps_subsystem_path'])
        return self.rv
