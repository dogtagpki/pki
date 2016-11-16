# Authors:
# Matthew Harmsen <mharmsen@redhat.com>
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
from __future__ import absolute_import
import os

# PKI Deployment Imports
from .. import pkiconfig as config
from .. import pkimessages as log
from .. import pkiscriptlet


# PKI Deployment Instance Layout Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):

    def spawn(self, deployer):

        if config.str2bool(deployer.mdict['pki_skip_installation']):
            config.pki_log.info(log.SKIP_INSTANCE_SPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            return

        config.pki_log.info(log.INSTANCE_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)

        # if this is the first subsystem
        if len(deployer.instance.tomcat_instance_subsystems()) == 1:

            # establish instance logs
            deployer.directory.create(deployer.mdict['pki_instance_log_path'])

            # copy /usr/share/pki/server/conf tree into
            # /var/lib/pki/<instance>/conf
            # except common ldif files and theme deployment descriptor
            deployer.directory.copy(
                deployer.mdict['pki_source_server_path'],
                deployer.mdict['pki_instance_configuration_path'],
                ignore_cb=file_ignore_callback_src_server)

            # Link /etc/pki/<instance>/logging.properties
            # to /usr/share/pki/server/conf/logging.properties.
            deployer.symlink.create(
                os.path.join(deployer.mdict['pki_source_server_path'], "logging.properties"),
                os.path.join(deployer.mdict['pki_instance_configuration_path'],
                             "logging.properties"))

            # create /etc/sysconfig/<instance>
            deployer.file.copy_with_slot_substitution(
                deployer.mdict['pki_source_tomcat_conf'],
                deployer.mdict['pki_target_tomcat_conf_instance_id'],
                uid=0, gid=0, overwrite_flag=True)

            # create /var/lib/pki/<instance>/conf/tomcat.conf
            deployer.file.copy_with_slot_substitution(
                deployer.mdict['pki_source_tomcat_conf'],
                deployer.mdict['pki_target_tomcat_conf'],
                overwrite_flag=True)

            # Deploy ROOT web application
            deployer.deploy_webapp(
                "ROOT",
                os.path.join(
                    config.PKI_DEPLOYMENT_SOURCE_ROOT,
                    "server",
                    "webapps",
                    "ROOT"),
                os.path.join(
                    deployer.mdict['pki_source_server_path'],
                    "Catalina",
                    "localhost",
                    "ROOT.xml"))

            if os.path.exists(deployer.mdict['pki_theme_server_dir']):
                # Deploy theme web application if available
                deployer.deploy_webapp(
                    "pki",
                    deployer.mdict['pki_theme_server_dir'],
                    os.path.join(
                        deployer.mdict['pki_source_server_path'],
                        "Catalina",
                        "localhost",
                        "pki.xml"))

            # Deploy admin templates
            deployer.deploy_webapp(
                "pki#admin",
                os.path.join(
                    config.PKI_DEPLOYMENT_SOURCE_ROOT,
                    "server",
                    "webapps",
                    "pki",
                    "admin"),
                os.path.join(
                    deployer.mdict['pki_source_server_path'],
                    "Catalina",
                    "localhost",
                    "pki#admin.xml"))

            # Deploy JS library
            deployer.deploy_webapp(
                "pki#js",
                os.path.join(
                    config.PKI_DEPLOYMENT_SOURCE_ROOT,
                    "server",
                    "webapps",
                    "pki",
                    "js"),
                os.path.join(
                    deployer.mdict['pki_source_server_path'],
                    "Catalina",
                    "localhost",
                    "pki#js.xml"))

            # Create Tomcat instance library
            deployer.directory.create(deployer.mdict['pki_instance_lib'])
            for name in os.listdir(deployer.mdict['pki_tomcat_lib_path']):
                deployer.symlink.create(
                    os.path.join(
                        deployer.mdict['pki_tomcat_lib_path'],
                        name),
                    os.path.join(
                        deployer.mdict['pki_instance_lib'],
                        name))
            deployer.symlink.create(
                deployer.mdict['pki_instance_conf_log4j_properties'],
                deployer.mdict['pki_instance_lib_log4j_properties'])

            # Link /var/lib/pki/<instance>/common to /usr/share/pki/server/common
            deployer.symlink.create(
                '/usr/share/pki/server/common',
                deployer.mdict['pki_tomcat_common_path'])

            deployer.directory.create(deployer.mdict['pki_tomcat_tmpdir_path'])

            deployer.directory.create(deployer.mdict['pki_tomcat_work_path'])
            deployer.directory.create(
                deployer.mdict['pki_tomcat_work_catalina_path'])
            deployer.directory.create(
                deployer.mdict['pki_tomcat_work_catalina_host_path'])
            deployer.directory.create(
                deployer.mdict['pki_tomcat_work_catalina_host_run_path'])
            deployer.directory.create(
                deployer.mdict['pki_tomcat_work_catalina_host_subsystem_path'])
            # establish Tomcat instance logs
            # establish Tomcat instance registry
            # establish Tomcat instance convenience symbolic links
            deployer.symlink.create(
                deployer.mdict['pki_tomcat_bin_path'],
                deployer.mdict['pki_tomcat_bin_link'])
            deployer.symlink.create(
                deployer.mdict['pki_tomcat_systemd'],
                deployer.mdict['pki_instance_systemd_link'],
                uid=0, gid=0)

            # establish shared NSS security databases for this instance
            deployer.directory.create(deployer.mdict['pki_database_path'])
            # establish instance convenience symbolic links
            deployer.symlink.create(
                deployer.mdict['pki_database_path'],
                deployer.mdict['pki_instance_database_link'])
            deployer.symlink.create(
                deployer.mdict['pki_instance_configuration_path'],
                deployer.mdict['pki_instance_conf_link'])
            deployer.symlink.create(
                deployer.mdict['pki_instance_log_path'],
                deployer.mdict['pki_instance_logs_link'])

            # create Tomcat instance systemd service link
            deployer.symlink.create(deployer.mdict['pki_systemd_service'],
                                    deployer.mdict['pki_systemd_service_link'])

    def destroy(self, deployer):

        config.pki_log.info(log.INSTANCE_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)

        if len(deployer.instance.tomcat_instance_subsystems()) == 0:

            # remove Tomcat instance systemd service link
            deployer.symlink.delete(deployer.mdict['pki_systemd_service_link'])

            # remove Tomcat instance base
            deployer.directory.delete(deployer.mdict['pki_instance_path'])
            # remove Tomcat instance logs
            deployer.directory.delete(deployer.mdict['pki_instance_log_path'])
            # remove shared NSS security database path for this instance
            deployer.directory.delete(deployer.mdict['pki_database_path'])
            # remove Tomcat instance configuration
            deployer.directory.delete(
                deployer.mdict['pki_instance_configuration_path'])
            # remove PKI 'tomcat.conf' instance file
            deployer.file.delete(
                deployer.mdict['pki_target_tomcat_conf_instance_id'])
            # remove Tomcat instance registry
            deployer.directory.delete(
                deployer.mdict['pki_instance_registry_path'])
            # remove Tomcat PKI registry (if empty)
            if deployer.instance.tomcat_instances() == 0:
                deployer.directory.delete(
                    deployer.mdict['pki_instance_type_registry_path'])


# Callback only when the /usr/share/pki/server/conf directory
# Is getting copied to the etc tree.
# Don't copy the shared ldif files:
# schema.ldif, manager.ldif, database.ldif
def file_ignore_callback_src_server(src, names):
    config.pki_log.info(log.FILE_EXCLUDE_CALLBACK_2, src, names,
                        extra=config.PKI_INDENTATION_LEVEL_1)

    return {
        'schema.ldif',
        'database.ldif',
        'manager.ldif',
        'pki.xml',
        'logging.properties'
    }
