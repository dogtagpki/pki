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

            # establish Tomcat instance base
            deployer.directory.create(deployer.mdict['pki_tomcat_common_path'])
            deployer.directory.create(
                deployer.mdict['pki_tomcat_common_lib_path'])
            # establish Tomcat instance library
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
            # establish Tomcat instance common lib jar symbolic links
            deployer.symlink.create(
                deployer.mdict['pki_apache_commons_collections_jar'],
                deployer.mdict['pki_apache_commons_collections_jar_link'])
            deployer.symlink.create(
                deployer.mdict['pki_apache_commons_io_jar'],
                deployer.mdict['pki_apache_commons_io_jar_link'])
            deployer.symlink.create(
                deployer.mdict['pki_apache_commons_lang_jar'],
                deployer.mdict['pki_apache_commons_lang_jar_link'])
            deployer.symlink.create(
                deployer.mdict['pki_apache_commons_logging_jar'],
                deployer.mdict['pki_apache_commons_logging_jar_link'])
            deployer.symlink.create(
                deployer.mdict['pki_commons_codec_jar'],
                deployer.mdict['pki_commons_codec_jar_link'])
            deployer.symlink.create(
                deployer.mdict['pki_httpclient_jar'],
                deployer.mdict['pki_httpclient_jar_link'])
            deployer.symlink.create(
                deployer.mdict['pki_httpcore_jar'],
                deployer.mdict['pki_httpcore_jar_link'])
            deployer.symlink.create(
                deployer.mdict['pki_javassist_jar'],
                deployer.mdict['pki_javassist_jar_link'])
            deployer.symlink.create(
                deployer.mdict['pki_jss_jar'],
                deployer.mdict['pki_jss_jar_link'])
            deployer.symlink.create(
                deployer.mdict['pki_ldapjdk_jar'],
                deployer.mdict['pki_ldapjdk_jar_link'])
            deployer.symlink.create(
                deployer.mdict['pki_tomcat_jar'],
                deployer.mdict['pki_tomcat_jar_link'])
            deployer.symlink.create(
                deployer.mdict['pki_scannotation_jar'],
                deployer.mdict['pki_scannotation_jar_link'])
            deployer.symlink.create(
                deployer.mdict['pki_tomcatjss_jar'],
                deployer.mdict['pki_tomcatjss_jar_link'])
            deployer.symlink.create(
                deployer.mdict['pki_velocity_jar'],
                deployer.mdict['pki_velocity_jar_link'])
            deployer.symlink.create(
                deployer.mdict['pki_xerces_j2_jar'],
                deployer.mdict['pki_xerces_j2_jar_link'])
            deployer.symlink.create(
                deployer.mdict['pki_xml_commons_apis_jar'],
                deployer.mdict['pki_xml_commons_apis_jar_link'])
            deployer.symlink.create(
                deployer.mdict['pki_xml_commons_resolver_jar'],
                deployer.mdict['pki_xml_commons_resolver_jar_link'])

            # Jackson
            deployer.symlink.create(
                deployer.mdict['pki_jackson_core_asl_jar'],
                os.path.join(
                    deployer.mdict['pki_tomcat_common_lib_path'],
                    'jackson-core-asl.jar'))
            deployer.symlink.create(
                deployer.mdict['pki_jackson_jaxrs_jar'],
                os.path.join(
                    deployer.mdict['pki_tomcat_common_lib_path'],
                    'jackson-jaxrs.jar'))
            deployer.symlink.create(
                deployer.mdict['pki_jackson_mapper_asl_jar'],
                os.path.join(
                    deployer.mdict['pki_tomcat_common_lib_path'],
                    'jackson-mapper-asl.jar'))
            deployer.symlink.create(
                deployer.mdict['pki_jackson_mrbean_jar'],
                os.path.join(
                    deployer.mdict['pki_tomcat_common_lib_path'],
                    'jackson-mrbean.jar'))
            deployer.symlink.create(
                deployer.mdict['pki_jackson_smile_jar'],
                os.path.join(
                    deployer.mdict['pki_tomcat_common_lib_path'],
                    'jackson-smile.jar'))
            deployer.symlink.create(
                deployer.mdict['pki_jackson_xc_jar'],
                os.path.join(
                    deployer.mdict['pki_tomcat_common_lib_path'],
                    'jackson-xc.jar'))

            # RESTEasy
            deployer.symlink.create(
                deployer.mdict['pki_resteasy_atom_provider_jar'],
                os.path.join(
                    deployer.mdict['pki_tomcat_common_lib_path'],
                    'resteasy-atom-provider.jar'))
            deployer.symlink.create(
                deployer.mdict['pki_resteasy_client_jar'],
                os.path.join(
                    deployer.mdict['pki_tomcat_common_lib_path'],
                    'resteasy-client.jar'))
            deployer.symlink.create(
                deployer.mdict['pki_resteasy_jaxb_provider_jar'],
                os.path.join(
                    deployer.mdict['pki_tomcat_common_lib_path'],
                    'resteasy-jaxb-provider.jar'))
            deployer.symlink.create(
                deployer.mdict['pki_resteasy_jaxrs_api_jar'],
                os.path.join(
                    deployer.mdict['pki_tomcat_common_lib_path'],
                    'jaxrs-api.jar'))
            deployer.symlink.create(
                deployer.mdict['pki_resteasy_jaxrs_jar'],
                os.path.join(
                    deployer.mdict['pki_tomcat_common_lib_path'],
                    'resteasy-jaxrs.jar'))
            deployer.symlink.create(
                deployer.mdict['pki_resteasy_jackson_provider_jar'],
                os.path.join(
                    deployer.mdict['pki_tomcat_common_lib_path'],
                    'resteasy-jackson-provider.jar'))

            # nuxwdog
            deployer.symlink.create(
                deployer.mdict['pki_nuxwdog_client_jar'],
                os.path.join(
                    deployer.mdict['pki_tomcat_common_lib_path'],
                    'nuxwdog.jar'))

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

            # create the sym link to symkey regardless of subsystem
            # as long as pki-symkey is installed on the system
            if os.path.exists(deployer.mdict['pki_symkey_jar']):
                if not os.path.exists(deployer.mdict['pki_symkey_jar_link']):
                    deployer.symlink.create(
                        deployer.mdict['pki_symkey_jar'],
                        deployer.mdict['pki_symkey_jar_link'])

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

    excludes = {'schema.ldif', 'database.ldif', 'manager.ldif', 'pki.xml'}
    return excludes
