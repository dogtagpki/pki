#!/usr/bin/python -t
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
import os

# PKI Deployment Imports
from .. import pkiconfig as config
from .. import pkimessages as log
from .. import pkiscriptlet


# PKI Deployment Instance Layout Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):
    rv = 0

    def spawn(self, deployer):

        if config.str2bool(deployer.mdict['pki_skip_installation']):
            config.pki_log.info(log.SKIP_INSTANCE_SPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            return self.rv

        config.pki_log.info(log.INSTANCE_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)

        # if this is the first subsystem
        if deployer.mdict['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS \
                and len(deployer.instance.tomcat_instance_subsystems()) == 1:

            # establish instance logs
            deployer.directory.create(deployer.mdict['pki_instance_log_path'])

            # establish Tomcat instance configuration
            # don't copy over the common ldif files to etc instance path
            deployer.directory.copy(
                deployer.mdict['pki_source_server_path'],
                deployer.mdict['pki_instance_configuration_path'],
                ignore_cb=file_ignore_callback_src_server)

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

            # Copy /usr/share/pki/server/webapps to <instance>/webapps
            deployer.directory.copy(
                os.path.join(
                    config.PKI_DEPLOYMENT_SOURCE_ROOT,
                    "server",
                    "webapps"),
                deployer.mdict['pki_tomcat_webapps_path'])

            # If desired and available,
            # copy selected server theme
            # to <instance>/webapps/pki
            if config.str2bool(deployer.mdict['pki_theme_enable']) and \
                    os.path.exists(deployer.mdict['pki_theme_server_dir']):
                deployer.directory.copy(
                    deployer.mdict['pki_theme_server_dir'],
                    os.path.join(
                        deployer.mdict['pki_tomcat_webapps_path'],
                        "pki"),
                    overwrite_flag=True)

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
                deployer.mdict['pki_jackson_annotations_jar'],
                os.path.join(
                    deployer.mdict['pki_tomcat_common_lib_path'],
                    'jackson-annotations.jar'))
            deployer.symlink.create(
                deployer.mdict['pki_jackson_core_asl_jar'],
                os.path.join(
                    deployer.mdict['pki_tomcat_common_lib_path'],
                    'jackson-core-asl.jar'))
            deployer.symlink.create(
                deployer.mdict['pki_jackson_core_jar'],
                os.path.join(
                    deployer.mdict['pki_tomcat_common_lib_path'],
                    'jackson-core.jar'))
            deployer.symlink.create(
                deployer.mdict['pki_jackson_databind_jar'],
                os.path.join(
                    deployer.mdict['pki_tomcat_common_lib_path'],
                    'jackson-databind.jar'))
            deployer.symlink.create(
                deployer.mdict['pki_jackson_jaxrs_base_jar'],
                os.path.join(
                    deployer.mdict['pki_tomcat_common_lib_path'],
                    'jackson-jaxrs-base.jar'))
            deployer.symlink.create(
                deployer.mdict['pki_jackson_jaxrs_jar'],
                os.path.join(
                    deployer.mdict['pki_tomcat_common_lib_path'],
                    'jackson-jaxrs.jar'))
            deployer.symlink.create(
                deployer.mdict['pki_jackson_jaxrs_json_provider_jar'],
                os.path.join(
                    deployer.mdict['pki_tomcat_common_lib_path'],
                    'jackson-jaxrs-json-provider.jar'))
            deployer.symlink.create(
                deployer.mdict['pki_jackson_mapper_asl_jar'],
                os.path.join(
                    deployer.mdict['pki_tomcat_common_lib_path'],
                    'jackson-mapper-asl.jar'))
            deployer.symlink.create(
                deployer.mdict['pki_jackson_module_jaxb_annotations_jar'],
                os.path.join(
                    deployer.mdict['pki_tomcat_common_lib_path'],
                    'jackson-module-jaxb-annotations.jar'))
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

        if deployer.mdict['pki_subsystem'] == 'TKS':
            deployer.symlink.create(
                deployer.mdict['pki_symkey_jar'],
                deployer.mdict['pki_symkey_jar_link'])

        return self.rv

    def destroy(self, deployer):

        config.pki_log.info(log.INSTANCE_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)

        if deployer.mdict['pki_subsystem'] == 'TKS':
            deployer.symlink.delete(deployer.mdict['pki_symkey_jar_link'])

        if deployer.mdict['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS \
                and len(deployer.instance.tomcat_instance_subsystems()) == 0:
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

        return self.rv


# Callback only when the /usr/share/pki/server/conf directory
# Is getting copied to the etc tree.
# Don't copy the shared ldif files:
# schema.ldif, manager.ldif, database.ldif
def file_ignore_callback_src_server(src, names):
    config.pki_log.info(log.FILE_EXCLUDE_CALLBACK_2, src, names,
                        extra=config.PKI_INDENTATION_LEVEL_1)

    excludes = {'schema.ldif', 'database.ldif', 'manager.ldif'}
    return excludes
