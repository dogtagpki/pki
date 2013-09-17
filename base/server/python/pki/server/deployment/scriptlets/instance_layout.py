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


# PKI Deployment Instance Layout Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):
    rv = 0

    def spawn(self, deployer):

        if config.str2bool(deployer.master_dict['pki_skip_installation']):
            config.pki_log.info(log.SKIP_INSTANCE_SPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            return self.rv
        config.pki_log.info(log.INSTANCE_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # establish instance logs
        deployer.directory.create(deployer.master_dict['pki_instance_log_path'])
        # establish instance configuration
        deployer.directory.create(deployer.master_dict['pki_instance_configuration_path'])
        # establish Apache/Tomcat specific instance
        if deployer.master_dict['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            # establish Tomcat instance configuration
            deployer.directory.copy(deployer.master_dict['pki_source_server_path'],
                                deployer.master_dict['pki_instance_configuration_path'],
                                overwrite_flag=True)
            # establish Tomcat instance base
            deployer.directory.create(deployer.master_dict['pki_tomcat_common_path'])
            deployer.directory.create(deployer.master_dict['pki_tomcat_common_lib_path'])
            # establish Tomcat instance library
            deployer.directory.create(deployer.master_dict['pki_instance_lib'])
            for name in os.listdir(deployer.master_dict['pki_tomcat_lib_path']):
                deployer.symlink.create(
                    os.path.join(
                        deployer.master_dict['pki_tomcat_lib_path'],
                        name),
                    os.path.join(
                        deployer.master_dict['pki_instance_lib'],
                        name))
            deployer.symlink.create(deployer.master_dict['pki_instance_conf_log4j_properties'],
                                deployer.master_dict['pki_instance_lib_log4j_properties'])
            deployer.directory.create(deployer.master_dict['pki_tomcat_tmpdir_path'])
            deployer.directory.create(deployer.master_dict['pki_tomcat_webapps_path'])
            deployer.directory.create(deployer.master_dict['pki_tomcat_work_path'])
            deployer.directory.create(deployer.master_dict['pki_tomcat_work_catalina_path'])
            deployer.directory.create(deployer.master_dict['pki_tomcat_work_catalina_host_path'])
            deployer.directory.create(
                deployer.master_dict['pki_tomcat_work_catalina_host_run_path'])
            deployer.directory.create(
                deployer.master_dict['pki_tomcat_work_catalina_host_subsystem_path'])
            # establish Tomcat instance logs
            # establish Tomcat instance registry
            # establish Tomcat instance convenience symbolic links
            deployer.symlink.create(deployer.master_dict['pki_tomcat_bin_path'],
                                deployer.master_dict['pki_tomcat_bin_link'])
            deployer.symlink.create(deployer.master_dict['pki_tomcat_systemd'],
                                deployer.master_dict['pki_instance_systemd_link'],
                                uid=0, gid=0)
            # establish Tomcat instance common lib jar symbolic links
            deployer.symlink.create(deployer.master_dict['pki_apache_commons_collections_jar'],
                deployer.master_dict['pki_apache_commons_collections_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_apache_commons_io_jar'],
                deployer.master_dict['pki_apache_commons_io_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_apache_commons_lang_jar'],
                deployer.master_dict['pki_apache_commons_lang_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_apache_commons_logging_jar'],
                deployer.master_dict['pki_apache_commons_logging_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_commons_codec_jar'],
                deployer.master_dict['pki_commons_codec_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_httpclient_jar'],
                deployer.master_dict['pki_httpclient_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_httpcore_jar'],
                deployer.master_dict['pki_httpcore_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_javassist_jar'],
                deployer.master_dict['pki_javassist_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_resteasy_jaxrs_api_jar'],
                deployer.master_dict['pki_resteasy_jaxrs_api_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_jettison_jar'],
                deployer.master_dict['pki_jettison_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_jss_jar'],
                deployer.master_dict['pki_jss_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_ldapjdk_jar'],
                deployer.master_dict['pki_ldapjdk_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_tomcat_jar'],
                deployer.master_dict['pki_tomcat_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_resteasy_atom_provider_jar'],
                deployer.master_dict['pki_resteasy_atom_provider_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_resteasy_jaxb_provider_jar'],
                deployer.master_dict['pki_resteasy_jaxb_provider_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_resteasy_jaxrs_jar'],
                deployer.master_dict['pki_resteasy_jaxrs_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_resteasy_jettison_provider_jar'],
                deployer.master_dict['pki_resteasy_jettison_provider_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_scannotation_jar'],
                deployer.master_dict['pki_scannotation_jar_link'])
            if deployer.master_dict['pki_subsystem'] == 'TKS':
                deployer.symlink.create(deployer.master_dict['pki_symkey_jar'],
                    deployer.master_dict['pki_symkey_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_tomcatjss_jar'],
                deployer.master_dict['pki_tomcatjss_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_velocity_jar'],
                deployer.master_dict['pki_velocity_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_xerces_j2_jar'],
                deployer.master_dict['pki_xerces_j2_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_xml_commons_apis_jar'],
                deployer.master_dict['pki_xml_commons_apis_jar_link'])
            deployer.symlink.create(deployer.master_dict['pki_xml_commons_resolver_jar'],
                deployer.master_dict['pki_xml_commons_resolver_jar_link'])
        # establish shared NSS security databases for this instance
        deployer.directory.create(deployer.master_dict['pki_database_path'])
        # establish instance convenience symbolic links
        deployer.symlink.create(deployer.master_dict['pki_database_path'],
                            deployer.master_dict['pki_instance_database_link'])
        deployer.symlink.create(deployer.master_dict['pki_instance_configuration_path'],
                            deployer.master_dict['pki_instance_conf_link'])
        deployer.symlink.create(deployer.master_dict['pki_instance_log_path'],
                            deployer.master_dict['pki_instance_logs_link'])
        return self.rv

    def destroy(self, deployer):

        config.pki_log.info(log.INSTANCE_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        if deployer.master_dict['pki_subsystem'] == 'TKS':
            deployer.symlink.delete(deployer.master_dict['pki_symkey_jar_link'])
        if deployer.master_dict['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS and\
           deployer.instance.apache_instance_subsystems() == 0:
            # remove Apache instance base
            deployer.directory.delete(deployer.master_dict['pki_instance_path'])
            # remove Apache instance logs
            # remove shared NSS security database path for this instance
            deployer.directory.delete(deployer.master_dict['pki_database_path'])
            # remove Apache instance configuration
            deployer.directory.delete(deployer.master_dict['pki_instance_configuration_path'])
            # remove Apache instance registry
            deployer.directory.delete(deployer.master_dict['pki_instance_registry_path'])
            # remove Apache PKI registry (if empty)
            if deployer.instance.apache_instances() == 0:
                deployer.directory.delete(
                    deployer.master_dict['pki_instance_type_registry_path'])
        elif deployer.master_dict['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS and\
             len(deployer.instance.tomcat_instance_subsystems()) == 0:
            # remove Tomcat instance base
            deployer.directory.delete(deployer.master_dict['pki_instance_path'])
            # remove Tomcat instance logs
            deployer.directory.delete(deployer.master_dict['pki_instance_log_path'])
            # remove shared NSS security database path for this instance
            deployer.directory.delete(deployer.master_dict['pki_database_path'])
            # remove Tomcat instance configuration
            deployer.directory.delete(deployer.master_dict['pki_instance_configuration_path'])
            # remove PKI 'tomcat.conf' instance file
            deployer.file.delete(deployer.master_dict['pki_target_tomcat_conf_instance_id'])
            # remove Tomcat instance registry
            deployer.directory.delete(deployer.master_dict['pki_instance_registry_path'])
            # remove Tomcat PKI registry (if empty)
            if deployer.instance.tomcat_instances() == 0:
                deployer.directory.delete(
                    deployer.master_dict['pki_instance_type_registry_path'])
        return self.rv
