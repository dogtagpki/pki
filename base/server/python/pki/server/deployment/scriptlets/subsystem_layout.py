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
from .. import pkiconfig as config
from .. import pkimessages as log
from .. import pkiscriptlet


# PKI Deployment Subsystem Layout Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):
    rv = 0

    def spawn(self, deployer):

        if config.str2bool(deployer.master_dict['pki_skip_installation']):
            config.pki_log.info(log.SKIP_SUBSYSTEM_SPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            return self.rv
        config.pki_log.info(log.SUBSYSTEM_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # establish instance-based subsystem logs
        deployer.directory.create(deployer.master_dict['pki_subsystem_log_path'])
        deployer.directory.create(deployer.master_dict['pki_subsystem_archive_log_path'])
        if deployer.master_dict['pki_subsystem'] in config.PKI_SIGNED_AUDIT_SUBSYSTEMS:
            deployer.directory.create(deployer.master_dict['pki_subsystem_signed_audit_log_path'])
        # establish instance-based subsystem configuration
        deployer.directory.create(deployer.master_dict['pki_subsystem_configuration_path'])
        # deployer.directory.copy(deployer.master_dict['pki_source_conf_path'],
        #                     deployer.master_dict['pki_subsystem_configuration_path'])
        # establish instance-based Apache/Tomcat specific subsystems
        if deployer.master_dict['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            # establish instance-based Tomcat PKI subsystem base
            if deployer.master_dict['pki_subsystem'] == "CA":
                deployer.directory.copy(deployer.master_dict['pki_source_emails'],
                                    deployer.master_dict['pki_subsystem_emails_path'])
                deployer.directory.copy(deployer.master_dict['pki_source_profiles'],
                                    deployer.master_dict['pki_subsystem_profiles_path'])
            # establish instance-based Tomcat PKI subsystem logs
            # establish instance-based Tomcat PKI subsystem configuration
            if deployer.master_dict['pki_subsystem'] == "CA":
                deployer.file.copy(deployer.master_dict['pki_source_flatfile_txt'],
                               deployer.master_dict['pki_target_flatfile_txt'])
                deployer.file.copy(deployer.master_dict['pki_source_registry_cfg'],
                               deployer.master_dict['pki_target_registry_cfg'])
                # '*.profile'
                deployer.file.copy(deployer.master_dict['pki_source_admincert_profile'],
                               deployer.master_dict['pki_target_admincert_profile'])
                deployer.file.copy(deployer.master_dict['pki_source_caauditsigningcert_profile'],
                               deployer.master_dict['pki_target_caauditsigningcert_profile'])
                deployer.file.copy(deployer.master_dict['pki_source_cacert_profile'],
                               deployer.master_dict['pki_target_cacert_profile'])
                deployer.file.copy(deployer.master_dict['pki_source_caocspcert_profile'],
                               deployer.master_dict['pki_target_caocspcert_profile'])
                deployer.file.copy(deployer.master_dict['pki_source_servercert_profile'],
                               deployer.master_dict['pki_target_servercert_profile'])
                deployer.file.copy(deployer.master_dict['pki_source_subsystemcert_profile'],
                               deployer.master_dict['pki_target_subsystemcert_profile'])
            elif deployer.master_dict['pki_subsystem'] == "KRA":
                # '*.profile'
                deployer.file.copy(deployer.master_dict['pki_source_servercert_profile'],
                               deployer.master_dict['pki_target_servercert_profile'])
                deployer.file.copy(deployer.master_dict['pki_source_storagecert_profile'],
                               deployer.master_dict['pki_target_storagecert_profile'])
                deployer.file.copy(deployer.master_dict['pki_source_subsystemcert_profile'],
                               deployer.master_dict['pki_target_subsystemcert_profile'])
                deployer.file.copy(deployer.master_dict['pki_source_transportcert_profile'],
                               deployer.master_dict['pki_target_transportcert_profile'])
            # establish instance-based Tomcat PKI subsystem registry
            # establish instance-based Tomcat PKI subsystem convenience
            # symbolic links
            deployer.symlink.create(deployer.master_dict['pki_tomcat_webapps_path'],
                                deployer.master_dict['pki_subsystem_tomcat_webapps_link'])
        # establish instance-based subsystem convenience symbolic links
        deployer.symlink.create(deployer.master_dict['pki_instance_database_link'],
                            deployer.master_dict['pki_subsystem_database_link'])
        deployer.symlink.create(deployer.master_dict['pki_subsystem_configuration_path'],
                            deployer.master_dict['pki_subsystem_conf_link'])
        deployer.symlink.create(deployer.master_dict['pki_subsystem_log_path'],
                            deployer.master_dict['pki_subsystem_logs_link'])
        deployer.symlink.create(deployer.master_dict['pki_instance_registry_path'],
                            deployer.master_dict['pki_subsystem_registry_link'])
        return self.rv

    def destroy(self, deployer):

        config.pki_log.info(log.SUBSYSTEM_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # remove instance-based subsystem base
        if deployer.master_dict['pki_subsystem'] == "CA":
            deployer.directory.delete(deployer.master_dict['pki_subsystem_emails_path'])
            deployer.directory.delete(deployer.master_dict['pki_subsystem_profiles_path'])
        deployer.directory.delete(deployer.master_dict['pki_subsystem_path'])
        # remove instance-based subsystem logs
        if deployer.master_dict['pki_subsystem'] in config.PKI_SIGNED_AUDIT_SUBSYSTEMS:
            deployer.directory.delete(deployer.master_dict['pki_subsystem_signed_audit_log_path'])
        deployer.directory.delete(deployer.master_dict['pki_subsystem_archive_log_path'])
        deployer.directory.delete(deployer.master_dict['pki_subsystem_log_path'])
        # remove instance-based subsystem configuration
        deployer.directory.delete(deployer.master_dict['pki_subsystem_configuration_path'])
        # remove instance-based subsystem registry
        deployer.directory.delete(deployer.master_dict['pki_subsystem_registry_path'])
        return self.rv
