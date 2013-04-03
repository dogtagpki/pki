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


# PKI Deployment Subsystem Layout Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):
    rv = 0

    def spawn(self):
        if config.str2bool(master['pki_skip_installation']):
            config.pki_log.info(log.SKIP_SUBSYSTEM_SPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            return self.rv
        config.pki_log.info(log.SUBSYSTEM_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # establish instance-based subsystem logs
        util.directory.create(master['pki_subsystem_log_path'])
        util.directory.create(master['pki_subsystem_archive_log_path'])
        if master['pki_subsystem'] in config.PKI_SIGNED_AUDIT_SUBSYSTEMS:
            util.directory.create(master['pki_subsystem_signed_audit_log_path'])
        # establish instance-based subsystem configuration
        util.directory.create(master['pki_subsystem_configuration_path'])
        # util.directory.copy(master['pki_source_conf_path'],
        #                     master['pki_subsystem_configuration_path'])
        # establish instance-based Apache/Tomcat specific subsystems
        if master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            # establish instance-based Tomcat PKI subsystem base
            if master['pki_subsystem'] == "CA":
                util.directory.copy(master['pki_source_emails'],
                                    master['pki_subsystem_emails_path'])
                util.directory.copy(master['pki_source_profiles'],
                                    master['pki_subsystem_profiles_path'])
            # establish instance-based Tomcat PKI subsystem logs
            # establish instance-based Tomcat PKI subsystem configuration
            if master['pki_subsystem'] == "CA":
                util.file.copy(master['pki_source_flatfile_txt'],
                               master['pki_target_flatfile_txt'])
                util.file.copy(master['pki_source_registry_cfg'],
                               master['pki_target_registry_cfg'])
                # '*.profile'
                util.file.copy(master['pki_source_admincert_profile'],
                               master['pki_target_admincert_profile'])
                util.file.copy(master['pki_source_caauditsigningcert_profile'],
                               master['pki_target_caauditsigningcert_profile'])
                util.file.copy(master['pki_source_cacert_profile'],
                               master['pki_target_cacert_profile'])
                util.file.copy(master['pki_source_caocspcert_profile'],
                               master['pki_target_caocspcert_profile'])
                util.file.copy(master['pki_source_servercert_profile'],
                               master['pki_target_servercert_profile'])
                util.file.copy(master['pki_source_subsystemcert_profile'],
                               master['pki_target_subsystemcert_profile'])
            elif master['pki_subsystem'] == "KRA":
                # '*.profile'
                util.file.copy(master['pki_source_servercert_profile'],
                               master['pki_target_servercert_profile'])
                util.file.copy(master['pki_source_storagecert_profile'],
                               master['pki_target_storagecert_profile'])
                util.file.copy(master['pki_source_subsystemcert_profile'],
                               master['pki_target_subsystemcert_profile'])
                util.file.copy(master['pki_source_transportcert_profile'],
                               master['pki_target_transportcert_profile'])
            # establish instance-based Tomcat PKI subsystem registry
            # establish instance-based Tomcat PKI subsystem convenience
            # symbolic links
            util.symlink.create(master['pki_tomcat_webapps_path'],
                                master['pki_subsystem_tomcat_webapps_link'])
        # establish instance-based subsystem convenience symbolic links
        util.symlink.create(master['pki_instance_database_link'],
                            master['pki_subsystem_database_link'])
        util.symlink.create(master['pki_subsystem_configuration_path'],
                            master['pki_subsystem_conf_link'])
        util.symlink.create(master['pki_subsystem_log_path'],
                            master['pki_subsystem_logs_link'])
        util.symlink.create(master['pki_instance_registry_path'],
                            master['pki_subsystem_registry_link'])
        return self.rv

    def destroy(self):
        config.pki_log.info(log.SUBSYSTEM_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # remove instance-based subsystem base
        if master['pki_subsystem'] == "CA":
            util.directory.delete(master['pki_subsystem_emails_path'])
            util.directory.delete(master['pki_subsystem_profiles_path'])
        util.directory.delete(master['pki_subsystem_path'])
        # remove instance-based subsystem logs
        if master['pki_subsystem'] in config.PKI_SIGNED_AUDIT_SUBSYSTEMS:
            util.directory.delete(master['pki_subsystem_signed_audit_log_path'])
        util.directory.delete(master['pki_subsystem_archive_log_path'])
        util.directory.delete(master['pki_subsystem_log_path'])
        # remove instance-based subsystem configuration
        util.directory.delete(master['pki_subsystem_configuration_path'])
        # remove instance-based subsystem registry
        util.directory.delete(master['pki_subsystem_registry_path'])
        return self.rv
