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


# PKI Deployment Instance Layout Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):
    rv = 0

    def spawn(self):
        config.pki_log.info(log.INSTANCE_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # establish instance base
        util.directory.create(master['pki_instance_path'])
        # establish instance logs
        util.directory.create(master['pki_instance_log_path'])
        # establish instance configuration
        util.directory.create(master['pki_instance_configuration_path'])
        # establish instance registry
        util.directory.create(master['pki_instance_type_registry_path'])
        util.directory.create(master['pki_instance_registry_path'])
        # establish Apache/Tomcat specific instance
        if master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            # establish Tomcat instance base
            util.directory.create(master['pki_tomcat_common_path'])
            util.directory.create(master['pki_tomcat_common_lib_path'])
            util.directory.create(master['pki_tomcat_webapps_path'])
            util.directory.create(master['pki_tomcat_webapps_root_path'])
            util.directory.create(master['pki_tomcat_webapps_root_webinf_path'])
            util.file.copy(master['pki_source_webapps_root_web_xml'],
                           master['pki_tomcat_webapps_root_webinf_web_xml'],
                           overwrite_flag=True)
            util.directory.create(master['pki_tomcat_webapps_webinf_path'])
            util.directory.create(
                master['pki_tomcat_webapps_webinf_classes_path'])
            util.directory.create(master['pki_tomcat_webapps_webinf_lib_path'])
            # establish Tomcat instance logs
            # establish Tomcat instance configuration
            util.directory.copy(master['pki_source_shared_path'],
                                master['pki_instance_configuration_path'],
                                overwrite_flag=True)
            # establish Tomcat instance registry
            # establish Tomcat instance convenience
            # symbolic links
            util.symlink.create(master['pki_tomcat_bin_path'],
                                master['pki_tomcat_bin_link'])
            util.symlink.create(master['pki_tomcat_lib_path'],
                                master['pki_tomcat_lib_link'])
            util.symlink.create(master['pki_tomcat_systemd'],
                                master['pki_instance_systemd_link'])
        # establish shared NSS security databases for this instance
        util.directory.create(master['pki_database_path'])
        # establish instance convenience symbolic links
        util.symlink.create(master['pki_database_path'],
                            master['pki_instance_database_link'])
        util.symlink.create(master['pki_instance_configuration_path'],
                            master['pki_instance_conf_link'])
        util.symlink.create(master['pki_instance_log_path'],
                            master['pki_instance_logs_link'])
        return self.rv

    def respawn(self):
        config.pki_log.info(log.INSTANCE_RESPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # update instance base
        util.directory.modify(master['pki_instance_path'])
        # update instance logs
        util.directory.modify(master['pki_instance_log_path'])
        # update instance configuration
        util.directory.modify(master['pki_instance_configuration_path'])
        # update instance registry
        util.directory.modify(master['pki_instance_type_registry_path'])
        util.directory.modify(master['pki_instance_registry_path'])
        # update Apache/Tomcat specific instance
        if master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            # update Tomcat instance base
            util.directory.modify(master['pki_tomcat_common_path'])
            util.directory.modify(master['pki_tomcat_common_lib_path'])
            util.directory.modify(master['pki_tomcat_webapps_path'])
            util.directory.modify(master['pki_tomcat_webapps_root_path'])
            util.directory.modify(master['pki_tomcat_webapps_root_webinf_path'])
            util.file.copy(master['pki_source_webapps_root_web_xml'],
                           master['pki_tomcat_webapps_root_webinf_web_xml'],
                           overwrite_flag=True)
            util.directory.modify(master['pki_tomcat_webapps_webinf_path'])
            util.directory.modify(
                master['pki_tomcat_webapps_webinf_classes_path'])
            util.directory.modify(master['pki_tomcat_webapps_webinf_lib_path'])
            # update Tomcat instance logs
            # update Tomcat instance configuration
            # update Tomcat instance registry
            # update Tomcat instance convenience symbolic links
            util.symlink.modify(master['pki_tomcat_bin_link'])
            util.symlink.modify(master['pki_tomcat_lib_link'])
        # update shared NSS security databases for this instance
        util.directory.modify(master['pki_database_path'])
        # update instance convenience symbolic links
        util.symlink.modify(master['pki_instance_database_link'])
        util.symlink.modify(master['pki_instance_conf_link'])
        util.directory.copy(master['pki_source_shared_path'],
                            master['pki_instance_configuration_path'],
                            overwrite_flag=True)
        util.symlink.modify(master['pki_instance_logs_link'])
        return self.rv

    def destroy(self):
        config.pki_log.info(log.INSTANCE_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        if not config.pki_dry_run_flag:
            if master['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS and\
               util.instance.apache_instances() == 0:
                # remove Apache instance base
                util.directory.delete(master['pki_instance_path'])
                # remove Apache instance logs
                # remove shared NSS security database path for this instance
                util.directory.delete(master['pki_database_path'])
                # remove Apache instance configuration
                util.directory.delete(master['pki_instance_configuration_path'])
                # remove Apache instance registry
                util.directory.delete(master['pki_instance_type_registry_path'])
            elif master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS and\
                 util.instance.tomcat_instances() == 0:
                # remove Tomcat instance base
                util.directory.delete(master['pki_instance_path'])
                # remove Tomcat instance logs
                # remove shared NSS security database path for this instance
                util.directory.delete(master['pki_database_path'])
                # remove Tomcat instance configuration
                util.directory.delete(master['pki_instance_configuration_path'])
                # remove Tomcat instance registry
                util.directory.delete(master['pki_instance_type_registry_path'])
        else:
            # ALWAYS display correct information (even during dry_run)
            if master['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS and\
               util.instance.apache_instances() == 1:
                # remove Apache instance base
                util.directory.delete(master['pki_instance_path'])
                # remove Apache instance logs
                # remove shared NSS security database path for this instance
                util.directory.delete(master['pki_database_path'])
                # remove Apache instance configuration
                util.directory.delete(master['pki_instance_configuration_path'])
                # remove Apache instance registry
                util.directory.delete(master['pki_instance_type_registry_path'])
            elif master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS and\
                 util.instance.tomcat_instances() == 1:
                # remove Tomcat instance base
                util.directory.delete(master['pki_instance_path'])
                # remove Tomcat instance logs
                # remove shared NSS security database path for this instance
                util.directory.delete(master['pki_database_path'])
                # remove Tomcat instance configuration
                util.directory.delete(master['pki_instance_configuration_path'])
                # remove Tomcat instance registry
                util.directory.delete(master['pki_instance_type_registry_path'])
        return self.rv
