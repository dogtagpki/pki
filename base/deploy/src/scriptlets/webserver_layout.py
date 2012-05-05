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


# PKI Deployment Instance Population Classes
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):
    rv = 0

    def spawn(self):
        config.pki_log.info(log.WEBSERVER_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # establish instance-based webserver base
        util.directory.create(master['pki_webserver_path'])
        # establish instance-based webserver logs
        util.directory.create(master['pki_webserver_log_path'])
        # establish instance-based webserver configuration
        util.directory.create(master['pki_webserver_configuration_path'])
        # establish instance-based webserver registry
        util.directory.create(master['pki_webserver_registry_path'])
        # establish instance-based Apache/Tomcat specific webserver
        if master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            # establish instance-based Tomcat webserver base
            util.directory.create(master['pki_tomcat_common_path'])
            util.directory.create(master['pki_tomcat_common_lib_path'])
            util.directory.create(master['pki_tomcat_webapps_path'])
            util.directory.create(master['pki_tomcat_webapps_root_path'])
            util.directory.create(master['pki_tomcat_webapps_root_webinf_path'])
            util.file.copy(master['pki_source_webapps_root_web_xml'],
                           master['pki_tomcat_webapps_root_webinf_web_xml'],
                           overwrite_flag=True)
            util.directory.create(master['pki_tomcat_webapps_webinf_path'])
            util.directory.create(\
                master['pki_tomcat_webapps_webinf_classes_path'])
            util.directory.create(master['pki_tomcat_webapps_webinf_lib_path'])
            # establish instance-based Tomcat webserver logs
            # establish instance-based Tomcat webserver configuration
            # establish instance-based Tomcat webserver registry
            # establish instance-based Tomcat webserver convenience
            # symbolic links
            util.symlink.create(master['pki_tomcat_bin_path'],
                                master['pki_tomcat_bin_link'])
            util.symlink.create(master['pki_tomcat_lib_path'],
                                master['pki_tomcat_lib_link'])
            util.symlink.create(master['pki_tomcat_systemd'],
                                master['pki_webserver_systemd_link'])
        # establish instance-based webserver convenience symbolic links
        util.symlink.create(master['pki_instance_database_link'],
                            master['pki_webserver_database_link'])
        util.symlink.create(master['pki_webserver_configuration_path'],
                            master['pki_webserver_conf_link'])
        util.symlink.create(master['pki_webserver_log_path'],
                            master['pki_webserver_logs_link'])
        return self.rv

    def respawn(self):
        config.pki_log.info(log.WEBSERVER_RESPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # update instance-based webserver base
        util.directory.modify(master['pki_webserver_path'])
        # update instance-based webserver logs
        util.directory.modify(master['pki_webserver_log_path'])
        # update instance-based webserver configuration
        util.directory.modify(master['pki_webserver_configuration_path'])
        # update instance-based webserver registry
        util.directory.modify(master['pki_webserver_registry_path'])
        # update instance-based Apache/Tomcat specific webserver
        if master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            # update instance-based Tomcat webserver base
            util.directory.modify(master['pki_tomcat_common_path'])
            util.directory.modify(master['pki_tomcat_common_lib_path'])
            util.directory.modify(master['pki_tomcat_webapps_path'])
            util.directory.modify(master['pki_tomcat_webapps_root_path'])
            util.directory.modify(master['pki_tomcat_webapps_root_webinf_path'])
            util.file.copy(master['pki_source_webapps_root_web_xml'],
                           master['pki_tomcat_webapps_root_webinf_web_xml'],
                           overwrite_flag=True)
            util.directory.modify(master['pki_tomcat_webapps_webinf_path'])
            util.directory.modify(\
                master['pki_tomcat_webapps_webinf_classes_path'])
            util.directory.modify(master['pki_tomcat_webapps_webinf_lib_path'])
            # update instance-based Tomcat webserver logs
            # update instance-based Tomcat webserver configuration
            # update instance-based Tomcat webserver registry
            # update instance-based Tomcat webserver convenience symbolic links
            util.symlink.modify(master['pki_tomcat_bin_link'])
            util.symlink.modify(master['pki_tomcat_lib_link'])
        # update instance-based webserver convenience symbolic links
        util.symlink.modify(master['pki_webserver_database_link'])
        util.symlink.modify(master['pki_webserver_conf_link'])
        util.symlink.modify(master['pki_webserver_logs_link'])
        return self.rv

    def destroy(self):
        config.pki_log.info(log.WEBSERVER_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        if not config.pki_dry_run_flag:
            if master['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS and\
               util.instance.apache_instances() == 0:
                # remove instance-based webserver base
                util.directory.delete(master['pki_webserver_path'])
                # remove instance-based webserver logs
                # remove instance-based webserver configuration
                # remove instance-based webserver registry
            elif master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS and\
                 util.instance.tomcat_instances() == 0:
                # remove instance-based webserver base
                util.directory.delete(master['pki_webserver_path'])
                # remove instance-based webserver logs
                # remove instance-based webserver configuration
                # remove instance-based webserver registry
        else:
            # ALWAYS display correct information (even during dry_run)
            if master['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS and\
               util.instance.apache_instances() == 1:
                # remove instance-based webserver base
                util.directory.delete(master['pki_webserver_path'])
                # remove instance-based webserver logs
                # remove instance-based webserver configuration
                # remove instance-based webserver registry
            elif master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS and\
                 util.instance.tomcat_instances() == 1:
                # remove instance-based webserver base
                util.directory.delete(master['pki_webserver_path'])
                # remove instance-based webserver logs
                # remove instance-based webserver configuration
                # remove instance-based webserver registry
        return self.rv
