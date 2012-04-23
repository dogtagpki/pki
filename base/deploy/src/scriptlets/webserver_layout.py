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
        if master['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS:
            util.directory.create(master['pki_apache_path'])
        elif master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            util.directory.create(master['pki_tomcat_path'])
            util.directory.create(master['pki_common_path'])
            util.directory.create(master['pki_common_lib_path'])
            util.directory.create(master['pki_conf_path'])
            util.directory.create(master['pki_webapps_path'])
            util.directory.create(master['pki_webapps_root_path'])
            util.directory.create(master['pki_webapps_root_webinf_path'])
            util.directory.create(master['pki_webapps_webinf_path'])
            util.directory.create(master['pki_webapps_webinf_classes_path'])
            util.directory.create(master['pki_webapps_webinf_lib_path'])
        # establish instance-based webserver configuration
        util.directory.create(master['pki_database_path'])
        # establish convenience symbolic links
        util.symlink.create(master['pki_database_path'],
                            master['pki_instance_database_link'])
        util.symlink.create(master['pki_tomcat_bin_path'],
                            master['pki_tomcat_bin_link'])
        util.symlink.create(master['pki_tomcat_lib_path'],
                            master['pki_tomcat_lib_link'])
        util.symlink.create(master['pki_instance_log_path'],
                            master['pki_tomcat_logs_link'])
        return self.rv

    def respawn(self):
        config.pki_log.info(log.WEBSERVER_RESPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # update instance-based webserver base
        if master['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS:
            util.directory.modify(master['pki_apache_path'])
        elif master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            util.directory.modify(master['pki_tomcat_path'])
            util.directory.modify(master['pki_common_path'])
            util.directory.modify(master['pki_common_lib_path'])
            util.directory.modify(master['pki_conf_path'])
            util.directory.modify(master['pki_webapps_path'])
            util.directory.modify(master['pki_webapps_root_path'])
            util.directory.modify(master['pki_webapps_root_webinf_path'])
            util.directory.modify(master['pki_webapps_webinf_path'])
            util.directory.modify(master['pki_webapps_webinf_classes_path'])
            util.directory.modify(master['pki_webapps_webinf_lib_path'])
        # update instance-based webserver configuration
        util.directory.modify(master['pki_database_path'])
        # update convenience symbolic links
        util.symlink.modify(master['pki_instance_database_link'])
        util.symlink.modify(master['pki_tomcat_bin_link'])
        util.symlink.modify(master['pki_tomcat_lib_link'])
        util.symlink.modify(master['pki_tomcat_logs_link'])
        return self.rv

    def destroy(self):
        config.pki_log.info(log.WEBSERVER_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        # remove instance-based webserver base
        if not config.pki_dry_run_flag and\
           master['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS and\
           util.instance.apache_instances(master['pki_instance_path']) == 0:
            util.directory.delete(master['pki_apache_path'])
        elif master['pki_subsystem'] in config.PKI_APACHE_SUBSYSTEMS and\
             util.instance.apache_instances(master['pki_instance_path']) == 1:
            # always display correct information (even during dry_run)
            util.directory.delete(master['pki_apache_path'])
        if not config.pki_dry_run_flag and\
           master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS and\
           util.instance.tomcat_instances(master['pki_instance_path']) == 0:
            util.directory.delete(master['pki_tomcat_path'])
        elif master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS and\
             util.instance.tomcat_instances(master['pki_instance_path']) == 1:
            # always display correct information (even during dry_run)
            util.directory.delete(master['pki_tomcat_path'])
        # remove instance-based webserver configuration
        if not config.pki_dry_run_flag and\
           util.instance.pki_subsystem_instances(\
               master['pki_instance_path']) == 0:
            util.directory.delete(master['pki_database_path'])
        elif util.instance.pki_subsystem_instances(\
            master['pki_instance_path']) == 1:
            # always display correct information (even during dry_run)
            util.directory.delete(master['pki_database_path'])
        return self.rv
