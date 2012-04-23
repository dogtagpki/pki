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
        if master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            config.pki_log.info(log.WAR_EXPLOSION_SPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            # deploy war file
            util.directory.create(master['pki_webapps_subsystem_path'])
            util.war.explode(master['pki_war'],
                             master['pki_webapps_subsystem_path'])
            # establish convenience symbolic links
            util.symlink.create(master['pki_webapps_webinf_classes_path'],
                master['pki_webapps_subsystem_webinf_classes_link'])
            util.symlink.create(master['pki_webapps_webinf_lib_path'],
                master['pki_webapps_subsystem_webinf_lib_link'])
            # set ownerships, permissions, and acls
            util.directory.set_mode(master['pki_webapps_subsystem_path'])
        return self.rv

    def respawn(self):
        if master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            config.pki_log.info(log.WAR_EXPLOSION_RESPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            # redeploy war file
            util.directory.modify(master['pki_webapps_subsystem_path'])
            util.war.explode(master['pki_war'],
                             master['pki_webapps_subsystem_path'])
            # update ownerships, permissions, and acls
            # NOTE:  This includes existing convenience symbolic links
            util.directory.set_mode(master['pki_webapps_subsystem_path'])
        return self.rv

    def destroy(self):
        if master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            config.pki_log.info(log.WAR_EXPLOSION_DESTROY_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            util.directory.delete(master['pki_webapps_subsystem_path'])
        return self.rv
