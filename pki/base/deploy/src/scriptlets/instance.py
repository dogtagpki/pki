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
# Copyright (C) 2011 Red Hat, Inc.
# All rights reserved.
#

# System Imports
import os
import grp
import pwd

# PKI Deployment Imports
import pkiconfig
import pkimessages as log
import pkiscriptlet


# PKI Deployment Instance Population Classes
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):
    rv = 0
    pki_path = pkiconfig.pki_root_prefix +\
               pkiconfig.pki_common_dict['pki_instance_root']
    pki_instance_path = pki_path + "/" +\
                        pkiconfig.pki_common_dict['pki_instance_name']
    pki_subsystem_path = pki_instance_path + "/" +\
                         pkiconfig.pki_subsystem_dict['pki_subsystem'].lower()

    def spawn(self):
        if not os.path.exists(self.pki_subsystem_path):
            pkiconfig.pki_log.info(log.INSTANCE_SPAWN_1, __name__)
            pkiconfig.pki_log.info(log.INSTANCE_SPAWN_MKDIR_1,
                                   self.pki_subsystem_path)
            if not pkiconfig.pki_dry_run_flag:
                try:
                    pki_gid = grp.getgrnam(
                                  pkiconfig.pki_common_dict['pki_group'])[2]
                    pki_uid = pwd.getpwnam(
                                  pkiconfig.pki_common_dict['pki_user'])[2]
                    os.mkdir(self.pki_path,
                             pkiconfig.PKI_DEPLOYMENT_DEFAULT_DIR_PERMISSIONS)
                    os.chown(self.pki_path,
                             pki_uid,
                             pki_gid)
                    os.mkdir(self.pki_instance_path,
                             pkiconfig.PKI_DEPLOYMENT_DEFAULT_DIR_PERMISSIONS)
                    os.chown(self.pki_instance_path,
                             pki_uid,
                             pki_gid)
                    os.mkdir(self.pki_subsystem_path,
                             pkiconfig.PKI_DEPLOYMENT_DEFAULT_DIR_PERMISSIONS)
                    os.chown(self.pki_subsystem_path,
                             pki_uid,
                             pki_gid)
                except KeyError:
                    self.rv = KeyError
                except OSError:
                    self.rv = OSError
        elif not os.path.isdir(self.pki_subsystem_path):
            pkiconfig.pki_log.error(
                log.PKI_DIRECTORY_ALREADY_EXISTS_NOT_A_DIRECTORY_1,
                self.pki_subsystem_path)
            self.rv = -1
        else:
            pkiconfig.pki_log.error(log.PKI_DIRECTORY_ALREADY_EXISTS_1,
                                    self.pki_subsystem_path)
            self.rv = -1
        return self.rv

    def respawn(self):
        if not os.path.exists(self.pki_subsystem_path) or\
           not os.path.isdir(self.pki_subsystem_path):
            pkiconfig.pki_log.error(
                log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1,
                self.pki_subsystem_path)
            self.rv = -1
        else:
            pkiconfig.pki_log.info(log.INSTANCE_RESPAWN_1, __name__)
        return self.rv

    def destroy(self):
        if not os.path.exists(self.pki_subsystem_path) or\
           not os.path.isdir(self.pki_subsystem_path):
            pkiconfig.pki_log.error(
                log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1,
                self.pki_subsystem_path)
            self.rv = -1
        else:
            pkiconfig.pki_log.info(log.INSTANCE_DESTROY_1, __name__)
        return self.rv

