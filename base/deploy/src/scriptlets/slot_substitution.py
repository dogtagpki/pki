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
from pkiconfig import pki_slots_dict as slots
import pkihelper as util
import pkimessages as log
import pkiscriptlet


# PKI Deployment Slot Substitution Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):
    rv = 0

    def spawn(self):
        if config.str2bool(master['pki_skip_installation']):
            config.pki_log.info(log.SKIP_SLOT_ASSIGNMENT_SPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            return self.rv
        config.pki_log.info(log.SLOT_ASSIGNMENT_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        util.file.copy_with_slot_substitution(master['pki_source_cs_cfg'],
                                              master['pki_target_cs_cfg'])
        util.file.copy_with_slot_substitution(master['pki_source_registry'],
                                              master['pki_target_registry'],
                                              uid=0, gid=0, overwrite_flag=True)
        if master['pki_subsystem'] in config.PKI_TOMCAT_SUBSYSTEMS:
            util.file.copy_with_slot_substitution(
                master['pki_source_catalina_properties'],
                master['pki_target_catalina_properties'],
                overwrite_flag=True)
            util.file.copy_with_slot_substitution(
                master['pki_source_servercertnick_conf'],
                master['pki_target_servercertnick_conf'],
                overwrite_flag=True)
            util.file.copy_with_slot_substitution(
                master['pki_source_server_xml'],
                master['pki_target_server_xml'],
                overwrite_flag=True)
            util.file.copy_with_slot_substitution(
                master['pki_source_context_xml'],
                master['pki_target_context_xml'],
                overwrite_flag=True)
            util.file.copy_with_slot_substitution(
                master['pki_source_tomcat_conf'],
                master['pki_target_tomcat_conf_instance_id'],
                uid=0, gid=0, overwrite_flag=True)
            util.file.copy_with_slot_substitution(
                master['pki_source_tomcat_conf'],
                master['pki_target_tomcat_conf'],
                overwrite_flag=True)
            util.file.apply_slot_substitution(
                master['pki_target_auth_properties'])
            util.file.apply_slot_substitution(
                master['pki_target_velocity_properties'])
            util.file.apply_slot_substitution(
                master['pki_target_subsystem_web_xml'])
            # Strip "<filter>" section from subsystem "web.xml"
            # This is ONLY necessary because XML comments cannot be "nested"!
            #util.file.copy(master['pki_target_subsystem_web_xml'],
            #               master['pki_target_subsystem_web_xml_orig'])
            #util.file.delete(master['pki_target_subsystem_web_xml'])
            #util.xml_file.remove_filter_section_from_web_xml(
            #    master['pki_target_subsystem_web_xml_orig'],
            #    master['pki_target_subsystem_web_xml'])
            #util.file.delete(master['pki_target_subsystem_web_xml_orig'])
            if master['pki_subsystem'] == "CA":
                util.file.copy_with_slot_substitution(
                    master['pki_source_proxy_conf'],
                    master['pki_target_proxy_conf'])
                util.file.apply_slot_substitution(
                    master['pki_target_profileselect_template'])
        return self.rv

    def respawn(self):
        config.pki_log.info(log.SLOT_ASSIGNMENT_RESPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        return self.rv

    def destroy(self):
        config.pki_log.info(log.SLOT_ASSIGNMENT_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        config.pki_log.info("NOTHING NEEDS TO BE IMPLEMENTED",
                            extra=config.PKI_INDENTATION_LEVEL_2)
        return self.rv
