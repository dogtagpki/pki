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
import pkimessages as log
import pkiscriptlet


# PKI Deployment Instance Population Classes
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):
    rv = 0

    def spawn(self):
        config.pki_log.info(log.SLOT_ASSIGNMENT_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        config.pki_log.info("NOT YET IMPLEMENTED",
                            extra=config.PKI_INDENTATION_LEVEL_2)
        return self.rv

    def respawn(self):
        config.pki_log.info(log.SLOT_ASSIGNMENT_RESPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        config.pki_log.info("NOT YET IMPLEMENTED",
                            extra=config.PKI_INDENTATION_LEVEL_2)
        return self.rv

    def destroy(self):
        config.pki_log.info(log.SLOT_ASSIGNMENT_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        config.pki_log.info("NOT YET IMPLEMENTED",
                            extra=config.PKI_INDENTATION_LEVEL_2)
        return self.rv
