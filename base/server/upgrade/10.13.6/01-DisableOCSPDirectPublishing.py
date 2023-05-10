# Authors:
#     Marco Fargetta <mfargett@redhat.com>
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
# Copyright (C) 2023 Red Hat, Inc.

import fileinput
import os
import re
import pki.server.upgrade


class DisableOCSPDirectPublishing(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(DisableOCSPDirectPublishing, self).__init__()
        self.message = 'Disable direct publishing to the OCSP instance'

    def upgrade_subsystem(self, instance, subsystem):

        if subsystem.name != 'ca':
            return

        cs_cfg = os.path.join(
            instance.base_dir,
            'conf',
            subsystem.name,
            'CS.cfg')

        self.backup(cs_cfg)

        for line in fileinput.input(cs_cfg, inplace=1):
            line = re.sub(r'^ca.publish.rule.instance.ocsprule-(.*).enable=.*',
                          r'ca.publish.rule.instance.ocsprule-\1.enable=false',
                          line)

            print(line, end='')

        os.chown(cs_cfg, instance.uid, instance.gid)
