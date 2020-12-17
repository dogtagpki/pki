# Authors:
#     Christina Fu <cfu@redhat.com>
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
# Copyright (C) 2020 Red Hat, Inc.

import fileinput
import os
import re
import pki.server.upgrade


class FixChallengePasswordClassPath(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(FixChallengePasswordClassPath, self).__init__()
        self.message = 'Fix Challenge Password Class Path'

    def upgrade_subsystem(self, instance, subsystem):

        cs_cfg = os.path.join(
            instance.base_dir,
            'conf',
            subsystem.name,
            'CS.cfg')

        self.backup(cs_cfg)

        for line in fileinput.input(cs_cfg, inplace=1):
            line = re.sub(r"^oidmap.challenge_password.class=.*",
                          "oidmap.challenge_password.class=org.mozilla.jss."
                          "netscape.security.x509.ChallengePassword",
                          line)

            line = re.sub(r"^oidmap.extensions_requested_pkcs9.class=.*",
                          "oidmap.extensions_requested_pkcs9.class=org.mozilla.jss."
                          "netscape.security.x509.ExtensionsRequested",
                          line)

            line = re.sub(r"^oidmap.extensions_requested_vsgn.class=.*",
                          "oidmap.extensions_requested_vsgn.class=org.mozilla.jss."
                          "netscape.security.x509.ExtensionsRequested",
                          line)
            print(line, end='')

        os.chown(cs_cfg, instance.uid, instance.gid)
