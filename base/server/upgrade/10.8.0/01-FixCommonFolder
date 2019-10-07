# Authors:
#     Endi S. Dewata <edewata@redhat.com>
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
# Copyright (C) 2019 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
import os
import pki


class FixCommonFolder(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(FixCommonFolder, self).__init__()
        self.message = 'Fix common folder'

    def upgrade_instance(self, instance):

        if not os.path.islink(instance.common_dir):
            # <instance>/common is already a real folder
            return

        self.backup(instance.common_dir)

        # replace <instance>/common link with a real folder
        pki.util.unlink(instance.common_dir)
        instance.makedirs(instance.common_dir)

        # link <instance>/common/lib to /usr/share/pki/server/common/lib
        common_lib_dir = os.path.join(pki.server.PKIServer.SHARE_DIR, 'server', 'common', 'lib')
        instance.symlink(common_lib_dir, instance.common_lib_dir)
