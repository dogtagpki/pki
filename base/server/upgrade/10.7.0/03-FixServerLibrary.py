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

from __future__ import absolute_import
import os
import shutil

import pki.server.upgrade


class FixServerLibrary(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(FixServerLibrary, self).__init__()
        self.message = 'Fix server library'

    def upgrade_instance(self, instance):

        self.replace_with_link(
            instance,
            instance.lib_dir,
            '/usr/share/pki/server/lib')

    def replace_with_link(self, instance, source, target):

        # if source is already a link, skip
        if os.path.islink(source):
            return

        self.backup(source)

        if os.path.isdir(source):
            shutil.rmtree(source)
        else:
            os.remove(source)

        # link source to target
        instance.symlink(target, source)
