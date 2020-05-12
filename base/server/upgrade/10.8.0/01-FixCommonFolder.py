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
import logging
import os

import pki

logger = logging.getLogger(__name__)


class FixCommonFolder(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(FixCommonFolder, self).__init__()
        self.message = 'Fix common folder'

    def upgrade_instance(self, instance):

        logger.info('Checking %s', instance.common_dir)
        if not os.path.islink(instance.common_dir):
            logger.info('%s is already a real folder', instance.common_dir)
            return

        logger.info('Backing up %s', instance.common_dir)
        self.backup(instance.common_dir)

        logger.info('Replacing %s link with a real folder', instance.common_dir)
        pki.util.unlink(instance.common_dir)
        instance.makedirs(instance.common_dir)

        logger.info('Linking %s to /usr/share/pki/server/common/lib', instance.common_dir)
        common_lib_dir = os.path.join(pki.server.PKIServer.SHARE_DIR, 'server', 'common', 'lib')
        instance.symlink(common_lib_dir, instance.common_lib_dir)
