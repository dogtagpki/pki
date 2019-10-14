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


class RemoveCustomPolicy(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(RemoveCustomPolicy, self).__init__()
        self.message = 'Remove empty custom.policy from instance folder'

    def upgrade_instance(self, instance):

        custom_policy = os.path.join(instance.conf_dir, 'custom.policy')

        if not os.path.exists(custom_policy):
            logger.info('custom.policy does not exist')
            return

        with open(custom_policy) as f:
            lines = f.read().splitlines()

        empty = True

        for line in lines:
            line = line.strip()

            if not line:
                continue

            if line.startswith('//'):
                continue

            empty = False
            break

        if not empty:
            logger.info('custom.policy is not empty')
            return

        logger.info('Removing custom.policy')

        self.backup(custom_policy)
        pki.util.remove(custom_policy)
