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


class RemovePKIPolicy(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(RemovePKIPolicy, self).__init__()
        self.message = 'Remove pki.policy from instance folder'

    def upgrade_instance(self, instance):

        pki_policy = os.path.join(instance.conf_dir, 'pki.policy')
        logger.info('Checking %s', pki_policy)

        if os.path.exists(pki_policy):
            logger.info('Removing %s', pki_policy)
            self.backup(pki_policy)
            pki.util.remove(pki_policy)
