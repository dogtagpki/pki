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


class RemoveLDAPSetupFiles(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(RemoveLDAPSetupFiles, self).__init__()
        self.message = 'Remove LDAP setup files from instance folder'

    def upgrade_instance(self, instance):
        filenames = [
            'schema-authority.ldif',
            'schema-certProfile.ldif',
            'usn.ldif',
        ]

        for filename in filenames:
            path = os.path.join(instance.conf_dir, filename)
            logger.info('Checking %s', path)
            if os.path.exists(path):
                logger.info('Removing %s', path)
                self.backup(path)
                pki.util.remove(path)
