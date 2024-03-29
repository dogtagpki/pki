# Authors:
#     Ade Lee <alee@redhat.com>
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
# Copyright (C) 2013 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
import os
import re
import pki.server
import pki.server.upgrade


class FixRegistryFile(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(FixRegistryFile, self).__init__()
        self.message = 'Replace PKI_INSTANCE_ID and fix registry file ownership'

    def upgrade_instance(self, instance):
        registry_file = os.path.join(
            pki.server.PKIServer.REGISTRY_DIR, 'tomcat', instance.name, instance.name)
        self.backup(registry_file)

        with open(registry_file, "r", encoding='utf-8') as registry:
            lines = registry.readlines()

        with open(registry_file, "w", encoding='utf-8') as registry:
            for line in lines:
                registry.write(
                    re.sub(r'PKI_INSTANCE_ID', 'PKI_INSTANCE_NAME', line))

        os.chown(registry_file, instance.uid, instance.gid)
