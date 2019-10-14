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
# Copyright (C) 2018 Red Hat, Inc.
# All rights reserved.

from __future__ import absolute_import
import os
import pki.server.upgrade


class FixServerConfiguration(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(FixServerConfiguration, self).__init__()
        self.message = 'Fix server configuration'

    def upgrade_instance(self, instance):

        self.replace_with_link(
            instance,
            'catalina.properties',
            '/usr/share/pki/server/conf/catalina.properties')

        self.replace_with_link(
            instance,
            'ciphers.info',
            '/usr/share/pki/server/conf/ciphers.info')

        self.replace_with_link(
            instance,
            'context.xml',
            '/usr/share/tomcat/conf/context.xml')

        self.replace_with_link(
            instance,
            'web.xml',
            '/usr/share/tomcat/conf/web.xml')

    def replace_with_link(self, instance, filename, target):

        source = os.path.join(instance.conf_dir, filename)

        # if source is already a link, skip
        if os.path.islink(source):
            return

        self.backup(source)

        # if source already exists, remove it
        if os.path.exists(source):
            os.remove(source)

        # link source to target
        os.symlink(target, source)
        os.lchown(source, instance.uid, instance.gid)
