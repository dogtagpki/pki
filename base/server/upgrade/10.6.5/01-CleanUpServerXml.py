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
from lxml import etree

import pki


class CleanUpServerXml(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(CleanUpServerXml, self).__init__()
        self.message = 'Clean up server.xml'

        self.parser = etree.XMLParser(remove_blank_text=True)

    def upgrade_instance(self, instance):

        server_xml = os.path.join(instance.conf_dir, 'server.xml')
        self.backup(server_xml)

        document = etree.parse(server_xml, self.parser)
        server = document.getroot()

        self.normalize_appBase(instance, server)
        self.remove_resolveHosts(server)

        with open(server_xml, 'wb') as f:
            document.write(f, pretty_print=True, encoding='utf-8')

    def normalize_appBase(self, instance, server):

        prefix = instance.base_dir + '/'
        length = len(prefix)

        hosts = server.findall('Service/Engine/Host')
        for host in hosts:

            appBase = host.get('appBase')
            if not appBase.startswith(prefix):
                continue

            appBase = appBase[length:]
            host.set('appBase', appBase)

    def remove_resolveHosts(self, server):

        valves = server.findall('Service/Engine/Host/Valve')
        for valve in valves:

            valve.attrib.pop('resolveHosts', None)
