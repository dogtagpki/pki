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
from lxml import etree

import pki

logger = logging.getLogger(__name__)


class AddPKIListener(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(AddPKIListener, self).__init__()
        self.message = 'Add PKIListener in server.xml'

    def upgrade_instance(self, instance):

        self.backup(instance.server_xml)

        document = etree.parse(instance.server_xml, pki.server.parser)
        server = document.getroot()

        # find existing PKIListener
        class_name = 'com.netscape.cms.tomcat.PKIListener'
        pki_listener = server.find('Listener[@className=\'%s\']' % class_name)

        if pki_listener is None:
            logger.debug('Creating new PKIListener')
            pki_listener = etree.Element('Listener')
            pki_listener.set('className', class_name)

        else:
            logger.debug('Detaching existing PKIListener')
            server.remove(pki_listener)

        # find the last Listener
        last_listener = server.find('Listener[last()]')

        if last_listener is None:
            logger.debug('No other Listeners found')
            # (re)insert PKIListener at the top
            index = 0

        else:
            logger.debug('Found last Listener: %s', last_listener.get('className'))
            # (re)insert PKIListener after the last listener
            index = list(server).index(last_listener) + 1

        logger.debug('Inserting PKIListener at index %d', index)
        server.insert(index, pki_listener)

        with open(instance.server_xml, 'wb') as f:
            document.write(f, pretty_print=True, encoding='utf-8')
