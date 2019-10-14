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
import logging
from lxml import etree

import pki
import pki.server
import pki.util


class ResetWebApplication(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(ResetWebApplication, self).__init__()
        self.message = 'Reset web application to the default'

    def upgrade_instance(self, instance):

        self.reset_webapp('ROOT', instance.root_xml, instance.default_root_doc_base)
        self.reset_webapp('pki', instance.pki_xml, instance.default_pki_doc_base)

    def upgrade_subsystem(self, instance, subsystem):

        self.reset_webapp(subsystem.name, subsystem.context_xml, subsystem.default_doc_base)

    def reset_webapp(self, webapp_id, context_xml, default_doc_base):

        logging.debug('Resetting %s webapp', webapp_id)

        self.backup(context_xml)

        logging.debug('Loading %s', context_xml)
        document = etree.parse(context_xml, pki.server.parser)

        context = document.getroot()
        doc_base = context.get('docBase')
        logging.debug('Document base: %s', doc_base)

        if doc_base == default_doc_base:
            logging.debug('No change required')
            return

        logging.debug('Backing up custom webapp')
        self.backup(doc_base)

        logging.debug('Removing custom webapp')
        pki.util.rmtree(doc_base)

        logging.debug('Deploying default webapp')
        context.set('docBase', default_doc_base)

        logging.debug('Storing %s', context_xml)
        with open(context_xml, 'wb') as f:
            document.write(f, pretty_print=True, encoding='utf-8')
