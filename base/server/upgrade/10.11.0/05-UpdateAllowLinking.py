#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
from __future__ import absolute_import
import logging
from lxml import etree

import pki
import pki.server
import pki.util

logger = logging.getLogger(__name__)


class UpdateAllowLinking(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(UpdateAllowLinking, self).__init__()
        self.message = 'Update allowLinking in context.xml'

    def upgrade_instance(self, instance):

        self.update_context_xml(instance.root_xml)
        self.update_context_xml(instance.pki_xml)

    def upgrade_subsystem(self, instance, subsystem):

        self.update_context_xml(subsystem.context_xml)

    def update_context_xml(self, context_xml):

        logger.info('Updating %s', context_xml)
        self.backup(context_xml)

        document = etree.parse(context_xml, pki.server.parser)
        context = document.getroot()

        if 'allowLinking' in context.attrib:
            context.attrib.pop('allowLinking')

        resources = context.find('Resources')

        if resources is None:
            logger.info('Adding Resources element')
            resources = etree.Element('Resources')
            context.append(resources)

        resources.set('allowLinking', 'true')

        with open(context_xml, 'wb') as f:
            document.write(f, pretty_print=True, encoding='utf-8')
