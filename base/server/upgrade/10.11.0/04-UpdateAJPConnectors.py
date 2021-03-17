#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
from __future__ import absolute_import
import logging
from lxml import etree
import re

import pki

logger = logging.getLogger(__name__)


class UpdateAJPConnectors(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(UpdateAJPConnectors, self).__init__()
        self.message = 'Update AJP connectors in server.xml'

        self.parser = etree.XMLParser(remove_blank_text=True)

    def upgrade_instance(self, instance):

        logger.info('Updating %s', instance.server_xml)
        self.backup(instance.server_xml)

        document = etree.parse(instance.server_xml, self.parser)
        server = document.getroot()

        logger.info('Renaming requiredSecret to secret')

        services = server.findall('Service')
        for service in services:

            children = list(service)
            for child in children:

                if isinstance(child, etree._Comment):  # pylint: disable=protected-access
                    if 'protocol="AJP/1.3"' in child.text:
                        child.text = re.sub(r'requiredSecret=',
                                            r'secret=',
                                            child.text,
                                            flags=re.MULTILINE)

        connectors = server.findall('Service/Connector')
        for connector in connectors:

            if connector.get('protocol') != 'AJP/1.3':
                # Only modify AJP connectors.
                continue

            if connector.get('secret'):
                # Nothing to migrate because the secret attribute already
                # exists.
                continue

            if connector.get('requiredSecret') is None:
                # No requiredSecret field either; nothing to do.
                continue

            connector.set('secret', connector.get('requiredSecret'))
            connector.attrib.pop('requiredSecret', None)

        with open(instance.server_xml, 'wb') as f:
            document.write(f, pretty_print=True, encoding='utf-8')
