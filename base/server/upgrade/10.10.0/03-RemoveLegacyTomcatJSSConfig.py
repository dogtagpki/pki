# Authors:
#     Alexander Scheel <ascheel@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import absolute_import
import logging
from lxml import etree
import os

import pki

logger = logging.getLogger(__name__)


class RemoveLegacyTomcatJSSConfig(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(RemoveLegacyTomcatJSSConfig, self).__init__()
        self.message = 'Remove legacy TomcatJSS Configuration from server.xml'

        self.parser = etree.XMLParser(remove_blank_text=True)

    def upgrade_instance(self, instance):
        logger.info('Upgrading %s', instance.server_xml)
        self.backup(instance.server_xml)

        ciphers_info = os.path.join(instance.conf_dir, 'ciphers.info')
        if os.path.exists(ciphers_info):
            self.backup(ciphers_info)
            os.remove(ciphers_info)

        document = etree.parse(instance.server_xml, self.parser)

        server = document.getroot()

        removed_attrs = ['strictCiphers', 'sslVersionRangeStream', 'sslVersionRangeDatagram',
                         'sslRangeCiphers']

        connectors = server.findall('Service/Connector')
        for connector in connectors:
            for attr in removed_attrs:
                connector.attrib.pop(attr, None)

        with open(instance.server_xml, 'wb') as f:
            document.write(f, pretty_print=True, encoding='utf-8')
