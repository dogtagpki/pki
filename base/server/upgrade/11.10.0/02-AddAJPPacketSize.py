# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
from __future__ import absolute_import
import configparser
import logging
from lxml import etree

import pki
import pki.server.upgrade

logger = logging.getLogger(__name__)

DEFAULT_CFG = pki.SHARE_DIR + '/server/etc/default.cfg'


class AddAJPPacketSize(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super().__init__()
        self.message = 'Add packetSize to AJP connectors in server.xml'

        self.parser = etree.XMLParser(remove_blank_text=True)

    def upgrade_instance(self, instance):

        config = configparser.ConfigParser()
        config.optionxform = str
        config.read(DEFAULT_CFG)

        packet_size = config.get('Tomcat', 'pki_ajp_packet_size',
                                 fallback='65536')

        logger.info('Updating %s', instance.server_xml)
        self.backup(instance.server_xml)

        document = etree.parse(instance.server_xml, self.parser)
        server = document.getroot()

        for connector in server.findall('Service/Connector'):

            if not connector.get('protocol', '').startswith('AJP/'):
                continue

            if connector.get('packetSize'):
                logger.debug('AJP connector already has packetSize, skipping')
                continue

            connector.set('packetSize', packet_size)
            logger.info('Set packetSize=%s on AJP connector at %s',
                        packet_size, connector.get('address', '<unknown>'))

        with open(instance.server_xml, 'wb') as f:
            document.write(f, pretty_print=True, encoding='utf-8')
