# Authors:
#     Alexander Scheel <ascheel@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import absolute_import
import logging
from lxml import etree

import pki

logger = logging.getLogger(__name__)


class AddIPv6AJPAdapter(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(AddIPv6AJPAdapter, self).__init__()
        self.message = 'Add IPv6 localhost AJP adapter in server.xml'

        self.parser = etree.XMLParser(remove_blank_text=True)

    def upgrade_instance(self, instance):
        logger.info('Upgrading %s', instance.server_xml)
        self.backup(instance.server_xml)

        document = etree.parse(instance.server_xml, self.parser)

        server = document.getroot()

        services = server.findall('.//Service')

        for service in services:
            # Keep track of all IPv4 AJP connectors so we can create an IPv6
            # AJP connector later after finding them all. This lets us avoid
            # modifying the service subtree while iterating through it.
            ipv4_connectors = []

            # Store and retain any IPv6 connectors we find, to avoid creating
            # unnecessary duplicates in case anyone already added one.
            ipv6_connectors = []

            # For all connectors in our Service element...
            for connector in service.iter(tag='Connector'):
                protocol = connector.get('protocol')
                if protocol != 'AJP/1.3':
                    # Ignore non-AJP connectors
                    continue

                address = connector.get('address')
                if address == 'localhost6':
                    # If this AJP connector has a localhost6 address, we
                    # should save it.
                    ipv6_connectors.append(connector)
                    continue
                if address != 'localhost':
                    # If this is a localhost or any other address, skip this
                    # AJP adapter; it is up to the administrator to update
                    # their config appropriately.
                    continue

                # Since this AJP adapter has localhost, update it to be IPv4
                # only.
                connector.set('address', 'localhost4')

                # Save this connector so we can refer to it later and clone
                # it into an IPv6 connector
                ipv4_connectors.append(connector)

            for ipv4 in ipv4_connectors:
                # Copy all the connector attributes and add change the
                # address to localhost6.
                ipv6_attrib = {}
                ipv6_attrib.update(ipv4.attrib)
                ipv6_attrib['address'] = 'localhost6'

                found = False
                for element in ipv6_connectors:
                    if ipv6_attrib == element.attrib:
                        found = True

                if not found:
                    # If this element would have different attributes, we
                    # should add it into the tree.
                    etree.SubElement(service, 'Connector', ipv6_attrib)

        with open(instance.server_xml, 'wb') as f:
            document.write(f, pretty_print=True, encoding='utf-8')
