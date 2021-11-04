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
# Copyright (C) 2015 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
from __future__ import print_function

import getopt
import logging
import re
import sys

from lxml import etree

import pki.cli
import pki.nssdb
import pki.server.instance
import pki.util

logger = logging.getLogger(__name__)


class MigrateCLI(pki.cli.CLI):

    def __init__(self):
        super(MigrateCLI, self).__init__('migrate', 'Migrate system')

        self.parser = etree.XMLParser(remove_blank_text=True)

    def print_help(self):
        print('Usage: pki-server migrate [OPTIONS] [<instance ID>]')
        print()
        print('  -i, --instance <instance ID> Instance ID.')
        print('  -v, --verbose                Run in verbose mode.')
        print('      --debug                  Show debug messages.')
        print('      --help                   Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) > 0:
            instance_name = args[0]

        if instance_name:

            instance = pki.server.instance.PKIServerFactory.create(instance_name)

            if not instance.exists():
                logger.error('Invalid instance %s.', instance_name)
                sys.exit(1)

            instance.load()
            instance.init()
            instances = [instance]

        else:
            instances = pki.server.instance.PKIInstance.instances()

            for instance in instances:
                instance.init()

        # update AJP connectors for Tomcat 9.0.31 or later

        tomcat_version = pki.server.Tomcat.get_version()
        if tomcat_version >= pki.util.Version('9.0.31'):

            for instance in instances:
                self.update_ajp_connectors(instance)

    def update_ajp_connectors(self, instance):

        logger.info('Updating AJP connectors in %s', instance.server_xml)

        document = etree.parse(instance.server_xml, self.parser)
        server = document.getroot()

        # replace 'requiredSecret' with 'secret' in comments

        services = server.findall('Service')
        for service in services:

            children = list(service)
            for child in children:

                if not isinstance(child, etree._Comment):  # pylint: disable=protected-access
                    # not a comment -> skip
                    continue

                if 'protocol="AJP/1.3"' not in child.text:
                    # not an AJP connector -> skip
                    continue

                child.text = re.sub(r'requiredSecret=',
                                    r'secret=',
                                    child.text,
                                    flags=re.MULTILINE)

        # replace 'requiredSecret' with 'secret' in Connectors

        connectors = server.findall('Service/Connector')
        for connector in connectors:

            if connector.get('protocol') != 'AJP/1.3':
                # not an AJP connector -> skip
                continue

            if connector.get('secret'):
                # already has a 'secret' -> skip
                continue

            if connector.get('requiredSecret') is None:
                # does not have a 'requiredSecret' -> skip
                continue

            value = connector.attrib.pop('requiredSecret')
            connector.set('secret', value)

        with open(instance.server_xml, 'wb') as f:
            document.write(f, pretty_print=True, encoding='utf-8')
