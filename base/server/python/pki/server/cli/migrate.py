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
import os
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

            self.migrate(instance)

        else:
            instances = pki.server.instance.PKIInstance.instances()

            for instance in instances:
                self.migrate(instance)

    def migrate(self, instance):
        self.export_ca_cert(instance)
        self.migrate_service(instance)

    def export_ca_cert(self, instance):

        ca_path = os.path.join(instance.nssdb_dir, 'ca.crt')

        token = pki.nssdb.INTERNAL_TOKEN_NAME
        nickname = instance.get_sslserver_cert_nickname()

        if ':' in nickname:
            parts = nickname.split(':', 1)
            token = parts[0]
            nickname = parts[1]

        nssdb = instance.open_nssdb(token=token)

        try:
            nssdb.extract_ca_cert(ca_path, nickname)
        finally:
            nssdb.close()

    def migrate_service(self, instance):
        self.migrate_service_java_home(instance)

    def migrate_service_java_home(self, instance):
        # When JAVA_HOME in the Tomcat service config differs from the
        # value in /usr/share/pki/etc/pki.conf, update the value in
        # the service config.

        if "JAVA_HOME" not in os.environ or not os.environ["JAVA_HOME"]:
            logger.debug("Refusing to migrate JAVA_HOME with missing environment variable")
            return

        java_home = os.environ['JAVA_HOME']

        # Update in /etc/sysconfig/<instance>
        result = self.update_java_home_in_config(instance.service_conf, java_home)
        self.write_config(instance.service_conf, result)

        # Update in /etc/pki/<instance>/tomcat.conf
        result = self.update_java_home_in_config(instance.tomcat_conf, java_home)
        self.write_config(instance.tomcat_conf, result)

    def update_java_home_in_config(self, path, java_home):
        result = []

        target = "JAVA_HOME="

        with open(path, 'r') as conf_fp:
            for line in conf_fp:
                if not line.startswith(target):
                    result.append(line)
                else:
                    new_line = target + '"' + java_home + '"\n'
                    result.append(new_line)

        return result

    def write_config(self, path, output):
        with open(path, 'w') as conf_fp:
            for line in output:
                print(line, end='', file=conf_fp)
