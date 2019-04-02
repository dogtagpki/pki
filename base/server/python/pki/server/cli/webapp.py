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
from __future__ import print_function
import getopt
import logging
import sys

import pki.cli
import pki.server


class WebappCLI(pki.cli.CLI):

    def __init__(self):
        super(WebappCLI, self).__init__(
            'webapp', 'Webapp management commands')

        self.add_module(WebappFindCLI())

    @staticmethod
    def print_webapp(webapp):

        print('  Webapp ID: %s' % webapp['id'])
        print('  Path: %s' % webapp['path'])

        if 'version' in webapp:
            print('  Version: %s' % webapp['version'])

        print('  Descriptor: %s' % webapp['descriptor'])
        print('  Document Base: %s' % webapp['docBase'])


class WebappFindCLI(pki.cli.CLI):

    def __init__(self):
        super(WebappFindCLI, self).__init__('find', 'Find webapps')

    def print_help(self):
        print('Usage: pki-server webapp-find [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: %s' % e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: Unknown option: %s' % o)
                self.print_help()
                sys.exit(1)

        if len(args) > 0:
            instance_name = args[0]

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.is_valid():
            raise Exception('Invalid instance: %s' % instance_name)

        webapps = instance.get_webapps()
        first = True

        for webapp in webapps:
            if first:
                first = False
            else:
                print()

            WebappCLI.print_webapp(webapp)
