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
import sys

import pki.cli


class ACMECLI(pki.cli.CLI):

    def __init__(self):
        super(ACMECLI, self).__init__(
            'acme', 'ACME management commands')

        self.add_module(ACMEDeployCLI())
        # self.add_module(ACMEUndeployCLI())


class ACMEDeployCLI(pki.cli.CLI):

    def __init__(self):
        super(ACMEDeployCLI, self).__init__(
            'deploy', 'Deploy ACME subsystem')

    def print_help(self):
        print('Usage: pki-server acme-deploy [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: %s' % e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: unknown option %s' % o)
                self.print_help()
                sys.exit(1)

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.is_valid():
            raise ('Invalid instance: %s' % instance_name)

        instance.load()
