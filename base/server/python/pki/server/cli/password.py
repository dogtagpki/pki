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
# Copyright (C) 2018 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
from __future__ import print_function

import getopt
import sys

import pki.cli
import pki.server


class PasswordCLI(pki.cli.CLI):
    def __init__(self):
        super(PasswordCLI, self).__init__(
            'password', 'System password management commands')

        self.add_module(PasswordFindCLI())
        self.add_module(PasswordExportCLI())

    @staticmethod
    def print_system_password(name):
        print('  Password ID: %s' % name)


class PasswordFindCLI(pki.cli.CLI):
    def __init__(self):
        super(PasswordFindCLI, self).__init__(
            'find', 'Find system passwords.')

    def print_help(self):
        print('Usage: pki-server password-find [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
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
                print('ERROR: unknown option ' + o)
                self.print_help()
                sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)

        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        self.print_message('%s entries matched' % len(instance.passwords))

        first = True
        for name in instance.passwords:
            if first:
                first = False
            else:
                print()

            PasswordCLI.print_system_password(name)


class PasswordExportCLI(pki.cli.CLI):
    def __init__(self):
        super(PasswordExportCLI, self).__init__(
            'export', 'Export system password.')

    def usage(self):  # flake8: noqa
        print('Usage: pki-server password-export [OPTIONS] <Password ID>')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --output <path>                Output file to store the password.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'output=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.usage()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        output = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--output':
                output = a

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.usage()
                sys.exit()

            else:
                self.print_message('ERROR: unknown option ' + o)
                self.usage()
                sys.exit(1)

        if len(args) < 1:
            print('ERROR: missing password ID')
            self.usage()
            sys.exit(1)

        name = args[0]

        if not output:
            print('ERROR: missing output file')
            self.usage()
            sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)

        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        if name not in instance.passwords:
            print('ERROR: Password not available: %s' % name)
            sys.exit(1)

        password = instance.passwords[name]

        with open(output, 'w') as f:
            f.write(password)
