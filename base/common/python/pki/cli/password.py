# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the Lesser GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2018 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
from __future__ import print_function
import getopt
import sys

import pki
import pki.cli


class PasswordCLI(pki.cli.CLI):

    def __init__(self):
        super(PasswordCLI, self).__init__(
            'password', 'Password utilities')

        self.add_module(PasswordGenerateCLI())


class PasswordGenerateCLI(pki.cli.CLI):

    def __init__(self):
        super(PasswordGenerateCLI, self).__init__(
            'generate', 'Generate secure random password')

    def print_help(self):  # flake8: noqa
        print('Usage: pki password-generate [OPTIONS]')
        print()
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'v', [
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: %s' % e)
            self.print_help()
            sys.exit(1)

        for o, _ in opts:
            if o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: unknown option %s' % o)
                self.print_help()
                sys.exit(1)

        print(pki.generate_password())
