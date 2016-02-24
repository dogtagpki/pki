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
# Copyright (C) 2016 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
from __future__ import print_function
import getopt
import sys

import pki.cli


class PKCS12CLI(pki.cli.CLI):

    def __init__(self):
        super(PKCS12CLI, self).__init__(
            'pkcs12', 'PKCS #12 utilities')

        self.add_module(PKCS12ImportCLI())


class PKCS12ImportCLI(pki.cli.CLI):

    def __init__(self):
        super(PKCS12ImportCLI, self).__init__(
            'import', 'Import PKCS #12 file into NSS database')

    def print_help(self):
        print('Usage: pki pkcs12-import [OPTIONS]')
        print()
        print('      --pkcs12                    PKCS #12 file containing certificates and keys.')
        print('      --pkcs12-password           Password for the PKCS #12 file.')
        print('      --pkcs12-password-file      File containing the PKCS #12 password.')
        print('      --no-trust-flags            Do not include trust flags')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, args):

        try:
            opts, _ = getopt.gnu_getopt(args, 'v', [
                'pkcs12=', 'pkcs12-password=', 'pkcs12-password-file=',
                'no-trust-flags', 'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.print_help()
            sys.exit(1)

        pkcs12_file = None
        pkcs12_password = None
        password_file = None
        no_trust_flags = False

        for o, a in opts:
            if o == '--pkcs12':
                pkcs12_file = a

            elif o == '--pkcs12-password':
                pkcs12_password = a

            elif o == '--pkcs12-password-file':
                password_file = a

            elif o == '--no-trust-flags':
                no_trust_flags = True

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: unknown option ' + o)
                self.print_help()
                sys.exit(1)

        if not pkcs12_file:
            print('ERROR: Missing PKCS #12 file')
            self.print_help()
            sys.exit(1)

        if not pkcs12_password and not password_file:
            print('ERROR: Missing PKCS #12 password')
            self.print_help()
            sys.exit(1)

        main_cli = self.parent.parent

        cmd = ['pkcs12-import']

        if pkcs12_file:
            cmd.extend(['--pkcs12', pkcs12_file])

        if pkcs12_password:
            cmd.extend(['--pkcs12-password', pkcs12_password])

        if password_file:
            cmd.extend(['--pkcs12-password-file', password_file])

        if no_trust_flags:
            cmd.extend(['--no-trust-flags'])

        main_cli.execute_java(cmd)
