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
import getpass
import logging
import sys

import pki.cli


class NSSCLI(pki.cli.CLI):

    def __init__(self):
        super(NSSCLI, self).__init__(
            'nss', 'NSS management commands')

        self.add_module(NSSCreateCLI())
        self.add_module(NSSRemoveCLI())


class NSSCreateCLI(pki.cli.CLI):

    def __init__(self):
        super(NSSCreateCLI, self).__init__(
            'create', 'Create NSS database in PKI server')

    def print_help(self):
        print('Usage: pki-server nss-create [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --password <password>          NSS database password.')
        print('      --password-file <path>         NSS database password file.')
        print('      --force                        Force creation.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:d:v', [
                'instance=',
                'password=', 'password-file=', 'force',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: %s' % e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        password = None
        password_file = None
        force = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--password':
                password = a

            elif o == '--password-file':
                password_file = a

            elif o == '--force':
                force = True

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: unknown option: %s' % o)
                self.print_help()
                sys.exit(1)

        instance = pki.server.instance.PKIServerFactory.create(instance_name)

        if not instance.is_valid():
            raise Exception('Invalid instance: %s' % instance_name)

        if password_file is not None:
            with open(password_file) as f:
                password = f.read().splitlines()[0]

        elif password is None:
            password = getpass.getpass(prompt='Enter password for NSS database: ')

        instance.load()

        instance.passwords['internal'] = password
        instance.store_passwords()

        instance.create_nssdb(force=force)


class NSSRemoveCLI(pki.cli.CLI):

    def __init__(self):
        super(NSSRemoveCLI, self).__init__(
            'remove', 'Remove NSS database in PKI server')

    def print_help(self):
        print('Usage: pki-server nss-remove [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --force                        Force creation.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:d:v', [
                'instance=',
                'password=', 'password-file=', 'force',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: %s' % e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        force = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--force':
                force = True

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: unknown option: %s' % o)
                self.print_help()
                sys.exit(1)

        instance = pki.server.instance.PKIServerFactory.create(instance_name)

        if not instance.is_valid():
            raise Exception('Invalid instance: %s' % instance_name)

        if not force:
            value = pki.util.read_text(
                'Are you sure (Yes/No)',
                options=['Y', 'N'], default='N',
                delimiter='?', case_sensitive=False).lower()

            if value != 'y':
                return

        instance.remove_nssdb(force=force)
