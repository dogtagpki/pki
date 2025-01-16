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

import argparse
import getpass
import logging

import pki.cli


class NSSCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('nss', 'NSS management commands')

        self.add_module(NSSCreateCLI())
        self.add_module(NSSRemoveCLI())


class NSSCreateCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('create', 'Create NSS database in PKI server')

    def create_parser(self):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--no-password',
            action='store_true')
        self.parser.add_argument('--password')
        self.parser.add_argument('--password-file')
        self.parser.add_argument(
            '--force',
            action='store_true')
        self.parser.add_argument(
            '-v',
            '--verbose',
            action='store_true')
        self.parser.add_argument(
            '--debug',
            action='store_true')
        self.parser.add_argument(
            '--help',
            action='store_true')

    def print_help(self):
        print('Usage: pki-server nss-create [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --no-password                  Without NSS database password.')
        print('      --password <password>          NSS database password.')
        print('      --password-file <path>         NSS database password file.')
        print('      --force                        Force creation.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv, args=None):

        if not args:
            args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        instance_name = args.instance
        no_password = args.no_password
        password = args.password
        password_file = None
        force = args.force

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        if no_password:
            password = ''

        elif password is not None:
            pass

        elif password_file is not None:
            with open(password_file, encoding='utf-8') as f:
                password = f.read().splitlines()[0]

        else:
            password = getpass.getpass(prompt='Enter password for NSS database: ')

        instance.passwords['internal'] = password
        instance.store_passwords()

        instance.create_nssdb(force=force)


class NSSRemoveCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('remove', 'Remove NSS database in PKI server')

    def create_parser(self):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--force',
            action='store_true')
        self.parser.add_argument(
            '-v',
            '--verbose',
            action='store_true')
        self.parser.add_argument(
            '--debug',
            action='store_true')
        self.parser.add_argument(
            '--help',
            action='store_true')

    def print_help(self):
        print('Usage: pki-server nss-remove [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --force                        Force removal.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv, args=None):

        if not args:
            args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        instance_name = args.instance
        force = args.force

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        if not force:
            value = pki.util.read_text(
                'Are you sure (Yes/No)',
                options=['Y', 'N'], default='N',
                delimiter='?', case_sensitive=False).lower()

            if value != 'y':
                return

        instance.remove_nssdb(force=force)
