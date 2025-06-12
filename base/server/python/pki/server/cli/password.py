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

logger = logging.getLogger(__name__)


class PasswordCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('password', 'Password management commands')

        self.add_module(PasswordFindCLI())
        self.add_module(PasswordAddCLI())
        self.add_module(PasswordRemoveCLI())
        self.add_module(PasswordSetCLI())
        self.add_module(PasswordUnsetCLI())

    @staticmethod
    def print_password(name):
        print('  Password ID: %s' % name)


class PasswordFindCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('find', 'Find passwords')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
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
        print('Usage: pki-server password-find [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
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

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        first = True

        for name in instance.passwords:

            if first:
                first = False
            else:
                print()

            PasswordCLI.print_password(name)


class PasswordAddCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('add', 'Add password', deprecated=True)

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--password')
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
        self.parser.add_argument(
            'name',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server password-add [OPTIONS] <password ID>')
        print()
        print('  -i, --instance <instance ID>              Instance ID (default: pki-tomcat).')
        print('      --password <password>                 Password.')
        print('  -v, --verbose                             Run in verbose mode.')
        print('      --debug                               Run in debug mode.')
        print('      --help                                Show help message.')
        print()

    def execute(self, argv, args=None):

        logger.warning(
            'The pki-server password-add has been deprecated. '
            'Use pki-server password-set instead.')

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
        password = args.password
        name = args.name

        if name is None:
            raise pki.cli.CLIException('Missing password ID')

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        if name in instance.passwords:
            raise Exception('Password already exists: %s' % name)

        instance.passwords[name] = password
        instance.store_passwords()


class PasswordRemoveCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('del', 'Remove password', deprecated=True)

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
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
        self.parser.add_argument(
            'name',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server password-del [OPTIONS] <password ID>')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv, args=None):

        logger.warning(
            'The pki-server password-del has been deprecated. '
            'Use pki-server password-unset instead.')

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
        name = args.name

        if name is None:
            raise pki.cli.CLIException('Missing password ID')

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        instance.passwords.pop(name)
        instance.store_passwords()


class PasswordSetCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('set', 'Set password')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--password')
        self.parser.add_argument('--password-file')
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
        self.parser.add_argument(
            'name',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server password-set [OPTIONS] <password ID>')
        print()
        print('  -i, --instance <instance ID>              Instance ID (default: pki-tomcat).')
        print('      --password <password>                 Password.')
        print('      --password-file <path>                Password file.')
        print('  -v, --verbose                             Run in verbose mode.')
        print('      --debug                               Run in debug mode.')
        print('      --help                                Show help message.')
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
        password = args.password
        password_file = args.password_file
        name = args.name

        if name is None:
            raise pki.cli.CLIException('Missing password ID')

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        if password is not None:
            pass

        elif password_file is not None:
            with open(password_file, encoding='utf-8') as f:
                password = f.read().splitlines()[0]

        else:
            password = getpass.getpass(prompt='Enter password: ')

        instance.passwords[name] = password
        instance.store_passwords()


class PasswordUnsetCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('unset', 'Unset password')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
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
        self.parser.add_argument(
            'name',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server password-unset [OPTIONS] <password ID>')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
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
        name = args.name

        if name is None:
            raise pki.cli.CLIException('Missing password ID')

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        instance.passwords.pop(name)
        instance.store_passwords()
