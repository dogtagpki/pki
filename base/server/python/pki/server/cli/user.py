#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import argparse
import inspect
import logging
import textwrap

import pki.cli

logger = logging.getLogger(__name__)


class UserCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('user', '%s user management commands' % parent.name.upper())

        self.parent = parent

        self.add_module(UserAddCLI(self))
        self.add_module(UserFindCLI(self))
        self.add_module(UserModifyCLI(self))
        self.add_module(UserRemoveCLI(self))
        self.add_module(UserShowCLI(self))

        self.add_module(UserCertCLI(self))
        self.add_module(UserRoleCLI(self))


class UserAddCLI(pki.cli.CLI):
    '''
    Add {subsystem} user
    '''

    help = '''\
        Usage: pki-server {subsystem}-user-add [OPTIONS] <user ID>

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
              --full-name <full name>        Full name
              --email <email>                Email
              --password <password>          Password
              --password-file <path>         Password file
              --cert <path>                  Certificate file
              --cert-format <format>         Certificate format (default: PEM)
              --phone <phone>                Phone
              --type <type>                  Type: userType, agentType, adminType, subsystemType
              --state <state>                State
              --tps-profiles <profiles>      Comma-separated TPS profiles
              --ignore-duplicate             Ignore duplicate.
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''

    def __init__(self, parent):
        super().__init__(
            'add',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.name.upper()))

        self.parent = parent

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--full-name')
        self.parser.add_argument('--email')
        self.parser.add_argument('--password')
        self.parser.add_argument('--password-file')
        self.parser.add_argument('--cert')
        self.parser.add_argument('--cert-format')
        self.parser.add_argument('--phone')
        self.parser.add_argument('--type')
        self.parser.add_argument('--state')
        self.parser.add_argument('--tps-profiles')
        self.parser.add_argument(
            '--ignore-duplicate',
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
        self.parser.add_argument(
            'user_id',
            nargs='?')

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.name))


class UserFindCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('find', 'Find %s users' % parent.parent.name.upper())

        self.parent = parent

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--see-also')
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
        print('Usage: pki-server %s-user-find [OPTIONS]' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --see-also <subject DN>        Find users linked to a certificate.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()


class UserModifyCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('mod', 'Modify %s user' % parent.parent.name.upper())

        self.parent = parent

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
            '--attr',
            action='append')
        self.parser.add_argument('--add-see-also')
        self.parser.add_argument('--del-see-also')
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
            'user_id',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server %s-user-mod [OPTIONS] <user ID>' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --password <password>          User password')
        print('      --password-file <path>         User password file')
        print('      --attr <name>=<value>          Update attribute.')
        print('      --add-see-also <subject DN>    Link user to a certificate.')
        print('      --del-see-also <subject DN>    Unlink user from a certificate.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()


class UserRemoveCLI(pki.cli.CLI):
    '''
    Remove {subsystem} user
    '''

    help = '''\
        Usage: pki-server {subsystem}-user-del [OPTIONS] <user ID>

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat).
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''

    def __init__(self, parent):
        super().__init__(
            'del',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.name.upper()))

        self.parent = parent

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
            'user_id',
            nargs='?')

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.name))


class UserShowCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('show', 'Display %s user' % parent.parent.name.upper())

        self.parent = parent

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--attr',
            action='append')
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
            'user_id',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server %s-user-show [OPTIONS] <user ID>' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --attr <name>                  Show attribute.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()


class UserCertCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('cert', '%s user cert management commands' % parent.parent.name.upper())

        self.parent = parent
        self.add_module(UserCertFindCLI(self))
        self.add_module(UserCertAddCLI(self))
        self.add_module(UserCertRemoveCLI(self))


class UserCertFindCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('find', 'Find %s user certificates' % parent.parent.parent.name.upper())

        self.parent = parent

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
            'user_id',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server %s-user-cert-find [OPTIONS] <user ID>'
              % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()


class UserCertAddCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('add', 'Add %s user cert' % parent.parent.parent.name.upper())

        self.parent = parent

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--cert')
        self.parser.add_argument(
            '--format',
            default='PEM')
        self.parser.add_argument(
            '--ignore-duplicate',
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
        self.parser.add_argument(
            'user_id',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server %s-user-cert-add [OPTIONS] <user ID>'
              % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --cert <path>                  Certificate to add.')
        print('      --format <format>              Certificate format: PEM (default), DER.')
        print('      --ignore-duplicate             Ignore duplicate.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()


class UserCertRemoveCLI(pki.cli.CLI):
    '''
    Remove {subsystem} user certificate
    '''

    help = '''\
        Usage: pki-server {subsystem}-user-cert-del [OPTIONS] <user ID> <cert ID>

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat).
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''

    def __init__(self, parent):
        super().__init__(
            'del',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.parent.name.upper()))

        self.parent = parent

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
            'user_id',
            nargs='?')
        self.parser.add_argument(
            'cert_id',
            nargs='?')

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.name))


class UserRoleCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('role', '%s user role management commands' % parent.parent.name.upper())

        self.parent = parent
        self.add_module(UserRoleFindCLI(self))
        self.add_module(UserRoleAddCLI(self))
        self.add_module(UserRoleRemoveCLI(self))


class UserRoleFindCLI(pki.cli.CLI):
    '''
    Find {subsystem} user roles
    '''

    help = '''\
        Usage: pki-server {subsystem}-user-role-find [OPTIONS] <user ID>

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
              --output-format <format>       Output format: text (default), json.
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''

    def __init__(self, parent):
        super().__init__(
            'find',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.parent.name.upper()))

        self.parent = parent

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--output-format')
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
            'user_id',
            nargs='?')

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.name))


class UserRoleAddCLI(pki.cli.CLI):
    '''
    Add {subsystem} user role
    '''

    help = '''\
        Usage: pki-server {subsystem}-user-role-add [OPTIONS] <user ID> <role ID>

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''

    def __init__(self, parent):
        super().__init__(
            'add',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.parent.name.upper()))

        self.parent = parent

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
            'user_id',
            nargs='?')
        self.parser.add_argument(
            'role_id',
            nargs='?')

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.name))


class UserRoleRemoveCLI(pki.cli.CLI):
    '''
    Remove {subsystem} user role
    '''

    help = '''\
        Usage: pki-server {subsystem}-user-role-del [OPTIONS] <user ID> <role ID>

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''

    def __init__(self, parent):
        super().__init__(
            'del',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.parent.name.upper()))

        self.parent = parent

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
            'user_id',
            nargs='?')
        self.parser.add_argument(
            'role_id',
            nargs='?')

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.name))
