#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import argparse
import logging

import pki.cli

logger = logging.getLogger(__name__)


class GroupCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'group', '%s group management commands' % parent.name.upper())

        self.parent = parent
        self.add_module(GroupAddCLI(self))
        self.add_module(GroupFindCLI(self))
        self.add_module(GroupMemberCLI(self))


class GroupAddCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'add',
            'Add group to %s' % parent.parent.name.upper())

        self.parent = parent

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--description')
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
            'group_id',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server %s-group-add [OPTIONS] <group ID>' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --description <description>    Group decsription.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()


class GroupFindCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'find',
            'Find %s groups' % parent.parent.name.upper())

        self.parent = parent

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--member')
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
        print('Usage: pki-server %s-group-find [OPTIONS]' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --member <ID>                  Member ID')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()


class GroupMemberCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'member', '%s group member management commands' % parent.name.upper())

        self.parent = parent
        self.add_module(GroupMemberFindCLI(self))
        self.add_module(GroupMemberAddCLI(self))
        self.add_module(GroupMemberRemoveCLI(self))


class GroupMemberFindCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'find',
            'Find %s group members' % parent.parent.parent.name.upper())

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
            'group_id',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server %s-group-member-find [OPTIONS] <group ID>'
              % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()


class GroupMemberAddCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'add',
            'Add %s group member' % parent.parent.parent.name.upper())

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
            'group_id',
            nargs='?')
        self.parser.add_argument(
            'member_id',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server %s-group-member-add [OPTIONS] <group ID> <member ID>'
              % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()


class GroupMemberRemoveCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'del',
            'Remove %s group member' % parent.parent.parent.name.upper())

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
            'group_id',
            nargs='?')
        self.parser.add_argument(
            'member_id',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server %s-group-member-del [OPTIONS] <group ID> <member ID>'
              % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()
