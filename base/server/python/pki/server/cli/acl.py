#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import argparse
import logging
import sys

import pki.cli

logger = logging.getLogger(__name__)


class SubsystemACLCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'acl', '%s ACL management commands' % parent.name.upper())

        self.parent = parent
        self.add_module(SubsystemACLFindCLI(self))
        self.add_module(SubsystemACLAddCLI(self))
        self.add_module(SubsystemACLDeleteCLI(self))


class SubsystemACLFindCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(SubsystemACLFindCLI, self).__init__(
            'find',
            'Find %s ACLs' % parent.parent.name.upper())

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
            '--as-current-user',
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
        print('Usage: pki-server %s-acl-find [OPTIONS]' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --as-current-user              Run as current user.')
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
        subsystem_name = self.parent.parent.name
        as_current_user = args.as_current_user

        instance = pki.server.instance.PKIInstance(instance_name)

        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.find_acl(as_current_user=as_current_user)


class SubsystemACLAddCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(SubsystemACLAddCLI, self).__init__(
            'add',
            'Add %s ACL' % parent.parent.name.upper())

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
            '--as-current-user',
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
            'acl',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server %s-acl-add [OPTIONS] <acl>' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --as-current-user              Run as current user.')
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
        subsystem_name = self.parent.parent.name
        as_current_user = args.as_current_user
        acl = args.acl
        instance = pki.server.instance.PKIInstance(instance_name)

        if acl is None:
            raise pki.cli.CLIException('Missing ACL')

        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.add_acl(acl, as_current_user=as_current_user)


class SubsystemACLDeleteCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(SubsystemACLDeleteCLI, self).__init__(
            'del',
            'Delete %s ACL' % parent.parent.name.upper())

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
            '--as-current-user',
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
            'acl',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server %s-acl-del [OPTIONS] <acl>' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --as-current-user              Run as current user.')
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
        subsystem_name = self.parent.parent.name
        as_current_user = args.as_current_user
        acl = args.acl
        instance = pki.server.instance.PKIInstance(instance_name)

        if acl is None:
            raise pki.cli.CLIException('Missing ACL')

        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.delete_acl(acl, as_current_user=as_current_user)
