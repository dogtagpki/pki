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


class RangeCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'range',
            '%s range configuration management commands' % parent.name.upper())

        self.parent = parent
        self.add_module(RangeShowCLI(self))
        self.add_module(RangeRequestCLI(self))
        self.add_module(RangeUpdateCLI(self))


class RangeShowCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('show', 'Display %s range configuration' % parent.parent.name.upper())

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
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
        print('Usage: pki-server %s-range-show [OPTIONS]' % self.parent.parent.name)
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
        subsystem_name = self.parent.parent.name

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        print('  Begin request ID: %s' % subsystem.config.get('dbs.beginRequestNumber'))
        print('  End request ID: %s' % subsystem.config.get('dbs.endRequestNumber'))

        print('  Begin serial number: %s' % subsystem.config.get('dbs.beginSerialNumber'))
        print('  End serial number: %s' % subsystem.config.get('dbs.endSerialNumber'))

        print('  Begin replica ID: %s' % subsystem.config.get('dbs.beginReplicaNumber'))
        print('  End replica ID: %s' % subsystem.config.get('dbs.endReplicaNumber'))

        print('  Enable serial management: %s' %
              subsystem.config.get('dbs.enableSerialManagement'))


class RangeRequestCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('request', 'Request ranges from %s master' % parent.parent.name.upper())

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--master')
        self.parser.add_argument('--session')
        self.parser.add_argument('--install-token')
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
        print('Usage: pki-server %s-range-request [OPTIONS]' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --master <URL>                 Master URL.')
        print('      --session <ID>                 Session ID')
        print('      --install-token <path>         Install token')
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
        master_url = args.master
        session_id = args.session
        install_token = args.install_token

        if not master_url:
            raise Exception('Missing master URL')

        if not session_id and not install_token:
            raise Exception('Missing session ID or install token')

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.request_ranges(
            master_url,
            session_id=session_id,
            install_token=install_token)


class RangeUpdateCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('update', 'Update %s ranges' % parent.parent.name.upper())

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
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
        print('Usage: pki-server %s-range-update [OPTIONS]' % self.parent.parent.name)
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
        subsystem_name = self.parent.parent.name

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.update_ranges()
