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

import argparse
import logging
import sys

import pki.cli

logger = logging.getLogger(__name__)


class SubsystemConfigCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('config', '%s configuration management commands' % parent.name.upper())

        self.parent = parent
        self.add_module(SubsystemConfigFindCLI(self))
        self.add_module(SubsystemConfigShowCLI(self))
        self.add_module(SubsystemConfigSetCLI(self))
        self.add_module(SubsystemConfigUnsetCLI(self))


class SubsystemConfigFindCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('find', 'Find %s configuration parameters' % parent.parent.name.upper())

        self.parent = parent

    def create_parser(self):

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
        print('Usage: pki-server %s-config-find [OPTIONS]' % self.parent.parent.name)
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
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No such subsystem: %s', subsystem_name.upper())
            sys.exit(1)

        for name, value in subsystem.config.items():
            print('%s=%s' % (name, value))


class SubsystemConfigShowCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'show',
            'Show %s configuration parameter value' % parent.parent.name.upper())

        self.parent = parent

    def create_parser(self):

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
        self.parser.add_argument('name')

    def print_help(self):
        print('Usage: pki-server %s-config-show [OPTIONS] <name>' % self.parent.parent.name)
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
        name = args.name

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No such subsystem: %s', subsystem_name.upper())
            sys.exit(1)

        if name in subsystem.config:
            value = subsystem.config[name]
            print(value)

        else:
            logger.error('No such parameter: %s', name)
            sys.exit(1)


class SubsystemConfigSetCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'set',
            'Set %s configuration parameter value' % parent.parent.name.upper())

        self.parent = parent

    def create_parser(self):

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
        self.parser.add_argument('name')
        self.parser.add_argument('value')

    def print_help(self):
        print('Usage: pki-server %s-config-set [OPTIONS] <name> <value>'
              % self.parent.parent.name)
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
        name = args.name
        value = args.value

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No such subsystem: %s', subsystem_name.upper())
            sys.exit(1)

        subsystem.set_config(name, value)
        subsystem.save()


class SubsystemConfigUnsetCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('unset', 'Unset %s configuration parameter' % parent.parent.name.upper())

        self.parent = parent

    def create_parser(self):

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
        self.parser.add_argument('name')

    def print_help(self):
        print('Usage: pki-server %s-config-unset [OPTIONS] <name>'
              % self.parent.parent.name)
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
        name = args.name

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No such subsystem: %s', subsystem_name.upper())
            sys.exit(1)

        subsystem.config.pop(name, None)
        subsystem.save()
