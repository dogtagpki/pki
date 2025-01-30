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


class IdCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'id',
            '%s id configuration management commands' % parent.name.upper())

        self.parent = parent
        self.add_module(IdGeneratorCLI(self))


class IdGeneratorCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('generator',
                         '%s id generator configuration' % parent.parent.name.upper())

        self.parent = parent
        self.add_module(IdGeneratorShowCLI(self))
        self.add_module(IdGeneratorUpdateCLI(self))


class IdGeneratorShowCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('show', 'Display %s id generator' % parent.parent.parent.name.upper())

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

    def print_help(self):
        print('Usage: pki-server %s-id-generator-show [OPTIONS]' %
              self.parent.parent.parent.name)
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
        subsystem_name = self.parent.parent.parent.name

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

        print('  Request ID generator: %s' % subsystem.config.get('dbs.request.id.generator'))
        print('  Cert ID generator: %s' % subsystem.config.get('dbs.cert.id.generator'))


class IdGeneratorUpdateCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('update', 'Update %s id generator' % parent.parent.parent.name.upper())

        self.parent = parent

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('-t', '--type')
        self.parser.add_argument('-r', '--range')
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
        self.parser.add_argument('object_name')

    def print_help(self):
        print('Usage: pki-server %s-id-generator-update [OPTIONS] <object>' %
              self.parent.parent.parent.name)
        print()
        print('  <object>                         Element to apply the generator (e.g. cert).')
        print('  -t, --type <generator type>      Type of generator to use (e.g. random).')
        print('  -r, --range <rangeTree>          Name for the new range tree if needed.')
        print('  -i, --instance <instance ID>     Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                    Run in verbose mode.')
        print('      --debug                      Run in debug mode.')
        print('      --help                       Show help message.')
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
        subsystem_name = self.parent.parent.parent.name
        generator_object = args.object_name
        generator = args.type
        range_object = args.range

        if not generator:
            logger.error('No <generator type> specified')
            self.print_help()
            sys.exit(1)

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

        subsystem.update_id_generator(generator, generator_object, range_object)
