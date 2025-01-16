# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later


import argparse
import logging
import os

import pki.cli
import pki.server
import pki.server.cli.subsystem

DEFAULT_SUBSYSTEM_NAME = 'est'
DEFAULT_INSTANCE_NAME = 'pki-tomcat'

logger = logging.getLogger(__name__)


class ESTCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('est', 'Manage the EST subsystem')

        self.add_module(ESTCreateCLI())
        self.add_module(ESTRemoveCLI())
        self.add_module(pki.server.cli.subsystem.SubsystemDeployCLI(self))
        self.add_module(pki.server.cli.subsystem.SubsystemUndeployCLI(self))


class ESTCreateCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('create', 'Create EST subsystem')

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default=DEFAULT_INSTANCE_NAME)
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
        self.parser.add_argument(
            'name',
            nargs='?',
            default=DEFAULT_SUBSYSTEM_NAME)

    def print_help(self):
        print('Usage: pki-server est-create [OPTIONS] [name]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
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
        name = args.name
        force = args.force

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        est_conf_dir = os.path.join(instance.conf_dir, name)
        instance.makedirs(est_conf_dir, force=force)


class ESTRemoveCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('remove', 'Remove EST subsystem')

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default=DEFAULT_INSTANCE_NAME)
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
        self.parser.add_argument(
            'name',
            nargs='?',
            default=DEFAULT_SUBSYSTEM_NAME)

    def print_help(self):
        print('Usage: pki-server est-remove [OPTIONS] [name]')
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
        name = args.name
        force = args.force

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        est_conf_dir = os.path.join(instance.conf_dir, name)
        logger.info('Removing %s', est_conf_dir)
        pki.util.rmtree(est_conf_dir, force=force)
