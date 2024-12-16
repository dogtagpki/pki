#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import argparse
import logging
import sys

import pki.cli
import pki.server

logger = logging.getLogger(__name__)


class SDCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('sd', 'Security domain management commands')

        self.add_module(SDCreateCLI())
        self.add_module(SDSubsystemCLI())


class SDCreateCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('create', 'Create security domain')

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--name')
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
        print('Usage: pki-server sd-create [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --name <name>                  Security domain name')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

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

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        subsystem.create_security_domain(name=name)


class SDSubsystemCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('subsystem', 'Security domain subsystem management commands')

        self.add_module(SDSubsystemFindCLI())
        self.add_module(SDSubsystemAddCLI())
        self.add_module(SDSubsystemRemoveCLI())


class SDSubsystemFindCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('find', 'Find security domain subsystems')

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
        print('Usage: pki-server sd-subsystem-find [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

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

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        subsystem.display_security_domain_subsystems()


class SDSubsystemAddCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('add', 'Add security domain subsystem')

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--subsystem')
        self.parser.add_argument('--hostname')
        self.parser.add_argument('--unsecure-port')
        self.parser.add_argument(
            '--secure-port',
            default='8443')
        self.parser.add_argument(
            '--domain-manager',
            action='store_true')
        self.parser.add_argument(
            '--clone',
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
        self.parser.add_argument('subsystem_id')

    def print_help(self):
        print('Usage: pki-server sd-subsystem-add [OPTIONS] <subsystem ID>')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --subsystem <type>             Subsystem type')
        print('      --hostname <hostname>          Hostname')
        print('      --unsecure-port <port>         Unsecure port')
        print('      --secure-port <port>           Secure port (default: 8443)')
        print('      --domain-manager               Domain manager')
        print('      --clone                        Clone')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        instance_name = args.instance
        subsystem_type = args.subsystem
        hostname = args.hostname
        unsecure_port = args.unsecure_port
        secure_port = args.secure_port
        domain_manager = args.domain_manager
        clone = args.clone
        subsystem_id = args.subsystem_id

        if not subsystem_type:
            logger.error('Missing subsystem type')
            self.print_help()
            sys.exit(1)

        if not hostname:
            logger.error('Missing hostname')
            self.print_help()
            sys.exit(1)

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        subsystem.add_security_domain_subsystem(
            subsystem_id,
            subsystem_type,
            hostname,
            unsecure_port=unsecure_port,
            secure_port=secure_port,
            domain_manager=domain_manager,
            clone=clone)


class SDSubsystemRemoveCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('del', 'Remove security domain subsystem')

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
        self.parser.add_argument('subsystem_id')

    def print_help(self):
        print('Usage: pki-server sd-subsystem-del [OPTIONS] <subsystem ID>')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        instance_name = args.instance
        subsystem_id = args.subsystem_id

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        subsystem.remove_security_domain_subsystem(subsystem_id)
