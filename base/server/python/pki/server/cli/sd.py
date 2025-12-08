#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import argparse
import inspect
import logging
import sys
import textwrap

import pki.cli
import pki.server

logger = logging.getLogger(__name__)


class SDCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__(
            'sd',
            'Security domain management commands',
            deprecated=True)

        self.add_module(SDCreateCLI())
        self.add_module(SDTypeCLI())
        self.add_module(SDSubsystemCLI())


class SDCreateCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__(
            'create',
            'Create security domain',
            deprecated=True)

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
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

    def execute(self, argv, args=None):

        logger.warning(
            'The pki-server sd-create has been deprecated. '
            'Use pki-server ca-sd-create instead.')

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

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        subsystem.create_security_domain(name=name)


class SDTypeCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__(
            'type',
            'Security domain subsystem type management commands',
            deprecated=True)

        self.add_module(SDTypeAddCLI())


class SDTypeAddCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__(
            'add',
            'Add subsystem type to security domain',
            deprecated=True)

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
            'subsystem_type',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server sd-type-add [OPTIONS] <subsystem_type>')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv, args=None):

        logger.warning(
            'The pki-server sd-type-add has been deprecated. '
            'Use pki-server ca-sd-type-add instead.')

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
        subsystem_type = args.subsystem_type
        if subsystem_type is None:
            raise pki.cli.CLIException('Missing type to add')

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        subsystem.add_security_domain_type(subsystem_type=subsystem_type)


class SDSubsystemCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__(
            'subsystem',
            'Security domain subsystem management commands',
            deprecated=True)

        self.add_module(SDSubsystemFindCLI())
        self.add_module(SDSubsystemAddCLI())
        self.add_module(SDSubsystemRemoveCLI())


class SDSubsystemFindCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__(
            'find',
            'Find security domain subsystems',
            deprecated=True)

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
        print('Usage: pki-server sd-subsystem-find [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv, args=None):

        logger.warning(
            'The pki-server sd-subsystem-find has been deprecated. '
            'Use pki-server ca-sd-subsystem-find instead.')

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

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        subsystem.display_security_domain_subsystems()


class SDSubsystemAddCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__(
            'add',
            'Add security domain subsystem',
            deprecated=True)

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
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
        self.parser.add_argument(
            'subsystem_id',
            nargs='?')

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

    def execute(self, argv, args=None):

        logger.warning(
            'The pki-server sd-subsystem-add has been deprecated. '
            'Use pki-server ca-sd-subsystem-add instead.')

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
        subsystem_type = args.subsystem
        hostname = args.hostname
        unsecure_port = args.unsecure_port
        secure_port = args.secure_port
        domain_manager = args.domain_manager
        clone = args.clone
        subsystem_id = args.subsystem_id

        if subsystem_id is None:
            raise pki.cli.CLIException('Missing subsystem ID')

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
        super().__init__(
            'del',
            'Remove security domain subsystem',
            deprecated=True)

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
            'subsystem_id',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server sd-subsystem-del [OPTIONS] <subsystem ID>')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv, args=None):

        logger.warning(
            'The pki-server sd-subsystem-del has been deprecated. '
            'Use pki-server ca-sd-subsystem-del instead.')

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
        subsystem_id = args.subsystem_id

        if subsystem_id is None:
            raise pki.cli.CLIException('Missing subsystem ID')

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


class SubsystemSDCLI(pki.cli.CLI):
    '''
    {subsystem} security domain management commands
    '''

    def __init__(self, parent):
        super().__init__(
            'sd',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.name.upper()))

        self.parent = parent

        self.add_module(SubsystemSDCreateCLI(self))
        self.add_module(SubsystemSDTypeCLI(self))
        self.add_module(SubsystemSDSubsystemCLI(self))


class SubsystemSDCreateCLI(pki.cli.CLI):
    '''
    Create {subsystem} security domain
    '''

    help = '''\
        Usage: pki-server {subsystem}-sd-create [OPTIONS]

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
              --name <name>                  Security domain name
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''  # noqa: E501

    def __init__(self, parent):
        super().__init__(
            'create',
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
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.name))


class SubsystemSDTypeCLI(pki.cli.CLI):
    '''
    Security domain subsystem type management commands
    '''

    def __init__(self, parent):
        super().__init__(
            'type',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.name.upper()))

        self.parent = parent

        self.add_module(SubsystemSDTypeAddCLI(self))


class SubsystemSDTypeAddCLI(pki.cli.CLI):
    '''
    Add subsystem type to {subsystem} security domain
    '''

    help = '''\
        Usage: pki-server {subsystem}-sd-type-add [OPTIONS] <subsystem_type>

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''  # noqa: E501

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
            'subsystem_type',
            nargs='?')

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.name))


class SubsystemSDSubsystemCLI(pki.cli.CLI):
    '''
    {subsystem} security domain subsystem management commands
    '''

    def __init__(self, parent):
        super().__init__(
            'subsystem',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.name.upper()))

        self.parent = parent

        self.add_module(SubsystemSDSubsystemFindCLI(self))
        self.add_module(SubsystemSDSubsystemAddCLI(self))
        self.add_module(SubsystemSDSubsystemRemoveCLI(self))


class SubsystemSDSubsystemFindCLI(pki.cli.CLI):
    '''
    Find {subsystem} security domain subsystems
    '''

    help = '''\
        Usage: pki-server {subsystem}-sd-subsystem-find [OPTIONS]

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''  # noqa: E501

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
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.name))


class SubsystemSDSubsystemAddCLI(pki.cli.CLI):
    '''
    Add {subsystem} security domain subsystem
    '''

    help = '''\
        Usage: pki-server {subsystem}-sd-subsystem-add [OPTIONS] <subsystem ID>

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
              --subsystem <type>             Subsystem type
              --hostname <hostname>          Hostname
              --unsecure-port <port>         Unsecure port
              --secure-port <port>           Secure port (default: 8443)
              --domain-manager               Domain manager
              --clone                        Clone
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''  # noqa: E501

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
        self.parser.add_argument(
            'subsystem_id',
            nargs='?')

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.name))


class SubsystemSDSubsystemRemoveCLI(pki.cli.CLI):
    '''
    Remove {subsystem} security domain subsystem
    '''

    help = '''\
        Usage: pki-server {subsystem}-sd-subsystem-del [OPTIONS] <subsystem ID>

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''  # noqa: E501

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
            'subsystem_id',
            nargs='?')

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.name))
