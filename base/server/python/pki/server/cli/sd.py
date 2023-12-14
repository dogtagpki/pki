#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
from __future__ import absolute_import
from __future__ import print_function
import getopt
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

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'name=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        name = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--name':
                name = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
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

    def print_help(self):
        print('Usage: pki-server sd-subsystem-find [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
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

        subsystem.display_security_domain_subsystems()


class SDSubsystemAddCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('add', 'Add security domain subsystem')

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

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'subsystem=', 'hostname=', 'unsecure-port=', 'secure-port=',
                'domain-manager', 'clone',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_type = None
        hostname = None
        unsecure_port = None
        secure_port = '8443'
        domain_manager = False
        clone = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--subsystem':
                subsystem_type = a

            elif o == '--hostname':
                hostname = a

            elif o == '--unsecure-port':
                unsecure_port = a

            elif o == '--secure-port':
                secure_port = a

            elif o == '--domain-manager':
                domain_manager = True

            elif o == '--clone':
                clone = True

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) < 1:
            logger.error('Missing subsystem ID')
            self.print_help()
            sys.exit(1)

        subsystem_id = args[0]

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

    def print_help(self):
        print('Usage: pki-server sd-subsystem-del [OPTIONS] <subsystem ID>')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) < 1:
            logger.error('Missing subsystem ID')
            self.print_help()
            sys.exit(1)

        subsystem_id = args[0]

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
