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

    def print_help(self):
        print('Usage: pki-server %s-id-generator-show [OPTIONS]' %
              self.parent.parent.parent.name)
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
        subsystem_name = self.parent.parent.parent.name

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

    def print_help(self):
        print('Usage: pki-server %s-id-generator-update [OPTIONS] <object>' %
              self.parent.parent.parent.name)
        print()
        print('  <object>                           Element to apply the generator (e.g. cert).')
        print('  -t, --type <generator type>        Type of generator to use (e.g. random).')
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, args = getopt.gnu_getopt(argv, 'i:t:v', [
                'instance=', 'type=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        if len(args) != 1:
            logger.error('Missing object for generator')
            self.print_help()
            sys.exit(1)

        generator_object = args[0]
        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.parent.name
        generator = None

        for o, a in opts:
            if o in ('-t', '--type'):
                generator = a

            elif o in ('-i', '--instance'):
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

        subsystem.update_id_generator(generator, generator_object)
