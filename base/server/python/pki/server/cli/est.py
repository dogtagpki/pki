# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later


from __future__ import absolute_import
from __future__ import print_function
import getopt
import logging
import os
import sys

import pki.cli
import pki.server
import pki.server.instance
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

    def print_help(self):
        print('Usage: pki-server est-create [OPTIONS] [name]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --force                        Force creation.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'database=', 'issuer=',
                'force',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        name = DEFAULT_SUBSYSTEM_NAME
        instance_name = DEFAULT_INSTANCE_NAME
        force = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--force':
                force = True

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) > 0:
            name = args[0]

        instance = pki.server.instance.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        est_conf_dir = os.path.join(instance.conf_dir, name)
        instance.makedirs(est_conf_dir, force=force)


class ESTRemoveCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('remove', 'Remove EST subsystem')

    def print_help(self):
        print('Usage: pki-server est-remove [OPTIONS] [name]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --force                        Force removal.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'force',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        name = DEFAULT_SUBSYSTEM_NAME
        instance_name = DEFAULT_INSTANCE_NAME
        force = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--force':
                force = True

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) > 0:
            name = args[0]

        instance = pki.server.instance.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        est_conf_dir = os.path.join(instance.conf_dir, name)
        logger.info('Removing %s', est_conf_dir)
        pki.util.rmtree(est_conf_dir, force=force)
