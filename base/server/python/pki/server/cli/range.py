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
import pki.server.instance

logger = logging.getLogger(__name__)


class RangeCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(RangeCLI, self).__init__(
            'range', '%s range configuration management commands' % parent.name.upper())

        self.parent = parent
        self.add_module(RangeShowCLI(self))


class RangeShowCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(RangeShowCLI, self).__init__(
            'show',
            'Display %s range configuration' % parent.parent.name.upper())

        self.parent = parent

    def print_help(self):
        print('Usage: pki-server %s-range-show [OPTIONS]' % self.parent.parent.name)
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
        subsystem_name = self.parent.parent.name

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

        instance = pki.server.instance.PKIInstance(instance_name)
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
