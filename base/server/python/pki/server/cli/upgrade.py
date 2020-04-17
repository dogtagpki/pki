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
# Copyright (C) 2013 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
from __future__ import print_function
import getopt
import logging
import sys

import pki.cli
import pki.upgrade
import pki.server.upgrade

logger = logging.getLogger(__name__)


class UpgradeCLI(pki.cli.CLI):

    def __init__(self):
        super(UpgradeCLI, self).__init__('upgrade', 'Upgrade PKI server')

    def usage(self):
        print('Usage: pki-server upgrade [OPTIONS] [<instance ID>]')
        print()
        print('  --status                       Show upgrade status only. Do not perform upgrade.')
        print('  --revert                       Revert the last version.')
        print('  --validate                     Validate upgrade status.')
        print()
        print('  -i, --instance <instance>      Upgrade a specific instance only.')
        print()
        print('  -X                             Show advanced options.')
        print('  -v, --verbose                  Run in verbose mode.')
        print('      --debug                    Run in debug mode.')
        print('  -h, --help                     Show this help message.')

    def advancedOptions(self):
        print()
        print('WARNING: These options may render the system unusable.')
        print()
        print('  --remove-tracker               Remove tracker.')
        print('  --reset-tracker                Reset tracker to match package version.')
        print('  --set-tracker <version>        Set tracker to a specific version.')

    def execute(self, argv):

        try:
            opts, args = getopt.getopt(argv, 'hi:s:t:vX', [
                'instance=',
                'status', 'revert', 'validate',
                'remove-tracker', 'reset-tracker', 'set-tracker=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.usage()
            sys.exit(1)

        instance_name = None

        status = False
        revert = False
        validate = False

        remove_tracker = False
        reset_tracker = False

        tracker_version = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--status':
                status = True

            elif o == '--revert':
                revert = True

            elif o == '--validate':
                validate = True

            elif o == '--remove-tracker':
                remove_tracker = True

            elif o == '--reset-tracker':
                reset_tracker = True

            elif o == '--set-tracker':
                tracker_version = pki.util.Version(a)

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-h', '--help'):
                self.usage()
                sys.exit()

            elif o == '-X':
                self.usage()
                self.advancedOptions()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.usage()
                sys.exit(1)

        if len(args) > 0:
            instance_name = args[0]

        if instance_name:
            instance = pki.server.instance.PKIInstance(instance_name)

            if not instance.exists():
                raise Exception('Invalid instance: %s' % instance_name)

            instance.load()
            instances = [instance]

        else:
            instances = pki.server.instance.PKIInstance.instances()

        for instance in instances:
            self.upgrade(
                instance,
                status,
                revert,
                validate,
                remove_tracker,
                reset_tracker,
                tracker_version)

    def upgrade(self, instance, status, revert, validate,
                remove_tracker, reset_tracker, tracker_version):

        upgrader = pki.server.upgrade.PKIServerUpgrader(instance=instance)

        if status:
            upgrader.status()

        elif revert:
            upgrader.revert()

        elif validate:
            upgrader.validate()

        elif remove_tracker:
            upgrader.remove_tracker()

        elif reset_tracker:
            upgrader.reset_tracker()

        elif tracker_version is not None:
            upgrader.set_tracker(tracker_version)

        else:
            logger.info('Upgrading PKI server %s', instance)
            upgrader.upgrade()
