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
import pki.server.instance
import pki.server.upgrade


class UpgradeCLI(pki.cli.CLI):

    def __init__(self):
        super(UpgradeCLI, self).__init__('upgrade', 'Upgrade PKI server')

    def usage(self):
        print('Usage: pki-server upgrade [OPTIONS] [<instance ID>]')
        print()
        print('  --silent                       Upgrade in silent mode.')
        print('  --status                       Show upgrade status only. Do not perform upgrade.')
        print('  --revert                       Revert the last version.')
        print('  --validate                     Validate upgrade status.')
        print()
        print('  -i, --instance <instance>      Upgrade a specific instance only.')
        print('  -s, --subsystem <subsystem>    Upgrade a specific subsystem in an instance only.')
        print('  -t, --instance-type <type>     Upgrade a specific instance type.')
        print('                                 Specify 9 for PKI 9 instances, 10 for PKI 10.')
        print()
        print('  -X                             Show advanced options.')
        print('  -v, --verbose                  Run in verbose mode.')
        print('      --debug                    Run in debug mode.')
        print('  -h, --help                     Show this help message.')

    def advancedOptions(self):
        print()
        print('WARNING: These options may render the system unusable.')
        print()
        print('  --scriptlet-version <version>  Run scriptlets for a specific version only.')
        print('  --scriptlet-index <index>      Run a specific scriptlet only.')
        print()
        print('  --remove-tracker               Remove tracker.')
        print('  --reset-tracker                Reset tracker to match package version.')
        print('  --set-tracker <version>        Set tracker to a specific version.')

    def execute(self, argv):

        try:
            opts, args = getopt.getopt(argv, 'hi:s:t:vX', [
                'instance=', 'subsystem=', 'instance-type=',
                'scriptlet-version=', 'scriptlet-index=',
                'silent', 'status', 'revert', 'validate',
                'remove-tracker', 'reset-tracker', 'set-tracker=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: %s' % e)
            self.usage()
            sys.exit(1)

        instanceName = None
        subsystemName = None
        instance_version = None

        scriptlet_version = None
        scriptlet_index = None

        silent = False
        status = False
        revert = False
        validate = False

        remove_tracker = False
        reset_tracker = False

        tracker_version = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instanceName = a

            elif o in ('-s', '--subsystem'):
                subsystemName = a

            elif o in ('-t', '--instance-type'):
                instance_version = int(a)

            elif o == '--scriptlet-version':
                scriptlet_version = a

            elif o == '--scriptlet-index':
                scriptlet_index = int(a)

            elif o == '--silent':
                silent = True

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
                pki.upgrade.verbose = True
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
                print('ERROR: unknown option ' + o)
                self.usage()
                sys.exit(1)

        if len(args) > 0:
            instanceName = args[0]

        if subsystemName and not instanceName:
            print('ERROR: --subsystem requires --instance')
            self.usage()
            sys.exit(1)

        if scriptlet_index and not scriptlet_version:
            print('ERROR: --scriptlet-index requires --scriptlet-version')
            self.usage()
            sys.exit(1)

        upgrader = pki.server.upgrade.PKIServerUpgrader(
            instanceName=instanceName,
            subsystemName=subsystemName,
            instance_version=instance_version,
            version=scriptlet_version,
            index=scriptlet_index,
            silent=silent)

        if status:
            upgrader.status()

        elif revert:
            logging.info('Reverting PKI server last upgrade')
            upgrader.revert()

        elif validate:
            upgrader.validate()

        elif remove_tracker:
            logging.info('Removing PKI server upgrade tracker')
            upgrader.remove_tracker()

        elif reset_tracker:
            logging.info('Resetting PKI server upgrade tracker')
            upgrader.reset_tracker()

        elif tracker_version is not None:
            logging.info('Setting PKI server upgrade tracker')
            upgrader.set_tracker(tracker_version)

        else:
            logging.info('Upgrading PKI server')
            upgrader.upgrade()
