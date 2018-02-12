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
import signal
import sys

import pki
import pki.upgrade

# pylint: disable=W0613


def interrupt_handler(event, frame):
    print()
    print()
    print('Upgrade canceled.')
    sys.exit(1)


def usage():
    print('Usage: pki-upgrade [OPTIONS]')
    print()
    print('  --silent                       Upgrade in silent mode.')
    print('  --status                       Show upgrade status only. Do not perform upgrade.')
    print('  --revert                       Revert the last version.')
    print()
    print('  -X                             Show advanced options.')
    print('  -v, --verbose                  Run in verbose mode.')
    print('  -h, --help                     Show this help message.')


def advancedOptions():
    print()
    print('WARNING: These options may render the system unusable.')
    print()
    print('  --scriptlet-version <version>  Run scriptlets for a specific version only.')
    print('  --scriptlet-index <index>      Run a specific scriptlet only.')
    print()
    print('  --remove-tracker               Remove tracker.')
    print('  --reset-tracker                Reset tracker to match package version.')
    print('  --set-tracker <version>        Set tracker to a specific version.')


def main(argv):

    signal.signal(signal.SIGINT, interrupt_handler)

    try:
        opts, _ = getopt.getopt(argv[1:], 'hi:s:t:vX', [
            'scriptlet-version=', 'scriptlet-index=',
            'silent', 'status', 'revert',
            'remove-tracker', 'reset-tracker', 'set-tracker=',
            'verbose', 'help'])

    except getopt.GetoptError as e:
        print('ERROR: ' + str(e))
        usage()
        sys.exit(1)

    scriptlet_version = None
    scriptlet_index = None

    silent = False
    status = False
    revert = False

    remove_tracker = False
    reset_tracker = False

    tracker_version = None

    for o, a in opts:
        if o == '--scriptlet-version':
            scriptlet_version = a

        elif o == '--scriptlet-index':
            scriptlet_index = int(a)

        elif o == '--silent':
            silent = True

        elif o == '--status':
            status = True

        elif o == '--revert':
            revert = True

        elif o == '--remove-tracker':
            remove_tracker = True

        elif o == '--reset-tracker':
            reset_tracker = True

        elif o == '--set-tracker':
            tracker_version = pki.upgrade.Version(a)

        elif o in ('-v', '--verbose'):
            pki.upgrade.verbose = True

        elif o in ('-h', '--help'):
            usage()
            sys.exit()

        elif o == '-X':
            usage()
            advancedOptions()
            sys.exit()

        else:
            print('ERROR: unknown option ' + o)
            usage()
            sys.exit(1)

    if scriptlet_index and not scriptlet_version:
        print('ERROR: --scriptlet-index requires --scriptlet-version')
        usage()
        sys.exit(1)

    try:
        upgrader = pki.upgrade.PKIUpgrader(
            version=scriptlet_version,
            index=scriptlet_index,
            silent=silent)

        if status:
            upgrader.status()

        elif revert:
            upgrader.revert()

        elif remove_tracker:
            upgrader.remove_tracker()

        elif reset_tracker:
            upgrader.reset_tracker()

        elif tracker_version is not None:
            upgrader.set_tracker(tracker_version)

        else:
            upgrader.upgrade()

    except pki.PKIException as e:
        print(e.message)


if __name__ == '__main__':
    main(sys.argv)
