# Authors:
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
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
# Copyright (C) 2015-2017 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
from __future__ import print_function

import getopt
import sys
import logging

import pki.cli
import pki.server as server

logger = logging.getLogger(__name__)


class SelfTestCLI(pki.cli.CLI):
    def __init__(self):
        super(SelfTestCLI, self).__init__('selftest',
                                          'Selftest management commands')
        self.add_module(EnableSelfTestCLI())
        self.add_module(DisableSelftestCLI())


class EnableSelfTestCLI(pki.cli.CLI):
    def __init__(self):
        super(EnableSelfTestCLI, self).__init__(
            'enable', 'Enable selftests.')

    def print_help(self):
        print('Usage: pki-server selftest-enable [Selftest ID] [--subsystem <subsystem>]')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  --subsystem <subsystem name>    Subsystem Name.')
        print('  --help                          Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:', [
                'subsystem=', 'instance=', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.print_help()
            sys.exit(1)

        # To hold the subsystem names
        subsystems = []
        test = None
        instance_name = 'pki-tomcat'

        if len(args) == 1:
            test = args[0]

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--subsystem':
                subsystems.append(a)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: unknown option ' + o)
                self.print_help()
                sys.exit(1)

        # Load instance
        instance = server.PKIInstance(instance_name)

        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        # To hold the instance of the loaded subsystems
        target_subsystems = []

        # Load subsystem or subsystems
        if not subsystems:
            for subsys in instance.subsystems:
                target_subsystems.append(subsys)
        else:
            for subsys in subsystems:
                target_subsystems.append(instance.get_subsystem(subsys))

        try:
            # Enable critical tests for all subsystems listed in target_subsystems
            for subsys in target_subsystems:
                subsys.set_startup_test_criticality(test=test, critical=True)
                # Save the updated CS.cfg to disk
                subsys.save()

        except server.PKIServerException as e:
            logger.error(str(e))
            sys.exit(1)


class DisableSelftestCLI(pki.cli.CLI):
    def __init__(self):
        super(DisableSelftestCLI, self).__init__(
            'disable', 'Disable selftests.')

    def print_help(self):
        print('Usage: pki-server selftest-disable [Selftest ID] [--subsystem <subsystem>]')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  --subsystem <subsystem name>    Subsystem Name.')
        print('  --help                          Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:', [
                'subsystem=', 'instance=', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.print_help()
            sys.exit(1)

        # To hold the subsystem names
        subsystems = []
        test = None
        instance_name = 'pki-tomcat'

        if len(args) == 1:
            test = args[0]

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--subsystem':
                subsystems.append(a)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: unknown option ' + o)
                self.print_help()
                sys.exit(1)

        # Load instance
        instance = server.PKIInstance(instance_name)

        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        # To hold the instance of the loaded subsystems
        target_subsystems = []

        # Load subsystem or subsystems
        if not subsystems:
            for subsys in instance.subsystems:
                target_subsystems.append(subsys)
        else:
            for subsys in subsystems:
                target_subsystems.append(instance.get_subsystem(subsys))

        try:
            # Disable critical tests for all subsystems listed in target_subsystems
            for subsys in target_subsystems:
                subsys.set_startup_test_criticality(test=test, critical=False)
                # Save the updated CS.cfg to disk
                subsys.save()

        except server.PKIServerException as e:
            logger.error(str(e))
            sys.exit(1)
