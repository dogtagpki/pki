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

import pki.cli
import pki.server as server

SELFTEST_CRITICAL = 'critical'


class SelfTestCLI(pki.cli.CLI):
    def __init__(self):
        super(SelfTestCLI, self).__init__('selftest',
                                          'Selftest management commands')
        self.add_module(EnableSelfTestCLI())
        self.add_module(DisableSelftestCLI())

    @staticmethod
    def set_test_level(instance,
                       subsystem, test, test_level=None):

        target_subsystems = []

        # Load subsystem or subsystems
        if not subsystem:
            for subsys in instance.subsystems:
                target_subsystems.append(subsys)
        else:
            target_subsystems.append(instance.get_subsystem(subsystem))

        for subsys in target_subsystems:
            target_tests = subsys.get_startup_tests()
            # Change the test level to critical
            if test:
                if test not in target_tests:
                    raise Exception('No such self test available for %s' % subsystem)
                target_tests[test] = test_level == SELFTEST_CRITICAL
            else:
                for testID in target_tests:
                    target_tests[testID] = test_level == SELFTEST_CRITICAL

            subsys.set_startup_tests(target_tests)
            # save the CS.cfg
            subsys.save()


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

        subsystem = None
        test = None
        instance_name = 'pki-tomcat'

        if len(args) == 1:
            test = args[0]

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--subsystem':
                subsystem = a

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

        SelfTestCLI.set_test_level(test_level=SELFTEST_CRITICAL, instance=instance,
                                   subsystem=subsystem, test=test)


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

        subsystem = None
        test = None
        instance_name = 'pki-tomcat'

        if len(args) == 1:
            test = args[0]

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--subsystem':
                subsystem = a

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

        SelfTestCLI.set_test_level(instance=instance,
                                   subsystem=subsystem, test=test)
