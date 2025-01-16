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

import argparse
import sys
import logging

import pki.cli
import pki.server


class SelfTestCLI(pki.cli.CLI):
    def __init__(self):
        super().__init__('selftest', 'Selftest management commands')
        self.add_module(EnableSelfTestCLI())
        self.add_module(DisableSelftestCLI())


class EnableSelfTestCLI(pki.cli.CLI):
    def __init__(self):
        super().__init__('enable', 'Enable selftests.')

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--subsystem',
            action='append')
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
            'selftest_id',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server selftest-enable [OPTIONS] [<Selftest ID>]')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  --subsystem <subsystem name>    Subsystem Name.')
        print('  --help                          Show help message.')
        print()

    def execute(self, argv, args=None):

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
        subsystem_names = args.subsystem
        test = args.selftest_id

        # Load instance
        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        # To hold the instance of the loaded subsystems
        target_subsystems = []

        # Load subsystem or subsystems
        if not subsystem_names:
            for subsys in instance.get_subsystems():
                target_subsystems.append(subsys)
        else:
            for subsys in subsystem_names:
                target_subsystems.append(instance.get_subsystem(subsys))

        try:
            # Enable critical tests for all subsystems listed in target_subsystems
            for subsys in target_subsystems:
                subsys.set_startup_test_criticality(test=test, critical=True)
                # Save the updated CS.cfg to disk
                subsys.save()

        except pki.server.PKIServerException as e:
            logging.error(str(e))
            sys.exit(1)


class DisableSelftestCLI(pki.cli.CLI):
    def __init__(self):
        super().__init__('disable', 'Disable selftests.')

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--subsystem',
            action='append')
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
            'selftest_id',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server selftest-disable [OPTIONS] [<Selftest ID>]')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  --subsystem <subsystem name>    Subsystem Name.')
        print('  --help                          Show help message.')
        print()

    def execute(self, argv, args=None):

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
        subsystem_names = args.subsystem
        test = args.selftest_id

        # Load instance
        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        # To hold the instance of the loaded subsystems
        target_subsystems = []

        # Load subsystem or subsystems
        if not subsystem_names:
            for subsys in instance.get_subsystems():
                target_subsystems.append(subsys)
        else:
            for subsys in subsystem_names:
                target_subsystems.append(instance.get_subsystem(subsys))

        try:
            # Disable critical tests for all subsystems listed in target_subsystems
            for subsys in target_subsystems:
                subsys.set_startup_test_criticality(test=test, critical=False)
                # Save the updated CS.cfg to disk
                subsys.save()

        except pki.server.PKIServerException as e:
            logging.error(str(e))
            sys.exit(1)
