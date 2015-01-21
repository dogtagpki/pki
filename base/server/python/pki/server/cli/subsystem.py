#!/usr/bin/python
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
# Copyright (C) 2015 Red Hat, Inc.
# All rights reserved.
#

import getopt
import os
import sys

import pki.cli
import pki.server


class SubsystemCLI(pki.cli.CLI):

    def __init__(self):
        super(SubsystemCLI, self).__init__('subsystem', 'Subsystem management commands')

        self.add_module(SubsystemDisableCLI())
        self.add_module(SubsystemEnableCLI())
        self.add_module(SubsystemFindCLI())
        self.add_module(SubsystemShowCLI())

    @staticmethod
    def print_subsystem(subsystem):
        print '  Subsystem ID: %s' % subsystem.name
        print '  Instance ID: %s' % subsystem.instance.name
        print '  Enabled: %s' % subsystem.is_enabled()


class SubsystemFindCLI(pki.cli.CLI):

    def __init__(self):
        super(SubsystemFindCLI, self).__init__('find', 'Find subsystems')

    def usage(self):
        print 'Usage: pki-server subsystem-find [OPTIONS]'
        print
        print '  -i, --instance <instance ID>    Instance ID.'
        print '  -v, --verbose                   Run in verbose mode.'
        print '      --help                      Show help message.'
        print

    def execute(self, args):

        try:
            opts, _ = getopt.getopt(args, 'i:v', [
                'instance=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print 'ERROR: ' + str(e)
            self.usage()
            sys.exit(1)

        instance_name = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print 'ERROR: unknown option ' + o
                self.usage()
                sys.exit(1)

        if not instance_name:
            print 'ERROR: missing instance ID'
            self.usage()
            sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)
        instance.load()

        results = []

        for name in os.listdir(instance.base_dir):

            subsystem = pki.server.PKISubsystem(instance, name)
            if not subsystem.is_valid():
                continue

            results.append(subsystem)

        self.print_message('%s entries matched' % len(results))

        first = True
        for subsystem in results:
            if first:
                first = False
            else:
                print

            SubsystemCLI.print_subsystem(subsystem)


class SubsystemShowCLI(pki.cli.CLI):

    def __init__(self):
        super(SubsystemShowCLI, self).__init__('show', 'Show subsystem')

    def usage(self):
        print 'Usage: pki-server subsystem-show [OPTIONS] <subsystem ID>'
        print
        print '  -i, --instance <instance ID>    Instance ID.'
        print '  -v, --verbose                   Run in verbose mode.'
        print '      --help                      Show help message.'
        print

    def execute(self, argv):

        try:
            opts, args = getopt.getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print 'ERROR: ' + str(e)
            self.usage()
            sys.exit(1)

        if len(args) != 1:
            print 'ERROR: missing subsystem ID'
            self.usage()
            sys.exit(1)

        subsystem_name = args[0]
        instance_name = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print 'ERROR: unknown option ' + o
                self.usage()
                sys.exit(1)

        if not instance_name:
            print 'ERROR: missing instance ID'
            self.usage()
            sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)
        instance.load()

        subsystem = pki.server.PKISubsystem(instance, subsystem_name)

        SubsystemCLI.print_subsystem(subsystem)


class SubsystemEnableCLI(pki.cli.CLI):

    def __init__(self):
        super(SubsystemEnableCLI, self).__init__('enable', 'Enable subsystem')

    def usage(self):
        print 'Usage: pki-server subsystem-enable [OPTIONS] <subsystem ID>'
        print
        print '  -i, --instance <instance ID>    Instance ID.'
        print '  -v, --verbose                   Run in verbose mode.'
        print '      --help                      Show help message.'
        print

    def execute(self, argv):

        try:
            opts, args = getopt.getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print 'ERROR: ' + str(e)
            self.usage()
            sys.exit(1)

        if len(args) != 1:
            print 'ERROR: missing subsystem ID'
            self.usage()
            sys.exit(1)

        subsystem_name = args[0]
        instance_name = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print 'ERROR: unknown option ' + o
                self.usage()
                sys.exit(1)

        if not instance_name:
            print 'ERROR: missing instance ID'
            self.usage()
            sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)
        instance.load()

        subsystem = pki.server.PKISubsystem(instance, subsystem_name)
        subsystem.enable()

        self.print_message('Enabled "%s" subsystem' % subsystem_name)

        SubsystemCLI.print_subsystem(subsystem)


class SubsystemDisableCLI(pki.cli.CLI):

    def __init__(self):
        super(SubsystemDisableCLI, self).__init__('disable', 'Disable subsystem')

    def usage(self):
        print 'Usage: pki-server subsystem-disable [OPTIONS] <subsystem ID>'
        print
        print '  -i, --instance <instance ID>    Instance ID.'
        print '  -v, --verbose                   Run in verbose mode.'
        print '      --help                      Show help message.'
        print

    def execute(self, argv):

        try:
            opts, args = getopt.getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print 'ERROR: ' + str(e)
            self.usage()
            sys.exit(1)

        if len(args) != 1:
            print 'ERROR: missing subsystem ID'
            self.usage()
            sys.exit(1)

        subsystem_name = args[0]
        instance_name = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print 'ERROR: unknown option ' + o
                self.usage()
                sys.exit(1)

        if not instance_name:
            print 'ERROR: missing instance ID'
            self.usage()
            sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)
        instance.load()

        subsystem = pki.server.PKISubsystem(instance, subsystem_name)
        subsystem.disable()

        self.print_message('Disabled "%s" subsystem' % subsystem_name)

        SubsystemCLI.print_subsystem(subsystem)
