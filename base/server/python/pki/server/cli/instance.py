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


class InstanceCLI(pki.cli.CLI):

    def __init__(self):
        super(InstanceCLI, self).__init__('instance', 'Instance management commands')

        self.add_module(InstanceFindCLI())
        self.add_module(InstanceShowCLI())
        self.add_module(InstanceStartCLI())
        self.add_module(InstanceStopCLI())
        self.add_module(InstanceMigrateCLI())

    @staticmethod
    def print_instance(instance):
        print '  Instance ID: %s' % instance.name
        print '  Active: %s' % instance.is_active()


class InstanceFindCLI(pki.cli.CLI):

    def __init__(self):
        super(InstanceFindCLI, self).__init__('find', 'Find instances')

    def print_help(self):
        print 'Usage: pki-server instance-find [OPTIONS]'
        print
        print '  -v, --verbose                Run in verbose mode.'
        print '      --help                   Show help message.'
        print

    def execute(self, argv):

        try:
            opts, _ = getopt.getopt(argv, 'i:v', [
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print 'ERROR: ' + str(e)
            self.print_help()
            sys.exit(1)

        for o, _ in opts:
            if o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print 'ERROR: unknown option ' + o
                self.print_help()
                sys.exit(1)

        results = []
        if os.path.exists(pki.server.INSTANCE_BASE_DIR):
            for f in os.listdir(pki.server.INSTANCE_BASE_DIR):

                if not os.path.isdir:
                    continue

                results.append(f)

        self.print_message('%s entries matched' % len(results))

        first = True
        for instance_name in results:
            if first:
                first = False
            else:
                print

            instance = pki.server.PKIInstance(instance_name)
            instance.load()

            InstanceCLI.print_instance(instance)


class InstanceShowCLI(pki.cli.CLI):

    def __init__(self):
        super(InstanceShowCLI, self).__init__('show', 'Show instance')

    def print_help(self):
        print 'Usage: pki-server instance-show [OPTIONS] <instance ID>'
        print
        print '  -v, --verbose                Run in verbose mode.'
        print '      --help                   Show help message.'
        print

    def execute(self, argv):

        try:
            opts, args = getopt.getopt(argv, 'i:v', [
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print 'ERROR: ' + str(e)
            self.print_help()
            sys.exit(1)

        if len(args) != 1:
            print 'ERROR: missing instance ID'
            self.print_help()
            sys.exit(1)

        instance_name = args[0]

        for o, _ in opts:
            if o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print 'ERROR: unknown option ' + o
                self.print_help()
                sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)
        instance.load()

        InstanceCLI.print_instance(instance)


class InstanceStartCLI(pki.cli.CLI):

    def __init__(self):
        super(InstanceStartCLI, self).__init__('start', 'Start instance')

    def print_help(self):
        print 'Usage: pki-server instance-start [OPTIONS] <instance ID>'
        print
        print '  -v, --verbose                Run in verbose mode.'
        print '      --help                   Show help message.'
        print

    def execute(self, argv):

        try:
            opts, args = getopt.getopt(argv, 'i:v', [
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print 'ERROR: ' + str(e)
            self.print_help()
            sys.exit(1)

        if len(args) != 1:
            print 'ERROR: missing instance ID'
            self.print_help()
            sys.exit(1)

        instance_name = args[0]

        for o, _ in opts:
            if o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print 'ERROR: unknown option ' + o
                self.print_help()
                sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)
        instance.load()
        instance.start()

        self.print_message('%s instance started' % instance_name)


class InstanceStopCLI(pki.cli.CLI):

    def __init__(self):
        super(InstanceStopCLI, self).__init__('stop', 'Stop instance')

    def print_help(self):
        print 'Usage: pki-server instance-stop [OPTIONS] <instance ID>'
        print
        print '  -v, --verbose                Run in verbose mode.'
        print '      --help                   Show help message.'
        print

    def execute(self, argv):

        try:
            opts, args = getopt.getopt(argv, 'i:v', [
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print 'ERROR: ' + str(e)
            self.print_help()
            sys.exit(1)

        if len(args) != 1:
            print 'ERROR: missing instance ID'
            self.print_help()
            sys.exit(1)

        instance_name = args[0]

        for o, _ in opts:
            if o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print 'ERROR: unknown option ' + o
                self.print_help()
                sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)
        instance.load()
        instance.stop()

        self.print_message('%s instance stopped' % instance_name)

class InstanceMigrateCLI(pki.cli.CLI):

    def __init__(self):
        super(InstanceMigrateCLI, self).__init__('migrate', 'Migrate instance')

    def print_help(self):
        print 'Usage: pki-server instance-migrate [OPTIONS] <instance ID>'
        print
        print '      --tomcat <version>       Use the specified Tomcat version.'
        print '  -v, --verbose                Run in verbose mode.'
        print '      --debug                  Show debug messages.'
        print '      --help                   Show help message.'
        print

    def execute(self, argv):

        try:
            opts, args = getopt.getopt(argv, 'i:v', [
                'tomcat=', 'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            print 'ERROR: ' + str(e)
            self.print_help()
            sys.exit(1)

        if len(args) != 1:
            print 'ERROR: missing instance ID'
            self.print_help()
            sys.exit(1)

        instance_name = args[0]
        tomcat_version = None

        for o, a in opts:
            if o == '--tomcat':
                tomcat_version = a

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--debug':
                self.set_verbose(True)
                self.set_debug(True)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print 'ERROR: unknown option ' + o
                self.print_help()
                sys.exit(1)

        if not tomcat_version:
            print 'ERROR: missing Tomcat version'
            self.print_help()
            sys.exit(1)

        module = self.top.find_module('migrate')
        module.set_verbose(self.verbose)
        module.set_debug(self.debug)

        instance = pki.server.PKIInstance(instance_name)
        instance.load()

        module.migrate(instance, tomcat_version) # pylint: disable=no-member,maybe-no-member

        self.print_message('%s instance migrated' % instance_name)
