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
# Copyright (C) 2018 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import, print_function

import getopt
import logging
import sys

import pki.cli


class SubsystemConfigCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(SubsystemConfigCLI, self).__init__(
            'config', '%s configuration management commands' % parent.name.upper())

        self.parent = parent
        self.add_module(SubsystemConfigFindCLI(self))
        self.add_module(SubsystemConfigShowCLI(self))
        self.add_module(SubsystemConfigSetCLI(self))
        self.add_module(SubsystemConfigUnsetCLI(self))


class SubsystemConfigFindCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(SubsystemConfigFindCLI, self).__init__(
            'find', 'Find %s configuration parameters' % parent.parent.name.upper())
        self.parent = parent

    def print_help(self):
        print('Usage: pki-server %s-config-find [OPTIONS]' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            logging.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logging.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        instance = pki.server.instance.PKIInstance(instance_name)
        if not instance.is_valid():
            logging.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logging.error('No such subsystem: %s', subsystem_name.upper())
            sys.exit(1)

        for name, value in subsystem.config.items():
            print('%s=%s' % (name, value))


class SubsystemConfigShowCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(SubsystemConfigShowCLI, self).__init__(
            'show',
            'Show %s configuration parameter value' % parent.parent.name.upper())
        self.parent = parent

    def print_help(self):
        print('Usage: pki-server %s-config-show [OPTIONS] <name>' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            logging.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logging.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) < 1:
            logging.error('Missing %s configuration parameter name',
                          self.parent.parent.name.upper())
            self.print_help()
            sys.exit(1)

        name = args[0]

        instance = pki.server.instance.PKIInstance(instance_name)
        if not instance.is_valid():
            logging.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logging.error('No such subsystem: %s', subsystem_name.upper())
            sys.exit(1)

        if name in subsystem.config:
            value = subsystem.config[name]
            print(value)

        else:
            logging.error('No such parameter: %s', name)


class SubsystemConfigSetCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(SubsystemConfigSetCLI, self).__init__(
            'set', 'Set %s configuration parameter value' % parent.parent.name.upper())
        self.parent = parent

    def print_help(self):
        print('Usage: pki-server %s-config-set [OPTIONS] <name> <value>'
              % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            logging.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logging.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) < 1:
            logging.error('Missing %s configuration parameter name',
                          self.parent.parent.name.upper())
            self.print_help()
            sys.exit(1)

        if len(args) < 2:
            logging.error('Missing %s configuration parameter value',
                          self.parent.parent.name.upper())
            self.print_help()
            sys.exit(1)

        name = args[0]
        value = args[1]

        instance = pki.server.instance.PKIInstance(instance_name)
        if not instance.is_valid():
            logging.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logging.error('No such subsystem: %s', subsystem_name.upper())
            sys.exit(1)

        subsystem.config[name] = value
        subsystem.save()


class SubsystemConfigUnsetCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(SubsystemConfigUnsetCLI, self).__init__(
            'unset', 'Unset %s configuration parameter' % parent.parent.name.upper())
        self.parent = parent

    def print_help(self):
        print('Usage: pki-server %s-config-unset [OPTIONS] <name>'
              % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            logging.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logging.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) < 1:
            logging.error('Missing %s configuration parameter name',
                          self.parent.parent.name.upper())
            self.print_help()
            sys.exit(1)

        name = args[0]

        instance = pki.server.instance.PKIInstance(instance_name)
        if not instance.is_valid():
            logging.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logging.error('No such subsystem: %s', subsystem_name.upper())
            sys.exit(1)

        subsystem.config.pop(name, None)
        subsystem.save()
