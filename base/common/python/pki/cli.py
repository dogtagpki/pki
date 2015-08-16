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

from __future__ import absolute_import
from __future__ import print_function
import collections
import getopt
import sys
from six import itervalues


class CLI(object):

    def __init__(self, name, description):

        self.name = name
        self.description = description
        self.parent = None
        self.top = self

        self.verbose = False
        self.debug = False

        self.modules = collections.OrderedDict()

    def set_verbose(self, verbose):
        self.verbose = verbose
        if self.parent:
            self.parent.set_verbose(verbose)

    def set_debug(self, debug):
        self.debug = debug
        if self.parent:
            self.parent.set_debug(debug)

    def get_full_name(self):
        if self.parent:
            return self.parent.get_full_module_name(self.name)
        return self.name

    def get_full_module_name(self, module_name):
        return self.get_full_name() + '-' + module_name

    def add_module(self, module):
        self.modules[module.name] = module
        module.parent = self
        module.top = self.top

    def get_module(self, name):
        return self.modules.get(name)

    def print_message(self, message):
        print('-' * len(message))
        print(message)
        print('-' * len(message))

    def print_help(self):

        print('Commands:')

        for module in itervalues(self.modules):
            full_name = module.get_full_name()
            print(' {:30}{:30}'.format(full_name, module.description))

    def find_module(self, command):

        module = self

        while True:
            (module, command) = module.parse_command(command)

            if not module or not command:
                return module

    def parse_command(self, command):

        # A command consists of parts joined by dashes: <part 1>-<part 2>-...-<part N>.
        # For example: cert-request-find

        # The command will be split into module name and sub command, for example:
        #  - module name: cert
        #  - sub command: request-find
        module_name = None
        sub_command = None

        # Search the module by incrementally adding parts into module name.
        # Repeat until it finds the module or until there is no more parts to
        # add.
        module = None
        position = 0

        while True:

            # Find the next dash.
            i = command.find('-', position)
            if i >= 0:
                # Dash found. Split command into module name and sub command.
                module_name = command[0:i]
                sub_command = command[i + 1:]
            else:
                # Dash not found. Use the whole command.
                module_name = command
                sub_command = None

            if self.debug:
                print('Module: %s' % module_name)

            m = self.get_module(module_name)
            if m:
                # Module found. Check sub command.
                if not sub_command:
                    # No sub command. Use this module.
                    module = m
                    break

                # There is a sub command. It must be processed by module's
                # children.
                if len(m.modules) > 0:
                    # Module has children. Use this module.
                    module = m
                    break

                # Module doesn't have children. Keep looking.

            # If there's no more dashes, stop.
            if i < 0:
                break

            position = i + 1

        return (module, sub_command)

    def parse_args(self, args):

        command = args[0]
        (module, sub_command) = self.parse_command(command)

        if not module:
            raise Exception('Invalid module "%s".' % command)

        # Prepare module arguments.
        if sub_command:
            # If module command exists, include it as arguments:
            # <module command> <args>...
            module_args = [sub_command] + args[1:]

        else:
            # Otherwise, pass the original arguments: <args>...
            module_args = args[1:]

        return (module, module_args)

    def execute(self, argv):

        try:
            opts, args = getopt.getopt(argv, 'v', [
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.print_help()
            sys.exit(1)

        if len(args) == 0:
            self.print_help()
            sys.exit()

        for o, _ in opts:
            if o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: unknown option %s' % o)
                self.print_help()
                sys.exit(1)

        (module, module_args) = self.parse_args(argv)

        module.execute(module_args)
