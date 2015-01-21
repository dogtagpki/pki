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

import sys
import collections


class CLI(object):

    def __init__(self, name, description):

        self.name = name
        self.description = description
        self.parent = None

        self.verbose = False
        self.modules = collections.OrderedDict()

    def set_verbose(self, verbose):
        self.verbose = verbose
        if self.parent:
            self.parent.set_verbose(verbose)

    def get_full_name(self):
        if self.parent:
            return self.parent.get_full_module_name(self.name)
        return self.name

    def get_full_module_name(self, module_name):
        return self.get_full_name() + '-' + module_name

    def add_module(self, module):
        self.modules[module.name] = module
        module.parent = self

    def get_module(self, name):
        return self.modules.get(name)

    def print_message(self, message):
        print '-' * len(message)
        print message
        print '-' * len(message)

    def print_help(self):

        print 'Commands:'

        for module in self.modules.itervalues():
            full_name = module.get_full_name()
            print ' {:30}{:30}'.format(full_name, module.description)

    def init(self):
        pass

    def execute(self, args):

        if len(args) == 0:
            self.print_help()
            sys.exit()

        # A command consists of parts joined by dashes: <part 1>-<part 2>-...-<part N>.
        # For example: cert-request-find
        command = args[0]

        # The command will be split into module name and sub command, for example:
        #  - module name: cert
        #  - sub command: request-find
        module_name = None
        sub_command = None

        # Search the module by incrementally adding parts into module name.
        # Repeat until it finds the module or until there is no more parts to add.
        module = None
        position = 0

        while True:

            # Find the next dash.
            i = command.find('-', position)
            if i >= 0:
                # Dash found. Split command into module name and sub command.
                module_name = command[0:i]
                sub_command = command[i+1:]
            else:
                # Dash not found. Use the whole command.
                module_name = command
                sub_command = None

            if self.verbose:
                print 'Module: %s' % module_name

            m = self.get_module(module_name)
            if m:
                # Module found. Check sub command.
                if not sub_command:
                    # No sub command. Use this module.
                    module = m
                    break

                # There is a sub command. It must be processed by module's children.
                if len(m.modules) > 0:
                    # Module has children. Use this module.
                    module = m
                    break

                # Module doesn't have children. Keep looking.

            # If there's no more dashes, stop.
            if i<0:
                break

            position = i + 1

        if not module:
            raise Exception('Invalid module "%s".' % self.get_full_module_name(module_name))

        # Prepare module arguments.
        if sub_command:
            # If module command exists, include it as arguments: <module command> <args>...
            module_args = [sub_command] + args[1:]

        else:
            # Otherwise, pass the original arguments: <args>...
            module_args = args[1:]

        module.init()
        module.execute(module_args)
