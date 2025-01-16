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
# Copyright (C) 2019 Red Hat, Inc.
# All rights reserved.
#

import logging

import pki.cli


class ListenerCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('listener', 'Listener management commands')

        self.add_module(ListenerFindCLI())

    @staticmethod
    def print_listener(listener_name, listener):

        print('  Listener ID: %s' % listener_name)

        for name, value in listener.items():
            print('  %s: %s' % (name, value))


class ListenerFindCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('find', 'Find listeners')

    def create_parser(self, subparsers=None):

        self.parser = subparsers.add_parser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
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

    def print_help(self):
        print('Usage: pki-server listener-find [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
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

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        server_config = instance.get_server_config()

        first = True
        counter = 0

        for listener in server_config.get_listeners():

            if first:
                first = False
            else:
                print()

            counter += 1
            listener_name = 'Listener%d' % counter
            ListenerCLI.print_listener(listener_name, listener)
