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

from __future__ import absolute_import
from __future__ import print_function
import getopt
import logging
import sys

import pki.cli
import pki.server
import pki.server.cli.audit
import pki.server.cli.banner
import pki.server.cli.ca
import pki.server.cli.cert
import pki.server.cli.config
import pki.server.cli.db
import pki.server.cli.http
import pki.server.cli.instance
import pki.server.cli.kra
import pki.server.cli.migrate
import pki.server.cli.nuxwdog
import pki.server.cli.ocsp
import pki.server.cli.selftest
import pki.server.cli.subsystem
import pki.server.cli.tks
import pki.server.cli.tps
import pki.server.cli.upgrade
import pki.util


class PKIServerCLI(pki.cli.CLI):

    def __init__(self):
        super(PKIServerCLI, self).__init__(
            'pki-server',
            'PKI server command-line interface')

        self.add_module(pki.server.cli.StatusCLI())
        self.add_module(pki.server.cli.StartCLI())
        self.add_module(pki.server.cli.StopCLI())

        self.add_module(pki.server.cli.ca.CACLI())
        self.add_module(pki.server.cli.kra.KRACLI())
        self.add_module(pki.server.cli.ocsp.OCSPCLI())
        self.add_module(pki.server.cli.tks.TKSCLI())
        self.add_module(pki.server.cli.tps.TPSCLI())

        self.add_module(pki.server.cli.banner.BannerCLI())
        self.add_module(pki.server.cli.db.DBCLI())
        self.add_module(pki.server.cli.instance.InstanceCLI())
        self.add_module(pki.server.cli.subsystem.SubsystemCLI())
        self.add_module(pki.server.cli.migrate.MigrateCLI())
        self.add_module(pki.server.cli.nuxwdog.NuxwdogCLI())
        self.add_module(pki.server.cli.cert.CertCLI())
        self.add_module(pki.server.cli.selftest.SelfTestCLI())
        self.add_module(pki.server.cli.http.HTTPCLI())

    def get_full_module_name(self, module_name):
        return module_name

    def print_help(self):
        print('Usage: pki-server [OPTIONS]')
        print()
        print('  -v, --verbose                Run in verbose mode.')
        print('      --debug                  Show debug messages.')
        print('      --help                   Show help message.')
        print()

        super(PKIServerCLI, self).print_help()

    def execute(self, argv):
        try:
            opts, args = getopt.getopt(argv[1:], 'v', [
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.print_help()
            sys.exit(1)

        for o, _ in opts:
            if o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--debug':
                self.set_verbose(True)
                self.set_debug(True)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: unknown option ' + o)
                self.print_help()
                sys.exit(1)

        if self.verbose:
            print('Command: %s' % ' '.join(args))

        super(PKIServerCLI, self).execute(args)

    @staticmethod
    def print_status(server):
        print('  Server ID: %s' % server.name)
        print('  Active: %s' % server.is_active())


class StatusCLI(pki.cli.CLI):

    def __init__(self):
        super(StatusCLI, self).__init__('status', 'Display server status')

    def print_help(self):
        print('Usage: pki-server status [OPTIONS] [<server ID>]')
        print()
        print('  -v, --verbose                 Run in verbose mode.')
        print('      --debug                   Run in debug mode.')
        print('      --help                    Show help message.')
        print()

    def execute(self, argv):

        logging.basicConfig(format='%(levelname)s: %(message)s')

        try:
            opts, args = getopt.gnu_getopt(argv, 'v', [
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: %s' % e)
            self.print_help()
            sys.exit(1)

        server_name = 'pki-tomcat'

        for o, _ in opts:
            if o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: Unknown option: %s' % o)
                self.print_help()
                sys.exit(1)

        if len(args) > 0:
            server_name = args[0]

        server = pki.server.PKIServer(server_name)

        if not server.is_valid():
            print('ERROR: Invalid server: %s' % server_name)
            sys.exit(1)

        PKIServerCLI.print_status(server)


class StartCLI(pki.cli.CLI):

    def __init__(self):
        super(StartCLI, self).__init__('start', 'Start server')

    def print_help(self):
        print('Usage: pki-server start [OPTIONS] [<server ID>]')
        print()
        print('  -v, --verbose                 Run in verbose mode.')
        print('      --debug                   Run in debug mode.')
        print('      --help                    Show help message.')
        print()

    def execute(self, argv):

        logging.basicConfig(format='%(levelname)s: %(message)s')

        try:
            opts, args = getopt.gnu_getopt(argv, 'v', [
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: %s' % e)
            self.print_help()
            sys.exit(1)

        server_name = 'pki-tomcat'

        for o, _ in opts:
            if o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: Unknown option: %s' % o)
                self.print_help()
                sys.exit(1)

        if len(args) > 0:
            server_name = args[0]

        server = pki.server.PKIServer(server_name)

        if not server.is_valid():
            print('ERROR: Invalid server: %s' % server_name)
            sys.exit(1)

        if server.is_active():
            self.print_message('Server already started')
            return

        server.start()


class StopCLI(pki.cli.CLI):

    def __init__(self):
        super(StopCLI, self).__init__('stop', 'Stop server')

    def print_help(self):
        print('Usage: pki-server stop [OPTIONS] [<server ID>]')
        print()
        print('  -v, --verbose                 Run in verbose mode.')
        print('      --debug                   Run in debug mode.')
        print('      --help                    Show help message.')
        print()

    def execute(self, argv):

        logging.basicConfig(format='%(levelname)s: %(message)s')

        try:
            opts, args = getopt.gnu_getopt(argv, 'v', [
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: %s' % e)
            self.print_help()
            sys.exit(1)

        server_name = 'pki-tomcat'

        for o, _ in opts:
            if o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: Unknown option: %s' % o)
                self.print_help()
                sys.exit(1)

        if len(args) > 0:
            server_name = args[0]

        server = pki.server.PKIServer(server_name)

        if not server.is_valid():
            print('ERROR: Invalid server: %s' % server_name)
            sys.exit(1)

        if not server.is_active():
            self.print_message('Server already stopped')
            return

        server.stop()
