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
import pki.server.cli.jss
import pki.server.cli.kra
import pki.server.cli.listener
import pki.server.cli.migrate
import pki.server.cli.nss
import pki.server.cli.nuxwdog
import pki.server.cli.ocsp
import pki.server.cli.password
import pki.server.cli.selftest
import pki.server.cli.subsystem
import pki.server.cli.tks
import pki.server.cli.tps
import pki.util


class PKIServerCLI(pki.cli.CLI):

    def __init__(self):
        super(PKIServerCLI, self).__init__(
            'pki-server',
            'PKI server command-line interface')

        self.add_module(pki.server.cli.CreateCLI())
        self.add_module(pki.server.cli.RemoveCLI())

        self.add_module(pki.server.cli.StatusCLI())
        self.add_module(pki.server.cli.StartCLI())
        self.add_module(pki.server.cli.StopCLI())

        self.add_module(pki.server.cli.http.HTTPCLI())
        self.add_module(pki.server.cli.listener.ListenerCLI())

        self.add_module(pki.server.cli.password.PasswordCLI())
        self.add_module(pki.server.cli.nss.NSSCLI())
        self.add_module(pki.server.cli.jss.JSSCLI())

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
    def print_status(instance):
        print('  Instance ID: %s' % instance.name)
        print('  Active: %s' % instance.is_active())


class CreateCLI(pki.cli.CLI):

    def __init__(self):
        super(CreateCLI, self).__init__('create', 'Create instance')

    def print_help(self):
        print('Usage: pki-server create [OPTIONS] [<instance ID>]')
        print()
        print('      --force                   Force creation.')
        print('  -v, --verbose                 Run in verbose mode.')
        print('      --debug                   Run in debug mode.')
        print('      --help                    Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'v', [
                'force',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: %s' % e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        force = False

        for o, _ in opts:
            if o == '--force':
                force = True

            elif o in ('-v', '--verbose'):
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
            instance_name = args[0]

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not force and instance.is_valid():
            print('ERROR: Instance already exists: %s' % instance_name)
            sys.exit(1)

        instance.create(force)


class RemoveCLI(pki.cli.CLI):

    def __init__(self):
        super(RemoveCLI, self).__init__('remove', 'Remove instance')

    def print_help(self):
        print('Usage: pki-server remove [OPTIONS] [<instance ID>]')
        print()
        print('      --force                   Force removal.')
        print('  -v, --verbose                 Run in verbose mode.')
        print('      --debug                   Run in debug mode.')
        print('      --help                    Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'v', [
                'force',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: %s' % e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        force = False

        for o, _ in opts:
            if o == '--force':
                force = True

            elif o in ('-v', '--verbose'):
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
            instance_name = args[0]

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not force and not instance.is_valid():
            print('ERROR: Invalid instance: %s' % instance_name)
            sys.exit(1)

        instance.remove(force)


class StatusCLI(pki.cli.CLI):

    def __init__(self):
        super(StatusCLI, self).__init__('status', 'Display instance status')

    def print_help(self):
        print('Usage: pki-server status [OPTIONS] [<instance ID>]')
        print()
        print('  -v, --verbose                 Run in verbose mode.')
        print('      --debug                   Run in debug mode.')
        print('      --help                    Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'v', [
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: %s' % e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'

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
            instance_name = args[0]

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.is_valid():
            print('ERROR: Invalid instance: %s' % instance_name)
            sys.exit(1)

        PKIServerCLI.print_status(instance)


class StartCLI(pki.cli.CLI):

    def __init__(self):
        super(StartCLI, self).__init__('start', 'Start instance')

    def print_help(self):
        print('Usage: pki-server start [OPTIONS] [<instance ID>]')
        print()
        print('  -v, --verbose                 Run in verbose mode.')
        print('      --debug                   Run in debug mode.')
        print('      --help                    Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'v', [
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: %s' % e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'

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
            instance_name = args[0]

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.is_valid():
            print('ERROR: Invalid instance: %s' % instance_name)
            sys.exit(1)

        if instance.is_active():
            self.print_message('Instance already started')
            return

        instance.start()


class StopCLI(pki.cli.CLI):

    def __init__(self):
        super(StopCLI, self).__init__('stop', 'Stop instance')

    def print_help(self):
        print('Usage: pki-server stop [OPTIONS] [<instance ID>]')
        print()
        print('  -v, --verbose                 Run in verbose mode.')
        print('      --debug                   Run in debug mode.')
        print('      --help                    Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'v', [
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: %s' % e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'

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
            instance_name = args[0]

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.is_valid():
            print('ERROR: Invalid instance: %s' % instance_name)
            sys.exit(1)

        if not instance.is_active():
            self.print_message('Instance already stopped')
            return

        instance.stop()
