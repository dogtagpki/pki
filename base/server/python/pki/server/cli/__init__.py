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
import socket
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
import pki.server.cli.upgrade
import pki.server.cli.webapp
import pki.util

logger = logging.getLogger(__name__)


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
        self.add_module(pki.server.cli.RestartCLI())
        self.add_module(pki.server.cli.RunCLI())

        self.add_module(pki.server.cli.http.HTTPCLI())
        self.add_module(pki.server.cli.listener.ListenerCLI())

        self.add_module(pki.server.cli.password.PasswordCLI())
        self.add_module(pki.server.cli.nss.NSSCLI())
        self.add_module(pki.server.cli.jss.JSSCLI())

        self.add_module(pki.server.cli.webapp.WebappCLI())

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

        self.add_module(pki.server.cli.upgrade.UpgradeCLI())

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
            logger.error(e)
            self.print_help()
            sys.exit(1)

        for o, _ in opts:
            if o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Unknown option %s', o)
                self.print_help()
                sys.exit(1)

        logger.info('Command: %s', ' '.join(args))

        super(PKIServerCLI, self).execute(args)

    @staticmethod
    def print_status(instance):
        print('  Instance ID: %s' % instance.name)
        print('  Active: %s' % instance.is_active())

        server_config = instance.get_server_config()

        unsecurePort = server_config.get_unsecure_port()
        if unsecurePort:
            print('  Unsecure Port: %s' % unsecurePort)

        securePort = server_config.get_secure_port()
        if securePort:
            print('  Secure Port: %s' % securePort)

        ajpPort = server_config.get_ajp_port()
        if ajpPort:
            print('  AJP Port: %s' % ajpPort)

        tomcatPort = server_config.get_port()
        print('  Tomcat Port: %s' % tomcatPort)

        hostname = socket.gethostname()

        ca = instance.get_subsystem('ca')
        if ca:
            print()
            print('  CA Subsystem:')

            if ca.config['subsystem.select'] == 'Clone':
                subsystem_type = 'CA Clone'
            else:
                subsystem_type = ca.config['hierarchy.select'] + ' CA'
            if ca.config['securitydomain.select'] == 'new':
                subsystem_type += ' (Security Domain)'
            print('    Type:                %s' % subsystem_type)

            url = 'https://%s:%s' % (
                ca.config['securitydomain.host'],
                ca.config['securitydomain.httpsadminport'])
            print('    SD Registration URL: %s' % url)

            enabled = ca.is_enabled()
            print('    Enabled:             %s' % enabled)

            if enabled:
                url = 'http://%s:%s/ca' % (hostname, unsecurePort)
                print('    Unsecure URL:        %s/ee/ca' % url)

                url = 'https://%s:%s/ca' % (hostname, securePort)
                print('    Secure Agent URL:    %s/agent/ca' % url)
                print('    Secure EE URL:       %s/ee/ca' % url)
                print('    Secure Admin URL:    %s/services' % url)
                print('    PKI Console URL:     %s' % url)

        kra = instance.get_subsystem('kra')
        if kra:
            print()
            print('  KRA Subsystem:')

            subsystem_type = 'KRA'
            if kra.config['subsystem.select'] == 'Clone':
                subsystem_type += ' Clone'
            elif kra.config['kra.standalone'] == 'true':
                subsystem_type += ' (Standalone)'
            print('    Type:                %s' % subsystem_type)

            url = 'https://%s:%s' % (
                kra.config['securitydomain.host'],
                kra.config['securitydomain.httpsadminport'])
            print('    SD Registration URL: %s' % url)

            enabled = kra.is_enabled()
            print('    Enabled:             %s' % enabled)

            if enabled:
                url = 'https://%s:%s/kra' % (hostname, securePort)
                print('    Secure Agent URL:    %s/agent/kra' % url)
                print('    Secure Admin URL:    %s/services' % url)
                print('    PKI Console URL:     %s' % url)

        ocsp = instance.get_subsystem('ocsp')
        if ocsp:
            print()
            print('  OCSP Subsystem:')

            subsystem_type = 'OCSP'
            if ocsp.config['subsystem.select'] == 'Clone':
                subsystem_type += ' Clone'
            elif ocsp.config['ocsp.standalone'] == 'true':
                subsystem_type += ' (Standalone)'
            print('    Type:                %s' % subsystem_type)

            url = 'https://%s:%s' % (
                ocsp.config['securitydomain.host'],
                ocsp.config['securitydomain.httpsadminport'])
            print('    SD Registration URL: %s' % url)

            enabled = ocsp.is_enabled()
            print('    Enabled:             %s' % enabled)

            if enabled:
                url = 'http://%s:%s/ocsp' % (hostname, unsecurePort)
                print('    Unsecure URL:        %s/ee/ocsp/<ocsp request blob>' % url)

                url = 'https://%s:%s/ocsp' % (hostname, securePort)
                print('    Secure Agent URL:    %s/agent/ocsp' % url)
                print('    Secure EE URL:       %s/ee/ocsp/<ocsp request blob>' % url)
                print('    Secure Admin URL:    %s/services' % url)
                print('    PKI Console URL:     %s' % url)

        tks = instance.get_subsystem('tks')
        if tks:
            print()
            print('  TKS Subsystem:')

            subsystem_type = 'TKS'
            if tks.config['subsystem.select'] == 'Clone':
                subsystem_type += ' Clone'
            print('    Type:                %s' % subsystem_type)

            url = 'https://%s:%s' % (
                tks.config['securitydomain.host'],
                tks.config['securitydomain.httpsadminport'])
            print('    SD Registration URL: %s' % url)

            enabled = tks.is_enabled()
            print('    Enabled:             %s' % enabled)

            if enabled:
                url = 'https://%s:%s/tks' % (hostname, securePort)
                print('    Secure Agent URL:    %s/agent/tks' % url)
                print('    Secure Admin URL:    %s/services' % url)
                print('    PKI Console URL:     %s' % url)

        tps = instance.get_subsystem('tps')
        if tps:
            print()
            print('  TPS Subsystem:')

            subsystem_type = 'TPS'
            if tps.config['subsystem.select'] == 'Clone':
                subsystem_type += ' Clone'
            print('    Type:                %s' % subsystem_type)

            url = 'https://%s:%s' % (
                tps.config['securitydomain.host'],
                tps.config['securitydomain.httpsadminport'])
            print('    SD Registration URL: %s' % url)

            enabled = tps.is_enabled()
            print('    Enabled:             %s' % enabled)

            if enabled:
                url = 'http://%s:%s/tps' % (hostname, unsecurePort)
                print('    Unsecure URL:        %s' % url)
                print('    Unsecure PHONE HOME: %s/phoneHome' % url)

                url = 'https://%s:%s/tps' % (hostname, securePort)
                print('    Secure URL:          %s' % url)
                print('    Secure PHONE HOME:   %s/phoneHome' % url)


class CreateCLI(pki.cli.CLI):

    def __init__(self):
        super(CreateCLI, self).__init__('create', 'Create PKI server')

    def print_help(self):
        print('Usage: pki-server create [OPTIONS] [<instance ID>]')
        print()
        print('      --with-maven-deps         Install Maven dependencies.')
        print('      --force                   Force creation.')
        print('  -v, --verbose                 Run in verbose mode.')
        print('      --debug                   Run in debug mode.')
        print('      --help                    Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'v', [
                'with-maven-deps', 'force',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        with_maven_deps = False
        force = False

        for o, _ in opts:
            if o == '--with-maven-deps':
                with_maven_deps = True

            elif o == '--force':
                force = True

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) > 0:
            instance_name = args[0]

        instance = pki.server.instance.PKIServerFactory.create(instance_name)

        if not force and instance.is_valid():
            logger.error('Instance already exists: %s', instance_name)
            sys.exit(1)

        logging.info('Creating instance: %s', instance_name)

        instance.with_maven_deps = with_maven_deps
        instance.create(force=force)


class RemoveCLI(pki.cli.CLI):

    def __init__(self):
        super(RemoveCLI, self).__init__('remove', 'Remove PKI server')

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
            logger.error(e)
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
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) > 0:
            instance_name = args[0]

        instance = pki.server.instance.PKIServerFactory.create(instance_name)

        if not force and not instance.is_valid():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        logging.info('Removing instance: %s', instance_name)

        instance.stop()
        instance.remove(force=force)


class StatusCLI(pki.cli.CLI):

    def __init__(self):
        super(StatusCLI, self).__init__('status', 'Display PKI service status')

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
            logger.error(e)
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
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) > 0:
            instance_name = args[0]

        instance = pki.server.instance.PKIServerFactory.create(instance_name)

        if not instance.is_valid():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        PKIServerCLI.print_status(instance)


class StartCLI(pki.cli.CLI):

    def __init__(self):
        super(StartCLI, self).__init__('start', 'Start PKI service')

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
            logger.error(e)
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
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) > 0:
            instance_name = args[0]

        instance = pki.server.instance.PKIServerFactory.create(instance_name)

        if not instance.is_valid():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        if instance.is_active():
            self.print_message('Instance already started')
            return

        instance.start()


class StopCLI(pki.cli.CLI):

    def __init__(self):
        super(StopCLI, self).__init__('stop', 'Stop PKI service')

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
            logger.error(e)
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
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) > 0:
            instance_name = args[0]

        instance = pki.server.instance.PKIServerFactory.create(instance_name)

        if not instance.is_valid():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        if not instance.is_active():
            self.print_message('Instance already stopped')
            return

        instance.stop()


class RestartCLI(pki.cli.CLI):

    def __init__(self):
        super(RestartCLI, self).__init__('restart', 'Restart PKI service')

    def print_help(self):
        print('Usage: pki-server restart [OPTIONS] [<instance ID>]')
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
            logger.error(e)
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
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) > 0:
            instance_name = args[0]

        instance = pki.server.instance.PKIServerFactory.create(instance_name)

        if not instance.is_valid():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.restart()


class RunCLI(pki.cli.CLI):

    def __init__(self):
        super(RunCLI, self).__init__('run', 'Run PKI server in foreground')

    def print_help(self):
        print('Usage: pki-server run [OPTIONS] [<instance ID>]')
        print()
        print('      --as-current-user         Run as current user.')
        print('      --jdb                     Run with Java Debugger.')
        print('  -v, --verbose                 Run in verbose mode.')
        print('      --debug                   Run in debug mode.')
        print('      --help                    Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'v', [
                'as-current-user', 'jdb',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        as_current_user = False
        jdb = False

        for o, _ in opts:
            if o == '--as-current-user':
                as_current_user = True

            elif o == '--jdb':
                jdb = True

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) > 0:
            instance_name = args[0]

        instance = pki.server.instance.PKIServerFactory.create(instance_name)

        if not instance.is_valid():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        try:
            instance.run(jdb=jdb, as_current_user=as_current_user)

        except KeyboardInterrupt:
            logging.debug('Server stopped')
