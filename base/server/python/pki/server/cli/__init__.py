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

import argparse
import logging
import socket
import sys

import pki.cli
import pki.server
import pki.server.cli.acme
import pki.server.cli.audit
import pki.server.cli.banner
import pki.server.cli.ca
import pki.server.cli.cert
import pki.server.cli.config
import pki.server.cli.db
import pki.server.cli.est
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
import pki.server.cli.sd
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
        super().__init__('pki-server', 'PKI server command-line interface')

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

        self.add_module(pki.server.cli.sd.SDCLI())
        self.add_module(pki.server.cli.ca.CACLI())
        self.add_module(pki.server.cli.kra.KRACLI())
        self.add_module(pki.server.cli.ocsp.OCSPCLI())
        self.add_module(pki.server.cli.tks.TKSCLI())
        self.add_module(pki.server.cli.tps.TPSCLI())
        self.add_module(pki.server.cli.acme.ACMECLI())
        self.add_module(pki.server.cli.est.ESTCLI())

        self.add_module(pki.server.cli.banner.BannerCLI())
        self.add_module(pki.server.cli.db.DBCLI())
        self.add_module(pki.server.cli.instance.InstanceCLI())
        self.add_module(pki.server.cli.subsystem.SubsystemCLI())
        self.add_module(pki.server.cli.migrate.MigrateCLI())
        self.add_module(pki.server.cli.nuxwdog.NuxwdogCLI())
        self.add_module(pki.server.cli.cert.CertCLI())
        self.add_module(pki.server.cli.selftest.SelfTestCLI())

        self.add_module(pki.server.cli.upgrade.UpgradeCLI())

    def create_parser(self, subparsers=None):

        # create main parser
        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
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
            '--version',
            action='store_true')

        self.parser.add_argument(
            'remainder',
            nargs=argparse.REMAINDER)

        # create parsers in modules
        super().create_parser()

    def get_full_module_name(self, module_name):
        return module_name

    def print_help(self):
        print('Usage: pki-server [OPTIONS]')
        print()
        print('  -v, --verbose                  Run in verbose mode.')
        print('      --debug                    Show debug messages.')
        print('      --help                     Show help message.')
        print('      --version                  Show version number.')
        print()

        super().print_help()

    def print_version(self):
        print('PKI Server Command-Line Interface %s' % pki.implementation_version())

    def execute(self, argv, args=None):

        if not args:
            args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.version:
            self.print_version()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        command = None
        if len(args.remainder) > 0:
            command = args.remainder[0]
        logger.debug('Command: %s', command)

        if not command:
            self.print_help()
            return

        module = self.find_module(command)

        if not module:
            raise pki.cli.CLIException('Invalid module "%s".' % command)

        logger.debug('Module: %s', module.get_full_name())

        module_args = args.remainder[1:]
        logger.debug('Arguments: %s', ' '.join(module_args))

        module.execute(module_args)

    @staticmethod
    def print_status(instance):
        print('  Instance ID: %s' % instance.name)
        print('  Active: %s' % instance.is_active())
        print('  Nuxwdog Enabled: %s' % instance.type.endswith('-nuxwdog'))

        server_config = instance.get_server_config()

        http_port = server_config.get_http_port()
        if http_port:
            print('  Unsecure Port: %s' % http_port)

        https_port = server_config.get_https_port()
        if https_port:
            print('  Secure Port: %s' % https_port)

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

            domain_manager = ca.config.get('securitydomain.select') == 'new'
            print('    SD Manager:          %s' % domain_manager)
            print('    SD Name:             %s' % ca.config['securitydomain.name'])
            url = 'https://%s:%s' % (
                ca.config['securitydomain.host'],
                ca.config['securitydomain.httpsadminport'])
            print('    SD Registration URL: %s' % url)

            enabled = ca.is_enabled()
            print('    Enabled:             %s' % enabled)

            if enabled:
                url = 'http://%s:%s/ca' % (hostname, http_port)
                print('    Unsecure URL:        %s/ee/ca' % url)

                url = 'https://%s:%s/ca' % (hostname, https_port)
                print('    Secure Agent URL:    %s/agent/ca' % url)
                print('    Secure EE URL:       %s/ee/ca' % url)
                print('    Secure Admin URL:    %s/services' % url)
                print('    PKI Console URL:     %s' % url)

        kra = instance.get_subsystem('kra')
        if kra:
            print()
            print('  KRA Subsystem:')

            sd_type = kra.config.get('securitydomain.select')
            if sd_type:
                domain_manager = sd_type == 'new'
                print('    SD Manager:          %s' % domain_manager)

                sd_name = kra.config['securitydomain.name']
                print('    SD Name:             %s' % sd_name)

                url = 'https://%s:%s' % (
                    kra.config['securitydomain.host'],
                    kra.config['securitydomain.httpsadminport'])
                print('    SD Registration URL: %s' % url)

            enabled = kra.is_enabled()
            print('    Enabled:             %s' % enabled)

            if enabled:
                url = 'https://%s:%s/kra' % (hostname, https_port)
                print('    Secure Agent URL:    %s/agent/kra' % url)
                print('    Secure Admin URL:    %s/services' % url)
                print('    PKI Console URL:     %s' % url)

        ocsp = instance.get_subsystem('ocsp')
        if ocsp:
            print()
            print('  OCSP Subsystem:')

            domain_manager = ocsp.config.get('securitydomain.select') == 'new'
            print('    SD Manager:          %s' % domain_manager)
            print('    SD Name:             %s' % ocsp.config['securitydomain.name'])
            url = 'https://%s:%s' % (
                ocsp.config['securitydomain.host'],
                ocsp.config['securitydomain.httpsadminport'])
            print('    SD Registration URL: %s' % url)

            enabled = ocsp.is_enabled()
            print('    Enabled:             %s' % enabled)

            if enabled:
                url = 'http://%s:%s/ocsp' % (hostname, http_port)
                print('    Unsecure URL:        %s/ee/ocsp/<ocsp request blob>' % url)

                url = 'https://%s:%s/ocsp' % (hostname, https_port)
                print('    Secure Agent URL:    %s/agent/ocsp' % url)
                print('    Secure EE URL:       %s/ee/ocsp/<ocsp request blob>' % url)
                print('    Secure Admin URL:    %s/services' % url)
                print('    PKI Console URL:     %s' % url)

        tks = instance.get_subsystem('tks')
        if tks:
            print()
            print('  TKS Subsystem:')

            domain_manager = tks.config.get('securitydomain.select') == 'new'
            print('    SD Manager:          %s' % domain_manager)
            print('    SD Name:             %s' % tks.config['securitydomain.name'])
            url = 'https://%s:%s' % (
                tks.config['securitydomain.host'],
                tks.config['securitydomain.httpsadminport'])
            print('    SD Registration URL: %s' % url)

            enabled = tks.is_enabled()
            print('    Enabled:             %s' % enabled)

            if enabled:
                url = 'https://%s:%s/tks' % (hostname, https_port)
                print('    Secure Agent URL:    %s/agent/tks' % url)
                print('    Secure Admin URL:    %s/services' % url)
                print('    PKI Console URL:     %s' % url)

        tps = instance.get_subsystem('tps')
        if tps:
            print()
            print('  TPS Subsystem:')

            domain_manager = tps.config.get('securitydomain.select') == 'new'
            print('    SD Manager:          %s' % domain_manager)
            print('    SD Name:             %s' % tps.config['securitydomain.name'])
            url = 'https://%s:%s' % (
                tps.config['securitydomain.host'],
                tps.config['securitydomain.httpsadminport'])
            print('    SD Registration URL: %s' % url)

            enabled = tps.is_enabled()
            print('    Enabled:             %s' % enabled)

            if enabled:
                url = 'http://%s:%s/tps' % (hostname, http_port)
                print('    Unsecure URL:        %s' % url)
                print('    Unsecure PHONE HOME: %s/phoneHome' % url)

                url = 'https://%s:%s/tps' % (hostname, https_port)
                print('    Secure URL:          %s' % url)
                print('    Secure PHONE HOME:   %s/phoneHome' % url)


class CreateCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('create', 'Create PKI server')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument('--user')
        self.parser.add_argument('--group')
        self.parser.add_argument('--conf')
        self.parser.add_argument('--logs')
        self.parser.add_argument(
            '--with-maven-deps',
            action='store_true')
        self.parser.add_argument(
            '--force',
            action='store_true')
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
            'instance_name',
            nargs='?',
            default='pki-tomcat')

    def print_help(self):
        print('Usage: pki-server create [OPTIONS] [<instance ID>]')
        print()
        print('      --user <name>             User.')
        print('      --group <name>            Group.')
        print('      --conf <path>             Config folder')
        print('      --logs <path>             Logs folder')
        print('      --with-maven-deps         Install Maven dependencies.')
        print('      --force                   Force creation.')
        print('  -v, --verbose                 Run in verbose mode.')
        print('      --debug                   Run in debug mode.')
        print('      --help                    Show help message.')
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

        instance_name = args.instance_name
        user = args.user
        group = args.group
        conf_dir = args.conf
        logs_dir = args.logs
        with_maven_deps = args.with_maven_deps
        force = args.force

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not force and instance.exists():
            logger.error('Instance already exists: %s', instance_name)
            sys.exit(1)

        logger.info('Creating instance: %s', instance_name)

        if user:
            instance.user = user

        if group:
            instance.group = group

        if conf_dir:
            instance.actual_conf_dir = conf_dir

        if logs_dir:
            instance.actual_logs_dir = logs_dir

        instance.with_maven_deps = with_maven_deps

        instance.create(force=force)


class RemoveCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('remove', 'Remove PKI server')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '--remove-conf',
            action='store_true')
        self.parser.add_argument(
            '--remove-logs',
            action='store_true')
        self.parser.add_argument(
            '--force',
            action='store_true')
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
            'instance_name',
            nargs='?',
            default='pki-tomcat')

    def print_help(self):
        print('Usage: pki-server remove [OPTIONS] [<instance ID>]')
        print()
        print('      --remove-conf             Remove config folder.')
        print('      --remove-logs             Remove logs folder.')
        print('      --force                   Force removal.')
        print('  -v, --verbose                 Run in verbose mode.')
        print('      --debug                   Run in debug mode.')
        print('      --help                    Show help message.')
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

        instance_name = args.instance_name
        remove_conf = args.remove_conf
        remove_logs = args.remove_logs
        force = args.force

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not force and not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        logger.info('Removing instance: %s', instance_name)

        instance.remove(
            remove_conf=remove_conf,
            remove_logs=remove_logs,
            force=force)


class StatusCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('status', 'Display PKI service status')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
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
            'instance_name',
            nargs='?',
            default='pki-tomcat')

    def print_help(self):
        print('Usage: pki-server status [OPTIONS] [<instance ID>]')
        print()
        print('  -v, --verbose                 Run in verbose mode.')
        print('      --debug                   Run in debug mode.')
        print('      --help                    Show help message.')
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

        instance_name = args.instance_name

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        PKIServerCLI.print_status(instance)


class StartCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('start', 'Start PKI service')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '--wait',
            action='store_true')
        self.parser.add_argument(
            '--max-wait',
            type=int,
            default=60)
        self.parser.add_argument(
            '--timeout',
            type=int)
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
            'instance_name',
            nargs='?',
            default='pki-tomcat')

    def print_help(self):
        print('Usage: pki-server start [OPTIONS] [<instance ID>]')
        print()
        print('      --wait                    Wait until started.')
        print('      --max-wait <seconds>      Maximum wait time (default: 60)')
        print('      --timeout <seconds>       Connection timeout')
        print('  -v, --verbose                 Run in verbose mode.')
        print('      --debug                   Run in debug mode.')
        print('      --help                    Show help message.')
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

        instance_name = args.instance_name
        wait = args.wait
        max_wait = args.max_wait
        timeout = args.timeout

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        if instance.is_active():
            self.print_message('Instance already started')
            return

        instance.start(wait=wait, max_wait=max_wait, timeout=timeout)


class StopCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('stop', 'Stop PKI service')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '--wait',
            action='store_true')
        self.parser.add_argument(
            '--max-wait',
            type=int,
            default=60)
        self.parser.add_argument(
            '--timeout',
            type=int)
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
            'instance_name',
            nargs='?',
            default='pki-tomcat')

    def print_help(self):
        print('Usage: pki-server stop [OPTIONS] [<instance ID>]')
        print()
        print('      --wait                    Wait until stopped.')
        print('      --max-wait <seconds>      Maximum wait time (default: 60)')
        print('      --timeout <seconds>       Connection timeout')
        print('  -v, --verbose                 Run in verbose mode.')
        print('      --debug                   Run in debug mode.')
        print('      --help                    Show help message.')
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

        instance_name = args.instance_name
        wait = args.wait
        max_wait = args.max_wait
        timeout = args.timeout

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        if not instance.is_active():
            self.print_message('Instance already stopped')
            return

        instance.stop(wait=wait, max_wait=max_wait, timeout=timeout)


class RestartCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('restart', 'Restart PKI service')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '--wait',
            action='store_true')
        self.parser.add_argument(
            '--max-wait',
            type=int,
            default=60)
        self.parser.add_argument(
            '--timeout',
            type=int)
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
            'instance_name',
            nargs='?',
            default='pki-tomcat')

    def print_help(self):
        print('Usage: pki-server restart [OPTIONS] [<instance ID>]')
        print()
        print('      --wait                    Wait until restarted.')
        print('      --max-wait <seconds>      Maximum wait time (default: 60)')
        print('      --timeout <seconds>       Connection timeout')
        print('  -v, --verbose                 Run in verbose mode.')
        print('      --debug                   Run in debug mode.')
        print('      --help                    Show help message.')
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

        instance_name = args.instance_name
        wait = args.wait
        max_wait = args.max_wait
        timeout = args.timeout

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.restart(wait=wait, max_wait=max_wait, timeout=timeout)


class RunCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('run', 'Run PKI server in foreground')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '--as-current-user',
            action='store_true')
        self.parser.add_argument(
            '--with-jdb',
            action='store_true')
        self.parser.add_argument(
            '--with-gdb',
            action='store_true')
        self.parser.add_argument(
            '--with-valgrind',
            action='store_true')
        self.parser.add_argument('--agentpath')
        self.parser.add_argument(
            '--skip-upgrade',
            action='store_true')
        self.parser.add_argument(
            '--skip-migration',
            action='store_true')
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
            'instance_name',
            nargs='?',
            default='pki-tomcat')

    def print_help(self):
        print('Usage: pki-server run [OPTIONS] [<instance ID>]')
        print()
        print('      --skip-upgrade            Skip config upgrade.')
        print('      --skip-migration          Skip config migration.')
        print('      --as-current-user         Run as current user.')
        print('      --with-jdb                Run with Java debugger.')
        print('      --with-gdb                Run with GNU debugger.')
        print('      --with-valgrind           Run with Valgrind.')
        print('      --agentpath <value>       Java agent path.')
        print('  -v, --verbose                 Run in verbose mode.')
        print('      --debug                   Run in debug mode.')
        print('      --help                    Show help message.')
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

        instance_name = args.instance_name
        as_current_user = args.as_current_user
        with_jdb = args.with_jdb
        with_gdb = args.with_gdb
        with_valgrind = args.with_valgrind
        agentpath = args.agentpath
        skip_upgrade = args.skip_upgrade
        skip_migration = args.skip_migration

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        try:
            instance.run(
                as_current_user=as_current_user,
                with_jdb=with_jdb,
                with_gdb=with_gdb,
                with_valgrind=with_valgrind,
                agentpath=agentpath,
                skip_upgrade=skip_upgrade,
                skip_migration=skip_migration)

        except KeyboardInterrupt:
            logger.debug('Server stopped')
