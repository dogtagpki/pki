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

import argparse
import getpass
import logging
import os
import sys

import pki.cli
import pki.nssdb
import pki.server
import pki.server.cli.nuxwdog
import pki.util

logger = logging.getLogger(__name__)


class InstanceCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('instance', 'Instance management commands')

        self.add_module(InstanceCertCLI())
        self.add_module(InstanceFindCLI())
        self.add_module(InstanceShowCLI())
        self.add_module(InstanceStartCLI())
        self.add_module(InstanceStopCLI())
        self.add_module(InstanceMigrateCLI())
        self.add_module(InstanceNuxwdogEnableCLI())
        self.add_module(InstanceNuxwdogDisableCLI())
        self.add_module(InstanceExternalCertAddCLI())
        self.add_module(InstanceExternalCertDeleteCLI())

    @staticmethod
    def print_instance(instance):
        print('  Instance ID: %s' % instance.name)
        print('  Active: %s' % instance.is_active())


class InstanceCertCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('cert', 'Instance certificate management commands')

        self.add_module(InstanceCertExportCLI())


class InstanceCertExportCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('export', 'Export system certificates')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--pkcs12-file')
        self.parser.add_argument('--pkcs12-password')
        self.parser.add_argument('--pkcs12-password-file')
        self.parser.add_argument(
            '--append',
            action='store_true')
        self.parser.add_argument(
            '--no-trust-flags',
            action='store_true')
        self.parser.add_argument(
            '--no-key',
            action='store_true')
        self.parser.add_argument(
            '--no-chain',
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
            'nicknames',
            nargs='*')

    def print_help(self):
        print('Usage: pki-server instance-cert-export [OPTIONS] [nicknames...]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --pkcs12-file <path>           Output file to store the exported certificate '
              'and key in PKCS #12 format.')
        print('      --pkcs12-password <password>   Password for the PKCS #12 file.')
        print('      --pkcs12-password-file <path>  Input file containing the password for the '
              'PKCS #12 file.')
        print('      --append                       Append into an existing PKCS #12 file.')
        print('      --no-trust-flags               Do not include trust flags')
        print('      --no-key                       Do not include private key')
        print('      --no-chain                     Do not include certificate chain')
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
        pkcs12_file = args.pkcs12_file
        pkcs12_password = args.pkcs12_password
        pkcs12_password_file = args.pkcs12_password_file
        append = args.append
        include_trust_flags = not args.no_trust_flags
        include_key = not args.no_key
        include_chain = not args.no_chain

        nicknames = args.nicknames

        if not pkcs12_file:
            logger.error('missing output file')
            self.print_help()
            sys.exit(1)

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        if not pkcs12_password and not pkcs12_password_file:
            pkcs12_password = getpass.getpass(prompt='Enter password for PKCS #12 file: ')

        nssdb = instance.open_nssdb()
        try:
            nssdb.export_pkcs12(
                pkcs12_file=pkcs12_file,
                pkcs12_password=pkcs12_password,
                pkcs12_password_file=pkcs12_password_file,
                nicknames=nicknames,
                append=append,
                include_trust_flags=include_trust_flags,
                include_key=include_key,
                include_chain=include_chain)
        finally:
            nssdb.close()


class InstanceFindCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('find', 'Find instances')

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

    def print_help(self):
        print('Usage: pki-server instance-find [OPTIONS]')
        print()
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

        instances = []
        if os.path.exists(pki.server.PKIServer.BASE_DIR):
            for instance_name in os.listdir(pki.server.PKIServer.BASE_DIR):

                instance = pki.server.PKIServerFactory.create(instance_name)

                if not instance.exists():
                    continue

                instances.append(instance)

        self.print_message('%s entries matched' % len(instances))

        first = True
        for instance in instances:
            if first:
                first = False
            else:
                print()

            instance.load()

            InstanceCLI.print_instance(instance)


class InstanceShowCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('show', 'Show instance')

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
        self.parser.add_argument('instance_id')

    def print_help(self):
        print('Usage: pki-server instance-show [OPTIONS] <instance ID>')
        print()
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

        instance_name = args.instance_id

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        InstanceCLI.print_instance(instance)


class InstanceStartCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('start', 'Start instance')

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
        self.parser.add_argument('instance_id')

    def print_help(self):
        print('Usage: pki-server instance-start [OPTIONS] <instance ID>')
        print()
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

        instance_name = args.instance_id

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        if instance.is_active():
            self.print_message('%s instance already started' % instance_name)
            return

        instance.load()
        instance.start()

        self.print_message('%s instance started' % instance_name)


class InstanceStopCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('stop', 'Stop instance')

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
        self.parser.add_argument('instance_id')

    def print_help(self):
        print('Usage: pki-server instance-stop [OPTIONS] <instance ID>')
        print()
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

        instance_name = args.instance_id

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        if not instance.is_active():
            self.print_message('%s instance already stopped' % instance_name)
            return

        instance.load()
        instance.stop()

        self.print_message('%s instance stopped' % instance_name)


class InstanceMigrateCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('migrate', 'Migrate instance')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument('--tomcat')
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
        self.parser.add_argument('instance_id')

    def print_help(self):
        print('Usage: pki-server instance-migrate [OPTIONS] <instance ID>')
        print()
        print('      --tomcat <version>       Use the specified Tomcat version.')
        print('  -v, --verbose                Run in verbose mode.')
        print('      --debug                  Show debug messages.')
        print('      --help                   Show help message.')
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

        if args.tomcat:
            tomcat_version = pki.util.Version(args.tomcat)
        else:
            tomcat_version = pki.server.Tomcat.get_version()

        instance_name = args.instance_id

        logger.info('Migrating to Tomcat %s', tomcat_version)

        module = self.get_top_module().find_module('migrate')

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        module.migrate(  # pylint: disable=no-member,maybe-no-member
            instance,
            tomcat_version)

        self.print_message('%s instance migrated' % instance_name)


class InstanceNuxwdogEnableCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('nuxwdog-enable', 'Instance enable nuxwdog')

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
        self.parser.add_argument('instance_id')

    def print_help(self):
        print('Usage: pki-server instance-nuxwdog-enable [OPTIONS] <instance ID>')
        print()
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

        instance_name = args.instance_id

        module = self.get_top_module().find_module('nuxwdog-enable')
        module = pki.server.cli.nuxwdog.NuxwdogEnableCLI()

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()
        module.enable_nuxwdog(  # pylint: disable=no-member,maybe-no-member
            instance)

        self.print_message('Nuxwdog enabled for instance %s.' % instance_name)


class InstanceNuxwdogDisableCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('nuxwdog-disable', 'Instance disable nuxwdog')

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
        self.parser.add_argument('instance_id')

    def print_help(self):
        print('Usage: pki-server instance-nuxwdog-disable [OPTIONS] <instance ID>')
        print()
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

        instance_name = args.instance_id

        module = self.get_top_module().find_module('nuxwdog-disable')

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        module.disable_nuxwdog(
            instance)  # pylint: disable=no-member,maybe-no-member

        self.print_message('Nuxwdog disabled for instance %s.' % instance_name)


class InstanceExternalCertAddCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('externalcert-add', 'Add external certificate or chain to the instance')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--cert-file')
        self.parser.add_argument(
            '--trust-args',
            default='\",,\"')
        self.parser.add_argument('--nickname')
        self.parser.add_argument(
            '--token',
            default=pki.nssdb.INTERNAL_TOKEN_NAME)
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
        print('Usage: pki-server instance-externalcert-add [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --cert-file <path>             Input file containing the external certificate'
              ' or certificate chain.')
        print('      --trust-args <trust-args>      Trust args (default \",,\").')
        print('      --nickname <nickname>          Nickname to be used.')
        print('      --token <token_name>           Token (default: internal).')
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
        cert_file = args.cert_file
        trust_args = args.trust_args
        nickname = args.nickname
        token = args.token

        if not cert_file:
            logger.error('Missing input file containing certificate')
            self.print_help()
            sys.exit(1)

        if not nickname:
            logger.error('Missing nickname')
            self.print_help()
            sys.exit(1)

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        if instance.external_cert_exists(nickname, token):
            logger.error('Certificate already imported for instance %s.', instance_name)
            sys.exit(1)

        nicks = self.import_certs(
            instance, cert_file, nickname, token, trust_args)
        self.update_instance_config(instance, nicks, token)

        self.print_message('Certificate imported for instance %s.' %
                           instance_name)

    def import_certs(self, instance, cert_file, nickname, token, trust_args):

        logger.info('Importing %s into %s', cert_file, instance.nssdb_dir)

        password = instance.get_token_password(token)
        certdb = pki.nssdb.NSSDatabase(
            directory=instance.nssdb_dir,
            password=password,
            token=token)
        certdb.import_cert_chain(
            nickname=nickname,
            cert_chain_file=cert_file,
            trust_attributes=trust_args)
        return [nickname]

    def update_instance_config(self, instance, nicks, token):

        for nickname in nicks:
            logger.info('Adding %s cert', nickname)
            instance.add_external_cert(nickname, token)

        instance.store_external_certs()


class InstanceExternalCertDeleteCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('externalcert-del', 'Delete external certificate from the instance')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--nickname')
        self.parser.add_argument(
            '--token',
            default=pki.nssdb.INTERNAL_TOKEN_NAME)
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
        print('Usage: pki-server instance-externalcert-del [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --nickname <nickname>          Nickname to be used.')
        print('      --token <token_name>           Token (default: internal).')
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
        nickname = args.nickname
        token = args.token

        if not nickname:
            logger.error('Missing nickname')
            self.print_help()
            sys.exit(1)

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        self.remove_cert(instance, nickname, token)

        logger.info('Removing %s cert', nickname)
        instance.delete_external_cert(nickname, token)

        instance.store_external_certs()

        self.print_message('Certificate removed from instance %s.' %
                           instance_name)

    def remove_cert(self, instance, nickname, token):
        nssdb = instance.open_nssdb()
        try:
            nssdb.remove_cert(
                nickname=nickname,
                token=token)
        finally:
            nssdb.close()
