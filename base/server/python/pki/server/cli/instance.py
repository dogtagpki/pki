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

import getopt
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
        super(InstanceCLI, self).__init__('instance',
                                          'Instance management commands')

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
        super(InstanceCertCLI, self).__init__(
            'cert', 'Instance certificate management commands')

        self.add_module(InstanceCertExportCLI())


class InstanceCertExportCLI(pki.cli.CLI):

    def __init__(self):
        super(InstanceCertExportCLI, self).__init__(
            'export', 'Export system certificates')

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

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'pkcs12-file=', 'pkcs12-password=', 'pkcs12-password-file=',
                'append', 'no-trust-flags', 'no-key', 'no-chain',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        nicknames = args

        instance_name = 'pki-tomcat'
        pkcs12_file = None
        pkcs12_password = None
        pkcs12_password_file = None
        append = False
        include_trust_flags = True
        include_key = True
        include_chain = True

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--pkcs12-file':
                pkcs12_file = a

            elif o == '--pkcs12-password':
                pkcs12_password = a

            elif o == '--pkcs12-password-file':
                pkcs12_password_file = a

            elif o == '--append':
                append = True

            elif o == '--no-trust-flags':
                include_trust_flags = False

            elif o == '--no-key':
                include_key = False

            elif o == '--no-chain':
                include_chain = False

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if not pkcs12_file:
            logger.error('missing output file')
            self.print_help()
            sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)

        if not instance.is_valid():
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
        super(InstanceFindCLI, self).__init__('find', 'Find instances')

    def print_help(self):
        print('Usage: pki-server instance-find [OPTIONS]')
        print()
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        for o, _ in opts:
            if o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        results = []
        if os.path.exists(pki.server.PKIServer.BASE_DIR):
            for f in os.listdir(pki.server.PKIServer.BASE_DIR):

                if not os.path.isdir:
                    continue

                results.append(f)

        self.print_message('%s entries matched' % len(results))

        first = True
        for instance_name in results:
            if first:
                first = False
            else:
                print()

            instance = pki.server.PKIInstance(instance_name)
            instance.load()

            InstanceCLI.print_instance(instance)


class InstanceShowCLI(pki.cli.CLI):

    def __init__(self):
        super(InstanceShowCLI, self).__init__('show', 'Show instance')

    def print_help(self):
        print('Usage: pki-server instance-show [OPTIONS] <instance ID>')
        print()
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        for o, _ in opts:
            if o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) != 1:
            logger.error('Missing instance ID')
            self.print_help()
            sys.exit(1)

        instance_name = args[0]

        instance = pki.server.PKIInstance(instance_name)

        if not instance.is_valid():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        InstanceCLI.print_instance(instance)


class InstanceStartCLI(pki.cli.CLI):

    def __init__(self):
        super(InstanceStartCLI, self).__init__('start', 'Start instance')

    def print_help(self):
        print('Usage: pki-server instance-start [OPTIONS] <instance ID>')
        print()
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        for o, _ in opts:
            if o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) != 1:
            logger.error('Missing instance ID')
            self.print_help()
            sys.exit(1)

        instance_name = args[0]

        instance = pki.server.PKIInstance(instance_name)

        if not instance.is_valid():
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
        super(InstanceStopCLI, self).__init__('stop', 'Stop instance')

    def print_help(self):
        print('Usage: pki-server instance-stop [OPTIONS] <instance ID>')
        print()
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        for o, _ in opts:
            if o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) != 1:
            logger.error('Missing instance ID')
            self.print_help()
            sys.exit(1)

        instance_name = args[0]

        instance = pki.server.PKIInstance(instance_name)

        if not instance.is_valid():
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
        super(InstanceMigrateCLI, self).__init__('migrate', 'Migrate instance')

    def print_help(self):
        print('Usage: pki-server instance-migrate [OPTIONS] <instance ID>')
        print()
        print('      --tomcat <version>       Use the specified Tomcat version.')
        print('  -v, --verbose                Run in verbose mode.')
        print('      --debug                  Show debug messages.')
        print('      --help                   Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'tomcat=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        tomcat_version = None

        for o, a in opts:
            if o == '--tomcat':
                tomcat_version = pki.util.Version(a)

            elif o == '--debug':
                self.set_verbose(True)
                self.set_debug(True)
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) != 1:
            logger.error('Missing instance ID')
            self.print_help()
            sys.exit(1)

        instance_name = args[0]

        if not tomcat_version:
            tomcat_version = pki.server.Tomcat.get_version()

        logger.info('Migrating to Tomcat %s', tomcat_version)

        module = self.get_top_module().find_module('migrate')
        module.set_verbose(logger.isEnabledFor(logging.INFO))
        module.set_debug(logger.isEnabledFor(logging.DEBUG))

        instance = pki.server.PKIInstance(instance_name)

        if not instance.is_valid():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        module.migrate(  # pylint: disable=no-member,maybe-no-member
            instance,
            tomcat_version)

        self.print_message('%s instance migrated' % instance_name)


class InstanceNuxwdogEnableCLI(pki.cli.CLI):

    def __init__(self):
        super(InstanceNuxwdogEnableCLI, self).__init__(
            'nuxwdog-enable',
            'Instance enable nuxwdog')

    def print_help(self):
        print('Usage: pki-server instance-nuxwdog-enable [OPTIONS] <instance ID>')
        print()
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        for o, _ in opts:
            if o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) != 1:
            logger.error('Missing instance ID')
            self.print_help()
            sys.exit(1)

        instance_name = args[0]

        module = self.get_top_module().find_module('nuxwdog-enable')
        module = pki.server.cli.nuxwdog.NuxwdogEnableCLI()
        module.set_verbose(logger.isEnabledFor(logging.INFO))

        instance = pki.server.PKIInstance(instance_name)

        if not instance.is_valid():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()
        module.enable_nuxwdog(  # pylint: disable=no-member,maybe-no-member
            instance)

        self.print_message('Nuxwdog enabled for instance %s.' % instance_name)


class InstanceNuxwdogDisableCLI(pki.cli.CLI):

    def __init__(self):
        super(InstanceNuxwdogDisableCLI, self).__init__(
            'nuxwdog-disable',
            'Instance disable nuxwdog')

    def print_help(self):
        print('Usage: pki-server instance-nuxwdog-disable [OPTIONS] <instance ID>')
        print()
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        for o, _ in opts:
            if o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) != 1:
            logger.error('Missing instance ID')
            self.print_help()
            sys.exit(1)

        instance_name = args[0]

        module = self.get_top_module().find_module('nuxwdog-disable')
        module.set_verbose(logger.isEnabledFor(logging.INFO))

        instance = pki.server.PKIInstance(instance_name)

        if not instance.is_valid():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        module.disable_nuxwdog(
            instance)  # pylint: disable=no-member,maybe-no-member

        self.print_message('Nuxwdog disabled for instance %s.' % instance_name)


class InstanceExternalCertAddCLI(pki.cli.CLI):

    def __init__(self):
        super(InstanceExternalCertAddCLI, self).__init__(
            'externalcert-add',
            'Add external certificate or chain to the instance')

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

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'cert-file=', 'trust-args=', 'nickname=', 'token=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        cert_file = None
        trust_args = '\",,\"'
        nickname = None
        token = pki.nssdb.INTERNAL_TOKEN_NAME

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--cert-file':
                cert_file = a

            elif o == '--trust-args':
                trust_args = a

            elif o == '--nickname':
                nickname = a

            elif o == '--token':
                token = a

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if not cert_file:
            logger.error('Missing input file containing certificate')
            self.print_help()
            sys.exit(1)

        if not nickname:
            logger.error('Missing nickname')
            self.print_help()
            sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)

        if not instance.is_valid():
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
        password = instance.get_token_password(token)
        certdb = pki.nssdb.NSSDatabase(
            directory=instance.nssdb_dir,
            password=password,
            token=token)
        _chain, nicks = certdb.import_cert_chain(
            nickname=nickname,
            cert_chain_file=cert_file,
            trust_attributes=trust_args)
        return nicks

    def update_instance_config(self, instance, nicks, token):
        for nickname in nicks:
            instance.add_external_cert(nickname, token)


class InstanceExternalCertDeleteCLI(pki.cli.CLI):

    def __init__(self):
        super(InstanceExternalCertDeleteCLI, self).__init__(
            'externalcert-del',
            'Delete external certificate from the instance')

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

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'nickname=', 'token=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        nickname = None
        token = pki.nssdb.INTERNAL_TOKEN_NAME

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--nickname':
                nickname = a

            elif o == '--token':
                token = a

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if not nickname:
            logger.error('Missing nickname')
            self.print_help()
            sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)

        if not instance.is_valid():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        self.remove_cert(instance, nickname, token)
        instance.delete_external_cert(nickname, token)

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
