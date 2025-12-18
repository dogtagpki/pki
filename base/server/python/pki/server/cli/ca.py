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
import inspect
import io
import logging
import os
import shutil
import sys
import tempfile
import textwrap
import urllib

import pki.cli
import pki.server
import pki.server.cli.acl
import pki.server.cli.audit
import pki.server.cli.config
import pki.server.cli.db
import pki.server.cli.group
import pki.server.cli.id
import pki.server.cli.range
import pki.server.cli.subsystem
import pki.server.cli.user

logger = logging.getLogger(__name__)


class CACLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('ca', 'CA management commands')

        self.add_module(pki.server.cli.subsystem.SubsystemCreateCLI(self))
        self.add_module(pki.server.cli.subsystem.SubsystemDeployCLI(self))
        self.add_module(pki.server.cli.subsystem.SubsystemUndeployCLI(self))
        self.add_module(pki.server.cli.subsystem.SubsystemRedeployCLI(self))
        self.add_module(pki.server.cli.audit.AuditCLI(self))
        self.add_module(CACertCLI())
        self.add_module(CACRLCLI())
        self.add_module(CACloneCLI())
        self.add_module(CAConnectorCLI())
        self.add_module(pki.server.cli.config.SubsystemConfigCLI(self))
        self.add_module(pki.server.cli.db.SubsystemDBCLI(self))
        self.add_module(pki.server.cli.group.GroupCLI(self))
        self.add_module(CAProfileCLI())
        self.add_module(pki.server.cli.range.RangeCLI(self))
        self.add_module(pki.server.cli.id.IdCLI(self))
        self.add_module(pki.server.cli.user.UserCLI(self))
        self.add_module(pki.server.cli.acl.SubsystemACLCLI(self))
        self.add_module(pki.server.cli.sd.SubsystemSDCLI(self))


class CACertCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('cert', 'CA certificates management commands')

        self.add_module(CACertFindCLI())
        self.add_module(CACertCreateCLI())
        self.add_module(CACertImportCLI())
        self.add_module(CACertRemoveCLI())
        self.add_module(CACertChainCLI())
        self.add_module(CACertRequestCLI())


class CACertFindCLI(pki.cli.CLI):
    '''
    Find certificates in CA
    '''

    help = '''\
        Usage: pki-server ca-cert-find [OPTIONS]

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
              --status <status>              Certificate status: VALID, INVALID, REVOKED, EXPIRED, REVOKED_EXPIRED
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''  # noqa: E501

    def __init__(self):
        super().__init__('find', inspect.cleandoc(self.__class__.__doc__))

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--status')
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
        print(textwrap.dedent(self.__class__.help))


class CACertCreateCLI(pki.cli.CLI):
    '''
    Create certificate from certificate request in CA
    '''

    help = '''\
        Usage: pki-server ca-cert-create [OPTIONS]

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
              --csr <path>                   CSR path
              --csr-format <format>          CSR format: PEM (default), DER
              --request <ID>                 Request ID
              --profile <path>               Bootstrap profile path
              --type <type>                  Certificate type: selfsign (default), local
              --key-id <ID>                  Key ID
              --key-token <name>             Key token
              --key-algorithm <name>         Key algorithm (default: SHA256withRSA)
              --signing-algorithm <name>     Signing algorithm (default: SHA256withRSA)
              --serial <serial>              Certificate serial number
              --format <format>              Certificate format: PEM (default), DER
              --cert <path>                  Certificate path
              --import-cert                  Import certificate into CA database.
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''

    def __init__(self):
        super().__init__('create', inspect.cleandoc(self.__class__.__doc__))

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--csr')
        self.parser.add_argument(
            '--csr-format',
            default='PEM')
        self.parser.add_argument('--request')
        self.parser.add_argument('--profile')
        self.parser.add_argument(
            '--type',
            default='selfsign')
        self.parser.add_argument('--key-id')
        self.parser.add_argument('--key-token')
        self.parser.add_argument(
            '--key-algorithm',
            default='SHA256withRSA')
        self.parser.add_argument(
            '--signing-algorithm',
            default='SHA256withRSA')
        self.parser.add_argument('--serial')
        self.parser.add_argument(
            '--format',
            default='PEM')
        self.parser.add_argument('--cert')
        self.parser.add_argument(
            '--import-cert',
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

    def print_help(self):
        print(textwrap.dedent(self.__class__.help))


class CACertImportCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('import', 'Import certificate into CA')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--cert')
        self.parser.add_argument(
            '--format',
            default='PEM')
        self.parser.add_argument('--csr')
        self.parser.add_argument(
            '--csr-format',
            default='PEM')
        self.parser.add_argument('--profile')
        self.parser.add_argument('--request')
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
        print('Usage: pki-server ca-cert-import [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat)')
        print('      --cert <path>                  Certificate path')
        print('      --format <format>              Certificate format: PEM (default), DER')
        print('      --csr <path>                   CSR path')
        print('      --csr-format <format>          CSR format: PEM (default), DER')
        print('      --profile <path>               Bootstrap profile path')
        print('      --request <ID>                 Request ID')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()


class CACertRemoveCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('del', 'Remove certificate in CA')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
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
        self.parser.add_argument(
            'serial_number',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server ca-cert-remove [OPTIONS] <serial number>')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()


class CACertChainCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('chain', 'CA certificate chain management commands')

        self.add_module(CACertChainExportCLI())


class CACertChainExportCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('export', 'Export certificate chain')

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
        print('Usage: pki-server ca-cert-chain-export [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --pkcs12-file <path>           PKCS #12 file to store certificates and keys.')
        print('      --pkcs12-password <password>   Password for the PKCS #12 file.')
        print('      --pkcs12-password-file <path>  File containing the PKCS #12 password.')
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

        pkcs12_password = None

        if args.pkcs12_password:
            pkcs12_password = args.pkcs12_password.encode()

        if args.pkcs12_password_file:
            with io.open(args.pkcs12_password_file, 'rb') as f:
                pkcs12_password = f.read()

        if not pkcs12_file:
            logger.error('Missing PKCS #12 file')
            self.print_help()
            sys.exit(1)

        if not pkcs12_password:
            logger.error('Missing PKCS #12 password')
            self.print_help()
            sys.exit(1)

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        tmpdir = tempfile.mkdtemp()

        try:
            pkcs12_password_file = os.path.join(tmpdir, 'pkcs12_password.txt')
            with open(pkcs12_password_file, 'wb') as f:
                f.write(pkcs12_password)

            subsystem.export_cert_chain(pkcs12_file, pkcs12_password_file)

        finally:
            shutil.rmtree(tmpdir)


class CACertRequestCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('request', 'CA certificate requests management commands')

        self.add_module(CACertRequestFindCLI())
        self.add_module(CACertRequestShowCLI())
        self.add_module(CACertRequestImportCLI())

    @staticmethod
    def print_request(request, details=False):
        print('  Request ID: %s' % request['id'])
        print('  Type: %s' % request['type'])
        print('  Status: %s' % request['status'])

        if details:
            print('  Request: %s' % request['request'])


class CACertRequestFindCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('find', 'Find CA certificate requests')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--cert')
        self.parser.add_argument('--cert-file')
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
        print('Usage: pki-server ca-cert-request-find [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --cert                         Issued certificate.')
        print('      --cert-file                    File containing issued certificate.')
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
        cert = args.cert

        if args.cert_file:
            with io.open(args.cert_file, 'rb') as f:
                cert = f.read()

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        results = subsystem.find_cert_requests(cert=cert)

        self.print_message('%s entries matched' % len(results))

        first = True
        for request in results:
            if first:
                first = False
            else:
                print()

            CACertRequestCLI.print_request(request)


class CACertRequestShowCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('show', 'Show CA certificate request')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--output-file')
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
            'request_id',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server ca-cert-request-show [OPTIONS] <request ID>')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --output-file <file_name>      Save request in file.')
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
        output_file = args.output_file
        request_id = args.request_id

        if request_id is None:
            raise pki.cli.CLIException('Missing request ID')

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        request = subsystem.get_cert_requests(request_id)

        if output_file:
            with io.open(output_file, 'wb') as f:
                f.write(request['request'].encode())

        else:
            CACertRequestCLI.print_request(request, details=True)


class CACertRequestImportCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('import', 'Import certificate request into CA')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--csr')
        self.parser.add_argument(
            '--format',
            default='PEM')
        self.parser.add_argument('--profile')
        self.parser.add_argument('--request')
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
        print('Usage: pki-server ca-cert-request-import [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>     Instance ID (default: pki-tomcat)')
        print('      --csr <path>                 Certificate request path')
        print('      --format <format>            Certificate request format: PEM (default), DER')
        print('      --profile <path>             Bootstrap profile path')
        print('      --request <ID>               Certificate request ID')
        print('  -v, --verbose                    Run in verbose mode.')
        print('      --debug                      Run in debug mode.')
        print('      --help                       Show help message.')
        print()


class CACRLCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('crl', 'CA CRL configuration management commands')

        self.add_module(CACRLShowCLI())
        self.add_module(CACRLIPCLI())
        self.add_module(CACRLRecordCLI())

    @staticmethod
    def print_crl_config(config):

        output = f'''
            Page Size: {config.get('pageSize')}
        '''

        print(textwrap.indent(textwrap.dedent(output).strip(), '  '))


class CACRLShowCLI(pki.cli.CLI):
    '''
    Show CRL configuration in CA
    '''

    help = '''\
        Usage: pki-server ca-crl-show [OPTIONS]

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''  # noqa: E501

    def __init__(self):
        super().__init__('show', inspect.cleandoc(self.__class__.__doc__))

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
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
        print(textwrap.dedent(self.__class__.help))

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
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        config = subsystem.get_crl_config()
        CACRLCLI.print_crl_config(config)


class CACRLIPCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('ip', 'CA CRL issuing point configuration management commands')

        self.add_module(CACRLIPFindCLI())
        self.add_module(CACRLIPShowCLI())
        self.add_module(CACRLIPModifyCLI())

    @staticmethod
    def print_crl_issuing_point_config(ip_id, config, details=False):

        output = f'''
            ID: {ip_id}
            Description: {config.get('description')}
            Class: {config.get('class')}
            Enable: {config.get('enable')}
        '''

        print(textwrap.indent(textwrap.dedent(output).strip(), '  '))

        if not details:
            return

        output = f'''
            Allow Extensions: {config.get('allowExtensions')}
            Always Update: {config.get('alwaysUpdate')}
            Auto Update Interval (minutes): {config.get('autoUpdateInterval')}
            CA Certs Only: {config.get('caCertsOnly')}
            Cache Update Interval (minutes): {config.get('cacheUpdateInterval')}
            Unexpected Exception Wait Time (minutes): {config.get('unexpectedExceptionWaitTime')}
            Unexpected Exception Loop Max: {config.get('unexpectedExceptionLoopMax')}
            Daily Updates: {config.get('dailyUpdates')}
            Enable CRL Cache: {config.get('enableCRLCache')}
            Enable CRL Updates: {config.get('enableCRLUpdates')}
            Enable Cache Testing: {config.get('enableCacheTesting')}
            Enable Cache Recovery: {config.get('enableCacheRecovery')}
            Enable Daily Updates: {config.get('enableDailyUpdates')}
            Enable Update Interval: {config.get('enableUpdateInterval')}
            Extended Next Update: {config.get('extendedNextUpdate')}
            Include Expired Certs: {config.get('includeExpiredCerts')}
            Min Update Interval (minutes): {config.get('minUpdateInterval')}
            Next Update Grace Period (minutes): {config.get('nextUpdateGracePeriod')}
            Publish On Start: {config.get('publishOnStart')}
            Save Memory: {config.get('saveMemory')}
            Signing Algorithm: {config.get('signingAlgorithm')}
            Update Schema: {config.get('updateSchema')}
        '''

        print(textwrap.indent(textwrap.dedent(output).strip(), '  '))


class CACRLIPFindCLI(pki.cli.CLI):
    '''
    Find CRL issuing point configurations in CA
    '''

    help = '''\
        Usage: pki-server ca-crl-ip-find [OPTIONS]

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''  # noqa: E501

    def __init__(self):
        super().__init__('find', inspect.cleandoc(self.__class__.__doc__))

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
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
        print(textwrap.dedent(self.__class__.help))

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
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        ids = subsystem.find_crl_issuing_point_ids()

        first = True
        for ip_id in ids:
            if first:
                first = False
            else:
                print()

            config = subsystem.get_crl_issuing_point_config(ip_id)
            CACRLIPCLI.print_crl_issuing_point_config(ip_id, config)


class CACRLIPShowCLI(pki.cli.CLI):
    '''
    Show CRL issuing point configuration in CA
    '''

    help = '''\
        Usage: pki-server ca-crl-ip-show [OPTIONS] <id>

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''  # noqa: E501

    def __init__(self):
        super().__init__('show', inspect.cleandoc(self.__class__.__doc__))

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
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
        self.parser.add_argument(
            'id',
            nargs='?')

    def print_help(self):
        print(textwrap.dedent(self.__class__.help))

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
        ip_id = args.id

        if ip_id is None:
            raise pki.cli.CLIException('Missing CRL issuing point ID')

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        config = subsystem.get_crl_issuing_point_config(ip_id)
        CACRLIPCLI.print_crl_issuing_point_config(ip_id, config, details=True)


class CACRLIPModifyCLI(pki.cli.CLI):
    '''
    Modify CRL issuing point configuration in CA
    '''

    help = '''\
        Usage: pki-server ca-crl-ip-mod [OPTIONS] <id>

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
              --desc <value>                 Issuing point description
              --class <value>                Issuing point class
              --enable <value>               Enable issuing point (default: true)
              -D <name>=<value>              Issuing point parameter
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''  # noqa: E501

    def __init__(self):
        super().__init__('mod', inspect.cleandoc(self.__class__.__doc__))

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--desc')
        self.parser.add_argument('--class')
        self.parser.add_argument(
            '--enable',
            default='true')
        self.parser.add_argument(
            '-D',
            action='append')
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
            'id',
            nargs='?')

    def print_help(self):
        print(textwrap.dedent(self.__class__.help))

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
        ip_id = args.id

        if ip_id is None:
            raise pki.cli.CLIException('Missing CRL issuing point ID')

        config = {}
        for param in args.D:
            i = param.index('=')
            name = param[0:i]
            value = param[i + 1:]
            config[name] = value

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        subsystem.update_crl_issuing_point_config(ip_id, config)
        subsystem.save()


class CACRLRecordCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('record', 'CRL record management commands')

        self.add_module(CACRLRecordShowCLI())
        self.add_module(CACRLRecordCertCLI())


class CACRLRecordShowCLI(pki.cli.CLI):
    '''
    Show CRL record
    '''

    help = '''\
        Usage: pki-server ca-crl-record-show [OPTIONS] <CRL Record ID>

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''  # noqa: E501

    def __init__(self):
        super().__init__('show', inspect.cleandoc(self.__class__.__doc__))

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
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
        self.parser.add_argument(
            'id',
            nargs='?')

    def print_help(self):
        print(textwrap.dedent(self.__class__.help))


class CACRLRecordCertCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('cert', 'Revoked certificate management commands')

        self.add_module(CACRLRecordCertFindCLI())


class CACRLRecordCertFindCLI(pki.cli.CLI):
    '''
    Find revoked certificates in CRL record
    '''

    help = '''\
        Usage: pki-server ca-crl-record-cert-find [OPTIONS] <CRL Record ID>

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''  # noqa: E501

    def __init__(self):
        super().__init__('find', inspect.cleandoc(self.__class__.__doc__))

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
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
        self.parser.add_argument(
            'id',
            nargs='?')

    def print_help(self):
        print(textwrap.dedent(self.__class__.help))


class CACloneCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('clone', 'CA clone management commands')

        self.add_module(CAClonePrepareCLI())


class CAClonePrepareCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('prepare', 'Prepare CA clone')

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
            '--no-key',
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

    def print_help(self):
        print('Usage: pki-server ca-clone-prepare [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --pkcs12-file <path>           PKCS #12 file to store certificates and keys.')
        print('      --pkcs12-password <password>   Password for the PKCS #12 file.')
        print('      --pkcs12-password-file <path>  File containing the PKCS #12 password.')
        print('      --no-key                       Do not include private key.')
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

        pkcs12_password = None

        if args.pkcs12_password:
            pkcs12_password = args.pkcs12_password.encode()

        if args.pkcs12_password_file:
            with io.open(args.pkcs12_password_file, 'rb') as f:
                pkcs12_password = f.read()

        no_key = args.no_key

        if not pkcs12_file:
            logger.error('Missing PKCS #12 file')
            self.print_help()
            sys.exit(1)

        if not pkcs12_password:
            logger.error('Missing PKCS #12 password')
            self.print_help()
            sys.exit(1)

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        tmpdir = tempfile.mkdtemp()

        try:
            pkcs12_password_file = os.path.join(tmpdir, 'pkcs12_password.txt')
            with open(pkcs12_password_file, 'wb') as f:
                f.write(pkcs12_password)

            subsystem.export_system_cert(
                'subsystem', pkcs12_file, pkcs12_password_file, no_key=no_key)
            subsystem.export_system_cert(
                'signing', pkcs12_file, pkcs12_password_file, no_key=no_key, append=True)
            subsystem.export_system_cert(
                'ocsp_signing', pkcs12_file, pkcs12_password_file, no_key=no_key, append=True)

            # audit signing cert is optional
            cert = subsystem.get_subsystem_cert('audit_signing')

            # export audit signing cert if available (i.e. has nickname)
            if cert['nickname']:
                subsystem.export_system_cert(
                    'audit_signing',
                    pkcs12_file,
                    pkcs12_password_file,
                    no_key=no_key,
                    append=True)

            instance.export_external_certs(
                pkcs12_file, pkcs12_password_file, append=True)

        finally:
            shutil.rmtree(tmpdir)


class CAConnectorCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('connector', 'CA connector management commands')

        self.add_module(CAConnectorFindCLI())
        self.add_module(CAConnectorAddCLI())

    @staticmethod
    def print_connector(connector, show_all=False):

        connector_id = connector.get('id')
        print('  Connector ID: {}'.format(connector_id))

        enabled = connector.get('enabled')
        print('  Enabled: {}'.format(enabled))

        urls = connector.get('urls')
        print('  URL: {}'.format(' '.join(urls)))

        nickname = connector.get('nickname')
        print('  Nickname: {}'.format(nickname))

        if not show_all:
            return

        local = connector.get('local')
        print('  Local: {}'.format(local))

        path = connector.get('path')
        print('  Path: {}'.format(path))

        minConns = connector.get('minConns')
        if minConns:
            print('  Min Connections: {}'.format(minConns))

        maxConns = connector.get('maxConns')
        if maxConns:
            print('  Max Cconnections: {}'.format(maxConns))

        timeout = connector.get('timeout')
        if timeout:
            print('  Timeout: {}'.format(timeout))

        transportCert = connector.get('transportCert')
        if transportCert:
            print('  Transport Cert: {}'.format(transportCert))

        clientCiphers = connector.get('clientCiphers')
        if clientCiphers:
            print('  Client Ciphers: {}'.format(' '.join(clientCiphers)))

        certRevocationCheck = connector.get('certRevocationCheck')
        if certRevocationCheck:
            print('  Cert Revocation Rheck: {}'.format(certRevocationCheck))


class CAConnectorFindCLI(pki.cli.CLI):
    '''
    Find CA connectors
    '''

    help = '''\
        Usage: pki-server ca-connector-find [OPTIONS]

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
              --show-all                     Show all attributes.
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''  # noqa: E501

    def __init__(self):
        super().__init__('find', inspect.cleandoc(self.__class__.__doc__))

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--show-all',
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

    def print_help(self):
        print(textwrap.dedent(self.__class__.help))

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
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ca')

        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        first = True

        for connector in subsystem.get_connectors():

            if first:
                first = False
            else:
                print()

            CAConnectorCLI.print_connector(connector, args.show_all)


class CAConnectorAddCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('add', 'Add CA connector')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--url',
            action='append')
        self.parser.add_argument('--nickname')
        self.parser.add_argument('--transport-cert')
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
            'connector_id',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server ca-connector-add [OPTIONS] <connector ID>')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat)')
        print('      --url <URL>                    Subsystem URL')
        print('      --nickname <nickname>          Certificate nickname')
        print('      --transport-cert <path>        Transport certificate')
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
        connector_id = args.connector_id

        if connector_id is None:
            raise pki.cli.CLIException('Missing connector ID')

        urls = []
        for url in args.url:
            urls.append(urllib.parse.urlparse(url))

        nickname = args.nickname

        with open(args.transport_cert, 'r', encoding='utf-8') as f:
            transport_cert = f.read()

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ca')

        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        subsystem.add_connector(
            connector_id=connector_id,
            urls=urls,
            nickname=nickname,
            transport_cert=transport_cert)

        subsystem.save()


class CAProfileCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('profile', 'CA profile management commands')

        self.add_module(CAProfileFindCLI())
        self.add_module(CAProfileImportCLI())
        self.add_module(CAProfileModifyCLI())

    @staticmethod
    def print_profile(profile):
        print('  Profile ID: %s' % profile.get('id'))
        print('  Name: %s' % profile.get('name'))
        print('  Description: %s' % profile.get('desc'))
        print('  Visible: %s' % profile.get('visible'))
        print('  Enable: %s' % profile.get('enable'))


class CAProfileFindCLI(pki.cli.CLI):
    '''
    Find profiles in CA
    '''

    help = '''\
        Usage: pki-server ca-profile-find [OPTIONS]

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''  # noqa: E501

    def __init__(self):
        super().__init__('find', inspect.cleandoc(self.__class__.__doc__))

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
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
        print(textwrap.dedent(self.__class__.help))

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
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        profiles = subsystem.get_profiles()

        first = True
        for profile in profiles:
            if first:
                first = False
            else:
                print()

            CAProfileCLI.print_profile(profile)


class CAProfileImportCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('import', 'Import CA profiles')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--input-folder',
            default='/usr/share/pki/ca/profiles/ca')
        self.parser.add_argument(
            '--as-current-user',
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

    def print_help(self):
        print('Usage: pki-server ca-profile-import [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --input-folder <path>          '
              'Input folder (default: /usr/share/pki/ca/profiles/ca)')
        print('      --as-current-user              Run as current user.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()


class CAProfileModifyCLI(pki.cli.CLI):
    '''
    Modify profile in CA
    '''

    help = '''\
        Usage: pki-server ca-profile-mod [OPTIONS] <profile ID>

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
              --name <name>                  Profile name')
              --desc <description>           Profile description')
              --visible <boolean>            Profile visibile')
              --enabled <boolean>            Profile enabled')
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''  # noqa: E501

    def __init__(self):
        super().__init__('mod', inspect.cleandoc(self.__class__.__doc__))

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--name')
        self.parser.add_argument('--desc')
        self.parser.add_argument('--visible')
        self.parser.add_argument('--enabled')
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
            'profile_id',
            nargs='?')

    def print_help(self):
        print(textwrap.dedent(self.__class__.help))

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

        profile_name = args.name
        profile_description = args.desc
        profile_visible = args.visible
        profile_enabled = args.enabled

        profile_id = args.profile_id

        if profile_id is None:
            raise pki.cli.CLIException('Missing profile ID')

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        profile = subsystem.get_profile(profile_id)

        if profile_name is not None:
            profile['name'] = profile_name

        if profile_description is not None:
            profile['desc'] = profile_description

        if profile_visible is not None:
            profile['visible'] = profile_visible

        if profile_enabled is not None:
            profile['enable'] = profile_enabled

        subsystem.update_profile(profile_id, profile)

        CAProfileCLI.print_profile(profile)
