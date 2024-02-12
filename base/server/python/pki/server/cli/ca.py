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
import inspect
import io
import logging
import os
import shutil
import sys
import tempfile
import textwrap

import pki.cli
import pki.server
import pki.server.cli.audit
import pki.server.cli.config
import pki.server.cli.db
import pki.server.cli.group
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
        self.add_module(pki.server.cli.config.SubsystemConfigCLI(self))
        self.add_module(pki.server.cli.db.SubsystemDBCLI(self))
        self.add_module(pki.server.cli.group.GroupCLI(self))
        self.add_module(CAProfileCLI())
        self.add_module(pki.server.cli.range.RangeCLI(self))
        self.add_module(pki.server.cli.user.UserCLI(self))


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

    def print_help(self):
        print(textwrap.dedent(self.__class__.help))

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'status=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        status = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--status':
                status = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
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

        subsystem.find_certs(
            status=status)


class CACertCreateCLI(pki.cli.CLI):
    '''
    Create certificate from certificate request in CA
    '''

    help = '''\
        Usage: pki-server ca-cert-create [OPTIONS]

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
              --request <ID>                 Request ID
              --profile <ID>                 Bootstrap profile filename
              --type <type>                  Certificate type: selfsign (default), local
              --key-id <ID>                  Key ID
              --key-token <name>             Key token
              --key-algorithm <name>         Key algorithm (default: SHA256withRSA)
              --signing-algorithm <name>     Signing algorithm (default: SHA256withRSA)
              --serial <serial>              Certificate serial number
              --format <format>              Certificate format: PEM (default), DER
              --cert <path>                  Certificate path
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''

    def __init__(self):
        super().__init__('create', inspect.cleandoc(self.__class__.__doc__))

    def print_help(self):
        print(textwrap.dedent(self.__class__.help))

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'request=', 'profile=', 'type=',
                'key-id=', 'key-token=', 'key-algorithm=',
                'signing-algorithm=',
                'serial=', 'format=', 'cert=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        request_id = None
        profile_id = None
        cert_type = None
        key_id = None
        key_token = None
        key_algorithm = None
        signing_algorithm = None
        serial = None
        cert_format = None
        cert_path = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--request':
                request_id = a

            elif o == '--profile':
                profile_id = a

            elif o == '--type':
                cert_type = a

            elif o == '--key-id':
                key_id = a

            elif o == '--key-token':
                key_token = a

            elif o == '--key-algorithm':
                key_algorithm = a

            elif o == '--signing-algorithm':
                signing_algorithm = a

            elif o == '--serial':
                serial = a

            elif o == '--format':
                cert_format = a

            elif o == '--cert':
                cert_path = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
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

        cert_data = subsystem.create_cert(
            request_id=request_id,
            profile_id=profile_id,
            cert_type=cert_type,
            key_token=key_token,
            key_id=key_id,
            key_algorithm=key_algorithm,
            signing_algorithm=signing_algorithm,
            serial=serial,
            cert_format=cert_format)

        if cert_path:
            with open(cert_path, 'wb') as f:
                f.write(cert_data)

        else:
            sys.stdout.buffer.write(cert_data)


class CACertImportCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('import', 'Import certificate into CA')

    def print_help(self):
        print('Usage: pki-server ca-cert-import [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat)')
        print('      --cert <path>                  Certificate path')
        print('      --format <format>              Certificate format: PEM (default), DER')
        print('      --profile <path>               Bootstrap profile path')
        print('      --request <ID>                 Request ID')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'cert=', 'format=', 'profile=', 'request=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        cert_path = None
        cert_format = None
        profile_path = None
        request_id = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--cert':
                cert_path = a

            elif o == '--format':
                cert_format = a

            elif o == '--profile':
                profile_path = a

            elif o == '--request':
                request_id = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
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

        subsystem.import_cert(
            cert_path=cert_path,
            cert_format=cert_format,
            profile_path=profile_path,
            request_id=request_id)


class CACertRemoveCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('del', 'Remove certificate in CA')

    def print_help(self):
        print('Usage: pki-server ca-cert-remove [OPTIONS] <serial number>')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        if len(args) != 1:
            logger.error('Missing serial number')
            self.print_help()
            sys.exit(1)

        serial_number = args[0]
        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
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

        subsystem.remove_cert(serial_number)


class CACertChainCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('chain', 'CA certificate chain management commands')

        self.add_module(CACertChainExportCLI())


class CACertChainExportCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('export', 'Export certificate chain')

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

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'pkcs12-file=', 'pkcs12-password=', 'pkcs12-password-file=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        pkcs12_file = None
        pkcs12_password = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--pkcs12-file':
                pkcs12_file = a

            elif o == '--pkcs12-password':
                pkcs12_password = a.encode()

            elif o == '--pkcs12-password-file':
                with io.open(a, 'rb') as f:
                    pkcs12_password = f.read()

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

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

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'cert=', 'cert-file=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        cert = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--cert':
                cert = a

            elif o == '--cert-file':
                with io.open(a, 'rb') as f:
                    cert = f.read()

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
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

    def print_help(self):
        print('Usage: pki-server ca-cert-request-show [OPTIONS] <request ID>')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --output-file <file_name>      Save request in file.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'output-file=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        if len(args) != 1:
            logger.error('Missing request ID')
            self.print_help()
            sys.exit(1)

        request_id = args[0]
        instance_name = 'pki-tomcat'
        output_file = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--output-file':
                output_file = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
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

        request = subsystem.get_cert_requests(request_id)

        if output_file:
            with io.open(output_file, 'wb') as f:
                f.write(request['request'].encode())

        else:
            CACertRequestCLI.print_request(request, details=True)


class CACertRequestImportCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('import', 'Import certificate request into CA')

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

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'csr=', 'format=', 'profile=', 'request=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        request_path = None
        request_format = None
        profile_path = None
        request_id = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--csr':
                request_path = a

            elif o == '--format':
                request_format = a

            elif o == '--profile':
                profile_path = a

            elif o == '--request':
                request_id = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
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

        result = subsystem.import_cert_request(
            request_path=request_path,
            request_format=request_format,
            profile_path=profile_path,
            request_id=request_id)

        request_id = result['requestID']
        print('  Request ID: %s' % request_id)


class CACRLCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('crl', 'CA CRL configuration management commands')

        self.add_module(CACRLShowCLI())
        self.add_module(CACRLIPCLI())

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

    def print_help(self):
        print(textwrap.dedent(self.__class__.help))

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
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

    def print_help(self):
        print(textwrap.dedent(self.__class__.help))

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
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

    def print_help(self):
        print(textwrap.dedent(self.__class__.help))

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        if len(args) != 1:
            logger.error('Missing CRL issuing point ID')
            self.print_help()
            sys.exit(1)

        ip_id = args[0]
        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
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

    def print_help(self):
        print(textwrap.dedent(self.__class__.help))

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:D:v', [
                'instance=', 'desc=', 'class=', 'enable=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        if len(args) != 1:
            logger.error('Missing CRL issuing point ID')
            self.print_help()
            sys.exit(1)

        ip_id = args[0]
        instance_name = 'pki-tomcat'
        config = {}

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--desc':
                config['description'] = a

            elif o == '--class':
                config['class'] = a

            elif o == '--enable':
                config['enable'] = a

            elif o == '-D':
                i = a.index('=')
                name = a[0:i]
                value = a[i + 1:]
                config[name] = value

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
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

        subsystem.update_crl_issuing_point_config(ip_id, config)
        subsystem.save()


class CACloneCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('clone', 'CA clone management commands')

        self.add_module(CAClonePrepareCLI())


class CAClonePrepareCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('prepare', 'Prepare CA clone')

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

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'pkcs12-file=', 'pkcs12-password=', 'pkcs12-password-file=',
                'no-key',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        pkcs12_file = None
        pkcs12_password = None
        no_key = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--pkcs12-file':
                pkcs12_file = a

            elif o == '--pkcs12-password':
                pkcs12_password = a.encode()

            elif o == '--pkcs12-password-file':
                with io.open(a, 'rb') as f:
                    pkcs12_password = f.read()

            elif o == '--no-key':
                no_key = True

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

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
            subsystem.export_system_cert(
                'audit_signing', pkcs12_file, pkcs12_password_file, no_key=no_key, append=True)
            instance.export_external_certs(
                pkcs12_file, pkcs12_password_file, append=True)

        finally:
            shutil.rmtree(tmpdir)


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

    def print_help(self):
        print(textwrap.dedent(self.__class__.help))

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
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

    def print_help(self):
        print('Usage: pki-server ca-profile-import [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --input-folder <path>          Input folder.')
        print('      --as-current-user              Run as current user.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'input-folder=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        input_folder = '/usr/share/pki/ca/profiles/ca'
        as_current_user = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--input-folder':
                input_folder = a

            elif o == '--as-current-user':
                as_current_user = True

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
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

        subsystem.import_profiles(
            input_folder=input_folder,
            as_current_user=as_current_user)


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
              --enable <boolean>             Profile enabled')
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''  # noqa: E501

    def __init__(self):
        super().__init__('mod', inspect.cleandoc(self.__class__.__doc__))

    def print_help(self):
        print(textwrap.dedent(self.__class__.help))

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'name=', 'desc=', 'visible=', 'enabled=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        if len(args) < 1:
            logger.error('Missing profile ID')
            self.print_help()
            sys.exit(1)

        profile_id = args[0]

        instance_name = 'pki-tomcat'
        profile_name = None
        profile_description = None
        profile_visible = None
        profile_enabled = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--name':
                profile_name = a

            elif o == '--desc':
                profile_description = a

            elif o == '--visible':
                profile_visible = a

            elif o == '--enabled':
                profile_enabled = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
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
