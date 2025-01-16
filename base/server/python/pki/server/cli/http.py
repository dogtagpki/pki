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
# Copyright (C) 2018 Red Hat, Inc.
# All rights reserved.
#

import inspect
import logging
import sys
import textwrap

import pki.cli
import pki.nssdb
import pki.server
import pki.server.cli.nuxwdog
import pki.util

logger = logging.getLogger(__name__)


class HTTPCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('http', 'HTTP management commands')

        self.add_module(HTTPConnectorCLI())


class HTTPConnectorCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('connector', 'HTTP connector management commands')

        self.add_module(HTTPConnectorAddCLI())
        self.add_module(HTTPConnectorDeleteCLI())
        self.add_module(HTTPConnectorFindCLI())
        self.add_module(HTTPConnectorModCLI())
        self.add_module(HTTPConnectorShowCLI())

        self.add_module(SSLHostCLI())
        self.add_module(SSLCertCLI())

    @staticmethod
    def print_param(element, name, label):

        value = element.get(name)
        if value:
            print('  %s: %s' % (label, value))

    @staticmethod
    def set_param(element, name, value):
        pki.util.set_property(element.attrib, name, value)

    @staticmethod
    def print_connector(connector):

        HTTPConnectorCLI.print_param(connector, 'name', 'Connector ID')
        HTTPConnectorCLI.print_param(connector, 'port', 'Port')
        HTTPConnectorCLI.print_param(connector, 'protocol', 'Protocol')
        HTTPConnectorCLI.print_param(connector, 'redirectPort', 'Redirect Port')
        HTTPConnectorCLI.print_param(connector, 'address', 'Address')
        HTTPConnectorCLI.print_param(connector, 'scheme', 'Scheme')
        HTTPConnectorCLI.print_param(connector, 'secure', 'Secure')
        HTTPConnectorCLI.print_param(connector, 'SSLEnabled', 'SSL Enabled')

        HTTPConnectorCLI.print_param(connector, 'sslImplementationName', 'SSL Implementation')

        HTTPConnectorCLI.print_param(connector, 'sslVersionRangeStream',
                                     'SSL Version Range Stream')
        HTTPConnectorCLI.print_param(connector, 'sslVersionRangeDatagram',
                                     'SSL Version Range Datagram')
        HTTPConnectorCLI.print_param(connector, 'sslRangeCiphers', 'SSL Range Ciphers')

        HTTPConnectorCLI.print_param(connector, 'certdbDir', 'NSS Database Directory')
        HTTPConnectorCLI.print_param(connector, 'passwordClass', 'NSS Password Class')
        HTTPConnectorCLI.print_param(connector, 'passwordFile', 'NSS Password File')
        HTTPConnectorCLI.print_param(connector, 'serverCertNickFile', 'Server Cert Nickname File')

        HTTPConnectorCLI.print_param(connector, 'keystoreFile', 'Keystore File')
        HTTPConnectorCLI.print_param(connector, 'keystorePassFile', 'Keystore Password File')

        HTTPConnectorCLI.print_param(connector, 'trustManagerClassName', 'Trust Manager')


class HTTPConnectorAddCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('add', 'Add connector')

    def create_parser(self, subparsers=None):

        self.parser = subparsers.add_parser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--port')
        self.parser.add_argument('--protocol')
        self.parser.add_argument('--scheme')
        self.parser.add_argument('--secure')
        self.parser.add_argument('--sslEnabled')
        self.parser.add_argument('--sslImpl')
        self.parser.add_argument('--sslProtocol')
        self.parser.add_argument('--certVerification')
        self.parser.add_argument('--trustManager')
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
        self.parser.add_argument('name')

    def print_help(self):
        print('Usage: pki-server http-connector-add [OPTIONS] <connector ID>')
        print()
        print('  -i, --instance <instance ID>              Instance ID (default: pki-tomcat).')
        print('      --port <port>                         Port number.')
        print('      --protocol <protocol>                 Protocol.')
        print('      --scheme <scheme>                     Scheme.')
        print('      --secure <true|false>                 Secure.')
        print('      --sslEnabled <true|false>             SSL enabled.')
        print('      --sslImpl <class>                     SSL implementation.')
        print('      --sslProtocol <protocol>              SSL protocol.')
        print('      --certVerification <verification>     Certificate verification.')
        print('      --trustManager <class>                Trust Manager.')
        print('  -v, --verbose                             Run in verbose mode.')
        print('      --debug                               Run in debug mode.')
        print('      --help                                Show help message.')
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
        port = args.port
        protocol = args.protocol
        scheme = args.scheme
        secure = args.secure
        sslEnabled = args.sslEnabled
        sslImpl = args.sslImpl
        sslProtocol = args.sslProtocol
        certVerification = args.certVerification
        trustManager = args.trustManager
        name = args.name

        if port is None:
            raise Exception('Missing port number')

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            print('ERROR: invalid instance: %s' % instance_name)
            sys.exit(1)

        instance.load()

        server_config = instance.get_server_config()

        connector = server_config.get_connector(name=name)

        if connector is not None:
            raise Exception('Connector already exists: %s' % name)

        connector = server_config.create_connector(name)

        HTTPConnectorCLI.set_param(connector, 'port', port)
        HTTPConnectorCLI.set_param(connector, 'protocol', protocol)
        HTTPConnectorCLI.set_param(connector, 'scheme', scheme)
        HTTPConnectorCLI.set_param(connector, 'secure', secure)
        HTTPConnectorCLI.set_param(connector, 'SSLEnabled', sslEnabled)
        HTTPConnectorCLI.set_param(connector, 'sslImplementationName', sslImpl)

        sslhost = server_config.create_sslhost(connector)

        HTTPConnectorCLI.set_param(sslhost, 'sslProtocol', sslProtocol)
        HTTPConnectorCLI.set_param(sslhost, 'certificateVerification', certVerification)
        HTTPConnectorCLI.set_param(sslhost, 'trustManagerClassName', trustManager)

        server_config.save()

        HTTPConnectorCLI.print_connector(connector)


class HTTPConnectorDeleteCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('del', 'Delete connector')

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
        self.parser.add_argument('name')

    def print_help(self):
        print('Usage: pki-server http-connector-del [OPTIONS] <connector ID>')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
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
        name = args.name

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            print('ERROR: Invalid instance: %s' % instance_name)
            sys.exit(1)

        instance.load()

        server_config = instance.get_server_config()
        server_config.remove_connector(name)
        server_config.save()


class HTTPConnectorFindCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('find', 'Find connectors')

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
        print('Usage: pki-server http-connector-find [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
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
            print('ERROR: Invalid instance: %s' % instance_name)
            sys.exit(1)

        instance.load()

        server_config = instance.get_server_config()
        connectors = server_config.get_connectors()

        self.print_message('%s entries matched' % len(connectors))

        first = True
        for connector in connectors:

            if first:
                first = False
            else:
                print()

            HTTPConnectorCLI.print_connector(connector)


class HTTPConnectorShowCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('show', 'Show connector')

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
        self.parser.add_argument('name')

    def print_help(self):
        print('Usage: pki-server http-connector-show [OPTIONS] <connector ID>')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
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
        name = args.name

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            print('ERROR: Invalid instance: %s' % instance_name)
            sys.exit(1)

        instance.load()

        server_config = instance.get_server_config()
        connector = server_config.get_connector(name=name)

        if connector is None:
            raise KeyError('Connector not found: %s' % name)

        HTTPConnectorCLI.print_connector(connector)


class HTTPConnectorModCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('mod', 'Modify connector')

    def create_parser(self, subparsers=None):

        self.parser = subparsers.add_parser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--type')
        self.parser.add_argument('--nss-database-dir')
        self.parser.add_argument('--nss-password-file')
        self.parser.add_argument('--keystore-file')
        self.parser.add_argument('--keystore-password-file')
        self.parser.add_argument('--server-cert-nickname-file')
        self.parser.add_argument('--port')
        self.parser.add_argument('--protocol')
        self.parser.add_argument('--scheme')
        self.parser.add_argument('--secure')
        self.parser.add_argument('--sslEnabled')
        self.parser.add_argument('--sslImp')
        self.parser.add_argument('--sslProtocol')
        self.parser.add_argument('--cartVerification')
        self.parser.add_argument('--trustManager')
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
        self.parser.add_argument('name')

    def print_help(self):
        print('Usage: pki-server http-connector-mod [OPTIONS] <connector ID>')
        print()
        print('  -i, --instance <instance ID>              Instance ID (default: pki-tomcat).')
        print('      --type <type>                         Connector type: JSS, JSSE.')
        print('      --nss-database-dir <dir>              NSS database directory.')
        print('      --nss-password-file <file>            NSS password file.')
        print('      --keystore-file <file>                Key store file.')
        print('      --keystore-password-file <file>       Key store password file.')
        print('      --server-cert-nickname-file <file>    Server certificate nickname file.')
        print('      --port <port>                         Port number.')
        print('      --protocol <protocol>                 Protocol.')
        print('      --scheme <scheme>                     Scheme.')
        print('      --secure <true|false>                 Secure.')
        print('      --sslEnabled <true|false>             SSL enabled.')
        print('      --sslImpl <class>                     SSL implementation.')
        print('  -v, --verbose                             Run in verbose mode.')
        print('      --debug                               Run in debug mode.')
        print('      --help                                Show help message.')
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
        connector_type = args.type
        nss_database_dir = args.nss_database_dir
        nss_password_file = args.nss_password_file
        keystore_file = args.keystore_file
        keystore_password_file = args.keystore_password_file
        server_cert_nickname_file = args.server_cert_nickname_file
        port = args.port
        protocol = args.protocol
        scheme = args.scheme
        secure = args.secure
        sslEnabled = args.sslEnabled
        sslImpl = args.sslImpl
        name = args.name

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            print('ERROR: invalid instance: %s' % instance_name)
            sys.exit(1)

        instance.load()

        server_config = instance.get_server_config()
        connector = server_config.get_connector(name=name)

        if connector is None:
            raise KeyError('Connector not found: %s' % name)

        if connector_type == 'JSS':

            connector.set(
                'protocol',
                'org.apache.coyote.http11.Http11Protocol')

            connector.set(
                'sslImplementationName',
                'org.dogtagpki.jss.tomcat.JSSImplementation')

            connector.attrib.pop('keystoreType', None)
            connector.attrib.pop('keystoreFile', None)
            connector.attrib.pop('keystorePassFile', None)
            connector.attrib.pop('keyAlias', None)

            connector.attrib.pop('trustManagerClassName', None)

            HTTPConnectorCLI.set_param(connector, 'certdbDir', nss_database_dir)
            HTTPConnectorCLI.set_param(connector, 'passwordClass',
                                       'org.dogtagpki.jss.tomcat.PlainPasswordFile')
            HTTPConnectorCLI.set_param(connector, 'passwordFile', nss_password_file)
            HTTPConnectorCLI.set_param(connector, 'serverCertNickFile', server_cert_nickname_file)

        elif connector_type == 'JSSE':

            connector.set(
                'protocol',
                'org.dogtagpki.jss.tomcat.Http11NioProtocol')

            connector.attrib.pop('sslImplementationName', None)

            HTTPConnectorCLI.set_param(connector, 'keystoreType', 'pkcs12')
            HTTPConnectorCLI.set_param(connector, 'keystoreFile', keystore_file)
            HTTPConnectorCLI.set_param(connector, 'keystorePassFile', keystore_password_file)
            HTTPConnectorCLI.set_param(connector, 'keyAlias', 'sslserver')

            HTTPConnectorCLI.set_param(connector, 'trustManagerClassName',
                                       'org.dogtagpki.tomcat.PKITrustManager')

            HTTPConnectorCLI.set_param(connector, 'certdbDir', nss_database_dir)
            HTTPConnectorCLI.set_param(connector, 'passwordClass',
                                       'org.dogtagpki.jss.tomcat.PlainPasswordFile')
            HTTPConnectorCLI.set_param(connector, 'passwordFile', nss_password_file)
            HTTPConnectorCLI.set_param(connector, 'serverCertNickFile', server_cert_nickname_file)

        else:

            HTTPConnectorCLI.set_param(connector, 'port', port)
            HTTPConnectorCLI.set_param(connector, 'protocol', protocol)
            HTTPConnectorCLI.set_param(connector, 'scheme', scheme)
            HTTPConnectorCLI.set_param(connector, 'secure', secure)
            HTTPConnectorCLI.set_param(connector, 'SSLEnabled', sslEnabled)
            HTTPConnectorCLI.set_param(connector, 'sslImplementationName', sslImpl)

        server_config.save()

        HTTPConnectorCLI.print_connector(connector)


class SSLHostCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('host', 'SSL host configuration management commands')

        self.add_module(SSLHostAddCLI())
        self.add_module(SSLHostDeleteCLI())
        self.add_module(SSLHostFindCLI())
        self.add_module(SSLHostModifyCLI())
        self.add_module(SSLHostShowCLI())

    @staticmethod
    def print_sslhost(sslhost):

        hostName = sslhost.get('hostName', '_default_')
        print('  Hostname: %s' % hostName)

        HTTPConnectorCLI.print_param(
            sslhost, 'sslProtocol', 'SSL Protocol')
        HTTPConnectorCLI.print_param(
            sslhost, 'certificateVerification', 'Certificate Verification')
        HTTPConnectorCLI.print_param(
            sslhost, 'trustManagerClassName', 'Trust Manager')


class SSLHostAddCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('add', 'Add SSL host configuration')

    def create_parser(self, subparsers=None):

        self.parser = subparsers.add_parser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--sslProtocol')
        self.parser.add_argument('--certVerification')
        self.parser.add_argument('--trustManager')
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
        self.parser.add_argument('connector_name')
        self.parser.add_argument('hostname')

    def print_help(self):
        print('Usage: pki-server http-connector-host-add [OPTIONS] <connector ID> <hostname>')
        print()
        print('  -i, --instance <instance ID>              Instance ID (default: pki-tomcat).')
        print('      --sslProtocol <protocol>              SSL protocol.')
        print('      --certVerification <verification>     Certificate verification.')
        print('      --trustManager <class>                Trust Manager.')
        print('  -v, --verbose                             Run in verbose mode.')
        print('      --debug                               Run in debug mode.')
        print('      --help                                Show help message.')
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
        sslProtocol = args.sslProtocol
        certVerification = args.certVerification
        trustManager = args.trustManager
        connector_name = args.connector_name
        hostname = args.hostname

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            print('ERROR: invalid instance: %s' % instance_name)
            sys.exit(1)

        instance.load()

        server_config = instance.get_server_config()
        connector = server_config.get_connector(name=connector_name)

        if connector is None:
            raise KeyError('Connector not found: %s' % connector_name)

        sslhost = server_config.get_sslhost(connector, hostname)

        if sslhost is not None:
            raise Exception('SSL host already exists: %s' % hostname)

        sslhost = server_config.create_sslhost(connector, hostname)

        HTTPConnectorCLI.set_param(sslhost, 'sslProtocol', sslProtocol)
        HTTPConnectorCLI.set_param(sslhost, 'certificateVerification', certVerification)
        HTTPConnectorCLI.set_param(sslhost, 'trustManagerClassName', trustManager)

        server_config.save()

        SSLHostCLI.print_sslhost(sslhost)


class SSLHostDeleteCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('del', 'Delete SSL host configuration')

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
        self.parser.add_argument('connector_name')
        self.parser.add_argument('hostname')

    def print_help(self):
        print('Usage: pki-server http-connector-host-del [OPTIONS] <connector ID> <hostname>')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
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
        connector_name = args.connector_name
        hostname = args.hostname

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            print('ERROR: Invalid instance: %s' % instance_name)
            sys.exit(1)

        instance.load()

        server_config = instance.get_server_config()
        connector = server_config.get_connector(name=connector_name)

        if connector is None:
            raise KeyError('Connector not found: %s' % connector_name)

        server_config.remove_sslhost(connector, hostname)

        server_config.save()


class SSLHostFindCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('find', 'Find SSL host configurations')

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
        self.parser.add_argument('connector_name')

    def print_help(self):
        print('Usage: pki-server http-connector-sslhost-find [OPTIONS] <connector ID>')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
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
        connector_name = args.connector_name

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            print('ERROR: Invalid instance: %s' % instance_name)
            sys.exit(1)

        instance.load()

        server_config = instance.get_server_config()
        connector = server_config.get_connector(name=connector_name)

        if connector is None:
            raise KeyError('Connector not found: %s' % connector_name)

        sslhosts = server_config.get_sslhosts(connector)

        self.print_message('%s entries matched' % len(sslhosts))

        first = True
        for sslhost in sslhosts:

            if first:
                first = False
            else:
                print()

            SSLHostCLI.print_sslhost(sslhost)


class SSLHostModifyCLI(pki.cli.CLI):
    '''
    Modify SSL host configuration
    '''

    help = '''\
        Usage: pki-server http-connector-host-mod [OPTIONS] <connector ID> <hostname>

          -i, --instance <instance ID>              Instance ID (default: pki-tomcat)
              --sslProtocol <protocol>              SSL protocol
              --certVerification <verification>     Certificate verification
              --trustManager <class>                Trust manager
          -v, --verbose                             Run in verbose mode.
              --debug                               Run in debug mode.
              --help                                Show help message.
        '''

    def __init__(self):
        super().__init__('mod', inspect.cleandoc(self.__class__.__doc__))

    def create_parser(self, subparsers=None):

        self.parser = subparsers.add_parser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--sslProtocol')
        self.parser.add_argument('--certVerification')
        self.parser.add_argument('--trustManager')
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
        self.parser.add_argument('connector_name')
        self.parser.add_argument('hostname')

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
        sslProtocol = args.sslProtocol
        certVerification = args.certVerification
        trustManager = args.trustManager
        connector_name = args.connector_name
        hostname = args.hostname

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        server_config = instance.get_server_config()
        connector = server_config.get_connector(name=connector_name)

        if connector is None:
            logger.error('Connector not found: %s', connector_name)
            sys.exit(1)

        sslhost = server_config.get_sslhost(connector, hostname)

        if sslhost is None:
            logger.error('SSL host not found: %s', hostname)
            sys.exit(1)

        HTTPConnectorCLI.set_param(sslhost, 'sslProtocol', sslProtocol)
        HTTPConnectorCLI.set_param(sslhost, 'certificateVerification', certVerification)
        HTTPConnectorCLI.set_param(sslhost, 'trustManagerClassName', trustManager)

        server_config.save()

        SSLHostCLI.print_sslhost(sslhost)


class SSLHostShowCLI(pki.cli.CLI):
    '''
    Display SSL host configuration
    '''

    help = '''\
        Usage: pki-server http-connector-host-show [OPTIONS] <connector ID> <hostname>

          -i, --instance <instance ID>    Instance ID (default: pki-tomcat)
          -v, --verbose                   Run in verbose mode.
              --debug                     Run in debug mode.
              --help                      Show help message.
    '''

    def __init__(self):
        super().__init__('show', inspect.cleandoc(self.__class__.__doc__))

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
        self.parser.add_argument('connector_name')
        self.parser.add_argument('hostname')

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
        connector_name = args.connector_name
        hostname = args.hostname

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        server_config = instance.get_server_config()
        connector = server_config.get_connector(name=connector_name)

        if connector is None:
            logger.error('Connector not found: %s', connector_name)

        sslhost = server_config.get_sslhost(connector, hostname)

        if sslhost is None:
            logger.error('SSL host not found: %s', hostname)
            sys.exit(1)

        SSLHostCLI.print_sslhost(sslhost)


class SSLCertCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('cert', 'SSL certificate configuration management commands')

        self.add_module(SSLCertAddCLI())
        self.add_module(SSLCertDeleteCLI())
        self.add_module(SSLCertFindLI())

    @staticmethod
    def print_sslcert(sslcert):

        certType = sslcert.get('type', 'UNDEFINED')
        print('  Type: %s' % certType)

        HTTPConnectorCLI.print_param(
            sslcert, 'certificateFile', 'Certificate File')
        HTTPConnectorCLI.print_param(
            sslcert, 'certificateKeyFile', 'Key File')
        HTTPConnectorCLI.print_param(
            sslcert, 'certificateKeyAlias', 'Key Alias')
        HTTPConnectorCLI.print_param(
            sslcert, 'certificateKeystoreType', 'Keystore Type')
        HTTPConnectorCLI.print_param(
            sslcert, 'certificateKeystoreProvider', 'Keystore Provider')
        HTTPConnectorCLI.print_param(
            sslcert, 'certificateKeystoreFile', 'Keystore File')


class SSLCertAddCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('add', 'Add SSL certificate configuration')

    def create_parser(self, subparsers=None):

        self.parser = subparsers.add_parser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--connector',
            default='Secure')
        self.parser.add_argument(
            '--sslHost',
            default='_default_')
        self.parser.add_argument('--certFile')
        self.parser.add_argument('--keyAlias')
        self.parser.add_argument('--keyFile')
        self.parser.add_argument('--keystoreType')
        self.parser.add_argument('--keystoreProvider')
        self.parser.add_argument('--keystoreFile')
        self.parser.add_argument('--keystorePassword')
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
            'type',
            nargs='?',
            default='UNDEFINED')

    def print_help(self):
        print('Usage: pki-server http-connector-cert-add '
              '[OPTIONS] [<type>]')
        print()
        print('  -i, --instance <instance ID>              Instance ID (default: pki-tomcat).')
        print('      --connector <connector ID>            Connector ID (default: Secure).')
        print('      --sslHost <hostname>                  SSL host (default: _default_).')
        print('      --certFile <path>                     Certificate file.')
        print('      --keyAlias <alias>                    Key alias.')
        print('      --keyFile <path>                      Key file.')
        print('      --keystoreType <type>                 Keystore type.')
        print('      --keystoreProvider <name>             Keystore provider.')
        print('      --keystoreFile <path>                 Keystore file.')
        print('      --keystorePassword <password>         Keystore password.')
        print('  -v, --verbose                             Run in verbose mode.')
        print('      --debug                               Run in debug mode.')
        print('      --help                                Show help message.')
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
        connector_name = args.connector
        hostname = args.sslHost
        certFile = args.certFile
        keyAlias = args.keyAlias
        keyFile = args.keyFile
        keystoreType = args.keystoreType
        keystoreProvider = args.keystoreProvider
        keystoreFile = args.keystoreFile
        keystorePassword = args.keystorePassword
        certType = args.type

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            print('ERROR: invalid instance: %s' % instance_name)
            sys.exit(1)

        instance.load()

        server_config = instance.get_server_config()
        connector = server_config.get_connector(name=connector_name)

        if connector is None:
            raise KeyError('Connector not found: %s' % connector_name)

        sslhost = server_config.get_sslhost(connector, hostname)

        if sslhost is None:
            raise Exception('SSL host not found: %s' % hostname)

        sslcert = server_config.get_sslcert(sslhost, certType)

        if sslcert is not None:
            raise Exception('SSL certificate already exists: %s' % certType)

        sslcert = server_config.create_sslcert(sslhost, certType)

        HTTPConnectorCLI.set_param(sslcert, 'certificateFile', certFile)
        HTTPConnectorCLI.set_param(sslcert, 'certificateKeyAlias', keyAlias)
        HTTPConnectorCLI.set_param(sslcert, 'certificateKeyFile', keyFile)
        HTTPConnectorCLI.set_param(sslcert, 'certificateKeystoreType', keystoreType)
        HTTPConnectorCLI.set_param(sslcert, 'certificateKeystoreProvider', keystoreProvider)
        HTTPConnectorCLI.set_param(sslcert, 'certificateKeystoreFile', keystoreFile)
        HTTPConnectorCLI.set_param(sslcert, 'certificateKeystorePassword', keystorePassword)

        server_config.save()

        SSLCertCLI.print_sslcert(sslcert)


class SSLCertDeleteCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('del', 'Delete SSL certificate configuration')

    def create_parser(self, subparsers=None):

        self.parser = subparsers.add_parser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--connector',
            default='Secure')
        self.parser.add_argument(
            '--sslHost',
            default='_default_')
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
            'type',
            nargs='?',
            default='UNDEFINED')

    def print_help(self):
        print('Usage: pki-server http-connector-cert-del '
              '[OPTIONS] [<type>]')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('      --connector <connector ID>  Connector ID (default: Secure).')
        print('      --sslHost <hostname>        SSL host (default: _default_).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
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
        connector_name = args.connector
        hostname = args.sslHost
        certType = args.type

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            print('ERROR: Invalid instance: %s' % instance_name)
            sys.exit(1)

        instance.load()

        server_config = instance.get_server_config()
        connector = server_config.get_connector(name=connector_name)

        if connector is None:
            raise KeyError('Connector not found: %s' % connector_name)

        sslhost = server_config.get_sslhost(connector, hostname)

        if sslhost is None:
            raise Exception('SSL host not found: %s' % hostname)

        server_config.remove_sslcert(sslhost, certType)

        server_config.save()


class SSLCertFindLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('find', 'Find SSL certificate configurations')

    def create_parser(self, subparsers=None):

        self.parser = subparsers.add_parser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--connector',
            default='Secure')
        self.parser.add_argument(
            '--sslHost',
            default='_default_')
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
        print('Usage: pki-server http-connector-cert-find '
              '[OPTIONS]')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('      --connector <connector ID>  Connector ID (default: Secure).')
        print('      --sslHost <hostname>        SSL host (default: _default_).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
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
        connector_name = args.connector
        hostname = args.sslHost

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            print('ERROR: Invalid instance: %s' % instance_name)
            sys.exit(1)

        instance.load()

        server_config = instance.get_server_config()
        connector = server_config.get_connector(name=connector_name)

        if connector is None:
            raise KeyError('Connector not found: %s' % connector_name)

        sslhost = server_config.get_sslhost(connector, hostname)

        if sslhost is None:
            raise Exception('SSL host not found: %s' % hostname)

        sslcerts = server_config.get_sslcerts(sslhost)

        self.print_message('%s entries matched' % len(sslcerts))

        first = True
        for sslcert in sslcerts:

            if first:
                first = False
            else:
                print()

            SSLCertCLI.print_sslcert(sslcert)
