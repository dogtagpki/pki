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

from __future__ import absolute_import
from __future__ import print_function
import getopt
import sys

import pki.cli
import pki.nssdb
import pki.server
import pki.server.cli.nuxwdog


class HTTPCLI(pki.cli.CLI):

    def __init__(self):
        super(HTTPCLI, self).__init__(
            'http', 'HTTP management commands')

        self.add_module(HTTPConnectorCLI())


class HTTPConnectorCLI(pki.cli.CLI):

    def __init__(self):
        super(HTTPConnectorCLI, self).__init__(
            'connector', 'HTTP connector management commands')

        self.add_module(HTTPConnectorFindCLI())
        self.add_module(HTTPConnectorShowCLI())
        self.add_module(HTTPConnectorModCLI())

    @staticmethod
    def print_param(connector, name, label):

        value = connector.get(name)
        if value:
            print('  %s: %s' % (label, value))

    @staticmethod
    def set_param(connector, name, value):

        if value is None:
            return

        if value:  # non-empty
            connector.set(name, value)

        else:
            connector.attrib.pop(name)

    @staticmethod
    def print_connector(connector):

        HTTPConnectorCLI.print_param(connector, 'name', 'Connector ID')
        HTTPConnectorCLI.print_param(connector, 'scheme', 'Scheme')
        HTTPConnectorCLI.print_param(connector, 'port', 'Port')
        HTTPConnectorCLI.print_param(connector, 'protocol', 'Protocol')

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


class HTTPConnectorFindCLI(pki.cli.CLI):

    def __init__(self):
        super(HTTPConnectorFindCLI, self).__init__('find', 'Find connectors')

    def print_help(self):
        print('Usage: pki-server http-connector-find [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: Unknown option: %s' % o)
                self.print_help()
                sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)

        if not instance.is_valid():
            print('ERROR: Invalid instance: %s' % instance_name)
            sys.exit(1)

        instance.load()

        server_config = instance.get_server_config()
        connectors = server_config.get_connectors()

        self.print_message('%s entries matched' % len(connectors))

        first = True
        for name in connectors:

            if first:
                first = False
            else:
                print()

            connector = connectors[name]
            HTTPConnectorCLI.print_connector(connector)


class HTTPConnectorShowCLI(pki.cli.CLI):

    def __init__(self):
        super(HTTPConnectorShowCLI, self).__init__('show', 'Show connector')

    def print_help(self):
        print('Usage: pki-server http-connector-show [OPTIONS] <connector ID>')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: Unknown option: %s' % o)
                self.print_help()
                sys.exit(1)

        if len(args) != 1:
            print('ERROR: Missing connector ID')
            self.print_help()
            sys.exit(1)

        name = args[0]

        instance = pki.server.PKIInstance(instance_name)

        if not instance.is_valid():
            print('ERROR: Invalid instance: %s' % instance_name)
            sys.exit(1)

        instance.load()

        server_config = instance.get_server_config()
        connectors = server_config.get_connectors()

        if name not in connectors:
            print('ERROR: Connector not found: %s' % name)
            sys.exit(1)

        connector = connectors[name]
        HTTPConnectorCLI.print_connector(connector)


class HTTPConnectorModCLI(pki.cli.CLI):

    def __init__(self):
        super(HTTPConnectorModCLI, self).__init__('mod', 'Modify connector')

    def print_help(self):
        print('Usage: pki-server http-connector-mod [OPTIONS] <connector ID>')
        print()
        print('  -i, --instance <instance ID>              Instance ID (default: pki-tomcat).')
        print('      --type <type>                         Connector type: JSS (default), JSSE.')
        print('      --nss-database-dir <dir>              NSS database directory.')
        print('      --nss-password-file <file>            NSS password file.')
        print('      --keystore-file <file>                Key store file.')
        print('      --keystore-password-file <file>       Key store password file.')
        print('      --server-cert-nickname-file <file>    Server certificate nickname file.')
        print('  -v, --verbose                             Run in verbose mode.')
        print('      --help                                Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'type=',
                'nss-database-dir=', 'nss-password-file=',
                'keystore-file=', 'keystore-password-file=',
                'server-cert-nickname-file=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        connector_type = 'JSS'
        nss_database_dir = None
        nss_password_file = None
        keystore_file = None
        keystore_password_file = None
        server_cert_nickname_file = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--type':
                connector_type = a

            elif o == '--nss-database-dir':
                nss_database_dir = a

            elif o == '--nss-password-file':
                nss_password_file = a

            elif o == '--keystore-file':
                keystore_file = a

            elif o == '--keystore-password-file':
                keystore_password_file = a

            elif o == '--server-cert-nickname-file':
                server_cert_nickname_file = a

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: Unknown option: %s' % o)
                self.print_help()
                sys.exit(1)

        if len(args) != 1:
            print('ERROR: Missing connector ID')
            self.print_help()
            sys.exit(1)

        name = args[0]

        instance = pki.server.PKIInstance(instance_name)

        if not instance.is_valid():
            print('ERROR: invalid instance: %s' % instance_name)
            sys.exit(1)

        instance.load()

        server_config = instance.get_server_config()
        connectors = server_config.get_connectors()

        if name not in connectors:
            print('ERROR: Connector not found: %s' % name)
            sys.exit(1)

        connector = connectors[name]

        HTTPConnectorCLI.set_param(connector, 'certdbDir', nss_database_dir)
        HTTPConnectorCLI.set_param(connector, 'passwordClass',
                                   'org.apache.tomcat.util.net.jss.PlainPasswordFile')
        HTTPConnectorCLI.set_param(connector, 'passwordFile', nss_password_file)
        HTTPConnectorCLI.set_param(connector, 'serverCertNickFile', server_cert_nickname_file)

        if connector_type == 'JSS':

            connector.set(
                'protocol',
                'org.apache.coyote.http11.Http11Protocol')

            connector.set(
                'sslImplementationName',
                'org.apache.tomcat.util.net.jss.JSSImplementation')

            connector.attrib.pop('keystoreType', None)
            connector.attrib.pop('keystoreFile', None)
            connector.attrib.pop('keystorePassFile', None)
            connector.attrib.pop('keyAlias', None)

            connector.attrib.pop('trustManagerClassName', None)

        elif connector_type == 'JSSE':

            connector.set(
                'protocol',
                'org.dogtagpki.tomcat.Http11NioProtocol')

            connector.attrib.pop('sslImplementationName', None)

            HTTPConnectorCLI.set_param(connector, 'keystoreType', 'pkcs12')
            HTTPConnectorCLI.set_param(connector, 'keystoreFile', keystore_file)
            HTTPConnectorCLI.set_param(connector, 'keystorePassFile', keystore_password_file)
            HTTPConnectorCLI.set_param(connector, 'keyAlias', 'sslserver')

            HTTPConnectorCLI.set_param(connector, 'trustManagerClassName',
                                       'org.dogtagpki.tomcat.PKITrustManager')

        else:
            raise Exception('Invalid connector type: %s' % connector_type)

        server_config.save()

        self.print_message('Updated connector')
        HTTPConnectorCLI.print_connector(connector)
