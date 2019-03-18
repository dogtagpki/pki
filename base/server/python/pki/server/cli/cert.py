# Authors:
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
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
# Copyright (C) 2015-2017 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
from __future__ import print_function

from contextlib import contextmanager
import datetime
import getopt
import getpass
import logging
import os
import random
import subprocess
import sys
from tempfile import NamedTemporaryFile
import time

from six.moves.urllib.parse import quote  # pylint: disable=F0401,E0611

import pki.cert
import pki.cli
import pki.nssdb
import pki.server as server

logger = logging.getLogger(__name__)


class CertCLI(pki.cli.CLI):
    def __init__(self):
        super(CertCLI, self).__init__('cert',
                                      'System certificate management commands')
        self.add_module(CertFindCLI())
        self.add_module(CertUpdateCLI())
        self.add_module(CertCreateCLI())
        self.add_module(CertImportCLI())
        self.add_module(CertExportCLI())
        self.add_module(CertRemoveCLI())
        self.add_module(CertFixCLI())

    @staticmethod
    def print_system_cert(cert, show_all=False):
        print('  Cert ID: %s' % cert['id'])
        print('  Nickname: %s' % cert['nickname'])

        token = cert.get('token')
        if token:
            print('  Token: %s' % token)

        serial_number = cert.get('serial_number')
        if serial_number:
            print('  Serial Number: %s' % hex(serial_number))

        subject = cert.get('subject')
        if subject:
            print('  Subject DN: %s' % subject)

        issuer = cert.get('issuer')
        if issuer:
            print('  Issuer DN: %s' % issuer)

        not_before = cert.get('not_before')
        if not_before:
            print('  Not Valid Before: %s' % CertCLI.convert_millis_to_date(not_before))

        not_after = cert.get('not_after')
        if not_after:
            print('  Not Valid After: %s' % CertCLI.convert_millis_to_date(not_after))

        if show_all:
            print('  Certificate: %s' % cert['data'])
            print('  Request: %s' % cert['request'])

    @staticmethod
    def convert_millis_to_date(millis):
        return datetime.datetime.fromtimestamp(millis / 1000.0).strftime("%a %b %d %H:%M:%S %Y")


class CertFindCLI(pki.cli.CLI):
    def __init__(self):
        super(CertFindCLI, self).__init__(
            'find', 'Find system certificates.')

    def print_help(self):
        print('Usage: pki-server cert-find [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('      --show-all                  Show all attributes.')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        logging.basicConfig(format='%(levelname)s: %(message)s')

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'show-all',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        show_all = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--show-all':
                show_all = True

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                self.set_verbose(True)
                self.set_debug(True)
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('option %s not recognized', o)
                self.print_help()
                sys.exit(1)

        instance = server.PKIInstance(instance_name)

        if not instance.is_valid():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        first = True
        results = []

        for subsystem in instance.subsystems:

            # Retrieve the subsystem's system certificate
            certs = subsystem.find_system_certs()

            # Iterate on all subsystem's system certificate to prepend subsystem name to the ID
            for cert in certs:

                if cert['id'] != 'sslserver' and cert['id'] != 'subsystem':
                    cert['id'] = subsystem.name + '_' + cert['id']

                # Append only unique certificates to other subsystem certificate list
                if cert['id'] in results:
                    continue

                results.append(cert['id'])

                if first:
                    first = False
                else:
                    print()

                CertCLI.print_system_cert(cert, show_all)


class CertUpdateCLI(pki.cli.CLI):
    def __init__(self):
        super(CertUpdateCLI, self).__init__(
            'update', 'Update system certificate.')

    def print_help(self):
        print('Usage: pki-server cert-update [OPTIONS] <cert ID>')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        logging.basicConfig(format='%(levelname)s: %(message)s')

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
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
                self.set_verbose(True)
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                self.set_verbose(True)
                self.set_debug(True)
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('option %s not recognized', o)
                self.print_help()
                sys.exit(1)

        if len(args) < 1:
            logger.error('Missing cert ID.')
            self.print_help()
            sys.exit(1)

        cert_id = args[0]

        instance = server.PKIInstance(instance_name)

        if not instance.is_valid():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name, cert_tag = server.PKIServer.split_cert_id(cert_id)

        # If cert ID is instance specific, get it from first subsystem
        if not subsystem_name:
            subsystem_name = instance.subsystems[0].name

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error(
                'No %s subsystem in instance %s.',
                subsystem_name, instance_name)
            sys.exit(1)

        subsystem_cert = subsystem.get_subsystem_cert(cert_tag)

        logger.info(
            'Retrieving certificate %s from %s',
            subsystem_cert['nickname'],
            subsystem_cert['token'])

        token = subsystem_cert['token']
        nssdb = instance.open_nssdb(token)

        # Get the cert data from NSS DB
        data = nssdb.get_cert(
            nickname=subsystem_cert['nickname'],
            output_format='base64')
        subsystem_cert['data'] = data

        # format cert data for LDAP database
        lines = [data[i:i + 64] for i in range(0, len(data), 64)]
        data = '\r\n'.join(lines) + '\r\n'

        # Get the cert request from LDAP database
        logger.info('Retrieving certificate request from CA database')

        # TODO: add support for remote CA
        ca = instance.get_subsystem('ca')
        if not ca:
            logger.error('No CA subsystem in instance %s.', instance_name)
            sys.exit(1)

        results = ca.find_cert_requests(cert=data)

        if results:
            cert_request = results[-1]
            request = cert_request['request']

            # format cert request for CS.cfg
            lines = request.splitlines()
            if lines[0] == '-----BEGIN CERTIFICATE REQUEST-----':
                lines = lines[1:]
            if lines[-1] == '-----END CERTIFICATE REQUEST-----':
                lines = lines[:-1]
            request = ''.join(lines)
            subsystem_cert['request'] = request

        else:
            print('WARNING: Certificate request not found')

        instance.cert_update_config(cert_id, subsystem_cert)

        self.print_message('Updated "%s" system certificate' % cert_id)


class CertCreateCLI(pki.cli.CLI):
    def __init__(self):
        super(CertCreateCLI, self).__init__(
            'create', 'Create system certificate.')

    def print_help(self):
        print('Usage: pki-server cert-create [OPTIONS] <Cert ID>')
        # CertID:  subsystem, sslserver, kra_storage, kra_transport, ca_ocsp_signing,
        # ca_audit_signing, kra_audit_signing
        # ca.cert.list=signing,ocsp_signing,sslserver,subsystem,audit_signing
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -d <database>                   Security database location '
              '(default: ~/.dogtag/nssdb)')
        print('  -c <NSS DB password>            NSS database password')
        print('  -C <path>                       Input file containing the password for the'
              ' NSS database.')
        print('  -n <nickname>                   Client certificate nickname')
        print('      --temp                      Create temporary certificate.')
        print('      --serial <number>           Provide serial number for the certificate.')
        print('      --output <file>             Provide output file name.')
        print('      --renew                     Renew permanent certificate.')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        logging.basicConfig(format='%(levelname)s: %(message)s')

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:d:c:C:n:v', [
                'instance=', 'temp', 'serial=',
                'output=', 'renew',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        temp_cert = False
        serial = None
        client_nssdb = os.getenv('HOME') + '/.dogtag/nssdb'
        client_nssdb_password = None
        client_nssdb_pass_file = None
        client_cert = None
        output = None
        renew = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '-d':
                client_nssdb = a

            elif o == '-c':
                client_nssdb_password = a

            elif o == '-C':
                client_nssdb_pass_file = a

            elif o == '-n':
                client_cert = a

            elif o == '--temp':
                temp_cert = True

            elif o == '--serial':
                # string containing the dec or hex value for the identifier
                serial = str(int(a, 0))

            elif o == '--output':
                output = a

            elif o == '--renew':
                renew = True

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                self.set_verbose(True)
                self.set_debug(True)
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('option %s not recognized', o)
                self.print_help()
                sys.exit(1)

        if len(args) < 1:
            logger.error('Missing cert ID.')
            self.print_help()
            sys.exit(1)

        if not temp_cert:
            # For permanent certificate, password of NSS db is required.
            if not client_nssdb_password and not client_nssdb_pass_file:
                logger.error('NSS database password is required.')
                self.print_help()
                sys.exit(1)

        cert_id = args[0]

        instance = server.PKIInstance(instance_name)

        if not instance.is_valid():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        # Load the instance. Default: pki-tomcat
        instance.load()

        try:
            instance.cert_create(
                cert_id=cert_id,
                client_cert=client_cert, client_nssdb=client_nssdb,
                client_nssdb_pass=client_nssdb_password,
                client_nssdb_pass_file=client_nssdb_pass_file,
                serial=serial, temp_cert=temp_cert, renew=renew, output=output)

        except server.PKIServerException as e:
            logger.error(str(e))
            sys.exit(1)


class CertImportCLI(pki.cli.CLI):
    def __init__(self):
        super(CertImportCLI, self).__init__(
            'import', 'Import system certificate.')

    def print_help(self):
        print('Usage: pki-server cert-import [OPTIONS] <Cert ID>')
        # CertID:  subsystem, sslserver, kra_storage, kra_transport, ca_ocsp_signing,
        # ca_audit_signing, kra_audit_signing
        # ca.cert.list=signing,ocsp_signing,sslserver,subsystem,audit_signing
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('      --input <file>              Provide input file name.')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        logging.basicConfig(format='%(levelname)s: %(message)s')

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'input=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        cert_file = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--input':
                cert_file = a

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                self.set_verbose(True)
                self.set_debug(True)
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('option %s not recognized', o)
                self.print_help()
                sys.exit(1)

        if len(args) < 1:
            logger.error('Missing cert ID.')
            self.print_help()
            sys.exit(1)

        cert_id = args[0]

        instance = server.PKIInstance(instance_name)

        if not instance.is_valid():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        # Load the instance. Default: pki-tomcat
        instance.load()

        try:
            # Load the cert into NSS db and update all corresponding subsystem's CS.cfg
            instance.cert_import(cert_id, cert_file)

        except server.PKIServerException as e:
            logger.error(str(e))
            sys.exit(1)


class CertExportCLI(pki.cli.CLI):
    def __init__(self):
        super(CertExportCLI, self).__init__(
            'export', 'Export system certificate.')

    def usage(self):  # flake8: noqa
        print('Usage: pki-server cert-export [OPTIONS] <Cert ID>')
        print()
        print('Specify at least one output file: certificate, CSR, or PKCS #12.')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --cert-file <path>             Output file to store the exported certificate in PEM format.')
        print('      --csr-file <path>              Output file to store the exported CSR in PEM format.')
        print('      --pkcs12-file <path>           Output file to store the exported certificate and key in PKCS #12 format.')
        print('      --pkcs12-password <password>   Password for the PKCS #12 file.')
        print('      --pkcs12-password-file <path>  Input file containing the password for the PKCS #12 file.')
        print('      --append                       Append into an existing PKCS #12 file.')
        print('      --no-trust-flags               Do not include trust flags')
        print('      --no-key                       Do not include private key')
        print('      --no-chain                     Do not include certificate chain')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'cert-file=', 'csr-file=',
                'pkcs12-file=', 'pkcs12-password=', 'pkcs12-password-file=',
                'append', 'no-trust-flags', 'no-key', 'no-chain',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.usage()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        cert_file = None
        csr_file = None
        pkcs12_file = None
        pkcs12_password = None
        pkcs12_password_file = None
        append = False
        include_trust_flags = True
        include_key = True
        include_chain = True
        debug = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--cert-file':
                cert_file = a

            elif o == '--csr-file':
                csr_file = a

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

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--debug':
                debug = True

            elif o == '--help':
                self.usage()
                sys.exit()

            else:
                self.print_message('ERROR: unknown option ' + o)
                self.usage()
                sys.exit(1)

        if len(args) < 1:
            print('ERROR: missing cert ID')
            self.usage()
            sys.exit(1)

        cert_id = args[0]

        if not (cert_file or csr_file or pkcs12_file):
            print('ERROR: missing output file')
            self.usage()
            sys.exit(1)

        instance = server.PKIInstance(instance_name)

        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name, cert_tag = server.PKIServer.split_cert_id(cert_id)

        # If cert ID is instance specific, get it from first subsystem
        if not subsystem_name:
            subsystem_name = instance.subsystems[0].name

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            print('ERROR: No %s subsystem in instance.'
                  '%s.' % (subsystem_name, instance_name))
            sys.exit(1)

        nssdb = instance.open_nssdb()

        try:
            cert = subsystem.get_subsystem_cert(cert_tag)

            if not cert:
                print('ERROR: missing %s certificate' % cert_id)
                self.usage()
                sys.exit(1)

            if cert_file:

                if self.verbose:
                    print('Exporting %s certificate into %s.' % (cert_id, cert_file))

                cert_data = cert.get('data', None)
                if cert_data is None:
                    print("ERROR: Unable to find certificate data for %s" % cert_id)
                    sys.exit(1)

                cert_data = pki.nssdb.convert_cert(cert_data, 'base64', 'pem')
                with open(cert_file, 'w') as f:
                    f.write(cert_data)

            if csr_file:

                if self.verbose:
                    print('Exporting %s CSR into %s.' % (cert_id, csr_file))

                cert_request = cert.get('request', None)
                if cert_request is None:
                    print("ERROR: Unable to find certificate request for %s" % cert_id)
                    sys.exit(1)

                csr_data = pki.nssdb.convert_csr(cert_request, 'base64', 'pem')
                with open(csr_file, 'w') as f:
                    f.write(csr_data)

            if pkcs12_file:

                if self.verbose:
                    print('Exporting %s certificate and key into %s.' % (cert_id, pkcs12_file))

                if not pkcs12_password and not pkcs12_password_file:
                    pkcs12_password = getpass.getpass(prompt='Enter password for PKCS #12 file: ')

                nicknames = []
                nicknames.append(cert['nickname'])

                nssdb.export_pkcs12(
                    pkcs12_file=pkcs12_file,
                    pkcs12_password=pkcs12_password,
                    pkcs12_password_file=pkcs12_password_file,
                    nicknames=nicknames,
                    append=append,
                    include_trust_flags=include_trust_flags,
                    include_key=include_key,
                    include_chain=include_chain,
                    debug=debug)

        finally:
            nssdb.close()


class CertRemoveCLI(pki.cli.CLI):
    def __init__(self):
        super(CertRemoveCLI, self).__init__(
            'del', 'Remove system certificate.')

    def print_help(self):
        print('Usage: pki-server cert-del [OPTIONS] <Cert ID>')
        # CertID:  subsystem, sslserver, kra_storage, kra_transport, ca_ocsp_signing,
        # ca_audit_signing, kra_audit_signing
        # ca.cert.list=signing,ocsp_signing,sslserver,subsystem,audit_signing
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('      --remove-key                Remove key.')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        logging.basicConfig(format='%(levelname)s: %(message)s')

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'remove-key',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        remove_key = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--remove-key':
                remove_key = True

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                self.set_verbose(True)
                self.set_debug(True)
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('option %s not recognized', o)
                self.print_help()
                sys.exit(1)

        if len(args) < 1:
            logger.error('Missing cert ID.')
            self.print_help()
            sys.exit(1)

        cert_id = args[0]

        instance = server.PKIInstance(instance_name)

        if not instance.is_valid():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        # Load the instance. Default: pki-tomcat
        instance.load()

        logger.info('Removing %s certificate from NSS database', cert_id)
        instance.cert_del(cert_id=cert_id, remove_key=remove_key)


class CertFixCLI(pki.cli.CLI):
    def __init__(self):
        super(CertFixCLI, self).__init__(
            'fix', 'Fix expired system certificate(s).')

    PKIDBUSER_LDIF_TEMPLATE = (
        "dn: {dn}\n"
        "changetype: modify\n"
        "add: userCertificate\n"
        "userCertificate:< file://{der_file}\n"
    )

    def print_help(self):  # flake8: noqa
        print('Usage: pki-server cert-fix [OPTIONS]')
        # CertID:  subsystem, sslserver, kra_storage, kra_transport, ca_ocsp_signing,
        # ca_audit_signing, kra_audit_signing
        # ca.cert.list=signing,ocsp_signing,sslserver,subsystem,audit_signing
        print()
        print('      --cert <Cert ID>            Fix specified system cert (default: all certs).')
        print('      --extra-cert <Serial>       Also renew cert with given serial number.')
        print('      --agent-uid <String>        UID of Dogtag agent user')
        print('      --ldapi-socket <Path>       Path to DS LDAPI socket')
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):
        logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'cert=', 'extra-cert=', 'agent-uid=',
                'ldapi-socket=', 'verbose', 'debug', 'help',
            ])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        all_certs = True
        fix_certs = []
        extra_certs = []
        agent_uid = None
        ldap_url = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--cert':
                all_certs = False
                fix_certs.append(a)

            elif o == '--extra-cert':
                try:
                    int(a)
                except ValueError:
                    logger.error('--extra-cert requires serial number as integer')
                    sys.exit(1)
                all_certs = False
                extra_certs.append(a)

            elif o == '--agent-uid':
                agent_uid = a

            elif o == '--ldapi-socket':
                ldap_url = 'ldapi://{}'.format(quote(a, safe=''))

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--debug':
                self.set_verbose(True)
                self.set_debug(True)
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('option %s not recognized', o)
                self.print_help()
                sys.exit(1)

        instance = server.PKIInstance(instance_name)

        if not instance.is_valid():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        if not agent_uid:
            logger.error('Must specify --agent-uid')
            sys.exit(1)

        if not ldap_url:
            logger.error('Must specify --ldapi-socket')
            sys.exit(1)

        instance.load()

        # 1. Make a list of certs to fix OR use the list provided through CLI options
        if all_certs:
            # TODO: Identify only certs that are EXPIRED or ALMOST EXPIRED
            for subsystem in instance.subsystems:
                # Retrieve the subsystem's system certificate
                certs = subsystem.find_system_certs()

                # Iterate on all subsystem's system certificate to prepend
                # subsystem name to the ID
                for cert in certs:
                    if cert['id'] != 'sslserver' and cert['id'] != 'subsystem':
                        cert['id'] = subsystem.name + '_' + cert['id']

                    # Append only unique certificates to other subsystem certificate list
                    # ca_signing isn't supported yet
                    if cert['id'] in fix_certs or cert['id'] == 'ca_signing':
                        continue

                    fix_certs.append(cert['id'])

        logger.info('Fixing the following system certs: %s', fix_certs)
        logger.info('Renewing the following additional certs: %s', extra_certs)

        # Get the CA subsystem and find out Base DN.
        ca_subsystem = instance.get_subsystem('ca')
        basedn = ca_subsystem.get_db_config()['internaldb.basedn']
        dbuser_dn = 'uid=pkidbuser,ou=people,{}'.format(basedn)
        agent_dn = 'uid={},ou=people,{}'.format(agent_uid, basedn)

        # Verify LDAP connection
        try:
            subprocess.check_output([
                'ldapsearch', '-H', ldap_url, '-Y', 'EXTERNAL',
                '-s', 'base', '-b', basedn, '1.1',
            ])
        except subprocess.CalledProcessError:
            logger.error("Failed to connect to LDAP at %s", ldap_url)
            sys.exit(1)

        # 2. Stop the server, if it's up
        logger.info('Stopping the instance to proceed with system cert renewal')
        instance.stop()

        # 3. Find the subsystem and disable Self-tests
        try:
            # Placeholder used to hold subsystems whose selftest have been turned off
            # Note: This is initialized as a set to avoid duplicates
            # Example of duplicates:
            # fix_certs = [ca_ocsp_signing, ca_audit_signing] -> will add 'ca' entry twice
            target_subsys = set()

            if 'sslserver' in fix_certs or 'subsystem' in fix_certs:
                # If the cert is either sslserver/subsystem, disable selftest for all
                # subsystems since all subsystems use these 2 certs.
                target_subsys = set(instance.subsystems)

            else:
                for cert_id in fix_certs:
                    # Since we already filtered sslserver/subsystem, we can be quite sure
                    # that this split will definitely be of form: <subsys>_<cert_tag>
                    subsystem_name = cert_id.split('_', 1)[0]
                    subsystem = instance.get_subsystem(subsystem_name)

                    # If the subsystem is wrong, stop the process
                    if not subsystem:
                        logger.error('No %s subsystem in instance %s.',
                                     subsystem_name, instance_name)
                        sys.exit(1)

                    target_subsys.add(subsystem)

            if len(extra_certs) > 0:
                target_subsys.add(ca_subsystem)

            # Generate new password for agent account
            agent_pass = gen_random_password()

            with write_temp_file(agent_pass.encode('utf8')) as agent_pass_file, \
                    ldap_password_authn(instance, target_subsys, dbuser_dn, ldap_url), \
                    suppress_selftest(target_subsys):
                # Reset agent password
                logger.info('Resetting password for %s', agent_dn)
                ldappasswd(ldap_url, agent_dn, agent_pass_file)

                # 4. Bring up the server using a temp SSL cert if the sslcert is expired
                if 'sslserver' in fix_certs:
                    # 4a. Create temp SSL cert
                    logger.info('Creating a temporary sslserver cert')
                    instance.cert_create(cert_id='sslserver', temp_cert=True)

                    # 4b. Delete the existing SSL Cert
                    logger.debug('Removing sslserver cert from instance')
                    instance.cert_del('sslserver')

                    # 4d. Import the temp sslcert into the instance
                    logger.debug('Importing temp sslserver cert')
                    instance.cert_import('sslserver')

                with start_stop(instance):
                    # Place renewal request for all certs in fix_certs
                    for cert_id in fix_certs:
                        logger.info('Requesting new cert for %s', cert_id)
                        instance.cert_create(
                            cert_id=cert_id, renew=True,
                            username=agent_uid, password=agent_pass)
                    for serial in extra_certs:
                        output = instance.cert_file('{}-renewed'.format(serial))
                        logger.info(
                            'Requesting new cert for %s; writing to %s',
                            serial, output)
                        try:
                            instance.cert_create(
                                serial=serial, renew=True, output=output,
                                username=agent_uid, password=agent_pass)
                        except pki.PKIException as e:
                            logger.error("Failed to renew certificate %s: %s", serial, e)

                # 8. Delete existing certs and then import the renewed system cert(s)
                for cert_id in fix_certs:
                    # Delete the existing cert from the instance
                    logger.debug('Removing old %s cert from instance %s', cert_id, instance_name)
                    instance.cert_del(cert_id)

                    # Import this new cert into the instance
                    logger.debug('Importing new %s cert into instance %s', cert_id, instance_name)
                    instance.cert_import(cert_id)

                # If subsystem cert was renewed and server was using
                # TLS auth, add the cert to pkidbuser entry
                if dbuser_dn and 'subsystem' in fix_certs:
                    logger.info('Importing new subsystem cert into %s', dbuser_dn)
                    with NamedTemporaryFile(mode='w+b') as der_file:
                        # convert subsystem cert to DER
                        subprocess.check_call([
                            'openssl', 'x509',
                            '-inform', 'PEM', '-outform', 'DER',
                            '-in', instance.cert_file('subsystem'),
                            '-out', der_file.name,
                        ])

                        with write_temp_file(
                            self.PKIDBUSER_LDIF_TEMPLATE
                                .format(dn=dbuser_dn, der_file=der_file.name)
                                .encode('utf-8')
                        ) as ldif_file:
                            # ldapmodify
                            subprocess.check_call([
                                'ldapmodify', '-H', ldap_url, '-Y', 'EXTERNAL',
                                '-f', ldif_file,
                            ])

            # 10. Bring up the server
            logger.info('Starting the instance with renewed certs')
            instance.start()

        except server.PKIServerException as e:
            logger.error(str(e))
            sys.exit(1)


@contextmanager
def suppress_selftest(subsystems):
    """Suppress selftests in the given subsystems."""
    for subsystem in subsystems:
        subsystem.set_startup_test_criticality(False)
        subsystem.save()
    logger.info(
        'Selftests disabled for subsystems: %s',
        ', '.join(str(x.name) for x in subsystems))
    try:
        yield
    finally:
        for subsystem in subsystems:
            subsystem.set_startup_test_criticality(True)
            subsystem.save()
        logger.info(
            'Selftests enabled for subsystems: %s',
            ', '.join(str(x.name) for x in subsystems))


@contextmanager
def start_stop(instance):
    """Start the server, run the block, and guarantee stop afterwards."""
    logger.info('Starting the instance')
    instance.start()
    logger.info('Sleeping for 10 seconds to allow server time to start...')
    time.sleep(10)
    try:
        yield
    finally:
        logger.info('Stopping the instance')
        instance.stop()


@contextmanager
def ldap_password_authn(instance, subsystems, bind_dn, ldap_url):
    """LDAP password authentication context.

    This context manager switches the server to password
    authentication, runs the block, then restores the original
    subsystem configuration.

    Specifically:

    - if we are already using BasicAuth, force port 389 and no TLS/STARTTLS
      but leave everything else alone.

    - if using TLS client cert auth, switch to BasicAuth, using pkidbuser
      account, and using a randomly generated password.  The DM credential
      is required to set that password.

    This context manager yields the pkidbuser DN, so that the new
    subsystem certificate (if it was one of the renewal targets) can
    be added to the entry.  It is only yielded if the server was
    already using TLS client cert authn, otherwise the yielded value
    is ``None``.

    """
    logger.info('Configuring LDAP password authentication')
    orig = {}
    try:
        password = instance.passwords['internaldb']
    except KeyError:
        # generate a new password and write it to file
        password = gen_random_password()
        instance.passwords['internaldb'] = password
        instance.store_passwords()
        generated_password = True
    else:
        generated_password = False

    # We don't perform ldappasswd unless we need to (and only once).
    ldappasswd_performed = False

    for subsystem in subsystems:
        cfg = subsystem.get_db_config()
        orig[subsystem] = cfg.copy()  # copy because dict is mutable

        authtype = cfg['internaldb.ldapauth.authtype']
        if authtype == 'SslClientAuth':
            # switch to BasicAuth
            cfg['internaldb.ldapauth.authtype'] = 'BasicAuth'
            cfg['internaldb.ldapconn.port'] = '389'
            cfg['internaldb.ldapconn.secureConn'] = 'false'
            cfg['internaldb.ldapauth.bindDN'] = bind_dn

            # _now_ we can perform ldappasswd
            if not ldappasswd_performed:
                logger.info('Setting pkidbuser password via ldappasswd')
                with write_temp_file(password.encode('utf8')) as pwdfile:
                    ldappasswd(ldap_url, bind_dn, pwdfile)
                ldappasswd_performed = True

        elif authtype == 'BasicAuth':
            # force port 389, no TLS / STARTTLS.  Leave other settings alone.
            cfg['internaldb.ldapconn.port'] = '389'
            cfg['internaldb.ldapconn.secureConn'] = 'false'

        subsystem.set_db_config(cfg)
        subsystem.save()

    try:
        yield

    finally:
        logger.info('Restoring previous LDAP configuration')

        for subsystem, cfg in orig.items():
            subsystem.set_db_config(cfg)
            subsystem.save()

        if generated_password:
            del instance.passwords['internaldb']
            instance.store_passwords()


def ldappasswd(ldap_url, user_dn, pass_file):
    """
    Run ldappasswd as Directory Manager.

    Raise CalledProcessError on error.

    """
    subprocess.check_call([
        'ldappasswd', '-H', ldap_url, '-Y', 'EXTERNAL',
        '-T', pass_file, user_dn,
    ])


def gen_random_password():
    rnd = random.SystemRandom()
    xs = "abcdefghijklmnopqrstuvwxyz0123456789"
    return ''.join(rnd.choice(xs) for i in range(32))


@contextmanager
def write_temp_file(data):
    """Create a temporary file, write data to it, yield the filename."""
    with NamedTemporaryFile() as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
        yield f.name
