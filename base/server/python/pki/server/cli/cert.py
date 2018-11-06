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

import datetime
import getopt
import getpass
import logging
import os
import sys

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
        self.add_module(CertShowCLI())
        self.add_module(CertUpdateCLI())
        self.add_module(CertCreateCLI())
        self.add_module(CertImportCLI())
        self.add_module(CertExportCLI())
        self.add_module(CertRemoveCLI())

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


class CertShowCLI(pki.cli.CLI):
    def __init__(self):
        super(CertShowCLI, self).__init__(
            'show', 'Display system certificate details.')

    def print_help(self):
        print('Usage: pki-server cert-show [OPTIONS] <cert ID>')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('      --show-all                  Show all attributes.')
        print('      --pretty-print              Pretty print.')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        logging.basicConfig(format='%(levelname)s: %(message)s')

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'show-all', 'pretty-print',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        show_all = False
        pretty_print = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--show-all':
                show_all = True

            elif o == '--pretty-print':
                pretty_print = True

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

        cert = subsystem.get_subsystem_cert(cert_tag)
        CertCLI.print_system_cert(cert, show_all)

        if pretty_print:
            nssdb = instance.open_nssdb()
            try:
                output = nssdb.get_cert(
                    nickname=cert['nickname'],
                    token=cert['token'],
                    output_format='pretty-print')

                print()
                print(output)

            finally:
                nssdb.close()


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
            instance.cert_create(cert_id, client_cert, client_nssdb, client_nssdb_password,
                                 client_nssdb_pass_file, serial, temp_cert, renew, output)

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

        try:
            # Load the cert into NSS db
            cert = subsystem.nssdb_import_cert(cert_tag, cert_file)
            # Update the CS.cfg file for (all) corresponding subsystems
            instance.cert_update_config(cert_id, cert)

        except server.PKIServerException as e:
            logger.error(str(e))
            sys.exit(1)


class CertExportCLI(pki.cli.CLI):
    def __init__(self):
        super(CertExportCLI, self).__init__(
            'export', 'Export system certificate.')

    def print_help(self):  # flake8: noqa
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
        print('      --friendly-name <name>         Friendly name for the certificate in PKCS #12 file.')
        print('      --cert-encryption <algorithm>  Certificate encryption algorithm (default: none).')
        print('      --key-encryption <algorithm>   Key encryption algorithm (default: PBES2).')
        print('      --append                       Append into an existing PKCS #12 file.')
        print('      --no-trust-flags               Do not include trust flags')
        print('      --no-key                       Do not include private key')
        print('      --no-chain                     Do not include certificate chain')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()
        print('Supported certificate encryption algorithms:')
        print(' - none')
        print(' - PBE/SHA1/RC2-40')
        print()
        print('Supported key encryption algorithms:')
        print(' - PBES2')
        print(' - PBE/SHA1/DES3/CBC')
        print()

    def execute(self, argv):

        logging.basicConfig(format='%(levelname)s: %(message)s')

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'cert-file=', 'csr-file=',
                'pkcs12-file=', 'pkcs12-password=', 'pkcs12-password-file=',
                'friendly-name=',
                'cert-encryption=', 'key-encryption=',
                'append', 'no-trust-flags', 'no-key', 'no-chain',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        cert_file = None
        csr_file = None
        pkcs12_file = None
        pkcs12_password = None
        pkcs12_password_file = None
        friendly_name = None
        cert_encryption = None
        key_encryption = None
        append = False
        include_trust_flags = True
        include_key = True
        include_chain = True

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

            elif o == '--friendly-name':
                friendly_name = a

            elif o == '--cert-encryption':
                cert_encryption = a

            elif o == '--key-encryption':
                key_encryption = a

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

        if not (cert_file or csr_file or pkcs12_file):
            logger.error('missing output file')
            self.print_help()
            sys.exit(1)

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

        cert = subsystem.get_subsystem_cert(cert_tag)

        if not cert:
            logger.error('missing %s certificate', cert_id)
            self.print_help()
            sys.exit(1)

        if cert_id == 'sslserver':
            # get nickname and token from serverCertNick.conf
            full_name = instance.get_sslserver_cert_nickname()
            i = full_name.find(':')
            if i < 0:
                nickname = full_name
                token = None

            else:
                nickname = full_name[i + 1:]
                token = full_name[:i]

        else:
            # get nickname and token from CS.cfg
            nickname = cert['nickname']
            token = cert['token']

        logger.info('Nickname: %s', nickname)
        logger.info('Token: %s', token)

        nssdb = instance.open_nssdb(token)

        try:
            if cert_file:

                logger.info('Exporting %s certificate into %s.', cert_id, cert_file)

                cert_data = cert.get('data', None)
                if cert_data is None:
                    logger.error('Unable to find certificate data for %s', cert_id)
                    sys.exit(1)

                cert_data = pki.nssdb.convert_cert(cert_data, 'base64', 'pem')
                with open(cert_file, 'w') as f:
                    f.write(cert_data)

            if csr_file:

                logger.info('Exporting %s CSR into %s.', cert_id, csr_file)

                cert_request = cert.get('request', None)
                if cert_request is None:
                    logger.error('Unable to find certificate request for %s', cert_id)
                    sys.exit(1)

                csr_data = pki.nssdb.convert_csr(cert_request, 'base64', 'pem')
                with open(csr_file, 'w') as f:
                    f.write(csr_data)

            if pkcs12_file:

                logger.info('Exporting %s certificate and key into %s.', cert_id, pkcs12_file)

                if not pkcs12_password and not pkcs12_password_file:
                    pkcs12_password = getpass.getpass(prompt='Enter password for PKCS #12 file: ')

                logger.info('Friendly name: %s', friendly_name)

                nssdb.export_cert(
                    nickname=nickname,
                    pkcs12_file=pkcs12_file,
                    pkcs12_password=pkcs12_password,
                    pkcs12_password_file=pkcs12_password_file,
                    friendly_name=friendly_name,
                    cert_encryption=cert_encryption,
                    key_encryption=key_encryption,
                    append=append,
                    include_trust_flags=include_trust_flags,
                    include_key=include_key,
                    include_chain=include_chain,
                    debug=self.debug)

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

        logger.info('Removing %s certificate from NSS database', cert_id)
        subsystem.cert_del(cert_tag=cert_tag, remove_key=remove_key)
