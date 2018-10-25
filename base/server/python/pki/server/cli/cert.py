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
import shutil
import sys
import tempfile

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
        create_temp_cert = False
        serial = None
        client_nssdb_location = os.getenv('HOME') + '/.dogtag/nssdb'
        client_nssdb_password = None
        client_nssdb_pass_file = None
        client_cert = None
        output = None
        renew = False
        connection = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '-d':
                client_nssdb_location = a

            elif o == '-c':
                client_nssdb_password = a

            elif o == '-C':
                client_nssdb_pass_file = a

            elif o == '-n':
                client_cert = a

            elif o == '--temp':
                create_temp_cert = True

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

        if not create_temp_cert:
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

        subsystem_name = None
        cert_tag = cert_id

        if cert_id == 'sslserver' or cert_id == 'subsystem':
            subsystem_name = None
            cert_tag = cert_id

        else:
            parts = cert_id.split('_', 1)
            subsystem_name = parts[0]
            cert_tag = parts[1]

        # If cert ID is instance specific, get it from first subsystem
        if not subsystem_name:
            subsystem_name = instance.subsystems[0].name

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error(
                'No %s subsystem in instance %s.',
                subsystem_name, instance_name)
            sys.exit(1)

        nssdb = instance.open_nssdb()
        tmpdir = tempfile.mkdtemp()
        try:
            cert_folder = os.path.join(pki.CONF_DIR, instance_name, 'certs')
            if not os.path.exists(cert_folder):
                os.makedirs(cert_folder)
            new_cert_file = os.path.join(cert_folder, cert_id + '.crt')

            if output:
                new_cert_file = output

            if create_temp_cert:
                if not serial:
                    # If admin doesn't provide a serial number, find the highest in NSS db
                    # and add 1 to it
                    serial = 0
                    for sub in instance.subsystems:
                        for n_cert in sub.find_system_certs():
                            if int(n_cert['serial_number']) > serial:
                                serial = int(n_cert['serial_number'])

                    # Add 1 and then rewrap it as a string
                    serial = str(serial + 1)

            else:
                # Create permanent certificate
                if not renew:
                    # Fixme: Support rekey
                    raise Exception('Rekey is not supported yet.')

                # Create a secure connection to CA
                connection = server.PKIServer.setup_authentication(
                    c_nssdb_pass=client_nssdb_password,
                    c_cert=client_cert,
                    c_nssdb_pass_file=client_nssdb_pass_file,
                    c_nssdb=client_nssdb_location,
                    tmpdir=tmpdir,
                    subsystem_name='ca')

            if cert_tag == 'sslserver':
                self.create_ssl_cert(subsystem=subsystem,
                                     is_temp_cert=create_temp_cert,
                                     new_cert_file=new_cert_file, nssdb=nssdb, serial=serial,
                                     tmpdir=tmpdir, connection=connection)

            elif cert_tag == 'subsystem':
                self.create_subsystem_cert(is_temp_cert=create_temp_cert, serial=serial,
                                           subsystem=subsystem, new_cert_file=new_cert_file,
                                           connection=connection)

            elif cert_id in ['ca_ocsp_signing', 'ocsp_signing']:
                self.create_ocsp_cert(is_temp_cert=create_temp_cert, serial=serial,
                                      subsystem=subsystem, new_cert_file=new_cert_file,
                                      connection=connection)

            elif cert_tag == 'audit_signing':
                self.create_audit_cert(is_temp_cert=create_temp_cert, serial=serial,
                                       subsystem=subsystem, new_cert_file=new_cert_file,
                                       connection=connection)

            else:
                # renewal not yet supported
                raise Exception('Renewal for %s not yet supported.' % cert_id)

        finally:
            nssdb.close()
            shutil.rmtree(tmpdir)

    def renew_system_certificate(self, connection,
                                 output, serial):

        # Instantiate the CertClient
        cert_client = pki.cert.CertClient(connection)

        inputs = dict()
        inputs['serial_num'] = serial

        # request: CertRequestInfo object for request generated.
        # cert: CertData object for certificate generated (if any)
        ret = cert_client.enroll_cert(inputs=inputs, profile_id='caManualRenewal')

        request_data = ret[0].request
        cert_data = ret[0].cert

        logger.info('Request ID: %s', request_data.request_id)
        logger.info('Request Status: %s', request_data.request_status)

        if not cert_data:
            raise Exception('Unable to renew system certificate for serial: %s' % serial)

        # store cert_id for usage later
        cert_id = cert_data.serial_number
        if not cert_id:
            raise Exception('Unable to retrieve serial number of renewed certificate.')

        logger.info('Serial Number: %s', cert_id)
        logger.info('Issuer: %s', cert_data.issuer_dn)
        logger.info('Subject: %s', cert_data.subject_dn)
        logger.info('Pretty Print:')
        logger.info(cert_data.pretty_repr)

        new_cert_data = cert_client.get_cert(cert_serial_number=cert_id)
        with open(output, 'w') as f:
            f.write(new_cert_data.encoded)

    # NOTE: The following method will be removed in subsequent patches
    def create_ssl_cert(self, subsystem, serial, is_temp_cert, tmpdir,
                        new_cert_file, nssdb, connection):

        logger.info('Creating SSL server certificate.')

        if is_temp_cert:
            subsystem.temp_cert_create(nssdb, tmpdir, 'sslserver', serial, new_cert_file)

        else:

            logger.info('Renewing SSL certificate')

            if not serial:
                # If serial number is not provided, get Serial Number from NSS db
                serial = subsystem.get_subsystem_cert('sslserver')["serial_number"]

            logger.info('Serial number: %s', serial)

            self.renew_system_certificate(connection=connection,
                                          output=new_cert_file, serial=serial)

    # NOTE: The following method will be removed in subsequent patches
    def create_ocsp_cert(self, subsystem, is_temp_cert, new_cert_file, serial, connection):

        if is_temp_cert:
            raise Exception('Temp certificate for OCSP is not supported.')

        else:
            cert_tag = 'ocsp_signing'
            if subsystem.name is 'ocsp':
                cert_tag = 'signing'

            if not serial:
                # If serial number is not provided, get Serial Number from NSS db
                serial = subsystem.get_subsystem_cert(cert_tag)["serial_number"]

            logger.info('Renewing for certificate with serial number: %s', serial)

            self.renew_system_certificate(connection=connection,
                                          output=new_cert_file, serial=serial)

    # NOTE: The following method will be removed in subsequent patches
    def create_subsystem_cert(self, subsystem, is_temp_cert, new_cert_file, serial,
                              connection):

        if is_temp_cert:
            raise Exception('Temp certificate for subsystem is not supported.')

        else:
            if not serial:
                # If serial number is not provided, get Serial Number from NSS db
                serial = subsystem.get_subsystem_cert('subsystem')["serial_number"]

            logger.info('Renewing for certificate with serial number: %s', serial)

            self.renew_system_certificate(connection=connection,
                                          output=new_cert_file, serial=serial)

    # NOTE: The following method will be removed in subsequent patches
    def create_audit_cert(self, subsystem, is_temp_cert, new_cert_file, serial, connection):

        logger.info('Creating audit certificate')

        if is_temp_cert:
            raise Exception('Temp certificate for audit signing is not supported.')
        else:
            if not serial:
                # If serial number is not provided, get Serial Number from NSS db
                serial = subsystem.get_subsystem_cert('audit_signing')["serial_number"]

            logger.info('Renewing for certificate with serial number: %s', serial)

            self.renew_system_certificate(connection=connection,
                                          output=new_cert_file, serial=serial)


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
