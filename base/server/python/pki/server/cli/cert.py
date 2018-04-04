# Authors:
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
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
import re
import shutil
import subprocess
import sys
import tempfile

import pki.cli
import pki.server as server
import pki.client as client
import pki.cert
import pki.nssdb

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

    @staticmethod
    def print_system_cert(cert, show_all=False):
        print('  Cert ID: %s' % cert['id'])
        print('  Nickname: %s' % cert['nickname'])
        print('  Token: %s' % cert['token'])

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
        print('      --debug                     Show debug messages.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        logging.basicConfig(format='%(levelname)s: %(message)s')

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'show-all',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
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
                print('ERROR: unknown option ' + o)
                self.print_help()
                sys.exit(1)

        instance = server.PKIInstance(instance_name)

        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
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
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        logging.basicConfig(format='%(levelname)s: %(message)s')

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
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

        cert = subsystem.get_subsystem_cert(cert_tag)
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

        subsystem_name = None
        cert_tag = cert_id

        if cert_id != 'sslserver' and cert_id != 'subsystem':
            # To avoid ambiguity where cert ID can contain more than 1 _, we limit to one split
            temp_cert_identify = cert_id.split('_', 1)
            subsystem_name = temp_cert_identify[0]
            cert_tag = temp_cert_identify[1]

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

        # store cert data and request in CS.cfg
        if cert_id == 'sslserver' or cert_id == 'subsystem':
            # Update for all subsystems
            for subsystem in instance.subsystems:
                subsystem.update_subsystem_cert(subsystem_cert)
                subsystem.save()
        else:
            subsystem.update_subsystem_cert(subsystem_cert)
            subsystem.save()

        self.print_message('Updated "%s" system certificate' % cert_id)


class CertCreateCLI(pki.cli.CLI):
    def __init__(self):
        super(CertCreateCLI, self).__init__(
            'create', 'Create system certificate.')

    def usage(self):
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
        print('      --debug                     Show debug messages.')
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
            print('ERROR: ' + str(e))
            self.usage()
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
                serial = a

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

        if not create_temp_cert:
            # For permanent certificate, password of NSS db is required.
            if not client_nssdb_password and not client_nssdb_pass_file:
                print('ERROR: NSS db password is required.')
                self.usage()
                sys.exit(1)

        cert_id = args[0]

        instance = server.PKIInstance(instance_name)

        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        # Load the instance. Default: pki-tomcat
        instance.load()

        subsystem_name = None
        cert_tag = cert_id

        if cert_id != 'sslserver' and cert_id != 'subsystem':
            # To avoid ambiguity where cert ID can contain more than 1 _, we limit to one split
            temp_cert_identify = cert_id.split('_', 1)
            subsystem_name = temp_cert_identify[0]
            cert_tag = temp_cert_identify[1]

        # If cert ID is instance specific, get it from first subsystem
        if not subsystem_name:
            subsystem_name = instance.subsystems[0].name

        # Get the subsystem - Eg: ca, kra, tps, tks
        subsystem = instance.get_subsystem(subsystem_name)
        if not subsystem:
            print('ERROR: No %s subsystem in instance '
                  '%s.' % (subsystem_name, instance_name))
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

                connection = self.setup_authentication(subsystem=subsystem,
                                                       c_nssdb_pass=client_nssdb_password,
                                                       c_cert=client_cert,
                                                       c_nssdb_pass_file=client_nssdb_pass_file,
                                                       c_nssdb=client_nssdb_location,
                                                       tmpdir=tmpdir)

            if cert_tag == 'sslserver':
                self.create_ssl_cert(instance=instance, subsystem=subsystem,
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

    @staticmethod
    def setup_temp_renewal(instance, subsystem, tmpdir, cert_id):

        csr_file = os.path.join(tmpdir, cert_id + '.csr')
        ca_cert_file = os.path.join(tmpdir, 'ca_certificate.crt')

        logger.debug('Exporting CSR for %s cert', cert_id)

        cert_request = subsystem.get_subsystem_cert(cert_id).get('request', None)
        if cert_request is None:
            logger.error('Unable to find CSR for %s cert', cert_id)
            sys.exit(1)

        csr_data = pki.nssdb.convert_csr(cert_request, 'base64', 'pem')
        with open(csr_file, 'w') as f:
            f.write(csr_data)

        logger.debug('Extracting SKI from CA cert')
        # TODO: Support remote CA.

        ca_signing_cert = instance.get_subsystem('ca').get_subsystem_cert('signing')
        ca_cert_data = ca_signing_cert.get('data', None)
        if ca_cert_data is None:
            logger.error('Unable to find certificate data for CA signing certificate.')
            sys.exit(1)

        ca_cert = pki.nssdb.convert_cert(ca_cert_data, 'base64', 'pem')
        with open(ca_cert_file, 'w') as f:
            f.write(ca_cert)

        ca_cert_retrieve_cmd = [
            'openssl',
            'x509',
            '-in', ca_cert_file,
            '-noout',
            '-text'
        ]

        logger.debug('Command: %s', ' '.join(ca_cert_retrieve_cmd))
        ca_cert_details = subprocess.check_output(ca_cert_retrieve_cmd)

        aki = re.search(r'Subject Key Identifier.*\n.*?(.*?)\n', ca_cert_details).group(1)

        # Add 0x to represent this is a Hex
        aki = '0x' + aki.strip().replace(':', '')
        logger.debug('AKI: %s', aki)

        return ca_signing_cert, aki, csr_file

    def setup_authentication(self, subsystem, c_nssdb_pass, c_nssdb_pass_file, c_cert,
                             c_nssdb, tmpdir):
        temp_auth_p12 = os.path.join(tmpdir, 'auth.p12')
        temp_auth_cert = os.path.join(tmpdir, 'auth.pem')

        if not c_cert:
            print('ERROR: Client cert nickname is required.')
            self.usage()
            sys.exit(1)

        # Create a PKIConnection object that stores the details of subsystem.
        connection = client.PKIConnection('https', os.environ['HOSTNAME'], '8443', subsystem.name)

        # Create a p12 file using
        # pk12util -o <p12 file name> -n <cert nick name> -d <NSS db path>
        # -W <pkcs12 password> -K <NSS db pass>
        cmd_generate_pk12 = [
            'pk12util',
            '-o', temp_auth_p12,
            '-n', c_cert,
            '-d', c_nssdb
        ]

        # The pem file used for authentication. Created from a p12 file using the
        # command:
        # openssl pkcs12 -in <p12_file_path> -out /tmp/auth.pem -nodes
        cmd_generate_pem = [
            'openssl',
            'pkcs12',
            '-in', temp_auth_p12,
            '-out', temp_auth_cert,
            '-nodes',

        ]

        if c_nssdb_pass_file:
            # Use the same password file for the generated pk12 file
            cmd_generate_pk12.extend(['-k', c_nssdb_pass_file,
                                      '-w', c_nssdb_pass_file])
            cmd_generate_pem.extend(['-passin', 'file:' + c_nssdb_pass_file])
        else:
            # Use the same password for the generated pk12 file
            cmd_generate_pk12.extend(['-K', c_nssdb_pass,
                                      '-W', c_nssdb_pass])
            cmd_generate_pem.extend(['-passin', 'pass:' + c_nssdb_pass])

        res_pk12 = subprocess.check_output(cmd_generate_pk12, stderr=subprocess.STDOUT)
        if self.verbose:
            print(res_pk12)

        res_pem = subprocess.check_output(cmd_generate_pem, stderr=subprocess.STDOUT)
        if self.verbose:
            print(res_pem)

            # Bind the authentication with the connection object
        connection.set_authentication_cert(temp_auth_cert)

        return connection

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
        if self.verbose:
            print('Request ID: ' + request_data.request_id)
            print('Request Status:' + request_data.request_status)

        if not cert_data:
            raise Exception('ERROR: Unable to renew system certificate for serial: %s' % serial)

        # store cert_id for usage later
        cert_id = cert_data.serial_number
        if not cert_id:
            raise Exception('ERROR: Unable to retrieve serial number of renewed certificate.')

        if self.verbose:
            print('Serial Number: ' + cert_id)
            print('Issuer: ' + cert_data.issuer_dn)
            print('Subject: ' + cert_data.subject_dn)
            print('Pretty Print:')
            print(cert_data.pretty_repr)

        new_cert_data = cert_client.get_cert(cert_serial_number=cert_id)
        with open(output, 'w') as f:
            f.write(new_cert_data.encoded)

    def create_ssl_cert(self, instance, subsystem, serial, is_temp_cert, tmpdir,
                        new_cert_file, nssdb, connection):

        logger.info('Creating SSL server certificate.')

        if is_temp_cert:

            logger.info('Generate temp SSL certificate')

            ca_signing_cert, aki, csr_file = self.setup_temp_renewal(
                instance=instance, subsystem=subsystem, tmpdir=tmpdir, cert_id='sslserver')

            # --keyUsage
            key_usage_ext = {
                'digitalSignature': True,
                'nonRepudiation': True,
                'keyEncipherment': True,
                'dataEncipherment': True,
                'critical': True
            }

            # -3
            aki_ext = {
                'auth_key_id': aki
            }

            # --extKeyUsage
            ext_key_usage_ext = {
                'serverAuth': True
            }

            rc = nssdb.create_cert(
                issuer=ca_signing_cert['nickname'],
                request_file=csr_file,
                cert_file=new_cert_file,
                serial=serial,
                key_usage_ext=key_usage_ext,
                aki_ext=aki_ext,
                ext_key_usage_ext=ext_key_usage_ext)
            if rc:
                raise Exception('Failed to generate CA-signed temp SSL certificate. '
                                'RC: %d' % rc)

        else:

            logger.info('Renewing SSL certificate')

            if not serial:
                # If serial number is not provided, get Serial Number from NSS db
                serial = subsystem.get_subsystem_cert('sslserver')["serial_number"]

            logger.info('Serial number: %s', serial)

            self.renew_system_certificate(connection=connection,
                                          output=new_cert_file, serial=serial)

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

            if self.verbose:
                print('Renewing for certificate with serial number: %s' % serial)

            self.renew_system_certificate(connection=connection,
                                          output=new_cert_file, serial=serial)

    def create_subsystem_cert(self, subsystem, is_temp_cert, new_cert_file, serial,
                              connection):

        if is_temp_cert:
            raise Exception('Temp certificate for subsystem is not supported.')

        else:
            if not serial:
                # If serial number is not provided, get Serial Number from NSS db
                serial = subsystem.get_subsystem_cert('subsystem')["serial_number"]

            if self.verbose:
                print('Renewing for certificate with serial number: %s' % serial)

            self.renew_system_certificate(connection=connection,
                                          output=new_cert_file, serial=serial)

    def create_audit_cert(self, subsystem, is_temp_cert, new_cert_file, serial, connection):

        logger.info('Creating audit certificate')

        if is_temp_cert:
            raise Exception('Temp certificate for audit signing is not supported.')
        else:
            if not serial:
                # If serial number is not provided, get Serial Number from NSS db
                serial = subsystem.get_subsystem_cert('audit_signing')["serial_number"]

            if self.verbose:
                print('Renewing for certificate with serial number: %s' % serial)

            self.renew_system_certificate(connection=connection,
                                          output=new_cert_file, serial=serial)


class CertImportCLI(pki.cli.CLI):
    def __init__(self):
        super(CertImportCLI, self).__init__(
            'import', 'Import system certificate.')

    def usage(self):
        print('Usage: pki-server cert-import [OPTIONS] <Cert ID>')
        # CertID:  subsystem, sslserver, kra_storage, kra_transport, ca_ocsp_signing,
        # ca_audit_signing, kra_audit_signing
        # ca.cert.list=signing,ocsp_signing,sslserver,subsystem,audit_signing
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('      --input <file>              Provide input file name.')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Show debug messages.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        logging.basicConfig(format='%(levelname)s: %(message)s')

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'input=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.usage()
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

        instance = server.PKIInstance(instance_name)

        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        # Load the instance. Default: pki-tomcat
        instance.load()

        subsystem_name = None
        cert_tag = cert_id
        if cert_id != 'sslserver' and cert_id != 'subsystem':
            # To avoid ambiguity where cert ID can contain more than 1 _, we limit to one split
            temp_cert_identify = cert_id.split('_', 1)
            subsystem_name = temp_cert_identify[0]
            cert_tag = temp_cert_identify[1]

        # If cert ID is instance specific, get it from first subsystem
        if not subsystem_name:
            subsystem_name = instance.subsystems[0].name

        # Get the subsystem - Eg: ca, kra, tps, tks
        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            print('ERROR: No %s subsystem in instance.'
                  '%s.' % (subsystem_name, instance_name))
            sys.exit(1)

        nssdb = instance.open_nssdb()

        try:
            cert_folder = os.path.join(pki.CONF_DIR, instance_name, 'certs')
            if not cert_file:
                cert_file = os.path.join(cert_folder, cert_id + '.crt')

            if not os.path.isfile(cert_file):
                print('ERROR: No %s such file.' % cert_file)
                self.usage()
                sys.exit(1)

            cert = subsystem.get_subsystem_cert(cert_tag)

            logger.info('Removing old %s certificate from NSS database', cert_id)

            nssdb.remove_cert(cert['nickname'])

            logger.info('Importing new %s certificate into NSS database', cert_id)

            nssdb.add_cert(
                nickname=cert['nickname'],
                token=cert['token'],
                cert_file=cert_file)

            logger.info('Updating CS.cfg with the new certificate')

            data = nssdb.get_cert(
                nickname=cert['nickname'],
                token=cert['token'],
                output_format='base64')
            cert['data'] = data

            if cert_id == 'sslserver' or cert_id == 'subsystem':
                # Update all subsystem's CS.cfg
                for subsystem in instance.subsystems:
                    subsystem.update_subsystem_cert(cert)
                    subsystem.save()
            else:
                subsystem.update_subsystem_cert(cert)
                subsystem.save()

        finally:
            nssdb.close()


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

        subsystem_name = None
        cert_tag = cert_id

        if cert_id != 'sslserver' and cert_id != 'subsystem':
            # To avoid ambiguity where cert ID can contain more than 1 _, we limit to one split
            temp_cert_identify = cert_id.split('_', 1)
            subsystem_name = temp_cert_identify[0]
            cert_tag = temp_cert_identify[1]

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
                nickname = full_name[i+1:]
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
