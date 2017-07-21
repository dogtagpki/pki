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

import getopt
import sys
import tempfile
import os
import random
import shutil
import re
import subprocess

import pki.cli
import pki.server as server
import pki.cert
import pki.nssdb


class CertCLI(pki.cli.CLI):
    def __init__(self):
        super(CertCLI, self).__init__('cert',
                                      'System certificate management commands')
        self.add_module(CertFindCLI())
        self.add_module(CertUpdateCLI())
        self.add_module(CertCreateCLI())
        self.add_module(CertImportCLI())

    @staticmethod
    def print_system_cert(cert, show_all=False):
        print('  Cert ID: %s' % cert['id'])
        print('  Nickname: %s' % cert['nickname'])
        print('  Token: %s' % cert['token'])

        if show_all:
            print('  Certificate: %s' % cert['data'])
            print('  Request: %s' % cert['request'])


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
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'show-all',
                'verbose', 'help'])

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
        results = []

        for subsystem in instance.subsystems:
            # Retrieve the subsystem's system certificate
            sub_system_certs = subsystem.find_system_certs()
            # Iterate on all subsystem's system certificate to prepend subsystem name to the ID
            for subsystem_cert in sub_system_certs:
                if subsystem_cert['id'] != 'sslserver' and subsystem_cert['id'] != 'subsystem':
                    subsystem_cert['id'] = subsystem.name + '_' + subsystem_cert['id']
                # Append only unique certificates to other subsystem certificate list
                if subsystem_cert not in results:
                    results.append(subsystem_cert)

        self.print_message('%s entries matched' % len(results))

        first = True
        for cert in results:
            if first:
                first = False
            else:
                print()

            CertCLI.print_system_cert(cert, show_all)


class CertUpdateCLI(pki.cli.CLI):
    def __init__(self):
        super(CertUpdateCLI, self).__init__(
            'update', 'Update system certificate.')

    def usage(self):
        print('Usage: pki-server cert-update [OPTIONS] <cert ID>')
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
            self.usage()
            sys.exit(1)

        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.usage()
                sys.exit()

            else:
                print('ERROR: unknown option ' + o)
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
            print('ERROR: No %s subsystem in instance '
                  '%s.' % (subsystem_name, instance_name))
            sys.exit(1)
        subsystem_cert = subsystem.get_subsystem_cert(cert_tag)

        if self.verbose:
            print('Retrieving certificate %s from %s' %
                  (subsystem_cert['nickname'], subsystem_cert['token']))

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
        if self.verbose:
            print('Retrieving certificate request from CA database')

        # TODO: add support for remote CA
        ca = instance.get_subsystem('ca')
        if not ca:
            print('ERROR: No CA subsystem in instance %s.' % instance_name)
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
        print('  -v, --verbose                   Run in verbose mode.')
#        print('  -d <database>                   Security database location (default: '
#              '~/.dogtag/nssdb)')
#        print('  -c <NSS DB password>            NSS database password')
#        print('  -n <nickname>                   Client certificate nickname')
        print('      --temp                      Create temporary certificate.')
        print('      --serial <number>           Provide serial number for temp certificate.')
        print('      --output <file>             Provide output file name.')
#        print('      --rekey                     Rekey permanent certificate.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'verbose', 'temp', 'serial=',
                'output=', 'rekey', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.usage()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        is_permanent_cert = True
        serial = None
#        client_nssdb_location = os.getenv('HOME') + '/.dogtag/nssdb'
#        client_nssdb_password = None
#        client_cert = None
        output = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

#            elif o == '-d':
#                client_nssdb_location = a

#            elif o == '-c':
#                client_nssdb_password = a

#            elif o == '-n':
#                client_cert = a

            elif o == '--help':
                self.usage()
                sys.exit()

            elif o == '--temp':
                is_permanent_cert = False

            elif o == '--serial':
                serial = a

            elif o == '--output':
                output = a

#            elif o == '--rekey':
#                rekey = True

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
            print('ERROR: No %s subsystem in instance '
                  '%s.' % (subsystem_name, instance_name))
            sys.exit(1)

        nssdb = instance.open_nssdb()

        try:
            cert_folder = os.path.join(pki.CONF_DIR, instance_name, 'certs')
            if not os.path.exists(cert_folder):
                os.makedirs(cert_folder)
            new_cert_file = os.path.join(cert_folder, cert_id + '.crt')

            if output:
                new_cert_file = output

            # Check if the request is for permanent certificate creation
            if is_permanent_cert:
                # Serial number for permanent certificate must be auto-generated
                if serial:
                    raise Exception('--serial not allowed for permanent cert')
                    # Fixme: Get the serial from LDAP DB (Method 3a)
            else:
                if not serial:
                    # Fixme: Get the highest serial number from NSS DB and add 1 (Method 2b)
                    # If admin doesn't provide a serial number, generate one
                    serial = str(random.randint(
                        int(subsystem.config.get('dbs.beginSerialNumber', '1')),
                        int(subsystem.config.get('dbs.endSerialNumber', '10000000'))))

            if cert_tag == 'sslserver':
                self.create_ssl_cert(subsystem=subsystem, is_permanent_cert=is_permanent_cert,
                                     new_cert_file=new_cert_file, nssdb=nssdb,
                                     serial=serial)

            elif cert_tag == 'subsystem':
                self.create_subsystem_cert(is_permanent_cert=is_permanent_cert)

            elif cert_tag == 'ca_ocsp_signing':
                self.create_ocsp_cert(is_permanent_cert=is_permanent_cert)

            elif cert_tag == 'ca_audit_signing':
                self.create_audit_cert(is_permanent_cert=is_permanent_cert)

            else:
                # renewal not yet supported
                raise Exception('Renewal for %s not yet supported.' % cert_id)

        finally:
            nssdb.close()

    @staticmethod
    def setup_temp_renewal(subsystem, tmpdir, cert_id):

        csr_file = os.path.join(tmpdir, cert_id + '.csr')
        ca_cert_file = os.path.join(tmpdir, 'ca_certificate.crt')

        # Export the CSR for the cert
        cert_request = subsystem.get_subsystem_cert(cert_id).get('request', None)
        if cert_request is None:
            print("ERROR: Unable to find certificate request for %s" % cert_id)
            sys.exit(1)

        csr_data = pki.nssdb.convert_csr(cert_request, 'base64', 'pem')
        with open(csr_file, 'w') as f:
            f.write(csr_data)

        # Extract SKI
        # 1. Get the CA certificate
        # 2. Then get the SKI from it
        # TODO: Support remote CA.
        ca_signing_cert = subsystem.get_subsystem_cert('signing')
        ca_cert_data = ca_signing_cert.get('data', None)
        if ca_cert_data is None:
            print("ERROR: Unable to find certificate data for CA signing certificate.")
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

        ca_cert_details = subprocess.check_output(ca_cert_retrieve_cmd)
        aki = re.search(r'Subject Key Identifier.*\n.*?(.*?)\n', ca_cert_details).group(1)

        # Add 0x to represent this is a Hex
        aki = '0x' + aki.strip().replace(':', '')

        return ca_signing_cert, aki, csr_file

    def create_ssl_cert(self, subsystem, serial, is_permanent_cert, new_cert_file,
                        nssdb):
        if self.verbose:
            print('Creating SSL server certificate.')

        if is_permanent_cert:
            # TODO: Online renewal

            raise Exception('SSL cert online renewal not yet supported.')

        else:
            # Generate temp SSL Certificate signed by CA
            tmpdir = tempfile.mkdtemp()
            try:
                ca_signing_cert, aki, csr_file = self.setup_temp_renewal(
                    subsystem=subsystem, tmpdir=tmpdir, cert_id='sslserver')

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
            finally:
                # Remove temporary directory and files used
                shutil.rmtree(tmpdir)

    def create_ocsp_cert(self, is_permanent_cert):
        if is_permanent_cert:
            # TODO: Online renewal
            raise Exception('OCSP cert online renewal not yet supported.')
        else:
            raise Exception('Temp certificate for OCSP is not supported.')

    def create_subsystem_cert(self, is_permanent_cert):
        if is_permanent_cert:
            # TODO: Online renewal
            raise Exception('Subsystem cert online renewal not yet supported.')
        else:
            raise Exception('Temp certificate for subsystem is not supported.')

    def create_audit_cert(self, is_permanent_cert):
        if is_permanent_cert:
            # TODO: Online renewal
            raise Exception('Audit signing cert online renewal not yet supported.')
        else:
            raise Exception('Temp certificate for audit signing is not supported.')


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
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --input <file>              Provide input file name.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'verbose', 'input=', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.usage()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        cert_file = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.usage()
                sys.exit()

            elif o == '--input':
                cert_file = a

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

        if cert_id != 'sslserver' and cert_id != 'subsystem':
            # To avoid ambiguity where cert ID can contain more than 1 _, we limit to one split
            temp_cert_identify = cert_id.split('_', 1)
            subsystem_name = temp_cert_identify[0]
            cert_id = temp_cert_identify[1]

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
            if not cert_file:
                cert_file = os.path.join(pki.CONF_DIR, instance_name, 'certs', cert_id + '.crt')

            if not os.path.isfile(cert_file):
                print('ERROR: No %s such file.' % cert_file)
                self.usage()
                sys.exit(1)

            cert = subsystem.get_subsystem_cert(cert_id)

            # Import cert into NSS db
            if self.verbose:
                print('Removing old %s certificate from NSS database.' % cert_id)
            nssdb.remove_cert(cert['nickname'])

            if self.verbose:
                print('Adding new %s certificate into NSS database.' % cert_id)
            nssdb.add_cert(nickname=cert['nickname'], cert_file=cert_file)

            # Update CS.cfg with the new certificate
            if self.verbose:
                print('Updating CS.cfg')

            data = nssdb.get_cert(nickname=cert['nickname'], output_format='base64')
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
