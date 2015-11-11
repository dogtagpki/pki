#!/usr/bin/python
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

import base64
import os
import shutil
import subprocess
import tempfile


CSR_HEADER = '-----BEGIN NEW CERTIFICATE REQUEST-----'
CSR_FOOTER = '-----END NEW CERTIFICATE REQUEST-----'

CERT_HEADER = '-----BEGIN CERTIFICATE-----'
CERT_FOOTER = '-----END CERTIFICATE-----'


def convert_data(data, input_format, output_format, header=None, footer=None):

    if input_format == 'base64' and output_format == 'pem':

        # split a single line into multiple lines
        lines = [data[i:i+64] for i in range(0, len(data), 64)]
        return '%s\n%s\n%s\n' % (header, '\n'.join(lines), footer)

    if input_format == 'pem' and output_format == 'base64':

        # join multiple lines into a single line
        lines = []
        for line in data.splitlines():
            line = line.rstrip('\r\n')
            if line == header:
                continue
            if line == footer:
                continue
            lines.append(line)

        return ''.join(lines)

    raise Exception('Unable to convert data from %s to %s' % (input_format, output_format))

def convert_csr(csr_data, input_format, output_format):

    return convert_data(csr_data, input_format, output_format, CSR_HEADER, CSR_FOOTER)

def convert_cert(cert_data, input_format, output_format):

    return convert_data(cert_data, input_format, output_format, CERT_HEADER, CERT_FOOTER)


class NSSDatabase(object):

    def __init__(self, directory, password=None, password_file=None):
        self.directory = directory

        self.tmpdir = tempfile.mkdtemp()

        if password:
            self.password_file = os.path.join(self.tmpdir, 'password.txt')
            with open(self.password_file, 'w') as f:
                f.write(password)

        elif password_file:
            self.password_file = password_file

        else:
            raise Exception('Missing NSS database password')

    def close(self):
        shutil.rmtree(self.tmpdir)

    def add_cert(self,
        nickname, cert_file,
        trust_attributes='u,u,u'):

        subprocess.check_call([
            'certutil',
            '-A',
            '-d', self.directory,
            '-n', nickname,
            '-i', cert_file,
            '-t', trust_attributes
        ])

    def modify_cert(self,
        nickname,
        trust_attributes='u,u,u'):

        subprocess.check_call([
            'certutil',
            '-M',
            '-d', self.directory,
            '-n', nickname,
            '-t', trust_attributes
        ])

    def create_noise(self, noise_file, size=2048):

        subprocess.check_call([
            'openssl',
            'rand',
            '-out', noise_file,
            str(size)
        ])

    def create_request(self,
        subject_dn,
        noise_file,
        request_file):

        tmpdir = tempfile.mkdtemp()

        try:
            binary_request_file = os.path.join(tmpdir, 'request.bin')
            b64_request_file = os.path.join(tmpdir, 'request.b64')

            # generate binary request
            subprocess.check_call([
                'certutil',
                '-R',
                '-d', self.directory,
                '-f', self.password_file,
                '-s', subject_dn,
                '-z', noise_file,
                '-o', binary_request_file
            ])

            # encode binary request in base-64
            subprocess.check_call([
                'BtoA', binary_request_file, b64_request_file])

            # read base-64 request
            with open(b64_request_file, 'r') as f:
                b64_request = f.read()

            # add header and footer
            with open(request_file, 'w') as f:
                f.write('-----BEGIN NEW CERTIFICATE REQUEST-----\n')
                f.write(b64_request)
                f.write('-----END NEW CERTIFICATE REQUEST-----\n')

        finally:
            shutil.rmtree(tmpdir)

    def create_self_signed_ca_cert(self,
        subject_dn,
        request_file,
        cert_file,
        serial='1',
        validity=240):

        p = subprocess.Popen([
            'certutil',
            '-C',
            '-x',
            '-d', self.directory,
            '-f', self.password_file,
            '-c', subject_dn,
            '-a',
            '-i', request_file,
            '-o', cert_file,
            '-m', serial,
            '-v', str(validity),
            '--keyUsage', 'digitalSignature,nonRepudiation,certSigning,crlSigning,critical',
            '-2',
            '-3',
            '--extSKID',
            '--extAIA'
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        keystroke = ''

        # Is this a CA certificate [y/N]?
        keystroke += 'y\n'

        # Enter the path length constraint, enter to skip [<0 for unlimited path]:
        keystroke += '\n'

        # Is this a critical extension [y/N]?
        keystroke += 'y\n'

        # Enter value for the authKeyID extension [y/N]?
        keystroke += 'y\n'

        # TODO: generate SHA1 ID (see APolicyRule.formSHA1KeyId())
        # Enter value for the key identifier fields,enter to omit:
        keystroke += '2d:7e:83:37:75:5a:fd:0e:8d:52:a3:70:16:93:36:b8:4a:d6:84:9f\n'

        # Select one of the following general name type:
        keystroke += '0\n'

        # Enter value for the authCertSerial field, enter to omit:
        keystroke += '\n'

        # Is this a critical extension [y/N]?
        keystroke += '\n'

        # TODO: generate SHA1 ID (see APolicyRule.formSHA1KeyId())
        # Adding Subject Key ID extension.
        # Enter value for the key identifier fields,enter to omit:
        keystroke += '2d:7e:83:37:75:5a:fd:0e:8d:52:a3:70:16:93:36:b8:4a:d6:84:9f\n'

        # Is this a critical extension [y/N]?
        keystroke += '\n'

        # Enter access method type for Authority Information Access extension:
        keystroke += '2\n'

        # Select one of the following general name type:
        keystroke += '7\n'

        # TODO: replace with actual hostname name and port number
        # Enter data:
        keystroke += 'http://server.example.com:8080/ca/ocsp\n'

        # Select one of the following general name type:
        keystroke += '0\n'

        # Add another location to the Authority Information Access extension [y/N]
        keystroke += '\n'

        # Is this a critical extension [y/N]?
        keystroke += '\n'

        p.communicate(keystroke)

        rc = p.wait()

        if rc:
            raise Exception('Failed to generate self-signed CA certificate. RC: %d' + rc)

    def get_cert(self, nickname, output_format='pem'):

        if output_format == 'pem':
            output_format_option = '-a'

        elif output_format == 'base64':
            output_format_option = '-r'

        else:
            raise Exception('Unsupported output format: %s' % output_format)

        cert_data = subprocess.check_output([
            'certutil',
            '-L',
            '-d', self.directory,
            '-n', nickname,
            output_format_option
        ])

        if output_format == 'base64':
            cert_data = base64.b64encode(cert_data)

        return cert_data

    def remove_cert(self, nickname):

        subprocess.check_call([
            'certutil',
            '-D',
            '-d', self.directory,
            '-n', nickname
        ])

    def import_pkcs12(self, pkcs12_file, pkcs12_password=None, pkcs12_password_file=None):

        tmpdir = tempfile.mkdtemp()

        try:
            if pkcs12_password:
                password_file = os.path.join(tmpdir, 'password.txt')
                with open(password_file, 'w') as f:
                    f.write(pkcs12_password)

            elif pkcs12_password_file:
                password_file = pkcs12_password_file

            else:
                raise Exception('Missing PKCS #12 password')

            subprocess.check_call([
                'pk12util',
                '-d', self.directory,
                '-k', self.password_file,
                '-i', pkcs12_file,
                '-w', password_file
            ])

        finally:
            shutil.rmtree(tmpdir)

    def export_pkcs12(self, pkcs12_file, nickname, pkcs12_password=None, pkcs12_password_file=None):

        tmpdir = tempfile.mkdtemp()

        try:
            if pkcs12_password:
                password_file = os.path.join(tmpdir, 'password.txt')
                with open(password_file, 'w') as f:
                    f.write(pkcs12_password)

            elif pkcs12_password_file:
                password_file = pkcs12_password_file

            else:
                raise Exception('Missing PKCS #12 password')

            subprocess.check_call([
                'pk12util',
                '-d', self.directory,
                '-k', self.password_file,
                '-o', pkcs12_file,
                '-w', password_file,
                '-n', nickname
            ])

        finally:
            shutil.rmtree(tmpdir)
