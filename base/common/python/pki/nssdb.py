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

PKCS7_HEADER = '-----BEGIN PKCS7-----'
PKCS7_FOOTER = '-----END PKCS7-----'


def convert_data(data, input_format, output_format, header=None, footer=None):

    if input_format == output_format:
        return data

    if input_format == 'base64' and output_format == 'pem':

        # join base-64 data into a single line
        data = data.replace('\r', '').replace('\n', '')

        # re-split the line into fixed-length lines
        lines = [data[i:i+64] for i in range(0, len(data), 64)]

        # add header and footer
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

def convert_pkcs7(pkcs7_data, input_format, output_format):

    return convert_data(pkcs7_data, input_format, output_format, PKCS7_HEADER, PKCS7_FOOTER)

def get_file_type(filename):

    with open(filename, 'r') as f:
        data = f.read()

    if data.startswith(CSR_HEADER):
        return 'csr'

    if data.startswith(CERT_HEADER):
        return 'cert'

    if data.startswith(PKCS7_HEADER):
        return 'pkcs7'

    return None


class NSSDatabase(object):

    def __init__(self, directory, token='internal', password=None, password_file=None):
        self.directory = directory
        self.token = token

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
        nickname,
        cert_file,
        trust_attributes=',,'):

        cmd = [
            'certutil',
            '-A',
            '-d', self.directory,
            '-h', self.token,
            '-f', self.password_file,
            '-n', nickname,
            '-i', cert_file,
            '-t', trust_attributes
        ]

        subprocess.check_call(cmd)

    def modify_cert(self,
        nickname,
        trust_attributes):

        cmd = [
            'certutil',
            '-M',
            '-d', self.directory,
            '-h', self.token,
            '-f', self.password_file,
            '-n', nickname,
            '-t', trust_attributes
        ]

        subprocess.check_call(cmd)

    def create_noise(self, noise_file, size=2048):

        subprocess.check_call([
            'openssl',
            'rand',
            '-out', noise_file,
            str(size)
        ])

    def create_request(self,
        subject_dn,
        request_file,
        noise_file=None,
        key_type=None,
        key_size=None,
        curve=None,
        hash_alg=None):

        tmpdir = tempfile.mkdtemp()

        try:
            if not noise_file:
                noise_file = os.path.join(tmpdir, 'noise.bin')
                if key_size:
                    size = key_size
                else:
                    size = 2048
                self.create_noise(
                    noise_file=noise_file,
                    size=size)

            binary_request_file = os.path.join(tmpdir, 'request.bin')

            cmd = [
                'certutil',
                '-R',
                '-d', self.directory,
                '-h', self.token,
                '-f', self.password_file,
                '-s', subject_dn,
                '-o', binary_request_file,
                '-z', noise_file
            ]

            if key_type:
                cmd.extend(['-k', key_type])

            if key_size:
                cmd.extend(['-g', str(key_size)])

            if curve:
                cmd.extend(['-q', curve])

            if hash_alg:
                cmd.extend(['-Z', hash_alg])

            # generate binary request
            subprocess.check_call(cmd)

            # encode binary request in base-64
            b64_request_file = os.path.join(tmpdir, 'request.b64')
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

        cmd = [
            'certutil',
            '-C',
            '-x',
            '-d', self.directory,
            '-h', self.token,
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
        ]

        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

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
            raise Exception('Failed to generate self-signed CA certificate. RC: %d' % rc)

    def get_cert(self, nickname, output_format='pem'):

        if output_format == 'pem':
            output_format_option = '-a'

        elif output_format == 'base64':
            output_format_option = '-r'

        else:
            raise Exception('Unsupported output format: %s' % output_format)

        cmd = [
            'certutil',
            '-L',
            '-d', self.directory,
            '-h', self.token,
            '-f', self.password_file,
            '-n', nickname,
            output_format_option
        ]

        cert_data = subprocess.check_output(cmd)

        if output_format == 'base64':
            cert_data = base64.b64encode(cert_data)

        return cert_data

    def remove_cert(self, nickname):

        cmd = [
            'certutil',
            '-D',
            '-d', self.directory,
            '-h', self.token,
            '-f', self.password_file,
            '-n', nickname
        ]

        subprocess.check_call(cmd)

    def import_cert_chain(self, nickname, cert_chain_file, trust_attributes=None):

        tmpdir = tempfile.mkdtemp()

        try:
            file_type = get_file_type(cert_chain_file)

            if file_type == 'cert': # import single PEM cert
                self.add_cert(
                    nickname=nickname,
                    cert_file=cert_chain_file,
                    trust_attributes=trust_attributes)
                return self.get_cert(
                    nickname=nickname,
                    output_format='base64')

            elif file_type == 'pkcs7': # import PKCS #7 cert chain
                return self.import_pkcs7(
                    pkcs7_file=cert_chain_file,
                    nickname=nickname,
                    trust_attributes=trust_attributes,
                    output_format='base64')

            else: # import PKCS #7 data without header/footer
                with open(cert_chain_file, 'r') as f:
                    base64_data = f.read()
                pkcs7_data = convert_pkcs7(base64_data, 'base64', 'pem')

                tmp_cert_chain_file = os.path.join(tmpdir, 'cert_chain.p7b')
                with open(tmp_cert_chain_file, 'w') as f:
                    f.write(pkcs7_data)

                self.import_pkcs7(
                    pkcs7_file=tmp_cert_chain_file,
                    nickname=nickname,
                    trust_attributes=trust_attributes)

                return base64_data

        finally:
            shutil.rmtree(tmpdir)

    def import_pkcs7(self, pkcs7_file, nickname, trust_attributes=None, output_format='pem'):

        tmpdir = tempfile.mkdtemp()

        try:
            # export certs from PKCS #7 into PEM output
            output = subprocess.check_output([
                'openssl',
                'pkcs7',
                '-print_certs',
                '-in', pkcs7_file
            ])

            # parse PEM output into separate PEM certificates
            certs = []
            lines = []
            state = 'header'

            for line in output.splitlines():

                if state == 'header':
                    if line != CERT_HEADER:
                        # ignore header lines
                        pass
                    else:
                        # save cert header
                        lines.append(line)
                        state = 'body'

                elif state == 'body':
                    if line != CERT_FOOTER:
                        # save cert body
                        lines.append(line)
                    else:
                        # save cert footer
                        lines.append(line)

                        # construct PEM cert
                        cert = '\n'.join(lines)
                        certs.append(cert)
                        lines = []
                        state = 'header'

            # import PEM certs into NSS database
            counter = 1
            for cert in certs:

                cert_file = os.path.join(tmpdir, 'cert%d.pem' % counter)
                with open(cert_file, 'w') as f:
                    f.write(cert)

                if counter == 1:
                    n = nickname
                else:
                    n = '%s #%d' % (nickname, counter)

                self.add_cert(n, cert_file, trust_attributes)

                counter += 1

            # convert PKCS #7 data to the requested format
            with open(pkcs7_file, 'r') as f:
                data = f.read()

            return convert_pkcs7(data, 'pem', output_format)

        finally:
            shutil.rmtree(tmpdir)

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

            cmd = [
                'pki',
                '-d', self.directory,
                '-C', self.password_file
            ]

            if self.token and self.token != 'internal':
                cmd.extend(['--token', self.token])

            cmd.extend([
                'pkcs12-import',
                '--pkcs12', pkcs12_file,
                '--pkcs12-password-file', password_file
            ])

            subprocess.check_call(cmd)

        finally:
            shutil.rmtree(tmpdir)

    def export_pkcs12(self, pkcs12_file, nicknames=None, pkcs12_password=None,
                      pkcs12_password_file=None):

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

            cmd = [
                'pki',
                '-d', self.directory,
                '-C', self.password_file
            ]

            if self.token and self.token != 'internal':
                cmd.extend(['--token', self.token])

            cmd.extend(['pkcs12-export'])

            cmd.extend([
                '--pkcs12', pkcs12_file,
                '--pkcs12-password-file', password_file
            ])

            if nicknames:
                cmd.extend(nicknames)

            subprocess.check_call(cmd)

        finally:
            shutil.rmtree(tmpdir)
