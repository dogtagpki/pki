# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#     Dinesh Prasnath M K <dmoluguw@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the Lesser GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2015 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
import base64
import os
import shutil
import subprocess
import tempfile
import re
import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend


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
        lines = [data[i:i + 64] for i in range(0, len(data), 64)]

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

    def __init__(self, directory=None, token=None, password=None, password_file=None,
                 internal_password=None, internal_password_file=None):

        if not directory:
            directory = os.path.join(os.path.expanduser("~"), '.dogtag', 'nssdb')

        self.directory = directory

        if token == 'internal' or token == 'Internal Key Storage Token':
            self.token = None
        else:
            self.token = token

        self.tmpdir = tempfile.mkdtemp()

        if password:
            self.password_file = os.path.join(self.tmpdir, 'password.txt')
            with open(self.password_file, 'w') as f:
                f.write(password)

        elif password_file:
            self.password_file = password_file

        else:
            self.password_file = None

        if internal_password:
            # Store the specified internal token into password file.
            self.internal_password_file = os.path.join(self.tmpdir, 'internal_password.txt')
            with open(self.internal_password_file, 'w') as f:
                f.write(internal_password)

        elif internal_password_file:
            # Use the specified internal token password file.
            self.internal_password_file = internal_password_file

        else:
            # By default use the same password for both internal token and HSM.
            self.internal_password_file = self.password_file

    def close(self):
        shutil.rmtree(self.tmpdir)

    def add_cert(self, nickname, cert_file, trust_attributes=',,'):

        # Add cert in two steps due to bug #1393668.

        # First, import cert into HSM without trust attributes.
        if self.token:
            cmd = [
                'certutil',
                '-A',
                '-d', self.directory,
                '-h', self.token,
                '-f', self.password_file,
                '-n', nickname,
                '-i', cert_file,
                '-t', ''
            ]

            # Ignore return code due to bug #1393668.
            subprocess.call(cmd)

        # Then, import cert into internal token with trust attributes.
        cmd = [
            'certutil',
            '-A',
            '-d', self.directory,
            '-f', self.internal_password_file,
            '-n', nickname,
            '-i', cert_file,
            '-t', trust_attributes
        ]

        subprocess.check_call(cmd)

    def modify_cert(self, nickname, trust_attributes):
        cmd = [
            'certutil',
            '-M',
            '-d', self.directory
        ]

        if self.token:
            cmd.extend(['-h', self.token])

        cmd.extend([
            '-f', self.password_file,
            '-n', nickname,
            '-t', trust_attributes
        ])

        subprocess.check_call(cmd)

    def create_noise(self, noise_file, size=2048):
        subprocess.check_call([
            'openssl',
            'rand',
            '-out', noise_file,
            str(size)
        ])

    def create_request(self, subject_dn, request_file, noise_file=None,
                       key_type=None, key_size=None, curve=None,
                       hash_alg=None,
                       basic_constraints_ext=None,
                       key_usage_ext=None,
                       extended_key_usage_ext=None,
                       generic_exts=None):

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

            keystroke = ''

            cmd = [
                'certutil',
                '-R',
                '-d', self.directory
            ]

            if self.token:
                cmd.extend(['-h', self.token])

            cmd.extend([
                '-f', self.password_file,
                '-s', subject_dn,
                '-o', binary_request_file,
                '-z', noise_file
            ])

            if key_type:
                cmd.extend(['-k', key_type])

            if key_size:
                cmd.extend(['-g', str(key_size)])

            if curve:
                cmd.extend(['-q', curve])

            if hash_alg:
                cmd.extend(['-Z', hash_alg])

            if key_usage_ext:

                cmd.extend(['--keyUsage'])

                usages = []
                for usage in key_usage_ext:
                    if key_usage_ext[usage]:
                        usages.append(usage)

                cmd.extend([','.join(usages)])

            if basic_constraints_ext:

                cmd.extend(['-2'])

                # Is this a CA certificate [y/N]?
                if basic_constraints_ext['ca']:
                    keystroke += 'y'

                keystroke += '\n'

                # Enter the path length constraint, enter to skip [<0 for unlimited path]:
                if basic_constraints_ext['path_length'] is not None:
                    keystroke += basic_constraints_ext['path_length']

                keystroke += '\n'

                # Is this a critical extension [y/N]?
                if basic_constraints_ext['critical']:
                    keystroke += 'y'

                keystroke += '\n'

            if extended_key_usage_ext:

                cmd.extend(['--extKeyUsage'])

                usages = []
                for usage in extended_key_usage_ext:
                    if extended_key_usage_ext[usage]:
                        usages.append(usage)

                cmd.extend([','.join(usages)])

            if generic_exts:

                cmd.extend(['--extGeneric'])

                counter = 0
                exts = []

                for generic_ext in generic_exts:
                    data_file = os.path.join(tmpdir, 'csr-ext-%d' % counter)
                    with open(data_file, 'w') as f:
                        f.write(generic_ext['data'])

                    critical = 'critical' if generic_ext['critical'] else 'not-critical'

                    ext = generic_ext['oid']
                    ext += ':' + critical
                    ext += ':' + data_file

                    exts.append(ext)
                    counter += 1

                cmd.append(','.join(exts))

            # generate binary request
            p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)

            p.communicate(keystroke)

            rc = p.wait()

            if rc:
                raise Exception('Failed to generate certificate request. RC: %d' % rc)

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

    def create_cert(self, request_file, cert_file, serial, issuer=None,
                    key_usage_ext=None, basic_constraints_ext=None,
                    aki_ext=None, ski_ext=None, aia_ext=None, ext_key_usage_ext=None,
                    validity=None):
        cmd = [
            'certutil',
            '-C',
            '-d', self.directory
        ]

        # Check if it's self signed
        if issuer:
            cmd.extend(['-c', issuer])
        else:
            cmd.extend('-x')

        if self.token:
            cmd.extend(['-h', self.token])

        cmd.extend([
            '-f', self.password_file,
            '-a',
            '-i', request_file,
            '-o', cert_file,
            '-m', serial
        ])

        if validity:
            cmd.extend(['-v', str(validity)])

        keystroke = ''

        if aki_ext:
            cmd.extend(['-3'])

            # Enter value for the authKeyID extension [y/N]
            if 'auth_key_id' in aki_ext:
                keystroke += 'y\n'

                # Enter value for the key identifier fields,enter to omit:
                keystroke += aki_ext['auth_key_id']

            keystroke += '\n'

            # Select one of the following general name type:
            # TODO: General Name type isn't used as of now for AKI
            keystroke += '0\n'

            if 'auth_cert_serial' in aki_ext:
                keystroke += aki_ext['auth_cert_serial']

            keystroke += '\n'

            # Is this a critical extension [y/N]?
            if 'critical' in aki_ext and aki_ext['critical']:
                keystroke += 'y'

            keystroke += '\n'

        # Key Usage Constraints
        if key_usage_ext:

            cmd.extend(['--keyUsage'])

            usages = []
            for usage in key_usage_ext:
                if key_usage_ext[usage]:
                    usages.append(usage)

            cmd.extend([','.join(usages)])

        # Extended key usage
        if ext_key_usage_ext:
            cmd.extend(['--extKeyUsage'])
            usages = []
            for usage in ext_key_usage_ext:
                if ext_key_usage_ext[usage]:
                    usages.append(usage)

            cmd.extend([','.join(usages)])

        # Basic constraints
        if basic_constraints_ext:

            cmd.extend(['-2'])

            # Is this a CA certificate [y/N]?
            if basic_constraints_ext['ca']:
                keystroke += 'y'

            keystroke += '\n'

            # Enter the path length constraint, enter to skip [<0 for unlimited path]:
            if basic_constraints_ext['path_length']:
                keystroke += basic_constraints_ext['path_length']

            keystroke += '\n'

            # Is this a critical extension [y/N]?
            if basic_constraints_ext['critical']:
                keystroke += 'y'

            keystroke += '\n'

        if ski_ext:
            cmd.extend(['--extSKID'])

            # Adding Subject Key ID extension.
            # Enter value for the key identifier fields,enter to omit:
            if 'sk_id' in ski_ext:
                keystroke += ski_ext['sk_id']

            keystroke += '\n'

            # Is this a critical extension [y/N]?
            if 'critical' in ski_ext and ski_ext['critical']:
                keystroke += 'y'

            keystroke += '\n'

        if aia_ext:
            cmd.extend(['--extAIA'])

            # To ensure whether this is the first AIA being added
            firstentry = True

            # Enter access method type for Authority Information Access extension:
            for s in aia_ext:
                if not firstentry:
                    keystroke += 'y\n'

                # 1. CA Issuers
                if s == 'ca_issuers':
                    keystroke += '1'

                # 2. OCSP
                if s == 'ocsp':
                    keystroke += '2'
                keystroke += '\n'
                for gn in aia_ext[s]['uri']:
                    # 7. URI
                    keystroke += '7\n'
                    # Enter data
                    keystroke += gn + '\n'

                # Any other number to finish
                keystroke += '0\n'

                # One entry is done.
                firstentry = False

            # Add another location to the Authority Information Access extension [y/N]
            keystroke += '\n'

            # Is this a critical extension [y/N]?
            if 'critical' in aia_ext and aia_ext['critical']:
                keystroke += 'y'

            keystroke += '\n'

        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)

        p.communicate(keystroke)

        rc = p.wait()

        return rc

    def create_self_signed_ca_cert(self, request_file, cert_file,
                                   serial='1', validity=240):

        # --keyUsage
        key_usage_ext = {
            'digitalSignature': True,
            'nonRepudiation': True,
            'certSigning': True,
            'crlSigning': True,
            'critical': True
        }

        # -2
        basic_constraints_ext = {
            'path_length': None
        }

        # FIXME: do not hard-code AKI extension
        # -3
        aki_ext = {
            'auth_key_id': '0x2d7e8337755afd0e8d52a370169336b84ad6849f'
        }

        # FIXME: do not hard-code SKI extension
        # --extSKID
        ski_ext = {
            'sk_id': '0x2d7e8337755afd0e8d52a370169336b84ad6849f'
        }

        # FIXME: do not hard-code AIA extension
        # --extAIA
        aia_ext = {
            'ocsp': {
                'uri': ['http://server.example.com:8080/ca/ocsp']
            }

        }

        rc = self.create_cert(
            request_file=request_file,
            cert_file=cert_file,
            serial=serial,
            validity=validity,
            key_usage_ext=key_usage_ext,
            basic_constraints_ext=basic_constraints_ext,
            aki_ext=aki_ext,
            ski_ext=ski_ext,
            aia_ext=aia_ext)

        if rc:
            raise Exception('Failed to generate self-signed CA certificate. RC: %d' % rc)

    def show_certs(self):

        cmd = [
            'certutil',
            '-L',
            '-d', self.directory
        ]

        subprocess.check_call(cmd)

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
            '-d', self.directory
        ]

        fullname = nickname

        if self.token:
            cmd.extend(['-h', self.token])
            fullname = self.token + ':' + fullname

        cmd.extend([
            '-f', self.password_file,
            '-n', fullname,
            output_format_option
        ])

        try:
            cert_data = subprocess.check_output(cmd)

            if output_format == 'base64':
                cert_data = base64.b64encode(cert_data)

            return cert_data

        except subprocess.CalledProcessError:
            # All certutil errors return the same code (i.e. 255).
            # For now assume it was caused by missing certificate.
            # TODO: Check error message. If it's caused by other
            # issue, throw exception.
            return None

    def get_cert_info(self, nickname):

        cert = dict()
        cmd_extract_serial = [
            'certutil',
            '-L',
            '-d', self.directory,
            '-n', nickname
        ]

        cert_details = subprocess.check_output(cmd_extract_serial, stderr=subprocess.STDOUT)
        cert_pem = subprocess.check_output(
            cmd_extract_serial + ['-a'], stderr=subprocess.STDOUT)

        cert_obj = x509.load_pem_x509_certificate(cert_pem, backend=default_backend())

        cert["serial_number"] = cert_obj.serial_number

        cert["issuer"] = re.search(r'Issuer:(.*)', cert_details).group(1).strip()\
            .replace('"', '')
        cert["subject"] = re.search(r'Subject:(.*)', cert_details).group(1).strip()\
            .replace('"', '')

        str_not_before = re.search(r'Not Before.?:(.*)', cert_details).group(1).strip()
        cert["not_before"] = self.convert_time_to_millis(str_not_before)

        str_not_after = re.search(r'Not After.?:(.*)', cert_details).group(1).strip()
        cert["not_after"] = self.convert_time_to_millis(str_not_after)

        return cert

    @staticmethod
    def convert_time_to_millis(date):
        epoch = datetime.datetime.utcfromtimestamp(0)
        stripped_date = datetime.datetime.strptime(date, "%a %b %d %H:%M:%S %Y")
        return (stripped_date - epoch).total_seconds() * 1000

    def remove_cert(self, nickname, remove_key=False):

        cmd = ['certutil']

        if remove_key:
            cmd.extend(['-F'])
        else:
            cmd.extend(['-D'])

        cmd.extend(['-d', self.directory])

        if self.token:
            cmd.extend(['-h', self.token])

        cmd.extend([
            '-f', self.password_file,
            '-n', nickname
        ])

        subprocess.check_call(cmd)

    def import_cert_chain(self, nickname, cert_chain_file,
                          trust_attributes=None):

        tmpdir = tempfile.mkdtemp()

        try:
            file_type = get_file_type(cert_chain_file)

            if file_type == 'cert':  # import single PEM cert
                self.add_cert(
                    nickname=nickname,
                    cert_file=cert_chain_file,
                    trust_attributes=trust_attributes)
                return (
                    self.get_cert(nickname=nickname, output_format='base64'),
                    [nickname]
                )

            elif file_type == 'pkcs7':  # import PKCS #7 cert chain
                chain, nicks = self.import_pkcs7(
                    pkcs7_file=cert_chain_file,
                    nickname=nickname,
                    trust_attributes=trust_attributes,
                    output_format='base64')
                return chain, nicks

            else:  # import PKCS #7 data without header/footer
                with open(cert_chain_file, 'r') as f:
                    base64_data = f.read()

                # TODO: fix ipaserver/install/cainstance.py in IPA
                # to no longer remove PKCS #7 header/footer

                # join base-64 data into a single line
                base64_data = base64_data.replace('\r', '').replace('\n', '')

                pkcs7_data = convert_pkcs7(base64_data, 'base64', 'pem')

                tmp_cert_chain_file = os.path.join(tmpdir, 'cert_chain.p7b')
                with open(tmp_cert_chain_file, 'w') as f:
                    f.write(pkcs7_data)

                chain, nicks = self.import_pkcs7(
                    pkcs7_file=tmp_cert_chain_file,
                    nickname=nickname,
                    trust_attributes=trust_attributes)

                return base64_data, nicks

        finally:
            shutil.rmtree(tmpdir)

    def import_pkcs7(self, pkcs7_file, nickname, trust_attributes=None,
                     output_format='pem'):

        subprocess.check_call([
            'pki',
            '-d', self.directory,
            '-C', self.password_file,
            'client-cert-import',
            '--pkcs7', pkcs7_file,
            '--trust', trust_attributes,
            nickname
        ])

        # convert PKCS #7 data to the requested format
        with open(pkcs7_file, 'r') as f:
            data = f.read()

        return convert_pkcs7(data, 'pem', output_format), [nickname]

    def import_pkcs12(self, pkcs12_file,
                      pkcs12_password=None,
                      pkcs12_password_file=None,
                      no_user_certs=False,
                      no_ca_certs=False,
                      overwrite=False):

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

            if self.token:
                cmd.extend(['--token', self.token])

            cmd.extend([
                'pkcs12-import',
                '--pkcs12-file', pkcs12_file,
                '--pkcs12-password-file', password_file
            ])

            if no_user_certs:
                cmd.extend(['--no-user-certs'])

            if no_ca_certs:
                cmd.extend(['--no-ca-certs'])

            if overwrite:
                cmd.extend(['--overwrite'])

            subprocess.check_call(cmd)

        finally:
            shutil.rmtree(tmpdir)

    def export_pkcs12(self, pkcs12_file,
                      pkcs12_password=None,
                      pkcs12_password_file=None,
                      nicknames=None,
                      append=False,
                      include_trust_flags=True,
                      include_key=True,
                      include_chain=True,
                      debug=False):

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

            if self.token:
                cmd.extend(['--token', self.token])

            cmd.extend(['pkcs12-export'])

            cmd.extend([
                '--pkcs12-file', pkcs12_file,
                '--pkcs12-password-file', password_file
            ])

            if append:
                cmd.extend(['--append'])

            if not include_trust_flags:
                cmd.extend(['--no-trust-flags'])

            if not include_key:
                cmd.extend(['--no-key'])

            if not include_chain:
                cmd.extend(['--no-chain'])

            if debug:
                cmd.extend(['--debug'])

            if nicknames:
                cmd.extend(nicknames)

            subprocess.check_call(cmd)

        finally:
            shutil.rmtree(tmpdir)
