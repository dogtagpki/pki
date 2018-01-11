# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
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
import binascii
import logging
import os
import re
import shutil
import stat
import subprocess
import tempfile
import datetime

import six

from cryptography import x509
from cryptography.hazmat.backends import default_backend

try:
    import selinux
except ImportError:
    selinux = None

import pki

CSR_HEADER = '-----BEGIN CERTIFICATE REQUEST-----'
CSR_FOOTER = '-----END CERTIFICATE REQUEST-----'

LEGACY_CSR_HEADER = '-----BEGIN NEW CERTIFICATE REQUEST-----'
LEGACY_CSR_FOOTER = '-----END NEW CERTIFICATE REQUEST-----'

CERT_HEADER = '-----BEGIN CERTIFICATE-----'
CERT_FOOTER = '-----END CERTIFICATE-----'

PKCS7_HEADER = '-----BEGIN PKCS7-----'
PKCS7_FOOTER = '-----END PKCS7-----'

INTERNAL_TOKEN_NAME = 'internal'
INTERNAL_TOKEN_FULL_NAME = 'Internal Key Storage Token'

logger = logging.LoggerAdapter(
    logging.getLogger(__name__),
    extra={'indent': ''})


def convert_data(data, input_format, output_format,
                 header=None, footer=None,
                 headers=None, footers=None):
    '''
    This method converts a PEM file to base-64 and vice versa.
    It supports CSR, certificate, and PKCS #7 certificate chain.
    '''

    if input_format == output_format:
        return data

    # converting from base-64 to PEM
    if input_format == 'base64' and output_format == 'pem':

        # join base-64 data into a single line
        data = data.replace('\r', '').replace('\n', '')

        # re-split the line into fixed-length lines
        lines = [data[i:i + 64] for i in range(0, len(data), 64)]

        # add header and footer
        return '%s\n%s\n%s\n' % (header, '\n'.join(lines), footer)

    # converting from PEM to base-64
    if input_format == 'pem' and output_format == 'base64':

        # initialize list of headers if not provided
        if not headers:
            headers = [header]

        # initialize list of footers if not provided
        if not footers:
            footers = [footer]

        # join multiple lines into a single line
        lines = []
        for line in data.splitlines():
            line = line.rstrip('\r\n')

            # if the line is a header, skip
            if line in headers:
                continue

            # if the line is a footer, skip
            if line in footers:
                continue

            lines.append(line)

        return ''.join(lines)

    raise Exception('Unable to convert data from {} to {}'.format(
        input_format, output_format))


def convert_csr(csr_data, input_format, output_format):
    return convert_data(csr_data, input_format, output_format,
                        CSR_HEADER, CSR_FOOTER,
                        headers=[CSR_HEADER, LEGACY_CSR_HEADER],
                        footers=[CSR_FOOTER, LEGACY_CSR_FOOTER])


def convert_cert(cert_data, input_format, output_format):
    return convert_data(cert_data, input_format, output_format,
                        CERT_HEADER, CERT_FOOTER)


def convert_pkcs7(pkcs7_data, input_format, output_format):
    return convert_data(pkcs7_data, input_format, output_format,
                        PKCS7_HEADER, PKCS7_FOOTER)


def get_file_type(filename):
    '''
    This method detects the content of a PEM file. It supports
    CSR, certificate, PKCS #7 certificate chain.
    '''

    with open(filename, 'r') as f:
        data = f.read()

    if data.startswith(CSR_HEADER) or data.startswith(LEGACY_CSR_HEADER):
        return 'csr'

    if data.startswith(CERT_HEADER):
        return 'cert'

    if data.startswith(PKCS7_HEADER):
        return 'pkcs7'

    return None


def normalize_token(token):
    """
    Normalize internal token name (e.g. empty string, 'internal',
    'Internal Key Storage Token') into None. Other token names
    will be unchanged.
    """
    if not token:
        return None

    if token.lower() == INTERNAL_TOKEN_NAME:
        return None

    if token.lower() == INTERNAL_TOKEN_FULL_NAME.lower():
        return None

    return token


class NSSDatabase(object):

    def __init__(self, directory=None,
                 token=None,
                 password=None,
                 password_file=None,
                 internal_password=None,
                 internal_password_file=None,
                 passwords=None):

        if not directory:
            directory = os.path.join(
                os.path.expanduser("~"), '.dogtag', 'nssdb')

        self.directory = directory
        self.token = normalize_token(token)

        self.tmpdir = tempfile.mkdtemp()

        if password:
            # if token password is provided, store it in a temp file
            self.password_file = self.create_password_file(
                self.tmpdir, password)

        elif password_file:
            # if token password file is provided, use the file
            self.password_file = password_file

        else:
            self.password_file = None

        if internal_password:
            # if internal password is provided, store it in a temp file
            self.internal_password_file = self.create_password_file(
                self.tmpdir, internal_password, 'internal_password.txt')

        elif internal_password_file:
            # if internal password file is provided, use the file
            self.internal_password_file = internal_password_file

        else:
            # By default use the same password for both internal token and HSM.
            self.internal_password_file = self.password_file

        self.passwords = passwords

    def close(self):
        shutil.rmtree(self.tmpdir)

    def get_effective_token(self, token=None):
        if not normalize_token(token):
            return self.token
        return token

    def create_password_file(self, tmpdir, password, filename=None):
        if not filename:
            filename = 'password.txt'
        password_file = os.path.join(tmpdir, filename)
        with open(password_file, 'w') as f:
            f.write(password)
        return password_file

    def get_password_file(self, tmpdir, token, filename=None):

        # if no password map is provided, use password file
        if not self.passwords:
            return self.password_file

        # if password map is provided, get token password
        if normalize_token(token):
            token = 'hardware-%s' % token
        else:
            token = INTERNAL_TOKEN_NAME
        password = self.passwords[token]

        # then store it in a temp file
        return self.create_password_file(
            tmpdir,
            password,
            filename)

    def get_dbtype(self):
        def dbexists(filename):
            return os.path.isfile(os.path.join(self.directory, filename))

        if dbexists('cert9.db'):
            if not dbexists('key4.db') or not dbexists('pkcs11.txt'):
                raise RuntimeError(
                    "{} contains an incomplete NSS database in SQL "
                    "format".format(self.directory)
                )
            return 'sql'
        elif dbexists('cert8.db'):
            if not dbexists('key3.db') or not dbexists('secmod.db'):
                raise RuntimeError(
                    "{} contains an incomplete NSS database in DBM "
                    "format".format(self.directory)
                )
            return 'dbm'
        else:
            return None

    def needs_conversion(self):
        # Only attempt to convert if target format is SQL and DB is DBM
        dest_dbtype = os.environ.get('NSS_DEFAULT_DB_TYPE')
        return dest_dbtype == 'sql' and self.get_dbtype() == 'dbm'

    def convert_db(self):
        dbtype = self.get_dbtype()
        if dbtype is None:
            raise ValueError(
                "NSS database {} does not exist".format(self.directory)
            )
        elif dbtype == 'sql':
            raise ValueError(
                "NSS database {} already in SQL format".format(self.directory)
            )

        logger.info(
            "Convert NSSDB %s from DBM to SQL format", self.directory
        )

        basecmd = [
            'certutil',
            '-d', 'sql:{}'.format(self.directory),
            '-f', self.password_file,
        ]
        # See https://fedoraproject.org/wiki/Changes/NSSDefaultFileFormatSql
        cmd = basecmd + [
            '-N',
            '-@', self.password_file
        ]

        logger.debug('Command: %s', ' '.join(map(str, cmd)))
        subprocess.check_call(cmd)

        migration = (
            ('cert8.db', 'cert9.db'),
            ('key3.db', 'key4.db'),
            ('secmod.db', 'pkcs11.txt'),
        )

        for oldname, newname in migration:
            oldname = os.path.join(self.directory, oldname)
            newname = os.path.join(self.directory, newname)
            oldstat = os.stat(oldname)
            os.chmod(newname, stat.S_IMODE(oldstat.st_mode))
            os.chown(newname, oldstat.st_uid, oldstat.st_gid)

        if selinux is not None and selinux.is_selinux_enabled():
            selinux.restorecon(self.directory, recursive=True)

        # list certs to verify DB
        if self.get_dbtype() != 'sql':
            raise RuntimeError(
                "Migration of NSS database {} was not successfull.".format(
                    self.directory
                )
            )

        with open(os.devnull, 'wb') as f:
            subprocess.check_call(basecmd + ['-L'], stdout=f)

        for oldname, _ in migration:  # pylint: disable=unused-variable
            oldname = os.path.join(self.directory, oldname)
            os.rename(oldname, oldname + '.migrated')

        logger.info("Migration successful")

    def add_cert(self, nickname, cert_file, token=None, trust_attributes=None):

        tmpdir = tempfile.mkdtemp()
        try:
            token = self.get_effective_token(token)
            password_file = self.get_password_file(tmpdir, token)

            # Add cert in two steps due to bug #1393668.

            # If HSM is used, import cert into HSM without trust attributes.
            if token:
                cmd = [
                    'certutil',
                    '-A',
                    '-d', self.directory,
                    '-h', token,
                    '-P', token,
                    '-f', password_file,
                    '-n', nickname,
                    '-a',
                    '-i', cert_file,
                    '-t', ''
                ]

                logger.debug('Command: %s', ' '.join(map(str, cmd)))
                rc = subprocess.call(cmd)

                if rc:
                    logger.warning('certutil returned non-zero exit code (bug #1393668)')

            if not trust_attributes:
                trust_attributes = ',,'

            # If HSM is not used, or cert has trust attributes,
            # import cert into internal token.
            if not token or trust_attributes != ',,':
                cmd = [
                    'certutil',
                    '-A',
                    '-d', self.directory,
                    '-f', self.internal_password_file,
                    '-n', nickname,
                    '-a',
                    '-i', cert_file,
                    '-t', trust_attributes
                ]

                logger.debug('Command: %s', ' '.join(map(str, cmd)))
                subprocess.check_call(cmd)

        finally:
            shutil.rmtree(tmpdir)

    def add_ca_cert(self, cert_file, trust_attributes=None):

        # Import CA certificate into internal token with automatically
        # assigned nickname.

        # If the certificate has previously been imported, it will keep
        # the existing nickname. If the certificate has not been imported,
        # JSS will generate a nickname based on root CA's subject DN.

        # For example, if the root CA's subject DN is "CN=CA Signing
        # Certificate, O=EXAMPLE", the root CA cert's nickname will be
        # "CA Signing Certificate - EXAMPLE". The subordinate CA cert's
        # nickname will be "CA Signing Certificate - EXAMPLE #2".

        cmd = [
            'pki',
            '-d', self.directory,
            '-C', self.internal_password_file
        ]

        cmd.extend([
            'client-cert-import',
            '--ca-cert', cert_file
        ])

        if trust_attributes:
            cmd.extend(['--trust', trust_attributes])

        logger.debug('Command: %s', ' '.join(map(str, cmd)))
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

        logger.debug('Command: %s', ' '.join(map(str, cmd)))
        subprocess.check_call(cmd)

    def create_noise(self, noise_file, size=2048):
        cmd = [
            'openssl',
            'rand',
            '-out', noise_file,
            str(size)
        ]

        logger.debug('Command: %s', ' '.join(map(str, cmd)))
        subprocess.check_call(cmd)

    def create_request(
            self,
            subject_dn,
            request_file,
            token=None,
            noise_file=None,
            key_type=None,
            key_size=None,
            curve=None,
            hash_alg=None,
            basic_constraints_ext=None,
            key_usage_ext=None,
            extended_key_usage_ext=None,
            cka_id=None,
            subject_key_id=None,
            generic_exts=None):
        """
        Generate a CSR.

        ``cka_id``
            PKCS #11 CKA_ID of key in the NSSDB to use, as text.
            If ``None`` a new key will be generated (this is
            the typical use case).

        ``subject_key_id``
            If ``None``, no Subject Key ID will be included in the
            request.  If ``"DEFAULT"``, the Subject Key ID will be
            derived from the generated key, using the default
            digest.  Otherwise the value must be a hex-encoded
            string, without leading ``0x``, containing the desired
            Subject Key ID.

        ``generic_exts``
            List of generic extensions, each being a mapping with
            the following keys:

            ``oid``
                Extension OID (``str``)
            ``critical``
                ``bool``
            ``data``
                Raw extension data (``bytes``)

        """
        if cka_id is not None and not isinstance(cka_id, six.text_type):
            raise TypeError('cka_id must be a text string')

        tmpdir = tempfile.mkdtemp()

        try:
            if subject_key_id is not None:
                if subject_key_id == 'DEFAULT':
                    # Caller wants a default subject key ID included
                    # in CSR.  To do this we must first generate a
                    # key and temporary CSR, then compute an SKI
                    # from the public key data.

                    if not cka_id:
                        cka_id = self.__generate_key(
                            tmpdir, key_type=key_type, key_size=key_size,
                            curve=curve, noise_file=noise_file, token=token)

                    tmp_csr = os.path.join(tmpdir, 'tmp_csr.pem')
                    self.create_request(
                        subject_dn, tmp_csr,
                        token=token, cka_id=cka_id, subject_key_id=None)
                    with open(tmp_csr, 'rb') as f:
                        data = f.read()
                    csr = x509.load_pem_x509_csr(data, default_backend())
                    pub = csr.public_key()
                    ski = x509.SubjectKeyIdentifier.from_public_key(pub)
                    ski_bytes = ski.digest
                else:
                    # Explicit subject_key_id provided; decode it
                    ski_bytes = binascii.unhexlify(subject_key_id)

                if generic_exts is None:
                    generic_exts = []
                generic_exts.append({
                    'oid': x509.SubjectKeyIdentifier.oid.dotted_string,
                    'critical': False,
                    'data': bytearray([0x04, len(ski_bytes)]) + ski_bytes,
                    # OCTET STRING     ^tag  ^length            ^data
                    #
                    # This structure is incorrect if len > 127 bytes, but this
                    # will be fine for a CKA_ID or SKID of sensible length.
                })

            binary_request_file = os.path.join(tmpdir, 'request.bin')

            keystroke = ''

            cmd = [
                'certutil',
                '-R',
                '-d', self.directory
            ]

            if cka_id is not None:
                key_args = ['-k', cka_id]
            else:
                key_args = self.__generate_key_args(
                    key_type=key_type, key_size=key_size, curve=curve)
                if noise_file is None:
                    noise_file = os.path.join(tmpdir, 'noise')
                    size = key_size if key_size else 2048
                    self.create_noise(noise_file=noise_file, size=size)
                key_args.extend(['-z', noise_file])

            cmd.extend(key_args)

            token = self.get_effective_token(token)
            password_file = self.get_password_file(tmpdir, token)

            if token:
                cmd.extend(['-h', token])

            cmd.extend([
                '-f', password_file,
                '-s', subject_dn,
                '-o', binary_request_file,
            ])

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

                # Enter the path length constraint,
                # enter to skip [<0 for unlimited path]:
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
                exts = []

                for i, ext in enumerate(generic_exts):
                    data_file = os.path.join(tmpdir, 'csr-ext-%d' % i)
                    with open(data_file, 'wb') as f:
                        f.write(ext['data'])

                    if ext['critical']:
                        critical = 'critical'
                    else:
                        critical = 'not-critical'

                    exts.append(
                        '{}:{}:{}'.format(ext['oid'], critical, data_file)
                    )

                cmd.append(','.join(exts))

            logger.debug('Command: %s', ' '.join(map(str, cmd)))

            # generate binary request
            p = subprocess.Popen(cmd,
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)

            p.communicate(keystroke.encode('ascii'))

            rc = p.wait()

            if rc:
                raise Exception(
                    'Failed to generate certificate request. RC: %d' % rc)

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

    def __generate_key(
            self, tmpdir,
            key_type=None, key_size=None, curve=None,
            noise_file=None, token=None):
        """
        Generate a key of the given type and size.
        Returns the CKA_ID of the generated key, as a text string.

        This method enumerates all keys in the token, twice.  This
        could be expensive on an HSM with lots of keys.  Therefore
        avoid this method if possible.

        ``tmpdir``
          An existing temporary dir where a password file can be
          written.  Must be valid.  It is caller responsibility to
          create it and clean it up.

        ``noise_file``
          Path to a noise file, or ``None`` to automatically
          generate a noise file.

        """
        password_file = self.get_password_file(tmpdir, token)
        ids_pre = set(self.__list_private_keys(password_file, token=token))

        cmd = [
            'certutil',
            '-d', self.directory,
            '-f', password_file,
            '-G',
        ]

        token = self.get_effective_token(token)
        if token:
            cmd.extend(['-h', token])

        cmd.extend(self.__generate_key_args(
            key_type=key_type, key_size=key_size, curve=curve))

        temp_noise_file = noise_file is None
        if temp_noise_file:
            fd, noise_file = tempfile.mkstemp()
            os.close(fd)
            size = key_size if key_size else 2048
            self.create_noise(noise_file=noise_file, size=size)
        cmd.extend(['-z', noise_file])

        try:
            subprocess.check_call(cmd)
        finally:
            if temp_noise_file:
                os.unlink(noise_file)

        ids_post = set(self.__list_private_keys(password_file, token=token))
        return list(ids_post - ids_pre)[0].decode('ascii')

    def __list_private_keys(self, password_file, token=None):
        """
        Return list of hex-encoded private key CKA_IDs in the token.

        """
        cmd = [
            'certutil',
            '-d', self.directory,
            '-f', password_file,
            '-K',
        ]

        token = self.get_effective_token(token)
        if token:
            cmd.extend(['-h', token])

        try:
            out = subprocess.check_output(cmd)
        except subprocess.CalledProcessError as e:
            if e.returncode == 255:
                return []  # no keys were found
            else:
                raise e  # other error; re-raise

        # output contains list that looks like:
        #   < 0> rsa      b995381610fb58e8b45d3c2401dfd30d6efdd595 (orphan)
        #   < 1> rsa      dcd6cbc1226ede02a961488553b01639ff981cdd someNickame
        #
        # The hex string is the hex-encoded CKA_ID
        return re.findall(br'^<\s*\d+>\s+\w+\s+(\w+)', out, re.MULTILINE)

    def create_cert(self, request_file, cert_file, serial, issuer=None,
                    key_usage_ext=None, basic_constraints_ext=None,
                    aki_ext=None, ski_ext=None, aia_ext=None,
                    ext_key_usage_ext=None, validity=None):
        cmd = [
            'certutil',
            '-C',
            '-d', self.directory
        ]

        # Check if it's self signed
        if issuer:
            cmd.extend(['-c', issuer])
        else:
            cmd.extend(['-x'])

        if self.token:
            cmd.extend(['-h', self.token])

        cmd.extend([
            '-f', self.password_file,
            '-a',
            '-i', request_file,
            '-o', cert_file,
            '-m', str(serial)
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

            # Enter the path length constraint,
            # enter to skip [<0 for unlimited path]:
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

            # Enter access method type for AIA extension:
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

            # Add another location to the Authority Information
            # Access extension [y/N]
            keystroke += '\n'

            # Is this a critical extension [y/N]?
            if 'critical' in aia_ext and aia_ext['critical']:
                keystroke += 'y'

            keystroke += '\n'

        logger.debug('Command: %s', ' '.join(map(str, cmd)))

        p = subprocess.Popen(cmd,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)

        p.communicate(keystroke.encode('ascii'))

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
            raise Exception(
                'Failed to generate self-signed CA certificate. RC: %d' % rc)

    def show_certs(self):

        cmd = [
            'certutil',
            '-L',
            '-d', self.directory
        ]

        logger.debug('Command: %s', ' '.join(map(str, cmd)))
        subprocess.check_call(cmd)

    def get_cert(self, nickname, token=None, output_format='pem',
                 output_text=False):

        if output_format == 'pem':
            output_format_option = '-a'

        elif output_format == 'base64':
            output_format_option = '-r'

        elif output_format == 'pretty-print':
            output_format_option = None

        else:
            raise Exception('Unsupported output format: %s' % output_format)

        tmpdir = tempfile.mkdtemp()
        try:
            token = self.get_effective_token(token)
            password_file = self.get_password_file(tmpdir, token)

            cmd = [
                'certutil',
                '-L',
                '-d', self.directory
            ]

            fullname = nickname

            if token:
                cmd.extend(['-h', token])
                fullname = token + ':' + fullname

            cmd.extend([
                '-f', password_file,
                '-n', fullname
            ])

            if output_format_option:
                cmd.extend([output_format_option])

            logger.debug('Command: %s', ' '.join(map(str, cmd)))

            p = subprocess.Popen(cmd,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)

            cert_data, std_err = p.communicate()

            if std_err:
                # certutil returned an error
                # raise exception unless its not cert not found
                if std_err.startswith(b'certutil: Could not find cert: '):
                    return None

                raise Exception('Could not find cert: %s: %s' % (fullname, std_err.strip()))

            if not cert_data:
                # certutil did not return data
                return None

            if p.returncode != 0:
                logger.warning('certutil returned non-zero exit code (bug #1539996)')

            if output_format == 'base64':
                cert_data = base64.b64encode(cert_data).decode('utf-8')
            if output_text and not isinstance(cert_data, six.string_types):
                cert_data = cert_data.decode('ascii')

            return cert_data

        finally:
            shutil.rmtree(tmpdir)

    def get_cert_info(self, nickname):

        cert_pem = self.get_cert(
            nickname=nickname)

        if not cert_pem:
            return None

        cert_obj = x509.load_pem_x509_certificate(
            cert_pem, backend=default_backend())

        cert = {}
        cert['object'] = cert_obj

        cert['serial_number'] = cert_obj.serial_number

        cert['issuer'] = pki.convert_x509_name_to_dn(cert_obj.issuer)
        cert['subject'] = pki.convert_x509_name_to_dn(cert_obj.subject)

        cert['not_before'] = self.convert_time_to_millis(cert_obj.not_valid_before)
        cert['not_after'] = self.convert_time_to_millis(cert_obj.not_valid_after)

        return cert

    @staticmethod
    def convert_time_to_millis(date):
        epoch = datetime.datetime.utcfromtimestamp(0)
        return (date - epoch).total_seconds() * 1000

    def export_cert(self,
                    nickname,
                    pkcs12_file,
                    pkcs12_password=None,
                    pkcs12_password_file=None,
                    friendly_name=None,
                    cert_encryption=None,
                    key_encryption=None,
                    append=False,
                    include_trust_flags=True,
                    include_key=True,
                    include_chain=True,
                    debug=False):

        tmpdir = tempfile.mkdtemp()

        try:
            if pkcs12_password:
                # if PKCS #12 password is provided, store it in a temp file
                password_file = self.create_password_file(
                    tmpdir, pkcs12_password)

            elif pkcs12_password_file:
                # if PKCS #12 password file is provided, use the file
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
                full_name = self.token + ':' + nickname
            else:
                full_name = nickname

            cmd.extend(['pkcs12-cert-import'])

            cmd.extend([
                '--pkcs12-file', pkcs12_file,
                '--pkcs12-password-file', password_file
            ])

            if cert_encryption:
                cmd.extend(['--cert-encryption', cert_encryption])

            if key_encryption:
                cmd.extend(['--key-encryption', key_encryption])

            if friendly_name:
                cmd.extend(['--friendly-name', friendly_name])

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

            cmd.extend([full_name])

            logger.debug('Command: %s', ' '.join(map(str, cmd)))
            subprocess.check_call(cmd)

        finally:
            shutil.rmtree(tmpdir)

    def remove_cert(
            self,
            nickname,
            token=None,
            remove_key=False):

        tmpdir = tempfile.mkdtemp()
        try:
            token = self.get_effective_token(token)
            password_file = self.get_password_file(tmpdir, token)

            cmd = ['certutil']

            if remove_key:
                cmd.extend(['-F'])
            else:
                cmd.extend(['-D'])

            cmd.extend(['-d', self.directory])

            if token:
                cmd.extend(['-h', token])

            cmd.extend([
                '-f', password_file,
                '-n', nickname
            ])

            logger.debug('Command: %s', ' '.join(map(str, cmd)))
            subprocess.check_call(cmd)

        finally:
            shutil.rmtree(tmpdir)

    def import_cert_chain(
            self,
            nickname,
            cert_chain_file,
            token=None,
            trust_attributes=None):

        tmpdir = tempfile.mkdtemp()

        try:
            file_type = get_file_type(cert_chain_file)

            if file_type == 'cert':  # import single PEM cert
                self.add_cert(
                    nickname=nickname,
                    cert_file=cert_chain_file,
                    token=token,
                    trust_attributes=trust_attributes)
                return (
                    self.get_cert(
                        nickname=nickname,
                        token=token,
                        output_format='base64'),
                    [nickname]
                )

            elif file_type == 'pkcs7':  # import PKCS #7 cert chain
                chain, nicks = self.import_pkcs7(
                    pkcs7_file=cert_chain_file,
                    nickname=nickname,
                    token=token,
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
                    token=token,
                    trust_attributes=trust_attributes)

                return base64_data, nicks

        finally:
            shutil.rmtree(tmpdir)

    def import_pkcs7(
            self,
            pkcs7_file,
            nickname,
            token=None,
            trust_attributes=None,
            output_format='pem'):

        tmpdir = tempfile.mkdtemp()

        try:
            # Sort and split the certs from root to leaf.
            prefix = os.path.join(tmpdir, 'cert')
            suffix = '.crt'

            cmd = [
                'pki',
                '-d', self.directory,
                'pkcs7-cert-export',
                '--pkcs7-file', pkcs7_file,
                '--output-prefix', prefix,
                '--output-suffix', suffix
            ]

            logger.debug('Command: %s', ' '.join(map(str, cmd)))
            subprocess.check_call(cmd)

            # Count the number of certs in the chain.
            n = 0
            while True:
                cert_file = prefix + str(n) + suffix
                if not os.path.exists(cert_file):
                    break
                n = n + 1

            # Import CA certs with default nicknames and trust attributes.
            for i in range(0, n - 1):
                cert_file = prefix + str(i) + suffix
                self.add_ca_cert(cert_file)

            # Import user cert with specified nickname and trust attributes.
            cert_file = prefix + str(n - 1) + suffix
            self.add_cert(
                nickname=nickname,
                cert_file=cert_file,
                token=token,
                trust_attributes=trust_attributes)

        finally:
            shutil.rmtree(tmpdir)

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
                # if PKCS #12 password is provided, store it in a temp file
                password_file = self.create_password_file(
                    tmpdir, pkcs12_password)

            elif pkcs12_password_file:
                # if PKCS #12 password file is provided, use the file
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

            logger.debug('Command: %s', ' '.join(map(str, cmd)))
            subprocess.check_call(cmd)

        finally:
            shutil.rmtree(tmpdir)

    def export_pkcs12(self, pkcs12_file,
                      pkcs12_password=None,
                      pkcs12_password_file=None,
                      nicknames=None,
                      cert_encryption=None,
                      key_encryption=None,
                      append=False,
                      include_trust_flags=True,
                      include_key=True,
                      include_chain=True,
                      debug=False):

        tmpdir = tempfile.mkdtemp()

        try:
            if pkcs12_password:
                # if PKCS #12 password is provided, store it in a temp file
                password_file = self.create_password_file(
                    tmpdir, pkcs12_password)

            elif pkcs12_password_file:
                # if PKCS #12 password file is provided, use the file
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

            if cert_encryption:
                cmd.extend(['--cert-encryption', cert_encryption])

            if key_encryption:
                cmd.extend(['--key-encryption', key_encryption])

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

            logger.debug('Command: %s', ' '.join(map(str, cmd)))
            subprocess.check_call(cmd)

        finally:
            shutil.rmtree(tmpdir)

    @staticmethod
    def __generate_key_args(key_type=None, key_size=None, curve=None):
        """
        Construct certutil keygen command args.

        """
        args = []
        if key_type:
            args.extend(['-k', key_type])
        if key_type.lower() == 'ec':
            # This is fix for Bugzilla 1544843
            args.extend([
                '--keyOpFlagsOn', 'sign',
                '--keyOpFlagsOff', 'derive',
            ])
        if key_size:
            args.extend(['-g', str(key_size)])
        if curve:
            args.extend(['-q', curve])
        return args
