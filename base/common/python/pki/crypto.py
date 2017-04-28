# Authors:
#     Ade Lee <alee@redhat.com>
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
# Copyright (C) 2013 Red Hat, Inc.
# All rights reserved.
#
"""
Module containing crypto classes.
"""
from __future__ import absolute_import
import abc
import os
import shutil
import subprocess
import tempfile

import nss.nss as nss
import six
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
import cryptography.x509

# encryption algorithms OIDs
DES_EDE3_CBC_OID = "{1 2 840 113549 3 7}"
AES_128_CBC_OID = "{2 16 840 1 101 3 4 1 2}"

# Wrap Algorithm names as defined by JSS.
WRAP_AES_CBC_PAD = "AES/CBC/PKCS5Padding"
WRAP_AES_KEY_WRAP = "AES KeyWrap"
WRAP_AES_KEY_WRAP_PAD = "AES KeyWrap/Padding"
WRAP_DES3_CBC_PAD = "DES3/CBC/Pad"


class CryptoProvider(six.with_metaclass(abc.ABCMeta, object)):
    """
    Abstract class containing methods to do cryptographic operations.
    """

    def __init__(self):
        """ Constructor """
        pass

    @abc.abstractmethod
    def initialize(self):
        """ Initialization code """

    @abc.abstractmethod
    def get_supported_algorithm_keyset(self):
        """ returns highest supported algorithm keyset """

    @abc.abstractmethod
    def set_algorithm_keyset(self, level):
        """ sets required keyset """

    @abc.abstractmethod
    def generate_nonce_iv(self, mechanism):
        """ Create a random initialization vector """

    @abc.abstractmethod
    def generate_symmetric_key(self, mechanism=None, size=0):
        """ Generate and return a symmetric key """

    @abc.abstractmethod
    def generate_session_key(self):
        """ Generate a session key to be used for wrapping data to the DRM
        This must return a 3DES 168 bit key """

    @abc.abstractmethod
    def symmetric_wrap(self, data, wrapping_key, mechanism=None,
                       nonce_iv=None):
        """ encrypt data using a symmetric key (wrapping key)"""

    @abc.abstractmethod
    def symmetric_unwrap(self, data, wrapping_key, mechanism=None,
                         nonce_iv=None):
        """ decrypt data originally encrypted with symmetric key (wrapping key)

        We expect the data and nonce_iv values to be base64 encoded.
        The mechanism is the type of key used to do the wrapping.  It defaults
        to a 56 bit DES3 key.
        """

    @abc.abstractmethod
    def asymmetric_wrap(self, data, wrapping_cert, mechanism=None):
        """ encrypt a symmetric key with the public key of a transport cert.

        The mechanism is the type of symmetric key, which defaults to a 56 bit
        DES3 key.
        """

    @abc.abstractmethod
    def key_unwrap(self, mechanism, data, wrapping_key, nonce_iv):
        """ Unwrap data that has been key wrapped using AES KeyWrap """

    @abc.abstractmethod
    def get_cert(self, cert_nick):
        """ Get the certificate for the specified cert_nick. """


class NSSCryptoProvider(CryptoProvider):
    """
    Class that defines NSS implementation of CryptoProvider.
    Requires an NSS database to have been set up and initialized.

    Note that all inputs and outputs are unencoded.
    """

    @staticmethod
    def setup_database(
            db_dir, password=None, over_write=False, password_file=None):
        """ Create an NSS database """
        if os.path.exists(db_dir):
            if not over_write:
                raise IOError("Directory already exists.")
            if os.path.isdir(db_dir):
                shutil.rmtree(db_dir)
            else:
                os.remove(db_dir)
        os.makedirs(db_dir)

        try:
            if password:
                (f, password_file) = tempfile.mkstemp()
                os.write(f, password)
                os.close(f)

            command = ['certutil', '-N', '-d', db_dir, '-f', password_file]
            subprocess.check_call(command)

        finally:
            if password and password_file:
                os.remove(password_file)

    def __init__(self, certdb_dir, certdb_password=None, password_file=None):
        """ Initialize nss and nss related parameters

            This method expects a NSS database to have already been created at
            certdb_dir with password certdb_password.
        """
        CryptoProvider.__init__(self)
        self.certdb_dir = certdb_dir

        if certdb_password:
            self.certdb_password = certdb_password

        elif password_file:
            with open(password_file, 'r') as f:
                self.certdb_password = f.readline().strip()

        self.nonce_iv = "e4:bb:3b:d3:c3:71:2e:58"

    def initialize(self):
        """
        Initialize the nss db. Must be done before any crypto operations
        """
        nss.nss_init(self.certdb_dir)

    def get_supported_algorithm_keyset(self):
        """ returns highest supported algorithm keyset """
        return 0

    def set_algorithm_keyset(self, level):
        """ sets required keyset """
        if level > 0:
            raise Exception("Invalid keyset")

        # basically, do what we have always done, no need to set anything
        # special here.

    def import_cert(self, cert_nick, cert, trust=',,'):
        """ Import a certificate into the nss database
        """
        # accept both CertData object or cert actual data
        if type(cert).__name__ == 'CertData':
            content = cert.encoded
        else:
            content = cert

        # certutil -A -d db_dir -n cert_nick -t trust -i cert_file
        with tempfile.NamedTemporaryFile() as cert_file:
            cert_file.write(content)
            cert_file.flush()
            command = ['certutil', '-A', '-d', self.certdb_dir,
                       '-n', cert_nick, '-t', trust,
                       '-i', cert_file.name]
            subprocess.check_call(command)

    def generate_nonce_iv(self, mechanism=nss.CKM_DES3_CBC_PAD):
        """ Create a random initialization vector """
        iv_length = nss.get_iv_length(mechanism)
        if iv_length > 0:
            iv_data = nss.generate_random(iv_length)
            return iv_data
        else:
            return None

    @classmethod
    def setup_contexts(cls, mechanism, sym_key, nonce_iv):
        """ Set up contexts to do wrapping/unwrapping by symmetric keys. """
        # Get a PK11 slot based on the cipher
        slot = nss.get_best_slot(mechanism)

        if sym_key is None:
            sym_key = slot.key_gen(mechanism,
                                   None,
                                   slot.get_best_key_length(mechanism))

        # If initialization vector was supplied use it, otherwise set it to
        # None
        if nonce_iv:
            iv_si = nss.SecItem(nonce_iv)
            iv_param = nss.param_from_iv(mechanism, iv_si)
        else:
            iv_data = cls.generate_nonce_iv(mechanism)
            if iv_data is not None:
                iv_si = nss.SecItem(iv_data)
                iv_param = nss.param_from_iv(mechanism, iv_si)
            else:
                iv_param = None

        # Create an encoding context
        encoding_ctx = nss.create_context_by_sym_key(mechanism, nss.CKA_ENCRYPT,
                                                     sym_key, iv_param)

        # Create a decoding context
        decoding_ctx = nss.create_context_by_sym_key(mechanism, nss.CKA_DECRYPT,
                                                     sym_key, iv_param)

        return encoding_ctx, decoding_ctx

    def generate_symmetric_key(self, mechanism=nss.CKM_DES3_CBC_PAD, size=0):
        """ Returns a symmetric key.

        Note that for fixed length keys, this length should be 0.  If no length
        is provided, then the function will either use 0 (for fixed length keys)
        or the maximum available length for that algorithm and the token.
        """
        slot = nss.get_best_slot(mechanism)
        if size == 0:
            size = slot.get_best_key_length(mechanism)
        return slot.key_gen(mechanism, None, size)

    def generate_session_key(self):
        """ Returns a session key to be used when wrapping secrets for the DRM
        This will return a 168 bit 3DES key.
        """
        return self.generate_symmetric_key(mechanism=nss.CKM_DES3_CBC_PAD)

    def symmetric_wrap(self, data, wrapping_key, mechanism=nss.CKM_DES3_CBC_PAD,
                       nonce_iv=None):
        """
        :param data            Data to be wrapped
        :param wrapping_key    Symmetric key to wrap data
        :param mechanism       Mechanism to user when wrapping
        :param nonce_iv        Nonce to use when wrapping

        Wrap (encrypt) data using the supplied symmetric key
        """
        if nonce_iv is None:
            nonce_iv = nss.read_hex(self.nonce_iv)

        encoding_ctx, _decoding_ctx = self.setup_contexts(mechanism,
                                                          wrapping_key,
                                                          nonce_iv)
        wrapped_data = encoding_ctx.cipher_op(data) +\
            encoding_ctx.digest_final()
        return wrapped_data

    def symmetric_unwrap(self, data, wrapping_key,
                         mechanism=nss.CKM_DES3_CBC_PAD, nonce_iv=None):
        """
        :param data            Data to be unwrapped
        :param wrapping_key    Symmetric key to unwrap data
        :param mechanism       Mechanism to use when wrapping
        :param nonce_iv        iv data

        Unwrap (decrypt) data using the supplied symmetric key
        """
        if nonce_iv is None:
            nonce_iv = nss.read_hex(self.nonce_iv)

        _encoding_ctx, decoding_ctx = self.setup_contexts(mechanism,
                                                          wrapping_key,
                                                          nonce_iv)
        unwrapped_data = decoding_ctx.cipher_op(data) \
            + decoding_ctx.digest_final()
        return unwrapped_data

    def asymmetric_wrap(self, data, wrapping_cert,
                        mechanism=nss.CKM_DES3_CBC_PAD):
        """
        :param data             Data to be wrapped
        :param wrapping_cert    Public key to wrap data
        :param mechanism        algorithm of symmetric key to be wrapped

        Wrap (encrypt) data using the supplied asymmetric key
        """
        public_key = wrapping_cert.subject_public_key_info.public_key
        return nss.pub_wrap_sym_key(mechanism, public_key, data)

    def key_unwrap(self, mechanism, data, wrapping_key, nonce_iv):
        """
        :param mechanism        Key wrapping mechanism
        :param data:            Data to be unwrapped
        :param wrapping_key:    Wrapping Key
        :param nonce_iv         Nonce data
        :return:                Unwrapped data

        Return unwrapped data for data that has been keywrapped.
        For NSS, we only support 3DES - so something that has been
        keywrapped can be decrypted.  This is precisely what we used
        to do before.
        """
        return self.symmetric_unwrap(
            data,
            wrapping_key,
            mechanism=nss.CKM_DES3_CBC_PAD,
            nonce_iv=nonce_iv
        )

    def get_cert(self, cert_nick):
        """
        :param cert_nick       Nickname for the certificate to be returned

        Searches NSS database and returns SecItem object for this certificate.
        """
        return nss.find_cert_from_nickname(cert_nick)


class CryptographyCryptoProvider(CryptoProvider):
    """
    Class that defines python-cryptography implementation of CryptoProvider.
    Requires a PEM file containing the agent cert to be initialized.

    Note that all inputs and outputs are unencoded.
    """

    def __init__(self, transport_cert_nick, transport_cert,
                 backend=default_backend()):
        """ Initialize python-cryptography
        """
        super(CryptographyCryptoProvider, self).__init__()
        self.certs = {}

        if not isinstance(transport_cert, cryptography.x509.Certificate):
            # it's a file name
            with open(transport_cert, 'r') as f:
                transport_pem = f.read()
            transport_cert = cryptography.x509.load_pem_x509_certificate(
                transport_pem,
                backend)

        self.certs[transport_cert_nick] = transport_cert

        # default to AES
        self.encrypt_alg = algorithms.AES
        self.encrypt_mode = modes.CBC
        self.encrypt_size = 128
        self.backend = backend

    def initialize(self):
        """
        Any operations here that need to be performed before crypto
        operations.
        """
        pass

    def get_supported_algorithm_keyset(self):
        """ returns highest supported algorithm keyset """
        return 1

    def set_algorithm_keyset(self, level):
        """ sets required keyset """
        if level > 1:
            raise ValueError("Invalid keyset")
        elif level == 1:
            self.encrypt_alg = algorithms.AES
            self.encrypt_mode = modes.CBC
            self.encrypt_size = 128
        elif level == 0:
            # note that 3DES keys are actually 192 bits long, even
            # though only 168 bits are used internally.  See
            # https://tools.ietf.org/html/rfc4949
            # Using 168 here will cause python-cryptography key verification
            # checks to fail.
            self.encrypt_alg = algorithms.TripleDES
            self.encrypt_mode = modes.CBC
            self.encrypt_size = 192

    def generate_nonce_iv(self, mechanism='AES'):
        """ Create a random initialization vector """
        return os.urandom(self.encrypt_alg.block_size // 8)

    def generate_symmetric_key(self, mechanism=None, size=0):
        """ Returns a symmetric key.
        """
        if mechanism is None:
            size = self.encrypt_size // 8
        return os.urandom(size)

    def generate_session_key(self):
        """ Returns a session key to be used when wrapping secrets for the DRM.
        """
        return self.generate_symmetric_key()

    def symmetric_wrap(self, data, wrapping_key, mechanism=None,
                       nonce_iv=None):
        """
        :param data            Data to be wrapped
        :param wrapping_key    Symmetric key to wrap data
        :param mechanism       Mechanism to use for wrapping key
        :param nonce_iv        Nonce for initialization vector

        Wrap (encrypt) data using the supplied symmetric key
        """
        # TODO(alee)  Not sure yet how to handle non-default mechanisms
        # For now, lets just ignore them

        if wrapping_key is None:
            raise ValueError("Wrapping key must be provided")

        if self.encrypt_mode.name == "CBC":
            padder = padding.PKCS7(self.encrypt_alg.block_size).padder()
            padded_data = padder.update(data) + padder.finalize()
            data = padded_data
        else:
            raise ValueError('Only CBC mode is currently supported')

        cipher = Cipher(self.encrypt_alg(wrapping_key),
                        self.encrypt_mode(nonce_iv),
                        backend=self.backend)

        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        return ct

    def symmetric_unwrap(self, data, wrapping_key,
                         mechanism=None, nonce_iv=None):
        """
        :param data            Data to be unwrapped
        :param wrapping_key    Symmetric key to unwrap data
        :param mechanism       Mechanism to use when unwrapping
        :param nonce_iv        iv data

        Unwrap (decrypt) data using the supplied symmetric key
        """

        # TODO(alee) As above, no idea what to do with mechanism
        # ignoring for now.

        if wrapping_key is None:
            raise ValueError("Wrapping key must be provided")

        cipher = Cipher(self.encrypt_alg(wrapping_key),
                        self.encrypt_mode(nonce_iv),
                        backend=self.backend)

        decryptor = cipher.decryptor()
        unwrapped = decryptor.update(data) + decryptor.finalize()

        if self.encrypt_mode.name == 'CBC':
            unpadder = padding.PKCS7(self.encrypt_alg.block_size).unpadder()
            unpadded = unpadder.update(unwrapped) + unpadder.finalize()
            unwrapped = unpadded
        else:
            raise ValueError('Only CBC mode is currently supported')

        return unwrapped

    def asymmetric_wrap(self, data, wrapping_cert,
                        mechanism=None):
        """
        :param data             Data to be wrapped
        :param wrapping_cert    Public key to wrap data
        :param mechanism        algorithm of symmetric key to be wrapped

        Wrap (encrypt) data using the supplied asymmetric key
        """
        public_key = wrapping_cert.public_key()
        return public_key.encrypt(
            data,
            PKCS1v15()
        )

    def key_unwrap(self, mechanism, data, wrapping_key, nonce_iv):
        """
        :param mechanism        key wrapping mechanism
        :param data:            data to unwrap
        :param wrapping_key:    AES key used to wrap data
        :param nonce_iv         Nonce data
        :return:                unwrapped data

        Unwrap the encrypted data which has been wrapped using a
        KeyWrap mechanism.
        """
        if mechanism == WRAP_AES_CBC_PAD or mechanism == WRAP_DES3_CBC_PAD:
            return self.symmetric_unwrap(
                data,
                wrapping_key,
                nonce_iv=nonce_iv)

        if mechanism == WRAP_AES_KEY_WRAP:
            return keywrap.aes_key_unwrap(wrapping_key, data, self.backend)

        raise ValueError("Unsupported key wrap algorithm: " + mechanism)

    def get_cert(self, cert_nick):
        """
        :param cert_nick  Nickname for the certificate to be returned.
        """
        return self.certs[cert_nick]
