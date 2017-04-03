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
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
import cryptography.x509


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
        pass

    @staticmethod
    @abc.abstractmethod
    def get_supported_algorithm_keyset():
        """ returns highest supported algorithm keyset """
        pass

    @abc.abstractmethod
    def set_algorithm_keyset(self, level):
        """ sets required keyset """
        pass

    @staticmethod
    @abc.abstractmethod
    def generate_nonce_iv(mechanism):
        """ Create a random initialization vector """
        pass

    @abc.abstractmethod
    def generate_symmetric_key(self, mechanism=None, size=0):
        """ Generate and return a symmetric key """
        pass

    @abc.abstractmethod
    def generate_session_key(self):
        """ Generate a session key to be used for wrapping data to the DRM
        This must return a 3DES 168 bit key """
        pass

    @abc.abstractmethod
    def symmetric_wrap(self, data, wrapping_key, mechanism=None,
                       nonce_iv=None):
        """ encrypt data using a symmetric key (wrapping key)"""
        pass

    @abc.abstractmethod
    def symmetric_unwrap(self, data, wrapping_key, mechanism=None,
                         nonce_iv=None):
        """ decrypt data originally encrypted with symmetric key (wrapping key)

        We expect the data and nonce_iv values to be base64 encoded.
        The mechanism is the type of key used to do the wrapping.  It defaults
        to a 56 bit DES3 key.
        """
        pass

    @abc.abstractmethod
    def asymmetric_wrap(self, data, wrapping_cert, mechanism=None):
        """ encrypt a symmetric key with the public key of a transport cert.

        The mechanism is the type of symmetric key, which defaults to a 56 bit
        DES3 key.
        """
        pass

    # abc.abstractmethod
    def get_cert(self, cert_nick):
        """ Get the certificate for the specified cert_nick. """
        pass


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

    @staticmethod
    def get_supported_algorithm_keyset():
        """ returns highest supported algorithm keyset """
        return 0

    def set_algorithm_keyset(self, level):
        """ sets required keyset """
        if level > 0:
            raise Exception("Invalid keyset")

        # basically, do what we have always done, no need to set anything
        # special here.
        pass

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

    @staticmethod
    def generate_nonce_iv(mechanism=nss.CKM_DES3_CBC_PAD):
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

    def __init__(self, transport_cert_fname, transport_cert_nick):
        """ Initialize python-cryptography
        """
        CryptoProvider.__init__(self)

        # TODO(alee) We should source the environment files at pki.conf
        # and determine the default mechanisms.  Sometimes we want to talk
        # to an old server for instance.  This will be just like the Java
        # client.

        self.certs = {}

        with open(transport_cert_fname, 'r') as f:
            transport_pem = f.read()

        self.certs[transport_cert_nick] = (
            cryptography.x509.load_pem_x509_certificate(
                transport_pem,
                default_backend()
            )
        )

        # default to AES
        self.encrypt_alg = algorithms.AES
        self.encrypt_mode = modes.CBC
        self.encrypt_size = 128

    def initialize(self):
        """
        Any operations here that need to be performed before crypto
        operations.
        """
        pass

    @staticmethod
    def get_supported_algorithm_keyset():
        """ returns highest supported algorithm keyset """
        return 1

    def set_algorithm_keyset(self, level):
        """ sets required keyset """
        if level > 1:
            raise Exception("Invalid keyset")
        elif level == 1:
            self.encrypt_alg = algorithms.AES
            self.encrypt_mode = modes.CBC
            self.encrypt_size = 128
        elif level == 0:
            self.encrypt_alg = algorithms.TripleDES
            self.encrypt_mode = modes.CBC
            self.encrypt_size = 168

    @staticmethod
    def generate_nonce_iv(mechanism='AES'):
        """ Create a random initialization vector """
        if mechanism == 'AES':
            return os.urandom(16)
        elif mechanism == '3DES':
            return os.urandom(8)

    def generate_symmetric_key(self, mechanism=None, size=0):
        """ Returns a symmetric key.
        """
        if mechanism is None:
            size = self.encrypt_size / 8
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

        backend = default_backend()
        if wrapping_key is None:
            raise Exception("Wrapping key must be provided")

        if self.encrypt_mode.name == "CBC":
            padder = padding.PKCS7(self.encrypt_alg.block_size).padder()
            padded_data = padder.update(data) + padder.finalize()
            data = padded_data

        cipher = Cipher(self.encrypt_alg(wrapping_key),
                        self.encrypt_mode(nonce_iv),
                        backend=backend)

        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        return ct

    def symmetric_unwrap(self, data, wrapping_key,
                         mechanism=None, nonce_iv=None):
        """
        :param data            Data to be unwrapped
        :param wrapping_key    Symmetric key to unwrap data
        :param nonce_iv        iv data

        Unwrap (decrypt) data using the supplied symmetric key
        """

        # TODO(alee) As above, no idea what to do with mechanism
        # ignoring for now.

        backend = default_backend()
        if wrapping_key is None:
            raise Exception("Wrapping key must be provided")

        cipher = Cipher(self.encrypt_alg(wrapping_key),
                        self.encrypt_mode(nonce_iv),
                        backend=backend)

        decryptor = cipher.decryptor()
        unwrapped = decryptor.update(data) + decryptor.finalize()

        if self.encrypt_mode.name == 'CBC':
            unpadder = padding.PKCS7(self.encrypt_alg.block_size).unpadder()
            unpadded = unpadder.update(unwrapped) + unpadder.finalize()
            unwrapped = unpadded

        return unwrapped

    def asymmetric_wrap(self, data, wrapping_cert,
                        mechanism=nss.CKM_DES3_CBC_PAD):
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

    def get_cert(self, cert_nick):
        """
        :param cert_nick  Nickname for the certificate to be returned.
        """
        return self.certs[cert_nick]
