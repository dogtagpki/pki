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
            with open(transport_cert, 'rb') as f:
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
