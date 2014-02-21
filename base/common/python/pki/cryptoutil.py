#!/usr/bin/python
# Authors:
#     Ade Lee <alee@redhat.com>
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
# Copyright (C) 2013 Red Hat, Inc.
# All rights reserved.
#
'''
Module containing crypto classes.
'''
import abc
import exceptions
import nss.nss as nss
import os
import shutil
import subprocess
import tempfile


class CryptoUtil(object):
    '''
    Abstract class containing methods to do cryptographic operations.
    '''
    __metaclass__ = abc.ABCMeta

    def __init__(self):
        ''' Constructor '''
        pass

    @abc.abstractmethod
    def generate_symmetric_key(self, mechanism=None):
        ''' Generate and return a symmetric key '''
        pass

    @abc.abstractmethod
    def symmetric_wrap(self, data, wrapping_key, mechanism=None, nonce_iv=None):
        ''' encrypt data using a symmetric key (wrapping key)'''
        pass

    @abc.abstractmethod
    def symmetric_unwrap(self, data, wrapping_key, mechanism=None, nonce_iv=None):
        ''' decrypt data originally encrypted with symmetric key (wrapping key)

        We expect the data and nonce_iv values to be base64 encoded.
        The mechanism is the type of key used to do the wrapping.  It defaults
        to a 56 bit DES3 key.
        '''
        pass

    @abc.abstractmethod
    def asymmetric_wrap(self, data, wrapping_cert, mechanism=None):
        ''' encrypt a symmetric key with the public key of a transport cert.

        The mechanism is the type of symmetric key, which defaults to a 56 bit
        DES3 key.
        '''
        pass

    #abc.abstractmethod
    def get_cert(self, cert_nick):
        ''' Get the certificate for the specified cert_nick. '''
        pass

class NSSCryptoUtil(CryptoUtil):
    '''
    Class that defines NSS implementation of CryptoUtil.
    Requires an NSS database to have been set up and initialized.

    Note that all inputs and outputs are unencoded.
    '''

    @staticmethod
    def setup_database(db_dir, password, over_write=False):
        ''' Create an NSS database '''
        if os.path.exists(db_dir):
            if not over_write:
                raise exceptions.ValueError(
                        "Directory already exists and over_write is false")
            if os.path.isdir(db_dir):
                shutil.rmtree(db_dir)
            else:
                os.remove(db_dir)
        os.makedirs(db_dir)

        with tempfile.NamedTemporaryFile() as pwd_file:
            pwd_file.write(password)
            pwd_file.flush()
            command = ['certutil', '-N', '-d', db_dir, '-f', pwd_file.name]
            subprocess.check_call(command)

    def __init__(self, certdb_dir, certdb_password):
        ''' Initialize nss and nss related parameters

            This method expects a NSS database to have already been created at
            certdb_dir with password certdb_password.
        '''
        CryptoUtil.__init__(self)
        self.certdb_dir = certdb_dir
        self.certdb_password = certdb_password
        self.nonce_iv = "e4:bb:3b:d3:c3:71:2e:58"

    def initialize_db(self):
        ''' initialize the nss db.  Must be done before any crypto operations '''
        nss.nss_init(self.certdb_dir)

    def import_cert(self, cert_nick, cert, trust):
        ''' Import a certificate into the nss database
        '''
        # certutil -A -d db_dir -n cert_nick -t trust -i cert_file -a
        with tempfile.NamedTemporaryFile() as cert_file:
            cert_file.write(cert)
            cert_file.flush()
            command = ['certutil', '-A', '-d', self.certdb_dir,
                       '-n', cert_nick, '-t', trust,
                       '-i', cert_file.name]
            subprocess.check_call(command)

    @staticmethod
    def setup_contexts(mechanism, sym_key, nonce_iv):
        ''' Set up contexts to do wrapping/unwrapping by symmetric keys. '''
        # Get a PK11 slot based on the cipher
        slot = nss.get_best_slot(mechanism)

        if sym_key == None:
            sym_key = slot.key_gen(mechanism, None, slot.get_best_key_length(mechanism))

        # If initialization vector was supplied use it, otherwise set it to None
        if nonce_iv:
            iv_data = nss.read_hex(nonce_iv)
            iv_si = nss.SecItem(iv_data)
            iv_param = nss.param_from_iv(mechanism, iv_si)
        else:
            iv_length = nss.get_iv_length(mechanism)
            if iv_length > 0:
                iv_data = nss.generate_random(iv_length)
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

    def generate_symmetric_key(self, mechanism=nss.CKM_DES3_CBC_PAD):
        ''' Returns a symmetric key.'''
        slot = nss.get_best_slot(mechanism)
        return slot.key_gen(mechanism, None, slot.get_best_key_length(mechanism))

    def symmetric_wrap(self, data, wrapping_key, mechanism=nss.CKM_DES3_CBC_PAD, nonce_iv=None):
        '''
        :param data:           Data to be wrapped
        :param wrapping_key    Symmetric key to wrap data

        Wrap (encrypt) data using the supplied symmetric key
        '''
        encoding_ctx, _decoding_ctx = self.setup_contexts(mechanism, wrapping_key, nonce_iv)
        wrapped_data = encoding_ctx.cipher_op(data) + encoding_ctx.digest_final()
        return wrapped_data

    def symmetric_unwrap(self, data, wrapping_key, mechanism=nss.CKM_DES3_CBC_PAD, nonce_iv=None):
        '''
        :param data:           Data to be unwrapped
        :param wrapping_key    Symmetric key to unwrap data
        :param nonce_iv        iv data

        Unwrap (decrypt) data using the supplied symmetric key
        '''
        if nonce_iv == None:
            nonce_iv = self.nonce_iv
        else:
            nonce_iv = nss.data_to_hex(nonce_iv)

        _encoding_ctx, decoding_ctx = self.setup_contexts(mechanism, wrapping_key, nonce_iv)
        unwrapped_data = decoding_ctx.cipher_op(data) \
            + decoding_ctx.digest_final()
        return unwrapped_data

    def asymmetric_wrap(self, data, wrapping_cert, mechanism=nss.CKM_DES3_CBC_PAD):
        '''
        :param data:            Data to be wrapped
        :param wrapping_cert    Public key to wrap data
        :param mechanism        algorithm of symmetric key to be wrapped

        Wrap (encrypt) data using the supplied asymmetric key
        '''
        public_key = wrapping_cert.subject_public_key_info.public_key
        return nss.pub_wrap_sym_key(mechanism, public_key, data)

    def get_cert(self, cert_nick):
        '''
        :param cert_nick       Nickname for the certificate to be returned

        Searches NSS database and returns SecItem object for this certificate.
        '''
        return nss.find_cert_from_nickname(cert_nick)
