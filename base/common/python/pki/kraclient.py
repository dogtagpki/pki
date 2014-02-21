#!/usr/bin/python
# Authors:
#     Abhishek Koneru <akoneru@redhat.com>
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
Module containing KRAClient class.  This class should be used by Python clients
to interact with the DRM to expose the functionality of the KeyClient and
KeyRequestResouce REST APIs.
'''

import base64
import pki.key as key

from pki.systemcert import SystemCertClient

class KRAClient(object):
    '''
    Client class that models interactions with a KRA using the Key and KeyRequest REST APIs.
    '''

    def __init__(self, connection, crypto, transport_cert_nick=None):
        ''' Constructor

        :param connection - PKIConnection object with DRM connection info.
        :param crypto - CryptoUtil object.  NSSCryptoUtil is provided by default.
                        If a different crypto implementation is desired, a different
                        subclass of CryptoUtil must be provided.
        :param transport_cert_nick - identifier for the DRM transport certificate.  This will
                        be passed to the CryptoUtil.get_cert() command to get a representation
                        of the transport certificate usable for crypto operations.
                        Note that for NSS databases, the database must have been initialized
                        beforehand.
        '''
        self.connection = connection
        self.keys = key.KeyClient(connection)
        self.system_certs = SystemCertClient(connection)
        self.crypto = crypto
        if transport_cert_nick != None:
            self.transport_cert = crypto.get_cert(transport_cert_nick)
        else:
            self.transport_cert = None

    def set_transport_cert(self, transport_cert_nick):
        ''' Set the transport certificate for crypto operations '''
        self.transport_cert = self.crypto.get_cert(transport_cert_nick)

    def retrieve_key(self, key_id, trans_wrapped_session_key=None):
        ''' Retrieve a secret (passphrase or symmetric key) from the DRM.

        This function generates a key recovery request, approves it, and retrieves
        the secret referred to by key_id.  This assumes that only one approval is required
        to authorize the recovery.

        To ensure data security in transit, the data will be returned encrypted by a session
        key (56 bit DES3 symmetric key) - which is first wrapped (encrypted) by the public
        key of the DRM transport certificate before being sent to the DRM.  The
        parameter trans_wrapped_session_key refers to this wrapped session key.

        There are two ways of using this function:

        1) trans_wrapped_session_key is not provided by caller.

        In this case, the function will call CryptoUtil methods to generate and wrap the
        session key.  The function will return the tuple (KeyData, unwrapped_secret)

        2)  The trans_wrapped_session_key is provided by the caller.

        In this case, the function will simply pass the data to the DRM, and will return the secret
        wrapped in the session key.  The secret will still need to be unwrapped by the caller.

        The function will return the tuple (KeyData, None), where the KeyData structure includes the
        wrapped secret and some nonce data to be used as a salt when unwrapping.
        '''
        key_provided = True
        if (trans_wrapped_session_key == None):
            key_provided = False
            session_key = self.crypto.generate_symmetric_key()
            trans_wrapped_session_key = self.crypto.asymmetric_wrap(session_key,
                                                                    self.transport_cert)

        response = self.keys.request_recovery(key_id)
        request_id = response.get_request_id()
        self.keys.approve_request(request_id)

        key_data = self.keys.request_key_retrieval(key_id, request_id,
                        trans_wrapped_session_key=base64.encodestring(trans_wrapped_session_key))
        if key_provided:
            return key_data, None

        unwrapped_key = self.crypto.symmetric_unwrap(
                                base64.decodestring(key_data.wrappedPrivateData),
                                session_key,
                                nonce_iv=base64.decodestring(key_data.nonceData))
        return key_data, unwrapped_key

    def retrieve_key_by_passphrase(self, key_id, passphrase=None,
                                   trans_wrapped_session_key=None,
                                   session_wrapped_passphrase=None,
                                   nonce_data=None):
        ''' Retrieve a secret (passphrase or symmetric key) from the DRM using a passphrase.

        This function generates a key recovery request, approves it, and retrieves
        the secret referred to by key_id.  This assumes that only one approval is required
        to authorize the recovery.

        The secret is secured in transit by wrapping the secret with a passphrase using
        PBE encryption.

        There are two ways of using this function:

        1) A passphrase is provided by the caller.

        In this case, CryptoUtil methods will be called to create the data to securely send the
        passphrase to the DRM.  Basically, three pieces of data will be sent:

        - the passphrase wrapped by a 56 bit DES3 symmetric key (the session key).  This
          is referred to as the parameter session_wrapped_passphrase above.

        - the session key wrapped with the public key in the DRM transport certificate.  This
          is referred to as the trans_wrapped_session_key above.

        - ivps nonce data, referred to as nonce_data

        The function will return the tuple (KeyData, unwrapped_secret)

        2) The caller provides the trans_wrapped_session_key, session_wrapped_passphrase
        and nonce_data.

        In this case, the data will simply be passed to the DRM.  The function will return
        the secret encrypted by the passphrase using PBE Encryption.  The secret will still
        need to be decrypted by the caller.

        The function will return the tuple (KeyData, None)
        '''
        pass

    def retrieve_key_by_pkcs12(self, key_id, certificate, passphrase):
        ''' Retrieve an asymmetric private key and return it as PKCS12 data.

        This function generates a key recovery request, approves it, and retrieves
        the secret referred to by key_id in a PKCS12 file.  This assumes that only
        one approval is required to authorize the recovery.

        This function requires the following parameters:
        - key_id : the ID of the key
        - certificate: the certificate associated with the private key
        - passphrase: A passphrase for the pkcs12 file.

        The function returns a KeyData object.
        '''
        response = self.keys.request_recovery(key_id, b64certificate=certificate)
        request_id = response.get_request_id()
        self.keys.approve_request(request_id)

        return self.keys.request_key_retrieval(key_id, request_id, passphrase)


    def generate_symmetric_key(self, client_key_id, algorithm, size, usages):
        ''' Generate and archive a symmetric key on the DRM.

            Return a KeyRequestResponse which contains a KeyRequestInfo
            object that describes the URL for the request and generated key.
        '''
        request = key.SymKeyGenerationRequest(client_key_id=client_key_id,
                                              key_size=size,
                                              key_algorithm=algorithm,
                                              key_usages=usages)
        return self.keys.create_request(request)

    def archive_key(self, client_key_id, data_type, private_data=None,
                    wrapped_private_data=None,
                    key_algorithm=None, key_size=None):
        ''' Archive a secret (symmetric key or passphrase) on the DRM.

            Requires a user-supplied client ID.  There can be only one active
            key with a specified client ID.  If a record for a duplicate active
            key exists, a BadRequestException is thrown.

            data_type can be one of the following:
                KeyRequestResource.SYMMETRIC_KEY_TYPE,
                KeyRequestResource.ASYMMETRIC_KEY_TYPE,
                KeyRequestResource.PASS_PHRASE_TYPE

            key_algorithm and key_size are applicable to symmetric keys only.
            If a symmetric key is being archived, these parameters are required.

            wrapped_private_data consists of a PKIArchiveOptions structure, which
            can be constructed using either generate_archive_options() or
            generate_pki_archive_options() below.

            private_data is the secret that is to be archived.

            Callers must specify EITHER wrapped_private_data OR private_data.
            If wrapped_private_data is specified, then this data is forwarded to the
            DRM unchanged.  Otherwise, the private_data is converted to a
            PKIArchiveOptions structure using the functions below.

            The function returns a KeyRequestResponse object containing a KeyRequestInfo
            object with details about the archival request and key archived.
        '''
        if wrapped_private_data == None:
            if private_data == None:
                # raise BadRequestException - to be added in next patch
                return None
            wrapped_private_data = self.generate_archive_options(private_data)
        return self.keys.request_archival(client_key_id, data_type, wrapped_private_data,
                                          key_algorithm, key_size)

    def generate_pki_archive_options(self, trans_wrapped_session_key, session_wrapped_secret):
        ''' Return a PKIArchiveOptions structure for archiving a secret

            Takes in a session key wrapped by the DRM transport certificate,
            and a secret wrapped with the session key and creates a PKIArchiveOptions
            structure to be used when archiving a secret
        '''
        pass

    def generate_archive_options(self, secret):
        ''' Return a PKIArchiveOptions structure for archiving a secret.

            This method uses NSS calls to do the following:
            1) generate a session key
            2) wrap the session key with the transport key
            3) wrap the secret with the session key
            4) create the PKIArchiveOptions structure using the results of
               (2) and (3)

            This method expects initialize_nss() to have been called previously.
        '''
        session_key = self.crypto.generate_symmetric_key()
        trans_wrapped_session_key = self.crypto.asymmetric_wrap(session_key, self.transport_cert)
        wrapped_secret = self.crypto.symmetric_wrap(secret, session_key)

        return self.generate_pki_archive_options(trans_wrapped_session_key, wrapped_secret)

