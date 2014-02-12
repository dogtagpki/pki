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
to interact with the DRM to expose the functionality of the KeyResource and
KeyRequestResouce REST APIs.
'''

import base64
import pki.client as client
import pki.key as key
import pki.cert as cert
import nss.nss as nss
import time

class KRAClient(object):
    '''
    Client class that models interactions with a KRA using the Key and KeyRequest REST APIs.
    '''

    def __init__(self, connection):
        ''' Constructor '''
        self.connection = connection
        self.key_resource = key.KeyResource(connection)
        self.key_request_resource = key.KeyRequestResource(connection)
        self.cert_resource = cert.CertResource(connection)

        # nss parameters
        self.certdb_dir = None
        self.certdb_password = None
        self.transport_nick = None
        self.transport_cert = None

    def initialize_nss(self, certdb_dir, certdb_password, transport_nick):
        ''' Initialize nss and nss related parameters

            We expect this method to be called when an nss database is to
            be used to do client side cryptographic operations.

            This method expects a NSS database to have already been created at
            certdb_dir with password certdb_password, and the DRM transport
            certificate to have been imported as transport_nick
        '''
        self.certdb_dir = certdb_dir
        self.certdb_password = certdb_password
        self.transport_nick = transport_nick
        nss.nss_init(certdb_dir)
        self.transport_cert = nss.find_cert_from_nickname(self.transport_nick)

    def get_transport_cert(self):
        ''' Return the b64 of the transport certificate. '''
        return self.cert_resource.get_transport_cert()

    def list_requests(self, request_state, request_type, start=0,
                      page_size=100, max_results=100, max_time=10):
        ''' Search for a list of key requests of a specified type and state.

            The permitted values for request_state are:XXXX
            The permitted values for request_type are:

            Return a list of KeyRequestInfo objects '''
        return self.key_request_resource.list_requests(request_state=request_state,
                                                      request_type=request_type,
                                                      start=start,
                                                      page_size=page_size,
                                                      max_results=max_results,
                                                      max_time=max_time)
    def get_request(self, request_id):
        ''' Return a KeyRequestInfo object for a specific request '''
        return self.key_request_resource.get_request_info(key.RequestId(request_id))

    def list_keys(self, client_id, status):
        ''' Search for secrets archived in the DRM with a given client ID and status.

            The permitted values for status are: active, inactive
            Return a list of KeyInfo objects
        '''
        return self.key_resource.list_keys(client_id, status)

    def request_recovery(self, key_id, request_id=None, session_wrapped_passphrase=None,
                        trans_wrapped_session_key=None, b64certificate=None, nonce_data=None):
        ''' Create a request to recover a secret.

            To retrieve a symmetric key or passphrase, the only parameter that is required is
            the keyId.  It is possible (but not required) to pass in the session keys/passphrase
            and nonceData for the retrieval at this time.  Those parameters are documented
            in the docstring for retrieve_key below.

            To retrieve an asymmetric key, the keyId and the the base-64 encoded certificate
            is required.
        '''
        request = key.KeyRecoveryRequest(key_id=key_id,
                                         request_id=request_id,
                                         trans_wrapped_session_key=trans_wrapped_session_key,
                                         session_wrapped_passphrase=session_wrapped_passphrase,
                                         certificate=b64certificate,
                                         nonce_data=nonce_data)
        return self.key_request_resource.create_request(request)

    def approve_request(self, request_id):
        ''' Approve a key recovery request '''
        return self.key_request_resource.approve_request(key.RequestId(request_id))

    def reject_request(self, request_id):
        ''' Reject a key recovery request '''
        return self.key_request_resource.reject_request(key.RequestId(request_id))

    def cancel_request(self, request_id):
        ''' Cancel a key recovery request '''
        return self.key_request_resource.cancel_request(key.RequestId(request_id))

    def retrieve_key(self, key_id, request_id, trans_wrapped_session_key=None,
                     session_wrapped_passphrase=None, passphrase=None, nonce_data=None):
        ''' Retrieve a secret from the DRM.

            The secret (which is referenced by key_id) can be retrieved only if the
            recovery request (referenced by request_id) is approved.  key_id and request_id
            are required.

            Data must be provided to wrap the recovered secret.  This can either be
            a) a 56-bit DES3 symmetric key, wrapped by the DRM transport key, and
               passed in trans_wrapped_session_key
            b) a passphrase.  In this case, the passphrase must be wrapped by a 56-bit
               symmetric key ("the session key" and passed in session_wrapped_passphrase,
               and the session key must be wrapped by the DRM transport key and passed
               in trans_wrapped_session_key
            c) a passphrase for a p12 file.  If the key being recovered is an asymmetric
               key, then it is possible to pass in the passphrase for the P12 file to
               be generated.  This is passed in as passphrase

            nonce_data may also be passed as a salt.
        '''
        request = key.KeyRecoveryRequest(key_id=key_id,
                                         request_id=request_id,
                                         trans_wrapped_session_key=trans_wrapped_session_key,
                                         session_wrapped_passphrase=session_wrapped_passphrase,
                                         nonce_data=nonce_data,
                                         passphrase=passphrase)
        return self.key_resource.retrieve_key(request)

    def generate_sym_key(self, client_id, algorithm, size, usages):
        ''' Generate and archive a symmetric key on the DRM.

            Return a KeyRequestResponse which contains a KeyRequestInfo
            object that describes the URL for the request and generated key.
        '''
        request = key.SymKeyGenerationRequest(client_id=client_id,
                                              key_size=size,
                                              key_algorithm=algorithm,
                                              key_usage=usages)
        return self.key_request_resource.create_request(request)

    def archive_key(self, client_id, data_type, wrapped_private_data,
                    key_algorithm=None, key_size=None):
        ''' Archive a secret (symetric key or passphrase) on the DRM.

            Requires a user-supplied client ID.  There can be only one active
            key with a specified client ID.  If a record for a duplicate active
            key exists, an exception is thrown.

            data_type can be one of the following:

            wrapped_private_data consists of a PKIArchiveOptions structure, which
            can be constructed using either generate_archive_options() or
            generate_pki_archive_options() below.

            key_algorithm and key_size are applicable to symmetric keys only.
            If a symmetric key is being archived, these parameters are required.
        '''
        request = key.KeyArchivalRequest(client_id=client_id,
                                         data_type=data_type,
                                         wrapped_private_data=wrapped_private_data,
                                         key_algorithm=key_algorithm,
                                         key_size=key_size)
        return self.key_request_resource.create_request(request)

    def generate_pki_archive_options(self, trans_wrapped_session_key, session_wrapped_secret):
        ''' Return a PKIArchiveOptions structure for archiving a secret

            Takes in a session key wrapped by the DRM transport certificate,
            and a secret wrapped with the session key and creates a PKIArchiveOptions
            structure to be used when archiving a secret
        '''
        pass

    def setup_contexts(self, mechanism, sym_key, iv_vector):
        ''' Set up contexts to do wrapping/unwrapping by symmetric keys. '''
        # Get a PK11 slot based on the cipher
        slot = nss.get_best_slot(mechanism)

        if sym_key == None:
            sym_key = slot.key_gen(mechanism, None, slot.get_best_key_length(mechanism))

        # If initialization vector was supplied use it, otherwise set it to None
        if iv_vector:
            iv_data = nss.read_hex(iv_vector)
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
        mechanism = nss.CKM_DES3_CBC_PAD
        slot = nss.get_best_slot(mechanism)
        session_key = slot.key_gen(mechanism, None, slot.get_best_key_length(mechanism))

        public_key = self.transport_cert.subject_public_key_info.public_key
        trans_wrapped_session_key = base64.b64encode(nss.pub_wrap_sym_key(
                                        mechanism, public_key, session_key))

        encoding_ctx, _decoding_ctx = self.setup_contexts(mechanism, session_key, None)
        wrapped_secret = encoding_ctx.cipher_op(secret) + encoding_ctx.digest_final()

        return self.generate_pki_archive_options(trans_wrapped_session_key, wrapped_secret)

def print_key_request(request):
    ''' Prints the relevant fields of a KeyRequestInfo object '''
    print "RequestURL: " + str(request.requestURL)
    print "RequestType: " + str(request.requestType)
    print "RequestStatus: " + str(request.requestStatus)
    print "KeyURL: " + str(request.keyURL)

def print_key_info(key_info):
    ''' Prints the relevant fields of a KeyInfo object '''
    print "Key URL: " + str(key_info.keyURL)
    print "Client ID: " + str(key_info.clientID)
    print "Algorithm: " + str(key_info.algorithm)
    print "Status: " + str(key_info.status)
    print "Owner Name: " + str(key_info.ownerName)
    print "Size: " + str(key_info.size)

def print_key_data(key_data):
    ''' Prints the relevant fields of a KeyData object '''
    print "Key Algorithm: " + str(key_data.algorithm)
    print "Key Size: " + str(key_data.size)
    print "Nonce Data: " + str(key_data.nonceData)
    print "Wrapped Private Data: " + str(key_data.wrappedPrivateData)

def generate_symmetric_key(mechanism):
    ''' generate symmetric key - to be moved to nssutil module'''
    slot = nss.get_best_slot(mechanism)
    return slot.key_gen(mechanism, None, slot.get_best_key_length(mechanism))

def trans_wrap_sym_key(transport_cert, sym_key, mechanism):
    ''' wrap a sym key with a transport cert - to be moved to nsutil module'''
    public_key = transport_cert.subject_public_key_info.public_key
    return base64.b64encode(nss.pub_wrap_sym_key(mechanism, public_key, sym_key))

def barbican_encode(kraclient, client_id, algorithm, key_size, usage_string):
    response = kraclient.generate_sym_key(client_id, algorithm, key_size, usage_string)
    return response.requestInfo.get_key_id()

def barbican_decode(kraclient, key_id, wrapped_session_key):
    response = kraclient.request_recovery(key_id)
    recovery_request_id = response.requestInfo.get_request_id()
    kraclient.approve_request(recovery_request_id)
    return kraclient.retrieve_key(key_id, recovery_request_id, wrapped_session_key)

def main():
    ''' test code execution '''
    connection = client.PKIConnection('https', 'localhost', '8443', 'kra')
    connection.set_authentication_cert('/tmp/temp4.pem')
    kraclient = KRAClient(connection)
    # Get Transport Cert
    transport_cert = kraclient.get_transport_cert()
    print transport_cert

    print "Now getting key request"
    keyrequest = kraclient.get_request('2')
    print_key_request(keyrequest)

    print "Now listing requests"
    keyrequests = kraclient.list_requests('complete', 'securityDataRecovery')
    print keyrequests.key_requests
    for request in keyrequests.key_requests:
        print_key_request(request)

    print "Now generating symkey"
    client_id = "Vek #1" + time.strftime('%X %x %Z')
    algorithm = "AES"
    key_size = 128
    usages = [key.SymKeyGenerationRequest.DECRYPT_USAGE, key.SymKeyGenerationRequest.ENCRYPT_USAGE]
    response = kraclient.generate_sym_key(client_id, algorithm, key_size, ','.join(usages))
    print_key_request(response.requestInfo)
    print "Request ID is " + response.requestInfo.get_request_id()
    key_id = response.requestInfo.get_key_id()

    print "Now getting key ID for clientID=\"" + client_id + "\""
    key_infos = kraclient.list_keys(client_id, "active")
    for key_info in key_infos.key_infos:
        print_key_info(key_info)
        key_id2 = key_info.get_key_id()
    if key_id == key_id2:
        print "Success! The keys from generation and search match."
    else:
        print "Failure - key_ids for generation do not match!"

    print "Submit recovery request"
    response = kraclient.request_recovery(key_id)
    print response
    print_key_request(response.requestInfo)
    recovery_request_id = response.requestInfo.get_request_id()

    print "Approve recovery request"
    print kraclient.approve_request(recovery_request_id)

    # now begins the nss specific code
    # you need to have an nss database set up with the transport cert
    # imported therein.
    print "Retrieve key"
    nss.nss_init("/tmp/drmtest/certdb")
    mechanism = nss.CKM_DES3_CBC_PAD

    transport_cert = nss.find_cert_from_nickname("kra transport cert")
    session_key = generate_symmetric_key(mechanism)
    print session_key
    wrapped_session_key = trans_wrap_sym_key(transport_cert, session_key, nss.CKM_DES_CBC_PAD)

    response = kraclient.retrieve_key(key_id, recovery_request_id, wrapped_session_key)
    print_key_data(response)

    # do the above again - but this time using Barbican -like encode() and decode() functions

    # generate a symkey
    client_id = "Barbican VEK #1" + time.strftime('%X %x %Z')
    algorithm = "AES"
    key_size = 128
    usages = [key.SymKeyGenerationRequest.DECRYPT_USAGE, key.SymKeyGenerationRequest.ENCRYPT_USAGE]
    key_id = barbican_encode(kraclient, client_id, algorithm, key_size, ','.join(usages))
    print "barbican_encode() returns " + str(key_id)

    # recover the symkey
    session_key = generate_symmetric_key(mechanism)
    wrapped_session_key = trans_wrap_sym_key(transport_cert, session_key, nss.CKM_DES_CBC_PAD)
    response = barbican_decode(kraclient, key_id, wrapped_session_key)
    print "barbican_decode() returns:"
    print_key_data(response)

if __name__ == "__main__":
    main()
