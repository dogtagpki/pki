# Authors:
#   Ade Lee <alee@redhat.com>
#
# Copyright (C) 2012  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

'''
=========================================================================
Python test code for interacting with the DRM using the RESTful interface
=========================================================================

This code is to be viewed as example code on how to interact with the DRM
for Key and KeyRequest resources using the Python REST client framework.

Some setup is required to run the tests here successfully.
See drmtest.readme.txt.
'''

import base64
import pki
import pki.cryptoutil as cryptoutil
import pki.key as key
import time

from pki.client import PKIConnection
from pki.kraclient import KRAClient

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

def main():
    ''' test code execution '''
    connection = PKIConnection('https', 'localhost', '8443', 'kra')
    connection.set_authentication_cert('/tmp/temp4.pem')
    certdb_dir = "/tmp/drmtest-certdb"
    certdb_password = "redhat123"
    transport_nick = "kra transport cert"
    cryptoutil.NSSCryptoUtil.setup_database(certdb_dir, certdb_password, over_write=True)
    crypto = cryptoutil.NSSCryptoUtil(certdb_dir, certdb_password)
    kraclient = KRAClient(connection, crypto)

    # Test 1: Get transport certificate and import it into the NSS database
    transport_cert = kraclient.system_certs.get_transport_cert()
    print transport_cert
    tcert = transport_cert[len(pki.CERT_HEADER):len(transport_cert) -len(pki.CERT_FOOTER)]
    crypto.import_cert(transport_nick, base64.decodestring(tcert), "u,u,u")
    crypto.initialize_db()
    kraclient.set_transport_cert(transport_nick)

    # Test 2: Get key request info
    print "Now getting key request"
    keyrequest = kraclient.keys.get_request_info('2')
    print_key_request(keyrequest)

    # Test 3: List requests
    print "Now listing some requests"
    keyrequests = kraclient.keys.list_requests('complete', 'securityDataRecovery')
    print keyrequests.key_requests
    for request in keyrequests.key_requests:
        print_key_request(request)

    # Test 4: generate symkey -- same as barbican_encode()
    print "Now generating symkey on KRA"
    client_id = "Vek #1" + time.strftime('%X %x %Z')
    algorithm = "AES"
    key_size = 128
    usages = [key.SymKeyGenerationRequest.DECRYPT_USAGE, key.SymKeyGenerationRequest.ENCRYPT_USAGE]
    response = kraclient.generate_sym_key(client_id, algorithm, key_size, usages)
    print_key_request(response.requestInfo)
    print "Request ID is " + response.requestInfo.get_request_id()
    key_id = response.get_key_id()

    # Test 5: Confirm the key_id matches
    print "Now getting key ID for clientID=\"" + client_id + "\""
    key_infos = kraclient.keys.list_keys(client_id=client_id, status="active")
    for key_info in key_infos.key_infos:
        print_key_info(key_info)
        key_id2 = key_info.get_key_id()
    if key_id == key_id2:
        print "Success! The keys from generation and search match."
    else:
        print "Failure - key_ids for generation do not match!"

    # Test 6: Barbican_decode() - Retrieve while providing trans_wrapped_session_key
    session_key = crypto.generate_symmetric_key()
    wrapped_session_key = crypto.asymmetric_wrap(session_key, kraclient.transport_cert)
    key_data, _unwrapped_key = kraclient.retrieve_key(key_id, trans_wrapped_session_key=wrapped_session_key)
    print_key_data(key_data)
    unwrapped_key = crypto.symmetric_unwrap(base64.decodestring(key_data.wrappedPrivateData),
                                            session_key,
                                            nonce_iv=base64.decodestring(key_data.nonceData))
    key1 = base64.encodestring(unwrapped_key)

    # Test 7: Recover key without providing trans_wrapped_session_key
    key_data, unwrapped_key = kraclient.retrieve_key(key_id)
    print_key_data(key_data)
    key2 = base64.encodestring(unwrapped_key)

    # Test 8 - Confirm that keys returned are the same
    if key1 == key2:
        print "Success: The keys returned match! Key = " + str(key1)
    else:
        print "Failure: The returned keys do not match!"
        print "key1: " + key1
        print "key2: " + key2

    # Test 10 = test BadRequestException on create()
    print "Trying to generate a new symkey with the same client ID"
    try:
        response = kraclient.generate_sym_key(client_id, algorithm, key_size, usages)
    except pki.BadRequestException as exc:
        print "BadRequestException thrown - Code:" + exc.code + " Message: " + exc.message

    # Test 11 - Test RequestNotFoundException on get_request_info
    print "Try to list a nonexistent request"
    try:
        keyrequest = kraclient.keys.get_request_info('200000034')
    except pki.RequestNotFoundException as exc:
        print "RequestNotFoundException thrown - Code:" + exc.code + " Message: " + exc.message

    # Test 12 - Test exception on retrieve_key.
    print "Try to retrieve an invalid key"
    try:
        key_data, unwrapped_key = kraclient.retrieve_key('2000003434')
    except pki.KeyNotFoundException as exc:
        print "KeyNotFoundException thrown - Code:" + exc.code + " Message: " + exc.message
    except pki.PKIException as exc:
        # note: this is broken - we should be sending KeyNotFoundException here before the recovery
        # request is created - to be fixed in next patch
        print "PKIException thrown - Code:" + exc.code + " Message: " + exc.message

    #Test 13 = getKeyInfo
    print "Get key info for existing key"
    key_info = kraclient.keys.get_key_info(key_id)
    print_key_info(key_info)

    # Test 14: get the active key
    print "Get the active key for client id: " + client_id
    key_info = kraclient.keys.get_active_key_info(client_id)
    print_key_info(key_info)

    #Test 15: change the key status
    print "Change the key status"
    kraclient.keys.modify_key_status(key_id, "inactive")
    print_key_info(kraclient.keys.get_key_info(key_id))

    # Test 16: Get key info for non-existent key
    print "Get key info for non-existent key"
    try:
        key_info = kraclient.keys.get_key_info('200004556')
    except pki.KeyNotFoundException as exc:
        print "KeyNotFoundException thrown - Code:" + exc.code + " Message: " + exc.message

    # Test 17: Get key info for non-existent active key
    print "Get non-existent active key"
    try:
        key_info = kraclient.keys.get_active_key_info(client_id)
    except pki.ResourceNotFoundException as exc:
        print "ResourceNotFoundException thrown - Code: " + exc.code + "Message: " + exc.message

if __name__ == "__main__":
    main()
