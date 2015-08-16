#!/usr/bin/python
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
# Authors:
#     Ade Lee <alee@redhat.com>
#     Endi S. Dewata <edewata@redhat.com>

"""
=========================================================================
Python test code for interacting with the DRM using the REST interface
=========================================================================

This code is to be viewed as example code on how to interact with the DRM
for Key and KeyRequest resources using the Python REST client framework.

Some setup is required to run the tests here successfully.
See drmtest.readme.txt.
"""

from __future__ import absolute_import
import base64
import getopt
import os
import random
import shutil
import string
import sys
import tempfile
import time

import pki
import pki.crypto
import pki.key as key

from pki.client import PKIConnection
from pki.kra import KRAClient


def print_key_request(request):
    """ Prints the relevant fields of a KeyRequestInfo object """
    print "RequestURL: " + str(request.request_url)
    print "RequestType: " + str(request.request_type)
    print "RequestStatus: " + str(request.request_status)
    print "KeyURL: " + str(request.key_url)


def print_key_info(key_info):
    """ Prints the relevant fields of a KeyInfo object """
    print "Key URL: " + str(key_info.key_url)
    print "Client Key ID: " + str(key_info.client_key_id)
    print "Algorithm: " + str(key_info.algorithm)
    print "Status: " + str(key_info.status)
    print "Owner Name: " + str(key_info.owner_name)
    print "Size: " + str(key_info.size)
    if key_info.public_key is not None:
        print "Public key: "
        print
        pub_key = base64.encodestring(key_info.public_key)
        print pub_key


def print_key_data(key_data):
    """ Prints the relevant fields of a KeyData object """
    print "Key Algorithm: " + str(key_data.algorithm)
    print "Key Size: " + str(key_data.size)
    print "Nonce Data: " + base64.encodestring(key_data.nonce_data)
    print "Wrapped Private Data: " + \
          base64.encodestring(key_data.encrypted_data)
    if key_data.data is not None:
        print "Private Data: " + base64.encodestring(key_data.data)


def run_test(protocol, hostname, port, client_cert, certdb_dir, certdb_password):
    """ test code execution """

    # set up the connection to the DRM, including authentication credentials
    connection = PKIConnection(protocol, hostname, port, 'kra')
    connection.set_authentication_cert(client_cert)

    #create kraclient
    crypto = pki.crypto.NSSCryptoProvider(certdb_dir, certdb_password)
    kraclient = KRAClient(connection, crypto)
    keyclient = kraclient.keys

    # Get transport cert and insert in the certdb
    transport_nick = "kra transport cert"
    transport_cert = kraclient.system_certs.get_transport_cert()
    print "Subject DN: " + transport_cert.subject_dn
    print transport_cert.encoded
    crypto.import_cert(transport_nick, transport_cert)

    # initialize the certdb for crypto operations
    # for NSS db, this must be done after importing the transport cert
    crypto.initialize()

    # set transport cert into keyclient
    keyclient.set_transport_cert(transport_nick)

    # Test 2: Get key request info
    print "Now getting key request"
    try:
        key_request = keyclient.get_request_info('2')
        print_key_request(key_request)
    except pki.RequestNotFoundException:
        pass

    # Test 3: List requests
    print "Now listing some requests"
    keyrequests = keyclient.list_requests('complete', 'securityDataRecovery')
    print keyrequests.key_requests
    for request in keyrequests.key_requests:
        print_key_request(request)

    # Test 4: generate symkey -- same as barbican_encode()
    print "Now generating symkey on KRA"
    client_key_id = "Vek #1" + time.strftime('%c')
    algorithm = "AES"
    key_size = 128
    usages = [key.SymKeyGenerationRequest.DECRYPT_USAGE,
              key.SymKeyGenerationRequest.ENCRYPT_USAGE]
    response = keyclient.generate_symmetric_key(client_key_id,
                                                algorithm=algorithm,
                                                size=key_size,
                                                usages=usages)
    print_key_request(response.request_info)
    print "Request ID is " + response.request_info.get_request_id()
    key_id = response.get_key_id()

    # Test 5: Confirm the key_id matches
    print "Now getting key ID for clientKeyID=\"" + client_key_id + "\""
    key_infos = keyclient.list_keys(client_key_id=client_key_id,
                                    status=keyclient.KEY_STATUS_ACTIVE)
    key_id2 = None
    for key_info in key_infos.key_infos:
        print_key_info(key_info)
        key_id2 = key_info.get_key_id()
    if key_id == key_id2:
        print "Success! The keys from generation and search match."
    else:
        print "Failure - key_ids for generation do not match!"

    # Test 6: Barbican_decode() - Retrieve while providing
    # trans_wrapped_session_key
    session_key = crypto.generate_session_key()
    wrapped_session_key = crypto.asymmetric_wrap(session_key,
                                                 keyclient.transport_cert)
    print "My key id is " + str(key_id)
    key_data = keyclient.retrieve_key(
        key_id, trans_wrapped_session_key=wrapped_session_key)
    print_key_data(key_data)
    unwrapped_key = crypto.symmetric_unwrap(key_data.encrypted_data,
                                            session_key,
                                            nonce_iv=key_data.nonce_data)
    key1 = base64.encodestring(unwrapped_key)

    # Test 7: Recover key without providing trans_wrapped_session_key
    key_data = keyclient.retrieve_key(key_id)
    print_key_data(key_data)
    key2 = base64.encodestring(key_data.data)

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
        keyclient.generate_symmetric_key(client_key_id,
                                         algorithm=algorithm,
                                         size=key_size,
                                         usages=usages)
    except pki.BadRequestException as exc:
        print "BadRequestException thrown - Code:" + exc.code +\
              " Message: " + exc.message

    # Test 11 - Test RequestNotFoundException on get_request_info
    print "Try to list a nonexistent request"
    try:
        keyclient.get_request_info('200000034')
    except pki.RequestNotFoundException as exc:
        print "RequestNotFoundException thrown - Code:" + exc.code +\
              " Message: " + exc.message

    # Test 12 - Test exception on retrieve_key.
    print "Try to retrieve an invalid key"
    try:
        keyclient.retrieve_key('2000003434')
    except pki.KeyNotFoundException as exc:
        print "KeyNotFoundException thrown - Code:" + exc.code + \
              " Message: " + exc.message

    #Test 13 = getKeyInfo
    print "Get key info for existing key"
    key_info = keyclient.get_key_info(key_id)
    print_key_info(key_info)

    # Test 14: get the active key
    print "Get the active key for client id: " + client_key_id
    key_info = keyclient.get_active_key_info(client_key_id)
    print_key_info(key_info)

    #Test 15: change the key status
    print "Change the key status"
    keyclient.modify_key_status(key_id, keyclient.KEY_STATUS_INACTIVE)
    print_key_info(keyclient.get_key_info(key_id))

    # Test 16: Get key info for non-existent key
    print "Get key info for non-existent key"
    try:
        keyclient.get_key_info('200004556')
    except pki.KeyNotFoundException as exc:
        print "KeyNotFoundException thrown - Code:" + exc.code +\
              " Message: " + exc.message

    # Test 17: Get key info for non-existent active key
    print "Get non-existent active key"
    try:
        key_info = keyclient.get_active_key_info(client_key_id)
        print_key_info(key_info)
    except pki.ResourceNotFoundException as exc:
        print "ResourceNotFoundException thrown - Code: " + exc.code +\
              "Message: " + exc.message

    #Test 18: Generate a symmetric key with default parameters
    client_key_id = "Vek #3" + time.strftime('%c')
    response = keyclient.generate_symmetric_key(client_key_id)
    print_key_request(response.request_info)

    # Test 19: Try to archive key
    print "try to archive key"
    print "key to archive: " + key1
    client_key_id = "Vek #4" + time.strftime('%c')

    response = keyclient.archive_key(client_key_id,
                                     keyclient.SYMMETRIC_KEY_TYPE,
                                     base64.decodestring(key1),
                                     key_algorithm=keyclient.AES_ALGORITHM,
                                     key_size=128)
    print_key_request(response.request_info)

    # Test 20: Lets get it back
    key_info = keyclient.get_active_key_info(client_key_id)
    print_key_info(key_info)

    key_data = keyclient.retrieve_key(key_info.get_key_id())
    print_key_data(key_data)
    key2 = base64.encodestring(key_data.data)

    if key1 == key2:
        print "Success: archived and recovered keys match"
    else:
        print "Error: archived and recovered keys do not match"
    print

    #Test 20: Generating asymmetric keys
    print "Generating asymmetric keys"
    try:
        response = keyclient.generate_asymmetric_key(
            "Vek #5" + time.strftime('%c'),
            algorithm="RSA",
            key_size=1024,
            usages=None
        )
        print_key_request(response.request_info)
    except pki.BadRequestException as exc:
        print "BadRequestException thrown - Code:" + exc.code +\
              " Message: " + exc.message

    #Test 21: Get key information of the newly generated asymmetric keys
    print "Retrieving key information"
    key_info = keyclient.get_key_info(response.request_info.get_key_id())
    print_key_info(key_info)


def usage():
    print 'Usage: drmtest.py [OPTIONS]'
    print
    print '  -P <protocol>                  KRA server protocol (default: https).'
    print '  -h <hostname>                  KRA server hostname (default: localhost).'
    print '  -p <port>                      KRA server port (default: 8443).'
    print '  -n <path>                      KRA agent certificate and private key (default: kraagent.pem).'
    print
    print '  --help                         Show this help message.'


def main(argv):
    try:
        opts, _ = getopt.getopt(argv[1:], 'h:P:p:n:d:c:', ['help'])

    except getopt.GetoptError as e:
        print 'ERROR: ' + str(e)
        usage()
        sys.exit(1)

    protocol    = 'https'
    hostname    = 'localhost'
    port        = '8443'
    client_cert = 'kraagent.pem'

    for o, a in opts:
        if o == '-P':
            protocol = a

        elif o == '-h':
            hostname = a

        elif o == '-p':
            port = a

        elif o == '-n':
            client_cert = a

        elif o == '--help':
            usage()
            sys.exit()

        else:
            print 'ERROR: unknown option ' + o
            usage()
            sys.exit(1)

    certdb_dir = tempfile.mkdtemp(prefix='pki-kra-test-')
    print "NSS database dir: %s" % certdb_dir

    certdb_password = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(8))
    print "NSS database password: %s" % certdb_password

    try:
        run_test(protocol, hostname, port, client_cert, certdb_dir, certdb_password)
    finally:
        shutil.rmtree(certdb_dir)


if __name__ == "__main__":
    main(sys.argv)
