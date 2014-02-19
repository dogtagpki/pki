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
Module containing the Python client classes for the KeyClient and
KeyRequestClient REST API on a DRM
'''
import pki.encoder as encoder
import json
import pki
import types

class KeyId(object):
    '''
    Class representing a key ID
    '''
    def __init__(self, key_id=None):
        ''' Constructor '''
        self.value = key_id

#should be moved to request.py
class RequestId(object):
    '''
    Class representing a Request ID
    '''
    def __init__(self, req_id):
        ''' Constructor'''
        self.value = req_id

class KeyData(object):
    '''
    This is the object that contains the wrapped secret
    when that secret is retrieved.
    '''

    def __init__(self):
        ''' Constructor '''
        self.algorithm = None
        self.nonceData = None
        self.size = None
        self.wrappedPrivateData = None

    @classmethod
    def from_json(cls, attr_list):
        ''' Return a KeyData object from a JSON dict '''
        key_data = cls()
        for key in attr_list:
            setattr(key_data, key, attr_list[key])
        return key_data

class KeyInfo(object):
    '''
    This is the object that contains information stored
    in the databse record for an archived secret.  It does not
    contain the secret itself.
    '''

    def __init__(self):
        ''' Constructor '''
        self.clientID = None
        self.keyURL = None
        self.algorithm = None
        self.status = None
        self.ownerName = None
        self.size = None

    @classmethod
    def from_json(cls, attr_list):
        ''' Return KeyInfo from JSON dict '''
        key_info = cls()
        for key in attr_list:
            setattr(key_info, key, attr_list[key])
        return key_info

    def get_key_id(self):
        ''' Return the key ID as parsed from key URL '''
        if self.keyURL != None:
            indx = str(self.keyURL).rfind("/") + 1
            return str(self.keyURL)[indx:]
        return None


class KeyInfoCollection(object):
    '''
    This class represents data returned when searching the DRM archived
    secrets.  Essentially, its a list of KeyInfo objects.
    '''

    def __init__(self):
        ''' Constructor '''
        self.key_infos = []
        self.links = []

    @classmethod
    def from_json(cls, json_value):
        ''' Return a KeyInfoCollection object from its JSON representation '''
        ret = cls()
        infos = json_value['entries']
        if not isinstance(infos, types.ListType):
            ret.key_infos.append(KeyInfo.from_json(infos))
        else:
            for info in infos:
                ret.key_infos.append(KeyInfo.from_json(info))
        return ret

class KeyRequestInfo(object):
    '''
    This class represents data about key requests (archival, recovery,
    key generation etc.) in the DRM.
    '''

    def __init__(self):
        ''' Constructor '''
        self.requestURL = None
        self.requestType = None
        self.keyURL = None
        self.requestStatus = None

    @classmethod
    def from_json(cls, attr_list):
        ''' Return a KeyRequestInfo object from a JSON dict. '''
        key_request_info = cls()
        for key in attr_list:
            setattr(key_request_info, key, attr_list[key])
        return key_request_info

    def get_request_id(self):
        ''' Return the request ID by parsing the request URL. '''
        if self.requestURL != None:
            indx = str(self.requestURL).rfind("/") + 1
            return str(self.requestURL)[indx:]
        return None

    def get_key_id(self):
        ''' Return the ID of the secret referred to by this request. '''
        if self.keyURL != None:
            indx = str(self.keyURL).rfind("/") + 1
            return str(self.keyURL)[indx:]
        return None

class KeyRequestInfoCollection(object):
    '''
    This class represents the data returned when searching the key
    requests in the DRM.  Essentially, its a list of KeyRequestInfo
    objects.
    '''

    def __init__(self):
        ''' Constructor '''
        self.key_requests = []
        self.links = []

    @classmethod
    def from_json(cls, json_value):
        ''' Return a KeyRequestInfoCollection object from its JSON representation. '''
        ret = cls()
        infos = json_value['entries']
        if not isinstance(infos, types.ListType):
            ret.key_requests.append(KeyRequestInfo.from_json(infos))
        else:
            for info in infos:
                ret.key_requests.append(KeyRequestInfo.from_json(info))
        return ret

class KeyRequestResponse(object):
    '''
    This class is returned when an archival, recovery or key generation
    request is created.  It includes a KeyRequestInfo object with
    information about the created request, and a KeyData structure
    which contains the wrapped secret (if that operation is supported).
    '''

    def __init__(self):
        ''' Constructor '''
        self.requestInfo = None
        self.keyData = None

    @classmethod
    def from_json(cls, json_value):
        ''' Return a KeyRequestResponse object from its JSON representation. '''
        ret = cls()

        if 'RequestInfo' in json_value:
            ret.requestInfo = KeyRequestInfo.from_json(json_value['RequestInfo'])

        if 'KeyData' in json_value:
            ret.keyData = KeyData.from_json(json_value['KeyData'])
        return ret

    def get_key_id(self):
        ''' Return the id for the key archived, recovered or generated '''
        return self.requestInfo.get_key_id()

    def get_request_id(self):
        ''' Return the id for the created request '''
        return self.requestInfo.get_request_id()

class KeyArchivalRequest(pki.ResourceMessage):
    '''
    Class representing the object sent to the DRM when archiving a secret.
    '''

    def __init__(self, client_id=None, data_type=None, wrapped_private_data=None,
                 key_algorithm=None, key_size=None):
        ''' Constructor '''
        pki.ResourceMessage.__init__(self,
                                 "com.netscape.certsrv.key.KeyArchivalRequest")
        self.add_attribute("clientID", client_id)
        self.add_attribute("dataType", data_type)
        self.add_attribute("wrappedPrivateData", wrapped_private_data)
        self.add_attribute("keyAlgorithm", key_algorithm)
        self.add_attribute("keySize", key_size)

class KeyRecoveryRequest(pki.ResourceMessage):
    '''
    Class representing the data sent to the DRM when either creating a request
    for the recovery of a secret, or, once the request is approved, retrieving
    the secret.
    '''

    def __init__(self, key_id=None, request_id=None,
                 trans_wrapped_session_key=None,
                 session_wrapped_passphrase=None,
                 nonce_data=None, certificate=None,
                 passphrase=None):
        ''' Constructor '''
        pki.ResourceMessage.__init__(self,
                                 "com.netscape.certsrv.key.KeyRecoveryRequest")
        self.add_attribute("requestId", request_id)
        self.add_attribute("transWrappedSessionKey", trans_wrapped_session_key)
        self.add_attribute("sessionWrappedPassphrase", session_wrapped_passphrase)
        self.add_attribute("nonceData", nonce_data)
        self.add_attribute("certificate", certificate)
        self.add_attribute("passphrase", passphrase)
        self.add_attribute("keyId", key_id)

class SymKeyGenerationRequest(pki.ResourceMessage):
    '''
    Class representing the data sent to the DRM when generating and archiving
    a symmetric key on the DRM.
    '''

    UWRAP_USAGE = "unwrap"
    WRAP_USAGE = "wrap"
    VERIFY_USAGE = "verify"
    SIGN_USAGE = "sign"
    DECRYPT_USAGE = "decrypt"
    ENCRYPT_USAGE = "encrypt"

    def __init__(self, client_id=None, key_size=None, key_algorithm=None,
                 key_usages=None):
        ''' Constructor '''
        pki.ResourceMessage.__init__(self,
                                 "com.netscape.certsrv.key.SymKeyGenerationRequest")
        key_usages = key_usages or []
        self.add_attribute("clientID", client_id)
        self.add_attribute("keySize", key_size)
        self.add_attribute("keyAlgorithm", key_algorithm)
        self.add_attribute("keyUsage", ','.join(key_usages))

class KeyClient(object):
    '''
    Class that encapsulates and mirrors the functions in the KeyResource
    and KeyRequestResource Java classes in the DRM REST API.
    '''

    SYMMETRIC_KEY_TYPE = "symmetricKey"
    PASS_PHRASE_TYPE = "passPhrase"
    ASYMMETRIC_KEY_TYPE = "asymmetricKey"

    def __init__(self, connection):
        ''' Constructor '''
        self.connection = connection
        self.headers = {'Content-type': 'application/json',
                        'Accept': 'application/json'}
        self.keyURL = '/rest/agent/keys'
        self.keyRequestsURL = '/rest/agent/keyrequests'

    @pki.handle_exceptions()
    def list_keys(self, client_id=None, status=None, max_results=None,
                  max_time=None, start=None, size=None):
        ''' List/Search archived secrets in the DRM.

            See KRAClient.list_keys for the valid values of status.
            Returns a KeyInfoCollection object.
        '''
        query_params = {'clientID':client_id, 'status':status,
                        'maxResults':max_results, 'maxTime':max_time,
                        'start':start, 'size':size}
        response = self.connection.get(self.keyURL, self.headers, params=query_params)
        return KeyInfoCollection.from_json(response.json())

    @pki.handle_exceptions()
    def retrieve_key(self, data):
        ''' Retrieve a secret from the DRM.

            @param: data - a KeyRecoveryRequest containing the keyId of the
            secret being retrieved, the request_id of the approved recovery
            request and a wrapping mechanism.  More details at
            KRAClient.retrieve_key.

            Returns a KeyData object containing the wrapped secret.
        '''
        url = self.keyURL + '/retrieve'
        keyRequest = json.dumps(data, cls=encoder.CustomTypeEncoder, sort_keys=True)
        response = self.connection.post(url, keyRequest, self.headers)
        return KeyData.from_json(response.json())

    @pki.handle_exceptions()
    def request_key_retrieval(self, key_id, request_id, trans_wrapped_session_key=None,
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

            Returns a KeyData object containing the wrapped secret.
        '''
        request = KeyRecoveryRequest(key_id=key_id,
                                     request_id=request_id,
                                     trans_wrapped_session_key=trans_wrapped_session_key,
                                     session_wrapped_passphrase=session_wrapped_passphrase,
                                     nonce_data=nonce_data,
                                     passphrase=passphrase)

        return self.retrieve_key(request)

    @pki.handle_exceptions()
    def list_requests(self, request_state=None, request_type=None, client_id=None,
                     start=None, page_size=None, max_results=None, max_time=None):
        ''' List/Search key requests in the DRM.

            See KRAClient.list_requests for the valid values of request_state and
            request_type.  Returns a KeyRequestInfoCollection object.
        '''
        query_params = {'requestState':request_state, 'requestType':request_type,
                        'clientID':client_id, 'start':start, 'pageSize':page_size,
                        'maxResults':max_results, 'maxTime':max_time}
        response = self.connection.get(self.keyRequestsURL, self.headers,
                                params=query_params)
        return KeyRequestInfoCollection.from_json(response.json())

    @pki.handle_exceptions()
    def get_request_info(self, request_id):
        ''' Return a KeyRequestInfo object for a specific request. '''
        url = self.keyRequestsURL + '/' + request_id
        response = self.connection.get(url, self.headers)
        return KeyRequestInfo.from_json(response.json())

    @pki.handle_exceptions()
    def create_request(self, request):
        ''' Submit an archival, recovery or key generation request
            to the DRM.

            @param request - is either a KeyArchivalRequest,
            KeyRecoverRequest or SymKeyGenerationRequest.

            returns a KeyRequestResponse object.
        '''
        url = self.keyRequestsURL
        key_request = json.dumps(request, cls=encoder.CustomTypeEncoder, sort_keys=True)
        response = self.connection.post(url, key_request, self.headers)
        return KeyRequestResponse.from_json(response.json())

    @pki.handle_exceptions()
    def approve_request(self, request_id):
        ''' Approve a secret recovery request '''
        url = self.keyRequestsURL + '/' + request_id + '/approve'
        self.connection.post(url, self.headers)

    @pki.handle_exceptions()
    def reject_request(self, request_id):
        ''' Reject a secret recovery request. '''
        url = self.keyRequestsURL + '/' + request_id + '/reject'
        self.connection.post(url, self.headers)

    @pki.handle_exceptions()
    def cancel_request(self, request_id):
        ''' Cancel a secret recovery request '''
        url = self.keyRequestsURL + '/' + request_id + '/cancel'
        self.connection.post(url, self.headers)

    @pki.handle_exceptions()
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
        request = KeyRecoveryRequest(key_id=key_id,
                                     request_id=request_id,
                                     trans_wrapped_session_key=trans_wrapped_session_key,
                                     session_wrapped_passphrase=session_wrapped_passphrase,
                                     certificate=b64certificate,
                                     nonce_data=nonce_data)
        return self.create_request(request)

    @pki.handle_exceptions()
    def request_archival(self, client_id, data_type, wrapped_private_data,
                    key_algorithm=None, key_size=None):
        ''' Archive a secret (symmetric key or passphrase) on the DRM.

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
        request = KeyArchivalRequest(client_id=client_id,
                                     data_type=data_type,
                                     wrapped_private_data=wrapped_private_data,
                                     key_algorithm=key_algorithm,
                                     key_size=key_size)
        return self.create_request(request)

    @pki.handle_exceptions()
    def get_key_info(self, key_id):
        ''' Get the info in the KeyRecord for a specific secret in the DRM. '''
        url = self.keyURL + '/' + key_id
        response = self.connection.get(url, headers=self.headers)
        return KeyInfo.from_json(response.json())

    @pki.handle_exceptions()
    def modify_key_status(self, key_id, status):
        ''' Modify the status of a key '''
        url = self.keyURL + '/' + key_id
        params = {'status':status}
        self.connection.post(url, None, headers=self.headers, params=params)

encoder.NOTYPES['Attribute'] = pki.Attribute
encoder.NOTYPES['AttributeList'] = pki.AttributeList
encoder.NOTYPES['KeyArchivalRequest'] = KeyArchivalRequest
encoder.NOTYPES['KeyRecoveryRequest'] = KeyRecoveryRequest
encoder.NOTYPES['ResourceMessage'] = pki.ResourceMessage
encoder.NOTYPES['SymKeyGenerationRequest'] = SymKeyGenerationRequest

def main():
    ''' Some unit tests - basically printing different types of requests '''
    print "printing symkey generation request"
    client_id = "vek 123"
    usages = [SymKeyGenerationRequest.DECRYPT_USAGE, SymKeyGenerationRequest.ENCRYPT_USAGE]
    gen_request = SymKeyGenerationRequest(client_id, 128, "AES", usages)
    print json.dumps(gen_request, cls=encoder.CustomTypeEncoder, sort_keys=True)

    print "printing key recovery request"
    key_request = KeyRecoveryRequest("25", "MX12345BBBAAA", None,
                                     "1234ABC", None, None)
    print json.dumps(key_request, cls=encoder.CustomTypeEncoder, sort_keys=True)

    print "printing key archival request"
    archival_request = KeyArchivalRequest(client_id, "symmetricKey",
                                          "MX123AABBCD", "AES", 128)
    print json.dumps(archival_request, cls=encoder.CustomTypeEncoder, sort_keys=True)

if __name__ == '__main__':
    main()
