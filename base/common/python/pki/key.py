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
Module containing the Python client classes for the KeyResource and
KeyRequestResource REST API on a DRM
'''
import pki.encoder as e
import json
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

    def from_dict(self, attr_list):
        ''' Return a KeyData object from a JSON dict '''
        for key in attr_list:
            setattr(self, key, attr_list[key])
        return self

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

    def from_dict(self, attr_list):
        ''' Return KeyInfo from JSON dict '''
        for key in attr_list:
            setattr(self, key, attr_list[key])
        return self

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

    def decode_from_json(self, json_value):
        ''' Populate the object from its JSON representation '''
        infos = json_value['entries']
        if not isinstance(infos, types.ListType):
            info = KeyInfo()
            self.key_infos.append(info.from_dict(infos))
        else:
            for info in infos:
                key_info = KeyInfo()
                key_info.from_dict(info)
                self.key_infos.append(key_info)

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

    def from_dict(self, attr_list):
        ''' Return a KeyRequestInfo object from a JSON dict. '''
        for key in attr_list:
            setattr(self, key, attr_list[key])
        return self

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

    def decode_from_json(self, json_value):
        ''' Populate the object from its JSON representation. '''
        infos = json_value['entries']
        if not isinstance(infos, types.ListType):
            info = KeyRequestInfo()
            self.key_requests.append(info.from_dict(infos))
        else:
            for info in infos:
                key_request_info = KeyRequestInfo()
                key_request_info.from_dict(info)
                self.key_requests.append(key_request_info)

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

    def decode_from_json(self, json_value):
        ''' Populate the object from its JSON representation. '''
        self.requestInfo = KeyRequestInfo()
        self.requestInfo.from_dict(json_value['RequestInfo'])

class Attribute(object):
    '''
    Class representing a key/value pair.

    This object is the basis of the representation of a ResourceMessage.
    '''

    def __init__(self, name, value):
        ''' Constructor '''
        self.name = name
        self.value = value

class AttributeList(object):
    '''
    Class representing a list of attributes.

    This class is needed because of a JavaMapper used in the REST API.
    '''

    def __init__(self):
        ''' Constructor '''
        self.Attribute = []

class ResourceMessage(object):
    '''
    This class is the basis for the various types of key requests.
    It is essentially a list of attributes.
    '''

    def __init__(self, class_name):
        ''' Constructor '''
        self.Attributes = AttributeList()
        self.ClassName = class_name

    def add_attribute(self, name, value):
        ''' Add an attribute to the list. '''
        attr = Attribute(name, value)
        self.Attributes.Attribute.append(attr)

    def get_attribute_value(self, name):
        ''' Get the value of a given attribute '''
        for attr in self.Attributes.Attribute:
            if attr.name == name:
                return attr.value
        return None

class KeyArchivalRequest(ResourceMessage):
    '''
    Class representing the object sent to the DRM when archiving a secret.
    '''

    def __init__(self, client_id=None, data_type=None, wrapped_private_data=None,
                 key_algorithm=None, key_size=None):
        ''' Constructor '''
        ResourceMessage.__init__(self,
                                 "com.netscape.certsrv.key.KeyArchivalRequest")
        self.add_attribute("clientID", client_id)
        self.add_attribute("dataType", data_type)
        self.add_attribute("wrappedPrivateData", wrapped_private_data)
        self.add_attribute("keyAlgorithm", key_algorithm)
        self.add_attribute("keySize", key_size)

class KeyRecoveryRequest(ResourceMessage):
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
        ResourceMessage.__init__(self,
                                 "com.netscape.certsrv.key.KeyRecoveryRequest")
        self.add_attribute("requestId", request_id)
        self.add_attribute("transWrappedSessionKey", trans_wrapped_session_key)
        self.add_attribute("sessionWrappedPassphrase", session_wrapped_passphrase)
        self.add_attribute("nonceData", nonce_data)
        self.add_attribute("certificate", certificate)
        self.add_attribute("passphrase", passphrase)
        self.add_attribute("keyId", key_id)

class SymKeyGenerationRequest(ResourceMessage):
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
                 key_usage=None):
        ''' Constructor '''
        ResourceMessage.__init__(self,
                                 "com.netscape.certsrv.key.SymKeyGenerationRequest")
        self.add_attribute("clientID", client_id)
        self.add_attribute("keySize", key_size)
        self.add_attribute("keyAlgorithm", key_algorithm)
        self.add_attribute("keyUsage", key_usage)

class KeyResource(object):
    '''
    Class that encapsulates and mirrors the functions in the KeyResource
    Java class in the DRM REST API.
    '''

    def __init__(self, connection):
        ''' Constructor '''
        self.connection = connection
        self.headers = {'Content-type': 'application/json',
                        'Accept': 'application/json'}
        self.keyURL = '/rest/agent/keys'

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
        kdis = KeyInfoCollection()
        kdis.decode_from_json(response.json())
        return kdis

    def retrieve_key(self, data):
        ''' Retrieve a secret from the DRM.

            @param: data - a KeyRecoveryRequest containing the keyId of the
            secret being retrieved, the request_id of the approved recovery
            request and a wrapping mechanism.  More details at
            KRAClient.retrieve_key.

            Returns a KeyData object containing the wrapped secret.
        '''
        url = self.keyURL + '/retrieve'
        print url
        e.NOTYPES['KeyRecoveryRequest'] = KeyRecoveryRequest
        e.NOTYPES['ResourceMessage'] = ResourceMessage
        e.NOTYPES['Attribute'] = Attribute
        e.NOTYPES['AttributeList'] = AttributeList
        keyRequest = json.dumps(data, cls=e.CustomTypeEncoder, sort_keys=True)
        response = self.connection.post(url, keyRequest, self.headers)
        keydata = KeyData()
        keydata.from_dict(response.json())
        return keydata

class KeyRequestResource(object):
    '''
    Class that encapsulates and mirrors the functions in the KeyRequestResource
    Java class in the DRM REST API/
    '''

    def __init__(self, connection):
        ''' Constructor '''
        self.connection = connection
        self.headers = {'Content-type': 'application/json',
                        'Accept': 'application/json'}
        self.keyRequestsURL = '/rest/agent/keyrequests'

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
        kdis = KeyRequestInfoCollection()
        kdis.decode_from_json(response.json())
        return kdis

    def get_request_info(self, request_id):
        ''' Return a KeyRequestInfo object for a specific request. '''
        url = self.keyRequestsURL + '/' + request_id.value
        response = self.connection.get(url, self.headers)
        info = KeyRequestInfo()
        info.from_dict(response.json())
        return info

    def create_request(self, request):
        ''' Submit an archival, recovery or key generation request
            to the DRM.

            @param request - is either a KeyArchivalRequest,
            KeyRecoverRequest or SymKeyGenerationRequest.

            returns a KeyRequestResponse object.
        '''
        url = self.keyRequestsURL
        print request
        e.NOTYPES['SymKeyGenerationRequest'] = SymKeyGenerationRequest
        e.NOTYPES['KeyArchivalRequest'] = KeyArchivalRequest
        e.NOTYPES['KeyRecoveryRequest'] = KeyRecoveryRequest
        e.NOTYPES['ResourceMessage'] = ResourceMessage
        e.NOTYPES['Attribute'] = Attribute
        e.NOTYPES['AttributeList'] = AttributeList
        key_request1 = json.dumps(request, cls=e.CustomTypeEncoder, sort_keys=True)
        print key_request1
        response = self.connection.post(url, key_request1, self.headers)
        key_response = KeyRequestResponse()
        key_response.decode_from_json(response.json())
        return key_response

    def approve_request(self, request_id):
        ''' Approve a secret recovery request '''
        url = self.keyRequestsURL + '/' + request_id.value + '/approve'
        return self.connection.post(url, self.headers)

    def reject_request(self, request_id):
        ''' Reject a secret recovery request. '''
        url = self.keyRequestsURL + '/' + request_id.value + '/reject'
        return self.connection.post(url, self.headers)

    def cancel_request(self, request_id):
        ''' Cancel a secret recovery request '''
        url = self.keyRequestsURL + '/' + request_id.value + '/cancel'
        return self.connection.post(url, self.headers)


def main():
    print "printing symkey generation request"
    client_id = "vek 123"
    gen_request = SymKeyGenerationRequest(client_id, 128, "AES", "encrypt,decrypt")
    e.NOTYPES['SymKeyGenerationRequest'] = SymKeyGenerationRequest
    e.NOTYPES['ResourceMessage'] = ResourceMessage
    e.NOTYPES['Attribute'] = Attribute
    e.NOTYPES['AttributeList'] = AttributeList
    print json.dumps(gen_request, cls=e.CustomTypeEncoder, sort_keys=True)

    print "printing key recovery request"
    key_request = KeyRecoveryRequest("25", "MX12345BBBAAA", None,
                                     "1234ABC", None, None)
    e.NOTYPES['KeyRecoveryRequest'] = KeyRecoveryRequest
    e.NOTYPES['ResourceMessage'] = ResourceMessage
    e.NOTYPES['Attribute'] = Attribute
    e.NOTYPES['AttributeList'] = AttributeList
    print json.dumps(key_request, cls=e.CustomTypeEncoder, sort_keys=True)

    print "printing key archival request"
    archival_request = KeyArchivalRequest(client_id, "symmetricKey",
                                          "MX123AABBCD", "AES", 128)
    e.NOTYPES['KeyArchivalRequest'] = KeyArchivalRequest
    e.NOTYPES['ResourceMessage'] = ResourceMessage
    e.NOTYPES['Attribute'] = Attribute
    e.NOTYPES['AttributeList'] = AttributeList
    print json.dumps(archival_request, cls=e.CustomTypeEncoder, sort_keys=True)

if __name__ == '__main__':
    main()
