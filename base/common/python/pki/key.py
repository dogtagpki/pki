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
import base64
import pki.encoder as encoder
import json
import pki
import types
import urllib

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
        self.clientKeyID = None
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
        if self.keyURL is not None:
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
        if self.requestURL is not None:
            indx = str(self.requestURL).rfind("/") + 1
            return str(self.requestURL)[indx:]
        return None

    def get_key_id(self):
        ''' Return the ID of the secret referred to by this request. '''
        if self.keyURL is not None:
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

    def __init__(self, client_key_id=None, data_type=None, wrapped_private_data=None,
                 key_algorithm=None, key_size=None):
        ''' Constructor '''
        pki.ResourceMessage.__init__(self,
                                 "com.netscape.certsrv.key.KeyArchivalRequest")
        self.add_attribute("clientKeyID", client_key_id)
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

    def __init__(self, client_key_id=None, key_size=None, key_algorithm=None,
                 key_usages=None, trans_wrapped_session_key=None):
        ''' Constructor '''
        pki.ResourceMessage.__init__(self,
                                 "com.netscape.certsrv.key.SymKeyGenerationRequest")
        key_usages = key_usages or []
        self.add_attribute("clientKeyID", client_key_id)
        self.add_attribute("keySize", key_size)
        self.add_attribute("keyAlgorithm", key_algorithm)
        self.add_attribute("keyUsage", ','.join(key_usages))
        self.add_attribute("transWrappedSessionKey", trans_wrapped_session_key)

class KeyClient(object):
    '''
    Class that encapsulates and mirrors the functions in the KeyResource
    and KeyRequestResource Java classes in the DRM REST API.
    '''

    SYMMETRIC_KEY_TYPE = "symmetricKey"
    PASS_PHRASE_TYPE = "passPhrase"
    ASYMMETRIC_KEY_TYPE = "asymmetricKey"

    KEY_STATUS_ACTIVE = "active"
    KEY_STATUS_INACTIVE = "inactive"

    def __init__(self, connection, crypto, transport_cert_nick=None):
        ''' Constructor '''
        self.connection = connection
        self.headers = {'Content-type': 'application/json',
                        'Accept': 'application/json'}
        self.keyURL = '/rest/agent/keys'
        self.keyRequestsURL = '/rest/agent/keyrequests'
        self.crypto = crypto

        if transport_cert_nick is not None:
            self.crypto.initialize()
            self.transport_cert = crypto.get_cert(transport_cert_nick)
        else:
            self.transport_cert = None

    def set_transport_cert(self, transport_cert_nick):
        ''' Set the transport certificate for crypto operations '''
        if transport_cert_nick is None:
            raise ValueError("Transport cert nickname must be specified.")
        self.transport_cert = self.crypto.get_cert(transport_cert_nick)

    @pki.handle_exceptions()
    def list_keys(self, client_key_id=None, status=None, max_results=None,
                  max_time=None, start=None, size=None):
        ''' List/Search archived secrets in the DRM.

            See KRAClient.list_keys for the valid values of status.
            Returns a KeyInfoCollection object.
        '''
        query_params = {'clientKeyID':client_key_id, 'status':status,
                        'maxResults':max_results, 'maxTime':max_time,
                        'start':start, 'size':size}
        response = self.connection.get(self.keyURL, self.headers, params=query_params)
        return KeyInfoCollection.from_json(response.json())

    @pki.handle_exceptions()
    def list_requests(self, request_state=None, request_type=None, client_key_id=None,
                     start=None, page_size=None, max_results=None, max_time=None):
        ''' List/Search key requests in the DRM.

            See KRAClient.list_requests for the valid values of request_state and
            request_type.  Returns a KeyRequestInfoCollection object.
        '''
        query_params = {'requestState':request_state, 'requestType':request_type,
                        'clientKeyID':client_key_id, 'start':start, 'pageSize':page_size,
                        'maxResults':max_results, 'maxTime':max_time}
        response = self.connection.get(self.keyRequestsURL, self.headers,
                                params=query_params)
        return KeyRequestInfoCollection.from_json(response.json())

    @pki.handle_exceptions()
    def get_request_info(self, request_id):
        ''' Return a KeyRequestInfo object for a specific request. '''
        if request_id is None:
            raise ValueError("request_id must be specified")

        url = self.keyRequestsURL + '/' + request_id
        response = self.connection.get(url, self.headers)
        return KeyRequestInfo.from_json(response.json())

    @pki.handle_exceptions()
    def get_key_info(self, key_id):
        ''' Get the info in the KeyRecord for a specific secret in the DRM. '''
        if key_id is None:
            raise ValueError("key_id must be specified")

        url = self.keyURL + '/' + key_id
        response = self.connection.get(url, headers=self.headers)
        return KeyInfo.from_json(response.json())

    @pki.handle_exceptions()
    def get_active_key_info(self, client_key_id):
        ''' Get the info in the KeyRecord for the active secret in the DRM. '''
        if client_key_id is None:
            raise ValueError("client_key_id must be specified")

        url = self.keyURL + '/active/' + urllib.quote_plus(client_key_id)
        response = self.connection.get(url, headers=self.headers)
        return KeyInfo.from_json(response.json())

    @pki.handle_exceptions()
    def modify_key_status(self, key_id, status):
        ''' Modify the status of a key '''
        if (key_id is None) or (status is None):
            raise ValueError("key_id and status must be specified")

        url = self.keyURL + '/' + key_id
        params = {'status':status}
        self.connection.post(url, None, headers=self.headers, params=params)

    @pki.handle_exceptions()
    def approve_request(self, request_id):
        ''' Approve a secret recovery request '''
        if request_id is None:
            raise ValueError("request_id must be specified")

        url = self.keyRequestsURL + '/' + request_id + '/approve'
        self.connection.post(url, self.headers)

    @pki.handle_exceptions()
    def reject_request(self, request_id):
        ''' Reject a secret recovery request. '''
        if request_id is None:
            raise ValueError("request_id must be specified")

        url = self.keyRequestsURL + '/' + request_id + '/reject'
        self.connection.post(url, self.headers)

    @pki.handle_exceptions()
    def cancel_request(self, request_id):
        ''' Cancel a secret recovery request '''
        if request_id is None:
            raise ValueError("request_id must be specified")

        url = self.keyRequestsURL + '/' + request_id + '/cancel'
        self.connection.post(url, self.headers)

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
        if secret is None:
            raise ValueError("secret must be specified")

        session_key = self.crypto.generate_symmetric_key()
        trans_wrapped_session_key = self.crypto.asymmetric_wrap(session_key, self.transport_cert)
        wrapped_secret = self.crypto.symmetric_wrap(secret, session_key)

        return self.generate_pki_archive_options(trans_wrapped_session_key, wrapped_secret)

    @pki.handle_exceptions()
    def create_request(self, request):
        ''' Submit an archival, recovery or key generation request
            to the DRM.

            @param request - is either a KeyArchivalRequest,
            KeyRecoverRequest or SymKeyGenerationRequest.

            returns a KeyRequestResponse object.
        '''
        if request is None:
            raise ValueError("request must be specified")

        url = self.keyRequestsURL
        key_request = json.dumps(request, cls=encoder.CustomTypeEncoder, sort_keys=True)
        response = self.connection.post(url, key_request, self.headers)
        return KeyRequestResponse.from_json(response.json())

    @pki.handle_exceptions()
    def generate_symmetric_key(self, client_key_id, algorithm=None, size=None, usages=None,
                               trans_wrapped_session_key=None):
        ''' Generate and archive a symmetric key on the DRM.

            Return a KeyRequestResponse which contains a KeyRequestInfo
            object that describes the URL for the request and generated key.

        '''
        if client_key_id is None:
            raise ValueError("Must specify client_key_id")

        if trans_wrapped_session_key is not None:
            twsk = base64.encodestring(trans_wrapped_session_key)
            request = SymKeyGenerationRequest(
                            client_key_id=client_key_id,
                            key_size=size,
                            key_algorithm=algorithm,
                            key_usages=usages,
                            trans_wrapped_session_key=twsk)
            raise NotImplementedError(
                    "Returning the symmetric key in the same call is not yet implemented.")
        else:
            request = SymKeyGenerationRequest(
                            client_key_id=client_key_id,
                            key_size=size,
                            key_algorithm=algorithm,
                            key_usages=usages)
        return self.create_request(request)

    @pki.handle_exceptions()
    def archive_key(self, client_key_id, data_type, private_data=None,
                    wrapped_private_data=None,
                    key_algorithm=None, key_size=None):
        ''' Archive a secret (symmetric key or passphrase) on the DRM.

            Requires a user-supplied client ID.  There can be only one active
            key with a specified client ID.  If a record for a duplicate active
            key exists, a BadRequestException is thrown.

            data_type can be one of the following:
                KeyClient.SYMMETRIC_KEY_TYPE,
                KeyClient.ASYMMETRIC_KEY_TYPE,
                KeyClient.PASS_PHRASE_TYPE

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
        if (client_key_id is None) or (data_type is None):
            raise ValueError("client_key_id and data_type must be specified")

        if data_type == KeyClient.SYMMETRIC_KEY_TYPE:
            if (key_algorithm is None) or (key_size is None):
                raise ValueError(
                        "For symmetric keys, key algorithm and key_size must be specified")

        if wrapped_private_data is None:
            if private_data is None:
                raise ValueError("No data provided to be archived")
            wrapped_private_data = self.generate_archive_options(private_data)

        request = KeyArchivalRequest(client_key_id=client_key_id,
                                     data_type=data_type,
                                     wrapped_private_data=wrapped_private_data,
                                     key_algorithm=key_algorithm,
                                     key_size=key_size)
        return self.create_request(request)

    @pki.handle_exceptions()
    def recover_key(self, key_id, request_id=None, session_wrapped_passphrase=None,
                        trans_wrapped_session_key=None, b64certificate=None, nonce_data=None):
        ''' Create a request to recover a secret.

            To retrieve a symmetric key or passphrase, the only parameter that is required is
            the keyId.  It is possible (but not required) to pass in the session keys/passphrase
            and nonceData for the retrieval at this time.  Those parameters are documented
            in the docstring for retrieve_key below.

            To retrieve an asymmetric key, the keyId and the the base-64 encoded certificate
            is required.
        '''
        if key_id is None:
            raise ValueError("key_id must be defined")

        request = KeyRecoveryRequest(key_id=key_id,
                                     request_id=request_id,
                                     trans_wrapped_session_key=trans_wrapped_session_key,
                                     session_wrapped_passphrase=session_wrapped_passphrase,
                                     certificate=b64certificate,
                                     nonce_data=nonce_data)
        return self.create_request(request)

    @pki.handle_exceptions()
    def retrieve_key_data(self, data):
        ''' Retrieve a secret from the DRM.

            @param: data - a KeyRecoveryRequest containing the keyId of the
            secret being retrieved, the request_id of the approved recovery
            request and a wrapping mechanism.  More details at
            KRAClient.retrieve_key.

            Returns a KeyData object containing the wrapped secret.
        '''
        if data is None:
            raise ValueError("KeyRecoveryRequest must be specified")

        url = self.keyURL + '/retrieve'
        keyRequest = json.dumps(data, cls=encoder.CustomTypeEncoder, sort_keys=True)
        response = self.connection.post(url, keyRequest, self.headers)
        return KeyData.from_json(response.json())

    @pki.handle_exceptions()
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
        if key_id is None:
            raise ValueError("key_id must be specified")

        key_provided = True
        if trans_wrapped_session_key is None:
            key_provided = False
            session_key = self.crypto.generate_symmetric_key()
            trans_wrapped_session_key = self.crypto.asymmetric_wrap(session_key,
                                                                    self.transport_cert)

        response = self.recover_key(key_id)
        request_id = response.get_request_id()
        self.approve_request(request_id)

        request = KeyRecoveryRequest(
                        key_id=key_id,
                        request_id=request_id,
                        trans_wrapped_session_key=base64.encodestring(trans_wrapped_session_key))

        key_data = self.retrieve_key_data(request)
        if key_provided:
            return key_data, None

        unwrapped_key = self.crypto.symmetric_unwrap(
                                base64.decodestring(key_data.wrappedPrivateData),
                                session_key,
                                nonce_iv=base64.decodestring(key_data.nonceData))
        return key_data, unwrapped_key

    @pki.handle_exceptions()
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

    @pki.handle_exceptions()
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
        if (key_id is None) or (certificate is None) or (passphrase is None):
            raise ValueError("key_id, certificate and passphrase must all be specified")

        response = self.recover_key(key_id, b64certificate=certificate)
        request_id = response.get_request_id()
        self.approve_request(request_id)

        request = KeyRecoveryRequest(key_id=key_id,
                                     request_id=request_id,
                                     passphrase=passphrase)

        return self.retrieve_key_data(request)

encoder.NOTYPES['Attribute'] = pki.Attribute
encoder.NOTYPES['AttributeList'] = pki.AttributeList
encoder.NOTYPES['KeyArchivalRequest'] = KeyArchivalRequest
encoder.NOTYPES['KeyRecoveryRequest'] = KeyRecoveryRequest
encoder.NOTYPES['ResourceMessage'] = pki.ResourceMessage
encoder.NOTYPES['SymKeyGenerationRequest'] = SymKeyGenerationRequest

def main():
    ''' Some unit tests - basically printing different types of requests '''
    print "printing symkey generation request"
    client_key_id = "vek 123"
    usages = [SymKeyGenerationRequest.DECRYPT_USAGE, SymKeyGenerationRequest.ENCRYPT_USAGE]
    gen_request = SymKeyGenerationRequest(client_key_id, 128, "AES", usages)
    print json.dumps(gen_request, cls=encoder.CustomTypeEncoder, sort_keys=True)

    print "printing key recovery request"
    key_request = KeyRecoveryRequest("25", "MX12345BBBAAA", None,
                                     "1234ABC", None, None)
    print json.dumps(key_request, cls=encoder.CustomTypeEncoder, sort_keys=True)

    print "printing key archival request"
    archival_request = KeyArchivalRequest(client_key_id, "symmetricKey",
                                          "MX123AABBCD", "AES", 128)
    print json.dumps(archival_request, cls=encoder.CustomTypeEncoder, sort_keys=True)

if __name__ == '__main__':
    main()
