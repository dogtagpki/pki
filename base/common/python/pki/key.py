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
#     Abhishek Koneru <akoneru@redhat.com>
#     Ade Lee <alee@redhat.com>
#
"""
Module containing the Python client classes for the KeyClient and
KeyRequestClient REST API on a DRM
"""
from __future__ import absolute_import
from __future__ import print_function
import base64
import json

from six import iteritems
from six.moves.urllib.parse import quote  # pylint: disable=F0401,E0611

import pki
import pki.encoder as encoder


# should be moved to request.py
# pylint: disable=R0903
class RequestId(object):
    """
    Class representing a Request ID
    """

    def __init__(self, req_id):
        """ Constructor"""
        self.value = req_id


# pylint: disable=R0903
class KeyData(object):
    """
    This is the object that contains the encoded wrapped secret
    when that secret is retrieved. It is used by the DRM
    to send information of the key in the key retrieval requests.
    """

    json_attribute_names = {
        'nonceData': 'nonce_data', 'wrappedPrivateData': 'wrapped_private_data'
    }

    # pylint: disable=C0103
    def __init__(self):
        """ Constructor """
        self.algorithm = None
        self.nonce_data = None
        self.size = None
        self.wrapped_private_data = None

    @classmethod
    def from_json(cls, attr_list):
        """ Return a KeyData object from a JSON dict """
        key_data = cls()
        for k, v in iteritems(attr_list):
            if k in KeyData.json_attribute_names:
                setattr(key_data, KeyData.json_attribute_names[k], v)
            else:
                setattr(key_data, k, v)
        return key_data


class Key(object):
    """
    An instance of this class stores the decoded encrypted secret
    present in the KeyData object passed in the constructor.
    All the key retrieval requests return this object.
    """

    def __init__(self, key_data):
        """ Constructor """
        self.encrypted_data = base64.decodestring(
            key_data.wrapped_private_data)
        self.nonce_data = base64.decodestring(key_data.nonce_data)
        self.algorithm = key_data.algorithm
        self.size = key_data.size

        # To store the unwrapped key information.
        # The decryption takes place on the client side.
        self.data = None


class KeyInfo(object):
    """
    This is the object that contains information stored
    in the database record for an archived secret.  It does not
    contain the secret itself.
    """

    json_attribute_names = {
        'clientKeyID': 'client_key_id', 'keyURL': 'key_url',
        'ownerName': 'owner_name', 'publicKey': 'public_key'
    }

    # pylint: disable=C0103
    def __init__(self):
        """ Constructor """
        self.client_key_id = None
        self.key_url = None
        self.algorithm = None
        self.status = None
        self.owner_name = None
        self.size = None
        self.public_key = None

    @classmethod
    def from_json(cls, attr_list):
        """ Return KeyInfo from JSON dict """
        key_info = cls()
        for k, v in iteritems(attr_list):
            if k in KeyInfo.json_attribute_names:
                setattr(key_info, KeyInfo.json_attribute_names[k], v)
            else:
                setattr(key_info, k, v)
        if key_info.public_key is not None:
            key_info.public_key = base64.decodestring(key_info.public_key)
        return key_info

    def get_key_id(self):
        """ Return the key ID as parsed from key URL """
        if self.key_url is not None:
            indx = str(self.key_url).rfind("/") + 1
            return str(self.key_url)[indx:]
        return None


# pylint: disable=R0903
class KeyInfoCollection(object):
    """
    This class represents data returned when searching the DRM archived
    secrets.  Essentially, its a list of KeyInfo objects.
    """

    def __init__(self):
        """ Constructor """
        self.key_infos = []
        self.links = []

    @classmethod
    def from_json(cls, json_value):
        """ Return a KeyInfoCollection object from its JSON representation """
        ret = cls()
        infos = json_value['entries']
        if not isinstance(infos, list):
            ret.key_infos.append(KeyInfo.from_json(infos))
        else:
            for info in infos:
                ret.key_infos.append(KeyInfo.from_json(info))
        return ret


class KeyRequestInfo(object):
    """
    This class represents data about key requests (archival, recovery,
    key generation etc.) in the DRM.
    """

    json_attribute_names = {
        'requestURL': 'request_url', 'requestType': 'request_type',
        'keyURL': 'key_url', 'requestStatus': 'request_status'
    }

    # pylint: disable=C0103
    def __init__(self):
        """ Constructor """
        self.request_url = None
        self.request_type = None
        self.key_url = None
        self.request_status = None

    @classmethod
    def from_json(cls, attr_list):
        """ Return a KeyRequestInfo object from a JSON dict. """
        key_request_info = cls()
        for k, v in iteritems(attr_list):
            if k in KeyRequestInfo.json_attribute_names:
                setattr(key_request_info,
                        KeyRequestInfo.json_attribute_names[k], v)
            else:
                setattr(key_request_info, k, v)

        return key_request_info

    def get_request_id(self):
        """ Return the request ID by parsing the request URL. """
        if self.request_url is not None:
            index = str(self.request_url).rfind("/") + 1
            return str(self.request_url)[index:]
        return None

    def get_key_id(self):
        """ Return the ID of the secret referred to by this request. """
        if self.key_url is not None:
            index = str(self.key_url).rfind("/") + 1
            return str(self.key_url)[index:]
        return None


# pylint: disable=R0903
class KeyRequestInfoCollection(object):
    """
    This class represents the data returned when searching the key
    requests in the DRM.  Essentially, its a list of KeyRequestInfo
    objects.
    """

    def __init__(self):
        """ Constructor """
        self.key_requests = []
        self.links = []

    @classmethod
    def from_json(cls, json_value):
        """
        Return a KeyRequestInfoCollection object from its JSON representation.
        """
        ret = cls()
        infos = json_value['entries']
        if not isinstance(infos, list):
            ret.key_requests.append(KeyRequestInfo.from_json(infos))
        else:
            for info in infos:
                ret.key_requests.append(KeyRequestInfo.from_json(info))
        return ret


class KeyRequestResponse(object):
    """
    This class is returned when an archival, recovery or key generation
    request is created.  It includes a KeyRequestInfo object with
    information about the created request, and a KeyData structure
    which contains the wrapped secret (if that operation is supported).
    """

    # pylint: disable=C0103
    def __init__(self):
        """ Constructor """
        self.request_info = None
        self.key_data = None

    @classmethod
    def from_json(cls, json_value):
        """ Return a KeyRequestResponse object from its JSON representation. """
        ret = cls()

        if 'RequestInfo' in json_value:
            ret.request_info = KeyRequestInfo.from_json(
                json_value['RequestInfo'])

        if 'KeyData' in json_value:
            ret.key_data = KeyData.from_json(json_value['KeyData'])
        return ret

    def get_key_id(self):
        """ Return the id for the key archived, recovered or generated """
        return self.request_info.get_key_id()

    def get_request_id(self):
        """ Return the id for the created request """
        return self.request_info.get_request_id()


class KeyArchivalRequest(pki.ResourceMessage):
    """
    Class representing the object sent to the DRM when archiving a secret.
    """

    def __init__(self, client_key_id=None, data_type=None,
                 wrapped_private_data=None,
                 trans_wrapped_session_key=None, pki_archive_options=None,
                 algorithm_oid=None, symkey_params=None,
                 key_algorithm=None, key_size=None):
        """ Constructor """
        pki.ResourceMessage.__init__(
            self,
            "com.netscape.certsrv.key.KeyArchivalRequest")
        self.add_attribute("clientKeyID", client_key_id)
        self.add_attribute("dataType", data_type)

        if wrapped_private_data is not None:
            self.add_attribute("wrappedPrivateData", wrapped_private_data)
        if trans_wrapped_session_key is not None:
            self.add_attribute("transWrappedSessionKey",
                               trans_wrapped_session_key)
        if algorithm_oid is not None:
            self.add_attribute("algorithmOID", algorithm_oid)
        if symkey_params is not None:
            self.add_attribute("symmetricAlgorithmParams", symkey_params)

        if pki_archive_options is not None:
            self.add_attribute("pkiArchiveOptions", pki_archive_options)

        if key_algorithm is not None:
            self.add_attribute("keyAlgorithm", key_algorithm)

        if key_size is not None:
            self.add_attribute("keySize", key_size)


class KeyRecoveryRequest(pki.ResourceMessage):
    """
    Class representing the data sent to the DRM when either creating a request
    for the recovery of a secret, or, once the request is approved, retrieving
    the secret.
    """

    def __init__(self, key_id=None, request_id=None,
                 trans_wrapped_session_key=None,
                 session_wrapped_passphrase=None,
                 nonce_data=None, certificate=None,
                 passphrase=None):
        """ Constructor """
        pki.ResourceMessage.__init__(
            self,
            "com.netscape.certsrv.key.KeyRecoveryRequest")
        self.add_attribute("requestId", request_id)
        self.add_attribute("transWrappedSessionKey", trans_wrapped_session_key)
        self.add_attribute("sessionWrappedPassphrase",
                           session_wrapped_passphrase)
        self.add_attribute("nonceData", nonce_data)
        self.add_attribute("certificate", certificate)
        self.add_attribute("passphrase", passphrase)
        self.add_attribute("keyId", key_id)


class SymKeyGenerationRequest(pki.ResourceMessage):
    """
    Class representing the data sent to the DRM when generating and archiving
    a symmetric key in the DRM.
    """

    UNWRAP_USAGE = "unwrap"
    WRAP_USAGE = "wrap"
    VERIFY_USAGE = "verify"
    SIGN_USAGE = "sign"
    DECRYPT_USAGE = "decrypt"
    ENCRYPT_USAGE = "encrypt"

    def __init__(self, client_key_id=None, key_size=None, key_algorithm=None,
                 key_usages=None, trans_wrapped_session_key=None):
        """ Constructor """
        pki.ResourceMessage.__init__(
            self,
            "com.netscape.certsrv.key.SymKeyGenerationRequest")
        key_usages = key_usages or []
        self.add_attribute("clientKeyID", client_key_id)
        self.add_attribute("keySize", key_size)
        self.add_attribute("keyAlgorithm", key_algorithm)
        self.add_attribute("keyUsage", ','.join(key_usages))
        self.add_attribute("transWrappedSessionKey", trans_wrapped_session_key)


class AsymKeyGenerationRequest(pki.ResourceMessage):

    """
    Class representing the data sent to the DRM when generating and archiving
    asymmetric keys in the DRM.
    """
    UNWRAP_USAGE = "unwrap"
    WRAP_USAGE = "wrap"
    VERIFY_USAGE = "verify"
    VERIFY_RECOVER_USAGE = "verify_recover"
    SIGN_USAGE = "sign"
    SIGN_RECOVER_USAGE = "sign_recover"
    DECRYPT_USAGE = "decrypt"
    ENCRYPT_USAGE = "encrypt"
    DERIVE_USAGE = "derive"

    def __init__(self, client_key_id=None, key_size=None, key_algorithm=None,
                 key_usages=None, trans_wrapped_session_key=None):
        """ Constructor """
        pki.ResourceMessage.__init__(
            self,
            "com.netscape.certsrv.key.AsymKeyGenerationRequest")
        key_usages = key_usages or []
        self.add_attribute("clientKeyID", client_key_id)
        self.add_attribute("keySize", key_size)
        self.add_attribute("keyAlgorithm", key_algorithm)
        self.add_attribute("keyUsage", ','.join(key_usages))
        self.add_attribute("transWrappedSessionKey", trans_wrapped_session_key)


class KeyClient(object):
    """
    Class that encapsulates and mirrors the functions in the KeyResource
    and KeyRequestResource Java classes in the DRM REST API.
    """

    SYMMETRIC_KEY_TYPE = "symmetricKey"
    PASS_PHRASE_TYPE = "passPhrase"
    ASYMMETRIC_KEY_TYPE = "asymmetricKey"

    KEY_STATUS_ACTIVE = "active"
    KEY_STATUS_INACTIVE = "inactive"

    DES_ALGORITHM = "DES"
    DESEDE_ALGORITHM = "DESede"
    DES3_ALGORITHM = "DES3"
    RC2_ALGORITHM = "RC2"
    RC4_ALGORITHM = "RC4"
    AES_ALGORITHM = "AES"

    # Asymmetric Key Algorithms
    RSA_ALGORITHM = "RSA"
    DSA_ALGORITHM = "DSA"

    # default session key wrapping algorithm
    DES_EDE3_CBC_OID = "{1 2 840 113549 3 7}"

    def __init__(self, connection, crypto, transport_cert_nick=None):
        """ Constructor """
        self.connection = connection
        self.headers = {'Content-type': 'application/json',
                        'Accept': 'application/json'}
        self.key_url = '/rest/agent/keys'
        self.key_requests_url = '/rest/agent/keyrequests'
        self.crypto = crypto

        if transport_cert_nick is not None:
            self.crypto.initialize()
            self.transport_cert = crypto.get_cert(transport_cert_nick)
        else:
            self.transport_cert = None

    def set_transport_cert(self, transport_cert_nick):
        """ Set the transport certificate for crypto operations """
        if transport_cert_nick is None:
            raise TypeError(
                "Transport certificate nickname must be specified.")
        self.transport_cert = self.crypto.get_cert(transport_cert_nick)

    @pki.handle_exceptions()
    def list_keys(self, client_key_id=None, status=None, max_results=None,
                  max_time=None, start=None, size=None):
        """ List/Search archived secrets in the DRM.

            See KRAClient.list_keys for the valid values of status.
            Returns a KeyInfoCollection object.
        """
        query_params = {'clientKeyID': client_key_id, 'status': status,
                        'maxResults': max_results, 'maxTime': max_time,
                        'start': start, 'size': size}
        response = self.connection.get(self.key_url, self.headers,
                                       params=query_params)
        return KeyInfoCollection.from_json(response.json())

    @pki.handle_exceptions()
    def list_requests(self, request_state=None, request_type=None,
                      client_key_id=None,
                      start=None, page_size=None, max_results=None,
                      max_time=None):
        """ List/Search key requests in the DRM.

            See KRAClient.list_requests for the valid values of request_state
            and request_type.  Returns a KeyRequestInfoCollection object.
        """
        query_params = {'requestState': request_state,
                        'requestType': request_type,
                        'clientKeyID': client_key_id, 'start': start,
                        'pageSize': page_size,
                        'maxResults': max_results, 'maxTime': max_time}
        response = self.connection.get(self.key_requests_url, self.headers,
                                       params=query_params)
        return KeyRequestInfoCollection.from_json(response.json())

    @pki.handle_exceptions()
    def get_request_info(self, request_id):
        """ Return a KeyRequestInfo object for a specific request. """
        if request_id is None:
            raise TypeError("Request ID must be specified")

        url = self.key_requests_url + '/' + request_id
        response = self.connection.get(url, self.headers)
        return KeyRequestInfo.from_json(response.json())

    @pki.handle_exceptions()
    def get_key_info(self, key_id):
        """ Get the info in the KeyRecord for a specific secret in the DRM. """
        if key_id is None:
            raise TypeError("Key ID must be specified")

        url = self.key_url + '/' + key_id
        response = self.connection.get(url, headers=self.headers)
        return KeyInfo.from_json(response.json())

    @pki.handle_exceptions()
    def get_active_key_info(self, client_key_id):
        """ Get the info in the KeyRecord for the active secret in the DRM. """
        if client_key_id is None:
            raise TypeError("Client Key ID must be specified")

        url = self.key_url + '/active/' + quote(client_key_id)
        response = self.connection.get(url, headers=self.headers)
        return KeyInfo.from_json(response.json())

    @pki.handle_exceptions()
    def modify_key_status(self, key_id, status):
        """ Modify the status of a key """
        if (key_id is None) or (status is None):
            raise TypeError("Key ID and status must be specified")

        url = self.key_url + '/' + key_id
        params = {'status': status}
        self.connection.post(url, None, headers=self.headers, params=params)

    @pki.handle_exceptions()
    def approve_request(self, request_id):
        """ Approve a secret recovery request """
        if request_id is None:
            raise TypeError("Request ID must be specified")

        url = self.key_requests_url + '/' + request_id + '/approve'
        self.connection.post(url, None, self.headers)

    @pki.handle_exceptions()
    def reject_request(self, request_id):
        """ Reject a secret recovery request. """
        if request_id is None:
            raise TypeError("Request ID must be specified")

        url = self.key_requests_url + '/' + request_id + '/reject'
        self.connection.post(url, None, self.headers)

    @pki.handle_exceptions()
    def cancel_request(self, request_id):
        """ Cancel a secret recovery request """
        if request_id is None:
            raise TypeError("Request ID must be specified")

        url = self.key_requests_url + '/' + request_id + '/cancel'
        self.connection.post(url, None, self.headers)

    @pki.handle_exceptions()
    def submit_request(self, request):
        """ Submit an archival, recovery or key generation request
            to the DRM.

            @param request - is either a KeyArchivalRequest,
            KeyRecoverRequest, SymKeyGenerationRequest or
            AsymKeyGenerationRequest.

            returns a KeyRequestResponse object.
        """
        if request is None:
            raise TypeError("Request must be specified")

        url = self.key_requests_url
        key_request = json.dumps(request, cls=encoder.CustomTypeEncoder,
                                 sort_keys=True)
        response = self.connection.post(url, key_request, self.headers)
        return KeyRequestResponse.from_json(response.json())

    @pki.handle_exceptions()
    def generate_symmetric_key(self, client_key_id, algorithm=None, size=None,
                               usages=None,
                               trans_wrapped_session_key=None):
        """ Generate and archive a symmetric key on the DRM.

            Return a KeyRequestResponse which contains a KeyRequestInfo
            object that describes the URL for the request and generated key.

        """
        if client_key_id is None:
            raise TypeError("Must specify Client Key ID")

        if trans_wrapped_session_key is not None:
            twsk = base64.encodestring(trans_wrapped_session_key)
            # noinspection PyUnusedLocal
            request = SymKeyGenerationRequest(
                client_key_id=client_key_id,
                key_size=size,
                key_algorithm=algorithm,
                key_usages=usages,
                trans_wrapped_session_key=twsk)
            raise NotImplementedError(
                "Returning the symmetric key in the same call is not yet "
                "implemented.")
        else:
            request = SymKeyGenerationRequest(
                client_key_id=client_key_id,
                key_size=size,
                key_algorithm=algorithm,
                key_usages=usages)
        return self.submit_request(request)

    @pki.handle_exceptions()
    def generate_asymmetric_key(self, client_key_id, algorithm=None,
                                key_size=None, usages=None,
                                trans_wrapped_session_key=None):
        """ Generate and archive asymmetric keys in the DRM.
            Supports algorithms RSA and DSA.
            Valid key size for RSA = 256 + (16 * n), where n: 0-496
            Valid key size for DSA = 512, 768, 1024. p,q,g params are not
            supported.

            Return a KeyRequestResponse which contains a KeyRequestInfo
            object that describes the URL for the request and generated keys.

        """
        if client_key_id is None:
            raise TypeError("Must specify Client Key ID")

        if str(algorithm).upper() not in \
                [self.RSA_ALGORITHM, self.DSA_ALGORITHM]:
            raise TypeError("Only RSA and DSA algorithms are supported.")

        # For generating keys using the RSA algorithm, the valid range of key
        # sizes is:
        #         256 + 16 * n, where 0 <= n <= 1008
        # When using DSA, the current supported values are 512, 768, 1024

        if algorithm == self.RSA_ALGORITHM:
            if key_size < 256:
                raise ValueError("Invalid key size specified.")
            if ((key_size - 256) % 16) != 0:
                raise ValueError("Invalid key size specified.")
        if algorithm == self.DSA_ALGORITHM:
            if key_size not in [512, 768, 1024]:
                raise ValueError("Invalid key size specified.")

        if trans_wrapped_session_key is not None:
            raise NotImplementedError(
                "Returning the asymmetric keys in the same call is not yet "
                "implemented.")

        request = AsymKeyGenerationRequest(
            client_key_id=client_key_id,
            key_size=key_size,
            key_algorithm=algorithm,
            key_usages=usages,
            trans_wrapped_session_key=trans_wrapped_session_key
        )

        return self.submit_request(request)

    @pki.handle_exceptions()
    def archive_key(self, client_key_id, data_type, private_data,
                    key_algorithm=None, key_size=None):
        """ Archive a secret (symmetric key or passphrase) on the DRM.

            Requires a user-supplied client ID.  There can be only one active
            key with a specified client ID.  If a record for a duplicate active
            key exists, a BadRequestException is thrown.

            data_type can be one of the following:
                KeyClient.SYMMETRIC_KEY_TYPE,
                KeyClient.ASYMMETRIC_KEY_TYPE,
                KeyClient.PASS_PHRASE_TYPE

            key_algorithm and key_size are applicable to symmetric keys only.
            If a symmetric key is being archived, these parameters are required.

            private_data is the raw secret to be archived.
            It will be wrapped and sent to the DRM.

            The function returns a KeyRequestResponse object containing a
            KeyRequestInfo object with details about the archival request and
            key archived.
        """
        if (client_key_id is None) or (data_type is None):
            raise TypeError("Client Key ID and data type must be specified")

        if data_type == KeyClient.SYMMETRIC_KEY_TYPE:
            if (key_algorithm is None) or (key_size is None):
                raise TypeError(
                    "For symmetric keys, key algorithm and key_size must "
                    "be specified")

        if private_data is None:
            raise TypeError("No data provided to be archived")

        nonce_iv = self.crypto.generate_nonce_iv()
        session_key = self.crypto.generate_session_key()

        wrapped_session_key = self.crypto.asymmetric_wrap(
            session_key,
            self.transport_cert)

        encrypted_data = self.crypto.symmetric_wrap(
            private_data,
            session_key,
            nonce_iv=nonce_iv)

        return self.archive_encrypted_data(
            client_key_id,
            data_type,
            encrypted_data,
            wrapped_session_key,
            algorithm_oid=None,
            nonce_iv=nonce_iv,
            key_algorithm=key_algorithm,
            key_size=key_size)

    @pki.handle_exceptions()
    def archive_encrypted_data(self,
                               client_key_id,
                               data_type,
                               encrypted_data,
                               wrapped_session_key,
                               algorithm_oid=None,
                               nonce_iv=None,
                               key_algorithm=None,
                               key_size=None):
        """
        Archive a secret (symmetric key or passphrase) on the DRM.

        Refer to archive_key() comments for a description of client_key_id,
        data_type, key_algorithm and key_size.

        The following parameters are also required:
            - encrypted_data - which is the data encrypted by a
              session key (168 bit 3DES symmetric key)
            - wrapped_session_key - the above session key wrapped by
              the DRM transport certificate public key.
            - the algorithm_oid string for the symmetric key wrap
            - the nonce_iv for the symmetric key wrap

        This function is useful if the caller wants to do their own wrapping
        of the secret, or if the secret was generated on a separate client
        machine and the wrapping was done there.

        The function returns a KeyRequestResponse object containing a
        KeyRequestInfo object with details about the archival request and
        key archived.
        """
        if (client_key_id is None) or (data_type is None):
            raise TypeError("Client Key ID and data type must be specified")

        if data_type == KeyClient.SYMMETRIC_KEY_TYPE:
            if (key_algorithm is None) or (key_size is None):
                raise TypeError(
                    "For symmetric keys, key algorithm and key size "
                    "must be specified")

        if not encrypted_data:
            raise TypeError('Missing encrypted data')

        if not wrapped_session_key:
            raise TypeError('Missing wrapped session key')

        if not algorithm_oid:
            algorithm_oid = KeyClient.DES_EDE3_CBC_OID

        if not nonce_iv:
            raise TypeError('Missing nonce IV')

        data = base64.encodestring(encrypted_data)
        twsk = base64.encodestring(wrapped_session_key)
        symkey_params = base64.encodestring(nonce_iv)

        request = KeyArchivalRequest(client_key_id=client_key_id,
                                     data_type=data_type,
                                     wrapped_private_data=data,
                                     trans_wrapped_session_key=twsk,
                                     algorithm_oid=algorithm_oid,
                                     symkey_params=symkey_params,
                                     key_algorithm=key_algorithm,
                                     key_size=key_size)

        return self.submit_request(request)

    @pki.handle_exceptions()
    def archive_pki_options(self, client_key_id, data_type, pki_archive_options,
                            key_algorithm=None, key_size=None):
        """ Archive a secret (symmetric key or passphrase) on the DRM.

            Refer to archive_key() comments for a description of client_key_id,
            data_type, key_algorithm and key_size.

            pki_archive_options is the data to be archived wrapped in a
            PKIArchiveOptions structure,

            The function returns a KeyRequestResponse object containing a
            KeyRequestInfo object with details about the archival request and
            key archived.
        """
        if (client_key_id is None) or (data_type is None):
            raise TypeError("Client Key_ID and Data Type must be specified")

        if data_type == KeyClient.SYMMETRIC_KEY_TYPE:
            if (key_algorithm is None) or (key_size is None):
                raise TypeError(
                    "For symmetric keys, key algorithm and key_size "
                    "must be specified")

        if pki_archive_options is None:
            raise TypeError("No data provided to be archived")

        data = base64.encodestring(pki_archive_options)
        request = KeyArchivalRequest(client_key_id=client_key_id,
                                     data_type=data_type,
                                     pki_archive_options=data,
                                     key_algorithm=key_algorithm,
                                     key_size=key_size)
        return self.submit_request(request)

    @pki.handle_exceptions()
    def recover_key(self, key_id, request_id=None,
                    session_wrapped_passphrase=None,
                    trans_wrapped_session_key=None, b64certificate=None,
                    nonce_data=None):
        """ Create a request to recover a secret.

            To retrieve a symmetric key or passphrase, the only parameter that
            is required is the keyId.  It is possible (but not required) to pass
            in the session keys/passphrase and nonceData for the retrieval at
            this time.  Those parameters are documented in the docstring for
            retrieve_key below.

            To retrieve an asymmetric key, the keyId and the the base-64 encoded
            certificate is required.
        """
        if key_id is None:
            raise TypeError("Key ID must be defined")

        request = KeyRecoveryRequest(
            key_id=key_id,
            request_id=request_id,
            trans_wrapped_session_key=trans_wrapped_session_key,
            session_wrapped_passphrase=session_wrapped_passphrase,
            certificate=b64certificate,
            nonce_data=nonce_data)
        return self.submit_request(request)

    @pki.handle_exceptions()
    def retrieve_key_data(self, data):
        """ Retrieve a secret from the DRM.

            @param: data - a KeyRecoveryRequest containing the keyId of the
            secret being retrieved, the request_id of the approved recovery
            request and a wrapping mechanism.  More details at
            KRAClient.retrieve_key.

            Returns a KeyData object containing the wrapped secret.
        """
        if data is None:
            raise TypeError("Key Recovery Request must be specified")

        url = self.key_url + '/retrieve'
        key_request = json.dumps(data, cls=encoder.CustomTypeEncoder,
                                 sort_keys=True)
        response = self.connection.post(url, key_request, self.headers)
        key_data = KeyData.from_json(response.json())
        return Key(key_data)

    @pki.handle_exceptions()
    def retrieve_key(self, key_id, trans_wrapped_session_key=None):
        """ Retrieve a secret (passphrase or symmetric key) from the DRM.

        This function generates a key recovery request, approves it, and
        retrieves the secret referred to by key_id.  This assumes that only one
        approval is required to authorize the recovery.

        To ensure data security in transit, the data will be returned encrypted
        by a session key (168 bit 3DES symmetric key) - which is first wrapped
        (encrypted) by the public key of the DRM transport certificate before
        being sent to the DRM.  The parameter trans_wrapped_session_key refers
        to this wrapped session key.

        There are two ways of using this function:

        1) trans_wrapped_session_key is not provided by caller.

        In this case, the function will call CryptoProvider methods to generate
        and wrap the session key.  The function will return the KeyData object
        with a private_data attribute which stores the unwrapped key
        information.

        2)  The trans_wrapped_session_key is provided by the caller.

        In this case, the function will simply pass the data to the DRM, and
        will return the secret wrapped in the session key.  The secret will
        still need to be unwrapped by the caller.

        The function will return the KeyData object, where the KeyData structure
        includes the wrapped secret and some nonce data to be used as a salt
        when unwrapping.
        """
        if key_id is None:
            raise TypeError("Key ID must be specified")

        key_provided = True
        session_key = None
        if trans_wrapped_session_key is None:
            key_provided = False
            session_key = self.crypto.generate_session_key()
            trans_wrapped_session_key = self.crypto.asymmetric_wrap(
                session_key,
                self.transport_cert)

        response = self.recover_key(key_id)
        request_id = response.get_request_id()
        self.approve_request(request_id)

        request = KeyRecoveryRequest(
            key_id=key_id,
            request_id=request_id,
            trans_wrapped_session_key=base64.encodestring(
                trans_wrapped_session_key))

        key = self.retrieve_key_data(request)
        if not key_provided:
            key.data = self.crypto.symmetric_unwrap(
                key.encrypted_data,
                session_key,
                nonce_iv=key.nonce_data)
        return key

    @pki.handle_exceptions()
    def retrieve_key_by_passphrase(self, key_id, passphrase=None,
                                   trans_wrapped_session_key=None,
                                   session_wrapped_passphrase=None,
                                   nonce_data=None):
        """
        Retrieve a secret (passphrase or symmetric key) from the DRM using
        a passphrase.

        This function generates a key recovery request, approves it, and
        retrieves the secret referred to by key_id.  This assumes that only one
        approval is required to authorize the recovery.

        The secret is secured in transit by wrapping the secret with a
        passphrase using PBE encryption.

        There are two ways of using this function:

        1) A passphrase is provided by the caller.

           In this case, CryptoProvider methods will be called to create the data
           to securely send the passphrase to the DRM.  Basically, three pieces of
           data will be sent:

           - the passphrase wrapped by a 168 bit 3DES symmetric key (the session
             key).  This is referred to as the parameter session_wrapped_passphrase.

           - the session key wrapped with the public key in the DRM transport
             certificate.  This is referred to as the trans_wrapped_session_key.

           - ivps nonce data, referred to as nonce_data

           The function will return the tuple (KeyData, unwrapped_secret)

        2) The caller provides the trans_wrapped_session_key,
           session_wrapped_passphrase and nonce_data.

           In this case, the data will simply be passed to the DRM.  The function
           will return the secret encrypted by the passphrase using PBE Encryption.
           The secret will still need to be decrypted by the caller.

           The function will return the tuple (KeyData, None)
        """
        pass

    @pki.handle_exceptions()
    def retrieve_key_by_pkcs12(self, key_id, certificate, passphrase):
        """ Retrieve an asymmetric private key and return it as PKCS12 data.

        This function generates a key recovery request, approves it, and
        retrieves the secret referred to by key_id in a PKCS12 file.  This
        assumes that only one approval is required to authorize the recovery.

        This function requires the following parameters:
        - key_id : the ID of the key
        - certificate: the certificate associated with the private key
        - passphrase: A passphrase for the pkcs12 file.

        The function returns a KeyData object.
        """
        if (key_id is None) or (certificate is None) or (passphrase is None):
            raise TypeError(
                "Key ID, certificate and passphrase must all be specified")

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
encoder.NOTYPES['AsymKeyGenerationRequest'] = AsymKeyGenerationRequest


def main():
    """ Some unit tests - basically printing different types of requests """
    print("printing symkey generation request")
    client_key_id = "vek 123"
    usages = [SymKeyGenerationRequest.DECRYPT_USAGE,
              SymKeyGenerationRequest.ENCRYPT_USAGE]
    gen_request = SymKeyGenerationRequest(client_key_id, 128, "AES", usages)
    print(json.dumps(gen_request, cls=encoder.CustomTypeEncoder, sort_keys=True))

    print("printing key recovery request")
    key_request = KeyRecoveryRequest("25", "MX12345BBBAAA", None,
                                     "1234ABC", None, None)
    print(json.dumps(key_request, cls=encoder.CustomTypeEncoder, sort_keys=True))

    print("printing key archival request")
    archival_request = KeyArchivalRequest(client_key_id, "symmetricKey",
                                          "MX123AABBCD", "AES", 128)
    print(json.dumps(archival_request, cls=encoder.CustomTypeEncoder,
                     sort_keys=True))


if __name__ == '__main__':
    main()
