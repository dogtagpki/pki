#!/usr/bin/python

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
# Copyright (C) 2014 Red Hat, Inc.
# All rights reserved.
#
# Authors:
#     Abhishek Koneru <akoneru@redhat.com>
#     Ade Lee <alee@redhat.com>

from __future__ import absolute_import
from __future__ import print_function
import copy
import json

from six import iteritems

import pki
import pki.client as client
import pki.encoder as encoder
import pki.profile as profile


class CertData(object):
    """
    Class containing certificate data as returned from getCert()
    """

    json_attribute_names = {
        'id': 'serial_number', 'IssuerDN': 'issuer_dn',
        'SubjectDN': 'subject_dn', 'PrettyPrint': 'pretty_repr',
        'Encoded': 'encoded', 'NotBefore': 'not_before',
        'NotAfter': 'not_after', 'Status': 'status', 'Nonce': 'nonce',
        'Link': 'link', 'PKCS7CertChain': 'pkcs7_cert_chain'
    }

    def __init__(self):
        """Constructor"""

        self.serial_number = None
        self.issuer_dn = None
        self.subject_dn = None
        self.pretty_repr = None
        self.encoded = None
        self.binary = None
        self.pkcs7_cert_chain = None
        self.not_before = None
        self.not_after = None
        self.status = None
        self.nonce = None
        self.link = None

    def __repr__(self):
        attributes = {
            "CertData": {
                "serial_number": self.serial_number,
                "subject_dn": self.subject_dn,
                "status": self.status
            }
        }
        return str(attributes)

    @classmethod
    def from_json(cls, attr_list):
        """ Return CertData object from JSON dict """
        cert_data = cls()

        for k, v in iteritems(attr_list):
            if k not in ['Link']:
                if k in CertData.json_attribute_names:
                    setattr(cert_data, CertData.json_attribute_names[k], v)
                else:
                    setattr(cert_data, k, v)

        if 'Link' in attr_list:
            cert_data.link = pki.Link.from_json(attr_list['Link'])

        return cert_data


class CertDataInfo(object):
    """
    Class containing information contained in a CertRecord on the CA.
    This data is returned when searching/listing certificate records.
    """

    json_attribute_names = {
        'id': 'serial_number', 'SubjectDN': 'subject_dn', 'Status': 'status',
        'Type': 'type', 'Version': 'version', 'KeyLength': 'key_length',
        'KeyAlgorithmOID': 'key_algorithm_oid', 'Link': 'link',
        'NotValidBefore': 'not_valid_before',
        'NotValidAfter': 'not_valid_after', 'IssuedOn': 'issued_on',
        'IssuedBy': 'issued_by'}

    def __init__(self):
        """ Constructor """
        self.serial_number = None
        self.subject_dn = None
        self.status = None
        self.type = None
        self.version = None
        self.key_algorithm_oid = None
        self.key_length = None
        self.not_valid_before = None
        self.not_valid_after = None
        self.issued_on = None
        self.issued_by = None
        self.link = None

    def __repr__(self):
        obj = {
            "CertDataInfo": {
                'serial_number': self.serial_number,
                'subject_dn': self.subject_dn,
                'type': self.type,
                'status': self.status
            }}
        return str(obj)

    @classmethod
    def from_json(cls, attr_list):
        """ Return CertDataInfo object from JSON dict """
        cert_data_info = cls()
        for k, v in iteritems(attr_list):
            if k not in ['Link']:
                if k in CertDataInfo.json_attribute_names:
                    setattr(cert_data_info,
                            CertDataInfo.json_attribute_names[k], v)
                else:
                    setattr(cert_data_info, k, v)

        if 'Link' in attr_list:
            cert_data_info.link = pki.Link.from_json(attr_list['Link'])

        return cert_data_info


class CertDataInfoCollection(object):
    """
    Class containing list of CertDataInfo objects and their respective link
    objects.
    This data is returned when searching/listing certificate records in the CA.
    """

    def __init__(self):
        """ Constructor """
        self.cert_data_info_list = []
        self.links = []

    def __iter__(self):
        return iter(self.cert_data_info_list)

    @classmethod
    def from_json(cls, json_value):
        """ Populate object from JSON input """
        ret = cls()
        cert_infos = json_value['entries']
        if not isinstance(cert_infos, list):
            ret.cert_data_info_list.append(CertDataInfo.from_json(cert_infos))
        else:
            for cert_info in cert_infos:
                ret.cert_data_info_list.append(
                    CertDataInfo.from_json(cert_info))

        links = json_value['Link']
        if not isinstance(links, list):
            ret.links.append(pki.Link.from_json(links))
        else:
            for link in links:
                ret.links.append(pki.Link.from_json(link))

        return ret


class CertRequestInfo(object):
    """
       An object of this class stores represents a
       certificate request.
    """
    json_attribute_names = {
        'requestType': 'request_type', 'requestURL': 'request_url',
        'requestStatus': 'request_status', 'certId': 'cert_id',
        'operationResult': 'operation_result', 'certURL': 'cert_url',
        'errorMessage': 'error_message', 'certRequestType': 'cert_request_type'
    }

    def __init__(self):
        """ Constructor """
        self.request_id = None
        self.request_type = None
        self.request_url = None
        self.request_status = None
        self.operation_result = None
        self.cert_id = None
        self.cert_request_type = None
        self.cert_url = None
        self.error_message = None

    def __repr__(self):
        obj = {
            'CertRequestInfo': {
                'request_id': self.request_id,
                'request_type': self.request_type,
                'request_status': self.request_status,
                'request_url': self.request_url
            }
        }
        return str(obj)

    @classmethod
    def from_json(cls, attr_list):
        cert_request_info = cls()

        for k, v in iteritems(attr_list):
            if k not in ['Link']:
                if k in CertRequestInfo.json_attribute_names:
                    setattr(cert_request_info,
                            CertRequestInfo.json_attribute_names[k], v)
                else:
                    setattr(cert_request_info, k, v)

        cert_request_info.request_id = \
            str(cert_request_info.request_url)[(str(
                cert_request_info.request_url).rfind("/") + 1):]

        return cert_request_info


class CertRequestStatus(object):
    """
    Class containing valid cert statuses.
    """

    PENDING = "pending"
    CANCELED = "canceled"
    REJECTED = "rejected"
    COMPLETE = "complete"


class CertEnrollmentResult(object):
    """
    Class containing results of an enrollment request.

    This structure contains information about the cert request generated
    and any certificates issued.
    """

    def __init__(self, request, cert):
        """  Initializer.
        :param: request: CertRequestInfo object for request generated.
        :param: cert: CertData object for certificate generated (if any)
        """
        self.request = request
        self.cert = cert


class CertRequestInfoCollection(object):
    """
    Class containing list of CertRequestInfo objects.
    This data is returned when listing certificate request records in the CA.
    """

    def __init__(self):
        self.cert_request_info_list = []
        self.links = []

    def __iter__(self):
        return iter(self.cert_request_info_list)

    @classmethod
    def from_json(cls, json_value):
        """ Populate object from JSON input """
        ret = cls()
        cert_req_infos = json_value['entries']
        if not isinstance(cert_req_infos, list):
            ret.cert_request_info_list.append(
                CertRequestInfo.from_json(cert_req_infos))
        else:
            for cert_info in cert_req_infos:
                ret.cert_request_info_list.append(
                    CertRequestInfo.from_json(cert_info))

        links = json_value['Link']
        if not isinstance(links, list):
            ret.links.append(pki.Link.from_json(links))
        else:
            for link in links:
                ret.links.append(pki.Link.from_json(link))

        return ret


class CertSearchRequest(object):
    """
        An object of this class is used to store the search parameters
        and send them to server.
    """

    search_params = {'serial_to': 'serialTo', 'serial_from': 'serialFrom',
                     'email': 'eMail', 'common_name': 'commonName',
                     'user_id': 'userID', 'org_unit': 'orgUnit', 'org': 'org',
                     'locality': 'locality', 'state': 'state',
                     'country': 'country', 'match_exactly': 'matchExactly',
                     'status': 'status', 'revoked_by': 'revokedBy',
                     'revoked_on_from': 'revokedOnFrom',
                     'revoked_on_to': 'revokedOnTo',
                     'revocation_reason': 'revocationReason',
                     'issued_by': 'issuedBy', 'issued_on_from': 'issuedOnFrom',
                     'issued_on_to': 'issuedOnTo',
                     'valid_not_before_from': 'validNotBeforeFrom',
                     'valid_not_before_to': 'validNotBeforeTo',
                     'valid_not_after_from': 'validNotAfterFrom',
                     'valid_not_after_to': 'validNotAfterTo',
                     'validity_operation': 'validityOperation',
                     'validity_count': 'validityCount',
                     'validity_unit': 'validityUnit',
                     'cert_type_sub_email_ca': 'certTypeSubEmailCA',
                     'cert_type_sub_ssl_ca': 'certTypeSubSSLCA',
                     'cert_type_secure_email': 'certTypeSecureEmail',
                     'cert_type_ssl_client': 'certTypeSSLClient',
                     'cert_type_ssl_server': 'certTypeSSLServer'}

    def __init__(self, **cert_search_params):
        """ Constructor """

        if len(cert_search_params) == 0:
            setattr(self, 'serialNumberRangeInUse', True)

        for param, value in iteritems(cert_search_params):
            if param not in CertSearchRequest.search_params:
                raise ValueError('Invalid search parameter: ' + param)

            if param in {'serial_to', 'serial_from'}:
                setattr(self, CertSearchRequest.search_params[param], value)
                setattr(self, 'serialNumberRangeInUse', True)

            if param in {
                'email', 'common_name', 'user_id', 'org_unit', 'org',
                'locality', 'state', 'country', 'match_exactly'
            }:
                setattr(self, CertSearchRequest.search_params[param], value)
                setattr(self, 'subjectInUse', True)

            if param == 'status':
                setattr(self, CertSearchRequest.search_params[param], value)

            if param == 'revoked_by':
                setattr(self, CertSearchRequest.search_params[param], value)
                setattr(self, 'revokedByInUse', True)

            if param in {'revoked_on_from', 'revoked_on_to'}:
                setattr(self, CertSearchRequest.search_params[param], value)
                setattr(self, 'revokedOnInUse', True)

            if param == 'revocation_reason':
                setattr(self, CertSearchRequest.search_params[param], value)
                setattr(self, 'revocationReasonInUse', True)

            if param == 'issued_by':
                setattr(self, CertSearchRequest.search_params[param], value)
                setattr(self, 'issuedByInUse', True)

            if param in {'issued_on_from', 'issued_on_to'}:
                setattr(self, CertSearchRequest.search_params[param], value)
                setattr(self, 'issuedOnInUse', True)

            if param in {'valid_not_before_from', 'valid_not_before_to'}:
                setattr(self, CertSearchRequest.search_params[param], value)
                setattr(self, 'validNotBeforeInUse', True)

            if param in {'valid_not_after_from', 'valid_not_after_to'}:
                setattr(self, CertSearchRequest.search_params[param], value)
                setattr(self, 'validNotAfterInUse', True)

            if param in {
                'validity_operation', 'validity_count', 'validity_unit'
            }:
                setattr(self, CertSearchRequest.search_params[param], value)
                setattr(self, 'validityLengthInUse', True)

            if param in {
                'cert_type_sub_email_ca', 'cert_type_sub_ssl_ca',
                'cert_type_secure_email', 'cert_type_ssl_client',
                'cert_type_ssl_server'
            }:
                setattr(self, CertSearchRequest.search_params[param], value)
                setattr(self, 'certTypeInUse', True)


class CertRevokeRequest(object):
    """
        An object of this class encapsulates all the
        parameters required for revoking a certificate.

        Valid values for reasons for revoking a request are:
            'Unspecified', 'Key_Compromise', 'CA_Compromise',
            'Affiliation_Changed', 'Superseded', 'Cessation_of_Operation',
            'Certificate_Hold', 'Remove_from_CRL', 'Privilege_Withdrawn',
            'AA_Compromise'
    """
    reasons = ['Unspecified', 'Key_Compromise', 'CA_Compromise',
               'Affiliation_Changed', 'Superseded', 'Cessation_of_Operation',
               'Certificate_Hold', 'Remove_from_CRL', 'Privilege_Withdrawn',
               'AA_Compromise']

    def __init__(self, nonce, reason=None, invalidity_date=None,
                 comments=None):
        """ Constructor """

        setattr(self, "Nonce", nonce)

        if reason is None:
            reason = 'Unspecified'
        else:
            if reason not in CertRevokeRequest.reasons:
                raise ValueError('Invalid revocation reason specified.')
        setattr(self, "Reason", reason)
        if invalidity_date is not None:
            setattr(self, "InvalidityDate", invalidity_date)
        if comments is not None:
            setattr(self, "Comments", comments)


class CertEnrollmentRequest(object):
    """
    This class encapsulates the parameters required for a certificate
     enrollment request.
    """

    json_attribute_names = {
        'ProfileID': 'profile_id', 'Renewal': 'renewal',
        'SerialNumber': 'serial_number', 'RemoteHost': 'remote_host',
        'RemoteAddress': 'remote_address', 'Input': 'inputs',
        'Output': 'outputs'
    }

    def __init__(self, profile_id=None, renewal=False, serial_number=None,
                 remote_host=None, remote_address=None, inputs=None,
                 outputs=None):
        """ Constructor """
        self.profile_id = profile_id
        self.renewal = renewal
        self.serial_number = serial_number
        self.remote_host = remote_host
        self.remote_address = remote_address
        if inputs is None:
            self.inputs = []
        else:
            self.inputs = inputs
        if outputs is None:
            self.outputs = []
        else:
            self.outputs = outputs

    def add_input(self, profile_input):
        self.inputs.append(profile_input)

    def remove_input(self, profile_input_name):
        for profile_input in self.inputs:
            if profile_input_name == profile_input.name:
                self.inputs.pop(profile_input)
                break

    def get_input(self, profile_input_name):
        for profile_input in self.inputs:
            if profile_input_name == profile_input.name:
                return profile_input

        return None

    def add_output(self, profile_output):
        self.outputs.append(profile_output)

    def remove_output(self, profile_output_name):
        for output in self.outputs:
            if profile_output_name == output.name:
                self.outputs.pop(output)
                break

    def get_output(self, profile_output_name):
        for output in self.outputs:
            if profile_output_name == output.name:
                return output

        return None

    @classmethod
    def from_json(cls, attr_list):

        enroll_request = cls()

        for k, v in iteritems(attr_list):
            if k not in ['Input', 'Output']:
                if k in CertEnrollmentRequest.json_attribute_names:
                    setattr(enroll_request,
                            CertEnrollmentRequest.json_attribute_names[k], v)
                else:
                    setattr(enroll_request, k, v)

        inputs = attr_list['Input']
        if not isinstance(inputs, list):
            enroll_request.inputs.append(
                profile.ProfileInput.from_json(inputs))
        else:
            for profile_input in inputs:
                enroll_request.inputs.append(
                    profile.ProfileInput.from_json(profile_input))

        outputs = attr_list['Output']
        if not isinstance(outputs, list):
            enroll_request.outputs.append(
                profile.ProfileOutput.from_json(outputs))
        else:
            for profile_output in outputs:
                enroll_request.outputs.append(
                    profile.ProfileOutput.from_json(profile_output))

        return enroll_request


class CertReviewResponse(CertEnrollmentRequest):
    """
    An object of this class represent the response from the server when
    reviewing a certificate enrollment request.
    It contains a nonce required to perform action on the request.
    """
    json_attribute_names = CertEnrollmentRequest.json_attribute_names.copy()
    json_attribute_names.update({
        'requestId': 'request_id', 'requestType': 'request_type',
        'requestStatus': 'request_status', 'requestOwner': 'request_owner',
        'requestCreationTime': 'request_creation_time',
        'requestNotes': 'request_notes',
        'requestModificationTime': 'request_modification_time',
        'profileApprovedBy': 'profile_approved_by',
        'profileSetId': 'profile_set_id', 'profileName': 'profile_name',
        'profileIsVisible': 'profile_is_visible',
        'profileDescription': 'profile_description',
        'profileRemoteHost': 'profile_remote_host',
        'profileRemoteAddr': 'profile_remote_address',
        'ProfilePolicySet': 'policy_sets'
    })

    def __init__(self, profile_id=None, renewal=False, serial_number=None,
                 remote_host=None, remote_address=None, inputs=None,
                 outputs=None, nonce=None, request_id=None, request_type=None,
                 request_status=None, request_owner=None,
                 request_creation_time=None, request_modification_time=None,
                 request_notes=None, profile_approval_by=None,
                 profile_set_id=None, profile_is_visible=None,
                 profile_name=None, profile_description=None,
                 profile_remote_host=None, profile_remote_address=None,
                 policy_sets=None):

        super(CertReviewResponse, self).__init__(profile_id, renewal,
                                                 serial_number, remote_host,
                                                 remote_address, inputs,
                                                 outputs)
        self.nonce = nonce
        self.request_id = request_id
        self.request_type = request_type
        self.request_status = request_status
        self.request_owner = request_owner
        self.request_creation_time = request_creation_time
        self.request_modification_time = request_modification_time
        self.request_notes = request_notes
        self.profile_approved_by = profile_approval_by
        self.profile_set_id = profile_set_id
        self.profile_is_visible = profile_is_visible
        self.profile_name = profile_name
        self.profile_description = profile_description
        self.profile_remote_host = profile_remote_host
        self.profile_remote_address = profile_remote_address

        if policy_sets is None:
            self.policy_sets = []
        else:
            self.policy_sets = policy_sets

    @classmethod
    def from_json(cls, attr_list):

        # First read the values for attributes defined in CertEnrollmentRequest
        review_response = super(CertReviewResponse, cls).from_json(attr_list)

        for k, v in iteritems(attr_list):
            if k not in ['ProfilePolicySet'] and k not in \
                    CertEnrollmentRequest.json_attribute_names:
                if k in CertReviewResponse.json_attribute_names:
                    setattr(review_response,
                            CertReviewResponse.json_attribute_names[k], v)
                else:
                    setattr(review_response, k, v)

        profile_policy_sets = attr_list['ProfilePolicySet']
        if not isinstance(profile_policy_sets, list):
            review_response.policy_sets.append(
                profile.ProfilePolicySet.from_json(profile_policy_sets))
        else:
            for policy_set in profile_policy_sets:
                review_response.policy_sets.append(
                    profile.ProfilePolicySet.from_json(policy_set))

        return review_response


class CertClient(object):
    """
    Class encapsulating and mirroring the functionality in the CertResource
    Java interface class defining the REST API for Certificate resources.
    """

    def __init__(self, connection):
        """ Constructor """
        self.connection = connection
        self.headers = {'Content-type': 'application/json',
                        'Accept': 'application/json'}
        self.cert_url = '/rest/certs'
        self.agent_cert_url = '/rest/agent/certs'
        self.cert_requests_url = '/rest/certrequests'
        self.agent_cert_requests_url = '/rest/agent/certrequests'
        self.enrollment_templates = {}

    @pki.handle_exceptions()
    def get_cert(self, cert_serial_number):
        """ Return a CertData object for a particular certificate. """
        if cert_serial_number is None:
            raise ValueError("Certificate ID must be specified")

        url = self.cert_url + '/' + str(cert_serial_number)
        r = self.connection.get(url, self.headers)
        # print r.json()
        return CertData.from_json(r.json())

    @pki.handle_exceptions()
    def list_certs(self, max_results=None, max_time=None, start=None, size=None,
                   **cert_search_params):
        """ Return a CertDataInfoCollection object with a information about all
            the certificates that satisfy the search criteria.
            If cert_search_request=None, returns all the certificates.
        """
        url = self.cert_url + '/search'
        query_params = {"maxResults": max_results, "maxTime": max_time,
                        "start": start, "size": size}
        cert_search_request = CertSearchRequest(**cert_search_params)
        search_request = json.dumps(cert_search_request,
                                    cls=encoder.CustomTypeEncoder,
                                    sort_keys=True)
        response = self.connection.post(url, search_request, self.headers,
                                        query_params)
        return CertDataInfoCollection.from_json(response.json())

    @pki.handle_exceptions()
    def review_cert(self, cert_serial_number):
        """ Reviews a certificate. Returns a CertData object with a nonce.
            This method requires an agent's authentication cert in the
            connection object.
        """
        if cert_serial_number is None:
            raise ValueError("Certificate ID must be specified")

        url = self.agent_cert_url + '/' + str(cert_serial_number)
        r = self.connection.get(url, self.headers)
        return CertData.from_json(r.json())

    def _submit_revoke_request(self, url, cert_serial_number,
                               revocation_reason=None, invalidity_date=None,
                               comments=None, nonce=None, authority=None):
        """
        Submits a certificate revocation request.
        Expects the URL for submitting the request.
        Creates a CertRevokeRequest object using the arguments provided.
        If nonce is passed as an argument, reviews the cert to get a nonce
        from the server and passes it in the request.
        Returns a CertRequestInfo object.
        """
        if cert_serial_number is None:
            raise ValueError("Certificate ID must be specified")

        if url is None:
            raise ValueError("URL not specified")

        if nonce is None:
            cert_data = self.review_cert(cert_serial_number)
            nonce = cert_data.nonce
        request = CertRevokeRequest(nonce, revocation_reason, invalidity_date,
                                    comments)
        revoke_request = json.dumps(request, cls=encoder.CustomTypeEncoder,
                                    sort_keys=True)
        params = {}
        if authority:
            params['authority'] = authority

        r = self.connection.post(
            url,
            revoke_request,
            headers=self.headers,
            params=params)

        return CertRequestInfo.from_json(r.json())

    @pki.handle_exceptions()
    def revoke_cert(self, cert_serial_number, revocation_reason=None,
                    invalidity_date=None, comments=None, nonce=None,
                    authority=None):
        """ Revokes a certificate.
            Returns a CertRequestInfo object with information about the request.
            This method requires an agent's authentication cert in the
            connection object.
        """
        url = self.agent_cert_url + '/' + str(cert_serial_number) + '/revoke'
        return self._submit_revoke_request(url, cert_serial_number,
                                           revocation_reason, invalidity_date,
                                           comments, nonce, authority)

    @pki.handle_exceptions()
    def revoke_ca_cert(self, cert_serial_number, revocation_reason=None,
                       invalidity_date=None, comments=None, nonce=None,
                       authority=None):
        """ Revokes a CA certificate.
            Returns a CertRequestInfo object with information about the request.
            This method requires an agent's authentication cert in the
            connection object.
        """
        url = self.agent_cert_url + '/' + str(cert_serial_number) + \
            '/revoke-ca'
        return self._submit_revoke_request(url, cert_serial_number,
                                           revocation_reason, invalidity_date,
                                           comments, nonce, authority)

    @pki.handle_exceptions()
    def hold_cert(self, cert_serial_number, comments=None, authority=None):
        """ Places a certificate on-hold.
            Calls the revoke_cert method with reason -
            CertRevokeRequest.REASON_CERTIFICATE_HOLD.
            Returns a CertRequestInfo object.
            This method requires an agent's authentication cert in the
            connection object.
        """
        return self.revoke_cert(cert_serial_number, 'Certificate_Hold',
                                comments=comments, authority=authority)

    @pki.handle_exceptions()
    def unrevoke_cert(self, cert_serial_number, authority=None):
        """ Un-revokes a revoked certificate.
            Returns a CertRequestInfo object.
            This method requires an agent's authentication cert in the
            connection object.
        """
        if cert_serial_number is None:
            raise ValueError("Certificate ID must be specified")

        url = self.agent_cert_url + '/' + str(cert_serial_number) + '/unrevoke'

        params = {}
        if authority is not None:
            params['authority'] = authority

        r = self.connection.post(
            url,
            None,
            headers=self.headers,
            params=params)

        return CertRequestInfo.from_json(r.json())

    @pki.handle_exceptions()
    def get_request(self, request_id):
        """
        Get information of a certificate request with the given request ID.
        Returns a CertRequestInfo object.
        """

        if request_id is None:
            raise ValueError("Request ID must be specified")
        url = self.cert_requests_url + '/' + str(request_id)
        r = self.connection.get(url, headers=self.headers)

        return CertRequestInfo.from_json(r.json())

    @pki.handle_exceptions()
    def list_requests(self, request_status=None, request_type=None,
                      from_request_id=None, size=None, max_results=None,
                      max_time=None):
        """
        Query for a list of certificates using the arguments passed.
        Returns a CertRequestInfoCollection object.
        """

        query_params = {
            'requestStatus': request_status,
            'requestType': request_type,
            'start': from_request_id,
            'pageSize': size,
            'maxResults': max_results,
            'maxTime': max_time
        }
        r = self.connection.get(self.agent_cert_requests_url, self.headers,
                                query_params)
        return CertRequestInfoCollection.from_json(r.json())

    @pki.handle_exceptions()
    def review_request(self, request_id):
        """
        Reviews a certificate enrollment request.
        Returns a CertReviewResponse object which contains the nonce
        from the server needed to perform an action on the request.
        """
        if request_id is None:
            raise ValueError("Request Id must be specified.")

        url = self.agent_cert_requests_url + '/' + str(request_id)
        r = self.connection.get(url, headers=self.headers)
        return CertReviewResponse.from_json(r.json())

    @pki.handle_exceptions()
    def _perform_action(self, request_id, cert_review_response, action):
        """
        An internal method used by all the action methods to perform
        an action on a certificate request.
        The parameter cert_review_response
        """
        if request_id is None:
            raise ValueError("Request Id must be specified.")
        if cert_review_response is None:
            cert_review_response = self.review_request(request_id)

        url = self.agent_cert_requests_url + '/' + request_id + '/' + action
        review_response = json.dumps(cert_review_response,
                                     cls=encoder.CustomTypeEncoder,
                                     sort_keys=True)
        # print review_response
        r = self.connection.post(url, review_response, headers=self.headers)
        return r

    def approve_request(self, request_id, cert_review_response=None):
        """
        Approves a certificate enrollment request.
        If cert_review_response is None, a review request operation is performed
        to fetch the CertReviewResponse object.
        Requires as agent level authentication.
        """
        return self._perform_action(
            request_id, cert_review_response, 'approve')

    def cancel_request(self, request_id, cert_review_response=None):
        """
        Cancels a certificate enrollment request.
        If cert_review_response is None, a review request operation is performed
        to fetch the CertReviewResponse object.
        Requires as agent level authentication.
        """
        return self._perform_action(request_id, cert_review_response, 'cancel')

    def reject_request(self, request_id, cert_review_response=None):
        """
        Rejects a certificate enrollment request.
        If cert_review_response is None, a review request operation is performed
        to fetch the CertReviewResponse object.
        Requires as agent level authentication.
        """
        return self._perform_action(request_id, cert_review_response, 'reject')

    def validate_request(self, request_id, cert_review_response):
        """
        Validates a certificate enrollment request.
        If cert_review_response is None, a review request operation is performed
        to fetch the CertReviewResponse object.
        Requires as agent level authentication.
        """
        return self._perform_action(request_id, cert_review_response,
                                    'validate')

    def update_request(self, request_id, cert_review_response):
        """
        Updates a certificate enrollment request.
        If cert_review_response is None, a review request operation is performed
        to fetch the CertReviewResponse object.
        Requires as agent level authentication.
        """
        return self._perform_action(request_id, cert_review_response, 'update')

    def assign_request(self, request_id, cert_review_response):
        """
        Assigns a certificate enrollment request.
        If cert_review_response is None, a review request operation is performed
        to fetch the CertReviewResponse object.
        Requires as agent level authentication.
        """
        return self._perform_action(request_id, cert_review_response, 'assign')

    def unassign_request(self, request_id, cert_review_response):
        """
        Un-assigns a certificate enrollment request.
        If cert_review_response is None, a review request operation is performed
        to fetch the CertReviewResponse object.
        Requires as agent level authentication.
        """
        return self._perform_action(request_id, cert_review_response,
                                    'unassign')

    @pki.handle_exceptions()
    def list_enrollment_templates(self, start=None, size=None):
        """
        Gets the list of profile templates supported by the CA.
        The values for start and size arguments determine the starting point and
        the length of the list.
        Returns a ProfileDataInfoCollection object.
        """

        url = self.cert_requests_url + '/profiles'
        query_params = {
            'start': start,
            'size': size
        }
        r = self.connection.get(url, self.headers, query_params)
        return profile.ProfileDataInfoCollection.from_json(r.json())

    @pki.handle_exceptions()
    def get_enrollment_template(self, profile_id):
        """
        Fetch the enrollment template for the given profile id.
        For the first time, the request is sent to the server.
        The retrieved CertEnrollmentRequest object is then cached locally for
        future requests.
        Returns a CerEnrollmentRequest object.
        """

        if profile_id is None:
            raise ValueError("Profile ID must be specified.")
        if profile_id in self.enrollment_templates:
            return copy.deepcopy(self.enrollment_templates[profile_id])
        url = self.cert_requests_url + '/profiles/' + str(profile_id)
        r = self.connection.get(url, self.headers)
        # print r.json()
        # Caching the enrollment template object in-memory for future use.
        enrollment_template = CertEnrollmentRequest.from_json(r.json())
        self.enrollment_templates[profile_id] = enrollment_template

        return copy.deepcopy(enrollment_template)

    @pki.handle_exceptions()
    def create_enrollment_request(self, profile_id, inputs):
        """
        Fetches the enrollment request object for the given profile and
        sets values to its attributes using the values provided in the inputs
        dictionary.
        Returns the CertEnrollmentRequest object, which can be submitted to
        enroll a certificate.
        """
        if inputs is None or len(inputs) == 0:
            raise ValueError("No inputs provided.")

        enrollment_template = self.get_enrollment_template(profile_id)
        for profile_input in enrollment_template.inputs:
            for attribute in profile_input.attributes:
                if attribute.name in inputs:
                    attribute.value = inputs[attribute.name]

        return enrollment_template

    @pki.handle_exceptions()
    def submit_enrollment_request(self, enrollment_request, authority=None):
        """
        Submits the CertEnrollmentRequest object to the server.
        Returns a CertRequestInfoCollection object with information about the
        certificate requests enrolled at the CA.
        """
        request_object = json.dumps(enrollment_request,
                                    cls=encoder.CustomTypeEncoder,
                                    sort_keys=True)

        params = {}
        if authority is not None:
            params['authority'] = authority

        # print request_object
        r = self.connection.post(self.cert_requests_url, request_object,
                                 self.headers, params)
        return CertRequestInfoCollection.from_json(r.json())

    @pki.handle_exceptions()
    def enroll_cert(self, profile_id, inputs, authority=None):
        """
        A convenience method for enrolling a certificate for a given profile id.
        The inputs parameter should be a dictionary with values for the profile
        attributes for an enrollment request.

        Calling this method with valid arguments, creates an enrollment request,
        submits it to the server, approves the certificate requests generated
        for the enrollment and returns a list of CertData objects for all the
        certificates generated as part of this enrollment.

        Note: This method supports only certificate enrollment where only one
        agent approval is sufficient.

        Requires an agent level authentication.
        Returns a list of CertEnrollmentResult objects.
        """

        # Create a CertEnrollmentRequest object using the inputs for the given
        #  profile id.
        enroll_request = self.create_enrollment_request(profile_id, inputs)

        # Submit the enrollment request
        cert_request_infos = self.submit_enrollment_request(
            enroll_request, authority)

        # Approve the requests generated for the certificate enrollment.
        # Fetch the CertData objects for all the certificates created and
        # return to the caller.

        ret = []
        for cert_request_info in cert_request_infos.cert_request_info_list:
            status = cert_request_info.request_status
            if status == CertRequestStatus.REJECTED or \
                    status == CertRequestStatus.CANCELED:
                ret.append(
                    CertEnrollmentResult(cert_request_info, None)
                )
            else:
                request_id = cert_request_info.request_id
                if status == CertRequestStatus.PENDING:
                    self.approve_request(request_id)
                cert_request_info = self.get_request(request_id)
                ret.append(
                    CertEnrollmentResult(
                        cert_request_info,
                        self.get_cert(cert_request_info.cert_id)
                    )
                )

        return ret


encoder.NOTYPES['CertData'] = CertData
encoder.NOTYPES['CertSearchRequest'] = CertSearchRequest
encoder.NOTYPES['CertRevokeRequest'] = CertRevokeRequest
encoder.NOTYPES['CertEnrollmentRequest'] = CertEnrollmentRequest
encoder.NOTYPES['ProfileInput'] = profile.ProfileInput
encoder.NOTYPES['ProfileAttribute'] = profile.ProfileAttribute
encoder.NOTYPES['Descriptor'] = profile.Descriptor
encoder.NOTYPES['ProfileOutput'] = profile.ProfileOutput
encoder.NOTYPES['CertReviewResponse'] = CertReviewResponse
encoder.NOTYPES['ProfilePolicySet'] = profile.ProfilePolicySet
encoder.NOTYPES['ProfilePolicy'] = profile.ProfilePolicy
encoder.NOTYPES['PolicyDefault'] = profile.PolicyDefault
encoder.NOTYPES['PolicyConstraint'] = profile.PolicyConstraint
encoder.NOTYPES['PolicyConstraintValue'] = profile.PolicyConstraintValue
encoder.NOTYPES['ProfileParameter'] = profile.ProfileParameter


def main():
    # Create a PKIConnection object that stores the details of the CA.
    connection = client.PKIConnection('https', 'localhost', '8443', 'ca')

    # The pem file used for authentication. Created from a p12 file using the
    # command -
    # openssl pkcs12 -in <p12_file_path> -out /tmp/auth.pem -nodes
    connection.set_authentication_cert("/tmp/auth.pem")

    # Instantiate the CertClient
    cert_client = CertClient(connection)

    cert_client.get_enrollment_template('caUserCert')

    # Enrolling an user certificate
    print('Enrolling an user certificate')
    print('-----------------------------')

    inputs = dict()
    inputs['cert_request_type'] = 'crmf'
    inputs['cert_request'] = "MIIBpDCCAaAwggEGAgUA5n9VYTCBx4ABAqUOMAwxCjAIBgN" \
                             "VBAMTAXimgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAK" \
                             "/SmUVoUjBtqHNw/e3OoCSXw42pdQSR53/eYJWpf7nyTbZ9U" \
                             "uIhGfXOtxy5vRetmDHE9u0AopmuJbr1rL17/tSnDakpkE9u" \
                             "mQ2lMOReLloSdX32w2xOeulUwh5BGbFpq10S0SvW1H93Vn0" \
                             "eCy2aa4UtILNEsp7JJ3FnYJibfuMPAgMBAAGpEDAOBgNVHQ" \
                             "8BAf8EBAMCBeAwMzAVBgkrBgEFBQcFAQEMCHJlZ1Rva2VuM" \
                             "BoGCSsGAQUFBwUBAgwNYXV0aGVudGljYXRvcqGBkzANBgkq" \
                             "hkiG9w0BAQUFAAOBgQCuywnrDk/wGwfbguw9oVs9gzFQwM4" \
                             "zeFbk+z82G5CWoG/4mVOT5LPL5Q8iF+KfnaU9Qcu6zZPxW6" \
                             "ZmDd8WpPJ+MTPyQl3Q5BfiKa4l5ra1NeqxMOlMiiupwINmm" \
                             "7jd1KaA2eIjuyC8/gTaO4b14R6aRaOj+Scp9cNYbthA7REh" \
                             "Jw=="
    inputs['sn_uid'] = 'test12345'
    inputs['sn_e'] = 'example@redhat.com'
    inputs['sn_cn'] = 'TestUser'

    enrollment_results = cert_client.enroll_cert('caUserCert', inputs)

    for enrollment_result in enrollment_results:
        request_data = enrollment_result.request
        cert_data = enrollment_result.cert
        print('Request ID: ' + request_data.request_id)
        print('Request Status:' + request_data.request_status)
        print('Serial Number: ' + cert_data.serial_number)
        print('Issuer: ' + cert_data.issuer_dn)
        print('Subject: ' + cert_data.subject_dn)
        print('Pretty Print:')
        print(cert_data.pretty_repr)

    print()

    # Enrolling a server certificate
    print("Enrolling a server certificate")
    print('------------------------------')

    inputs = dict()
    inputs['cert_request_type'] = 'pkcs10'
    inputs['cert_request'] = "MIIBmDCCAQECAQAwWDELMAkGA1UEBhMCVVMxCzAJBgNVBAg" \
                             "MAk5DMRAwDgYDVQQHDAdSYWxlaWdoMRUwEwYDVQQKDAxSZW" \
                             "QgSGF0IEluYy4xEzARBgNVBAMMClRlc3RTZXJ2ZXIwgZ8wD" \
                             "QYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMJpWz92dSYCvWxl" \
                             "lrQCY5atPKCswUwyppRNGPnKmJ77AdHBBI4dFyET+h/+69j" \
                             "QMTLZMa8FX7SbyHvgbgLBP4Q/RzCSE2S87qFNjriOqiQCqJ" \
                             "mcrzDzdncJQiP+O7T6MSpLo3smLP7dK1Vd7vK0Vy8yHwV0e" \
                             "Bx7DgYedv2slBPHAgMBAAGgADANBgkqhkiG9w0BAQUFAAOB" \
                             "gQBvkxAGKwkfK3TKwLc5Mg0IWp8zGRVwxdIlghAL8DugNoc" \
                             "CNNgmZazglJOOehLuk0/NkLX1ZM5RrVgM09W6kcfWZtIwr5" \
                             "Uje2K/+6tW2ZTGrbizs7CNOTMzA/9H8CkHb4H9P/qRT275z" \
                             "HIocYj4smUnXLwWGsBMeGs+OMMbGvSrHg=="

    inputs['requestor_name'] = 'Tester'
    inputs['requestor_email'] = 'example@redhat.com'

    cert_id = None
    enrollment_results_2 = cert_client.enroll_cert('caServerCert', inputs)
    for enrollment_result in enrollment_results_2:
        request_data = enrollment_result.request
        cert_data = enrollment_result.cert
        print('Request ID: ' + request_data.request_id)
        print('Request Status:' + request_data.request_status)
        if cert_data is not None:
            # store cert_id for usage later
            cert_id = cert_data.serial_number
            print('Serial Number: ' + cert_id)
            print('Issuer: ' + cert_data.issuer_dn)
            print('Subject: ' + cert_data.subject_dn)
            print('Pretty Print:')
            print(cert_data.pretty_repr)

    print()

    # List all the VALID certs
    print('An example listing all VALID certs')
    print('----------------------------------')

    search_params = {'status': 'VALID'}
    cert_data_list = cert_client.list_certs(**search_params)
    for cert_data_info in cert_data_list:
        print("Serial Number: " + cert_data_info.serial_number)
        print("Subject DN: " + cert_data_info.subject_dn)
        print("Status: " + cert_data_info.status)
    print()

    # Trying to get a non-existing cert
    # Assuming that there is no certificate with serial number = 100
    try:
        cert_data = cert_client.get_cert(100)
        print('Serial Number: ' + cert_data.serial_number)
        print('Issuer: ' + cert_data.issuer_dn)
        print('Subject: ' + cert_data.subject_dn)
    except pki.CertNotFoundException:
        print("Certificate with ID 100 does not exist")
        print()

    # Certificate Serial Number used for CertClient methods.
    # 7, 0x7 and '0x7' are also valid values
    # Following examples use the serial number of the user certificate enrolled
    #  before.

    # Get certificate data
    print('Getting information of a certificate')
    print('------------------------------------')

    cert_data = cert_client.get_cert(cert_id)
    # Print the certificate information
    print('Serial Number: ' + cert_data.serial_number)
    print('Issuer: ' + cert_data.issuer_dn)
    print('Subject: ' + cert_data.subject_dn)
    print('Status: ' + cert_data.status)
    print('Not Before: ' + cert_data.not_before)
    print('Not After: ' + cert_data.not_after)
    print('Encoded: ')
    print(cert_data.encoded)
    print("Pretty print format: ")
    print(cert_data.pretty_repr)
    print()

    # Review a certificate - used to get a nonce for revoke request.
    print('Reviewing a certificate')
    print('-----------------------')

    cert_data = cert_client.review_cert(cert_id)
    print('Serial Number: ' + cert_data.serial_number)
    print('Issuer: ' + cert_data.issuer_dn)
    print('Subject: ' + cert_data.subject_dn)
    print('Status: ' + cert_data.status)
    print('Nonce: ' + str(cert_data.nonce))
    print()

    # Revoke a certificate
    print('Revoking a certificate')
    print('----------------------')

    cert_request_info = cert_client.hold_cert(cert_data.serial_number,
                                              comments="Test revoking a cert")
    print('Request ID: ' + cert_request_info.request_id)
    print('Request Type: ' + cert_request_info.request_type)
    print('Request Status: ' + cert_request_info.request_status)
    print()

    # Un-revoke a certificate
    print('Un-revoking a certificate')
    print('-------------------------')

    cert_request_info = cert_client.unrevoke_cert(cert_data.serial_number)
    print('Request ID: ' + cert_request_info.request_id)
    print('Request Type: ' + cert_request_info.request_type)
    print('Request Status: ' + cert_request_info.request_status)
    print()


if __name__ == "__main__":
    main()
