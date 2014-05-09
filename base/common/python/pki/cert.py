#!/usr/bin/python
"""
Created on Feb 13, 2014

@author: akoneru
"""
import copy
import json
import types

import pki
import pki.client as client
import pki.encoder as encoder
import pki.profile as profile


class CertId(object):
    """
    Class encapsulating a certificate serial number
    """

    def __init__(self, cert_id):
        """ Constructor """
        self.value = cert_id


class CertData(object):
    """
    Class containing certificate data as returned from getCert()
    """

    def __init__(self):
        """ Constructor """
        self.serial_number = None
        self.issuer_dn = None
        self.subject_dn = None
        self.pretty_repr = None
        self.encoded = None
        self.pkcs7_cert_chain = None
        self.not_before = None
        self.not_after = None
        self.status = None
        self.nonce = None
        self.link = None

    @classmethod
    def from_json(cls, attr_list):
        """ Return CertData object from JSON dict """
        cert_data = cls()
        cert_data.serial_number = attr_list['id']
        cert_data.issuer_dn = attr_list['IssuerDN']
        cert_data.subject_dn = attr_list['SubjectDN']
        cert_data.pretty_repr = attr_list['PrettyPrint']
        cert_data.encoded = attr_list['Encoded']
        cert_data.pkcs7_cert_chain = attr_list['PKCS7CertChain']
        cert_data.not_before = attr_list['NotBefore']
        cert_data.not_after = attr_list['NotAfter']
        cert_data.status = attr_list['Status']
        cert_data.link = pki.Link.from_json(attr_list['Link'])

        #Special case. Only returned when reviewing a cert.
        if 'Nonce' in attr_list:
            cert_data.nonce = attr_list['Nonce']
        return cert_data


class CertDataInfo(object):
    """
    Class containing information contained in a CertRecord on the CA.
    This data is returned when searching/listing certificate records.
    """

    def __init__(self):
        """ Constructor """
        self.cert_id = None
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

    @classmethod
    def from_json(cls, attr_list):
        """ Return CertDataInfo object from JSON dict """
        cert_data_info = cls()
        cert_data_info.cert_id = attr_list['id']
        cert_data_info.subject_dn = attr_list['SubjectDN']
        cert_data_info.status = attr_list['Status']
        cert_data_info.type = attr_list['Type']
        cert_data_info.version = attr_list['Version']
        cert_data_info.key_algorithm_oid = attr_list['KeyAlgorithmOID']
        cert_data_info.key_length = attr_list['KeyLength']
        cert_data_info.not_valid_before = attr_list['NotValidBefore']
        cert_data_info.not_valid_after = attr_list['NotValidAfter']
        cert_data_info.issued_on = attr_list['IssuedOn']
        cert_data_info.issued_by = attr_list['IssuedBy']
        cert_data_info.link = pki.Link.from_json(attr_list['Link'])

        return cert_data_info


class CertDataInfoCollection(object):
    """
    Class containing list of CertDataInfo objects and their respective link objects.
    This data is returned when searching/listing certificate records in the CA.
    """

    def __init__(self):
        """ Constructor """
        self.cert_info_list = []
        self.links = []

    @classmethod
    def from_json(cls, json_value):
        """ Populate object from JSON input """
        ret = cls()
        cert_infos = json_value['entries']
        if not isinstance(cert_infos, types.ListType):
            ret.cert_info_list.append(CertDataInfo.from_json(cert_infos))
        else:
            for cert_info in cert_infos:
                ret.cert_info_list.append(CertDataInfo.from_json(cert_info))

        links = json_value['Link']
        if not isinstance(links, types.ListType):
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

    @classmethod
    def from_json(cls, attr_list):
        cert_request_info = cls()
        cert_request_info.request_type = attr_list['requestType']
        cert_request_info.request_url = attr_list['requestURL']
        cert_request_info.request_status = attr_list['requestStatus']
        cert_request_info.operation_result = attr_list['operationResult']
        cert_request_info.request_id = \
            str(cert_request_info.request_url)[(str(cert_request_info.request_url).rfind("/") + 1):]
        #Optional parameters
        if 'certId' in attr_list:
            cert_request_info.cert_id = attr_list['certId']
        if 'certURL' in attr_list:
            cert_request_info.cert_url = attr_list['certURL']
        if 'certRequestType' in attr_list:
            cert_request_info.cert_request_type = attr_list['certRequestType']
        if 'errorMessage' in attr_list:
            cert_request_info.error_message = attr_list['errorMessage']

        return cert_request_info


class CertRequestInfoCollection(object):
    """
    Class containing list of CertRequestInfo objects.
    This data is returned when listing certificate request records in the CA.
    """

    def __init__(self):
        self.cert_info_list = []
        self.links = []

    @classmethod
    def from_json(cls, json_value):
        """ Populate object from JSON input """
        ret = cls()
        cert_req_infos = json_value['entries']
        if not isinstance(cert_req_infos, types.ListType):
            ret.cert_info_list.append(CertRequestInfo.from_json(cert_req_infos))
        else:
            for cert_info in cert_req_infos:
                ret.cert_info_list.append(CertRequestInfo.from_json(cert_info))

        links = json_value['Link']
        if not isinstance(links, types.ListType):
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
                     'email': 'eMail', 'common_name': 'commonName', 'user_id': 'userID',
                     'org_unit': 'orgUnit', 'org': 'org', 'locality': 'locality',
                     'state': 'state', 'country': 'country', 'match_exactly': 'matchExactly',
                     'status': 'status', 'revoked_by': 'revokedBy', 'revoked_on_from': 'revokedOnFrom',
                     'revoked_on_to': 'revokedOnTo', 'revocation_reason': 'revocationReason',
                     'issued_by': 'issuedBy', 'issued_on_from': 'issuedOnFrom', 'issued_on_to': 'issuedOnTo',
                     'valid_not_before_from': 'validNotBeforeFrom', 'valid_not_before_to': 'validNotBeforeTo',
                     'valid_not_after_from': 'validNotAfterFrom', 'valid_not_after_to': 'validNotAfterTo',
                     'validity_operation': 'validityOperation', 'validity_count': 'validityCount',
                     'validity_unit': 'validityUnit', 'cert_type_sub_email_ca': 'certTypeSubEmailCA',
                     'cert_type_sub_ssl_ca': 'certTypeSubSSLCA', 'cert_type_secure_email': 'certTypeSecureEmail',
                     'cert_type_ssl_client': 'certTypeSSLClient', 'cert_type_ssl_server': 'certTypeSSLServer'}

    def __init__(self, **cert_search_params):
        """ Constructor """

        if len(cert_search_params) == 0:
            setattr(self, 'serialNumberRangeInUse', True)

        for param in cert_search_params:
            if not param in CertSearchRequest.search_params:
                raise ValueError('Invalid search parameter: ' + param)

            if param == 'serial_to' or param == 'serial_from':
                setattr(self, CertSearchRequest.search_params[param], cert_search_params[param])
                setattr(self, 'serialNumberRangeInUse', True)

            if param == 'email' or param == 'common_name' or param == 'user_id' or param == 'org_unit' \
                    or param == 'org' or param == 'locality' or param == 'state' or param == 'country' \
                    or param == 'match_exactly':
                setattr(self, CertSearchRequest.search_params[param], cert_search_params[param])
                setattr(self, 'subjectInUse', True)

            if param == 'status':
                setattr(self, CertSearchRequest.search_params[param], cert_search_params[param])

            if param == 'revoked_by':
                setattr(self, CertSearchRequest.search_params[param], cert_search_params[param])
                setattr(self, 'revokedByInUse', True)

            if param == 'revoked_on_from' or param == 'revoked_on_to':
                setattr(self, CertSearchRequest.search_params[param], cert_search_params[param])
                setattr(self, 'revokedOnInUse', True)

            if param == 'revocation_reason':
                setattr(self, CertSearchRequest.search_params[param], cert_search_params[param])
                setattr(self, 'revocationReasonInUse', True)

            if param == 'issued_by':
                setattr(self, CertSearchRequest.search_params[param], cert_search_params[param])
                setattr(self, 'issuedByInUse', True)

            if param == 'issued_on_from' or param == 'issued_on_to':
                setattr(self, CertSearchRequest.search_params[param], cert_search_params[param])
                setattr(self, 'issuedOnInUse', True)

            if param == 'valid_not_before_from' or param == 'valid_not_before_to':
                setattr(self, CertSearchRequest.search_params[param], cert_search_params[param])
                setattr(self, 'validNotBeforeInUse', True)

            if param == 'valid_not_after_from' or param == 'valid_not_after_to':
                setattr(self, CertSearchRequest.search_params[param], cert_search_params[param])
                setattr(self, 'validNotAfterInUse', True)

            if param == 'validity_operation' or param == 'validity_count' or param == 'validity_unit':
                setattr(self, CertSearchRequest.search_params[param], cert_search_params[param])
                setattr(self, 'validityLengthInUse', True)

            if param == 'cert_type_sub_email_ca' or param == 'cert_type_sub_ssl_ca' \
                    or param == 'cert_type_secure_email' or param == 'cert_type_ssl_client' \
                    or param == 'cert_type_ssl_server':
                setattr(self, CertSearchRequest.search_params[param], cert_search_params[param])
                setattr(self, 'certTypeInUse', True)


class CertRevokeRequest(object):
    """
        An object of this class encapsulates all the
        parameters required for revoking a certificate.
    """

    REASON_UNSPECIFIED = "Unspecified"
    REASON_KEY_COMPROMISE = "Key_Compromise"
    REASON_CA_COMPROMISE = "CA_Compromise"
    REASON_AFFILIATION_CHANGED = "Affiliation_Changed"
    REASON_SUPERSEDED = "Superseded"
    REASON_CESSATION_OF_OPERATION = "Cessation_of_Operation"
    REASON_CERTIFICATE_HOLD = "Certificate_Hold"
    REASON_REMOVE_FROM_CRL = "Remove_from_CRL"
    REASON_PRIVILEGE_WITHDRAWN = "Privilege_Withdrawn"
    REASON_AA_COMPROMISE = "AA_Compromise"

    def __init__(self, nonce, reason=None, invalidity_date=None, comments=None):
        """ Constructor """
        setattr(self, "Nonce", nonce)
        if reason is None:
            reason = self.REASON_UNSPECIFIED
        setattr(self, "Reason", reason)
        if invalidity_date is not None:
            setattr(self, "InvalidityDate", invalidity_date)
        if comments is not None:
            setattr(self, "Comments", comments)


class CertEnrollmentRequest(object):
    """
    This class encapsulates the parameters required for a certificate enrollment request.
    """

    def __init__(self, profile_id=None, renewal=False, serial_number=None, remote_host=None, remote_address=None,
                 inputs=None, outputs=None):
        """ Constructor """
        self.profile_id = profile_id
        self.renewal = renewal
        self.serial_number = serial_number
        self.remote_host = remote_host
        self.remote_address = remote_address
        if inputs is None:
            self.inputs = []
        if outputs is None:
            self.outputs = []

    @property
    def profile_id(self):
        return getattr(self, 'ProfileID', None)

    @profile_id.setter
    def profile_id(self, value):
        setattr(self, 'ProfileID', value)

    @property
    def renewal(self):
        return getattr(self, 'Renewal', False)

    @renewal.setter
    def renewal(self, value):
        setattr(self, 'Renewal', value)

    @property
    def serial_number(self):
        return getattr(self, 'SerialNumber', None)

    @serial_number.setter
    def serial_number(self, value):
        setattr(self, 'SerialNumber', value)

    @property
    def remote_host(self):
        return getattr(self, 'RemoteHost', None)

    @remote_host.setter
    def remote_host(self, value):
        setattr(self, 'RemoteHost', value)

    @property
    def remote_address(self):
        return getattr(self, 'RemoteAddress', None)

    @remote_address.setter
    def remote_address(self, value):
        setattr(self, 'RemoteAddress', value)

    @property
    def inputs(self):
        return getattr(self, 'Input')

    @inputs.setter
    def inputs(self, value):
        setattr(self, 'Input', value)

    @property
    def outputs(self):
        return getattr(self, 'Output')

    @outputs.setter
    def outputs(self, value):
        setattr(self, 'Output', value)

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
    def from_json(cls, json_value):
        enroll_request = cls()

        enroll_request.profile_id = json_value['ProfileID']
        enroll_request.renewal = json_value['Renewal']
        if 'SerialNumber' in json_value:
            enroll_request.serial_number = json_value['SerialNumber']
        if 'RemoteHost' in json_value:
            enroll_request.remote_host = json_value['RemoteHost']
        if 'RemoteAddress' in json_value:
            enroll_request.remote_address = json_value['RemoteAddress']

        inputs = json_value['Input']
        if not isinstance(inputs, types.ListType):
            enroll_request.inputs.append(profile.ProfileInput.from_json(inputs))
        else:
            for profile_input in inputs:
                enroll_request.inputs.append(profile.ProfileInput.from_json(profile_input))

        outputs = json_value['Output']
        if not isinstance(outputs, types.ListType):
            enroll_request.outputs.append(profile.ProfileOutput.from_json(outputs))
        else:
            for profile_output in outputs:
                enroll_request.outputs.append(profile.ProfileOutput.from_json(profile_output))

        return enroll_request


class CertReviewResponse(CertEnrollmentRequest):
    """
    An object of this class represent the response from the server when
    reviewing a certificate enrollment request.
    It contains a nonce required to perform action on the request.
    """

    def __init__(self, profile_id=None, renewal=False, serial_number=None, remote_host=None, remote_address=None,
                 inputs=None, outputs=None, nonce=None, request_id=None, request_type=None, request_status=None,
                 request_owner=None, request_creation_time=None, request_modification_time=None, request_notes=None,
                 profile_approval_by=None, profile_set_id=None, profile_is_visible=None, profile_name=None,
                 profile_description=None, profile_remote_host=None, profile_remote_address=None, policy_sets=None):

        super(CertReviewResponse, self).__init__(profile_id, renewal, serial_number, remote_host,
                                                 remote_address, inputs, outputs)
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

    @property
    def request_id(self):
        return getattr(self, 'requestId')

    @request_id.setter
    def request_id(self, value):
        setattr(self, 'requestId', value)

    @property
    def request_type(self):
        return getattr(self, 'requestType')

    @request_type.setter
    def request_type(self, value):
        setattr(self, 'requestType', value)

    @property
    def request_status(self):
        return getattr(self, 'requestStatus')

    @request_status.setter
    def request_status(self, value):
        setattr(self, 'requestStatus', value)

    @property
    def request_owner(self):
        return getattr(self, 'requestOwner')

    @request_owner.setter
    def request_owner(self, value):
        setattr(self, 'requestOwner', value)

    @property
    def request_creation_time(self):
        return getattr(self, 'requestCreationTime')

    @request_creation_time.setter
    def request_creation_time(self, value):
        setattr(self, 'requestCreationTime', value)

    @property
    def request_modification_time(self):
        return getattr(self, 'requestModificationTime')

    @request_modification_time.setter
    def request_modification_time(self, value):
        setattr(self, 'requestModificationTime', value)

    @property
    def request_notes(self):
        return getattr(self, 'requestNotes')

    @request_notes.setter
    def request_notes(self, value):
        setattr(self, 'requestNotes', value)

    @property
    def profile_approved_by(self):
        return getattr(self, 'profileApprovedBy')

    @profile_approved_by.setter
    def profile_approved_by(self, value):
        setattr(self, 'profileApprovedBy', value)

    @property
    def profile_set_id(self):
        return getattr(self, 'profileSetId')

    @profile_set_id.setter
    def profile_set_id(self, value):
        setattr(self, 'profileSetId', value)

    @property
    def profile_is_visible(self):
        return getattr(self, 'profileIsVisible')

    @profile_is_visible.setter
    def profile_is_visible(self, value):
        setattr(self, 'profileIsVisible', value)

    @property
    def profile_name(self):
        return getattr(self, 'profileName')

    @profile_name.setter
    def profile_name(self, value):
        setattr(self, 'profileName', value)

    @property
    def profile_description(self):
        return getattr(self, 'profileDescription')

    @profile_description.setter
    def profile_description(self, value):
        setattr(self, 'profileDescription', value)

    @property
    def profile_remote_host(self):
        return getattr(self, 'profileRemoteHost')

    @profile_remote_host.setter
    def profile_remote_host(self, value):
        setattr(self, 'profileRemoteHost', value)

    @property
    def profile_remote_address(self):
        return getattr(self, 'profileRemoteAddr')

    @profile_remote_address.setter
    def profile_remote_address(self, value):
        setattr(self, 'profileRemoteAddr', value)

    @property
    def policy_sets(self):
        return getattr(self, 'ProfilePolicySet')

    @policy_sets.setter
    def policy_sets(self, value):
        setattr(self, 'ProfilePolicySet', value)

    @classmethod
    def from_json(cls, json_value):

        #First read the values for attributes defined in CertEnrollmentRequest
        review_response = super(CertReviewResponse, cls).from_json(json_value)

        review_response.nonce = json_value['nonce']
        review_response.request_id = json_value['requestId']
        review_response.request_type = json_value['requestType']
        review_response.request_status = json_value['requestStatus']
        review_response.request_owner = json_value['requestOwner']
        review_response.request_creation_time = json_value['requestCreationTime']
        review_response.request_modification_time = json_value['requestModificationTime']
        review_response.request_notes = json_value['requestNotes']
        review_response.profile_approved_by = json_value['profileApprovedBy']
        review_response.profile_set_id = json_value['profileSetId']
        review_response.profile_is_visible = json_value['profileIsVisible']
        review_response.profile_name = json_value['profileName']
        review_response.profile_description = json_value['profileDescription']
        review_response.profile_remote_host = json_value['profileRemoteHost']
        review_response.profile_remote_address = json_value['profileRemoteAddr']

        profile_policy_sets = json_value['ProfilePolicySet']
        if not isinstance(profile_policy_sets, types.ListType):
            review_response.policy_sets.append(profile.ProfilePolicySet.from_json(profile_policy_sets))
        else:
            for policy_set in profile_policy_sets:
                review_response.policy_sets.append(profile.ProfilePolicySet.from_json(policy_set))

        return review_response


class CertClient(object):
    """
    Class encapsulating and mirroring the functionality in the CertResource Java interface class
    defining the REST API for Certificate resources.
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
    def get_cert(self, cert_id):
        """ Return a CertData object for a particular certificate. """
        if cert_id is None:
            raise ValueError("Certificate ID must be specified")

        url = self.cert_url + '/' + str(cert_id)
        r = self.connection.get(url, self.headers)
        return CertData.from_json(r.json())

    @pki.handle_exceptions()
    def list_certs(self, max_results=None, max_time=None, start=None, size=None, **cert_search_params):
        """ Return a CertDataInfoCollection object with a information about all the
            certificates that satisfy the search criteria.
            If cert_search_request=None, returns all the certificates.
        """
        url = self.cert_url + '/search'
        query_params = {"maxResults": max_results, "maxTime": max_time, "start": start, "size": size}
        cert_search_request = CertSearchRequest(**cert_search_params)
        search_request = json.dumps(cert_search_request, cls=encoder.CustomTypeEncoder, sort_keys=True)
        response = self.connection.post(url, search_request, self.headers, query_params)
        return CertDataInfoCollection.from_json(response.json())

    @pki.handle_exceptions()
    def review_cert(self, cert_id):
        """ Reviews a certificate. Returns a CertData object with a nonce.
            This method requires an agent's authentication cert in the connection object.
        """
        if cert_id is None:
            raise ValueError("Certificate ID must be specified")

        url = self.agent_cert_url + '/' + str(cert_id)
        r = self.connection.get(url, self.headers)
        return CertData.from_json(r.json())

    def _submit_revoke_request(self, url, cert_id, revocation_reason=None, invalidity_date=None, comments=None,
                               nonce=None):
        """
        Submits a certificate revocation request.
        Expects the URL for submitting the request.
        Creates a CertRevokeRequest object using the arguments provided.
        If nonce is passed as an argument, reviews the cert to get a nonce from the server
        and passes it in the request.
        Returns a CertRequestInfo object.
        """
        if cert_id is None:
            raise ValueError("Certificate ID must be specified")

        if url is None:
            raise ValueError("URL not specified")

        if nonce is None:
            cert_data = self.review_cert(cert_id)
            nonce = cert_data.nonce
        request = CertRevokeRequest(nonce, revocation_reason, invalidity_date, comments)
        revoke_request = json.dumps(request, cls=encoder.CustomTypeEncoder, sort_keys=True)
        r = self.connection.post(url, revoke_request, headers=self.headers)
        return CertRequestInfo.from_json(r.json())

    @pki.handle_exceptions()
    def revoke_cert(self, cert_id, revocation_reason=None, invalidity_date=None, comments=None, nonce=None):
        """ Revokes a certificate.
            Returns a CertRequestInfo object with information about the request.
            This method requires an agent's authentication cert in the connection object.
        """
        url = self.agent_cert_url + '/' + str(cert_id) + '/revoke'
        return self._submit_revoke_request(url, cert_id, revocation_reason, invalidity_date, comments, nonce)

    @pki.handle_exceptions()
    def revoke_ca_cert(self, cert_id, revocation_reason=None, invalidity_date=None, comments=None, nonce=None):
        """ Revokes a CA certificate.
            Returns a CertRequestInfo object with information about the request.
            This method requires an agent's authentication cert in the connection object.
        """
        url = self.agent_cert_url + '/' + str(cert_id) + '/revoke-ca'
        return self._submit_revoke_request(url, cert_id, revocation_reason, invalidity_date, comments, nonce)

    @pki.handle_exceptions()
    def hold_cert(self, cert_id, comments=None):
        """ Places a certificate on-hold.
            Calls the revoke_cert method with reason - CertRevokeRequest.REASON_CERTIFICATE_HOLD.
            Returns a CertRequestInfo object.
            This method requires an agent's authentication cert in the connection object.
        """
        return self.revoke_cert(cert_id, CertRevokeRequest.REASON_CERTIFICATE_HOLD, comments=comments)

    @pki.handle_exceptions()
    def unrevoke_cert(self, cert_id):
        """ Un-revokes a revoked certificate.
            Returns a CertRequestInfo object.
            This method requires an agent's authentication cert in the connection object.
        """
        if cert_id is None:
            raise ValueError("Certificate ID must be specified")

        url = self.agent_cert_url + '/' + str(cert_id) + '/unrevoke'
        r = self.connection.post(url, None, headers=self.headers)
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
    def list_requests(self, request_status=None, request_type=None, from_request_id=None, size=None,
                      max_results=None, max_time=None):
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
        r = self.connection.get(self.agent_cert_requests_url, self.headers, query_params)
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
        review_response = json.dumps(cert_review_response, cls=encoder.CustomTypeEncoder, sort_keys=True)
        r = self.connection.post(url, review_response, headers=self.headers)
        return r

    def approve_request(self, request_id, cert_review_response=None):
        """
        Approves a certificate enrollment request.
        If cert_review_response is None, a review request operation is performed to fetch the
        CertReviewResponse object.
        Requires as agent level authentication.
        """
        return self._perform_action(request_id, cert_review_response, 'approve')

    def cancel_request(self, request_id, cert_review_response=None):
        """
        Cancels a certificate enrollment request.
        If cert_review_response is None, a review request operation is performed to fetch the
        CertReviewResponse object.
        Requires as agent level authentication.
        """
        return self._perform_action(request_id, cert_review_response, 'cancel')

    def reject_request(self, request_id,  cert_review_response=None):
        """
        Rejects a certificate enrollment request.
        If cert_review_response is None, a review request operation is performed to fetch the
        CertReviewResponse object.
        Requires as agent level authentication.
        """
        return self._perform_action(request_id, cert_review_response, 'reject')

    def validate_request(self, request_id, cert_review_response):
        """
        Validates a certificate enrollment request.
        If cert_review_response is None, a review request operation is performed to fetch the
        CertReviewResponse object.
        Requires as agent level authentication.
        """
        return self._perform_action(request_id, cert_review_response, 'validate')

    def update_request(self, request_id, cert_review_response):
        """
        Updates a certificate enrollment request.
        If cert_review_response is None, a review request operation is performed to fetch the
        CertReviewResponse object.
        Requires as agent level authentication.
        """
        return self._perform_action(request_id, cert_review_response, 'update')

    def assign_request(self, request_id, cert_review_response):
        """
        Assigns a certificate enrollment request.
        If cert_review_response is None, a review request operation is performed to fetch the
        CertReviewResponse object.
        Requires as agent level authentication.
        """
        return self._perform_action(request_id, cert_review_response, 'assign')

    def unassign_request(self, request_id, cert_review_response):
        """
        Un-assigns a certificate enrollment request.
        If cert_review_response is None, a review request operation is performed to fetch the
        CertReviewResponse object.
        Requires as agent level authentication.
        """
        return self._perform_action(request_id, cert_review_response, 'unassign')

    @pki.handle_exceptions()
    def list_enrollment_templates(self, start=None, size=None):
        """
        Gets the list of profile templates supported by the CA.
        The values for start and size arguments determine the starting point and the length of the list.
        Returns a ProfileDataInfoCollection object.
        """

        url = self.cert_requests_url + '/profiles'
        query_params = {
            'start': start,
            'size': size
        }
        r = self.connection.get(url, self.headers, query_params)
        print r
        return profile.ProfileDataInfoCollection.from_json(r.json())

    @pki.handle_exceptions()
    def get_enrollment_template(self, profile_id):
        """
        Fetch the enrollment template for the given profile id.
        For the first time, the request is sent to the server.
        The retrieved CertEnrollmentRequest object is then cached locally for future requests.
        Returns a CerEnrollmentRequest object.
        """

        if profile_id in self.enrollment_templates:
            return copy.deepcopy(self.enrollment_templates[profile_id])
        url = self.cert_requests_url + '/profiles/' + str(profile_id)
        r = self.connection.get(url, self.headers)

        #Caching the enrollment template object in-memory for future use.
        enrollment_template = CertEnrollmentRequest.from_json(r.json())
        self.enrollment_templates[profile_id] = enrollment_template

        return copy.deepcopy(enrollment_template)

    @pki.handle_exceptions()
    def create_enrollment_request(self, profile_id, inputs):
        """
        Fetches the enrollment request object for the given profile and
        sets values to its attributes using the values provided in the inputs dictionary.
        Returns the CertEnrollmentRequest object, which can be submitted to enroll a certificate.
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
    def submit_enrollment_request(self, enrollment_request):
        """
        Submits the CertEnrollmentRequest object to the server.
        Returns a CertRequestInfoCollection object with information about the certificate requests
        enrolled at the CA.
        """
        request_object = json.dumps(enrollment_request, cls=encoder.CustomTypeEncoder, sort_keys=True)
        r = self.connection.post(self.cert_requests_url, request_object, self.headers)
        return CertRequestInfoCollection.from_json(r.json())

    @pki.handle_exceptions()
    def enroll_cert(self, profile_id, inputs):
        """
        A convenience method for enrolling a certificate for a given profile id.
        The inputs parameter should be a dictionary with values for the profile attributes
        for an enrollment request.

        Calling this method with valid arguments, creates an enrollment request, submits it
        to the server, approves the certificate requests generated for the enrollment and
        returns a list of CertData objects for all the certificates generated as part of this
        enrollment.

        Note: This method supports only certificate enrollment where only one agent approval
        is sufficient.

        Requires an agent level authentication.
        """

        # Create a CertEnrollmentRequest object using the inputs for the given profile id.
        enroll_request = self.create_enrollment_request(profile_id, inputs)

        # Submit the enrollment request
        cert_request_infos = self.submit_enrollment_request(enroll_request)

        # Approve the requests generated for the certificate enrollment.
        # Fetch the CertData objects for all the certificates created and return to the caller.

        certificates = []
        for cert_request_info in cert_request_infos.cert_info_list:
            request_id = cert_request_info.request_id
            self.approve_request(request_id)
            cert_id = self.get_request(request_id).cert_id
            certificates.append(self.get_cert(cert_id))

        return certificates


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

    # The pem file used for authentication. Created from a p12 file using the command -
    # openssl pkcs12 -in <p12_file_path> -out /tmp/auth.pem -nodes
    connection.set_authentication_cert("/tmp/auth.pem")

    #Instantiate the CertClient
    cert_client = CertClient(connection)

    cert_client.get_enrollment_template('caUserCert')

    #Enrolling an user certificate
    print('Enrolling an user certificate')
    print('-----------------------------')

    inputs = dict()
    inputs['cert_request_type'] = 'crmf'
    inputs['cert_request'] = "MIIBpDCCAaAwggEGAgUA5n9VYTCBx4ABAqUOMAwxCjAIBgNVBAMTAXimgZ8wDQYJKoZIhvcNAQEBBQAD" \
                             "gY0AMIGJAoGBAK/SmUVoUjBtqHNw/e3OoCSXw42pdQSR53/eYJWpf7nyTbZ9UuIhGfXOtxy5vRetmDHE" \
                             "9u0AopmuJbr1rL17/tSnDakpkE9umQ2lMOReLloSdX32w2xOeulUwh5BGbFpq10S0SvW1H93Vn0eCy2a" \
                             "a4UtILNEsp7JJ3FnYJibfuMPAgMBAAGpEDAOBgNVHQ8BAf8EBAMCBeAwMzAVBgkrBgEFBQcFAQEMCHJl" \
                             "Z1Rva2VuMBoGCSsGAQUFBwUBAgwNYXV0aGVudGljYXRvcqGBkzANBgkqhkiG9w0BAQUFAAOBgQCuywnr" \
                             "Dk/wGwfbguw9oVs9gzFQwM4zeFbk+z82G5CWoG/4mVOT5LPL5Q8iF+KfnaU9Qcu6zZPxW6ZmDd8WpPJ+" \
                             "MTPyQl3Q5BfiKa4l5ra1NeqxMOlMiiupwINmm7jd1KaA2eIjuyC8/gTaO4b14R6aRaOj+Scp9cNYbthA7REhJw=="
    inputs['sn_uid'] = 'test12345'
    inputs['sn_e'] = 'example@redhat.com'
    inputs['sn_cn'] = 'TestUser'

    cert_data_infos = cert_client.enroll_cert('caUserCert', inputs)

    for data in cert_data_infos:
        print('Serial Number: ' + data.serial_number)
        print('Issuer: ' + data.issuer_dn)
        print('Subject: ' + data.subject_dn)
        print('Pretty Print:')
        print(data.pretty_repr)

    print

    # Enrolling a server certificate
    print("Enrolling a server certificate")
    print('------------------------------')

    inputs = dict()
    inputs['cert_request_type'] = 'pkcs10'
    inputs['cert_request'] = "MIIBmDCCAQECAQAwWDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5DMRAwDgYDVQQHDAdSYWxlaWdoMRUwE" \
                             "wYDVQQKDAxSZWQgSGF0IEluYy4xEzARBgNVBAMMClRlc3RTZXJ2ZXIwgZ8wDQYJKoZIhvcNAQEBBQADgY" \
                             "0AMIGJAoGBAMJpWz92dSYCvWxllrQCY5atPKCswUwyppRNGPnKmJ77AdHBBI4dFyET+h/+69jQMTLZMa8" \
                             "FX7SbyHvgbgLBP4Q/RzCSE2S87qFNjriOqiQCqJmcrzDzdncJQiP+O7T6MSpLo3smLP7dK1Vd7vK0Vy8y" \
                             "HwV0eBx7DgYedv2slBPHAgMBAAGgADANBgkqhkiG9w0BAQUFAAOBgQBvkxAGKwkfK3TKwLc5Mg0IWp8zG" \
                             "RVwxdIlghAL8DugNocCNNgmZazglJOOehLuk0/NkLX1ZM5RrVgM09W6kcfWZtIwr5Uje2K/+6tW2ZTGrb" \
                             "izs7CNOTMzA/9H8CkHb4H9P/qRT275zHIocYj4smUnXLwWGsBMeGs+OMMbGvSrHg=="

    inputs['requestor_name'] = 'Tester'
    inputs['requestor_email'] = 'example@redhat.com'

    cert_data_infos_2 = cert_client.enroll_cert('caServerCert', inputs)
    for data in cert_data_infos_2:
        print('Serial Number: ' + data.serial_number)
        print('Issuer: ' + data.issuer_dn)
        print('Subject: ' + data.subject_dn)
        print('Pretty Print:')
        print(data.pretty_repr)

    print

    # List all the VALID certs
    print('An example listing all VALID certs')
    print('----------------------------------')

    search_params = {'status': 'VALID'}
    cert_data_list = cert_client.list_certs(**search_params)
    for cert_data_info in cert_data_list.cert_info_list:
        print("Serial Number: " + cert_data_info.cert_id)
        print("Subject DN: " + cert_data_info.subject_dn)
        print("Status: " + cert_data_info.status)
    print

    #Trying to get a non-existing cert
    #Assuming that there is no certificate with serial number = 100
    try:
        cert_data = cert_client.get_cert(100)
        print('Serial Number: ' + cert_data.serial_number)
        print('Issuer: ' + cert_data.issuer_dn)
        print('Subject: ' + cert_data.subject_dn)
    except pki.CertNotFoundException:
        print("Certificate with ID 100 does not exist")
        print

    # Certificate Serial Number used for CertClient methods.
    # 7, 0x7 and '0x7' are also valid values
    # Following examples use the serial number of the user certificate enrolled before.
    cert_id = cert_data_infos[0].serial_number

    #Get certificate data
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
    print

    # Review a certificate - used to get a nonce for revoke request.
    print('Reviewing a certificate')
    print('-----------------------')

    cert_data = cert_client.review_cert(cert_id)
    print('Serial Number: ' + cert_data.serial_number)
    print('Issuer: ' + cert_data.issuer_dn)
    print('Subject: ' + cert_data.subject_dn)
    print('Status: ' + cert_data.status)
    print('Nonce: ' + str(cert_data.nonce))
    print

    #Revoke a certificate
    print('Revoking a certificate')
    print('----------------------')

    cert_request_info = cert_client.revoke_cert(cert_data.serial_number,
                                                revocation_reason=CertRevokeRequest.REASON_CERTIFICATE_HOLD,
                                                comments="Test revoking a cert", nonce=cert_data.nonce)
    print('Request ID: ' + cert_request_info.request_id)
    print('Request Type: ' + cert_request_info.request_type)
    print('Request Status: ' + cert_request_info.request_status)
    print

    #Un-revoke a certificate
    print('Un-revoking a certificate')
    print('-------------------------')

    cert_request_info = cert_client.unrevoke_cert(cert_data.serial_number)
    print('Request ID: ' + cert_request_info.request_id)
    print('Request Type: ' + cert_request_info.request_type)
    print('Request Status: ' + cert_request_info.request_status)
    print


if __name__ == "__main__":
    main()