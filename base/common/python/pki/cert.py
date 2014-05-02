#!/usr/bin/python
"""
Created on Feb 13, 2014

@author: akoneru
"""
import json
import pki
import pki.client as client
import pki.encoder as encoder
import types


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
    Class containing lists of CertDataInfo objects.
    This data is returned when searching/listing certificate records on the CA.
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
        if 'certID' in attr_list:
            cert_request_info.cert_id = attr_list['certId']
        if 'certURL' in attr_list:
            cert_request_info.cert_url = attr_list['certURL']
        if 'certRequestType' in attr_list:
            cert_request_info.cert_request_type = attr_list['certRequestType']
        if 'errorMessage' in attr_list:
            cert_request_info.error_message = attr_list['errorMessage']

        return cert_request_info


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


encoder.NOTYPES['CertData'] = CertData
encoder.NOTYPES['CertSearchRequest'] = CertSearchRequest
encoder.NOTYPES['CertRevokeRequest'] = CertRevokeRequest


def main():
    # Create a PKIConnection object that stores the details of the CA.
    connection = client.PKIConnection('https', 'localhost', '8443', 'ca')

    # The pem file used for authentication. Created from a p12 file using the command -
    # openssl pkcs12 -in <p12_file_path> -out /tmp/auth.pem -nodes
    connection.set_authentication_cert("/tmp/auth.pem")

    #Instantiate the CertClient
    cert_client = CertClient(connection)

    # List all the VALID certs
    search_params = {'status': 'VALID'}
    cert_data_infos = cert_client.list_certs(**search_params)
    for cert_data_info in cert_data_infos.cert_info_list:
        print("Serial Number: " + cert_data_info.cert_id)
        print("Subject DN: " + cert_data_info.subject_dn)
        print("Status: " + cert_data_info.status)
    print

    #Trying an invalid get cert
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
    # 7 and '0x7' are also valid values
    cert_id = 0x7

    #Get certificate data
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
    cert_data = cert_client.review_cert(cert_id)
    print('Serial Number: ' + cert_data.serial_number)
    print('Issuer: ' + cert_data.issuer_dn)
    print('Subject: ' + cert_data.subject_dn)
    print('Status: ' + cert_data.status)
    print('Nonce: ' + str(cert_data.nonce))
    print

    #Revoke a certificate
    cert_request_info = cert_client.revoke_cert(cert_data.serial_number,
                                                revocation_reason=CertRevokeRequest.REASON_CERTIFICATE_HOLD,
                                                comments="Test revoking a cert", nonce=cert_data.nonce)
    print('Request ID: ' + cert_request_info.request_id)
    print('Request Type: ' + cert_request_info.request_type)
    print('Request Status: ' + cert_request_info.request_status)
    print

    #Un-revoke a certificate
    cert_request_info = cert_client.unrevoke_cert(cert_data.serial_number)
    print('Request ID: ' + cert_request_info.request_id)
    print('Request Type: ' + cert_request_info.request_type)
    print('Request Status: ' + cert_request_info.request_status)
    print


if __name__ == "__main__":
    main()
