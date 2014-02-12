#!/usr/bin/python
'''
Created on Aug 27, 2013

@author: akoneru
'''
import pki.client as client
import pki.encoder as e
import json
import types

class CertId(object):
    '''
    Class encapsulating a certificate serial number
    '''

    def __init__(self, cert_id):
        ''' Constructor '''
        if str(cert_id).startswith('0x'):
            #hex number
            print 'hex number'
            self.id = cert_id
        else:
            self.id = cert_id

class CertData(object):
    '''
    Class containing certificate data as returned from getCert()
    '''

    def __init__(self):
        ''' Constructor '''
        self.Encoded = None

    def from_dict(self, attr_list):
        ''' Return CertData object from JSON dict '''
        for key in attr_list:
            setattr(self, key, attr_list[key])
        return self

class CertDataInfo(object):
    '''
    Class containing information contained in a CertRecord on the CA.
    This data is returned when searching/listing certificate records.
    '''

    def __init__(self):
        ''' Constructor '''
        self.certId = None
        self.subjectDN = None
        self.status = None
        self.type = None
        self.version = None
        self.keyAlgorithmOID = None
        self.keyLength = None
        self.notValidBefore = None
        self.notValidAfter = None
        self.issuedOn = None
        self.issuedBy = None

    def from_dict(self, attr_list):
        ''' Return CertDataInfo object from JSON dict '''
        for key in attr_list:
            setattr(self, key, attr_list[key])
        return self

class CertDataInfos(object):
    '''
    Class containing lists of CertDataInfo objects.
    This data is returned when searching/listing certificate records on the CA.
    '''

    def __init__(self):
        ''' Constructor '''
        self.certInfoList = []
        self.links = []

    def decode_from_json(self, json_value):
        ''' Populate object from JSON input '''
        cert_infos = json_value['CertDataInfo']
        if not isinstance(cert_infos, types.ListType):
            certInfo = CertDataInfo()
            self.certInfoList.append(certInfo.from_dict(cert_infos))
        else:
            for cert_info in cert_infos:
                cert_data_info = CertDataInfo()
                cert_data_info.from_dict(cert_info)
                self.certInfoList.append(cert_data_info)

class CertSearchRequest(object):

    def __init__(self):
        self.serialNumberRangeInUse = False
        self.serialTo = None
        self.serialFrom = None
        self.subjectInUse = False
        self.eMail = None
        self.commonName = None
        self.userID = None
        self.orgUnit = None
        self.org = None
        self.locality = None
        self.state = None
        self.country = None
        self.matchExactly = None
        self.status = None
        self.revokedBy = None
        self.revokedOnFrom = None
        self.revokedOnTo = None
        self.revocationReason = None
        self.issuedBy = None
        self.issuedOnFrom = None
        self.issuedOnTo = None
        self.validNotBeforeFrom = None
        self.validNotBeforeTo = None
        self.validNotAfterFrom = None
        self.validNotAfterTo = None
        self.validityOperation = None
        self.validityCount = None
        self.validityUnit = None
        self.certTypeSubEmailCA = None
        self.certTypeSubSSLCA = None
        self.certTypeSecureEmail = None
        self.certTypeSSLClient = None
        self.certTypeSSLServer = None
        self.revokedByInUse = False
        self.revokedOnInUse = False
        self.revocationReasonInUse = None
        self.issuedByInUse = False
        self.issuedOnInUse = False
        self.validNotBeforeInUse = False
        self.validNotAfterInUse = False
        self.validityLengthInUse = False
        self.certTypeInUse = False


class CertResource(object):
    '''
    Class encapsulating and mirroring the functionality in the CertResouce Java interface class
    defining the REST API for Certificate resources.
    '''

    def __init__(self, connection):
        ''' Constructor '''
        #super(PKIResource, self).__init__(connection)
        self.connection = connection
        self.headers = {'Content-type': 'application/json',
                        'Accept': 'application/json'}
        self.cert_url = '/rest/certs'
        self.agent_cert_url = '/rest/agent/certs'

    def getCert(self, cert_id):
        ''' Return a CertData object for a particular certificate. '''
        url = self.cert_url + '/' + str(cert_id.id)
        response = self.connection.get(url, self.headers)
        e.TYPES['CertData'] = CertData()
        certData = e.CustomTypeDecoder(response.json())
        return certData

    def listCerts(self, status = None):
        ''' Return a CertDataInfos object for specific certs
            Not sure I understand what this method is for.
        '''
        if status is not None:
            cert_search_request =  CertSearchRequest()
            cert_search_request.status = status

        response = self.connection.get(self.cert_url, self.headers)
        print response.json()

    def searchCerts(self, cert_search_request):
        ''' Return a CertDataInfos object containing the results of a cert search.'''
        url = self.cert_url + '/search'
        e.TYPES['CertSearchRequest'] = CertSearchRequest
        searchRequest = json.dumps(cert_search_request, cls=e.CustomTypeEncoder)
        r = self.connection.post(url, searchRequest, self.headers)
        print r.json()['CertDataInfos']
        cdis = CertDataInfos()
        cdis.decode_from_json(r.json()['CertDataInfos'])
        return cdis

    def getCerts(self, cert_search_request):
        ''' Doctring needed here. '''
        pass

    def reviewCert(self, cert_id):
        ''' Doc string needed here. '''
        pass

    def revokeCert(self, cert_id, cert_revoke_request):
        ''' Doc string needed here '''
        pass

    def revokeCACert(self, cert_id, cert_revoke_request):
        ''' Doc string needed here. '''
        pass

    def unrevokecert(self, cert_id, cert_unrevoke_request):
        ''' Doc string needed here '''
        pass


    def get_transport_cert(self):
        ''' Return transport certificate '''
        url = '/rest/config/cert/transport'
        response = self.connection.get(url, self.headers)
        certData = CertData()
        certData.Encoded = response.json()['Encoded']
        return certData.Encoded

def main():
    connection = client.PKIConnection('http', 'localhost', '8080', 'ca')
    connection.authenticate('caadmin', 'Secret123')
    certResource = CertResource(connection)
    cert = certResource.getCert(CertId('0x6'))
    print cert

if __name__ == "__main__":
    main()
