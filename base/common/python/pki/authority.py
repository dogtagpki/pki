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
# Author:
#     Ade Lee <alee@redhat.com>

from __future__ import absolute_import
from __future__ import print_function

import json
from six import iteritems
import uuid

import pki
import pki.client as client
import pki.encoder as encoder
import pki.cert as cert


class AuthorityData(object):
    """
    Class containing authority data to be sent to/from the server when
    getting or creating subordinate CAs
    """

    json_attribute_names = {
        'id': 'aid',
        'description': 'description',
        'dn': 'dn',
        'enabled': 'enabled',
        'isHostAuthority': 'is_host_authority',
        'link': 'link',
        'parentID': 'parent_aid'
    }

    def __init__(self, dn=None, aid=None, parent_aid=None,
                 description=None, enabled="False",
                 is_host_authority="False", link=None):
        self.dn = dn
        self.aid = aid
        self.parent_aid = parent_aid
        self.description = description
        self.enabled = (enabled.lower() == "true")
        self.is_host_authority = (is_host_authority.lower() == "true")
        self.link = link

    def __repr__(self):
        attributes = {
            "AuthorityData": {
                "aid": self.aid,
                "dn": self.dn,
                "description": self.description,
                "is_host_authority": self.is_host_authority,
                "parent_aid": self.parent_aid,
                "enabled": self.enabled
            }
        }
        return str(attributes)

    @classmethod
    def from_json(cls, attr_list):
        """ Return AuthorityData object from JSON dict """
        ca_data = cls()

        for k, v in iteritems(attr_list):
            if k not in ['link']:
                if k in AuthorityData.json_attribute_names:
                    setattr(ca_data, AuthorityData.json_attribute_names[k], v)
                else:
                    setattr(ca_data, k, v)

        if 'link' in attr_list:
            ca_data.link = pki.Link.from_json(attr_list['link'])

        return ca_data


class AuthorityDataCollection(object):
    """
    Class containing list of AuthorityData objects and their respective link
    objects.
    This data is returned when searching/listing authorities.
    """

    def __init__(self):
        """ Constructor """
        self.ca_list = []
        self.links = []

    def __iter__(self):
        return iter(self.ca_list)

    @classmethod
    def from_json(cls, json_value):
        """ Populate object from JSON input """
        ret = cls()
        cas = json_value
        if not isinstance(cas, list):
            ret.ca_list.append(AuthorityData.from_json(cas))
        else:
            for ca in cas:
                ret.ca_list.append(
                    AuthorityData.from_json(ca))

        return ret


class AuthorityClient(object):
    """
    Class encapsulating and mirroring the functionality in the
    AuthorityResource Java interface class defining the REST API for
    subordinate CA (authority) resources.
    """

    def __init__(self, connection):
        """ Constructor """
        self.connection = connection
        self.ca_url = '/rest/authorities'

    @pki.handle_exceptions()
    def get_ca(self, aid):
        """ Return a AuthorityData object for a subordinate CA. """
        if aid is None:
            raise ValueError("Subordinate aid must be specified")

        url = self.ca_url + '/' + str(aid)
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}
        r = self.connection.get(url, headers)
        return AuthorityData.from_json(r.json())

    @pki.handle_exceptions()
    def get_cert(self, aid, output_format="PEM"):
        """Return the signing certificate for the CA

        :param aid: ID for the CA
        :param output_format: either 'PEM' or 'DER'
        :return: CA certificate in relevant format
        """
        """ Return the signing certificate for the CA. """
        if aid is None:
            raise ValueError("CA ID must be specified")

        url = '{}/{}/cert'.format(self.ca_url, str(aid))

        headers = {'Content-type': 'application/json'}

        if output_format == "PEM":
            headers['Accept'] = "application/x-pem-file"
        elif output_format == "DER":
            headers['Accept'] = "application/pkix-cert"
        else:
            raise ValueError(
                "Invalid format passed in - PEM or DER expected.")

        r = self.connection.get(url, headers)
        return r.text

    @pki.handle_exceptions()
    def get_chain(self, aid, output_format="PKCS7"):
        """Returns the certificate chain for the CA.

        :param aid: ID for the CA
        :param output_format: either PEM or PKCS7
        :return: CA certificate chain in requested format
        """
        if aid is None:
            raise ValueError("CA ID must be specified")

        url = '{}/{}/chain'.format(self.ca_url, str(aid))

        headers = {'Content-type': 'application/json'}
        if output_format == "PEM":
            headers['Accept'] = "application/x-pem-file"
        elif output_format == "PKCS7":
            headers['Accept'] = "application/pkcs7-mime"

        r = self.connection.get(url, headers)
        return r.text

    @pki.handle_exceptions()
    def list_cas(self, max_results=None, max_time=None, start=None, size=None):
        """ Return a AuthorityDataCollection object of subordinate CAs

        Right now, this is going to list all the defined authorities.  We will
        add search criteria when this is defined on the Java interface.
        """
        query_params = {"maxResults": max_results, "maxTime": max_time,
                        "start": start, "size": size}
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}
        response = self.connection.get(
            path=self.ca_url,
            headers=headers,
            params=query_params)
        return AuthorityDataCollection.from_json(response.json())

    @pki.handle_exceptions()
    def create_ca(self, ca_data):
        """ Create authority (subCA)
        :param ca_data: AuthorityData object containing parameters that
            describe how a subordinate authority should be constructed.
        :return: AuthorityData object for the created subordinate CA
        """
        if ca_data is None:
            raise ValueError("ca_data must be defined")

        if ca_data.dn is None:
            raise ValueError("Subject DN must be defined in ca_data")

        if ca_data.description is None:
            raise ValueError('Description must be defined in ca_data')

        if ca_data.parent_aid is None:
            raise ValueError('parent_aid must be defined.  '
                             'Top level CAs are not yet supported')

        create_request = json.dumps(ca_data, cls=encoder.CustomTypeEncoder,
                                    sort_keys=True)

        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}

        response = self.connection.post(
            self.ca_url,
            create_request,
            headers)

        new_ca = AuthorityData.from_json(response.json())
        return new_ca

    @pki.handle_exceptions()
    def enable_ca(self, aid):
        """Enable the specified CA
        :param aid: ID of the CA to be enabled
        :return: None
        """
        if aid is None:
            raise ValueError("CA ID must be specified")

        url = '{}/{}/enable'.format(self.ca_url, str(aid))

        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}

        self.connection.post(url, headers)

    @pki.handle_exceptions()
    def disable_ca(self, aid):
        """Disable the specified CA
        :param aid: ID of the CA to be disabled
        :return: None
        """
        if aid is None:
            raise ValueError("CA ID must be specified")

        url = '{}/{}/disable'.format(self.ca_url, str(aid))
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}

        self.connection.post(url, headers)


encoder.NOTYPES['AuthorityData'] = AuthorityData


def issue_cert_using_authority(cert_client, authority_id):
    print("Issuing Cert using subordinate CA")
    print("---------------------------------")
    print("aid: " + authority_id)

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

    enrollment_results = cert_client.enroll_cert(
        'caUserCert', inputs, authority_id)

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


def main():
    # Create a PKIConnection object that stores the details of the CA.
    connection = client.PKIConnection('https', 'localhost', '8453', 'ca')

    # The pem file used for authentication. Created from a p12 file using the
    # command -
    # openssl pkcs12 -in <p12_file_path> -out /tmp/auth.pem -nodes
    connection.set_authentication_cert("/tmp/auth.pem")

    # Instantiate the CertClient
    ca_client = AuthorityClient(connection)

    # Create a top level authority
    print("Creating a new top level CA")
    print("-----------------------------")

    subca_subject = ('cn=subca ' + str(uuid.uuid4()) +
                     ' signing cert, o=example.com')

    sub_subca_subject = ('cn=subca2 ' + str(uuid.uuid4()) +
                         ' signing cert, o=example.com')
    authority_data = {
        'dn': subca_subject,
        'description': 'Test Top-level subordinate CA',
    }
    data = AuthorityData(**authority_data)
    try:
        subca = ca_client.create_ca(data)
    except ValueError as e:
        print(e.message)

    # Get the host CA
    print("Getting the host CA")
    print("----------------------")
    authorities = ca_client.list_cas()
    for ca in authorities.ca_list:
        if ca.is_host_authority:
            host_ca = ca

    print(str(host_ca))

    # Create a sub CA
    print("Creating a new subordinate CA")
    print("-----------------------------")

    authority_data = {
        'dn': subca_subject,
        'description': 'Test subordinate CA',
        'parent_aid': host_ca.aid
    }
    data = AuthorityData(**authority_data)
    subca = ca_client.create_ca(data)
    print(ca_client.get_ca(subca.aid))

    # Get the authority signing cert and pkcs7 chain
    pem_cert = ca_client.get_cert(subca.aid, "PEM")
    print("PEM CA Signing Cert:")
    print(pem_cert)

    pkcs7_chain = ca_client.get_chain(subca.aid, "PKCS7")
    print("PKCS7 Cert Chain:")
    print(pkcs7_chain)

    pem_chain = ca_client.get_chain(subca.aid, "PEM")
    print("PEM Cert Chain:")
    print(pem_chain)

    # List all authorities
    print("Listing all authorities")
    print("-----------------------")
    authorities = ca_client.list_cas()
    for ca in authorities.ca_list:
        print(str(ca))

    # Issue a cert using the sub-CA
    cert_client = cert.CertClient(connection)
    issue_cert_using_authority(cert_client, subca.aid)

    # Create a sub-sub CA
    print('Create a sub-sub CA')
    print('-------------------')
    sub_subca_data = {
        'dn': sub_subca_subject,
        'description': 'Test sub-sub CA',
        'parent_aid': subca.aid
    }

    data = AuthorityData(**sub_subca_data)
    sub_subca = ca_client.create_ca(data)
    print(ca_client.get_ca(sub_subca.aid))

    # Get the authority signing cert and PKCS7
    # Get the authority signing cert and pkcs7 chain
    pem_cert = ca_client.get_cert(sub_subca.aid, "PEM")
    print("PEM CA Signing Cert:")
    print(pem_cert)

    pkcs7_chain = ca_client.get_chain(sub_subca.aid, "PKCS7")
    print("PKCS7 Cert Chain:")
    print(pkcs7_chain)

    pem_chain = ca_client.get_chain(sub_subca.aid, "PEM")
    print("PEM Cert Chain:")
    print(pem_chain)

    # issue a cert using the sub-subca
    cert_client = cert.CertClient(connection)
    issue_cert_using_authority(cert_client, sub_subca.aid)

    # disable the sub-subca
    print("Disable sub sub CA")
    ca_client.disable_ca(sub_subca.aid)

    # Get sub-subca
    sub_subca = ca_client.get_ca(sub_subca.aid)
    print(str(sub_subca))

    # issue a cert using sub-subca
    issue_cert_using_authority(cert_client, sub_subca.aid)


if __name__ == "__main__":
    main()
