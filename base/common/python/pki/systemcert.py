#!/usr/bin/python
# Authors:
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
"""
Module containing the Python client classes for the SystemCert REST API
"""
from __future__ import absolute_import
import base64
import pki
from pki.cert import CertData


class SystemCertClient(object):
    """
    Class encapsulating and mirroring the functionality in the
    SystemCertResource Java interface class defining the REST API for
    system certificate resources.
    """

    def __init__(self, connection):
        """ Constructor """
        # super(PKIResource, self).__init__(connection)
        self.connection = connection
        self.headers = {'Content-type': 'application/json',
                        'Accept': 'application/json'}
        self.cert_url = '/rest/config/cert'

    @pki.handle_exceptions()
    def get_transport_cert(self):
        """
        Return transport certificate.

        :return: pki.cert.CertData -- transport certificate data
        """
        url = self.cert_url + '/transport'
        response = self.connection.get(url, self.headers)
        cert_data = CertData.from_json(response.json())

        pem = cert_data.encoded
        b64 = pem[len(pki.CERT_HEADER):len(pem) - len(pki.CERT_FOOTER)]
        cert_data.binary = base64.decodestring(b64)

        return cert_data
