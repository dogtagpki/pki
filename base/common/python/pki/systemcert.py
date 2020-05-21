# Authors:
#     Ade Lee <alee@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the Lesser GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2013 Red Hat, Inc.
# All rights reserved.
#
"""
Module containing the Python client classes for the SystemCert REST API
"""
from __future__ import absolute_import

import pki
from pki.cert import CertData
from pki.encoder import decode_cert


class SystemCertClient(object):
    """
    Class encapsulating and mirroring the functionality in the
    SystemCertResource Java interface class defining the REST API for
    system certificate resources.
    """

    def __init__(self, connection, subsystem=None):
        """ Constructor """
        # super(PKIResource, self).__init__(connection)

        self.connection = connection

        self.cert_url = '/rest/config/cert'

        if subsystem:
            self.cert_url = '/' + subsystem + self.cert_url
        elif connection.subsystem is None:
            self.cert_url = '/ca' + self.cert_url

        self.headers = {'Content-type': 'application/json',
                        'Accept': 'application/json'}

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
        # pylint: disable=E0012,E1136
        b64 = pem[len(pki.CERT_HEADER):len(pem) - len(pki.CERT_FOOTER)]
        cert_data.binary = decode_cert(b64)

        return cert_data
