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

import inspect
import json
import logging

import pki
from pki.cert import CertData
from pki.encoder import decode_cert

logger = logging.getLogger(__name__)


class SystemCertClient(object):
    """
    Class encapsulating and mirroring the functionality in the
    SystemCertResource Java interface class defining the REST API for
    system certificate resources.
    """

    def __init__(self, parent, subsystem=None):
        """ Constructor """
        # super(PKIResource, self).__init__(connection)

        if isinstance(parent, pki.client.PKIConnection):

            logger.warning(
                '%s:%s: The PKIConnection parameter in SystemCertClient.__init__() '
                'has been deprecated. Provide SubsystemClient instead.',
                inspect.stack()[1].filename, inspect.stack()[1].lineno)

            self.subsystem_client = None
            self.pki_client = None
            self.connection = parent

            if subsystem:
                self.subsystem_name = subsystem
            elif self.connection.subsystem:
                self.subsystem_name = self.connection.subsystem
            else:
                self.subsystem_name = 'kra'

        else:
            self.subsystem_client = parent
            self.pki_client = self.subsystem_client.parent
            self.connection = self.pki_client.connection

            self.subsystem_name = self.subsystem_client.name

        self.headers = {'Content-type': 'application/json',
                        'Accept': 'application/json'}

    @pki.handle_exceptions()
    def get_transport_cert(self):
        """
        Return transport certificate.

        :return: pki.cert.CertData -- transport certificate data
        """

        if self.pki_client:
            api_path = self.pki_client.get_api_path()
        else:
            api_path = 'v2'

        path = '/%s/config/cert/transport' % api_path

        if not self.connection.subsystem:
            path = '/' + self.subsystem_name + path

        response = self.connection.get(path, self.headers)

        json_response = response.json()
        logger.debug('Response:\n%s', json.dumps(json_response, indent=4))

        cert_data = CertData.from_json(json_response)

        pem = cert_data.encoded
        # pylint: disable=E0012,E1136
        b64 = pem[len(pki.CERT_HEADER):len(pem) - len(pki.CERT_FOOTER)]
        cert_data.binary = decode_cert(b64)

        return cert_data
