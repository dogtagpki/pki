# Authors:
#     Abhishek Koneru <akoneru@redhat.com>
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
Module containing KRAClient class.  This class should be used by Python clients
to interact with the DRM to expose the functionality of the KeyClient and
KeyRequestResource REST APIs.
"""

import inspect
import logging

import pki.client
import pki.info
import pki.key
import pki.subsystem
import pki.systemcert

logger = logging.getLogger(__name__)


class KRAClient(pki.subsystem.SubsystemClient):
    """
    Client class that models interactions with a KRA using the Key and
    KeyRequest REST APIs.
    """

    def __init__(self, parent, crypto=None, transport_cert_nick=None):
        """ Constructor

        :param connection - PKIConnection object with DRM connection info.
        :param crypto - CryptoProvider object.
        :param transport_cert_nick - identifier for the DRM transport
                        certificate.  This will be passed to the
                        CryptoProvider.get_cert() command to get a
                        representation of the transport certificate usable for
                        crypto ops.

                        Note that for NSS databases, the database must have
                        been initialized beforehand.
        """

        super().__init__(parent, 'kra')

        if isinstance(parent, pki.client.PKIConnection):

            logger.warning(
                '%s:%s: The PKIConnection parameter in KRAClient.__init__() has been deprecated. '
                'Provide PKIClient instead.',
                inspect.stack()[1].filename, inspect.stack()[1].lineno)

            self.connection = parent

            self.crypto = crypto
            self.info = pki.info.InfoClient(self.connection)

            self.keys = pki.key.KeyClient(
                self.connection,
                crypto,
                transport_cert_nick,
                self.info)

            self.system_certs = pki.systemcert.SystemCertClient(self.connection)

        else:
            self.connection = parent.connection

            # do not automatically create these objects in KRAClient.
            # client application should create them as needed.
            self.crypto = None
            self.info = None
            self.keys = None
            self.system_certs = None
