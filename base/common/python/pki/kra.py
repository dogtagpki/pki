#!/usr/bin/python
# Authors:
#     Abhishek Koneru <akoneru@redhat.com>
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
Module containing KRAClient class.  This class should be used by Python clients
to interact with the DRM to expose the functionality of the KeyClient and
KeyRequestResource REST APIs.
"""

from __future__ import absolute_import
import pki.key as key

from pki.systemcert import SystemCertClient


class KRAClient(object):
    """
    Client class that models interactions with a KRA using the Key and
    KeyRequest REST APIs.
    """

    def __init__(self, connection, crypto, transport_cert_nick=None):
        """ Constructor

        :param connection - PKIConnection object with DRM connection info.
        :param crypto - CryptoProvider object.  NSSCryptoProvider is provided by
                        default.  If a different crypto implementation is
                        desired, a different subclass of CryptoProvider must be
                        provided.
        :param transport_cert_nick - identifier for the DRM transport
                        certificate.  This will be passed to the
                        CryptoProvider.get_cert() command to get a representation
                        of the transport certificate usable for crypto ops.
                        Note that for NSS databases, the database must have been
                        initialized beforehand.
        """
        self.connection = connection
        self.crypto = crypto
        self.keys = key.KeyClient(connection, crypto, transport_cert_nick)
        self.system_certs = SystemCertClient(connection)
