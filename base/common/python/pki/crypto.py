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
Module containing crypto classes.
"""
import abc
import inspect
import logging


# encryption algorithms OIDs
DES_EDE3_CBC_OID = "{1 2 840 113549 3 7}"
AES_128_CBC_OID = "{2 16 840 1 101 3 4 1 2}"

# Wrap Algorithm names as defined by JSS.
WRAP_AES_CBC_PAD = "AES/CBC/PKCS5Padding"
WRAP_AES_KEY_WRAP = "AES KeyWrap"
WRAP_AES_KEY_WRAP_PAD = "AES KeyWrap/Padding"
WRAP_DES3_CBC_PAD = "DES3/CBC/Pad"

logger = logging.getLogger(__name__)


class CryptoProvider(metaclass=abc.ABCMeta):
    """
    Abstract class containing methods to do cryptographic operations.
    """

    def __init__(self):
        """ Constructor """

    @abc.abstractmethod
    def initialize(self):
        """ Initialization code """


class CryptographyCryptoProvider(CryptoProvider):
    """
    Class that defines python-cryptography implementation of CryptoProvider.
    Requires a PEM file containing the agent cert to be initialized.

    Note that all inputs and outputs are unencoded.
    """

    def __init__(self, transport_cert_nick=None, transport_cert=None,
                 backend=None):
        """ Initialize python-cryptography
        """
        super().__init__()

        if transport_cert_nick:
            logger.warning(
                '%s:%s: The transport_cert_nick parameter in '
                'CryptographyCryptoProvider.__init__() is no longer used.',
                inspect.stack()[1].filename, inspect.stack()[1].lineno)

        if transport_cert:
            logger.warning(
                '%s:%s: The transport_cert parameter in CryptographyCryptoProvider.__init__() '
                'is no longer used.',
                inspect.stack()[1].filename, inspect.stack()[1].lineno)

        if backend:
            logger.warning(
                '%s:%s: The backend parameter in CryptographyCryptoProvider.__init__() '
                'is no longer used.',
                inspect.stack()[1].filename, inspect.stack()[1].lineno)

    def initialize(self):
        """
        Any operations here that need to be performed before crypto
        operations.
        """
