#!/usr/bin/python
# Authors:
#     Endi S. Dewata <edewata@redhat.com>
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
from __future__ import absolute_import
import pki


class AccountClient:
    """
    Class used to associate an authentication session variable with a
    connection.

    To use this class:
       * set the authentication credentials with the connection,
       * create an AccountClient and then call login().
       * further operations in this session will use the same authentication
         credentials without re-authentication.
       * call logout() to invalidate the session.
    """

    def __init__(self, connection):
        """
        Creates an AccountClient for the connection.

        :param connection: connection to be associated with the AccountClient
        :type connection: pki.PKIConnection
        :returns: AccountClient
        """
        self.connection = connection

    @pki.handle_exceptions()
    def login(self):
        """
        Login to account REST interface.  If login is successful,
        an authentication session variable is associated with the connection.

        :returns: None
        """
        self.connection.get('/rest/account/login')

    @pki.handle_exceptions()
    def logout(self):
        """
        Logs out of the session.  Authentication session variables are
        invalidated for the connection

        :returns: None
        """
        self.connection.get('/rest/account/logout')
