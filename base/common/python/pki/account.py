# Authors:
#     Endi S. Dewata <edewata@redhat.com>
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

    def __init__(self, connection, subsystem=None):
        """
        Creates an AccountClient for the connection.

        :param connection: connection to be associated with the AccountClient
        :type connection: pki.PKIConnection
        :returns: AccountClient
        """

        self.connection = connection

        self.login_url = '/rest/account/login'
        self.logout_url = '/rest/account/logout'

        if connection.subsystem is None:

            if subsystem is None:
                raise Exception('Missing subsystem for AccountClient')

            self.login_url = '/' + subsystem + self.login_url
            self.logout_url = '/' + subsystem + self.logout_url

    @pki.handle_exceptions()
    def login(self):
        """
        Login to account REST interface.  If login is successful,
        an authentication session variable is associated with the connection.

        :returns: None
        """
        self.connection.get(self.login_url)

    @pki.handle_exceptions()
    def logout(self):
        """
        Logs out of the session.  Authentication session variables are
        invalidated for the connection

        :returns: None
        """
        self.connection.get(self.logout_url)
