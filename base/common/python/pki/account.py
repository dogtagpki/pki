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

import inspect
import json
import logging

import pki

logger = logging.getLogger(__name__)


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

    def __init__(self, parent, subsystem=None):
        """
        Creates an AccountClient for the connection.

        :param parent: PKIClient object
        :type parent: pki.client.PKIClient
        :returns: AccountClient
        """

        if isinstance(parent, pki.client.PKIConnection):

            logger.warning(
                '%s:%s: The PKIConnection parameter in AccountClient.__init__() '
                'has been deprecated. Provide SubsystemClient instead.',
                inspect.stack()[1].filename, inspect.stack()[1].lineno)

            self.subsystem_client = None
            self.pki_client = None
            self.connection = parent

            # in legacy code the subsystem name is specified in AccountClient
            # in PKIConnection
            if subsystem:
                self.subsystem_name = subsystem
            elif self.connection.subsystem:
                self.subsystem_name = self.connection.subsystem
            else:
                raise Exception('Missing subsystem for AccountClient')

        else:
            self.subsystem_client = parent
            self.pki_client = self.subsystem_client.parent
            self.connection = self.pki_client.connection

            # in newer code the subsystem name is specified in subsystem client
            # (e.g. CAClient, KRAClient)
            self.subsystem_name = self.subsystem_client.name

    @pki.handle_exceptions()
    def login(self):
        """
        Login to account REST interface.  If login is successful,
        an authentication session variable is associated with the connection.

        :returns: None
        """

        if self.pki_client:
            api_path = self.pki_client.get_api_path()
        else:
            api_path = 'v2'

        path = '/%s/account/login' % api_path

        # in legacy code the PKIConnection object might already have the subsystem name
        # in newer code the subsystem name needs to be included in the path
        if not self.connection.subsystem:
            path = '/' + self.subsystem_name + path

        response = self.connection.get(path)

        json_response = response.json()
        logger.debug('Response:\n%s', json.dumps(json_response, indent=4))

        # TODO: return Account object instead of JSON/XML
        return json_response

    @pki.handle_exceptions()
    def logout(self):
        """
        Logs out of the session.  Authentication session variables are
        invalidated for the connection

        :returns: None
        """

        if self.pki_client:
            api_path = self.pki_client.get_api_path()
        else:
            api_path = 'v2'

        path = '/%s/account/logout' % api_path

        # in legacy code the PKIConnection object might already have the subsystem name
        # in newer code the subsystem name needs to be included in the path
        if not self.connection.subsystem:
            path = '/' + self.subsystem_name + path

        self.connection.get(path)
