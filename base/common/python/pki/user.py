#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import json
import logging

logger = logging.getLogger(__name__)


class UserClient:

    def __init__(self, parent):

        self.subsystem_client = parent
        self.pki_client = self.subsystem_client.parent
        self.connection = self.pki_client.connection

    def find_users(self):

        api_path = self.pki_client.get_api_path()

        # the UserClient doesn't support legacy code so the subsystem name
        # needs to be included in the path
        path = '/%s/%s/admin/users' % (self.subsystem_client.name, api_path)

        logger.info('Getting %s users from %s', self.subsystem_client.name.upper(), path)

        response = self.connection.get(path)

        json_response = response.json()
        logger.debug('Response:\n%s', json.dumps(json_response, indent=4))

        # TODO: return UserCollection object instead of JSON/XML
        return json_response
