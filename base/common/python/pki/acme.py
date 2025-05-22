#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import logging
import pki.subsystem

logger = logging.getLogger(__name__)


class ACMEClient(pki.subsystem.SubsystemClient):

    def __init__(self, parent):
        super().__init__(parent, 'acme')
        self.connection = self.parent.connection
        self.headers = {'Content-type': 'application/json',
                        'Accept': 'application/json'}

    def enable(self):
        path = '/acme/enable'
        response = self.connection.post(path, "", self.headers)
        logger.debug('Enable ACME returned %d', response.status_code)

    def disable(self):
        path = '/acme/disable'
        response = self.connection.post(path, "", self.headers)
        logger.debug('Disable ACME returned %d', response.status_code)
