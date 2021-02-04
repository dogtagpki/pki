# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import absolute_import
import logging
import os

import pki

logger = logging.getLogger(__name__)


class FixACMEProfileAuth(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(FixACMEProfileAuth, self).__init__()
        self.message = 'Fix the authentication for acmeServerCert profile'

    def upgrade_subsystem(self, instance, subsystem):

        if subsystem.name != 'ca':
            return

        path = os.path.join(subsystem.base_dir, 'profiles', 'ca', 'acmeServerCert.cfg')
        self.backup(path)

        config = {}

        logger.info('Loading %s', path)
        pki.util.load_properties(path, config)

        config.pop('auth.class_id', None)

        config['auth.instance_id'] = 'SessionAuthentication'
        config['authz.acl'] = 'group=Certificate Manager Agents'

        logger.info('Storing %s', path)
        pki.util.store_properties(path, config)
