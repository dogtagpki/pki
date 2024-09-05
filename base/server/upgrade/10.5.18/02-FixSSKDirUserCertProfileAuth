# Authors:
#     Christina Fu <cfu@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import absolute_import
import logging
import os

import pki

logger = logging.getLogger(__name__)


class FixSSKDirUserCertProfileAuth(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(FixSSKDirUserCertProfileAuth, self).__init__()
        self.message = 'Fix the authentication for caServerKeygen_UserCert profile'

    def upgrade_subsystem(self, instance, subsystem):

        if subsystem.name != 'ca':
            return

        path = os.path.join(subsystem.base_dir, 'profiles', 'ca', 'caServerKeygen_UserCert.cfg')
        self.backup(path)

        config = {}

        logger.info('Loading %s', path)
        pki.util.load_properties(path, config)

        config['input.list'] = 'i1'
        config.pop('input.i2.class_id', None)
        config.pop('input.i3.class_id', None)
        config['policyset.userCertSet.1.default.class_id'] = 'authTokenSubjectNameDefaultImpl'
        config['policyset.userCertSet.8.default.params.subjAltExtPattern_0'] = \
            '$request.auth_token.mail[0]$'

        logger.info('Storing %s', path)
        pki.util.store_properties(path, config)
