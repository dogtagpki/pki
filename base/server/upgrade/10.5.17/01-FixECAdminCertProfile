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


class FixECAdminCertProfile(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(FixECAdminCertProfile, self).__init__()
        self.message = 'Fix EC admin certificate profile'

    def upgrade_subsystem(self, instance, subsystem):

        if subsystem.name != 'ca':
            return

        self.backup(subsystem.cs_conf)

        path = subsystem.config.get('profile.caECAdminCert.config')
        logger.info('Current path: %s', path)

        dirname = os.path.dirname(path)

        path = os.path.join(dirname, 'caECAdminCert.cfg')
        logger.info('New path: %s', path)

        subsystem.config['profile.caECAdminCert.config'] = path
        subsystem.save()
