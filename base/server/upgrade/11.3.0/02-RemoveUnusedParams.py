# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import pki

logger = logging.getLogger(__name__)


class RemoveUnusedParams(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super().__init__()
        self.message = 'Remove unused params'

    def upgrade_subsystem(self, instance, subsystem):

        if subsystem.name != 'tps':
            return

        self.backup(subsystem.cs_conf)

        logger.info('Remove tokendb.hostport')
        subsystem.config.pop('tokendb.hostport', None)

        subsystem.save()
