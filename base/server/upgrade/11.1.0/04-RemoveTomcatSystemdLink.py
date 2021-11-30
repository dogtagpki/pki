#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
from __future__ import absolute_import
import logging
import os

import pki.server.upgrade

logger = logging.getLogger(__name__)


class RemoveTomcatSystemdLink(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super().__init__()
        self.message = 'Remove systemd link'

    def upgrade_instance(self, instance):

        systemd_link = os.path.join(instance.base_dir, instance.name)
        if not os.path.islink(systemd_link):
            return

        logger.info('Removing %s', systemd_link)

        self.backup(systemd_link)
        pki.util.unlink(systemd_link)
