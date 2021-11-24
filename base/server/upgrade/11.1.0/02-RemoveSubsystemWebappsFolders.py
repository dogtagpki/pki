#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
from __future__ import absolute_import
import logging
import os
import shutil

import pki.server.upgrade

logger = logging.getLogger(__name__)


class RemoveSubsystemWebappsFolders(
        pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(RemoveSubsystemWebappsFolders, self).__init__()
        self.message = 'Remove subsystem webapps folders'

    def upgrade_subsystem(self, instance, subsystem):

        webapps_dir = os.path.join(instance.base_dir, subsystem.name, 'webapps')

        if not os.path.isdir(webapps_dir):
            return

        logger.info('Removing %s', webapps_dir)

        self.backup(webapps_dir)

        shutil.rmtree(webapps_dir)
