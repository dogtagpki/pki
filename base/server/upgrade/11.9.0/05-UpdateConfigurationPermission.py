# Authors:
#     Marco Fargetta <mfargett@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import os

import pki

logger = logging.getLogger(__name__)


class UpdateConfigurationPermission(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super().__init__()
        self.message = 'Update permission for configuration files'

    def upgrade_subsystem(self, instance, subsystem):

        if subsystem.name == 'acme':
            return

        logger.info('Update configuration file permissions for %s', subsystem.name)
        os.chmod(subsystem.cs_conf, pki.server.DEFAULT_FILE_MODE)
        os.chmod(subsystem.registry_conf, pki.server.DEFAULT_FILE_MODE)

        if subsystem.name == 'est':
            os.chmod(subsystem.realm_conf, pki.server.DEFAULT_FILE_MODE)
