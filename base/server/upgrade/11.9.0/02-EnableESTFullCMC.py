#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
import logging

import pki

logger = logging.getLogger(__name__)


class EnableESTFullCMC(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super().__init__()
        self.message = 'Enable EST fullcmc support'

    def upgrade_subsystem(self, instance, subsystem):
        if subsystem.name != 'est':
            return

        logger.info('Update EST backend configuration for fullcmc support')
        self.update_est_backend_conf(subsystem)

    def update_est_backend_conf(self, subsystem):
        """Add fullcmc.profile configuration to EST backend.conf"""
        config = subsystem.get_backend_config()

        if 'fullcmc.profile' in config:
            logger.info('fullcmc.profile already configured in backend.conf')
            return

        self.backup(subsystem.backend_conf)
        config['fullcmc.profile'] = 'estFullcmcDeviceCert'

        subsystem.update_backend_config(config)
