# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging

import pki

logger = logging.getLogger(__name__)


class RemoveUnusedCMCParams(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super().__init__()
        self.message = 'Remove unused CMC params'

    def upgrade_subsystem(self, instance, subsystem):

        if subsystem.name == 'ca':
            return

        self.backup(subsystem.cs_conf)

        param = 'cmc.cert.confirmRequired'
        logger.info('Removing %s', param)
        subsystem.config.pop(param, None)

        param = 'cmc.lraPopWitness.verify.allow'
        logger.info('Removing %s', param)
        subsystem.config.pop(param, None)

        param = 'cmc.revokeCert.verify'
        logger.info('Removing %s', param)
        subsystem.config.pop(param, None)

        param = 'cmc.revokeCert.sharedSecret.class'
        logger.info('Removing %s', param)
        subsystem.config.pop(param, None)

        param = 'cmc.sharedSecret.class'
        logger.info('Removing %s', param)
        subsystem.config.pop(param, None)

        subsystem.save()
