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

        self.backup(subsystem.cs_conf)

        logger.info('Removing subsystem.select')
        subsystem.config.pop('subsystem.select', None)

        logger.info('Removing hierarchy.select')
        subsystem.config.pop('hierarchy.select', None)

        logger.info('Removing service.securityDomainPort')
        subsystem.config.pop('service.securityDomainPort', None)

        subsystem.save()
