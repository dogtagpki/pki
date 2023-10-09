# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging

import pki

logger = logging.getLogger(__name__)


class FixSignedAuditParams(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super().__init__()
        self.message = 'Fix malformed signed audit params'

    def upgrade_subsystem(self, instance, subsystem):

        self.backup(subsystem.cs_conf)

        logger.info('Removing malformed signed audit params')
        subsystem.config.pop('log.instance.SignedAudit.signedAudit:_000', None)
        subsystem.config.pop('log.instance.SignedAudit.signedAudit:_001', None)
        subsystem.config.pop('log.instance.SignedAudit.signedAudit:_002', None)
        subsystem.config.pop('log.instance.SignedAudit.signedAudit', None)

        logger.info('Add correct signed audit params')
        subsystem.config['log.instance.SignedAudit.signedAudit._000'] = '##'
        subsystem.config['log.instance.SignedAudit.signedAudit._001'] = \
            '## Fill in the nickname of a trusted signing certificate to allow ' \
            '%s audit logs to be signed' % subsystem.type
        subsystem.config['log.instance.SignedAudit.signedAudit._002'] = '##'

        subsystem.save()
