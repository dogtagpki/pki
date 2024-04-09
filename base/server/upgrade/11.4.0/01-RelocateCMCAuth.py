# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging

import pki

logger = logging.getLogger(__name__)


class RelocateCMCAuth(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super().__init__()
        self.message = 'Relocate CMCAuth'

    def upgrade_subsystem(self, instance, subsystem):

        self.backup(subsystem.cs_conf)

        if subsystem.name == 'ca':
            # create CMCAuth instance in CA
            param = 'auths.instance.CMCAuth.pluginName'
            logger.info('Adding %s', param)
            subsystem.set_config(param, 'CMCAuth')

        else:
            # don't register CMCAuth plugin in other subsystems
            param = 'auths.impl.CMCAuth.class'
            logger.info('Removing %s', param)
            subsystem.config.pop(param, None)

        subsystem.save()
