# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import re

import pki

logger = logging.getLogger(__name__)


class RemoveUnusedParams(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super().__init__()
        self.message = 'Remove unused params'

    def upgrade_subsystem(self, instance, subsystem):

        self.backup(subsystem.cs_conf)

        for name in list(subsystem.config.keys()):

            remove = False

            if re.match(r'pkicreate\.', name):
                remove = True

            elif re.match(r'pkiremove\.', name):
                remove = True

            elif re.match(r'os\.', name):
                remove = True

            elif re.match(r'tokendb\.hostport$', name):
                remove = True

            if not remove:
                continue

            logger.info('Removing %s', name)
            subsystem.config.pop(name, None)

        subsystem.save()
