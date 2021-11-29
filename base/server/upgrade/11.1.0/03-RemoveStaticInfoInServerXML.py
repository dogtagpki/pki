#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
from __future__ import absolute_import
import logging

import pki.server.upgrade

logger = logging.getLogger(__name__)


class RemoveStaticInfoInServerXML(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super().__init__()
        self.message = 'Remove static info in server.xml'

    def upgrade_instance(self, instance):

        logger.info('Updating %s', instance.server_xml)
        self.backup(instance.server_xml)

        with open(instance.server_xml) as f:
            lines = f.readlines()

        lines = [line.rstrip() for line in lines]
        new_lines = []
        remove = False

        # Remove everything between these lines:
        # <!-- DO NOT REMOVE - Begin PKI Status Definitions -->
        # ...
        # <!-- DO NOT REMOVE - End PKI Status Definitions -->

        for line in lines:

            if line == '<!-- DO NOT REMOVE - Begin PKI Status Definitions -->':
                remove = True

            elif line == '<!-- DO NOT REMOVE - End PKI Status Definitions -->':
                remove = False

            elif not remove:
                new_lines.append(line)

        with open(instance.server_xml, 'w') as f:
            for line in new_lines:
                f.write("%s\n" % line)
