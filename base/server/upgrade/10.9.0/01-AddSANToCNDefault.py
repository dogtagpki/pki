# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import absolute_import
import logging

import pki

logger = logging.getLogger(__name__)


class AddSANToCNDefault(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(AddSANToCNDefault, self).__init__()
        self.message = 'Add SANToCNDefault policy'

    def upgrade_subsystem(self, instance, subsystem):

        if subsystem.name != 'ca':
            return

        self.backup(subsystem.registry_conf)

        logger.info('Adding sanToCNDefaultImpl into defaultPolicy.ids')
        id_list = subsystem.registry.get('defaultPolicy.ids').split(',')
        if 'sanToCNDefaultImpl' not in id_list:
            id_list.append('sanToCNDefaultImpl')
            subsystem.registry['defaultPolicy.ids'] = ','.join(id_list)

        logger.info('Adding defaultPolicy.sanToCNDefaultImpl.name')
        subsystem.registry['defaultPolicy.sanToCNDefaultImpl.name'] = 'SAN to CN Default'

        logger.info('Adding defaultPolicy.sanToCNDefaultImpl.desc')
        subsystem.registry['defaultPolicy.sanToCNDefaultImpl.desc'] = 'SAN to CN Default'

        logger.info('Adding defaultPolicy.sanToCNDefaultImpl.class')
        subsystem.registry['defaultPolicy.sanToCNDefaultImpl.class'] = \
            'com.netscape.cms.profile.def.SANToCNDefault'

        subsystem.save()
