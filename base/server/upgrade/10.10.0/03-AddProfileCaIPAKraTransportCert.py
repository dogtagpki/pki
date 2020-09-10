# Authors:
#     Christina Fu <cfu@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import absolute_import
import logging
import os

import pki

logger = logging.getLogger(__name__)


class AddProfileCaIPAKraTransportCert(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(AddProfileCaIPAKraTransportCert, self).__init__()
        self.message = 'Add caIPAKraTransportCert profile'

    def upgrade_subsystem(self, instance, subsystem):

        if subsystem.name != 'ca':
            return

        path = os.path.join(subsystem.base_dir, 'profiles', 'ca', 'caIPAKraTransportCert.cfg')

        if not os.path.exists(path):
            logger.info('Creating caIPAKraTransportCert.cfg')
            self.backup(path)
            instance.copyfile('/usr/share/pki/ca/profiles/ca/caIPAKraTransportCert.cfg', path)

        logger.info('Adding caIPAKraTransportCert into profile.list')
        profile_list = subsystem.config.get('profile.list').split(',')
        if 'caIPAKraTransportCert' not in profile_list:
            profile_list.append('caIPAKraTransportCert')
            profile_list.sort()
            subsystem.config['profile.list'] = ','.join(profile_list)

        logger.info('Adding profile.caIPAKraTransportCert.class_id')
        subsystem.config['profile.caIPAKraTransportCert.class_id'] = 'caEnrollImpl'

        logger.info('Adding profile.caIPAKraTransportCert.config')
        subsystem.config['profile.caIPAKraTransportCert.config'] = path

        self.backup(subsystem.cs_conf)
        subsystem.save()
