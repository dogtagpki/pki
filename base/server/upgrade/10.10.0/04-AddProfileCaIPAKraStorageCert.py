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


class AddProfileCaIPAKraStorageCert(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(AddProfileCaIPAKraStorageCert, self).__init__()
        self.message = 'Add caIPAKraStorageCert profile'

    def upgrade_subsystem(self, instance, subsystem):

        if subsystem.name != 'ca':
            return

        path = os.path.join(subsystem.base_dir, 'profiles', 'ca', 'caIPAKraStorageCert.cfg')

        if not os.path.exists(path):
            logger.info('Creating caIPAKraStorageCert.cfg')
            self.backup(path)
            instance.copyfile('/usr/share/pki/ca/profiles/ca/caIPAKraStorageCert.cfg', path)

        logger.info('Adding caIPAKraStorageCert into profile.list')
        profile_list = subsystem.config.get('profile.list').split(',')
        if 'caIPAKraStorageCert' not in profile_list:
            profile_list.append('caIPAKraStorageCert')
            profile_list.sort()
            subsystem.config['profile.list'] = ','.join(profile_list)

        logger.info('Adding profile.caIPAKraStorageCert.class_id')
        subsystem.config['profile.caIPAKraStorageCert.class_id'] = 'caEnrollImpl'

        logger.info('Adding profile.caIPAKraStorageCert.config')
        subsystem.config['profile.caIPAKraStorageCert.config'] = path

        self.backup(subsystem.cs_conf)
        subsystem.save()
