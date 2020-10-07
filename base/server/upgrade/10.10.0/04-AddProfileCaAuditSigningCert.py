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


class AddProfileCaAuditSigningCert(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(AddProfileCaAuditSigningCert, self).__init__()
        self.message = 'Add caAuditSigningCert profile'

    def upgrade_subsystem(self, instance, subsystem):

        if subsystem.name != 'ca':
            return

        path = os.path.join(subsystem.base_dir, 'profiles', 'ca', 'caAuditSigningCert.cfg')

        if not os.path.exists(path):
            logger.info('Creating caAuditSigningCert.cfg')
            self.backup(path)
            instance.copyfile('/usr/share/pki/ca/profiles/ca/caAuditSigningCert.cfg', path)

        logger.info('Adding caAuditSigningCert into profile.list')
        profile_list = subsystem.config.get('profile.list').split(',')
        if 'caAuditSigningCert' not in profile_list:
            profile_list.append('caAuditSigningCert')
            profile_list.sort()
            subsystem.config['profile.list'] = ','.join(profile_list)

        logger.info('Adding profile.caAuditSigningCert.class_id')
        subsystem.config['profile.caAuditSigningCert.class_id'] = 'caEnrollImpl'

        logger.info('Adding profile.caAuditSigningCert.config')
        subsystem.config['profile.caAuditSigningCert.config'] = path

        self.backup(subsystem.cs_conf)
        subsystem.save()
