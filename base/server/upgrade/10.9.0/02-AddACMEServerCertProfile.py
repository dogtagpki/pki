# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import absolute_import
import logging
import os

import pki

logger = logging.getLogger(__name__)


class AddACMEServerCertProfile(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(AddACMEServerCertProfile, self).__init__()
        self.message = 'Add acmeServerCert profile'

    def upgrade_subsystem(self, instance, subsystem):

        if subsystem.name != 'ca':
            return

        logger.info('Creating acmeServerCert.cfg')
        path = os.path.join(subsystem.base_dir, 'profiles', 'ca', 'acmeServerCert.cfg')
        self.backup(path)

        instance.copyfile(
            '/usr/share/pki/ca/profiles/ca/acmeServerCert.cfg',
            path,
            exist_ok=True)

        logger.info('Adding acmeServerCert into profile.list')
        profile_list = subsystem.config.get('profile.list').split(',')
        if 'acmeServerCert' not in profile_list:
            profile_list.append('acmeServerCert')
            profile_list.sort()
            subsystem.set_config('profile.list', ','.join(profile_list))

        logger.info('Adding profile.acmeServerCert.class_id')
        subsystem.set_config('profile.acmeServerCert.class_id', 'caEnrollImpl')

        logger.info('Adding profile.acmeServerCert.config')
        subsystem.set_config('profile.acmeServerCert.config', path)

        self.backup(subsystem.cs_conf)
        subsystem.save()
