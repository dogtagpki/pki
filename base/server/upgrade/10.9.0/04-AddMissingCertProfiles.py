# Authors:
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import absolute_import
import logging
import os

import pki

logger = logging.getLogger(__name__)


class AddMissingCertProfiles(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(AddMissingCertProfiles, self).__init__()
        self.message = 'Add missing certificate profiles'

    def upgrade_subsystem(self, instance, subsystem):

        if subsystem.name != 'ca':
            return

        profiles_to_copy = [
            'ECAdminCert',
            'caCMCECUserCert',
            'caCMCECserverCert',
            'caCMCECsubsystemCert',
            'caECAdminCert',
            'caECAgentServerCert',
            'caECFullCMCSharedTokenCert',
            'caECFullCMCUserCert',
            'caECFullCMCUserSignedCert',
            'caECInternalAuthServerCert',
            'caECInternalAuthSubsystemCert',
            'caECServerCert',
            'caECServerCertWithSCT',
            'caECSimpleCMCUserCert',
            'caECSubsystemCert',
            'caFullCMCSharedTokenCert',
            'caServerCertWithSCT',
            'caServerKeygen_DirUserCert',
            'caServerKeygen_UserCert',
            'caECDirPinUserCert'
        ]

        # Read the available profile list
        profile_list = subsystem.config.get('profile.list').split(',')

        for profile in profiles_to_copy:
            # Create the right file name
            file_name = '{}.cfg'.format(profile)

            path = os.path.join(subsystem.base_dir, 'profiles', 'ca', file_name)

            if not os.path.exists(path):
                logger.info('Creating %s', file_name)
                self.backup(path)
                # copy file from rpm installed to installed instance
                instance.copyfile('/usr/share/pki/ca/profiles/ca/{}'.format(file_name), path)

            logger.info('Adding %s into profile.list', file_name)
            if profile not in profile_list:
                profile_list.append(profile)

            logger.info('Adding profile.%s.class_id', profile)
            subsystem.config['profile.{}.class_id'.format(profile)] = 'caEnrollImpl'

            logger.info('Adding profile.%s.config', profile)
            subsystem.config['profile.{}.config'.format(profile)] = path

        profile_list.sort()
        subsystem.config['profile.list'] = ','.join(profile_list)

        # Make a backup of existing CS.cfg before writing modified values
        self.backup(subsystem.cs_conf)
        subsystem.save()
