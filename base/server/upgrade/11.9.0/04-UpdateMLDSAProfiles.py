# Authors:
#     Marco Fargetta <mfargett@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import os

import pki

logger = logging.getLogger(__name__)


class UpdateMLDSAProfiles(pki.server.upgrade.PKIServerUpgradeScriptlet):
    # NOTE: the update does not work with LDAP stored profiles

    def __init__(self):
        super().__init__()
        self.message = 'Update CA profiles for ML-DSA support'

    def upgrade_subsystem(self, instance, subsystem):

        if subsystem.name != 'ca':
            return

        # New ML-DSA profiles to add
        new_profiles = [
            'caMLDSAUserCert',
            'caMLDSAServerCert',
            'caMLDSASubsystemCert',
            'caMLDSAAdminCert',
        ]

        # Read the available profile list
        profile_list = subsystem.config.get('profile.list').split(',')

        # Update all profiles
        # If the signature algorithms have been modified in the instance
        # the new algorithms are not included
        new_signing_algs = {'ML-DSA-87', 'ML-DSA-44', 'ML-DSA-65'}

        path_instance = os.path.join(subsystem.base_dir, 'profiles', 'ca')
        for file_name in os.listdir(path_instance):
            if file_name[-4:] != '.cfg':
                continue
            if not os.path.exists('/usr/share/pki/ca/profiles/ca/{}'.format(file_name)):
                continue

            new_profile = {}
            instance_profile = {}
            pki.util.load_properties(
                '/usr/share/pki/ca/profiles/ca/{}'.format(file_name),
                new_profile)

            path = os.path.join(path_instance, file_name)
            pki.util.load_properties(
                path,
                instance_profile)
            keys = [key for key, val in instance_profile.items()
                    if '.constraint.params.signingAlgsAllowed' in key]
            for key in keys:
                new_profile_signing = set(new_profile[key].split(','))
                instance_profile_signing = set(instance_profile[key].split(','))
                if new_signing_algs == new_profile_signing.difference(instance_profile_signing):
                    instance_profile[key] = new_profile[key]
            self.backup(path)
            logger.info('Storing %s', path)
            pki.util.store_properties(path, instance_profile)

        # Add new profiles
        for profile in new_profiles:
            file_name = '{}.cfg'.format(profile)

            path = os.path.join(subsystem.base_dir, 'profiles', 'ca', file_name)
            if os.path.exists(path):
                continue
            logger.info('Adding profile %s', file_name)

            instance.copyfile(
                '/usr/share/pki/ca/profiles/ca/{}'.format(file_name),
                path,
                exist_ok=True,
                force=False)

            if profile not in profile_list:
                # Add new profiles to profile.list
                logger.info('Adding %s to profile.list', profile)
                profile_list.append(profile)

            logger.info('Adding profile.%s.class_id', profile)
            subsystem.set_config('profile.{}.class_id'.format(profile), 'caEnrollImpl')

        subsystem.set_config('profile.list', ','.join(profile_list))

        # Make a backup of existing CS.cfg before writing modified values
        self.backup(subsystem.cs_conf)
        subsystem.save()

        logger.info('ML-DSA profile update completed')
