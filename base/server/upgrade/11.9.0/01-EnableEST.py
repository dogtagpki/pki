#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
import logging
import os

import pki

logger = logging.getLogger(__name__)


class EnableEST(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super().__init__()
        self.message = 'Enable EST maangement'

    def upgrade_subsystem(self, instance, subsystem):
        if subsystem.name != 'ca':
            return

        logger.info('Make est profile available')
        self.enable_est_profile(instance, subsystem)
        logger.info('Update internal profile to accept EST administrator')
        self.update_internal_profiles(instance, subsystem)
        logger.info('Update registry to accept est profile')
        self.update_registry(instance, subsystem)
        logger.info('Create the EST Adminitrator group')
        self.create_est_group(instance, subsystem)
        logger.info('Update ACL for EST administrators')
        self.update_acl(instance, subsystem)
        logger.info('AddEST type in the SD database')
        self.add_sd_type(instance, subsystem)

    def enable_est_profile(self, instance, subsystem):
        estProfile = 'estServiceCert'
        # Read the available profile list
        profile_list = subsystem.config.get('profile.list').split(',')

        if estProfile in profile_list:
            return

        file_name = '{}.cfg'.format(estProfile)

        logger.info('Creating %s', file_name)
        path = os.path.join(subsystem.base_dir, 'profiles', 'ca', file_name)
        self.backup(path)

        instance.copyfile(
            '/usr/share/pki/ca/profiles/ca/{}'.format(file_name),
            path,
            force=True)

        logger.info('Adding %s into profile.list', file_name)
        profile_list.append(estProfile)

        logger.info('Adding profile.%s.class_id', estProfile)
        subsystem.set_config('profile.{}.class_id'.format(estProfile), 'caEnrollImpl')

        profile_list.sort()
        subsystem.set_config('profile.list', ','.join(profile_list))

        # Make a backup of existing CS.cfg before writing modified values
        self.backup(subsystem.cs_conf)
        subsystem.save()

    def update_internal_profiles(self, instance, subsystem):
        profiles_to_update = [
            'caECInternalAuthSubsystemCert',
            'caInternalAuthServerCert',
            'caInternalAuthSubsystemCert'
        ]

        for profile in profiles_to_update:
            file_name = '{}.cfg'.format(profile)
            path = os.path.join(subsystem.base_dir, 'profiles', 'ca', file_name)
            self.backup(path)

            config = {}
            logger.info('Loading %s', path)
            pki.util.load_properties(path, config)

            logger.info('update acl in %s', profile)
            config['authz.acl'] = config['authz.acl'] + ' || group="Enterprise EST Administrators"'

            logger.info('Storing %s', path)
            pki.util.store_properties(path, config)

    def update_registry(self, instance, subsystem):
        self.backup(subsystem.registry_conf)
        policy_ids = subsystem.registry.get('constraintPolicy.ids')
        subsystem.registry['constraintPolicy.ids'] = \
            ','.join([policy_ids, 'raClientAuthSubjectNameConstraintImpl'])
        subsystem.registry['constraintPolicy.raClientAuthSubjectNameConstraintImp.class'] = \
            'com.netscape.cms.profile.constraint.RAClientAuthSubjectNameContraint'
        subsystem.registry['constraintPolicy.raClientAuthSubjectNameConstraintImp.desc'] = \
            'RA Client Subject Name Constraint'
        subsystem.registry['constraintPolicy.raClientAuthSubjectNameConstraintImp.name'] = \
            'RA Client Subject Name Constraint'

        input_ids = subsystem.registry.get('profileInput.ids')
        subsystem.registry['profileInput.ids'] = \
            ','.join([input_ids, 'raClientAuthInfoInputImpl'])
        subsystem.registry['profileInput.raClientAuthInfoInputImpl.class'] = \
            'com.netscape.cms.profile.input.RAClientAuthInfoInput'
        subsystem.registry['profileInput.raClientAuthInfoInputImpl.desc'] = \
            'RA Client Authentication Information Input'
        subsystem.registry['profileInput.raClientAuthInfoInputImpl.name'] = \
            'RA Client Authentication Information Input'

        subsystem.save()

    def create_est_group(self, instance, subsystem):
        group_id = "Enterprise EST Administrators"
        try:
            subsystem.add_group(
                group_id,
                "People who are the administrators for the security domain for EST")
            admin_members_entries = subsystem.find_group_members("Administrators")['entries']
            admin_members = [d['id'] for d in admin_members_entries]
            ca_admin_members_entries = \
                subsystem.find_group_members("Enterprise CA Administrators")['entries']
            ca_admin_members = [d['id'] for d in ca_admin_members_entries]

            for member in admin_members:
                if member in ca_admin_members:
                    subsystem.add_group_member(group_id, member)
        except Exception:
            logger.error('EST Administrator group cannot be created.')

    def update_acl(self, instance, subsystem):
        try:
            subsystem.delete_acl(
                ('certServer.securitydomain.domainxml:read,modify:allow (read) user="anybody"'
                 ';allow (modify) group="Subsystem Group" '
                 '|| group="Enterprise CA Administrators" '
                 '|| group="Enterprise KRA Administrators" '
                 '|| group="Enterprise RA Administrators" '
                 '|| group="Enterprise OCSP Administrators" '
                 '|| group="Enterprise TKS Administrators" '
                 '|| group="Enterprise TPS Administrators":Anybody is allowed to read domain.xml '
                 'but only Subsystem group and Enterprise Administrators '
                 'are allowed to modify the domain.xml'))
            subsystem.delete_acl(
                ('certServer.ca.registerUser:read,modify:allow (modify,read) '
                 'group="Enterprise CA Administrators" '
                 '|| group="Enterprise KRA Administrators" '
                 '|| group="Enterprise RA Administrators" '
                 '|| group="Enterprise OCSP Administrators" '
                 '|| group="Enterprise TKS Administrators" '
                 '|| group="Enterprise TPS Administrators":'
                 'Only Enterprise Administrators are allowed to register a new agent'))

            subsystem.add_acl(
                ('certServer.securitydomain.domainxml:read,modify:allow (read) user="anybody"'
                 ';allow (modify) group="Subsystem Group" '
                 '|| group="Enterprise CA Administrators" '
                 '|| group="Enterprise KRA Administrators" '
                 '|| group="Enterprise RA Administrators" '
                 '|| group="Enterprise OCSP Administrators" '
                 '|| group="Enterprise TKS Administrators" '
                 '|| group="Enterprise TPS Administrators" '
                 '|| group="Enterprise EST Administrators":'
                 'Anybody is allowed to read domain.xml but only Subsystem group and '
                 'Enterprise Administrators are allowed to modify the domain.xml'))
            subsystem.add_acl(
                ('certServer.ca.registerUser:read,modify:allow (modify,read) '
                 'group="Enterprise CA Administrators" '
                 '|| group="Enterprise KRA Administrators" '
                 '|| group="Enterprise RA Administrators" '
                 '|| group="Enterprise OCSP Administrators" '
                 '|| group="Enterprise TKS Administrators" '
                 '|| group="Enterprise TPS Administrators" '
                 '|| group="Enterprise EST Administrators":'
                 'Only Enterprise Administrators are allowed to register a new agent'))
        except Exception:
            logger.error('EST group ACL not configured properly')

    def add_sd_type(self, instance, subsystem):
        try:
            subsystem.add_security_domain_type(subsystem_type='EST')
        except Exception:
            logger.error('EST typeL not configured in security domain')
