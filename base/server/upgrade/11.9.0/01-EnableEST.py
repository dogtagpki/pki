#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
import logging
import os
import subprocess

import pki

logger = logging.getLogger(__name__)


class EnableEST(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super().__init__()
        self.message = 'Enable EST management'

    def upgrade_subsystem(self, instance, subsystem):
        if subsystem.name != 'ca':
            return

        try:
            subsystem.find_users()
        except subprocess.CalledProcessError:
            logger.debug("Impossible to access CA DB. Update aborted")
            return

        logger.info('Make est profile available')
        self.enable_est_profile(instance, subsystem)
        logger.info('Update internal profile to accept EST administrator')
        self.update_internal_profiles(subsystem)
        logger.info('Update registry to accept est profile')
        self.update_registry(subsystem)
        logger.info('Register CA authentication for EST-forwarded requests')
        self.register_ca_auth_for_est(subsystem)
        logger.info('Add CMC configuration parameters')
        self.add_cmc_config(subsystem)
        logger.info('Create the EST Administrator group')
        self.create_est_group(subsystem)
        logger.info('Update ACL for EST administrators')
        self.update_acl(subsystem)
        logger.info('Add EST type in the SD database')
        self.add_sd_type(subsystem)

    def enable_est_profile(self, instance, subsystem):
        estProfiles = ['estServiceCert', 'estFullcmcDeviceCert']
        # Read the available profile list
        profile_list = subsystem.config.get('profile.list').split(',')

        for estProfile in estProfiles:
            if estProfile in profile_list:
                logger.info('EST profile %s already in use.', estProfile)
                continue

            file_name = '{}.cfg'.format(estProfile)

            logger.info('Creating %s', file_name)
            path = os.path.join(subsystem.base_dir, 'profiles', 'ca', file_name)
            self.backup(path)

            instance.copyfile(
                '/usr/share/pki/ca/profiles/ca/{}'.format(file_name),
                path,
                force=True)

            # Try to import in LDAP if it is the profile storage
            try:
                subsystem.import_profiles(
                    input_folder='/usr/share/pki/ca/profiles/ca/')
            except subprocess.CalledProcessError:
                logger.error('EST profile import error.')

            logger.info('Adding %s into profile.list', file_name)
            profile_list.append(estProfile)

            logger.info('Adding profile.%s.class_id', estProfile)
            subsystem.set_config('profile.{}.class_id'.format(estProfile), 'caEnrollImpl')

        profile_list.sort()
        subsystem.set_config('profile.list', ','.join(profile_list))

        # Make a backup of existing CS.cfg before writing modified values
        self.backup(subsystem.cs_conf)
        subsystem.save()

    def update_internal_profiles(self, subsystem):
        profiles_to_update = [
            'caECInternalAuthSubsystemCert',
            'caInternalAuthServerCert',
            'caInternalAuthSubsystemCert'
        ]

        for profile in profiles_to_update:
            file_name = '{}.cfg'.format(profile)
            path = os.path.join(subsystem.base_dir, 'profiles', 'ca', file_name)

            config = {}
            logger.info('Loading %s', path)
            pki.util.load_properties(path, config)

            if 'group="Enterprise EST Administrators"' in config['authz.acl']:
                logger.info('Internal profile ACLs already updated.')
                return

            self.backup(path)
            config['authz.acl'] = config['authz.acl'] + ' || group="Enterprise EST Administrators"'

            logger.info('Storing %s', path)
            pki.util.store_properties(path, config)

    def update_registry(self, subsystem):
        self.backup(subsystem.registry_conf)
        policy_ids = subsystem.registry.get('constraintPolicy.ids')
        if 'raClientAuthSubjectNameConstraintImpl' in policy_ids:
            logger.info('Constraint raClientAuthSubjectNameConstraintImpl already defined.')
        else:
            subsystem.registry['constraintPolicy.ids'] = \
                ','.join([policy_ids, 'raClientAuthSubjectNameConstraintImpl'])
            subsystem.registry['constraintPolicy.raClientAuthSubjectNameConstraintImpl.class'] = \
                'com.netscape.cms.profile.constraint.RAClientAuthSubjectNameConstraint'
            subsystem.registry['constraintPolicy.raClientAuthSubjectNameConstraintImpl.desc'] = \
                'RA Client Subject Name Constraint'
            subsystem.registry['constraintPolicy.raClientAuthSubjectNameConstraintImpl.name'] = \
                'RA Client Subject Name Constraint'

        policy_ids = subsystem.registry.get('constraintPolicy.ids')
        if 'raHeaderClientCertSubjectNameConstraintImpl' in policy_ids:
            logger.info('Constraint raHeaderClientCertSubjectNameConstraintImpl already defined.')
        else:
            subsystem.registry['constraintPolicy.ids'] = \
                ','.join([policy_ids, 'raHeaderClientCertSubjectNameConstraintImpl'])
            constraint_class = \
                'com.netscape.cms.profile.constraint.RAHeaderClientCertSubjectNameConstraint'
            subsystem.registry[
                'constraintPolicy.raHeaderClientCertSubjectNameConstraintImpl.class'
            ] = constraint_class
            subsystem.registry[
                'constraintPolicy.raHeaderClientCertSubjectNameConstraintImpl.desc'
            ] = 'RA Header Client Cert Subject Name Constraint'
            subsystem.registry[
                'constraintPolicy.raHeaderClientCertSubjectNameConstraintImpl.name'
            ] = 'RA Header Client Cert Subject Name Constraint'

        input_ids = subsystem.registry.get('profileInput.ids')
        if 'raClientAuthInfoInputImpl' in input_ids:
            logger.info('Input already defined.')
        else:
            subsystem.registry['profileInput.ids'] = \
                ','.join([input_ids, 'raClientAuthInfoInputImpl'])
            subsystem.registry['profileInput.raClientAuthInfoInputImpl.class'] = \
                'com.netscape.cms.profile.input.RAClientAuthInfoInput'
            subsystem.registry['profileInput.raClientAuthInfoInputImpl.desc'] = \
                'RA Client Authentication Information Input'
            subsystem.registry['profileInput.raClientAuthInfoInputImpl.name'] = \
                'RA Client Authentication Information Input'
        subsystem.save()

    def register_ca_auth_for_est(self, subsystem):
        """Register CMCAuthForEST authentication module in CS.cfg"""
        self.backup(subsystem.cs_conf)

        # Check if CMCAuthForEST implementation is already registered
        auth_impl_class = subsystem.config.get('auths.impl.CMCAuthForEST.class')
        if auth_impl_class:
            logger.info('CMCAuthForEST implementation already registered.')
        else:
            # Register the implementation class
            subsystem.set_config('auths.impl.CMCAuthForEST.class',
                                 'com.netscape.cms.authentication.CMCAuthForEST')

        # Check if CMCAuthForEST instance is already configured
        auth_instance_plugin = subsystem.config.get('auths.instance.CMCAuthForEST.pluginName')
        if auth_instance_plugin:
            logger.info('CMCAuthForEST instance already configured.')
        else:
            # Register the instance
            subsystem.set_config('auths.instance.CMCAuthForEST.pluginName', 'CMCAuthForEST')

        subsystem.save()

    def add_cmc_config(self, subsystem):
        """Add CMC configuration parameters to CS.cfg"""
        self.backup(subsystem.cs_conf)

        # Check if cmc.response.useSimpleOnSuccess is already configured
        existing_value = subsystem.config.get('cmc.response.useSimpleOnSuccess')
        if existing_value is not None:
            logger.info('cmc.response.useSimpleOnSuccess already configured: %s', existing_value)
        else:
            # Parameter doesn't exist, add it with default value
            logger.info('Adding cmc.response.useSimpleOnSuccess=false')
            subsystem.set_config('cmc.response.useSimpleOnSuccess', 'false')
            subsystem.save()

    def create_est_group(self, subsystem):
        group_id = 'Enterprise EST Administrators'
        try:
            subsystem.find_group_members(group_id)
            logger.info('Group %s already exist', group_id)
            return
        except subprocess.CalledProcessError:
            logger.info("Group '%s' will be created.", group_id)

        subsystem.add_group(
            group_id,
            "People who are the administrators for the security domain for EST")
        admin_members_entries = subsystem.find_group_members("Administrators")['entries']
        ca_admin_members_entries = \
            subsystem.find_group_members("Enterprise CA Administrators")['entries']
        admin_members = {d['id'] for d in admin_members_entries}
        ca_admin_members = {d['id'] for d in ca_admin_members_entries}
        common_members = admin_members.intersection(ca_admin_members)
        for member in common_members:
            subsystem.add_group_member(group_id, member)

    def update_acl(self, subsystem):
        """
        Updates Access Control Lists to include EST administrators.

        Removes existing ACLs for domain.xml and registerUser operations,
        then adds new ACLs that include the EST administrators group.

        Note: Uses delete/add pattern because ACL modification isn't supported directly.
        """

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
        except subprocess.CalledProcessError:
            logger.info('EST group ACL already modified.')
            return

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

    def add_sd_type(self, subsystem):
        try:
            subsystem.add_security_domain_type(subsystem_type='EST')
        except subprocess.CalledProcessError:
            logger.error('EST SD type already exist.',)
