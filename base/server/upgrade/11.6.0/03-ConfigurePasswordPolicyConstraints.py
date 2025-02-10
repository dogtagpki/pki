#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
import pki.server.upgrade


class ConfigurePasswordPolicyConstraints(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super().__init__()
        self.message = 'Configure PKCS12 Password constraints policy'

    def upgrade_subsystem(self, instance, subsystem):

        if subsystem.name != 'ca':
            return

        self.backup(subsystem.registry_conf)

        policy_ids = subsystem.registry.get('constraintPolicy.ids')
        subsystem.registry['constraintPolicy.ids'] = \
            ','.join([policy_ids, 'p12ExportPasswordConstraintImpl'])
        subsystem.registry['constraintPolicy.p12ExportPasswordConstraintImpl.class'] = \
            'com.netscape.cms.profile.constraint.P12ExportPasswordConstraint'
        subsystem.registry['constraintPolicy.p12ExportPasswordConstraintImpl.desc'] = \
            'Generated PKCS12 Constraint'
        subsystem.registry['constraintPolicy.p12ExportPasswordConstraintImpl.name'] = \
            'Generated PKCS12 Constraint'

        subsystem.save()
