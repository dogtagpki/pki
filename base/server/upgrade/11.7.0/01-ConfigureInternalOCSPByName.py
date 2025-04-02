#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
import pki.server.upgrade


class ConfigureInternalOCSPByName(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super().__init__()
        self.message = 'Configure PKCS12 Password constraints policy'

    def upgrade_subsystem(self, instance, subsystem):

        if subsystem.name != 'ca':
            return

        if not subsystem.config.get('ca.byName'):
            self.backup(subsystem.cs_conf)
            subsystem.config['ca.byName'] = 'true'
            subsystem.save()
