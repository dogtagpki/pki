#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
import pki.server.upgrade


class ConfigureOCSPByName(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super().__init__()
        self.message = 'Configure PKCS12 Password constraints policy'

    def upgrade_subsystem(self, instance, subsystem):

        if subsystem.name == 'ca':
            if not subsystem.config.get('ca.byName'):
                self.backup(subsystem.cs_conf)
                subsystem.config['ca.byName'] = 'true'
                subsystem.save()

        if subsystem.name == 'ocsp':
            if subsystem.config.get('ocsp.storeId') == 'defStore':
                if not subsystem.config.get('ocsp.store.defStore.byName'):
                    self.backup(subsystem.cs_conf)
                    subsystem.config['ocsp.store.defStore.byName'] = 'true'
                    subsystem.save()
