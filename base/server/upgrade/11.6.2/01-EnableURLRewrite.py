#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
import pki.server.upgrade


class EnableURLRewrite(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super().__init__()
        self.message = 'Enable URL rewrite'

    def upgrade_instance(self, instance):

        self.backup(instance.server_xml)

        instance.enable_rewrite(exist_ok=True)
