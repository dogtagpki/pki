import pki.server.upgrade


class BasicUpgradeScript(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super().__init__()
        self.message = 'Basic upgrade script'

    def upgrade_instance(self, instance):
        print('BasicUpgradeScript: Upgrading %s instance' % instance.name)

    def upgrade_subsystem(self, instance, subsystem):
        print('BasicUpgradeScript: Upgrading %s subsystem' % subsystem.name)
