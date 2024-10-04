#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
import pki.server.upgrade


class AddSerialNumberUpdateJob(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super().__init__()
        self.message = 'Add SerialNumberUpdateJob'

    def upgrade_subsystem(self, instance, subsystem):

        if subsystem.name != 'ca':
            return

        self.backup(subsystem.cs_conf)

        class_name = subsystem.config.get('jobsScheduler.impl.SerialNumberUpdateJob.class')
        if class_name is None:
            subsystem.config['jobsScheduler.impl.SerialNumberUpdateJob.class'] = \
                'org.dogtagpki.server.ca.job.SerialNumberUpdateJob'

        enabled = subsystem.config.get('jobsScheduler.job.serialNumberUpdate.enabled')
        if enabled is None:
            subsystem.config['jobsScheduler.job.serialNumberUpdate.enabled'] = 'false'

        plugin_name = subsystem.config.get('jobsScheduler.job.serialNumberUpdate.pluginName')
        if plugin_name is None:
            subsystem.config['jobsScheduler.job.serialNumberUpdate.pluginName'] = \
                'SerialNumberUpdateJob'

        subsystem.save()
