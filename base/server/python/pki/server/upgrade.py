# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2013 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
from __future__ import print_function
import logging

import pki
import pki.upgrade
import pki.util
import pki.server

UPGRADE_DIR = pki.SHARE_DIR + '/server/upgrade'
BACKUP_DIR = pki.LOG_DIR + '/server/upgrade'

INSTANCE_TRACKER = '%s/tomcat.conf'

logger = logging.getLogger(__name__)


class PKIServerUpgradeScriptlet(pki.upgrade.PKIUpgradeScriptlet):

    def get_backup_dir(self):
        return BACKUP_DIR + '/' + str(self.version) + '/' + str(self.index)

    def upgrade_subsystem(self, instance, subsystem):
        # Callback method to upgrade a subsystem.
        pass

    def upgrade_instance(self, instance):
        # Callback method to upgrade an instance.
        pass


class PKIServerUpgrader(pki.upgrade.PKIUpgrader):

    def __init__(self, instance, upgrade_dir=UPGRADE_DIR):

        super(PKIServerUpgrader, self).__init__(upgrade_dir)

        self.instance = instance
        self.tracker = None

    def get_tracker(self):

        if self.tracker:
            return self.tracker

        self.tracker = pki.upgrade.PKIUpgradeTracker(
            '%s instance' % self.instance,
            INSTANCE_TRACKER % self.instance.conf_dir,
            version_key='PKI_VERSION',
            index_key='PKI_UPGRADE_INDEX')

        return self.tracker

    def validate(self):

        if not self.is_complete():
            log_file = '/var/log/pki/pki-server-upgrade-%s.log' % self.get_target_version()
            raise Exception('Upgrade incomplete: see %s' % log_file)

    def run_scriptlet(self, scriptlet):

        for subsystem in self.instance.subsystems:

            logging.info('Upgrading %s subsystem', subsystem)

            # reload changes
            subsystem.load()

            scriptlet.upgrade_subsystem(self.instance, subsystem)

        logger.info('Upgrading %s instance', self.instance)
        scriptlet.upgrade_instance(self.instance)
