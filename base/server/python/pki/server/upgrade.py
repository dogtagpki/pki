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
SUBSYSTEM_TRACKER = '%s/CS.cfg'

logger = logging.getLogger(__name__)


class PKIServerUpgradeScriptlet(pki.upgrade.PKIUpgradeScriptlet):

    def get_backup_dir(self):
        return BACKUP_DIR + '/' + str(self.version) + '/' + str(self.index)

    def can_upgrade_server(self, instance, subsystem=None):
        # A scriptlet can run if the version matches the tracker and
        # the index is the next to be executed.

        tracker = self.upgrader.get_server_tracker(instance, subsystem)

        return self.version == tracker.get_version() and \
            self.index == tracker.get_index() + 1

    def update_server_tracker(self, instance, subsystem=None):
        # Increment the index in the tracker. If it's the last scriptlet
        # in this version, update the tracker version.

        tracker = self.upgrader.get_server_tracker(instance, subsystem)
        self.backup(tracker.filename)

        if not self.last:
            tracker.set_index(self.index)

        else:
            tracker.remove_index()
            tracker.set_version(self.version.next)

    def upgrade_subsystems(self, instance):

        for subsystem in instance.subsystems:

            logging.info('Upgrading %s subsystem', subsystem.name)

            if not self.can_upgrade_server(instance, subsystem):
                logger.info('Skipping %s subsystem', subsystem)
                continue

            try:
                logger.info('Upgrading %s subsystem', subsystem)
                self.upgrade_subsystem(instance, subsystem)
                self.update_server_tracker(instance, subsystem)

            except Exception as e:

                if logger.isEnabledFor(logging.INFO):
                    logger.exception(e)
                else:
                    logger.error(e)

                message = 'Failed upgrading ' + str(subsystem) + ' subsystem.'
                print(message)

                raise pki.server.PKIServerException(
                    'Upgrade failed in %s: %s' % (subsystem, e),
                    e, instance, subsystem)

    def upgrade_subsystem(self, instance, subsystem):
        # Callback method to upgrade a subsystem.
        pass

    def upgrade_instance(self, instance):
        # Callback method to upgrade an instance.
        pass


class PKIServerUpgrader(pki.upgrade.PKIUpgrader):

    def __init__(self, instances, upgrade_dir=UPGRADE_DIR):

        super(PKIServerUpgrader, self).__init__(upgrade_dir)

        self.instances = instances

        self.instance_trackers = {}
        self.subsystem_trackers = {}

    def get_server_tracker(self, instance, subsystem=None):
        if subsystem:
            name = str(subsystem)
            try:
                tracker = self.subsystem_trackers[instance]
            except KeyError:
                tracker = pki.upgrade.PKIUpgradeTracker(
                    name + ' subsystem',
                    SUBSYSTEM_TRACKER % subsystem.conf_dir,
                    version_key='cms.product.version',
                    index_key='cms.upgrade.index')
                self.subsystem_trackers[name] = tracker

        else:
            try:
                tracker = self.instance_trackers[str(instance)]
            except KeyError:
                tracker = pki.upgrade.PKIUpgradeTracker(
                    str(instance) + ' instance',
                    INSTANCE_TRACKER % instance.conf_dir,
                    version_key='PKI_VERSION',
                    index_key='PKI_UPGRADE_INDEX')
                self.instance_trackers[str(instance)] = tracker

        return tracker

    def get_current_version(self):
        current_version = None

        for instance in self.instances:

            # check the instance version
            tracker = self.get_server_tracker(instance)
            version = tracker.get_version()

            # if instance version is older, use instance version
            if not current_version or version < current_version:
                current_version = version

            for subsystem in instance.subsystems:

                # check the subsystem version
                tracker = self.get_server_tracker(instance, subsystem)
                version = tracker.get_version()

                # if subsystem version is older, use subsystem version
                if not current_version or version < current_version:
                    current_version = version

        # if no instances defined, no upgrade required
        if not current_version:
            current_version = self.get_target_version()

        logging.debug('Current version: %s', current_version)

        return current_version

    def validate(self):

        if not self.is_complete():
            log_file = '/var/log/pki/pki-server-upgrade-%s.log' % self.get_target_version()
            raise Exception('Upgrade incomplete: see %s' % log_file)

    def run_scriptlet(self, scriptlet):

        for instance in self.instances:

            logging.info('Upgrading %s instance', instance.name)

            scriptlet.upgrade_subsystems(instance)

            if not scriptlet.can_upgrade_server(instance):
                logger.info('Skipping %s instance', instance)
                continue

            try:
                logger.info('Upgrading %s instance', instance)

                scriptlet.upgrade_instance(instance)
                scriptlet.update_server_tracker(instance)

            except Exception as e:

                if logger.isEnabledFor(logging.INFO):
                    logger.exception(e)
                else:
                    logger.error(e)

                message = 'Failed upgrading ' + str(instance) + ' instance.'
                print(message)

                raise pki.server.PKIServerException(
                    'Upgrade failed in %s: %s' % (instance, e), e, instance)

    def show_tracker(self):
        for instance in self.instances:

            tracker = self.get_server_tracker(instance)
            tracker.show()

            for subsystem in instance.subsystems:

                tracker = self.get_server_tracker(instance, subsystem)
                tracker.show()

    def set_tracker(self, version):
        for instance in self.instances:

            tracker = self.get_server_tracker(instance)
            tracker.set(version)

            for subsystem in instance.subsystems:

                tracker = self.get_server_tracker(instance, subsystem)
                tracker.set(version)

        print('Tracker has been set to version ' + str(version) + '.')

    def remove_tracker(self):
        for instance in self.instances:

            tracker = self.get_server_tracker(instance)
            tracker.remove()

            for subsystem in instance.subsystems:

                tracker = self.get_server_tracker(instance, subsystem)
                tracker.remove()

        print('Tracker has been removed.')
