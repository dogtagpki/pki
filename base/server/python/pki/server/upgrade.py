#!/usr/bin/python
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

import os
import traceback

import pki
import pki.upgrade
import pki.server

from pki.upgrade import verbose

UPGRADE_DIR = pki.SHARE_DIR + '/server/upgrade'
BACKUP_DIR = pki.LOG_DIR + '/server/upgrade'

INSTANCE_TRACKER = '%s/tomcat.conf'
SUBSYSTEM_TRACKER = '%s/CS.cfg'


class PKIServerUpgradeScriptlet(pki.upgrade.PKIUpgradeScriptlet):

    def __init__(self):

        super(PKIServerUpgradeScriptlet, self).__init__()

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

    def upgrade(self):

        for instance in self.upgrader.instances():

            self.upgrade_subsystems(instance)

            # If upgrading a specific subsystem don't upgrade the instance.
            if self.upgrader.subsystemName:
                continue

            if not self.can_upgrade_server(instance):
                if verbose: print 'Skipping ' + str(instance) + ' instance.'
                continue

            try:
                if verbose: print 'Upgrading ' + str(instance) + ' instance.'
                self.upgrade_instance(instance)
                self.update_server_tracker(instance)

            except Exception as e:

                if verbose: traceback.print_exc()
                else: print 'ERROR: ' + e.message

                message = 'Failed upgrading ' + str(instance) + ' instance.'
                if self.upgrader.silent:
                    print message
                else:
                    result = pki.read_text(message + ' Continue (Yes/No)',
                        options=['Y', 'N'], default='Y', delimiter='?', caseSensitive=False).lower()
                    if result == 'y': continue

                raise pki.server.PKIServerException(
                    'Upgrade failed in ' + str(instance) + ': ' + e.message,
                    e, instance)

    def upgrade_subsystems(self, instance):

        for subsystem in self.upgrader.subsystems(instance):

            if not self.can_upgrade_server(instance, subsystem):
                if verbose: print 'Skipping ' + str(subsystem) + ' subsystem.'
                continue

            try:
                if verbose: print 'Upgrading ' + str(subsystem) + ' subsystem.'
                self.upgrade_subsystem(instance, subsystem)
                self.update_server_tracker(instance, subsystem)

            except Exception as e:

                if verbose: traceback.print_exc()
                else: print 'ERROR: ' + e.message

                message = 'Failed upgrading ' + str(subsystem) + ' subsystem.'
                if self.upgrader.silent:
                    print message
                else:
                    result = pki.read_text(message + ' Continue (Yes/No)',
                        options=['Y', 'N'], default='Y', delimiter='?', caseSensitive=False).lower()
                    if result == 'y': continue

                raise pki.server.PKIServerException(
                    'Upgrade failed in ' + str(subsystem) + ': ' + e.message,
                    e, instance, subsystem)

    def upgrade_subsystem(self, instance, subsystem):
        # Callback method to upgrade a subsystem.
        pass

    def upgrade_instance(self, instance):
        # Callback method to upgrade an instance.
        pass


class PKIServerUpgrader(pki.upgrade.PKIUpgrader):

    def __init__(self, instanceName=None, instanceType=None, subsystemName=None, \
        upgrade_dir=UPGRADE_DIR, version=None, index=None, silent=False):

        super(PKIServerUpgrader, self).__init__(upgrade_dir, version, index, silent)

        if subsystemName and not instanceName:
            raise pki.PKIException(
                'Invalid subsystem: ' + subsystemName + ', Instance not defined')

        self.instanceName = instanceName
        self.instanceType = instanceType
        self.subsystemName = subsystemName

        self.instance_trackers = {}
        self.subsystem_trackers = {}

    def instances(self):

        if self.instanceName and self.instanceType:
            return [pki.server.PKIInstance(self.instanceName, self.instanceType)]

        instance_list = []

        if not self.instanceType or self.instanceType >= 10:
            if os.path.exists(os.path.join(pki.server.REGISTRY_DIR, 'tomcat')):
                for instanceName in os.listdir(pki.server.INSTANCE_BASE_DIR):
                    if not self.instanceName or \
                        self.instanceName == instanceName:
                        instance_list.append(pki.server.PKIInstance(instanceName))

        if not self.instanceType or self.instanceType == 9:
            for s in pki.server.SUBSYSTEM_TYPES:
                if os.path.exists(os.path.join(pki.server.REGISTRY_DIR, s)):
                    for instanceName in \
                        os.listdir(os.path.join(pki.server.REGISTRY_DIR, s)):
                        if not self.instanceName or \
                            self.instanceName == instanceName:
                            instance_list.append(pki.server.PKIInstance(instanceName, 9))

        instance_list.sort()

        return instance_list


    def subsystems(self, instance):

        if self.subsystemName:
            return [pki.server.PKISubsystem(instance, self.subsystemName)]

        subsystem_list = []

        if instance.type >= 10:
            registry_dir = os.path.join(pki.server.REGISTRY_DIR, 'tomcat',
                instance.name)
            for subsystemName in os.listdir(registry_dir):
                if subsystemName in pki.server.SUBSYSTEM_TYPES:
                    subsystem_list.append(pki.server.PKISubsystem(instance, subsystemName))
        else:
            for subsystemName in pki.server.SUBSYSTEM_TYPES:
                registry_dir = os.path.join(
                    pki.server.REGISTRY_DIR,
                    subsystemName,
                    instance.name)
                if os.path.exists(registry_dir):
                    subsystem_list.append(pki.server.PKISubsystem(instance, subsystemName))

        subsystem_list.sort()

        return subsystem_list

    def get_server_tracker(self, instance, subsystem=None):

        if subsystem:
            name = str(subsystem)
            try:
                tracker = self.subsystem_trackers[instance]
            except KeyError:
                tracker = pki.upgrade.PKIUpgradeTracker(name + ' subsystem',
                    SUBSYSTEM_TRACKER % subsystem.conf_dir,
                    version_key='cms.product.version',
                    index_key='cms.upgrade.index')
                self.subsystem_trackers[name] = tracker

        else:
            try:
                tracker = self.instance_trackers[str(instance)]
            except KeyError:
                tracker = pki.upgrade.PKIUpgradeTracker(str(instance) + ' instance',
                    INSTANCE_TRACKER % instance.conf_dir,
                    version_key='PKI_VERSION',
                    index_key='PKI_UPGRADE_INDEX')
                self.instance_trackers[str(instance)] = tracker

        return tracker

    def get_current_version(self):

        current_version = None

        for instance in self.instances():

            # if upgrading the entire instance, check the instance version
            if not self.subsystemName:
                tracker = self.get_server_tracker(instance)
                version = tracker.get_version()

                # if instance version is older, use instance version
                if not current_version or version < current_version:
                    current_version = version

            for subsystem in self.subsystems(instance):

                # subsystem is always upgraded, check the subsystem version
                tracker = self.get_server_tracker(instance, subsystem)
                version = tracker.get_version()

                # if subsystem version is older, use subsystem version
                if not current_version or version < current_version:
                    current_version = version

        # if no instances defined, no upgrade required
        if not current_version:
            current_version = self.get_target_version()

        return current_version

    def show_tracker(self):

        for instance in self.instances():

            if not self.subsystemName:
                tracker = self.get_server_tracker(instance)
                tracker.show()

            for subsystem in self.subsystems(instance):

                tracker = self.get_server_tracker(instance, subsystem)
                tracker.show()

    def set_tracker(self, version):

        for instance in self.instances():

            if not self.subsystemName:
                tracker = self.get_server_tracker(instance)
                tracker.set(version)

            for subsystem in self.subsystems(instance):

                tracker = self.get_server_tracker(instance, subsystem)
                tracker.set(version)

        print 'Tracker has been set to version ' + str(version) + '.'

    def remove_tracker(self):

        for instance in self.instances():

            if not self.subsystemName:
                tracker = self.get_server_tracker(instance)
                tracker.remove()

            for subsystem in self.subsystems(instance):

                tracker = self.get_server_tracker(instance, subsystem)
                tracker.remove()

        print 'Tracker has been removed.'
