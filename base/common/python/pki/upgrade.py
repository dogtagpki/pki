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

import functools
import os
import pwd
import re
import shutil
import sys
import traceback

import pki


DEFAULT_VERSION   = '10.0.0'

UPGRADE_DIR       = pki.SHARE_DIR + '/server/upgrade'
VERSION_DIR       = UPGRADE_DIR + '/%s'
SCRIPTLET_FILE    = VERSION_DIR + '/%s'

SYSTEM_TRACKER    = pki.CONF_DIR + '/pki.conf'
INSTANCE_TRACKER  = '%s/tomcat.conf'
SUBSYSTEM_TRACKER = '%s/CS.cfg'

verbose           = False


@functools.total_ordering
class Version(object):

    def __init__(self, obj):

        if isinstance(obj, str):

            # parse <version>-<release>
            pos = parts = obj.find('-')

            if pos > 0:
                self.version = obj[0:pos]
            elif pos < 0:
                self.version = obj
            else:
                raise Exception('Invalid version number: ' + obj)

            # parse <major>.<minor>.<patch>
            match = re.match('^(\d+)\.(\d+)\.(\d+)$', self.version)

            if match is None:
                raise Exception('Invalid version number: ' + self.version)

            self.major = int(match.group(1))
            self.minor = int(match.group(2))
            self.patch = int(match.group(3))

        elif isinstance(obj, Version):

            self.major = obj.major
            self.minor = obj.minor
            self.patch = obj.patch

        else:
            raise Exception('Unsupported version type: ' + str(type(obj)))


    # release is ignored in comparisons

    def __eq__(self, other):
        return self.major == other.major and \
            self.minor == other.minor and \
            self.patch == other.patch


    def __lt__(self, other):
        if self.major < other.major:
            return True

        if self.major == other.major and \
            self.minor < other.minor:
            return True

        if self.major == other.major and \
            self.minor == other.minor and \
            self.patch < other.patch:
            return True

        return False


    def __repr__(self):
        return self.version

class PKIUpgradeTracker(object):

    def __init__(self, name, filename,
        delimiter='=',
        version_key='PKI_VERSION',
        index_key='PKI_UPGRADE_INDEX'):

        self.name = name
        self.filename = filename

        self.delimiter = delimiter
        self.version_key = version_key
        self.index_key = index_key

        self.read()


    def read(self):

        self.lines = []

        if not os.path.exists(self.filename):
            return

        # read all lines and preserve the original order
        with open(self.filename, 'r') as f:
            for line in f:
                line = line.strip('\n')
                self.lines.append(line)


    def write(self):

        # write all lines in the original order
        with open(self.filename, 'w') as f:
            for line in self.lines:
                f.write(line + '\n')


    def remove(self):

        print 'Removing ' + self.name + ' tracker.'

        self.remove_version()
        self.remove_index()
        self.write()


    def reset(self, version):

        print 'Resetting ' + self.name + ' tracker.'

        self.set_version(version)
        self.remove_index()
        self.write()


    def show(self):

        print self.name + ':'

        version = self.get_version()
        print '  Configuration version: ' + str(version)

        index = self.get_index()
        if index > 0:
            print '  Last completed scriptlet: ' + str(index)

        print


    def get_property(self, name):

        result = None

        for line in self.lines:

            # parse <key> <delimiter> <value>
            match = re.match('^\s*(\S*)\s*%s\s*(.*)\s*$' % self.delimiter, line)

            if not match:
                continue

            key = match.group(1)
            value = match.group(2)

            if key.lower() == name.lower():
                result = value
                break

        return result


    def set_property(self, name, value):

        found = False

        for index, line in enumerate(self.lines):

            # parse <key> <delimiter> <value>
            match = re.match('^\s*(\S*)\s*%s\s*(.*)\s*$' % self.delimiter, line)

            if not match:
                continue

            key = match.group(1)

            if key.lower() != name.lower():
                continue

            self.lines[index] = key + self.delimiter + value
            found = True
            break

        if not found:
            self.lines.append(name + self.delimiter + value)


    def remove_property(self, name):

        for index, line in enumerate(self.lines):

            # parse <key> <delimiter> <value>
            match = re.match('^\s*(\S*)\s*%s\s*(.*)\s*$' % self.delimiter, line)

            if not match:
                continue

            key = match.group(1)

            if key.lower() != name.lower():
                continue

            self.lines.pop(index)


    def get_index(self):

        index = self.get_property(self.index_key)

        if index:
            return int(index)

        return 0


    def set_index(self, index):
        self.set_property(self.index_key, str(index))


    def remove_index(self):
        self.remove_property(self.index_key)


    def get_version(self):

        version = self.get_property(self.version_key)

        if version:
            return Version(version)

        return Version(DEFAULT_VERSION)


    def set_version(self, version):
        self.set_property(self.version_key, str(version))


    def remove_version(self):
        self.remove_property(self.version_key)


@functools.total_ordering
class PKIUpgradeScriptlet(object):

    def __init__(self):

        self.version = None

        self.index = None
        self.last = False

        self.message = None
        self.upgrader = None


    def can_upgrade(self, instance=None, subsystem=None):

        # A scriptlet can run if the version matches the tracker and
        # the index is the next to be executed.

        tracker = self.upgrader.get_tracker(instance, subsystem)

        return self.version == tracker.get_version() and \
            self.index == tracker.get_index() + 1


    def update_tracker(self, instance=None, subsystem=None):

        # Increment the index in the tracker. If it's the last scriptlet
        # in this version, update the tracker version.

        tracker = self.upgrader.get_tracker(instance, subsystem)

        if not self.last:
            tracker.set_index(self.index)

        else:
            tracker.remove_index()
            tracker.set_version(self.version.next)

        tracker.write()


    def upgrade_subsystem(self, instance, subsystem):
        # Callback method to upgrade a subsystem.
        pass


    def upgrade_instance(self, instance):
        # Callback method to upgrade an instance.
        pass


    def upgrade_system(self):
        # Callback method to upgrade the system.
        pass


    def upgrade_subsystems(self, instance):

        for subsystem in self.upgrader.subsystems(instance):

            if not self.can_upgrade(instance, subsystem):
                if verbose: print 'Skipping ' + str(subsystem) + ' subsystem.'
                continue

            try:
                if verbose: print 'Upgrading ' + str(subsystem) + ' subsystem.'
                self.upgrade_subsystem(instance, subsystem)
                self.update_tracker(instance, subsystem)

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

                raise pki.PKIException(
                    'Upgrade failed in ' + str(subsystem) + ': ' + e.message,
                    e, instance, subsystem)


    def upgrade_instances(self):

        for instance in self.upgrader.instances():

            self.upgrade_subsystems(instance)

            # If upgrading a specific subsystem don't upgrade the instance.
            if self.upgrader.subsystemName:
                continue

            if not self.can_upgrade(instance):
                if verbose: print 'Skipping ' + str(instance) + ' instance.'
                continue

            try:
                if verbose: print 'Upgrading ' + str(instance) + ' instance.'
                self.upgrade_instance(instance)
                self.update_tracker(instance)

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

                raise pki.PKIException(
                    'Upgrade failed in ' + str(instance) + ': ' + e.message,
                    e, instance)


    def upgrade(self):

        self.upgrade_instances()

        # If upgrading a specific instance don't upgrade the system.
        if self.upgrader.instanceName:
            return

        try:
            if not self.can_upgrade():
                if verbose: print 'Skipping system.'
                return

            if verbose: print 'Upgrading system.'
            self.upgrade_system()
            self.update_tracker()

        except Exception as e:

            if verbose: traceback.print_exc()
            else: print 'ERROR: ' + e.message

            message = 'Failed upgrading system.'
            if self.upgrader.silent:
                print message
            else:
                result = pki.read_text(message + ' Continue (Yes/No)',
                    options=['Y', 'N'], default='Y', delimiter='?', caseSensitive=False).lower()
                if result == 'y': return

            raise pki.PKIException('Upgrade failed: ' + e.message, e)


    def __eq__(self, other):
        return self.version == other.version and self.index == other.index


    def __lt__(self, other):
        if self.version < other.version:
            return True

        return self.version == other.version and self.index < other.index


class PKIUpgrader():

    def __init__(self, instanceName=None, instanceType=None, \
        subsystemName=None, version=None, index=None, silent=False):

        self.instanceName = instanceName
        self.subsystemName = subsystemName
        self.version = version
        self.index = index
        self.silent = silent
        self.instanceType = instanceType

        if version and not os.path.exists(VERSION_DIR % str(version)):
            raise pki.PKIException(
                'Invalid version: ' + str(version),
                None)

        if subsystemName and not instanceName:
            raise pki.PKIException(
                'Invalid subsystem: ' + subsystemName +\
                ', Instance not defined',
                None)

        self.system_tracker = None
        self.instance_trackers = {}
        self.subsystem_trackers = {}


    def versions(self):

        current_version = self.get_current_version()
        target_version = self.get_target_version()

        all_versions = []

        if os.path.exists(UPGRADE_DIR):
            for version in os.listdir(UPGRADE_DIR):
                version = Version(version)

                # skip old versions
                if version >= current_version:
                    all_versions.append(version)

        all_versions.sort()

        versions = []

        for index, version in enumerate(all_versions):

            # link versions
            if index < len(all_versions) - 1:
                version.next = all_versions[index + 1]
            else:
                version.next = target_version

            # if no scriptlet version is specified, add all versions to the list
            # if scriptlet version is specified, add only that version to the list
            if not self.version or str(version) == self.version:
                versions.append(version)

        return versions


    def scriptlets(self, version):

        filenames = os.listdir(VERSION_DIR % str(version))
        scriptlets = []

        for filename in filenames:

            # parse <index>-<classname>
            try:
                i = filename.index('-')
            except ValueError as e:
                raise pki.PKIException('Invalid scriptlet name: ' + filename, e)

            index = int(filename[0:i])
            classname = filename[i+1:]

            if self.index and index != self.index:
                continue

            # load scriptlet class
            vars = {}
            execfile(SCRIPTLET_FILE % (str(version), filename), vars)

            # create scriptlet object
            scriptlet = vars[classname]()

            scriptlet.upgrader = self
            scriptlet.version = version
            scriptlet.index = index
            scriptlet.last = index == len(filenames)

            scriptlets.append(scriptlet)

        # sort scriptlets based on index
        scriptlets.sort()

        return scriptlets


    def instances(self):

        if self.instanceName and self.instanceType:
            return [pki.PKIInstance(self.instanceName, self.instanceType)]

        list = []
        if not self.instanceType or self.instanceType >=10:
            if os.path.exists(os.path.join(pki.REGISTRY_DIR,'tomcat')):
                for instanceName in os.listdir(pki.INSTANCE_BASE_DIR):
                    if not self.instanceName or \
                        self.instanceName == instanceName:
                        list.append(pki.PKIInstance(instanceName))

        if not self.instanceType or self.instanceType == 9:
            for s in pki.SUBSYSTEM_TYPES:
                if os.path.exists(os.path.join(pki.REGISTRY_DIR, s)):
                    for instanceName in \
                        os.listdir(os.path.join(pki.REGISTRY_DIR, s)):
                        if not self.instanceName or \
                            self.instanceName == instanceName:
                            list.append(pki.PKIInstance(instanceName, 9))

        list.sort()
        return list


    def subsystems(self, instance):

        if self.subsystemName:
            return [pki.PKISubsystem(instance, self.subsystemName)]

        list = []

        if instance.type >= 10:
            registry_dir = os.path.join(pki.REGISTRY_DIR, 'tomcat',
                instance.name)
            for subsystemName in os.listdir(registry_dir):
                if subsystemName in pki.SUBSYSTEM_TYPES:
                    list.append(pki.PKISubsystem(instance, subsystemName))
        else:
            for subsystemName in pki.SUBSYSTEM_TYPES:
                registry_dir = os.path.join(
                    pki.REGISTRY_DIR,
                    subsystemName,
                    instance.name)
                if os.path.exists(registry_dir):
                    list.append(pki.PKISubsystem(instance, subsystemName))

        list.sort()

        return list


    def get_tracker(self, instance=None, subsystem=None):

        if subsystem:
            name = str(subsystem)
            try:
                tracker = self.subsystem_trackers[instance]
            except KeyError:
                tracker = PKIUpgradeTracker(name + ' subsystem',
                    SUBSYSTEM_TRACKER % subsystem.conf_dir,
                    version_key='cms.product.version',
                    index_key='cms.upgrade.index')
                self.subsystem_trackers[name] = tracker

        elif instance:
            try:
                tracker = self.instance_trackers[str(instance)]
            except KeyError:
                tracker = PKIUpgradeTracker(str(instance) + ' instance',
                    INSTANCE_TRACKER % instance.conf_dir,
                    version_key='PKI_VERSION',
                    index_key='PKI_UPGRADE_INDEX')
                self.instance_trackers[str(instance)] = tracker

        else:
            if self.system_tracker:
                tracker = self.system_tracker
            else:
                tracker = PKIUpgradeTracker('system', SYSTEM_TRACKER,
                    version_key='PKI_VERSION',
                    index_key='PKI_UPGRADE_INDEX')
                self.system_tracker = tracker

        return tracker

    # return the oldest version of the components being upgraded
    def get_current_version(self):

        current_version = None

        # if upgrading the entire system, get the system version
        if not self.instanceName:
            tracker = self.get_tracker()
            current_version = tracker.get_version()

        for instance in self.instances():

            # if upgrading the entire instance, check the instance version
            if not self.subsystemName:
                tracker = self.get_tracker(instance)
                version = tracker.get_version()

                # if instance version is older, use instance version
                if not current_version or version < current_version:
                    current_version = version

            for subsystem in self.subsystems(instance):

                # subsystem is always upgraded, check the subsystem version
                tracker = self.get_tracker(instance, subsystem)
                version = tracker.get_version()

                # if subsystem version is older, use subsystem version
                if not current_version or version < current_version:
                    current_version = version

        return current_version


    def get_target_version(self):

        return Version(pki.implementation_version())


    def is_complete(self):

        current_version = self.get_current_version()
        target_version = self.get_target_version()

        return current_version == target_version


    def upgrade_version(self, version):

        print 'Upgrading from version ' + str(version) + ' to ' + str(version.next) + ':'

        scriptlets = self.scriptlets(version)

        if len(scriptlets) == 0:

            print 'No upgrade scriptlets.'

            for instance in self.instances():
                for subsystem in self.subsystems(instance):

                    # update subsystem tracker
                    tracker = self.get_tracker(instance, subsystem)
                    tracker.remove_index()
                    tracker.set_version(version.next)
                    tracker.write()

                # update instance tracker
                tracker = self.get_tracker(instance)
                tracker.remove_index()
                tracker.set_version(version.next)
                tracker.write()

            # update system tracker
            tracker = self.get_tracker()
            tracker.remove_index()
            tracker.set_version(version.next)
            tracker.write()

            return

        # execute scriptlets
        for index, scriptlet in enumerate(scriptlets):

            message = str(scriptlet.index) + '. ' + scriptlet.message

            if self.silent:
                print message

            else:
                result = pki.read_text(message + ' (Yes/No)',
                    options=['Y', 'N'], default='Y', caseSensitive=False).lower()

                if result == 'n':
                    raise pki.PKIException('Upgrade canceled.')

            try:
                scriptlet.upgrade()

            except pki.PKIException as e:
                raise

            except Exception as e:

                print

                message = 'Upgrade failed: ' + e.message

                if verbose:
                    traceback.print_exc()
                else:
                    print e.message

                print

                result = pki.read_text('Continue (Yes/No)',
                    options=['Y', 'N'], default='Y', delimiter='?', caseSensitive=False).lower()

                if result == 'n':
                    raise pki.PKIException(message, e)


    def upgrade(self):

        versions = self.versions()

        for index, version in enumerate(versions):

            self.upgrade_version(version)
            print

        if self.is_complete():
            print 'Upgrade complete.'

        else:
            self.show_tracker()
            print 'Upgrade incomplete.'


    def show_tracker(self):

        if not self.instanceName:
            tracker = self.get_tracker()
            tracker.show()

        for instance in self.instances():

            if not self.subsystemName:
                tracker = self.get_tracker(instance)
                tracker.show()

            for subsystem in self.subsystems(instance):

                tracker = self.get_tracker(instance, subsystem)
                tracker.show()


    def status(self):

        self.show_tracker()

        if self.is_complete():
            print 'Upgrade complete.'

        else:
            print 'Upgrade incomplete.'


    def set_tracker(self, version):
        if not self.instanceName:
            tracker = self.get_tracker()
            tracker.reset(version)

        for instance in self.instances():

            if not self.subsystemName:
                tracker = self.get_tracker(instance)
                tracker.reset(version)

            for subsystem in self.subsystems(instance):

                tracker = self.get_tracker(instance, subsystem)
                tracker.reset(version)


    def reset_tracker(self):

        target_version = self.get_target_version()
        self.set_tracker(target_version)


    def remove_tracker(self):

        if not self.instanceName:
            tracker = self.get_tracker()
            tracker.remove()

        for instance in self.instances():

            if not self.subsystemName:
                tracker = self.get_tracker(instance)
                tracker.remove()

            for subsystem in self.subsystems(instance):

                tracker = self.get_tracker(instance, subsystem)
                tracker.remove()
