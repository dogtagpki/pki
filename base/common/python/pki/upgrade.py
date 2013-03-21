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


DEFAULT_VERSION   = '10.0.1'

CONF_DIR          = '/etc/pki'
SHARE_DIR         = '/usr/share/pki'
INSTANCE_BASE_DIR = '/var/lib/pki'

VERSION_FILE      = 'VERSION'
VERSION_KEY       = 'Configuration-Version'
INDEX_KEY         = 'Scriptlet-Index'

UPGRADE_DIR       = SHARE_DIR + '/server/upgrade'
VERSION_DIR       = UPGRADE_DIR + '/%s'
SCRIPTLET_FILE    = VERSION_DIR + '/%s'

PACKAGE_VERSION   = SHARE_DIR + '/' + VERSION_FILE
SYSTEM_VERSION    = CONF_DIR + '/' + VERSION_FILE

INSTANCE_CONF     = CONF_DIR + '/%s'
INSTANCE_VERSION  = INSTANCE_CONF + '/' + VERSION_FILE

SUBSYSTEM_CONF    = INSTANCE_CONF + '/%s'
SUBSYSTEM_VERSION = SUBSYSTEM_CONF + '/' + VERSION_FILE

verbose           = False


def read_text(message,
    options=None, default=None, delimiter=':',
    allowEmpty=True, caseSensitive=True):

    if default:
        message = message + ' [' + default + ']'
    message = message + delimiter + ' '

    done = False
    while not done:
        value = raw_input(message)
        value = value.strip()

        if len(value) == 0:  # empty value
            if allowEmpty:
                value = default
                done = True
                break

        else:  # non-empty value
            if options is not None:
                for v in options:
                    if caseSensitive:
                        if v == value:
                            done = True
                            break
                    else:
                        if v.lower() == value.lower():
                            done = True
                            break
            else:
                done = True
                break

    return value


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


class PKIUpgradeException(Exception):

    def __init__(self, message, exception=None, instance=None, subsystem=None):

        Exception.__init__(self, message)

        self.exception = exception
        self.instance = instance
        self.subsystem = subsystem


class PKIUpgradeTracker(object):

    def __init__(self, name, filename):
        self.name = name
        self.filename = filename

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

        if os.path.exists(self.filename):
            if verbose: print 'Removing ' + self.filename
            os.remove(self.filename)


    def reset(self, version):

        print 'Resetting ' + self.name + ' tracker.'

        self.lines = []
        self.set_version(version)
        self.write()


    def show(self):

        print self.name + ':'

        for line in self.lines:
            print '  ' + line

        print


    def get_property(self, name):

        result = None

        for line in self.lines:

            # parse <key>: <value>
            match = re.match('^\s*(\S*)\s*:\s*(.*)\s*$', line)

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

            # parse <key>: <value>
            match = re.match('^\s*(\S*)\s*:\s*(.*)\s*$', line)

            if not match:
                continue

            key = match.group(1)

            if key.lower() != name.lower():
                continue

            self.lines[index] = key + ': ' + value
            found = True
            break

        if not found:
            self.lines.append(name + ': ' + value)


    def remove_property(self, name):

        for index, line in enumerate(self.lines):

            # parse <key>: <value>
            match = re.match('^\s*(\S*)\s*: \s*(.*)\s*$', line)

            if not match:
                continue

            key = match.group(1)

            if key.lower() != name.lower():
                continue

            self.lines.pop(index)


    def get_index(self):

        index = self.get_property(INDEX_KEY)

        if index:
            return int(index)

        return 0


    def set_index(self, index):
        self.set_property(INDEX_KEY, str(index))


    def remove_index(self):
        self.remove_property(INDEX_KEY)


    def get_version(self):

        version = self.get_property(VERSION_KEY)

        if version:
            return Version(version)

        return Version(DEFAULT_VERSION)


    def set_version(self, version):
        self.set_property(VERSION_KEY, str(version))


@functools.total_ordering
class PKIUpgradeScriptlet(object):

    def __init__(self):

        self.version = None
        self.next_version = None

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
            tracker.set_version(self.next_version)

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
                if verbose: print 'Skipping ' + instance + '/' + subsystem + ' subsystem.'
                continue

            try:
                if verbose: print 'Upgrading ' + instance + '/' + subsystem + ' subsystem.'
                self.upgrade_subsystem(instance, subsystem)
                self.update_tracker(instance, subsystem)

            except Exception as e:

                if verbose: traceback.print_exc()
                else: print 'ERROR: ' + e.message

                message = 'Failed upgrading ' + instance + '/' + subsystem + ' subsystem.'
                if self.upgrader.silent:
                    print message
                else:
                    result = read_text(message + ' Continue (Yes/No)',
                        options=['Y', 'N'], default='Y', delimiter='?', caseSensitive=False).lower()
                    if result == 'y': continue

                raise PKIUpgradeException(
                    'Upgrade failed in ' + instance + '/' + subsystem + ': ' + e.message,
                    e, instance, subsystem)


    def upgrade_instances(self):

        for instance in self.upgrader.instances():

            self.upgrade_subsystems(instance)

            # If upgrading a specific subsystem don't upgrade the instance.
            if self.upgrader.subsystem:
                continue

            if not self.can_upgrade(instance):
                if verbose: print 'Skipping ' + instance + ' instance.'
                continue

            try:
                if verbose: print 'Upgrading ' + instance + ' instance.'
                self.upgrade_instance(instance)
                self.update_tracker(instance)

            except Exception as e:

                if verbose: traceback.print_exc()
                else: print 'ERROR: ' + e.message

                message = 'Failed upgrading ' + instance + ' instance.'
                if self.upgrader.silent:
                    print message
                else:
                    result = read_text(message + ' Continue (Yes/No)',
                        options=['Y', 'N'], default='Y', delimiter='?', caseSensitive=False).lower()
                    if result == 'y': continue

                raise PKIUpgradeException(
                    'Upgrade failed in ' + instance + ': ' + e.message,
                    e, instance)


    def upgrade(self):

        self.upgrade_instances()

        # If upgrading a specific instance don't upgrade the system.
        if self.upgrader.instance:
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
                result = read_text(message + ' Continue (Yes/No)',
                    options=['Y', 'N'], default='Y', delimiter='?', caseSensitive=False).lower()
                if result == 'y': return

            raise PKIUpgradeException('Upgrade failed: ' + e.message, e)


    def __eq__(self, other):
        return self.version == other.version and self.index == other.index


    def __lt__(self, other):
        if self.version < other.version:
            return True

        return self.version == other.version and self.index < other.index


class PKIUpgrader():

    def __init__(self, instance=None, subsystem=None, \
        version=None, index=None, silent=False):

        self.instance = instance
        self.subsystem = subsystem
        self.version = version
        self.index = index
        self.silent = silent

        if version and not os.path.exists(VERSION_DIR % str(version)):
            raise PKIUpgradeException(
                'Invalid version: ' + str(version),
                None)

        if instance and not os.path.exists(INSTANCE_CONF % instance):
            raise PKIUpgradeException(
                'Invalid instance: ' + instance,
                None, instance)

        if subsystem and not os.path.exists(SUBSYSTEM_CONF % (instance, subsystem)):
            raise PKIUpgradeException(
                'Invalid subsystem: ' + instance + '/' + subsystem,
                None, instance, subsystem)

        self.system_tracker = None
        self.instance_trackers = {}
        self.subsystem_trackers = {}


    def versions(self):

        if self.version:
            return [self.version]

        versions = []

        if os.path.exists(UPGRADE_DIR):
            for version in os.listdir(UPGRADE_DIR):
                versions.append(Version(version))

        versions.sort()

        return versions


    def scriptlets(self, version, next_version):

        filenames = os.listdir(VERSION_DIR % str(version))
        scriptlets = []

        for filename in filenames:

            # parse <index>-<classname>
            i = filename.index('-')
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
            scriptlet.next_version = next_version
            scriptlet.index = index
            scriptlet.last = index == len(filenames)

            scriptlets.append(scriptlet)

        # sort scriptlets based on index
        scriptlets.sort()

        return scriptlets


    def instances(self):

        if self.instance:
            return [self.instance]

        if not os.path.exists(INSTANCE_BASE_DIR):
            return []

        list = os.listdir(INSTANCE_BASE_DIR)
        list.sort()

        return list


    def subsystems(self, instance):

        if self.subsystem:
            return [self.subsystem]

        list = []

        instance_dir = os.path.join(INSTANCE_BASE_DIR, instance)
        for folder in os.listdir(instance_dir):

            # check whether it is a subsystem folder
            subsystem_conf = os.path.join(
                instance_dir, folder, 'conf', 'CS.cfg')

            if not os.path.exists(subsystem_conf):
                continue

            list.append(folder)

        list.sort()

        return list


    def get_tracker(self, instance=None, subsystem=None):

        if subsystem:
            name = instance + '/' + subsystem
            try:
                tracker = self.subsystem_trackers[instance]
            except KeyError:
                tracker = PKIUpgradeTracker(name + ' subsystem',
                    SUBSYSTEM_VERSION % (instance, subsystem))
                self.subsystem_trackers[name] = tracker

        elif instance:
            try:
                tracker = self.instance_trackers[instance]
            except KeyError:
                tracker = PKIUpgradeTracker(instance + ' instance',
                    INSTANCE_VERSION % instance)
                self.instance_trackers[instance] = tracker

        else:
            if self.system_tracker:
                tracker = self.system_tracker
            else:
                tracker = PKIUpgradeTracker('system', SYSTEM_VERSION)
                self.system_tracker = tracker

        return tracker

    # return the oldest version of the components being upgraded
    def get_current_version(self):

        current_version = None

        # if upgrading the entire system, get the system version
        if not self.instance:
            tracker = self.get_tracker()
            current_version = tracker.get_version()

        for instance in self.instances():

            # if upgrading the entire instance, check the instance version
            if not self.subsystem:
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

        with open(PACKAGE_VERSION, 'r') as f:
            for line in f:
                line = line.strip('\n')

                # parse <key>: <value>
                match = re.match('^\s*(\S*)\s*:\s*(.*)\s*$', line)

                if not match:
                    continue

                key = match.group(1)
                value = match.group(2)

                if key.lower() != 'implementation-version':
                    continue

                return Version(value)

        raise Exception('Invalid version file.')


    def is_complete(self):

        current_version = self.get_current_version()
        target_version = self.get_target_version()

        return current_version == target_version


    def upgrade_version(self, version, next_version):

        print 'Upgrading from version ' + str(version) + ':'

        scriptlets = self.scriptlets(version, next_version)

        # execute scriptlets
        for index, scriptlet in enumerate(scriptlets):

            message = str(scriptlet.index) + '. ' + scriptlet.message

            if self.silent:
                print message

            else:
                result = read_text(message + ' (Yes/No)',
                    options=['Y', 'N'], default='Y', caseSensitive=False).lower()

                if result == 'n':
                    raise PKIUpgradeException('Upgrade canceled.')

            try:
                scriptlet.upgrade()

            except PKIUpgradeException as e:
                raise

            except Exception as e:

                print

                message = 'Upgrade failed: ' + e.message

                if verbose:
                    traceback.print_exc()
                else:
                    print e.message

                print

                result = read_text('Continue (Yes/No)',
                    options=['Y', 'N'], default='Y', delimiter='?', caseSensitive=False).lower()

                if result == 'n':
                    raise PKIUpgradeException(message, e)

            print


    def upgrade(self):

        current_version = self.get_current_version()
        target_version = self.get_target_version()

        if verbose:
            print 'Upgrading from version ' + str(current_version) + ' to ' + str(target_version) + '.'
            print

        versions = self.versions()

        # run scriptlets from source version to target version
        for index, version in enumerate(versions):

            if version < current_version:
                # skip old scriptlets
                continue

            if index < len(versions) - 1:
                next_version = versions[index + 1]
            else:
                next_version = target_version

            if index > 0:
                print

            self.upgrade_version(version, next_version)


        if self.is_complete():
            print 'Upgrade complete.'

        else:
            self.show_tracker()
            print 'Upgrade incomplete.'


    def show_tracker(self):

        if not self.instance:
            tracker = self.get_tracker()
            tracker.show()

        for instance in self.instances():

            if not self.subsystem:
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


    def reset_tracker(self):

        target_version = self.get_target_version()

        if not self.instance:
            tracker = self.get_tracker()
            tracker.reset(target_version)

        for instance in self.instances():

            if not self.subsystem:
                tracker = self.get_tracker(instance)
                tracker.reset(target_version)

            for subsystem in self.subsystems(instance):

                tracker = self.get_tracker(instance, subsystem)
                tracker.reset(target_version)


    def remove_tracker(self):

        if not self.instance:
            tracker = self.get_tracker()
            tracker.remove()

        for instance in self.instances():

            if not self.subsystem:
                tracker = self.get_tracker(instance)
                tracker.remove()

            for subsystem in self.subsystems(instance):

                tracker = self.get_tracker(instance, subsystem)
                tracker.remove()
