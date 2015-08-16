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

from __future__ import absolute_import
from __future__ import print_function
import functools
import os
import re
import shutil
import traceback

import pki
import pki.util


DEFAULT_VERSION = '10.0.0'

UPGRADE_DIR = pki.SHARE_DIR + '/upgrade'
BACKUP_DIR = pki.LOG_DIR + '/upgrade'
SYSTEM_TRACKER = pki.CONF_DIR + '/pki.version'
verbose = False


@functools.total_ordering
class Version(object):

    def __init__(self, obj):

        if isinstance(obj, str):

            # parse <version>-<release>
            pos = obj.find('-')

            if pos > 0:
                self.version = obj[0:pos]
            elif pos < 0:
                self.version = obj
            else:
                raise Exception('Invalid version number: ' + obj)

            # parse <major>.<minor>.<patch>
            match = re.match(r'^(\d+)\.(\d+)\.(\d+)$', self.version)

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
        return (self.major == other.major and
                self.minor == other.minor and
                self.patch == other.patch)

    def __lt__(self, other):
        if self.major < other.major:
            return True

        if self.major == other.major and self.minor < other.minor:
            return True

        if (self.major == other.major and
                self.minor == other.minor and
                self.patch < other.patch):
            return True

        return False

    # not hashable
    __hash__ = None

    def __repr__(self):
        return self.version


class PKIUpgradeTracker(object):

    def __init__(self, name, filename, delimiter='=',
                 version_key='PKI_VERSION',
                 index_key='PKI_UPGRADE_INDEX'):

        self.name = name
        self.filename = filename

        self.version_key = version_key
        self.index_key = index_key

        # properties must be read and written immediately to avoid
        # interfering with scriptlets that update the same file

        self.properties = pki.PropertyFile(filename, delimiter)

    def remove(self):

        if verbose:
            print('Removing ' + self.name + ' tracker.')

        self.remove_version()
        self.remove_index()

    def set(self, version):

        if verbose:
            print('Setting ' + self.name + ' tracker to version ' +
                  str(version) + '.')

        self.set_version(version)
        self.remove_index()

    def show(self):

        print(self.name + ':')

        version = self.get_version()
        print('  Configuration version: ' + str(version))

        index = self.get_index()
        if index > 0:
            print('  Last completed scriptlet: ' + str(index))

        print()

    def get_index(self):

        self.properties.read()

        index = self.properties.get(self.index_key)

        if index:
            return int(index)

        return 0

    def set_index(self, index):

        self.properties.read()

        # find index
        i = self.properties.index(self.index_key)
        if i >= 0:
            # if already exists, update index
            self.properties.set(self.index_key, str(index))

        else:
            # find version
            i = self.properties.index(self.version_key)
            if i >= 0:
                # if version exists, add index after version
                self.properties.set(self.index_key, str(index), index=i + 1)

            else:
                # otherwise, add index at the end separated by a blank line

                # if last line is not empty, append empty line
                length = len(self.properties.lines)
                if length > 0 and self.properties.lines[length - 1] != '':
                    self.properties.insert_line(length, '')
                    length += 1

                # add index
                self.properties.set(self.index_key, str(index), index=length)

        self.properties.write()

    def remove_index(self):

        self.properties.read()
        self.properties.remove(self.index_key)
        self.properties.write()

    def get_version(self):

        self.properties.read()

        version = self.properties.get(self.version_key)
        if version:
            return Version(version)

        return Version(DEFAULT_VERSION)

    def set_version(self, version):

        self.properties.read()

        # find version
        i = self.properties.index(self.version_key)
        if i >= 0:
            # if already exists, update version
            self.properties.set(self.version_key, str(version))

        else:
            # otherwise, add version at the end separated by a blank line

            # if last line is not empty, append empty line
            length = len(self.properties.lines)
            if length > 0 and self.properties.lines[length - 1] != '':
                self.properties.insert_line(length, '')
                length += 1

            # add version
            self.properties.set(self.version_key, str(version), index=length)

        self.properties.write()

    def remove_version(self):

        self.properties.read()
        self.properties.remove(self.version_key)
        self.properties.write()


@functools.total_ordering
class PKIUpgradeScriptlet(object):

    def __init__(self):

        self.version = None

        self.index = None
        self.last = False

        self.message = None
        self.upgrader = None

    def get_backup_dir(self):
        return BACKUP_DIR + '/' + str(self.version) + '/' + str(self.index)

    def can_upgrade(self):

        # A scriptlet can run if the version matches the tracker and
        # the index is the next to be executed.

        tracker = self.upgrader.get_tracker()

        return self.version == tracker.get_version() and \
            self.index == tracker.get_index() + 1

    def update_tracker(self):

        # Increment the index in the tracker. If it's the last scriptlet
        # in this version, update the tracker version.

        tracker = self.upgrader.get_tracker()
        self.backup(tracker.filename)

        if not self.last:
            tracker.set_index(self.index)

        else:
            tracker.remove_index()
            tracker.set_version(self.version.next)

    def upgrade_system(self):
        # Callback method to upgrade the system.
        pass

    def init(self):

        backup_dir = self.get_backup_dir()

        if os.path.exists(backup_dir):
            # remove old backup dir
            shutil.rmtree(backup_dir)

        # create backup dir
        os.makedirs(backup_dir)

    def upgrade(self):

        try:
            if not self.can_upgrade():
                if verbose:
                    print('Skipping system.')
                return

            if verbose:
                print('Upgrading system.')
            self.upgrade_system()
            self.update_tracker()

        except Exception as e:

            if verbose:
                traceback.print_exc()
            else:
                print('ERROR: %s' % e)

            message = 'Failed upgrading system.'
            if self.upgrader.silent:
                print(message)
            else:
                result = pki.read_text(
                    message + ' Continue (Yes/No)',
                    options=['Y', 'N'], default='Y', delimiter='?',
                    case_sensitive=False).lower()
                if result == 'y':
                    return

            raise pki.PKIException('Upgrade failed: %s' % e, e)

    def revert(self):

        backup_dir = self.get_backup_dir()

        if not os.path.exists(backup_dir):
            return

        oldfiles = backup_dir + '/oldfiles'
        if os.path.exists(oldfiles):

            # restore all backed up files
            for sourcepath, _, filenames in os.walk(oldfiles):
                # unused item _ for dirnames

                destpath = sourcepath[len(oldfiles):]
                if destpath == '':
                    destpath = '/'

                if not os.path.isdir(destpath):
                    if verbose:
                        print('Restoring ' + destpath)
                    pki.util.copydirs(sourcepath, destpath)

                for filename in filenames:
                    sourcefile = os.path.join(sourcepath, filename)
                    targetfile = os.path.join(destpath, filename)

                    if verbose:
                        print('Restoring ' + targetfile)
                    pki.util.copyfile(sourcefile, targetfile)

        newfiles = backup_dir + '/newfiles'
        if os.path.exists(newfiles):

            # get paths that did not exist before upgrade
            paths = []
            with open(newfiles, 'r') as f:
                for path in f:
                    path = path.strip('\n')
                    paths.append(path)

            # remove paths in reverse order
            paths.reverse()
            for path in paths:

                if not os.path.exists(path):
                    continue
                if verbose:
                    print('Deleting ' + path)

                if os.path.isfile(path):
                    os.remove(path)
                else:
                    shutil.rmtree(path)

    def backup(self, path):

        backup_dir = self.get_backup_dir()

        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)

        if os.path.exists(path):

            # if path exists, keep a copy

            oldfiles = backup_dir + '/oldfiles'
            if not os.path.exists(oldfiles):
                os.mkdir(oldfiles)

            dest = oldfiles + path

            sourceparent = os.path.dirname(path)
            destparent = os.path.dirname(dest)

            pki.util.copydirs(sourceparent, destparent)

            if os.path.isfile(path):
                if verbose:
                    print('Saving ' + path)
                # do not overwrite initial backup
                pki.util.copyfile(path, dest, overwrite=False)

            else:
                for sourcepath, _, filenames in os.walk(path):

                    relpath = sourcepath[len(path):]
                    destpath = dest + relpath

                    if verbose:
                        print('Saving ' + sourcepath)
                    pki.util.copydirs(sourcepath, destpath)

                    for filename in filenames:
                        sourcefile = os.path.join(sourcepath, filename)
                        targetfile = os.path.join(destpath, filename)

                        if verbose:
                            print('Saving ' + sourcefile)
                        # do not overwrite initial backup
                        pki.util.copyfile(sourcefile, targetfile,
                                          overwrite=False)

        else:

            # otherwise, record the name

            if verbose:
                print('Recording ' + path)
            with open(backup_dir + '/newfiles', 'a') as f:
                f.write(path + '\n')

    def __eq__(self, other):
        return self.version == other.version and self.index == other.index

    def __lt__(self, other):
        if self.version < other.version:
            return True

        return self.version == other.version and self.index < other.index

    # not hashable
    __hash__ = None


class PKIUpgrader(object):

    def __init__(self, upgrade_dir=UPGRADE_DIR, version=None, index=None,
                 silent=False):

        self.upgrade_dir = upgrade_dir
        self.version = version
        self.index = index

        self.silent = silent

        if version and not os.path.exists(self.version_dir(version)):
            raise pki.PKIException(
                'Invalid scriptlet version: ' + str(version))

        self.system_tracker = None

    def version_dir(self, version):

        return os.path.join(self.upgrade_dir, str(version))

    def all_versions(self):

        all_versions = []

        if os.path.exists(self.upgrade_dir):
            for version in os.listdir(self.upgrade_dir):
                version = Version(version)
                all_versions.append(version)

        all_versions.sort()

        return all_versions

    def versions(self):

        current_version = self.get_current_version()
        target_version = self.get_target_version()

        current_versions = []

        for version in self.all_versions():

            # skip old versions
            if version >= current_version:
                current_versions.append(version)

        current_versions.sort()

        versions = []

        for index, version in enumerate(current_versions):

            # link versions
            if index < len(current_versions) - 1:
                version.next = current_versions[index + 1]
            else:
                version.next = target_version

            # if no scriptlet version is specified, add all versions to the list
            # if scriptlet version is specified, add only that version to the
            # list
            if not self.version or str(version) == self.version:
                versions.append(version)

        return versions

    def scriptlets(self, version):
        scriptlets = []

        version_dir = self.version_dir(version)
        if not os.path.exists(version_dir):
            return scriptlets

        filenames = os.listdir(version_dir)
        for filename in filenames:

            # parse <index>-<classname>
            try:
                i = filename.index('-')
            except ValueError as e:
                raise pki.PKIException(
                    'Invalid scriptlet name: ' + filename,
                    e)

            index = int(filename[0:i])
            classname = filename[i + 1:]

            if self.index and index != self.index:
                continue

            # load scriptlet class
            variables = {}
            absname = os.path.join(version_dir, filename)
            with open(absname, 'r') as f:
                bytecode = compile(f.read(), absname, 'exec')
            exec(bytecode, variables)  # pylint: disable=W0122

            # create scriptlet object
            scriptlet = variables[classname]()

            scriptlet.upgrader = self
            scriptlet.version = version
            scriptlet.index = index
            scriptlet.last = index == len(filenames)

            scriptlets.append(scriptlet)

        # sort scriptlets based on index
        scriptlets.sort()

        return scriptlets

    def get_tracker(self):

        if self.system_tracker:
            tracker = self.system_tracker

        else:
            tracker = PKIUpgradeTracker(
                'system',
                SYSTEM_TRACKER,
                delimiter=': ',
                version_key='Configuration-Version',
                index_key='Scriptlet-Index')
            self.system_tracker = tracker

        return tracker

    def get_current_version(self):

        tracker = self.get_tracker()
        return tracker.get_version()

    def get_target_version(self):
        return Version(pki.implementation_version())

    def is_complete(self):

        current_version = self.get_current_version()
        target_version = self.get_target_version()

        return current_version == target_version

    def upgrade_version(self, version):

        print('Upgrading from version ' + str(version) + ' to ' +
              str(version.next) + ':')

        scriptlets = self.scriptlets(version)

        if len(scriptlets) == 0:

            print('No upgrade scriptlets.')

            self.set_tracker(version.next)
            return

        # execute scriptlets
        for scriptlet in scriptlets:

            message = str(scriptlet.index) + '. ' + scriptlet.message

            if self.silent:
                print(message)

            else:
                result = pki.read_text(
                    message + ' (Yes/No)',
                    options=['Y', 'N'],
                    default='Y',
                    case_sensitive=False).lower()

                if result == 'n':
                    raise pki.PKIException('Upgrade canceled.')

            try:
                scriptlet.init()
                scriptlet.upgrade()

            except pki.PKIException:
                raise

            except Exception as e:  # pylint: disable=W0703

                print()

                message = 'Upgrade failed: %s' % e

                if verbose:
                    traceback.print_exc()
                else:
                    print(e)

                print()

                result = pki.read_text(
                    'Continue (Yes/No)',
                    options=['Y', 'N'],
                    default='Y',
                    delimiter='?',
                    case_sensitive=False).lower()

                if result == 'n':
                    raise pki.PKIException(message, e)

    def upgrade(self):

        versions = self.versions()

        for version in versions:
            self.upgrade_version(version)
            print()

        if self.is_complete():
            print('Upgrade complete.')

        else:
            self.show_tracker()
            print('Upgrade incomplete.')

    def revert_version(self, version):

        print('Reverting to version ' + str(version) + ':')

        scriptlets = self.scriptlets(version)
        scriptlets.reverse()

        for scriptlet in scriptlets:

            message = str(scriptlet.index) + '. ' + scriptlet.message

            if self.silent:
                print(message)

            else:
                result = pki.read_text(
                    message + ' (Yes/No)',
                    options=['Y', 'N'], default='Y',
                    case_sensitive=False).lower()

                if result == 'n':
                    raise pki.PKIException('Revert canceled.')

            try:
                scriptlet.revert()

            except pki.PKIException:
                raise

            except Exception as e:  # pylint: disable=W0703

                print()

                message = 'Revert failed: %s' % e

                if verbose:
                    traceback.print_exc()
                else:
                    print(e)

                print()

                result = pki.read_text(
                    'Continue (Yes/No)', options=['Y', 'N'],
                    default='Y', delimiter='?', case_sensitive=False).lower()

                if result == 'n':
                    raise pki.PKIException(message, e)

        self.set_tracker(version)

    def revert(self):

        current_version = self.get_current_version()

        versions = self.all_versions()
        versions.reverse()

        # find the first version smaller than the current version
        for version in versions:

            if version >= current_version:
                continue

            self.revert_version(version)
            return

        print('Unable to revert from version ' + str(current_version) + '.')

    def show_tracker(self):

        tracker = self.get_tracker()
        tracker.show()

    def status(self):

        self.show_tracker()

        if self.is_complete():
            print('Upgrade complete.')

        else:
            print('Upgrade incomplete.')

    def set_tracker(self, version):

        tracker = self.get_tracker()
        tracker.set(version)

        print('Tracker has been set to version ' + str(version) + '.')

    def reset_tracker(self):

        target_version = self.get_target_version()
        self.set_tracker(target_version)

    def remove_tracker(self):

        tracker = self.get_tracker()
        tracker.remove()

        print('Tracker has been removed.')
