# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the Lesser GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2013 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
from __future__ import print_function
import functools
import logging
import os
import re
import shutil

import pki
import pki.util


DEFAULT_VERSION = '10.0.0'

UPGRADE_DIR = pki.SHARE_DIR + '/upgrade'
BACKUP_DIR = pki.LOG_DIR + '/upgrade'
SYSTEM_TRACKER = pki.CONF_DIR + '/pki.version'

logger = logging.getLogger(__name__)


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

        logger.info('Removing %s tracker', self.name)

        self.remove_version()
        self.remove_index()

    def set(self, version):

        logger.info('Setting %s tracker to version %s', self.name, version)

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
            return pki.util.Version(version)

        return pki.util.Version(DEFAULT_VERSION)

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

    def get_backup_dir(self):
        return BACKUP_DIR + '/' + str(self.version) + '/' + str(self.index)

    def upgrade_system(self):
        # Callback method to upgrade the system.
        pass

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
                    logger.info('Restoring %s', destpath)
                    pki.util.copydirs(sourcepath, destpath, force=True)

                for filename in filenames:
                    sourcefile = os.path.join(sourcepath, filename)
                    targetfile = os.path.join(destpath, filename)

                    logger.info('Restoring %s', targetfile)
                    pki.util.copyfile(sourcefile, targetfile, force=True)

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
                logger.info('Deleting %s', path)

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

            if not os.path.exists(destparent):
                pki.util.copydirs(sourceparent, destparent, force=True)

            if os.path.isfile(path):
                logger.info('Saving %s', path)
                # do not overwrite initial backup
                pki.util.copyfile(path, dest, force=False)

            else:
                for sourcepath, _, filenames in os.walk(path):

                    relpath = sourcepath[len(path):]
                    destpath = dest + relpath

                    logger.info('Saving %s', sourcepath)
                    pki.util.copydirs(sourcepath, destpath, force=True)

                    for filename in filenames:
                        sourcefile = os.path.join(sourcepath, filename)
                        targetfile = os.path.join(destpath, filename)

                        logger.info('Saving %s', sourcefile)
                        # do not overwrite initial backup
                        pki.util.copyfile(sourcefile, targetfile, force=False)

        else:

            # otherwise, record the name

            logger.info('Recording %s', path)
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

    def __init__(self, upgrade_dir=UPGRADE_DIR):

        self.upgrade_dir = upgrade_dir
        self.system_tracker = None

    def version_dir(self, version):

        return os.path.join(self.upgrade_dir, str(version))

    def all_versions(self):

        all_versions = []

        if os.path.exists(self.upgrade_dir):
            for version in os.listdir(self.upgrade_dir):
                version = pki.util.Version(version)
                all_versions.append(version)

        all_versions.sort()

        return all_versions

    def versions(self):

        current_version = self.get_current_version()
        target_version = self.get_target_version()

        upgrade_path = []

        for version in self.all_versions():

            # skip older versions
            if version < current_version:
                continue

            # skip newer versions
            if version > target_version:
                continue

            upgrade_path.append(version)

        upgrade_path.sort()

        # start from current version
        if not upgrade_path or upgrade_path[0] != current_version:
            upgrade_path.insert(0, current_version)

        # stop at target version
        if not upgrade_path or upgrade_path[-1] != target_version:
            upgrade_path.append(target_version)

        logging.debug('Upgrade path:')
        for version in upgrade_path:
            logging.debug(' - %s', version)

        versions = []

        for index, version in enumerate(upgrade_path):

            # link versions
            if index < len(upgrade_path) - 1:
                version.next = upgrade_path[index + 1]
            else:
                version.next = target_version

            versions.append(version)

        return versions

    def scriptlets(self, version):
        scriptlets = []

        version_dir = self.version_dir(version)
        if not os.path.exists(version_dir):
            return scriptlets

        filenames = os.listdir(version_dir)
        for filename in filenames:

            # parse <index>_<classname>.py
            match = re.match(r'^(.+)-(.+)\.py$', filename)

            if not match:
                continue

            index = int(match.group(1))
            classname = match.group(2)

            # load scriptlet class
            variables = {}
            absname = os.path.join(version_dir, filename)
            with open(absname, 'r') as f:
                bytecode = compile(f.read(), absname, 'exec')
            exec(bytecode, variables)  # pylint: disable=W0122

            # create scriptlet object
            scriptlet = variables[classname]()

            scriptlet.version = version
            scriptlet.index = index

            scriptlets.append(scriptlet)

        # sort scriptlets based on index
        scriptlets.sort()

        if scriptlets:
            scriptlets[-1].last = True

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

        current_version = self.get_tracker().get_version()
        logging.debug('Current version: %s', current_version)

        return current_version

    def get_target_version(self):

        target_version = pki.util.Version(pki.specification_version())
        logging.debug('Target version: %s', target_version)

        return target_version

    def is_complete(self):

        current_version = self.get_current_version()
        target_version = self.get_target_version()

        return current_version == target_version

    def validate(self):

        if not self.is_complete():
            log_file = '/var/log/pki/pki-upgrade-%s.log' % self.get_target_version()
            raise Exception('Upgrade incomplete: see %s' % log_file)

    def upgrade_version(self, version):

        if version == version.next:
            print('Upgrading version %s:' % version)
        else:
            print('Upgrading from version %s to %s:' % (version, version.next))

        scriptlets = self.scriptlets(version)

        if len(scriptlets) == 0:

            print('No upgrade scriptlets.')

            self.set_tracker(version.next)
            return

        # execute scriptlets
        for scriptlet in scriptlets:

            message = str(scriptlet.index) + '. ' + scriptlet.message
            print(message)

            try:
                self.init_scriptlet(scriptlet)
                self.run_scriptlet(scriptlet)

            except Exception as e:  # pylint: disable=W0703

                print()

                message = 'Upgrade failed: %s' % e

                if logger.isEnabledFor(logging.INFO):
                    logger.exception(e)
                else:
                    logger.error(e)

                raise pki.PKIException(message, e)

    def init_scriptlet(self, scriptlet):

        backup_dir = scriptlet.get_backup_dir()

        if os.path.exists(backup_dir):
            logger.debug('Command: rm -rf %s', backup_dir)
            shutil.rmtree(backup_dir)

        logger.debug('Command: mkdir -p %s', backup_dir)
        os.makedirs(backup_dir)

    def can_upgrade(self, scriptlet):

        # A scriptlet can run if the version matches the tracker and
        # the index is the next to be executed.

        tracker = self.get_tracker()

        return scriptlet.version == tracker.get_version() and \
            scriptlet.index == tracker.get_index() + 1

    def run_scriptlet(self, scriptlet):

        try:
            if not self.can_upgrade(scriptlet):
                logger.info('Skipping system')
                return

            logger.info('Upgrading system')
            scriptlet.upgrade_system()
            self.update_tracker(scriptlet)

        except Exception as e:

            if logger.isEnabledFor(logging.INFO):
                logger.exception(e)
            else:
                logger.error(e)

            message = 'Failed upgrading system.'
            print(message)

            raise pki.PKIException('Upgrade failed: %s' % e, e)

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
            print(message)

            try:
                scriptlet.revert()

            except Exception as e:  # pylint: disable=W0703

                print()

                message = 'Revert failed: %s' % e

                if logger.isEnabledFor(logging.INFO):
                    logger.exception(e)
                else:
                    logger.error(e)

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

    def update_tracker(self, scriptlet):

        # Increment the index in the tracker. If it's the last scriptlet
        # in this version, update the tracker version.

        tracker = self.get_tracker()
        scriptlet.backup(tracker.filename)

        if not scriptlet.last:
            tracker.set_index(scriptlet.index)

        else:
            tracker.remove_index()
            tracker.set_version(scriptlet.version.next)

    def reset_tracker(self):

        target_version = self.get_target_version()
        self.set_tracker(target_version)

    def remove_tracker(self):

        tracker = self.get_tracker()
        tracker.remove()

        print('Tracker has been removed.')
