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
"""
Module containing utility functions and classes for the Dogtag python code
"""


from __future__ import absolute_import
import functools
import logging
import os
import re
import shutil
from shutil import Error
try:
    from shutil import WindowsError  # pylint: disable=E0611
except ImportError:
    WindowsError = None

import six
from six.moves import input   # pylint: disable=W0622,F0401
import subprocess

DEFAULT_PKI_ENV_LIST = [
    '/usr/share/pki/etc/pki.conf',
    '/etc/pki/pki.conf',
]


def replace_params(line, params=None):
    """
    Replace all occurrences of [param] in the line with the value of the
    parameter.
    """

    if not params:
        return line

    # find the first parameter in the line
    begin = line.find('[')

    # repeat while there are parameters in the line
    while begin >= 0:

        # find the end of the parameter
        end = line.find(']', begin + 1)

        # if the end not is found not found, don't do anything
        if end < 0:
            return line

        # get parameter name
        name = line[begin + 1:end]

        try:
            # get parameter value as string
            value = str(params[name])

            # replace parameter with value, keep the rest of the line
            line = line[0:begin] + value + line[end + 1:]

            # calculate the new end position
            end = begin + len(value) + 1

        except KeyError:
            # undefined parameter, skip
            logging.warning('Ignoring [%s] parameter', line[begin:end + 1])

        # find the next parameter in the remainder of the line
        begin = line.find('[', end + 1)

    return line


def makedirs(path, uid=-1, gid=-1, force=False):

    logging.debug('Command: mkdir -p %s', path)

    if force and os.path.exists(path):
        logging.warning('Directory already exists: %s', path)
        return

    os.makedirs(path)
    os.chown(path, uid, gid)


def symlink(source, dest, uid=-1, gid=-1, force=False):

    logging.debug('Command: ln -s %s %s', source, dest)

    if force and os.path.exists(dest):
        logging.warning('Link already exists: %s', dest)
        return

    os.symlink(source, dest)
    os.lchown(dest, uid, gid)


def copy(source, dest, uid=-1, gid=-1, force=False):
    """
    Copy a file or a folder and its contents.
    """

    # remove trailing slashes
    if source[-1] == '/':
        source = source[:-1]
    if dest[-1] == '/':
        dest = dest[:-1]

    sourceparent = os.path.dirname(source)
    destparent = os.path.dirname(dest)

    if not os.path.exists(destparent):
        copydirs(sourceparent, destparent, uid=uid, gid=gid, force=force)

    if os.path.isfile(source):
        copyfile(source, dest, uid=uid, gid=gid, force=force)

    else:
        for sourcepath, _, filenames in os.walk(source):

            relpath = sourcepath[len(source):]
            destpath = dest + relpath
            if destpath == '':
                destpath = '/'

            copydirs(sourcepath, destpath, uid=uid, gid=gid, force=force)

            for filename in filenames:
                sourcefile = os.path.join(sourcepath, filename)
                targetfile = os.path.join(destpath, filename)
                copyfile(sourcefile, targetfile, uid=uid, gid=gid, force=force)


def copyfile(source, dest, uid=-1, gid=-1, force=False):
    """
    Copy a file or link while preserving its attributes.
    """

    logging.debug('Command: cp %s %s', source, dest)

    # if dest already exists and not overwriting, do nothing
    if os.path.exists(dest):
        logging.warning('File already exists: %s', dest)

        if not force:
            return

    if os.path.islink(source):
        target = os.readlink(source)
        os.symlink(target, dest)

        stat = os.lstat(source)
        if uid == -1:
            uid = stat.st_uid
        if gid == -1:
            gid = stat.st_gid

        os.lchown(dest, uid, gid)

    else:
        shutil.copyfile(source, dest)

        stat = os.stat(source)
        if uid == -1:
            uid = stat.st_uid
        if gid == -1:
            gid = stat.st_gid

        os.utime(dest, (stat.st_atime, stat.st_mtime))
        os.chmod(dest, stat.st_mode)
        os.chown(dest, uid, gid)


def copydirs(source, dest, uid=-1, gid=-1, force=False):
    """
    Copy a folder and its parents while preserving their attributes.
    """

    destparent = os.path.dirname(dest)

    if not os.path.exists(destparent):
        sourceparent = os.path.dirname(source)
        copydirs(sourceparent, destparent, uid=uid, gid=gid, force=force)

    logging.debug('Command: mkdir %s', dest)

    if force and os.path.exists(dest):
        logging.warning('Directory already exists: %s', dest)
        return

    os.mkdir(dest)

    stat = os.stat(source)
    if uid == -1:
        uid = stat.st_uid
    if gid == -1:
        gid = stat.st_gid

    os.utime(dest, (stat.st_atime, stat.st_mtime))
    os.chmod(dest, stat.st_mode)
    os.chown(dest, uid, gid)


def chown(path, uid, gid):
    """
    Change ownership of a file, link, or folder recursively.
    """

    if os.path.islink(path):
        os.lchown(path, uid, gid)
    else:
        os.chown(path, uid, gid)

    if not os.path.isdir(path):
        return

    for item in os.listdir(path):
        itempath = os.path.join(path, item)
        chown(itempath, uid, gid)


def chmod(path, perms):
    """
    Change permissions of a file, link, or folder recursively.
    """

    os.chmod(path, perms)

    if not os.path.isdir(path):
        return

    for item in os.listdir(path):
        itempath = os.path.join(path, item)
        chmod(itempath, perms)


def remove(path, force=False):

    logging.debug('Command: rm -rf %s', path)

    if force and not os.path.exists(path):
        logging.warning('File not found: %s', path)
        return

    os.remove(path)


def rmtree(path, force=False):

    logging.debug('Command: rm -rf %s', path)

    if force and not os.path.exists(path):
        logging.warning('Directory not found: %s', path)
        return

    shutil.rmtree(path)


def unlink(link, force=False):

    logging.debug('Command: rm -rf %s', link)

    if force and not os.path.islink(link):
        logging.warning('Link not found: %s', link)
        return

    os.unlink(link)


def customize_file(input_file, output_file, params):
    """
    Customize a file with specified parameters.
    """

    with open(input_file) as infile, open(output_file, 'w') as outfile:
        for line in infile:
            for src, target in params.items():
                line = line.replace(src, target)
            outfile.write(line)


def load_properties(filename, properties):

    with open(filename) as f:

        lines = f.read().splitlines()
        name = None
        multi_line = False

        for index, line in enumerate(lines):

            if multi_line:
                # append line to previous property

                value = properties[name]
                value = value + line

            else:
                # parse line for new property

                line = line.lstrip()
                if not line or line.startswith('#'):
                    continue

                parts = line.split('=', 1)
                if len(parts) < 2:
                    raise Exception('Missing delimiter in %s line %d' %
                                    (filename, index + 1))

                name = parts[0].rstrip()
                value = parts[1].lstrip()

            # check if the value is multi-line
            if value.endswith('\\'):
                value = value[:-1]
                multi_line = True

            else:
                value = value.rstrip()
                multi_line = False

            # store value in properties
            properties[name] = value


def store_properties(filename, properties):

    with open(filename, 'w') as f:

        for name, value in properties.items():
            line = '%s=%s\n' % (name, value)
            f.write(line)


def copytree(src, dst, symlinks=False, ignore=None):
    """
    Recursively copy a directory tree using copy2().

    PATCH:  This code was copied from 'shutil.py' and patched to
            allow 'The destination directory to already exist.'

    If exception(s) occur, an Error is raised with a list of reasons.

    If the optional symlinks flag is true, symbolic links in the
    source tree result in symbolic links in the destination tree; if
    it is false, the contents of the files pointed to by symbolic
    links are copied.

    The optional ignore argument is a callable. If given, it
    is called with the `src` parameter, which is the directory
    being visited by copytree(), and `names` which is the list of
    `src` contents, as returned by os.listdir():

        callable(src, names) -> ignored_names

    Since copytree() is called recursively, the callable will be
    called once for each directory that is copied. It returns a
    list of names relative to the `src` directory that should
    not be copied.

    Consider this example code rather than the ultimate tool.
    """
    names = os.listdir(src)
    if ignore is not None:
        ignored_names = ignore(src, names)
    else:
        ignored_names = set()

    # PATCH:  ONLY execute 'os.makedirs(dst)' if the top-level
    #         destination directory does NOT exist!
    if not os.path.exists(dst):
        os.makedirs(dst)
    errors = []
    for name in names:
        if name in ignored_names:
            continue
        srcname = os.path.join(src, name)
        dstname = os.path.join(dst, name)
        try:
            if symlinks and os.path.islink(srcname):
                linkto = os.readlink(srcname)
                os.symlink(linkto, dstname)
            elif os.path.isdir(srcname):
                copytree(srcname, dstname, symlinks, ignore)
            else:
                # Will raise a SpecialFileError for unsupported file types
                shutil.copy2(srcname, dstname)
        # catch the Error from the recursive copytree so that we can
        # continue with other files
        except Error as err:
            errors.extend(err.args[0])
        except EnvironmentError as why:
            errors.append((srcname, dstname, str(why)))
    try:
        shutil.copystat(src, dst)
    except OSError as why:
        if WindowsError is not None and isinstance(why, WindowsError):
            # Copying file access times may fail on Windows
            pass
        else:
            errors.extend((src, dst, str(why)))
    if errors:
        raise Error(errors)


def read_environment_files(env_file_list=None):
    if env_file_list is None:
        env_file_list = DEFAULT_PKI_ENV_LIST

    file_command = ' && '.join(
        'source {}'.format(env_file) for env_file in env_file_list)
    file_command += ' && env'

    command = [
        'bash',
        '-c',
        file_command
    ]

    env_vals = subprocess.check_output(command).decode('utf-8').split('\n')

    for env_val in env_vals:
        (key, _, value) = env_val.partition("=")
        if not key.strip() or key == u'_':
            continue
        os.environ[key] = value


def read_text(message,
              options=None, default=None, delimiter=':',
              allow_empty=True, case_sensitive=True):
    """
    Get an input from the user. This is used, for example, in
    pkispawn and pkidestroy to obtain user input.

    :param message: prompt to display to the user
    :type message: str
    :param options: list of possible inputs by the user.
    :type options: list
    :param default: default value of parameter being prompted.
    :type default: str
    :param delimiter: delimiter to be used at the end of the prompt.
    :type delimiter: str
    :param allow_empty: Allow input to be empty.
    :type allow_empty: boolean -- True/False
    :param case_sensitive: Allow input to be case sensitive.
    :type case_sensitive: boolean -- True/False
    :returns: str -- value obtained from user input.
    """
    if default:
        message = message + ' [' + default + ']'
    message = message + delimiter + ' '

    done = False
    value = None
    while not done:
        value = input(message)
        value = value.strip()

        if len(value) == 0:  # empty value
            if allow_empty:
                value = default
                break

        else:  # non-empty value
            if options is not None:
                for val in options:
                    if case_sensitive:
                        if val == value:
                            done = True
                            break
                    else:
                        if val.lower() == value.lower():
                            done = True
                            break
            else:
                break

    return value


@functools.total_ordering
class Version(object):

    def __init__(self, obj):

        if isinstance(obj, six.string_types):

            # parse <major>.<minor>.<patch>[<suffix>]
            match = re.match(r'^(\d+)\.(\d+)\.(\d+)', obj)

            if match is None:
                raise Exception('Unable to parse version number: %s' % obj)

            self.major = int(match.group(1))
            self.minor = int(match.group(2))
            self.patch = int(match.group(3))

        elif isinstance(obj, Version):

            self.major = obj.major
            self.minor = obj.minor
            self.patch = obj.patch

        else:
            raise Exception('Unsupported version type: %s' % type(obj))

    # release is ignored in comparisons
    def __eq__(self, other):
        return (self.major == other.major and
                self.minor == other.minor and
                self.patch == other.patch)

    def __ne__(self, other):
        return not self.__eq__(other)

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

    def __gt__(self, other):
        return not self.__lt__(other) and not self.__eq__(other)

    # not hashable
    __hash__ = None

    def __repr__(self):
        return '%d.%d.%d' % (self.major, self.minor, self.patch)
