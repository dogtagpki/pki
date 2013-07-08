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
import re


CONF_DIR = '/etc/pki'
SHARE_DIR = '/usr/share/pki'
BASE_DIR = '/var/lib'
LOG_DIR = '/var/log/pki'

PACKAGE_VERSION = SHARE_DIR + '/VERSION'


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


def implementation_version():

    with open(PACKAGE_VERSION, 'r') as f:
        for line in f:
            line = line.strip('\n')

            # parse <key>: <value>
            match = re.match(r'^\s*(\S*)\s*:\s*(.*)\s*$', line)

            if not match:
                continue

            key = match.group(1)
            value = match.group(2)

            if key.lower() != 'implementation-version':
                continue

            return value

    raise Exception('Missing implementation version.')


class PKIException(Exception):

    def __init__(self, message, exception=None):

        Exception.__init__(self, message)

        self.exception = exception


class PropertyFile(object):

    def __init__(self, filename, delimiter='='):

        self.filename = filename
        self.delimiter = delimiter

        self.lines = []

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

    def show(self):

        for line in self.lines:
            print line

    def insert_line(self, index, line):

        self.lines.insert(index, line)

    def remove_line(self, index):

        self.lines.pop(index)

    def index(self, name):

        for i, line in enumerate(self.lines):

            # parse <key> <delimiter> <value>
            match = re.match(r'^\s*(\S*)\s*%s\s*(.*)\s*$' % self.delimiter, line)

            if not match:
                continue

            key = match.group(1)

            if key.lower() == name.lower():
                return i

        return -1

    def get(self, name):

        result = None

        for line in self.lines:

            # parse <key> <delimiter> <value>
            match = re.match(r'^\s*(\S*)\s*%s\s*(.*)\s*$' % self.delimiter, line)

            if not match:
                continue

            key = match.group(1)
            value = match.group(2)

            if key.lower() == name.lower():
                return value

        return result

    def set(self, name, value, index=None):

        for i, line in enumerate(self.lines):

            # parse <key> <delimiter> <value>
            match = re.match(r'^\s*(\S*)\s*%s\s*(.*)\s*$' % self.delimiter, line)

            if not match:
                continue

            key = match.group(1)

            if key.lower() == name.lower():
                self.lines[i] = key + self.delimiter + value
                return

        if index is None:
            self.lines.append(name + self.delimiter + value)

        else:
            self.insert_line(index, name + self.delimiter + value)

    def remove(self, name):

        for i, line in enumerate(self.lines):

            # parse <key> <delimiter> <value>
            match = re.match(r'^\s*(\S*)\s*%s\s*(.*)\s*$' % self.delimiter, line)

            if not match:
                continue

            key = match.group(1)
            value = match.group(2)

            if key.lower() == name.lower():
                self.lines.pop(i)
                return value

        return None
