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

import re
import os


CONF_DIR          = '/etc/pki'
SHARE_DIR         = '/usr/share/pki'
BASE_DIR          = '/var/lib'

PACKAGE_VERSION   = SHARE_DIR + '/VERSION'


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
            match = re.match('^\s*(\S*)\s*:\s*(.*)\s*$', line)

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
