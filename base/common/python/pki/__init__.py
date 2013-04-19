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
INSTANCE_BASE_DIR = '/var/lib/pki'
REGISTRY_DIR      = '/etc/sysconfig/pki'
SUBSYSTEM_TYPES   = ['ca', 'kra', 'ocsp', 'tks']

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

class PKISubsystem(object):

    def __init__(self, instance, subsystemName):
        self.instance = instance
        self.name = subsystemName
        self.type = instance.type
        if self.type >= 10:
            self.conf_dir = os.path.join(INSTANCE_BASE_DIR, \
                instance.name, 'conf', subsystemName)
            self.base_dir = os.path.join(INSTANCE_BASE_DIR, \
                instance.name, subsystemName)
        else:
            self.conf_dir = os.path.join(BASE_DIR, instance.name, 'conf')
            self.base_dir = os.path.join(BASE_DIR, instance.name)

        self.validate()

    def validate(self):
        if not os.path.exists(self.conf_dir):
            raise PKIException(
                'Invalid subsystem: ' + self.__repr__(),
                 None, self.instance)


    def __repr__(self):
        return str(self.instance) + '/' + self.name


class PKIInstance(object):

    def __init__(self, name, type=10):
        self.name = name
        self.type = type
        if self.type >= 10:
            self.conf_dir = os.path.join(INSTANCE_BASE_DIR, name, 'conf')
            self.base_dir = os.path.join(INSTANCE_BASE_DIR, name)
        else:
            self.conf_dir = os.path.join(BASE_DIR, name, 'conf')
            self.base_dir = os.path.join(BASE_DIR, name)

        self.validate()

    def validate(self):
        if not os.path.exists(self.conf_dir):
            raise PKIException(
                'Invalid instance: ' + self.__repr__(), None)


    def __repr__(self):
        if self.type == 9:
            return "Dogtag 9 " + self.name
        return self.name

class PKIException(Exception):

    def __init__(self, message, exception=None,\
                 instance=None, subsystem=None):

        Exception.__init__(self, message)

        self.exception = exception
        self.instance = instance
        self.subsystem = subsystem
