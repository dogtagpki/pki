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

import pki

INSTANCE_BASE_DIR = '/var/lib/pki'
REGISTRY_DIR = '/etc/sysconfig/pki'
SUBSYSTEM_TYPES = ['ca', 'kra', 'ocsp', 'tks', 'tps']


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
            self.conf_dir = os.path.join(pki.BASE_DIR, instance.name, 'conf')
            self.base_dir = os.path.join(pki.BASE_DIR, instance.name)

        self.validate()

    def validate(self):
        if not os.path.exists(self.conf_dir):
            raise pki.PKIException(
                'Invalid subsystem: ' + self.__repr__(),
                 None, self.instance)


    def __repr__(self):
        return str(self.instance) + '/' + self.name


class PKIInstance(object):

    def __init__(self, name, instanceType=10):
        self.name = name
        self.type = instanceType
        if self.type >= 10:
            self.conf_dir = os.path.join(INSTANCE_BASE_DIR, name, 'conf')
            self.base_dir = os.path.join(INSTANCE_BASE_DIR, name)
        else:
            self.conf_dir = os.path.join(pki.BASE_DIR, name, 'conf')
            self.base_dir = os.path.join(pki.BASE_DIR, name)

        self.validate()

    def validate(self):
        if not os.path.exists(self.conf_dir):
            raise pki.PKIException(
                'Invalid instance: ' + self.__repr__(), None)

    def __repr__(self):
        if self.type == 9:
            return "Dogtag 9 " + self.name
        return self.name


class PKIServerException(pki.PKIException):

    def __init__(self, message, exception=None, \
                 instance=None, subsystem=None):

        pki.PKIException.__init__(self, message, exception)

        self.instance = instance
        self.subsystem = subsystem
