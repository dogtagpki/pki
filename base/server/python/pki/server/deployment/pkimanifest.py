#!/usr/bin/python -t
# Authors:
#     Matthew Harmsen <mharmsen@redhat.com>
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
# Copyright (C) 2012 Red Hat, Inc.
# All rights reserved.
#

# System Imports
import csv

# PKI Deployment Imports
from . import pkiconfig as config
from . import pkimessages as log


# PKI Deployment Manifest Constants
RECORD_TYPE_DIRECTORY = "directory"
RECORD_TYPE_FILE = "file"
RECORD_TYPE_SYMLINK = "symlink"


# PKI Deployment Manifest Record Class
class Record(object):
    __slots__ = "name", \
               "type", \
               "user", \
               "group", \
               "uid", \
               "gid", \
               "permissions", \
               "acls",

    def __init__(self):
        self.name = None
        self.type = None
        self.user = None
        self.group = None
        self.uid = None
        self.gid = None
        self.permissions = None
        self.acls = None

    def items(self):
        "dict style items"
        return [
            (field_name, getattr(self, field_name))
            for field_name in self.__slots__]

    def __iter__(self):
        "iterate over fields tuple/list style"
        for field_name in self.__slots__:
            yield getattr(self, field_name)

    def __getitem__(self, index):
        "tuple/list style getitem"
        return getattr(self, self.__slots__[index])


# PKI Deployment Manifest File Class
class File:

    def __init__(self, database):
        self.filename = None
        self.database = database

    def register(self, name):
        self.filename = name

    def write(self):
        try:
            with open(self.filename, "w") as fd:
                c = csv.writer(fd)
                for record in self.database:
                    c.writerow(tuple(record))
        except IOError as exc:
            config.pki_log.error(log.PKI_IOERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_1)
            raise

    def read(self):
        try:
            with open(self.filename, "r") as fd:
                cr = csv.reader(fd)
                for row in cr:
                    print tuple(row)
        except IOError as exc:
            config.pki_log.error(log.PKI_IOERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_1)
            raise

