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

import requests

class PKIConnection:

    def __init__(self,
            protocol='http',
            hostname='localhost',
            port=80,
            subsystem='ca',
            accept='application/json'):

        self.protocol = protocol
        self.hostname = hostname
        self.port = port
        self.subsystem = subsystem

        self.serverURI = self.protocol + '://' + \
            self.hostname + ':' + self.port + '/' + \
            self.subsystem

        self.session = requests.Session()
        if accept:
            self.session.headers.update({'Accept': accept})

    def authenticate(self, username=None, password=None):
        if username is not None and password is not None:
            self.session.auth = (username, password)

    def get(self, path, headers=None):
        r = self.session.get(
            self.serverURI + path,
            verify=False,
            headers=headers)
        r.raise_for_status()
        return r

    def post(self, path, payload, headers=None):
        r = self.session.post(
                self.serverURI + path,
                verify=False,
                data=payload,
                headers=headers)
        r.raise_for_status()
        return r
