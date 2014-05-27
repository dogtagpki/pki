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

    def __init__(self, protocol='http', hostname='localhost', port='8080',
                 subsystem='ca', accept='application/json'):

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

    def set_authentication_cert(self, pem_cert_path):
        if pem_cert_path is None:
            raise Exception("No path for the certificate specified.")
        if len(str(pem_cert_path)) == 0:
            raise Exception("No path for the certificate specified.")
        self.session.cert = pem_cert_path

    def get(self, path, headers=None, params=None, payload=None):
        r = self.session.get(
            self.serverURI + path,
            verify=False,
            headers=headers,
            params=params,
            data=payload)
        r.raise_for_status()
        return r

    def post(self, path, payload, headers=None, params=None):
        r = self.session.post(
            self.serverURI + path,
            verify=False,
            data=payload,
            headers=headers,
            params=params)
        r.raise_for_status()
        return r


def main():
    conn = PKIConnection()
    headers = {'Content-type': 'application/json',
               'Accept': 'application/json'}
    conn.set_authentication_cert('/root/temp4.pem')
    print conn.get("", headers).json()

if __name__ == "__main__":
    main()
