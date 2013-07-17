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

import pki.encoder as encoder
import xml.etree.ElementTree as ET

class SecurityDomainInfo:

    def __init__(self):
        self.name = None

class SecurityDomainClient:

    def __init__(self, connection):
        self.connection = connection

    def getSecurityDomainInfo(self):
        r = self.connection.get('/rest/securityDomain/domainInfo')
        j = r.json()

        info = SecurityDomainInfo()
        info.name = j['DomainInfo']['@id']

        return info

    def getOldSecurityDomainInfo(self):
        r = self.connection.get('/admin/ca/getDomainXML')
        root = ET.fromstring(r.text)
        domaininfo = ET.fromstring(root.find("DomainInfo").text)
        info = SecurityDomainInfo()
        info.name = domaininfo.find("Name").text

        return info

class ConfigurationRequest:

    def __init__(self):
        self.token = "Internal Key Storage Token"
        self.isClone = "false"
        self.secureConn = "off"
        self.importAdminCert = "false"
        self.generateServerCert = "true"

class ConfigurationResponse:

    def __init__(self):
        pass

class SystemCertData:

    def __init__(self):
        pass

class SystemConfigClient:

    def __init__(self, connection):
        self.connection = connection

    def configure(self, data):
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}
        r = self.connection.post('/rest/installer/configure', data, headers)
        info = r.json()['ConfigurationResponse']
        return info

class SystemStatusClient:

    def __init__(self, connection):
        self.connection = connection

    def getStatus(self):
        r = self.connection.get('/admin/' + \
                self.connection.subsystem + '/getStatus')
        return r.text


encoder.TYPES['ConfigurationRequest'] = ConfigurationRequest
encoder.TYPES['ConfigurationResponse'] = ConfigurationResponse
encoder.NOTYPES['SystemCertData'] = SystemCertData
