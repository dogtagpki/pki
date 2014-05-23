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
import xml.etree.ElementTree as ETree
import os

SYSTEM_TYPE = "Fedora/RHEL"
if os.path.exists("/etc/debian_version"):
    SYSTEM_TYPE = "debian"


class SecurityDomainHost(object):
    def __init__(self):
        """ constructor """
        self.id = None
        self.clone = False
        self.domain_manager = False
        self.hostname = None
        self.unsecure_port = None
        self.admin_port = None
        self.agent_port = None
        self.ee_client_auth_port = None
        self.secure_port = None
        self.subsystem_name = None

    @classmethod
    def from_json(cls, json_value):
        host = cls()
        host.admin_port = json_value['SecureAdminPort']
        host.agent_port = json_value['SecureAgentPort']
        host.clone = json_value['Clone']
        host.domain_manager = json_value['DomainManager']
        host.ee_client_auth_port = json_value['SecureEEClientAuthPort']
        host.hostname = json_value['Hostname']
        host.id = json_value['id']
        host.secure_port = json_value['SecurePort']
        host.subsystem_name = json_value['SubsystemName']
        host.unsecure_port = json_value['Port']
        return host

class SecurityDomainSubsystem(object):
    def __init__(self):
        self.name = None
        self.hosts = {}

    @classmethod
    def from_json(cls, json_value):
        ret = cls()
        ret.name = json_value['id']
        for host in json_value['Host']:
            ret.hosts[host['id']] = SecurityDomainHost.from_json(host)
        return ret


class SecurityDomainInfo(object):
    def __init__(self):
        self.name = None
        self.systems = {}

    @classmethod
    def from_json(cls, json_value):
        ret = cls()
        ret.name = json_value['id']
        for slist in json_value['Subsystem']:
            subsystem = SecurityDomainSubsystem.from_json(slist)
            ret.systems[slist['id']] = subsystem
        return ret


class SecurityDomainClient(object):
    def __init__(self, connection):
        self.connection = connection

    def get_security_domain_info(self):
        response = self.connection.get('/rest/securityDomain/domainInfo')
        info = SecurityDomainInfo.from_json(response.json())
        return info

    def get_old_security_domain_info(self):
        response = self.connection.get('/admin/ca/getDomainXML')
        root = ETree.fromstring(response.text)
        domaininfo = ETree.fromstring(root.find("DomainInfo").text)
        info = SecurityDomainInfo()
        info.name = domaininfo.find("Name").text
        return info


class ConfigurationRequest(object):
    def __init__(self):
        self.token = "Internal Key Storage Token"
        self.isClone = "false"
        self.secureConn = "off"
        self.importAdminCert = "false"
        self.generateServerCert = "true"


class ConfigurationResponse(object):
    def __init__(self):
        pass


class SystemCertData(object):
    def __init__(self):
        pass


class SystemConfigClient(object):
    def __init__(self, connection):
        self.connection = connection

    def configure(self, data):
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}
        response = self.connection.post('/rest/installer/configure', data, headers)
        return response.json()


class SystemStatusClient(object):
    def __init__(self, connection):
        self.connection = connection

    def get_status(self):
        response = self.connection.get('/admin/' +
                                       self.connection.subsystem + '/getStatus')
        return response.text


encoder.NOTYPES['ConfigurationRequest'] = ConfigurationRequest
encoder.NOTYPES['ConfigurationResponse'] = ConfigurationResponse
encoder.NOTYPES['SystemCertData'] = SystemCertData
