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

from __future__ import absolute_import
import json
import xml.etree.ElementTree as ETree
import os

import pki.encoder

SYSTEM_TYPE = "Fedora/RHEL"
if os.path.exists("/etc/debian_version"):
    SYSTEM_TYPE = "debian"


class SecurityDomainHost(object):
    """
    Class representing a security domain host.
    """

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
        """
        Constructs a SecurityDomainHost object from JSON.

        :param json_value: JSON string representing a security domain host.
        :type json_value: str
        :returns: SecurityDomainHost
        """

        host = cls()

        try:
            # 10.2.x
            host.id = json_value['id']

        except KeyError:
            # 10.1.x
            host.id = json_value['@id']

        host.admin_port = json_value['SecureAdminPort']
        host.agent_port = json_value['SecureAgentPort']
        host.clone = json_value['Clone']
        host.domain_manager = json_value['DomainManager']
        host.ee_client_auth_port = json_value['SecureEEClientAuthPort']
        host.hostname = json_value['Hostname']
        host.secure_port = json_value['SecurePort']
        host.subsystem_name = json_value['SubsystemName']
        host.unsecure_port = json_value['Port']

        return host


class SecurityDomainSubsystem(object):
    """
    Class representing a security domain subsystem.
    This is essentially a list of SecurityDomainHost objects of a
    particular subsystem type (ca, kra, tps, tks, ocsp).
    """

    def __init__(self):
        self.name = None
        self.hosts = {}

    @classmethod
    def from_json(cls, json_value):
        """
        Constructs a SecurityDomainSubsystem from a JSON representation.

        :param json_value: JSON representation of the Security Domain Subsystem
        :type json_value: str
        :returns: SecurityDomainSubsystem
        """

        subsystem = cls()

        try:
            # 10.2.x
            subsystem.name = json_value['id']

        except KeyError:
            # 10.1.x
            subsystem.name = json_value['@id']

        hosts = json_value['Host']
        if isinstance(hosts, dict):
            hosts = [hosts]

        for h in hosts:
            host = SecurityDomainHost.from_json(h)
            subsystem.hosts[host.id] = host

        return subsystem


class SecurityDomainInfo(object):
    """
    Class representing the entire security domain.
    This is essentially a list of SecurityDomainSubsystem components.
    """

    def __init__(self):
        self.name = None
        self.systems = {}

    @classmethod
    def from_json(cls, json_value):
        """
        Create a SecurityDomainInfo object from JSON.

        :param json_value: JSON representation of a security domain.
        :type json_value: str
        :returns: SecurityDomainInfo
        """

        security_domain = cls()

        try:
            # 10.2.x
            security_domain.name = json_value['id']
            subsystems = json_value['Subsystem']

        except KeyError:
            # 10.1.x
            domain_info = json_value['DomainInfo']
            security_domain.name = domain_info['@id']

            subsystems = domain_info['Subsystem']
            if isinstance(subsystems, dict):
                subsystems = [subsystems]

        for s in subsystems:
            subsystem = SecurityDomainSubsystem.from_json(s)
            security_domain.systems[subsystem.name] = subsystem

        return security_domain


class SecurityDomainClient(object):
    """
    Client used to get the security domain from a security domain CA.
    The connection details for the security domain CA are specified in
    a PKIConnection object used to construct this client.
    """

    def __init__(self, connection):
        self.connection = connection

    def get_security_domain_info(self):
        """
        Contact the security domain CA specified in the connection object
        used to construct this client and get the security domain using the
        REST API.

        :returns: pki.system.SecurityDomainInfo
        """
        response = self.connection.get('/rest/securityDomain/domainInfo')
        info = SecurityDomainInfo.from_json(response.json())
        return info

    def get_old_security_domain_info(self):
        """
        Contact the security domain CA specified in the connection object
        used to construct this client and get the security domain using the
        old servlet-based interface.  This method is useful when contacting
        old servers which do not provide the REST API.

        :returns: pki.system.SecurityDomainInfo
        """
        response = self.connection.get('/admin/ca/getDomainXML')
        root = ETree.fromstring(response.text)
        domaininfo = ETree.fromstring(root.find("DomainInfo").text)
        info = SecurityDomainInfo()
        info.name = domaininfo.find("Name").text
        return info


class ConfigurationRequest(object):
    """
    Class used to represent a configuration request to be submitted to the
    Java installation servlet during the execution of pkispawn.

    This class is the python equivalent of the Java class:
    com.netscape.certsrv.system.ConfigurationRequest
    """

    def __init__(self):
        self.token = None
        self.isClone = "false"
        self.secureConn = "off"
        self.generateServerCert = "true"


class ConfigurationResponse(object):
    """
    Class used to represent the response from the Java configuration
    servlet during the execution of pkispawn.

    This class is the python equivalent of the Java class:
    com.netscape.certsrv.system.ConfigurationRequest
    """

    def __init__(self):
        pass


class AdminSetupRequest(object):
    def __init__(self):
        pass


class AdminSetupResponse(object):
    def __init__(self):
        pass


class KeyBackupRequest(object):
    def __init__(self):
        pass


class SystemCertData(object):
    """
    Class used to represent the data for a system certificate, which is
    used in the data passed into and returned from the Java installation
    servlet during the execution of pkispawn.

    This class is the python equivalent of the Java class:
    com.netscape.certsrv.system.SystemCertData
    """

    def __init__(self):
        pass


class SystemConfigClient(object):
    """
    Client used to interact with the Java configuration servlet to configure
    a Dogtag subsystem during the execution of pkispawn.

    The connection details for the system being configured are passed in
    the PKIConnection object used when constructing this object.
    """

    def __init__(self, connection):
        self.connection = connection

    def configure(self, request):
        """
        Contacts the server and invokes the Java configuration REST API to
        configure a Dogtag subsystem.

        :param request: Configuration request containing all the input needed to
            configure the subsystem
        :type request: ConfigurationRequest
        :return: ConfigurationResponse -- response from configuration servlet.
        """
        data = json.dumps(request, cls=pki.encoder.CustomTypeEncoder)
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}
        response = self.connection.post(
            '/rest/installer/configure',
            data,
            headers)
        return response.json()

    def setupDatabase(self, request):
        """
        Set up database.

        :param request: Configuration request
        :type request: ConfigurationRequest
        """
        data = json.dumps(request, cls=pki.encoder.CustomTypeEncoder)
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}
        self.connection.post(
            '/rest/installer/setupDatabase',
            data,
            headers)

    def configureCerts(self, request):
        """
        Configure certificates.

        :param request: Configuration request
        :type request: ConfigurationRequest
        :return: ConfigurationResponse
        """
        data = json.dumps(request, cls=pki.encoder.CustomTypeEncoder)
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}
        response = self.connection.post(
            '/rest/installer/configureCerts',
            data,
            headers)
        return response.json()

    def setupAdmin(self, request):
        """
        Set up admin.

        :param request: Admin setup request
        :type request: AdminSetupRequest
        :return: AdminSetupResponse
        """
        data = json.dumps(request, cls=pki.encoder.CustomTypeEncoder)
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}
        response = self.connection.post(
            '/rest/installer/setupAdmin',
            data,
            headers)
        return response.json()

    def backupKeys(self, request):
        """
        Backup keys.

        :param request: Key backup request
        :type request: KeyBackupRequest
        """
        data = json.dumps(request, cls=pki.encoder.CustomTypeEncoder)
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}
        self.connection.post(
            '/rest/installer/backupKeys',
            data,
            headers)

    def setupSecurityDomain(self, request):
        """
        Setup security domain.

        :param request: Configuration request
        :type request: ConfigurationRequest
        """
        data = json.dumps(request, cls=pki.encoder.CustomTypeEncoder)
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}
        self.connection.post(
            '/rest/installer/setupSecurityDomain',
            data,
            headers)

    def setupDatabaseUser(self, request):
        """
        Set up database user.

        :param request: Configuration request
        :type request: ConfigurationRequest
        """
        data = json.dumps(request, cls=pki.encoder.CustomTypeEncoder)
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}
        self.connection.post(
            '/rest/installer/setupDatabaseUser',
            data,
            headers)

    def finalizeConfiguration(self, request):
        """
        Finalize server configuration.

        :param request: Configuration request
        :type request: ConfigurationRequest
        """
        data = json.dumps(request, cls=pki.encoder.CustomTypeEncoder)
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}
        self.connection.post(
            '/rest/installer/finalizeConfiguration',
            data,
            headers)


class SystemStatusClient(object):
    """
    Client used to check the status of a Dogtag subsystem.
    """

    def __init__(self, connection):
        self.connection = connection

    def get_status(self, timeout=None):
        """
        Checks the status of the subsystem by calling the getStatus()
        servlet.  This is used to determine if the server is up and ready to
        receive and process requests.

        :return: str - getStatus response
        """
        response = self.connection.get(
            '/admin/' + self.connection.subsystem + '/getStatus',
            timeout=timeout,
        )
        return response.text


pki.encoder.NOTYPES['ConfigurationRequest'] = ConfigurationRequest
pki.encoder.NOTYPES['ConfigurationResponse'] = ConfigurationResponse
pki.encoder.NOTYPES['AdminSetupRequest'] = AdminSetupRequest
pki.encoder.NOTYPES['AdminSetupResponse'] = AdminSetupResponse
pki.encoder.NOTYPES['KeyBackupRequest'] = KeyBackupRequest
pki.encoder.NOTYPES['SystemCertData'] = SystemCertData
