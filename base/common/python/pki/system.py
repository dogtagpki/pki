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

        self.domain_info_url = '/rest/securityDomain/domainInfo'
        self.domain_xml_url = '/admin/ca/getDomainXML'

        if connection.subsystem is None:
            self.domain_info_url = '/ca' + self.domain_info_url
            self.domain_xml_url = '/ca' + self.domain_xml_url

    def get_security_domain_info(self):
        """
        Contact the security domain CA specified in the connection object
        used to construct this client and get the security domain using the
        REST API.

        :returns: pki.system.SecurityDomainInfo
        """
        response = self.connection.get(self.domain_info_url)
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
        response = self.connection.get(self.domain_xml_url)
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
        self.isClone = "false"


class DatabaseSetupRequest(object):
    def __init__(self):
        pass


class CertificateSetupRequest(object):
    def __init__(self):
        self.generateServerCert = "true"


class CertificateSetupResponse(object):
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


class SecurityDomainSetupRequest(object):
    def __init__(self):
        pass


class DatabaseUserSetupRequest(object):
    def __init__(self):
        pass


class FinalizeConfigRequest(object):
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

    def __init__(self, connection, subsystem=None):

        self.connection = connection

        self.configure_url = '/rest/installer/configure'
        self.setup_database_url = '/rest/installer/setupDatabase'
        self.setup_cert_url = '/rest/installer/setupCert'
        self.setup_admin_url = '/rest/installer/setupAdmin'
        self.backup_keys_url = '/rest/installer/backupKeys'
        self.setup_security_domain_url = '/rest/installer/setupSecurityDomain'
        self.setup_db_user_url = '/rest/installer/setupDatabaseUser'
        self.finalize_config_url = '/rest/installer/finalizeConfiguration'

        if connection.subsystem is None:

            if subsystem is None:
                raise Exception('Missing subsystem for SystemConfigClient')

            self.configure_url = '/' + subsystem + self.configure_url
            self.setup_database_url = '/' + subsystem + self.setup_database_url
            self.setup_cert_url = '/' + subsystem + self.setup_cert_url
            self.setup_admin_url = '/' + subsystem + self.setup_admin_url
            self.backup_keys_url = '/' + subsystem + self.backup_keys_url
            self.setup_security_domain_url = '/' + subsystem + self.setup_security_domain_url
            self.setup_db_user_url = '/' + subsystem + self.setup_db_user_url
            self.finalize_config_url = '/' + subsystem + self.finalize_config_url

    def configure(self, request):
        """
        Contacts the server and invokes the Java configuration REST API to
        configure a Dogtag subsystem.

        :param request: Configuration request containing all the input needed to
            configure the subsystem
        :type request: ConfigurationRequest
        """
        data = json.dumps(request, cls=pki.encoder.CustomTypeEncoder)
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}
        self.connection.post(
            self.configure_url,
            data,
            headers)

    def setupDatabase(self, request):
        """
        Set up database.

        :param request: Database setup request
        :type request: DatabaseSetupRequest
        """
        data = json.dumps(request, cls=pki.encoder.CustomTypeEncoder)
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}
        self.connection.post(
            self.setup_database_url,
            data,
            headers)

    def setupCert(self, request):
        """
        Set up certificate.

        :param request: Certificate setup request
        :type request: CertificateSetupRequest
        :return: SystemCertData
        """
        data = json.dumps(request, cls=pki.encoder.CustomTypeEncoder)
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}

        response = self.connection.post(
            self.setup_cert_url,
            data,
            headers)

        if not response.content:
            return None

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
            self.setup_admin_url,
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
            self.backup_keys_url,
            data,
            headers)

    def setupSecurityDomain(self, request):
        """
        Setup security domain.

        :param request: Security domain setup request
        :type request: SecurityDomainSetupRequest
        """
        data = json.dumps(request, cls=pki.encoder.CustomTypeEncoder)
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}
        self.connection.post(
            self.setup_security_domain_url,
            data,
            headers)

    def setupDatabaseUser(self, request):
        """
        Set up database user.

        :param request: Database user setup request
        :type request: DatabaseUserSetupRequest
        """
        data = json.dumps(request, cls=pki.encoder.CustomTypeEncoder)
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}
        self.connection.post(
            self.setup_db_user_url,
            data,
            headers)

    def finalizeConfiguration(self, request):
        """
        Finalize server configuration.

        :param request: Finalize configuration request
        :type request: FinalizeConfigRequest
        """
        data = json.dumps(request, cls=pki.encoder.CustomTypeEncoder)
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}
        self.connection.post(
            self.finalize_config_url,
            data,
            headers)


class SystemStatusClient(object):
    """
    Client used to check the status of a Dogtag subsystem.
    """

    def __init__(self, connection, subsystem=None):

        self.connection = connection

        if connection.subsystem is not None:
            self.get_status_url = '/admin/%s/getStatus' % connection.subsystem

        elif subsystem is not None:
            self.get_status_url = '/%s/admin/%s/getStatus' % (subsystem, subsystem)

        else:
            raise Exception('Missing subsystem for SystemStatusClient')

    def get_status(self, timeout=None):
        """
        Checks the status of the subsystem by calling the getStatus()
        servlet.  This is used to determine if the server is up and ready to
        receive and process requests.

        :return: str - getStatus response
        """
        response = self.connection.get(
            self.get_status_url,
            timeout=timeout,
        )
        return response.text


pki.encoder.NOTYPES['ConfigurationRequest'] = ConfigurationRequest
pki.encoder.NOTYPES['DatabaseSetupRequest'] = DatabaseSetupRequest
pki.encoder.NOTYPES['CertificateSetupRequest'] = CertificateSetupRequest
pki.encoder.NOTYPES['CertificateSetupResponse'] = CertificateSetupResponse
pki.encoder.NOTYPES['AdminSetupRequest'] = AdminSetupRequest
pki.encoder.NOTYPES['AdminSetupResponse'] = AdminSetupResponse
pki.encoder.NOTYPES['KeyBackupRequest'] = KeyBackupRequest
pki.encoder.NOTYPES['SecurityDomainSetupRequest'] = SecurityDomainSetupRequest
pki.encoder.NOTYPES['DatabaseUserSetupRequest'] = DatabaseUserSetupRequest
pki.encoder.NOTYPES['FinalizeConfigRequest'] = FinalizeConfigRequest
pki.encoder.NOTYPES['SystemCertData'] = SystemCertData
