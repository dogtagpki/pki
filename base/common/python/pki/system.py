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
import inspect
import json
import logging
import xml.etree.ElementTree as ETree
import os

import pki.encoder

SYSTEM_TYPE = "Fedora/RHEL"
if os.path.exists("/etc/debian_version"):
    SYSTEM_TYPE = "debian"

logger = logging.getLogger(__name__)


class SecurityDomainHost(object):
    """
    Class representing a security domain host.
    """

    def __init__(self):
        """ constructor """
        self.id = None
        self.Clone = False
        self.DomainManager = False
        self.Hostname = None
        self.Port = None
        self.SecureAdminPort = None
        self.SecureAgentPort = None
        self.SecureEEClientAuthPort = None
        self.SecurePort = None
        self.SubsystemName = None

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
            # PKI 10.2
            host.id = json_value['id']

        except KeyError:
            # PKI 10.1
            host.id = json_value['@id']

        host.SecureAdminPort = json_value['SecureAdminPort']
        host.SecureAgentPort = json_value['SecureAgentPort']
        host.Clone = json_value['Clone']
        host.DomainManager = json_value['DomainManager']
        host.SecureEEClientAuthPort = json_value['SecureEEClientAuthPort']
        host.Hostname = json_value['Hostname']
        host.SecurePort = json_value['SecurePort']
        host.SubsystemName = json_value['SubsystemName']
        host.Port = json_value.get('Port')

        return host


class SecurityDomainSubsystem(object):
    """
    Class representing a security domain subsystem.
    This is essentially a list of SecurityDomainHost objects of a
    particular subsystem type (ca, kra, tps, tks, ocsp).
    """

    def __init__(self):
        self.id = None
        self.hosts = {}

    def get_host(self, hostname, secure_port):

        logger.info('Searching for %s:%s', hostname, secure_port)

        for host in self.hosts.values():

            logger.info('- %s:%s', host.Hostname, host.SecurePort)

            if host.Hostname != hostname:
                continue

            if host.SecurePort != secure_port:
                continue

            return host

        raise Exception('Unable to find security domain host: %s:%s' %
                        (hostname, secure_port))

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
            # PKI 10.8
            subsystem.id = json_value['id']
            hosts = json_value['hosts']

            for k, v in hosts.items():
                host = SecurityDomainHost.from_json(v)
                subsystem.hosts[k] = host

        except KeyError:

            try:
                # PKI 10.2
                subsystem.id = json_value['id']

            except KeyError:
                # PKI 10.1
                subsystem.id = json_value['@id']

            hosts = json_value['Host']
            if isinstance(hosts, dict):
                hosts = [hosts]

            for h in hosts:
                host = SecurityDomainHost.from_json(h)
                subsystem.hosts[host.id] = host

        return subsystem


class DomainInfo(object):
    """
    Class representing the entire security domain.
    This is essentially a list of SecurityDomainSubsystem components.
    """

    def __init__(self):
        self.id = None
        self.subsystems = {}

    @property
    def systems(self):
        logger.warning(
            '%s:%s: The DomainInfo.systems has been deprecated '
            '(https://github.com/dogtagpki/pki/wiki/PKI-10.8-Python-Changes).',
            inspect.stack()[1].filename, inspect.stack()[1].lineno)
        return self.subsystems

    @classmethod
    def from_json(cls, json_value):
        """
        Create a DomainInfo object from JSON.

        :param json_value: JSON representation of a security domain.
        :type json_value: str
        :returns: DomainInfo
        """

        security_domain = cls()

        try:
            # PKI 10.8
            security_domain.id = json_value['id']
            subsystems = json_value['subsystems']

            for k, v in subsystems.items():
                subsystem = SecurityDomainSubsystem.from_json(v)
                security_domain.subsystems[k] = subsystem

        except KeyError:

            try:
                # PKI 10.2
                security_domain.id = json_value['id']
                subsystems = json_value['Subsystem']

            except KeyError:
                # PKI 10.1
                domain_info = json_value['DomainInfo']
                security_domain.id = domain_info['@id']

                subsystems = domain_info['Subsystem']
                if isinstance(subsystems, dict):
                    subsystems = [subsystems]

            for s in subsystems:
                subsystem = SecurityDomainSubsystem.from_json(s)
                security_domain.subsystems[subsystem.id] = subsystem

        return security_domain


class InstallToken(object):

    def __init__(self):
        self.token = None

    @classmethod
    def from_json(cls, json_value):

        install_token = cls()
        install_token.token = json_value['token']

        return install_token


class SecurityDomainClient(object):
    """
    Client used to get the security domain from a security domain CA.
    The connection details for the security domain CA are specified in
    a PKIConnection object used to construct this client.
    """

    def __init__(self, parent):

        if isinstance(parent, pki.client.PKIConnection):

            logger.warning(
                '%s:%s: The PKIConnection parameter in SecurityDomainClient.__init__() '
                'has been deprecated. Provide SubsystemClient instead.',
                inspect.stack()[1].filename, inspect.stack()[1].lineno)

            self.subsystem_client = None
            self.pki_client = None
            self.connection = parent

        else:
            self.subsystem_client = parent
            self.pki_client = self.subsystem_client.parent
            self.connection = self.pki_client.connection

    def get_security_domain_info(self):
        logger.warning(
            '%s:%s: The SecurityDomainClient.get_security_domain_info() has been deprecated '
            '(https://github.com/dogtagpki/pki/wiki/PKI-10.8-Python-Changes).',
            inspect.stack()[1].filename, inspect.stack()[1].lineno)
        return self.get_domain_info()

    def get_domain_info(self):
        """
        Contact the security domain CA specified in the connection object
        used to construct this client and get the security domain using the
        REST API.

        :returns: pki.system.DomainInfo
        """

        if self.pki_client:
            api_path = self.pki_client.get_api_path()
        else:
            api_path = 'rest'

        path = '/%s/securityDomain/domainInfo' % api_path

        if not self.connection.subsystem:
            path = '/ca' + path

        headers = {
            'Accept': 'application/json'
        }
        response = self.connection.get(path, headers=headers)

        json_response = response.json()
        logger.debug('Response:\n%s', json.dumps(json_response, indent=4))

        info = DomainInfo.from_json(json_response)
        return info

    def get_old_domain_info(self):
        """
        Contact the security domain CA specified in the connection object
        used to construct this client and get the security domain using the
        old servlet-based interface.  This method is useful when contacting
        old servers which do not provide the REST API.

        :returns: pki.system.DomainInfo
        """

        path = '/admin/ca/getDomainXML'

        if not self.connection.subsystem:
            path = '/ca' + path

        response = self.connection.get(path)
        root = ETree.fromstring(response.text)
        domaininfo = ETree.fromstring(root.find("DomainInfo").text)
        info = DomainInfo()
        info.id = domaininfo.find("Name").text
        return info

    def get_install_token(self, hostname, subsystem):
        '''
        :returns: pki.system.InstallToken
        '''

        if self.pki_client:
            api_path = self.pki_client.get_api_path()
        else:
            api_path = 'rest'

        path = '/%s/securityDomain/installToken' % api_path

        if not self.connection.subsystem:
            path = '/ca' + path

        params = {
            'hostname': hostname,
            'subsystem': subsystem
        }
        response = self.connection.get(path, params=params)

        json_response = response.json()
        logger.debug('Response:\n%s', json.dumps(json_response, indent=4))

        return InstallToken.from_json(json_response)


class CertificateSetupRequest(object):
    def __init__(self):
        self.installToken = None
        self.clone = 'false'
        self.systemCert = None


class CertificateSetupResponse(object):
    def __init__(self):
        pass


class AdminSetupRequest(object):
    def __init__(self):
        self.installToken = None


class AdminSetupResponse(object):
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
        self.token = None
        self.keyID = None
        self.keyType = None
        self.keySize = None
        self.keyWrap = False
        self.keyCurveName = None
        self.sslECDH = False


class SystemConfigClient(object):
    """
    Client used to interact with the Java configuration servlet to configure
    a Dogtag subsystem during the execution of pkispawn.

    The connection details for the system being configured are passed in
    the PKIConnection object used when constructing this object.
    """

    def __init__(self, connection, subsystem=None):

        self.connection = connection

        self.create_request_id_url = '/rest/installer/createRequestID'
        self.create_cert_id_url = '/rest/installer/createCertID'

        if connection.subsystem is None:

            if subsystem is None:
                raise Exception('Missing subsystem for SystemConfigClient')

            self.create_request_id_url = '/' + subsystem + self.create_request_id_url
            self.create_cert_id_url = '/' + subsystem + self.create_cert_id_url

    def createRequestID(self, request):
        """
        Create certificate request ID.

        :param request: Certificate setup request
        :type request: CertificateSetupRequest
        :return: SystemCertData
        """
        data = json.dumps(request, cls=pki.encoder.CustomTypeEncoder)
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}

        response = self.connection.post(
            self.create_request_id_url,
            data,
            headers)

        json_response = response.json()
        logger.debug('Response:\n%s', json.dumps(json_response, indent=4))

        return json_response

    def createCertID(self, request):
        """
        Create certificate ID.

        :param request: Certificate setup request
        :type request: CertificateSetupRequest
        :return: SystemCertData
        """
        data = json.dumps(request, cls=pki.encoder.CustomTypeEncoder)
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}

        response = self.connection.post(
            self.create_cert_id_url,
            data,
            headers)

        json_response = response.json()
        logger.debug('Response:\n%s', json.dumps(json_response, indent=4))

        return json_response


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


pki.encoder.NOTYPES['DomainInfo'] = DomainInfo
pki.encoder.NOTYPES['SecurityDomainSubsystem'] = SecurityDomainSubsystem
pki.encoder.NOTYPES['SecurityDomainHost'] = SecurityDomainHost
pki.encoder.NOTYPES['InstallToken'] = InstallToken
pki.encoder.NOTYPES['CertificateSetupRequest'] = CertificateSetupRequest
pki.encoder.NOTYPES['CertificateSetupResponse'] = CertificateSetupResponse
pki.encoder.NOTYPES['AdminSetupRequest'] = AdminSetupRequest
pki.encoder.NOTYPES['AdminSetupResponse'] = AdminSetupResponse
pki.encoder.NOTYPES['SystemCertData'] = SystemCertData
