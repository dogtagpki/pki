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
# Copyright (C) 2016 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
import os
import socket
import struct
import subprocess
import time
from time import strftime as date
from lxml import etree

from . import pkiconfig as config
from . import pkihelper as util


class PKIDeployer:
    """Holds the global dictionaries and the utility objects"""

    def __init__(self):

        # PKI Deployment "Mandatory" Command-Line Variables
        self.subsystem_name = None

        # Global dictionary variables
        self.mdict = {}
        self.slots = {}
        self.main_config = None
        self.user_config = None
        self.manifest_db = []

        self.identity = None
        self.namespace = None
        self.configuration_file = None
        self.instance = None
        self.directory = None
        self.file = None
        self.symlink = None
        self.war = None
        self.password = None
        self.hsm = None
        self.certutil = None
        self.modutil = None
        self.pk12util = None
        self.kra_connector = None
        self.security_domain = None
        self.servercertnick_conf = None
        self.systemd = None
        self.tps_connector = None
        self.config_client = None

        # Set installation time
        ticks = time.time()
        self.install_time = time.asctime(time.localtime(ticks))

        # Generate a timestamp
        self.log_timestamp = date('%Y%m%d%H%M%S', time.localtime(ticks))
        self.certificate_timestamp = date('%Y-%m-%d %H:%M:%S', time.localtime(ticks))

        # Obtain the architecture bit-size
        self.architecture = struct.calcsize("P") * 8

        # Retrieve hostname
        self.hostname = socket.getfqdn()

        # Retrieve DNS domainname
        self.dns_domainname = subprocess.check_output(["dnsdomainname"])
        self.dns_domainname = self.dns_domainname.decode('ascii').rstrip('\n')

        if not len(self.dns_domainname):
            self.dns_domainname = self.hostname

    def init(self):

        # Utility objects
        self.identity = util.Identity(self)
        self.namespace = util.Namespace(self)
        self.configuration_file = util.ConfigurationFile(self)
        self.instance = util.Instance(self)
        self.directory = util.Directory(self)
        self.file = util.File(self)
        self.symlink = util.Symlink(self)
        self.war = util.War(self)
        self.password = util.Password(self)
        self.hsm = util.HSM(self)
        self.certutil = util.Certutil(self)
        self.modutil = util.Modutil(self)
        self.pk12util = util.PK12util(self)
        self.kra_connector = util.KRAConnector(self)
        self.security_domain = util.SecurityDomain(self)
        self.servercertnick_conf = util.ServerCertNickConf(self)
        self.systemd = util.Systemd(self)
        self.tps_connector = util.TPSConnector(self)
        self.config_client = util.ConfigClient(self)

    def flatten_master_dict(self):

        self.mdict.update(__name__="PKI Master Dictionary")

        default_dict = dict(self.main_config.items('DEFAULT'))
        default_dict[0] = None
        self.mdict.update(default_dict)

        web_server_dict = None
        if self.main_config.has_section('Tomcat'):
            web_server_dict = dict(self.main_config.items('Tomcat'))

        if web_server_dict:
            web_server_dict[0] = None
            self.mdict.update(web_server_dict)

        if self.main_config.has_section(self.subsystem_name):
            subsystem_dict = dict(self.main_config.items(self.subsystem_name))
            subsystem_dict[0] = None
            self.mdict.update(subsystem_dict)

    def deploy_webapp(self, name, doc_base, descriptor):
        """
        Deploy a web application into a Tomcat instance.

        This method will copy the specified deployment descriptor into
        <instance>/conf/Catalina/localhost/<name>.xml and point the docBase
        to the specified location. The web application will become available
        under "/<name>" URL path.

        See also: http://tomcat.apache.org/tomcat-7.0-doc/config/context.html

        :param name: Web application name.
        :type name: str
        :param doc_base: Path to web application content.
        :type doc_base: str
        :param descriptor: Path to deployment descriptor (context.xml).
        :type descriptor: str
        """
        new_descriptor = os.path.join(
            self.mdict['pki_instance_configuration_path'],
            "Catalina",
            "localhost",
            name + ".xml")

        parser = etree.XMLParser(remove_blank_text=True)
        document = etree.parse(descriptor, parser)

        context = document.getroot()
        context.set('docBase', doc_base)

        with open(new_descriptor, 'wb') as f:
            # xml as UTF-8 encoded bytes
            document.write(f, pretty_print=True, encoding='utf-8')

        os.chown(new_descriptor, self.mdict['pki_uid'], self.mdict['pki_gid'])
        os.chmod(
            new_descriptor,
            config.PKI_DEPLOYMENT_DEFAULT_FILE_PERMISSIONS)

    @staticmethod
    def create_system_cert_verifier(instance=None, subsystem=None):
        return util.SystemCertificateVerifier(instance, subsystem)
