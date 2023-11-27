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
import base64
import json
import ldap
import logging
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import time
from time import strftime as date
import urllib.parse

import pki.account
import pki.client
import pki.system

from . import pkiconfig as config
from . import pkihelper as util
from . import pkimanifest as manifest
from . import pkimessages as log

logger = logging.getLogger(__name__)


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
        self.pk12util = None
        self.kra_connector = None
        self.security_domain = None
        self.systemd = None
        self.tps_connector = None
        self.config_client = None
        self.nss_db_type = None

        self.with_maven_deps = False

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

        self.ds_url = None
        self.ds_connection = None
        self.sd_connection = None

        self.domain_info = None
        self.sd_host = None
        self.install_token = None

        self.startup_timeout = None
        self.request_timeout = None

    def set_property(self, key, value, section=None):

        if not section:
            section = self.subsystem_name

        if section != "DEFAULT" and not self.main_config.has_section(section):
            self.main_config.add_section(section)

        self.main_config.set(section, key, value)
        self.flatten_master_dict()

        if section != "DEFAULT" and not self.user_config.has_section(section):
            self.user_config.add_section(section)

        self.user_config.set(section, key, value)

    def init(self):

        # Configure startup timeout
        try:
            self.startup_timeout = int(os.environ['PKISPAWN_STARTUP_TIMEOUT_SECONDS'])
        except (KeyError, ValueError):
            self.startup_timeout = 120

        if self.startup_timeout <= 0:
            self.startup_timeout = 60

        # Configure status request timeout. This is used for each
        # status request in wait_for_startup().
        value = self.mdict['pki_status_request_timeout']
        if len(value) > 0:
            self.request_timeout = int(value)
            if self.request_timeout <= 0:
                raise ValueError("Request timeout must be greater than zero")

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
        self.pk12util = util.PK12util(self)
        self.kra_connector = util.KRAConnector(self)
        self.security_domain = util.SecurityDomain(self)
        self.systemd = util.Systemd(self)
        self.tps_connector = util.TPSConnector(self)
        self.config_client = util.ConfigClient(self)

        self.ds_init()

    def ds_init(self):
        ds_hostname = self.mdict['pki_ds_hostname']

        if config.str2bool(self.mdict['pki_ds_secure_connection']):
            ds_protocol = 'ldaps'
            ds_port = self.mdict['pki_ds_ldaps_port']
            # ldap.set_option(ldap.OPT_DEBUG_LEVEL, 255)
            ldap.set_option(ldap.OPT_X_TLS_DEMAND, True)
            ldap.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND)
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE,
                            self.mdict['pki_ds_secure_connection_ca_pem_file'])
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
        else:
            ds_protocol = 'ldap'
            ds_port = self.mdict['pki_ds_ldap_port']

        self.ds_url = ds_protocol + '://' + ds_hostname + ':' + ds_port

    def validate(self):
        # Validate environmental settings for the deployer;
        # to be called before self.init().

        blacklisted_hostnames = ['localhost', 'localhost.localdomain',
                                 'localhost4', 'localhost4.localdomain4',
                                 'localhost6', 'localhost6.localdomain6']

        if self.hostname in blacklisted_hostnames:
            raise Exception("This host has a localhost-like domain as its " +
                            "FQDN. Please change this to a non-localhost " +
                            "FQDN. Changes must be made in /etc/hosts; to " +
                            "verify that they have applied run " +
                            "`python -c 'import socket; print(socket.getfqdn())'`.")

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

    def get_cert_id(self, subsystem, tag):

        if tag == 'signing':
            return '%s_%s' % (subsystem.name, tag)
        else:
            return tag

    def import_system_cert_request(self, subsystem, tag):

        cert_id = self.get_cert_id(subsystem, tag)

        csr_path = self.mdict.get('pki_%s_csr_path' % cert_id)
        if not csr_path or not os.path.exists(csr_path):
            return

        logger.info('Importing %s CSR from %s', tag, csr_path)

        with open(csr_path) as f:
            csr_data = f.read()

        b64_csr = pki.nssdb.convert_csr(csr_data, 'pem', 'base64')
        subsystem.config['%s.%s.certreq' % (subsystem.name, tag)] = b64_csr

    def import_system_cert_requests(self, subsystem):

        if subsystem.name == 'ca':
            self.import_system_cert_request(subsystem, 'signing')
            self.import_system_cert_request(subsystem, 'ocsp_signing')

        if subsystem.name == 'kra':
            self.import_system_cert_request(subsystem, 'storage')
            self.import_system_cert_request(subsystem, 'transport')

        if subsystem.name == 'ocsp':
            self.import_system_cert_request(subsystem, 'signing')

        self.import_system_cert_request(subsystem, 'audit_signing')
        self.import_system_cert_request(subsystem, 'subsystem')
        self.import_system_cert_request(subsystem, 'sslserver')

    def import_ca_signing_cert(self, nssdb):

        param = 'pki_ca_signing_cert_path'
        cert_file = self.mdict.get(param)

        if not cert_file:
            return

        if not os.path.exists(cert_file):
            raise Exception('Invalid certificate path: %s=%s' % (param, cert_file))

        nickname = self.mdict['pki_ca_signing_nickname']

        logger.info('Importing ca_signing certificate from %s', cert_file)

        nssdb.import_cert_chain(
            nickname=nickname,
            cert_chain_file=cert_file,
            trust_attributes='CT,C,C')

    def import_system_cert(
            self,
            nssdb,
            subsystem,
            tag,
            trust_attributes=None):

        logger.debug('import_system_cert')

        cert_id = self.get_cert_id(subsystem, tag)
        param = 'pki_%s_cert_path' % cert_id
        cert_file = self.mdict.get(param)

        if not cert_file or not os.path.exists(cert_file):
            return

        logger.info('Importing %s certificate from %s', cert_id, cert_file)

        cert = subsystem.get_subsystem_cert(tag)
        nickname = cert['nickname']
        token = pki.nssdb.normalize_token(cert['token'])

        if not token:
            token = self.mdict['pki_token_name']

        nssdb.import_cert_chain(
            nickname=nickname,
            cert_chain_file=cert_file,
            token=token,
            trust_attributes=trust_attributes)

    def import_admin_cert(self):

        cert_file = self.mdict.get('pki_admin_cert_path')
        if not cert_file or not os.path.exists(cert_file):
            return

        nickname = self.mdict['pki_admin_nickname']

        client_nssdb = pki.nssdb.NSSDatabase(
            directory=self.mdict['pki_client_database_dir'],
            password=self.mdict['pki_client_database_password'])

        try:
            logger.info('Importing admin certificate from %s', cert_file)

            client_nssdb.import_cert_chain(
                nickname=nickname,
                cert_chain_file=cert_file,
                trust_attributes=',,')

        finally:
            client_nssdb.close()

    def import_certs_and_keys(self, nssdb):

        pkcs12_file = self.mdict.get('pki_external_pkcs12_path')
        if not pkcs12_file or not os.path.exists(pkcs12_file):
            return

        logger.info('Importing certificates and keys from %s', pkcs12_file)

        pkcs12_password = self.mdict['pki_external_pkcs12_password']
        nssdb.import_pkcs12(pkcs12_file, pkcs12_password)

    def import_cert_chain(self, nssdb):

        logger.debug('PKIDeployer.import_cert_chain()')

        chain_file = self.mdict.get('pki_cert_chain_path')

        if not chain_file or not os.path.exists(chain_file):
            return

        nickname = self.mdict['pki_cert_chain_nickname']

        logger.info('Importing certificate chain from %s', chain_file)

        nssdb.import_cert_chain(
            nickname=nickname,
            cert_chain_file=chain_file,
            trust_attributes='CT,C,C')

    def import_system_certs(self, nssdb, subsystem):

        logger.debug("import_system_certs")

        if subsystem.name == 'ca':
            self.import_system_cert(nssdb, subsystem, 'signing', 'CT,C,C')
            self.import_system_cert(nssdb, subsystem, 'ocsp_signing')

        if subsystem.name == 'kra':
            self.import_ca_signing_cert(nssdb)

            self.import_system_cert(nssdb, subsystem, 'storage')
            self.import_system_cert(nssdb, subsystem, 'transport')
            self.import_admin_cert()

        if subsystem.name == 'ocsp':
            self.import_ca_signing_cert(nssdb)

            self.import_system_cert(nssdb, subsystem, 'signing')
            self.import_admin_cert()

        sslserver = subsystem.get_subsystem_cert('sslserver')
        nickname = sslserver['nickname']
        token = sslserver['token']
        subsystem.instance.set_sslserver_cert_nickname(nickname, token)

        self.import_system_cert(nssdb, subsystem, 'sslserver')
        self.import_system_cert(nssdb, subsystem, 'subsystem')
        self.import_system_cert(nssdb, subsystem, 'audit_signing', ',,P')

        # If provided, import certs and keys from PKCS #12 file
        # into NSS database.

        self.import_certs_and_keys(nssdb)

    def configure_system_cert(self, subsystem, tag):

        cert_id = self.get_cert_id(subsystem, tag)
        nickname = self.mdict['pki_%s_nickname' % cert_id]

        logger.info('Configuring %s certificate with nickname %s', cert_id, nickname)

        subsystem.config['%s.%s.nickname' % (subsystem.name, tag)] = nickname
        subsystem.config['%s.%s.tokenname' % (subsystem.name, tag)] = \
            self.mdict['pki_%s_token' % cert_id]
        subsystem.config['%s.%s.defaultSigningAlgorithm' % (subsystem.name, tag)] = \
            self.mdict['pki_%s_key_algorithm' % cert_id]

    def configure_system_certs(self, subsystem):

        logger.debug('PKIDeployer.configure_system_certs()')

        if subsystem.name == 'ca':
            self.configure_system_cert(subsystem, 'signing')

            nickname = self.mdict['pki_ca_signing_nickname']
            subsystem.config['ca.signing.cacertnickname'] = nickname

            self.configure_system_cert(subsystem, 'ocsp_signing')

        if subsystem.name == 'kra':
            self.configure_system_cert(subsystem, 'storage')
            self.configure_system_cert(subsystem, 'transport')

        if subsystem.name == 'ocsp':
            self.configure_system_cert(subsystem, 'signing')

        self.configure_system_cert(subsystem, 'sslserver')
        self.configure_system_cert(subsystem, 'subsystem')
        self.configure_system_cert(subsystem, 'audit_signing')

    def update_system_cert(self, nssdb, subsystem, tag):

        logger.debug('update_system_cert')

        cert_id = self.get_cert_id(subsystem, tag)
        nickname = self.mdict['pki_%s_nickname' % cert_id]

        cert_data = nssdb.get_cert(
            nickname=nickname,
            token=self.mdict['pki_%s_token' % cert_id],
            output_format='base64',
            output_text=True,
        )

        subsystem.config['%s.%s.cert' % (subsystem.name, tag)] = cert_data

    def update_admin_cert(self, subsystem):

        logger.info('Updating admin certificate')

        client_nssdb = pki.nssdb.NSSDatabase(
            directory=self.mdict['pki_client_database_dir'],
            password=self.mdict['pki_client_database_password'])

        try:
            nickname = self.mdict['pki_admin_nickname']
            cert_data = client_nssdb.get_cert(
                nickname=nickname,
                output_format='base64',
                output_text=True,
            )

            subsystem.config['%s.admin.cert' % subsystem.name] = cert_data

        finally:
            client_nssdb.close()

    def update_system_certs(self, nssdb, subsystem):

        logger.debug('update_system_certs')

        if subsystem.name == 'ca':
            self.update_system_cert(nssdb, subsystem, 'signing')
            self.update_system_cert(nssdb, subsystem, 'ocsp_signing')

        if subsystem.name == 'kra':
            self.update_system_cert(nssdb, subsystem, 'storage')
            self.update_system_cert(nssdb, subsystem, 'transport')
            self.update_admin_cert(subsystem)

        if subsystem.name == 'ocsp':
            self.update_system_cert(nssdb, subsystem, 'signing')
            self.update_admin_cert(subsystem)

        self.update_system_cert(nssdb, subsystem, 'sslserver')
        self.update_system_cert(nssdb, subsystem, 'subsystem')
        self.update_system_cert(nssdb, subsystem, 'audit_signing')

    def validate_system_cert(self, nssdb, subsystem, tag):

        logger.debug('validate_system_cert')

        cert_id = self.get_cert_id(subsystem, tag)
        nickname = self.mdict['pki_%s_nickname' % cert_id]

        cert_data = nssdb.get_cert(
            nickname=nickname,
            token=self.mdict['pki_%s_token' % cert_id],
            output_text=True
        )

        if not cert_data:
            return

        logger.info('Validating %s certificate', tag)

        subsystem.validate_system_cert(tag)

    def validate_system_certs(self, nssdb, subsystem):

        logger.debug('validate_system_certs')

        if subsystem.name == 'ca':
            self.validate_system_cert(nssdb, subsystem, 'signing')
            self.validate_system_cert(nssdb, subsystem, 'ocsp_signing')

        if subsystem.name == 'kra':
            self.validate_system_cert(nssdb, subsystem, 'storage')
            self.validate_system_cert(nssdb, subsystem, 'transport')

        if subsystem.name == 'ocsp':
            self.validate_system_cert(nssdb, subsystem, 'signing')

        self.validate_system_cert(nssdb, subsystem, 'sslserver')
        self.validate_system_cert(nssdb, subsystem, 'subsystem')
        self.validate_system_cert(nssdb, subsystem, 'audit_signing')

    def record(self, name, record_type, uid, gid, perms, acls=None):
        record = manifest.Record()
        record.name = name
        record.type = record_type
        record.user = self.mdict['pki_user']
        record.group = self.mdict['pki_group']
        record.uid = uid
        record.gid = gid
        record.permissions = perms
        record.acls = acls
        self.manifest_db.append(record)

    def ds_connect(self):
        if not self.ds_url:
            logger.debug('ds_connect() called without corresponding call to ds_init()')
            self.ds_init()

        logger.info('Connecting to LDAP server at %s', self.ds_url)

        self.ds_connection = ldap.initialize(self.ds_url)

    def ds_bind(self):
        self.ds_connection.simple_bind_s(
            self.mdict['pki_ds_bind_dn'],
            self.mdict['pki_ds_password'])

    def ds_search(self, key=None):
        if key is None:
            key = ''
        return self.ds_connection.search_s(key, ldap.SCOPE_BASE)

    def ds_close(self):
        self.ds_connection.unbind_s()

    def sd_connect(self):

        if self.sd_connection:
            return self.sd_connection

        sd_url = self.mdict['pki_security_domain_uri']

        url = urllib.parse.urlparse(sd_url)
        sd_hostname = url.hostname
        sd_port = str(url.port)

        logger.info('Connecting to security domain at %s', sd_url)

        ca_cert = os.path.join(self.mdict['pki_server_database_path'],
                               "ca.crt")

        if not os.path.exists(ca_cert):

            # if ca.crt doesn't exist, use provided cert chain
            cert_chain_path = self.mdict['pki_cert_chain_path']
            logger.info('Certificate chain: %s', cert_chain_path)

            if cert_chain_path:

                if not os.path.exists(cert_chain_path):
                    # if cert chain is specified but doesn't exist, throw exception
                    raise Exception('Certificate chain not found: %s' % cert_chain_path)

                ca_cert = cert_chain_path

        self.sd_connection = pki.client.PKIConnection(
            protocol='https',
            hostname=sd_hostname,
            port=sd_port,
            trust_env=False,
            cert_paths=ca_cert)

        return self.sd_connection

    def get_domain_info(self):

        if self.domain_info:
            return self.domain_info

        logger.info('Getting security domain info')

        self.sd_connect()

        sd_client = pki.system.SecurityDomainClient(self.sd_connection)
        self.domain_info = sd_client.get_domain_info()

        return self.domain_info

    def sd_login(self):

        sd_user = self.mdict['pki_security_domain_user']
        sd_password = self.mdict['pki_security_domain_password']

        self.sd_connection.authenticate(sd_user, sd_password)

        account = pki.account.AccountClient(self.sd_connection, subsystem='ca')
        account.login()

    def sd_logout(self):
        account = pki.account.AccountClient(self.sd_connection, subsystem='ca')
        account.logout()

    def get_install_token(self):

        if self.install_token:
            return self.install_token

        hostname = self.mdict['pki_hostname']
        subsystem = self.mdict['pki_subsystem']

        logger.info('Getting install token')

        sd_client = pki.system.SecurityDomainClient(self.sd_connection)
        self.install_token = sd_client.get_install_token(hostname, subsystem)

        # Sleep for a bit to allow the install token to replicate to other clones.
        # In the future this can be replaced with signed tokens.
        # https://github.com/dogtagpki/pki/issues/2951
        #
        # The default sleep time is 5s.

        sd_delay = self.mdict.get('pki_security_domain_post_login_sleep_seconds', '5')
        time.sleep(int(sd_delay))

        return self.install_token

    def join_security_domain(self):

        self.get_domain_info()

        sd_url = self.mdict['pki_security_domain_uri']

        url = urllib.parse.urlparse(sd_url)
        sd_hostname = url.hostname
        sd_port = str(url.port)

        sd_subsystem = self.domain_info.subsystems['CA']
        self.sd_host = sd_subsystem.get_host(sd_hostname, sd_port)

        self.get_install_token()

    def setup_cert(self, subsystem, client, tag, system_cert):

        logger.debug('PKIDeployer.setup_cert()')

        # Process existing CA installation like external CA
        external = config.str2bool(self.mdict['pki_external']) or \
            config.str2bool(self.mdict['pki_existing'])
        standalone = config.str2bool(self.mdict['pki_standalone'])

        request = pki.system.CertificateSetupRequest()
        request.tag = tag
        request.pin = self.mdict['pki_one_time_pin']
        request.installToken = self.install_token

        request.clone = config.str2bool(self.mdict['pki_clone'])
        request.masterURL = self.mdict['pki_clone_uri']

        self.config_client.set_system_cert_info(request, tag)

        if not request.systemCert.token:
            request.systemCert.token = subsystem.config['preop.module.token']

        request.systemCert.profile = subsystem.config['preop.cert.%s.profile' % tag]
        request.systemCert.type = subsystem.config['preop.cert.%s.type' % tag]

        inject_san = subsystem.config.get('service.injectSAN')
        if tag == 'sslserver' and inject_san == 'true':
            logger.info('SAN extension:')
            dns_names = subsystem.config['service.sslserver.san'].split(',')
            for dns_name in dns_names:
                logger.info('- %s', dns_name)
            request.systemCert.dnsNames = dns_names

        nssdb = subsystem.instance.open_nssdb()
        cert_data = None

        try:
            cert_data = nssdb.get_cert(
                nickname=request.systemCert.nickname,
                token=request.systemCert.token)
        finally:
            nssdb.close()

        logger.debug('returned from nssdb.get_cert')

        # For external/existing CA case, some/all system certs may be provided.
        # The SSL server cert will always be generated for the current host.

        # For external/standalone KRA/OCSP/TKS/TPS case, all system certs will be provided.
        # No system certs will be generated including the SSL server cert.

        if subsystem.type == 'CA' and external and tag != 'sslserver' and cert_data or \
                subsystem.type in ['KRA', 'OCSP', 'TKS', 'TPS'] and (external or standalone):

            logger.info('Loading %s certificate', tag)
            logger.debug('- cert: %s', system_cert['data'])
            logger.debug('- request: %s', system_cert['request'])

            client.loadCert(request)
            return

        logger.info('Setting up %s certificate', tag)
        cert = client.setupCert(request)

        logger.info('Storing %s certificate', tag)
        logger.debug('- cert: %s', cert['cert'])
        logger.debug('- request: %s', cert['request'])

        system_cert['data'] = cert['cert']
        system_cert['request'] = cert['request']
        system_cert['token'] = cert['token']

        subsystem.update_system_cert(system_cert)

    def setup_system_certs(self, subsystem, client):

        logger.debug('PKIDeployer.setup_system_certs()')
        system_certs = {}

        for system_cert in subsystem.find_system_certs():
            cert_id = system_cert['id']
            system_certs[cert_id] = system_cert

        clone = self.configuration_file.clone
        tomcat_instance_subsystems = len(self.instance.tomcat_instance_subsystems())

        for tag in subsystem.config['preop.cert.list'].split(','):

            if tag != 'sslserver' and clone:
                logger.info('%s certificate is already set up', tag)
                continue

            if tag == 'sslserver' and tomcat_instance_subsystems > 1:
                logger.info('sslserver certificate is already set up')
                continue

            if tag == 'subsystem' and tomcat_instance_subsystems > 1:
                logger.info('subsystem certificate is already set up')
                continue

            self.setup_cert(subsystem, client, tag, system_certs[tag])

        subsystem.save()

        return system_certs

    def load_admin_cert(self, subsystem):

        logger.debug('PKIDeployer.load_admin_cert()')

        standalone = config.str2bool(self.mdict['pki_standalone'])
        external_step_two = config.str2bool(self.mdict['pki_external_step_two'])

        if standalone or external_step_two and subsystem.type != 'CA':

            # Stand-alone/External PKI (Step 2)
            #
            # Copy the externally-issued admin certificate into
            # 'ca_admin.cert' under the specified 'pki_client_dir'
            # stripping the certificate HEADER/FOOTER prior to saving it.
            logger.debug('load_admin_cert: external_step_two and not CA')

            logger.info('Loading admin cert from %s', self.mdict['pki_admin_cert_path'])

            with open(self.mdict['pki_admin_cert_path'], 'r') as f:
                pem_cert = f.read()

            b64cert = pki.nssdb.convert_cert(pem_cert, 'pem', 'base64')

            logger.info('Storing admin cert into %s', self.mdict['pki_admin_cert_file'])

            with open(self.mdict['pki_admin_cert_file'], 'w') as f:
                f.write(b64cert)

        else:
            # pki_import_admin_cert is true for sharing admin cert
            logger.info(
                'Loading admin cert from client database: %s',
                self.mdict['pki_admin_nickname'])

            client_nssdb = pki.nssdb.NSSDatabase(
                directory=self.mdict['pki_client_database_dir'],
                password=self.mdict['pki_client_database_password'])

            try:
                b64cert = client_nssdb.get_cert(
                    nickname=self.mdict['pki_admin_nickname'],
                    output_format='base64',
                    output_text=True,  # JSON encoder needs text
                )

            finally:
                client_nssdb.close()

            if b64cert:
                return b64cert

            # admin cert was in 'pki_admin_cert_file' but not yet in client
            # nssdb
            logger.info('Loading admin cert from %s', self.mdict['pki_admin_cert_file'])

            with open(self.mdict['pki_admin_cert_file'], 'r') as f:
                pem_cert = f.read()

            b64cert = pki.nssdb.convert_cert(pem_cert, 'pem', 'base64')

        return b64cert

    def request_admin_cert(self, subsystem, csr):

        ca_type = subsystem.config['preop.ca.type']

        if ca_type == 'sdca':
            ca_hostname = subsystem.config['preop.ca.hostname']
            ca_port = subsystem.config['preop.ca.httpsport']
        else:
            ca_hostname = subsystem.config['securitydomain.host']
            ca_port = subsystem.config['securitydomain.httpseeport']

        ca_url = 'https://%s:%s' % (ca_hostname, ca_port)
        logger.info('Requesting admin cert from %s', ca_url)

        request_type = self.mdict['pki_admin_cert_request_type']
        key_type = self.mdict['pki_admin_key_type']

        if key_type.lower() == 'ecc':
            profile = 'caECAdminCert'
        else:
            profile = self.mdict['pki_admin_profile_id']

        subject = self.mdict['pki_admin_subject_dn']

        tmpdir = tempfile.mkdtemp()
        try:
            pem_csr = pki.nssdb.convert_csr(csr, 'base64', 'pem')
            csr_file = os.path.join(tmpdir, 'admin.csr')
            with open(csr_file, 'w') as f:
                f.write(pem_csr)

            install_token = os.path.join(tmpdir, 'install-token')
            with open(install_token, 'w') as f:
                f.write(self.install_token.token)

            cmd = [
                'pki',
                '-d', subsystem.instance.nssdb_dir,
                '-f', subsystem.instance.password_conf,
                '-U', ca_url,
                '--ignore-banner',
                'ca-cert-request-submit',
                '--request-type', request_type,
                '--csr-file', csr_file,
                '--profile', profile,
                '--subject', subject,
                '--install-token', install_token,
                '--output-format', 'PEM'
            ]

            if logger.isEnabledFor(logging.DEBUG):
                cmd.append('--debug')

            elif logger.isEnabledFor(logging.INFO):
                cmd.append('--verbose')

            logger.debug('Command: %s', ' '.join(cmd))
            result = subprocess.run(cmd, stdout=subprocess.PIPE, check=True)

            return pki.nssdb.convert_cert(result.stdout.decode(), 'pem', 'base64')

        finally:
            shutil.rmtree(tmpdir)

    def create_admin_csr(self):

        if self.mdict['pki_admin_cert_request_type'] != 'pkcs10':
            raise Exception(log.PKI_CONFIG_PKCS10_SUPPORT_ONLY)

        noise_file = os.path.join(self.mdict['pki_client_database_dir'], 'noise')
        output_file = os.path.join(self.mdict['pki_client_database_dir'], 'admin_pkcs10.bin')

        # note: in the function below, certutil is used to generate
        # the request for the admin cert.  The keys are generated
        # by NSS, which does not actually use the data in the noise
        # file, so it does not matter what is in this file.  Certutil
        # still requires it though, otherwise it waits for keyboard
        # input.
        with open(noise_file, 'w') as f:
            f.write('not_so_random_data')

        self.certutil.generate_certificate_request(
            self.mdict['pki_admin_subject_dn'],
            self.mdict['pki_admin_key_type'],
            self.mdict['pki_admin_key_size'],
            self.mdict['pki_client_password_conf'],
            noise_file,
            output_file,
            self.mdict['pki_client_database_dir'],
            None,
            None,
            True)

        self.file.delete(noise_file)

        # convert output to ASCII
        command = ['BtoA', output_file, output_file + '.asc']
        logger.debug('Command: %s', ' '.join(command))

        subprocess.check_call(command)

        standalone = config.str2bool(self.mdict['pki_standalone'])
        external_step_one = not config.str2bool(self.mdict['pki_external_step_two'])

        if standalone and external_step_one:
            # For convenience and consistency, save a copy of
            # the Stand-alone PKI 'Admin Certificate' CSR to the
            # specified "pki_admin_csr_path" location
            # (Step 1)
            self.config_client.save_admin_csr()

            # Save the client database for stand-alone PKI (Step 1)
            self.mdict['pki_client_database_purge'] = 'False'

        with open(output_file + '.asc', 'r') as f:
            b64csr = f.read().replace('\n', '')

        return b64csr

    def create_admin_cert(self, client, csr):

        request = pki.system.AdminSetupRequest()
        request.pin = self.mdict['pki_one_time_pin']
        request.installToken = self.install_token
        request.adminKeyType = self.mdict['pki_admin_key_type']
        request.adminProfileID = self.mdict['pki_admin_profile_id']
        request.adminSubjectDN = self.mdict['pki_admin_subject_dn']
        request.adminCertRequestType = self.mdict['pki_admin_cert_request_type']
        request.adminCertRequest = csr

        response = client.setupAdmin(request)
        return response['adminCert']['cert']

    def get_admin_cert(self, subsystem, client):

        logger.debug('PKIDeployer.get_admin_cert()')
        external_step_two = config.str2bool(self.mdict['pki_external_step_two'])
        if config.str2bool(self.mdict['pki_import_admin_cert']):
            b64cert = self.load_admin_cert(subsystem)
        else:
            if external_step_two and subsystem.type != 'CA':
                logger.debug('get_admin_cert: pki_external_step_two True')
                b64cert = self.load_admin_cert(subsystem)
                self.config_client.process_admin_p12()
                logger.debug('Admin cert: %s', b64cert)
                return base64.b64decode(b64cert)
            else:
                b64csr = self.create_admin_csr()
                if subsystem.type == 'CA':
                    b64cert = self.create_admin_cert(client, b64csr)
                else:
                    b64cert = self.request_admin_cert(subsystem, b64csr)

        logger.debug('Admin cert: %s', b64cert)

        if config.str2bool(self.mdict['pki_external']) \
                or config.str2bool(self.mdict['pki_standalone']) \
                or not config.str2bool(self.mdict['pki_import_admin_cert']):

            self.config_client.process_admin_cert(b64cert)
            self.config_client.process_admin_p12()

        return base64.b64decode(b64cert)

    def setup_admin_user(self, subsystem, cert_data, cert_format='DER'):

        uid = self.mdict['pki_admin_uid']
        full_name = self.mdict['pki_admin_name']
        email = self.mdict['pki_admin_email']
        password = self.mdict['pki_admin_password']

        tps_profiles = None
        if subsystem.type == 'TPS':
            tps_profiles = ['All Profiles']

        # Run the command as current user such that
        # it can read the temporary password file.
        subsystem.add_user(
            uid,
            full_name=full_name,
            email=email,
            password=password,
            user_type='adminType',
            state='1',
            tps_profiles=tps_profiles,
            as_current_user=True)

        admin_groups = subsystem.config['preop.admin.group']
        groups = [x.strip() for x in admin_groups.split(',')]

        if subsystem.config['securitydomain.select'] == 'new':

            if subsystem.type == 'CA':
                groups.extend([
                    'Security Domain Administrators',
                    'Enterprise CA Administrators',
                    'Enterprise KRA Administrators',
                    'Enterprise RA Administrators',
                    'Enterprise TKS Administrators',
                    'Enterprise OCSP Administrators',
                    'Enterprise TPS Administrators'
                ])

            elif subsystem.type == 'KRA':
                groups.extend([
                    'Security Domain Administrators',
                    'Enterprise KRA Administrators'
                ])

            elif subsystem.type == 'OCSP':
                groups.extend([
                    'Security Domain Administrators',
                    'Enterprise OCSP Administrators'
                ])

        for group in groups:
            logger.info('Adding %s into %s', uid, group)
            subsystem.add_group_member(group, uid)

        logger.info('Adding certificate for %s', uid)
        subsystem.add_user_cert(uid, cert_data=cert_data, cert_format=cert_format)

    def setup_subsystem_user(self, instance, subsystem, cert):

        server_config = instance.get_server_config()
        secure_port = server_config.get_secure_port()

        uid = 'CA-%s-%s' % (self.mdict['pki_hostname'], secure_port)
        logger.info('Adding %s', uid)

        try:
            subsystem.add_user(
                uid,
                full_name=uid,
                user_type='agentType',
                state='1')
        except Exception:    # pylint: disable=W0703
            logger.warning('Unable to add %s', uid)
            # TODO: ignore error only if user already exists

        cert_data = pki.nssdb.convert_cert(
            cert['data'],
            'base64',
            'pem')

        logger.info('Adding certificate for %s', uid)

        try:
            subsystem.add_user_cert(
                uid,
                cert_data=cert_data.encode(),
                cert_format='PEM')
        except Exception:    # pylint: disable=W0703
            logger.warning('Unable to add certificate for %s', uid)
            # TODO: ignore error only if user cert already exists

        logger.info('Adding %s into Subsystem Group', uid)

        try:
            subsystem.add_group_member('Subsystem Group', uid)
        except Exception:    # pylint: disable=W0703
            logger.warning('Unable to add %s into Subsystem Group', uid)
            # TODO: ignore error only if user already exists in the group

    def backup_keys(self, instance, subsystem):

        tmpdir = tempfile.mkdtemp()
        try:
            password_file = os.path.join(tmpdir, 'password.txt')
            with open(password_file, 'w') as f:
                f.write(self.mdict['pki_backup_password'])

            cmd = [
                'pki-server',
                'subsystem-cert-export',
                subsystem.name,
                '-i', instance.name,
                '--pkcs12-file', self.mdict['pki_backup_file'],
                '--pkcs12-password-file', password_file
            ]

            logger.debug('Command: %s', ' '.join(cmd))
            subprocess.run(cmd, check=True)

        finally:
            shutil.rmtree(tmpdir)

    def setup_database_user(self, instance, subsystem):

        logger.info('Adding pkidbuser')
        subsystem.add_user(
            'pkidbuser',
            full_name='pkidbuser',
            user_type='agentType',
            state='1')

        subsystem_cert = subsystem.get_subsystem_cert('subsystem')
        subject = subsystem_cert['subject']

        nssdb = instance.open_nssdb()
        try:
            cert_data = nssdb.get_cert(
                nickname=subsystem_cert['nickname'],
                token=subsystem_cert['token'])
        finally:
            nssdb.close()

        logger.info('Adding subsystem cert into pkidbuser')
        subsystem.add_user_cert('pkidbuser', cert_data=cert_data, cert_format='PEM')

        logger.info('Linking pkidbuser to subsystem cert: %s', subject)
        subsystem.modify_user('pkidbuser', add_see_also=subject)

        logger.info('Finding other users linked to subsystem cert')
        users = subsystem.find_users(see_also=subject)

        for user in users['entries']:
            uid = user['id']

            if uid == 'pkidbuser':
                continue

            logger.info('Unlinking %s from subsystem cert ', uid)
            subsystem.modify_user(uid, del_see_also=subject)

        # workaround for https://github.com/dogtagpki/pki/issues/2154

        if subsystem.type == 'CA':
            groups = ['Subsystem Group', 'Certificate Manager Agents']

        elif subsystem.type == 'KRA':
            groups = ['Data Recovery Manager Agents', 'Trusted Managers']

        elif subsystem.type == 'OCSP':
            groups = ['Trusted Managers']

        elif subsystem.type == 'TKS':
            groups = ['Token Key Service Manager Agents']

        else:
            groups = []

        for group in groups:
            logger.info('Adding pkidbuser into %s', group)
            subsystem.add_group_member(group, 'pkidbuser')

    def add_subsystem_user(
            self,
            instance,
            subsystem_type,
            subsystem_url,
            uid,
            full_name,
            cert=None,
            session=None,
            install_token=None):

        sd_url = self.mdict['pki_security_domain_uri']

        tmpdir = tempfile.mkdtemp()
        try:
            if not install_token:
                install_token = os.path.join(tmpdir, 'install-token')
                with open(install_token, 'w') as f:
                    f.write(session)

            cmd = [
                'pki',
                '-d', instance.nssdb_dir,
                '-f', instance.password_conf,
                '-U', subsystem_url,
                '--ignore-banner',
                '%s-user-add' % subsystem_type,
                uid,
                '--security-domain', sd_url,
                '--install-token', install_token,
                '--fullName', full_name
            ]

            if cert:
                cert_file = os.path.join(tmpdir, 'cert.pem')
                with open(cert_file, 'w') as f:
                    f.write(cert)
                cmd.extend(['--cert-file', cert_file])

            if logger.isEnabledFor(logging.DEBUG):
                cmd.append('--debug')

            elif logger.isEnabledFor(logging.INFO):
                cmd.append('--verbose')

            logger.debug('Command: %s', ' '.join(cmd))
            subprocess.check_call(cmd)

        finally:
            shutil.rmtree(tmpdir)

    def get_ca_signing_cert(self, instance, ca_url):

        cmd = [
            'pki',
            '-d', instance.nssdb_dir,
            '-f', instance.password_conf,
            '-U', ca_url,
            '--ignore-cert-status', 'UNTRUSTED_ISSUER',
            '--ignore-banner',
            'ca-cert-signing-export',
            '--pkcs7'
        ]

        if logger.isEnabledFor(logging.DEBUG):
            cmd.append('--debug')

        elif logger.isEnabledFor(logging.INFO):
            cmd.append('--verbose')

        logger.debug('Command: %s', ' '.join(cmd))
        output = subprocess.check_output(cmd)

        return output.decode()

    def get_ca_subsystem_cert(self, instance, ca_url):

        cmd = [
            'pki',
            '-d', instance.nssdb_dir,
            '-f', instance.password_conf,
            '-U', ca_url,
            '--ignore-banner',
            'ca-cert-subsystem-export'
        ]

        if logger.isEnabledFor(logging.DEBUG):
            cmd.append('--debug')

        elif logger.isEnabledFor(logging.INFO):
            cmd.append('--verbose')

        logger.debug('Command: %s', ' '.join(cmd))
        return subprocess.check_output(cmd)

    def add_kra_connector(self, instance, subsystem):

        server_config = instance.get_server_config()
        hostname = self.mdict['pki_hostname']
        securePort = server_config.get_secure_port()

        ca_url = self.mdict['pki_issuing_ca']
        kra_url = 'https://%s:%s/kra/agent/kra/connector' % (hostname, securePort)

        transport_cert = subsystem.config.get('kra.transport.cert')
        transport_nickname = subsystem.config.get('kra.cert.transport.nickname')

        tmpdir = tempfile.mkdtemp()
        try:
            transport_cert_file = os.path.join(tmpdir, 'kra_transport.crt')
            with open(transport_cert_file, 'w') as f:
                f.write(transport_cert)

            install_token = os.path.join(tmpdir, 'install-token')
            with open(install_token, 'w') as f:
                f.write(self.install_token.token)

            cmd = [
                'pki',
                '-d', instance.nssdb_dir,
                '-f', instance.password_conf,
                '-U', ca_url,
                '--ignore-banner',
                'ca-kraconnector-add',
                '--url', kra_url,
                '--transport-cert', transport_cert_file,
                '--transport-nickname', transport_nickname,
                '--install-token', install_token
            ]

            if logger.isEnabledFor(logging.DEBUG):
                cmd.append('--debug')

            elif logger.isEnabledFor(logging.INFO):
                cmd.append('--verbose')

            logger.debug('Command: %s', ' '.join(cmd))
            subprocess.check_call(cmd)

        finally:
            shutil.rmtree(tmpdir)

    def add_ocsp_publisher(self, instance):

        server_config = instance.get_server_config()
        hostname = self.mdict['pki_hostname']
        securePort = server_config.get_secure_port()

        ca_url = self.mdict['pki_issuing_ca']
        ocsp_url = 'https://%s:%s' % (hostname, securePort)

        tmpdir = tempfile.mkdtemp()
        try:
            install_token = os.path.join(tmpdir, 'install-token')
            with open(install_token, 'w') as f:
                f.write(self.install_token.token)

            cmd = [
                'pki',
                '-d', instance.nssdb_dir,
                '-f', instance.password_conf,
                '-U', ca_url,
                '--ignore-banner',
                'ca-publisher-ocsp-add',
                '--url', ocsp_url,
                '--install-token', install_token
            ]

            if logger.isEnabledFor(logging.DEBUG):
                cmd.append('--debug')

            elif logger.isEnabledFor(logging.INFO):
                cmd.append('--verbose')

            logger.debug('Command: %s', ' '.join(cmd))
            subprocess.check_call(cmd)

        finally:
            shutil.rmtree(tmpdir)

    def get_kra_transport_cert(self, instance):

        kra_url = self.mdict['pki_kra_uri']

        cmd = [
            'pki',
            '-d', instance.nssdb_dir,
            '-f', instance.password_conf,
            '-U', kra_url,
            '--ignore-banner',
            'kra-cert-transport-export'
        ]

        if logger.isEnabledFor(logging.DEBUG):
            cmd.append('--debug')

        elif logger.isEnabledFor(logging.INFO):
            cmd.append('--verbose')

        logger.debug('Command: %s', ' '.join(cmd))
        result = subprocess.run(cmd, stdout=subprocess.PIPE, check=True)

        return result.stdout.decode()

    def set_tks_transport_cert(self, instance, cert, session=None, install_token=None):

        tks_url = self.mdict['pki_tks_uri']
        sd_url = self.mdict['pki_security_domain_uri']

        hostname = self.mdict['pki_hostname']

        server_config = instance.get_server_config()
        secure_port = server_config.get_secure_port()

        nickname = 'transportCert-%s-%s' % (hostname, secure_port)

        tmpdir = tempfile.mkdtemp()
        try:
            if not install_token:
                install_token = os.path.join(tmpdir, 'install-token')
                with open(install_token, 'w') as f:
                    f.write(session)

            cmd = [
                'pki',
                '-d', instance.nssdb_dir,
                '-f', instance.password_conf,
                '-U', tks_url,
                '--ignore-banner',
                'tks-cert-transport-import',
                '--security-domain', sd_url,
                '--install-token', install_token,
                nickname
            ]

            if logger.isEnabledFor(logging.DEBUG):
                cmd.append('--debug')

            elif logger.isEnabledFor(logging.INFO):
                cmd.append('--verbose')

            logger.debug('Command: %s', ' '.join(cmd))
            subprocess.run(
                cmd,
                input=cert,
                universal_newlines=True,
                check=True)

        finally:
            shutil.rmtree(tmpdir)

    def get_tps_connector(self, instance, subsystem):

        tks_uri = self.mdict['pki_tks_uri']
        subsystem_cert = subsystem.get_subsystem_cert('subsystem')

        nickname = subsystem_cert['nickname']
        token = subsystem_cert['token']

        if pki.nssdb.normalize_token(token):
            nickname = token + ':' + nickname

        server_config = instance.get_server_config()
        securePort = server_config.get_secure_port()

        cmd = [
            'pki',
            '-U', tks_uri,
            '-d', instance.nssdb_dir,
            '-f', instance.password_conf,
            '-n', nickname,
            '--ignore-banner',
            'tks-tpsconnector-show',
            '--host', self.mdict['pki_hostname'],
            '--port', securePort,
            '--output-format', 'json'
        ]

        logger.debug('Command: %s', ' '.join(cmd))
        result = subprocess.run(cmd, stdout=subprocess.PIPE, check=False)

        if result.returncode == 0:
            return json.loads(result.stdout.decode())
        else:
            return None

    def create_tps_connector(self, instance, subsystem):

        tks_uri = self.mdict['pki_tks_uri']
        subsystem_cert = subsystem.get_subsystem_cert('subsystem')

        nickname = subsystem_cert['nickname']
        token = subsystem_cert['token']

        if pki.nssdb.normalize_token(token):
            nickname = token + ':' + nickname

        server_config = instance.get_server_config()
        securePort = server_config.get_secure_port()

        cmd = [
            'pki',
            '-U', tks_uri,
            '-d', instance.nssdb_dir,
            '-f', instance.password_conf,
            '-n', nickname,
            '--ignore-banner',
            'tks-tpsconnector-add',
            '--host', self.mdict['pki_hostname'],
            '--port', securePort,
            '--output-format', 'json'
        ]

        logger.debug('Command: %s', ' '.join(cmd))
        result = subprocess.run(cmd, stdout=subprocess.PIPE, check=False)

        if result.returncode == 0:
            return json.loads(result.stdout.decode())
        else:
            return None

    def get_shared_secret(self, instance, subsystem, tps_connector_id):

        tks_uri = self.mdict['pki_tks_uri']
        subsystem_cert = subsystem.get_subsystem_cert('subsystem')

        nickname = subsystem_cert['nickname']
        token = subsystem_cert['token']

        if pki.nssdb.normalize_token(token):
            nickname = token + ':' + nickname

        cmd = [
            'pki',
            '-U', tks_uri,
            '-d', instance.nssdb_dir,
            '-f', instance.password_conf,
            '-n', nickname,
            '--ignore-banner',
            'tks-key-export', tps_connector_id
        ]

        logger.debug('Command: %s', ' '.join(cmd))
        result = subprocess.run(cmd, stdout=subprocess.PIPE, check=False)

        if result.returncode == 0:
            return json.loads(result.stdout.decode())
        else:
            return None

    def create_shared_secret(self, instance, subsystem, tps_connector_id):

        tks_uri = self.mdict['pki_tks_uri']
        subsystem_cert = subsystem.get_subsystem_cert('subsystem')

        nickname = subsystem_cert['nickname']
        token = subsystem_cert['token']

        if pki.nssdb.normalize_token(token):
            nickname = token + ':' + nickname

        cmd = [
            'pki',
            '-U', tks_uri,
            '-d', instance.nssdb_dir,
            '-f', instance.password_conf,
            '-n', nickname,
            '--ignore-banner',
            'tks-key-create', tps_connector_id,
            '--output-format', 'json'
        ]

        logger.debug('Command: %s', ' '.join(cmd))
        result = subprocess.run(cmd, stdout=subprocess.PIPE, check=False)

        if result.returncode == 0:
            return json.loads(result.stdout.decode())
        else:
            return None

    def replace_shared_secret(self, instance, subsystem, tps_connector_id):

        tks_uri = self.mdict['pki_tks_uri']
        subsystem_cert = subsystem.get_subsystem_cert('subsystem')

        nickname = subsystem_cert['nickname']
        token = subsystem_cert['token']

        if pki.nssdb.normalize_token(token):
            nickname = token + ':' + nickname

        cmd = [
            'pki',
            '-U', tks_uri,
            '-d', instance.nssdb_dir,
            '-f', instance.password_conf,
            '-n', nickname,
            '--ignore-banner',
            'tks-key-replace', tps_connector_id,
            '--output-format', 'json'
        ]

        logger.debug('Command: %s', ' '.join(cmd))
        result = subprocess.run(cmd, stdout=subprocess.PIPE, check=False)

        if result.returncode == 0:
            return json.loads(result.stdout.decode())
        else:
            return None

    def import_shared_secret(self, instance, subsystem, secret_nickname, shared_secret):

        subsystem_cert = subsystem.get_subsystem_cert('subsystem')

        nickname = subsystem_cert['nickname']
        token = subsystem_cert['token']

        if pki.nssdb.normalize_token(token):
            nickname = token + ':' + nickname

        cmd = [
            'pki',
            '-d', instance.nssdb_dir,
            '-f', instance.password_conf,
            'nss-key-import', secret_nickname,
            '--wrapper', nickname
        ]

        logger.debug('Command: %s', ' '.join(cmd))
        subprocess.run(
            cmd,
            input=json.dumps(shared_secret),
            universal_newlines=True,
            check=True)

    def setup_shared_secret(self, instance, subsystem):

        # This method configures the shared secret between TKS and TPS. The shared secret
        # is initially generated in TKS, then exported from TKS, and reimported into TPS.
        # However, if TKS and TPS are running on the same instance, it is not necessary
        # to export and reimport since they are sharing the same NSS database.

        # TODO: Clean up the code and determine whether TKS and TPS are in the same
        # instance automatically.

        hostname = self.mdict['pki_hostname']

        server_config = instance.get_server_config()
        securePort = server_config.get_secure_port()

        secret_nickname = 'TPS-%s-%s sharedSecret' % (hostname, securePort)

        logger.info('Searching for TPS connector in TKS')
        tps_connector = self.get_tps_connector(instance, subsystem)

        if tps_connector:
            logger.info('Getting shared secret')
            tps_connector_id = tps_connector['id']
            shared_secret = self.get_shared_secret(instance, subsystem, tps_connector_id)

            if shared_secret:
                logger.info('Replacing shared secret')
                shared_secret = self.replace_shared_secret(instance, subsystem, tps_connector_id)

            else:
                logger.info('Creating shared secret')
                shared_secret = self.create_shared_secret(instance, subsystem, tps_connector_id)

        else:
            logger.info('Creating a new TPS connector')
            tps_connector = self.create_tps_connector(instance, subsystem)
            tps_connector_id = tps_connector['id']

            logger.info('Creating shared secret')
            shared_secret = self.create_shared_secret(instance, subsystem, tps_connector_id)

        if config.str2bool(self.mdict['pki_import_shared_secret']):
            logger.info('Importing shared secret')
            self.import_shared_secret(instance, subsystem, secret_nickname, shared_secret)

        subsystem.config['conn.tks1.tksSharedSymKeyName'] = secret_nickname
        subsystem.save()

    def finalize_subsystem(self, instance, subsystem):

        clone = self.configuration_file.clone
        standalone = self.configuration_file.standalone

        if subsystem.type == 'CA':

            if clone:
                logger.info('Disabling CRL caching and generation on clone')

                subsystem.config['ca.certStatusUpdateInterval'] = '0'
                subsystem.config['ca.listenToCloneModifications'] = 'false'
                subsystem.config['ca.crl.MasterCRL.enableCRLCache'] = 'false'
                subsystem.config['ca.crl.MasterCRL.enableCRLUpdates'] = 'false'

                master_url = self.mdict['pki_clone_uri']
                url = urllib.parse.urlparse(master_url)

                subsystem.config['master.ca.agent.host'] = url.hostname
                subsystem.config['master.ca.agent.port'] = str(url.port)

            else:
                logger.info('Updating CA ranges')
                subsystem.update_ranges()

            crl_number = self.mdict['pki_ca_starting_crl_number']
            logger.info('Starting CRL number: %s', crl_number)
            subsystem.config['ca.crl.MasterCRL.startingCrlNumber'] = crl_number

            logger.info('Enabling profile subsystem')
            subsystem.enable_subsystem('profile')

            # Delete CA signing cert record to avoid migration conflict
            if not config.str2bool(self.mdict['pki_ca_signing_record_create']):
                logger.info('Deleting CA signing cert record')
                serial_number = self.mdict['pki_ca_signing_serial_number']
                subsystem.remove_cert(serial_number)

        else:
            ca_type = subsystem.config.get('preop.ca.type')
            if ca_type:
                subsystem.config['cloning.ca.type'] = ca_type

        if subsystem.type == 'KRA':

            if not clone:
                logger.info('Updating KRA ranges')
                subsystem.update_ranges()

            ca_host = subsystem.config.get('preop.ca.hostname')

            if not clone and not standalone and ca_host:
                ca_port = subsystem.config.get('preop.ca.httpsadminport')
                ca_url = 'https://%s:%s' % (ca_host, ca_port)
                uid = 'CA-%s-%s' % (ca_host, ca_port)

                logger.info('Adding %s', uid)
                subsystem.add_user(
                    uid,
                    full_name=uid,
                    user_type='agentType',
                    state='1')

                logger.info('Getting subsystem certificate from %s', ca_url)
                subsystem_cert_data = self.get_ca_subsystem_cert(instance, ca_url)

                logger.info('Adding subsystem certificate into %s', uid)
                subsystem.add_user_cert(uid, cert_data=subsystem_cert_data, cert_format='PEM')

                logger.info('Adding %s into Trusted Managers', uid)
                subsystem.add_group_member('Trusted Managers', uid)

            ca_url = subsystem.config.get('preop.ca.url')

            if not standalone and ca_host and ca_url:

                logger.info('Adding KRA connector in CA')
                self.add_kra_connector(instance, subsystem)

        if subsystem.type == 'OCSP':

            ca_host = subsystem.config.get('preop.ca.hostname')

            if not clone and ca_host:

                logger.info('Adding CRL issuing point')
                base64_chain = subsystem.config['preop.ca.pkcs7']
                cert_chain = base64.b64decode(base64_chain)
                subsystem.add_crl_issuing_point(cert_chain=cert_chain, cert_format='DER')

            if not clone and not standalone and ca_host:
                ca_port = subsystem.config.get('preop.ca.httpsadminport')
                ca_url = 'https://%s:%s' % (ca_host, ca_port)
                uid = 'CA-%s-%s' % (ca_host, ca_port)

                logger.info('Adding %s', uid)
                subsystem.add_user(
                    uid,
                    full_name=uid,
                    user_type='agentType',
                    state='1')

                logger.info('Getting subsystem certificate from %s', ca_url)
                subsystem_cert_data = self.get_ca_subsystem_cert(instance, ca_url)

                logger.info('Adding subsystem certificate into %s', uid)
                subsystem.add_user_cert(uid, cert_data=subsystem_cert_data, cert_format='PEM')

                logger.info('Adding %s into Trusted Managers', uid)
                subsystem.add_group_member('Trusted Managers', uid)

                logger.info('Adding OCSP publisher in CA')
                # For now don't register publishing with the CA for a clone,
                # preserving existing functionality.
                # Next we need to treat the publishing of clones as a group,
                # and fail over amongst them.
                self.add_ocsp_publisher(instance)

        if subsystem.type == 'TPS':

            uid = 'TPS-%s-%s' % (self.mdict['pki_hostname'], self.mdict['pki_https_port'])
            full_name = subsystem.config['preop.subsystem.name']
            subsystem_cert = subsystem.get_subsystem_cert('subsystem').get('data')

            logger.info('Registering TPS in CA')
            self.add_subsystem_user(
                instance,
                'ca',
                self.mdict['pki_ca_uri'],
                uid,
                full_name,
                cert=subsystem_cert,
                session=self.install_token.token)

            logger.info('Registering TPS in TKS')
            self.add_subsystem_user(
                instance,
                'tks',
                self.mdict['pki_tks_uri'],
                uid,
                full_name,
                cert=subsystem_cert,
                session=self.install_token.token)

            keygen = config.str2bool(self.mdict['pki_enable_server_side_keygen'])

            if keygen:
                logger.info('Registering TPS in KRA')
                self.add_subsystem_user(
                    instance,
                    'kra',
                    self.mdict['pki_kra_uri'],
                    uid,
                    full_name,
                    cert=subsystem_cert,
                    session=self.install_token.token)

                logger.info('Exporting transport cert from KRA')
                transport_cert = self.get_kra_transport_cert(instance)

                logger.info('Importing transport cert into TKS')
                self.set_tks_transport_cert(
                    instance,
                    transport_cert,
                    session=self.install_token.token)

            logger.info('Setting up shared secret')
            self.setup_shared_secret(instance, subsystem)

        # save EC type for sslserver cert (if present)
        ec_type = subsystem.config.get('preop.cert.sslserver.ec.type', 'ECDHE')
        subsystem.config['jss.ssl.sslserver.ectype'] = ec_type

        for key in list(subsystem.config.keys()):
            if key.startswith('preop.'):
                del subsystem.config[key]

        subsystem.config['cs.state'] = '1'

        subsystem.save()
