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

        # If provided, import cert chain into NSS database.
        # Note: Cert chain must be imported after the system certs
        # to ensure that the system certs are imported with
        # the correct nicknames.

        self.import_cert_chain(nssdb)

    def configure_system_cert(self, subsystem, tag):

        cert_id = self.get_cert_id(subsystem, tag)
        nickname = self.mdict['pki_%s_nickname' % cert_id]

        logger.info('Configuring %s certificate', cert_id)

        subsystem.config['%s.%s.nickname' % (subsystem.name, tag)] = nickname
        subsystem.config['%s.%s.tokenname' % (subsystem.name, tag)] = \
            self.mdict['pki_%s_token' % cert_id]
        subsystem.config['%s.%s.defaultSigningAlgorithm' % (subsystem.name, tag)] = \
            self.mdict['pki_%s_key_algorithm' % cert_id]

    def configure_system_certs(self, subsystem):

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

        cert_id = self.get_cert_id(subsystem, tag)
        nickname = self.mdict['pki_%s_nickname' % cert_id]

        cert_data = nssdb.get_cert(
            nickname=nickname,
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

        cert_id = self.get_cert_id(subsystem, tag)
        nickname = self.mdict['pki_%s_nickname' % cert_id]

        cert_data = nssdb.get_cert(nickname=nickname)
        if not cert_data:
            return

        logger.info('Validating %s certificate', tag)

        subsystem.validate_system_cert(tag)

    def validate_system_certs(self, nssdb, subsystem):

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
            logger.info('ds_connect called without corresponding call to ds_init')
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
        sd_hostname = self.mdict['pki_security_domain_hostname']
        sd_port = self.mdict['pki_security_domain_https_port']

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

    def join_domain(self):

        self.get_domain_info()

        sd_hostname = self.mdict['pki_security_domain_hostname']
        sd_port = self.mdict['pki_security_domain_https_port']
        sd_subsystem = self.domain_info.subsystems['CA']
        self.sd_host = sd_subsystem.get_host(sd_hostname, sd_port)

        self.get_install_token()

    def setup_cert(self, client, tag):

        request = pki.system.CertificateSetupRequest()

        request.pin = self.mdict['pki_one_time_pin']
        request.installToken = self.install_token

        # Process existing CA installation like external CA
        request.external = config.str2bool(self.mdict['pki_external']) or \
            config.str2bool(self.mdict['pki_existing'])
        request.standAlone = config.str2bool(self.mdict['pki_standalone'])
        request.clone = config.str2bool(self.mdict['pki_clone'])
        request.masterURL = self.mdict['pki_clone_uri']

        request.tag = tag
        self.config_client.set_system_cert_info(request, tag)

        return client.setupCert(request)

    def setup_admin(self, subsystem, client):

        uid = self.mdict['pki_admin_uid']
        full_name = self.mdict['pki_admin_name']
        email = self.mdict['pki_admin_email']
        password = self.mdict['pki_admin_password']

        tps_profiles = None
        if subsystem.type == 'TPS':
            tps_profiles = ['All Profiles']

        request = pki.system.AdminSetupRequest()
        request.pin = self.mdict['pki_one_time_pin']
        request.installToken = self.install_token

        self.config_client.set_admin_parameters(request)

        response = client.setupAdmin(request)

        subsystem.add_user(
            uid,
            full_name=full_name,
            email=email,
            password=password,
            user_type='adminType',
            state='1',
            tps_profiles=tps_profiles)

        admin_groups = subsystem.config['preop.admin.group']
        groups = [x.strip() for x in admin_groups.split(',')]

        if subsystem.config['securitydomain.select'] == 'new':
            groups.extend([
                'Security Domain Administrators',
                'Enterprise CA Administrators',
                'Enterprise KRA Administrators',
                'Enterprise RA Administrators',
                'Enterprise TKS Administrators',
                'Enterprise OCSP Administrators',
                'Enterprise TPS Administrators'
            ])

        for group in groups:
            logger.info('Adding %s into %s', uid, group)
            subsystem.add_group_member(group, uid)

        admin_cert = response['adminCert']['cert']
        cert_data = base64.b64decode(admin_cert)

        logger.info('Adding certificate for %s', uid)
        subsystem.add_user_cert(uid, cert_data=cert_data, cert_format='DER')

        if config.str2bool(self.mdict['pki_external']) \
                or config.str2bool(self.mdict['pki_standalone']) \
                or not config.str2bool(self.mdict['pki_import_admin_cert']):

            self.config_client.process_admin_cert(admin_cert)

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

    def get_ca_signing_cert(self, instance, ca_url):

        cmd = [
            'pki',
            '-d', instance.nssdb_dir,
            '-f', instance.password_conf,
            '-U', ca_url,
            '--ignore-cert-status', 'UNTRUSTED_ISSUER',
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
            'ca-cert-subsystem-export'
        ]

        if logger.isEnabledFor(logging.DEBUG):
            cmd.append('--debug')

        elif logger.isEnabledFor(logging.INFO):
            cmd.append('--verbose')

        logger.debug('Command: %s', ' '.join(cmd))
        return subprocess.check_output(cmd)

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
            text=True,
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

        if subsystem.type == 'OCSP':

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

        if subsystem.type == 'TPS':
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
