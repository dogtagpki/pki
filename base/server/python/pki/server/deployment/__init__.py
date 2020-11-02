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
            if os.path.exists(self.mdict['pki_cert_chain_path']):
                ca_cert = self.mdict['pki_cert_chain_path']

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

    def finalize_subsystem(self, subsystem):

        if subsystem.type != 'CA':
            ca_type = subsystem.config.get('preop.ca.type')
            if ca_type:
                subsystem.config['cloning.ca.type'] = ca_type

        # save EC type for sslserver cert (if present)
        ec_type = subsystem.config.get('preop.cert.sslserver.ec.type', 'ECDHE')
        subsystem.config['jss.ssl.sslserver.ectype'] = ec_type

        for key in list(subsystem.config.keys()):
            if key.startswith('preop.'):
                del subsystem.config[key]

        subsystem.config['cs.state'] = '1'

        subsystem.save()
