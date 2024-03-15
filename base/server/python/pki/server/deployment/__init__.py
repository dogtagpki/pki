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
import binascii
import json
import ldap
import logging
import os
import re
import selinux
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from time import strftime as date
import urllib.parse

from lxml import etree

from cryptography import x509
from cryptography.hazmat.backends import default_backend

import pki.nssdb
import pki.account
import pki.client
import pki.server
import pki.server.deployment.scriptlets.configuration
import pki.server.deployment.scriptlets.fapolicy_setup
import pki.server.deployment.scriptlets.finalization
import pki.server.deployment.scriptlets.infrastructure_layout
import pki.server.deployment.scriptlets.initialization
import pki.server.deployment.scriptlets.instance_layout
import pki.server.deployment.scriptlets.keygen
import pki.server.deployment.scriptlets.security_databases
import pki.server.deployment.scriptlets.selinux_setup
import pki.server.deployment.scriptlets.subsystem_layout
import pki.system
import pki.util

from . import pkiconfig as config
from . import pkihelper as util
from . import pkimanifest as manifest
from . import pkimessages as log

seobject = None
if selinux.is_selinux_enabled():
    try:
        import seobject
    except ImportError:
        # TODO: Fedora 22 has an incomplete Python 3 package
        # sepolgen is missing.
        if sys.version_info.major == 2:
            raise

logger = logging.getLogger(__name__)


class PKIDeployer:
    """Holds the global dictionaries and the utility objects"""

    def __init__(self):

        # PKI Deployment "Mandatory" Command-Line Variables
        self.subsystem_type = None

        # Global dictionary variables
        self.mdict = {}
        self.main_config = None
        self.user_config = None
        self.manifest_db = []

        self.instance = None
        self.identity = None
        self.namespace = None
        self.configuration_file = None
        self.directory = None
        self.file = None
        self.symlink = None
        self.war = None
        self.password = None
        self.hsm = None
        self.certutil = None
        self.pk12util = None
        self.kra_connector = None
        self.systemd = None
        self.tps_connector = None
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

        self.client = None
        self.startup_timeout = None
        self.request_timeout = None

        self.force = False
        self.remove_logs = False

    def set_property(self, key, value, section=None):

        if not section:
            section = self.subsystem_type

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
        self.directory = util.Directory(self)
        self.file = util.File(self)
        self.symlink = util.Symlink(self)
        self.password = util.Password(self)
        self.hsm = util.HSM(self)
        self.certutil = util.Certutil(self)
        self.pk12util = util.PK12util(self)
        self.kra_connector = util.KRAConnector(self)
        self.systemd = util.Systemd(self)
        self.tps_connector = util.TPSConnector(self)

        self.ds_init()

    def ds_init(self):

        ds_url = self.mdict.get('pki_ds_url')

        if ds_url is None:

            ds_hostname = self.mdict['pki_ds_hostname']

            if config.str2bool(self.mdict['pki_ds_secure_connection']):
                ds_protocol = 'ldaps'
                ds_port = self.mdict['pki_ds_ldaps_port']
            else:
                ds_protocol = 'ldap'
                ds_port = self.mdict['pki_ds_ldap_port']

            ds_url = ds_protocol + '://' + ds_hostname + ':' + ds_port

        self.ds_url = urllib.parse.urlparse(ds_url)

        if self.ds_url.scheme == 'ldaps':
            # ldap.set_option(ldap.OPT_DEBUG_LEVEL, 255)
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE,
                            self.mdict['pki_ds_secure_connection_ca_pem_file'])
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)

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

        if self.main_config.has_section(self.subsystem_type):
            subsystem_dict = dict(self.main_config.items(self.subsystem_type))
            subsystem_dict[0] = None
            self.mdict.update(subsystem_dict)

    def configure_server_xml(self):

        if os.path.exists(self.instance.server_xml):
            logger.info('Updating %s', self.instance.server_xml)
        else:
            logger.info('Creating %s', self.instance.server_xml)
            self.instance.copy(
                pki.server.Tomcat.SERVER_XML,
                self.instance.server_xml)

        server_config = self.instance.get_server_config()

        logger.info('Configuring Tomcat admin port')
        server_config.set_port(self.mdict['pki_tomcat_server_port'])

        listener = server_config.get_listener('org.apache.catalina.core.AprLifecycleListener')
        if listener is not None:
            logger.info('Removing AprLifecycleListener')
            # It is not needed since PKI server will use JSS-based SSL connector
            server_config.remove_listener('org.apache.catalina.core.AprLifecycleListener')

        listener = server_config.get_listener('com.netscape.cms.tomcat.PKIListener')
        if listener is None:
            logger.info('Adding PKIListener')
            server_config.create_listener('com.netscape.cms.tomcat.PKIListener')
        else:
            logger.info('Reusing PKIListener')

        logger.info('Removing UserDatabase')
        server_config.remove_global_naming_resource('UserDatabase')

        # find default HTTP connector
        connector = server_config.get_connector(port='8080')
        service = connector.getparent()

        # get HTTP connector position
        index = service.index(connector)

        if config.str2bool(self.mdict['pki_http_enable']):

            logger.info('Configuring HTTP connector')
            connector.set('name', 'Unsecure')
            connector.set('port', self.mdict['pki_http_port'])
            connector.set('redirectPort', self.mdict['pki_https_port'])
            connector.set('maxHttpHeaderSize', '8192')
            connector.set('acceptCount', '100')
            connector.set('maxThreads', '150')
            connector.set('minSpareThreads', '25')
            connector.set('enableLookups', 'false')
            connector.set('connectionTimeout', '80000')
            connector.set('disableUploadTimeout', 'true')

            # add the HTTPS connector after this connector
            index = index + 1

        else:
            logger.info('Removing HTTP connector')
            service.remove(connector)

        connector = server_config.get_connector(port=self.mdict['pki_https_port'])

        if connector is None:
            logger.info('Adding HTTPS connector')
            connector = server_config.create_connector(name='Secure', index=index)
        else:
            logger.info('Updating HTTPS connector')
            connector.set('name', 'Secure')

        connector.set('port', self.mdict['pki_https_port'])
        connector.set('protocol', 'org.dogtagpki.jss.tomcat.Http11NioProtocol')
        connector.set('SSLEnabled', 'true')
        connector.set('sslImplementationName', 'org.dogtagpki.jss.tomcat.JSSImplementation')
        connector.set('scheme', 'https')
        connector.set('secure', 'true')
        connector.set('connectionTimeout', '80000')
        connector.set('keepAliveTimeout', '300000')
        connector.set('maxHttpHeaderSize', '8192')
        connector.set('acceptCount', '100')
        connector.set('maxThreads', '150')
        connector.set('minSpareThreads', '25')
        connector.set('enableLookups', 'false')
        connector.set('disableUploadTimeout', 'true')
        connector.set('enableOCSP', 'false')
        connector.set(
            'ocspResponderURL',
            'http://%s:%s/ca/ocsp' %
            (self.mdict['pki_hostname'], self.mdict['pki_http_port']))
        connector.set('ocspResponderCertNickname', 'ocspSigningCert cert-pki-ca')
        connector.set('ocspCacheSize', '1000')
        connector.set('ocspMinCacheEntryDuration', '7200')
        connector.set('ocspMaxCacheEntryDuration', '14400')
        connector.set('ocspTimeout', '10')
        connector.set('passwordFile', self.instance.password_conf)
        connector.set('passwordClass', 'org.dogtagpki.jss.tomcat.PlainPasswordFile')
        connector.set('certdbDir', self.instance.nssdb_dir)

        sslhost = server_config.get_sslhost(connector)
        if sslhost is None:
            logger.info('Adding SSL host configuration')
            sslhost = server_config.create_sslhost(connector)
        else:
            logger.info('Updating SSL host configuration')

        sslhost.set('sslProtocol', 'SSL')
        sslhost.set('certificateVerification', 'optional')

        sslcert = server_config.get_sslcert(sslhost)
        if sslcert is None:
            logger.info('Adding SSL certificate configuration')
            sslcert = server_config.create_sslcert(sslhost)
        else:
            logger.info('Updating SSL certificate configuration')

        sslcert.set('certificateKeystoreType', 'pkcs11')
        sslcert.set('certificateKeystoreProvider', 'Mozilla-JSS')
        sslcert.set('certificateKeyAlias', 'sslserver')

        if config.str2bool(self.mdict['pki_enable_proxy']):

            logger.info('Adding AJP connector for IPv4')

            connector = etree.Element('Connector')
            connector.set('port', self.mdict['pki_ajp_port'])
            connector.set('protocol', 'AJP/1.3')
            connector.set('redirectPort', self.mdict['pki_https_port'])
            connector.set('address', self.mdict['pki_ajp_host_ipv4'])
            connector.set('secret', self.mdict['pki_ajp_secret'])

            server_config.add_connector(connector)

            logger.info('Adding AJP connector for IPv6')

            connector = etree.Element('Connector')
            connector.set('port', self.mdict['pki_ajp_port'])
            connector.set('protocol', 'AJP/1.3')
            connector.set('redirectPort', self.mdict['pki_https_port'])
            connector.set('address', self.mdict['pki_ajp_host_ipv6'])
            connector.set('secret', self.mdict['pki_ajp_secret'])

            server_config.add_connector(connector)

        logger.info('Removing LockOutRealm')
        server_config.remove_realm('org.apache.catalina.realm.LockOutRealm')

        if config.str2bool(self.mdict['pki_enable_access_log']):

            valve = server_config.get_valve('org.apache.catalina.valves.AccessLogValve')

            if valve is None:
                logger.info('Adding AccessLogValve')
                valve = etree.Element('Valve')
                valve.set('className', 'org.apache.catalina.valves.AccessLogValve')
                server_config.add_valve(valve)
            else:
                logger.info('Updating AccessLogValve')

            valve.set('directory', 'logs')
            valve.set('prefix', 'localhost_access_log')
            valve.set('suffix', '.txt')
            valve.set('pattern', 'common')

        else:

            logger.info('Disabling access log')
            server_config.remove_valve('org.apache.catalina.valves.AccessLogValve')

        rewrite_valve_class = 'org.apache.catalina.valves.rewrite.RewriteValve'
        rewrite_valve = server_config.get_valve(rewrite_valve_class)

        if rewrite_valve is None:
            logger.info('Adding RewriteValve')
            server_config.create_valve(rewrite_valve_class)
        else:
            logger.info('Reusing RewriteValve')

        server_config.save()

    def update_rsa_pss_algorithm(self, cert_id, alg_type):

        param = 'pki_%s_%s_algorithm' % (cert_id, alg_type)
        algorithm = self.mdict[param]

        # if algorithm is XXXwithRSA, change it into XXXwithRSA/PSS
        if not re.search(r'withRSA$', algorithm):
            return

        self.mdict[param] = '%s/PSS' % algorithm

    def update_rsa_pss_algorithms(self, subsystem):

        logger.info('Updating RSA-PSS algorithms')

        if subsystem.type == 'CA':
            self.update_rsa_pss_algorithm('ca_signing', 'key')
            self.update_rsa_pss_algorithm('ca_signing', 'signing')

        if subsystem.type == 'KRA':
            self.update_rsa_pss_algorithm('storage', 'key')
            self.update_rsa_pss_algorithm('storage', 'signing')

            self.update_rsa_pss_algorithm('transport', 'key')
            self.update_rsa_pss_algorithm('transport', 'signing')

        if subsystem.type in ['CA', 'OCSP']:
            self.update_rsa_pss_algorithm('ocsp_signing', 'key')
            self.update_rsa_pss_algorithm('ocsp_signing', 'signing')

        self.update_rsa_pss_algorithm('audit_signing', 'key')
        self.update_rsa_pss_algorithm('audit_signing', 'signing')

        self.update_rsa_pss_algorithm('sslserver', 'key')
        self.update_rsa_pss_algorithm('sslserver', 'signing')

        self.update_rsa_pss_algorithm('subsystem', 'key')
        self.update_rsa_pss_algorithm('subsystem', 'signing')

        self.update_rsa_pss_algorithm('admin', 'key')

    def get_key_params(self, cert_id):

        key_type = self.mdict['pki_%s_key_type' % cert_id]
        key_alg = self.mdict['pki_%s_key_algorithm' % cert_id]
        key_size = self.mdict['pki_%s_key_size' % cert_id]

        if key_type == 'rsa':

            key_size = int(key_size)
            curve = None

            m = re.match(r'(.*)withRSA', key_alg)
            if not m:
                raise Exception('Invalid key algorithm: %s' % key_alg)

            hash_alg = m.group(1)

        elif key_type == 'ec' or key_type == 'ecc':

            key_type = 'ec'
            curve = key_size
            key_size = None

            if (cert_id in ['storage', 'transport']):
                raise Exception('Invalid key type for KRA %s cert: %s' % (cert_id, key_type))

            m = re.match(r'(.*)withEC', key_alg)
            if not m:
                raise Exception('Invalid key algorithm: %s' % key_alg)

            hash_alg = m.group(1)

        else:
            raise Exception('Invalid key type: %s' % key_type)

        return (key_type, key_size, curve, hash_alg)

    def update_external_certs_conf(self, external_path):

        external_certs = pki.server.instance.PKIInstance.read_external_certs(
            external_path)

        if not external_certs:
            return

        # load existing external certs
        self.instance.load_external_certs(
            os.path.join(self.instance.conf_dir, 'external_certs.conf')
        )

        # add new external certs
        for cert in external_certs:
            self.instance.add_external_cert(cert.nickname, cert.token)

    def create_server_nssdb(self):

        # Since 'certutil' does NOT strip the 'token=' portion of
        # the 'token=password' entries, create a temporary server 'pfile'
        # which ONLY contains the 'password' for the purposes of
        # allowing 'certutil' to generate the security databases

        pki_shared_pfile = os.path.join(self.instance.conf_dir, 'pfile')

        logger.info('Creating password file: %s', pki_shared_pfile)
        self.password.create_password_conf(
            pki_shared_pfile,
            self.mdict['pki_server_database_password'], pin_sans_token=True)
        self.file.modify(self.instance.password_conf)

        if not os.path.isdir(self.instance.nssdb_dir):
            self.instance.makedirs(self.instance.nssdb_dir, exist_ok=True)

        nssdb = pki.nssdb.NSSDatabase(
            directory=self.instance.nssdb_dir,
            password_file=pki_shared_pfile)

        try:
            if not nssdb.exists():
                logger.info('Creating NSS database: %s', self.instance.nssdb_dir)
                nssdb.create()
        finally:
            nssdb.close()

        if not os.path.islink(self.instance.nssdb_link):
            self.instance.symlink(
                self.instance.nssdb_dir,
                self.instance.nssdb_link,
                exist_ok=True)

        if config.str2bool(self.mdict['pki_hsm_enable']) and \
                self.mdict['pki_hsm_modulename'] and \
                self.mdict['pki_hsm_libfile'] and \
                not nssdb.module_exists(self.mdict['pki_hsm_modulename']):
            nssdb.add_module(
                self.mdict['pki_hsm_modulename'],
                self.mdict['pki_hsm_libfile'])

        # set the initial NSS database ownership and permissions

        pki.util.chown(
            self.instance.nssdb_dir,
            self.mdict['pki_uid'],
            self.mdict['pki_gid'])
        pki.util.chmod(
            self.instance.nssdb_dir,
            config.PKI_DEPLOYMENT_DEFAULT_SECURITY_DATABASE_PERMISSIONS)
        os.chmod(
            self.instance.nssdb_dir,
            pki.server.DEFAULT_DIR_MODE)

        # Always delete the temporary 'pfile'
        self.file.delete(pki_shared_pfile)

    def import_server_pkcs12(self):
        '''
        Import system certificates from PKCS #12 file.
        '''
        param = 'pki_server_pkcs12_path'
        pki_server_pkcs12_path = self.mdict.get(param)

        if not pki_server_pkcs12_path:
            # no PKCS #12 file to import
            return

        logger.info('Importing certs and keys from %s', pki_server_pkcs12_path)

        if not os.path.exists(pki_server_pkcs12_path):
            raise Exception('Invalid path in %s: %s' % (param, pki_server_pkcs12_path))

        pki_server_pkcs12_password = self.mdict['pki_server_pkcs12_password']
        if not pki_server_pkcs12_password:
            raise Exception('Missing pki_server_pkcs12_password property')

        pki_shared_pfile = os.path.join(self.instance.conf_dir, 'pfile')
        logger.info('Creating password file: %s', pki_shared_pfile)

        self.password.create_password_conf(
            pki_shared_pfile,
            self.mdict['pki_server_database_password'],
            pin_sans_token=True)

        self.file.modify(pki_shared_pfile)

        try:
            nssdb = pki.nssdb.NSSDatabase(
                directory=self.instance.nssdb_dir,
                password_file=pki_shared_pfile)

            try:
                nssdb.import_pkcs12(
                    pkcs12_file=pki_server_pkcs12_path,
                    pkcs12_password=pki_server_pkcs12_password)
            finally:
                nssdb.close()

            # update external CA file (if needed)
            external_certs_path = self.mdict['pki_server_external_certs_path']
            if not external_certs_path:
                return

            self.update_external_certs_conf(external_certs_path)

        finally:
            self.file.delete(pki_shared_pfile)

    def import_clone_pkcs12(self):
        '''
        Import CA certificates from PKCS #12 file for cloning.
        '''
        param = 'pki_clone_pkcs12_path'
        pki_clone_pkcs12_path = self.mdict.get(param)

        if not pki_clone_pkcs12_path:
            # no PKCS #12 file to import
            return

        logger.info('Importing certs and keys from %s', pki_clone_pkcs12_path)

        if not os.path.exists(pki_clone_pkcs12_path):
            raise Exception('Invalid path in %s: %s' % (param, pki_clone_pkcs12_path))

        pki_clone_pkcs12_password = self.mdict['pki_clone_pkcs12_password']
        if not pki_clone_pkcs12_password:
            raise Exception('Missing pki_clone_pkcs12_password property')

        pki_shared_pfile = os.path.join(self.instance.conf_dir, 'pfile')
        logger.info('Creating password file: %s', pki_shared_pfile)

        self.password.create_password_conf(
            pki_shared_pfile,
            self.mdict['pki_server_database_password'],
            pin_sans_token=True)

        self.file.modify(pki_shared_pfile)

        try:
            nssdb = pki.nssdb.NSSDatabase(
                directory=self.instance.nssdb_dir,
                password_file=pki_shared_pfile)

            try:
                # The PKCS12 class requires an NSS database to run. For simplicity
                # it uses the NSS database that has just been created.
                pkcs12 = pki.pkcs12.PKCS12(
                    path=pki_clone_pkcs12_path,
                    password=pki_clone_pkcs12_password,
                    nssdb=nssdb)

                try:
                    pkcs12.show_certs()
                finally:
                    pkcs12.close()

                # Import certificates
                nssdb.import_pkcs12(
                    pkcs12_file=pki_clone_pkcs12_path,
                    pkcs12_password=pki_clone_pkcs12_password)

                print('Certificates in %s:' % self.instance.nssdb_dir)
                nssdb.show_certs()

            finally:
                nssdb.close()

            # Export CA certificate to PEM file; same command as in
            # PKIServer.setup_cert_authentication().
            # openssl pkcs12 -in <p12_file_path> -out /tmp/auth.pem -nodes -nokeys

            pki_ca_crt_path = os.path.join(self.instance.nssdb_dir, 'ca.crt')

            cmd_export_ca = [
                'openssl', 'pkcs12',
                '-in', pki_clone_pkcs12_path,
                '-out', pki_ca_crt_path,
                '-nodes',
                '-nokeys',
                '-passin', 'pass:' + pki_clone_pkcs12_password
            ]

            res_ca = subprocess.check_output(
                cmd_export_ca,
                stderr=subprocess.STDOUT).decode('utf-8')

            logger.debug('Result of CA certificate export: %s', res_ca)

            # At this point, we're running as root. However, the subsystem
            # will eventually start up as non-root and will attempt to do a
            # migration. If we don't fix the permissions now, migration will
            # fail and subsystem won't start up.
            pki.util.chmod(pki_ca_crt_path, 0o644)
            pki.util.chown(
                pki_ca_crt_path,
                self.mdict['pki_uid'],
                self.mdict['pki_gid'])

        finally:
            self.file.delete(pki_shared_pfile)

    def install_cert_chain(self):

        param = 'pki_cert_chain_path'
        cert_chain_path = self.mdict.get(param)

        if not cert_chain_path:
            # no cert chain to import
            return

        if not os.path.exists(cert_chain_path):
            raise Exception('Certificate chain not found: %s' % cert_chain_path)

        logger.info('Importing cert chain from %s', cert_chain_path)

        destination = os.path.join(self.instance.nssdb_dir, 'ca.crt')

        if os.path.exists(destination):
            return

        # When we're passed a CA certificate file and we don't already
        # have a CA file for some reason, we need to copy the passed
        # file as the root CA certificate to establish trust in the
        # Python code. It doesn't import it into the NSS DB for Java
        # code, but so far we haven't had any issues with certificate
        # validation there. This is only usually necessary when
        # installing a non-CA subsystem on a fresh system.

        self.instance.copyfile(cert_chain_path, destination)

    def import_ds_ca_cert(self):

        if self.ds_url.scheme != 'ldaps':
            return

        pki_shared_pfile = os.path.join(self.instance.conf_dir, 'pfile')
        logger.info('Creating password file: %s', pki_shared_pfile)

        self.password.create_password_conf(
            pki_shared_pfile,
            self.mdict['pki_server_database_password'],
            pin_sans_token=True)

        self.file.modify(pki_shared_pfile)

        try:
            # Check to see if a directory server CA certificate
            # using the same nickname already exists
            #
            # NOTE:  ALWAYS use the software DB regardless of whether
            #        the instance will utilize 'softokn' or an HSM

            exists = self.certutil.verify_certificate_exists(
                path=self.instance.nssdb_dir,
                token=self.mdict['pki_self_signed_token'],
                nickname=self.mdict['pki_ds_secure_connection_ca_nickname'],
                password_file=pki_shared_pfile)

            if exists:
                return

            # Import the directory server CA certificate

            self.certutil.import_cert(
                self.mdict['pki_ds_secure_connection_ca_nickname'],
                self.mdict['pki_ds_secure_connection_ca_trustargs'],
                self.mdict['pki_ds_secure_connection_ca_pem_file'],
                password_file=pki_shared_pfile,
                path=self.instance.nssdb_dir,
                token=self.mdict['pki_self_signed_token'])

        finally:
            self.file.delete(pki_shared_pfile)

    def create_cs_cfg(self, subsystem):

        tmpdir = tempfile.mkdtemp()

        try:
            # Copy /usr/share/pki/<subsystem>/conf/CS.cfg
            # into temporary CS.cfg with param substitution

            source_cs_cfg = os.path.join(
                pki.server.PKIServer.SHARE_DIR,
                subsystem.name,
                'conf',
                'CS.cfg')

            tmp_cs_cfg = os.path.join(tmpdir, 'CS.cfg')

            self.instance.copyfile(
                source_cs_cfg,
                tmp_cs_cfg,
                params=self.mdict,
                force=True)

            # Merge temporary CS.cfg into /etc/pki/<instance>/<subsystem>/CS.cfg
            # to preserve params in existing CS.cfg

            pki.util.load_properties(tmp_cs_cfg, subsystem.config)
            self.instance.store_properties(subsystem.cs_conf, subsystem.config)

        finally:
            shutil.rmtree(tmpdir)

    def init_system_cert_params(self, subsystem):

        # Store system cert parameters in installation step to guarantee the
        # parameters exist during configuration step and to allow customization.

        certs = subsystem.find_system_certs()
        for cert in certs:

            # get CS.cfg tag and pkispawn tag
            config_tag = cert['id']
            deploy_tag = config_tag

            if config_tag == 'signing':  # for CA and OCSP
                deploy_tag = subsystem.name + '_signing'

            # store nickname and tokenname
            nickname = self.mdict['pki_%s_nickname' % deploy_tag]
            tokenname = self.mdict['pki_%s_token' % deploy_tag]

            if pki.nssdb.internal_token(tokenname):
                fullname = nickname
                tokenname = pki.nssdb.INTERNAL_TOKEN_NAME
            else:
                fullname = tokenname + ':' + nickname

            subsystem.config['preop.cert.%s.nickname' % config_tag] = nickname
            subsystem.config['%s.%s.nickname' % (subsystem.name, config_tag)] = nickname
            subsystem.config['%s.%s.tokenname' % (subsystem.name, config_tag)] = tokenname
            subsystem.config['%s.cert.%s.nickname' % (subsystem.name, config_tag)] = fullname

            # store subject DN
            subject_dn = self.mdict['pki_%s_subject_dn' % deploy_tag]
            subsystem.config['preop.cert.%s.dn' % config_tag] = subject_dn

            keyalgorithm = self.mdict['pki_%s_key_algorithm' % deploy_tag]
            subsystem.config['preop.cert.%s.keyalgorithm' % config_tag] = keyalgorithm

            signingalgorithm = self.mdict.get(
                'pki_%s_signing_algorithm' % deploy_tag, keyalgorithm)
            subsystem.config['preop.cert.%s.signingalgorithm' % config_tag] = signingalgorithm

            if subsystem.name == 'ca':
                if config_tag == 'signing':
                    subsystem.config['ca.signing.defaultSigningAlgorithm'] = signingalgorithm
                    subsystem.config['ca.crl.MasterCRL.signingAlgorithm'] = signingalgorithm

                elif config_tag == 'ocsp_signing':
                    subsystem.config['ca.ocsp_signing.defaultSigningAlgorithm'] = signingalgorithm

            elif subsystem.name == 'ocsp':
                if config_tag == 'signing':
                    subsystem.config['ocsp.signing.defaultSigningAlgorithm'] = signingalgorithm

            elif subsystem.name == 'kra':
                if config_tag == 'transport':
                    subsystem.config['kra.transportUnit.signingAlgorithm'] = signingalgorithm

            # TODO: move more system cert params here

        admin_dn = self.mdict['pki_admin_subject_dn']
        subsystem.config['preop.cert.admin.dn'] = admin_dn

        # If specified in the deployment parameter, add generic CA signing cert
        # extension parameters into the CS.cfg. Generic extension for other
        # system certs can be added directly into CS.cfg after before the
        # configuration step.

        if subsystem.type == 'CA':

            signing_nickname = subsystem.config['ca.signing.nickname']
            subsystem.config['ca.signing.certnickname'] = signing_nickname
            subsystem.config['ca.signing.cacertnickname'] = signing_nickname

            ocsp_signing_nickname = subsystem.config['ca.ocsp_signing.nickname']
            subsystem.config['ca.ocsp_signing.certnickname'] = ocsp_signing_nickname
            subsystem.config['ca.ocsp_signing.cacertnickname'] = ocsp_signing_nickname

            if self.configuration_file.add_req_ext:

                subsystem.config['preop.cert.signing.ext.oid'] = \
                    self.configuration_file.req_ext_oid
                subsystem.config['preop.cert.signing.ext.data'] = \
                    self.configuration_file.req_ext_data
                subsystem.config['preop.cert.signing.ext.critical'] = \
                    self.configuration_file.req_ext_critical.lower()

        if subsystem.type == 'KRA':

            storage_nickname = subsystem.config['kra.storage.nickname']
            storage_token = subsystem.config['kra.storage.tokenname']

            if pki.nssdb.internal_token(storage_token):
                subsystem.config['kra.storageUnit.nickName'] = storage_nickname
            else:
                subsystem.config['kra.storageUnit.hardware'] = storage_token
                subsystem.config['kra.storageUnit.nickName'] = \
                    storage_token + ':' + storage_nickname

            transport_nickname = subsystem.config['kra.transport.nickname']
            transport_token = subsystem.config['kra.transport.tokenname']

            if pki.nssdb.internal_token(transport_token):
                subsystem.config['kra.transportUnit.nickName'] = transport_nickname
            else:
                subsystem.config['kra.transportUnit.nickName'] = \
                    transport_token + ':' + transport_nickname

        if subsystem.type == 'OCSP':

            signing_nickname = subsystem.config['ocsp.signing.nickname']
            subsystem.config['ocsp.signing.certnickname'] = signing_nickname
            subsystem.config['ocsp.signing.cacertnickname'] = signing_nickname

        audit_nickname = subsystem.config['%s.audit_signing.nickname' % subsystem.name]
        audit_token = subsystem.config['%s.audit_signing.tokenname' % subsystem.name]

        if not pki.nssdb.internal_token(audit_token):
            audit_nickname = audit_token + ':' + audit_nickname

        subsystem.config['log.instance.SignedAudit.signedAuditCertNickname'] = audit_nickname

        san_inject = config.str2bool(self.mdict['pki_san_inject'])
        logger.info('Injecting SAN: %s', san_inject)

        san_for_server_cert = self.mdict.get('pki_san_for_server_cert')
        logger.info('SSL server cert SAN: %s', san_for_server_cert)

        if san_inject and san_for_server_cert:
            subsystem.config['service.injectSAN'] = 'true'
            subsystem.config['service.sslserver.san'] = san_for_server_cert

    def init_client_nssdb(self):

        # Place 'slightly' less restrictive permissions on
        # the top-level client directory ONLY

        self.directory.create(
            self.mdict['pki_client_subsystem_dir'],
            uid=0,
            gid=0,
            perms=config.PKI_DEPLOYMENT_DEFAULT_CLIENT_DIR_PERMISSIONS)

        # Since 'certutil' does NOT strip the 'token=' portion of
        # the 'token=password' entries, create a client password file
        # which ONLY contains the 'password' for the purposes of
        # allowing 'certutil' to generate the security databases

        logger.info('Creating password file: %s', self.mdict['pki_client_password_conf'])

        self.password.create_password_conf(
            self.mdict['pki_client_password_conf'],
            self.mdict['pki_client_database_password'],
            pin_sans_token=True)

        self.file.modify(
            self.mdict['pki_client_password_conf'],
            uid=0,
            gid=0)

        # Similarly, create a simple password file containing the
        # PKCS #12 password used when exporting the 'Admin Certificate'
        # into a PKCS #12 file

        self.password.create_client_pkcs12_password_conf(
            self.mdict['pki_client_pkcs12_password_conf'])

        self.file.modify(self.mdict['pki_client_pkcs12_password_conf'])

        pki.util.makedirs(self.mdict['pki_client_database_dir'], exist_ok=True)

        nssdb = pki.nssdb.NSSDatabase(
            directory=self.mdict['pki_client_database_dir'],
            password_file=self.mdict['pki_client_password_conf'],
            user=self.mdict['pki_user'],
            group=self.mdict['pki_group'])

        try:
            if not nssdb.exists():
                nssdb.create()
        finally:
            nssdb.close()

    def verify_subsystem_exists(self):

        subsystem_path = os.path.join(
            self.instance.base_dir,
            self.mdict['pki_subsystem_type'])

        if os.path.exists(subsystem_path):
            return

        logger.error(
            log.PKI_SUBSYSTEM_DOES_NOT_EXIST_2,
            self.subsystem_type,
            self.mdict['pki_instance_name'])

        raise Exception(
            log.PKI_SUBSYSTEM_DOES_NOT_EXIST_2 % (
                self.subsystem_type,
                self.mdict['pki_instance_name']))

    def init_subsystem(self, subsystem):

        external = self.configuration_file.external
        standalone = self.configuration_file.standalone
        subordinate = self.configuration_file.subordinate
        clone = self.configuration_file.clone

        if config.str2bool(self.mdict['pki_enable_proxy']):

            logger.info('Enabling HTTP proxy')

            subsystem.config['proxy.securePort'] = self.mdict['pki_proxy_https_port']
            subsystem.config['proxy.unsecurePort'] = self.mdict['pki_proxy_http_port']

        certs = subsystem.find_system_certs()
        for cert in certs:

            # get CS.cfg tag and pkispawn tag
            config_tag = cert['id']
            deploy_tag = config_tag

            if config_tag == 'signing':  # for CA and OCSP
                deploy_tag = subsystem.name + '_signing'

            key_type = self.mdict['pki_%s_key_type' % deploy_tag].upper()

            if key_type == 'ECC':
                key_type = 'EC'

            if key_type not in ['RSA', 'EC']:
                raise Exception('Unsupported key type: %s' % key_type)

            subsystem.config['preop.cert.%s.keytype' % config_tag] = key_type

        # configure SSL server cert
        if subsystem.type == 'CA' and clone or subsystem.type != 'CA':

            subsystem.config['preop.cert.sslserver.type'] = 'remote'
            key_type = subsystem.config['preop.cert.sslserver.keytype']

            if key_type == 'RSA':
                subsystem.config['preop.cert.sslserver.profile'] = 'caInternalAuthServerCert'

            elif key_type == 'EC':
                subsystem.config['preop.cert.sslserver.profile'] = 'caECInternalAuthServerCert'

        # configure subsystem cert
        if self.mdict['pki_security_domain_type'] == 'new':

            subsystem.config['preop.cert.subsystem.type'] = 'local'
            subsystem.config['preop.cert.subsystem.profile'] = 'subsystemCert.profile'

        else:  # self.mdict['pki_security_domain_type'] == 'existing':

            subsystem.config['preop.cert.subsystem.type'] = 'remote'
            key_type = subsystem.config['preop.cert.subsystem.keytype']

            if key_type == 'RSA':
                subsystem.config['preop.cert.subsystem.profile'] = 'caInternalAuthSubsystemCert'

            elif key_type == 'EC':
                subsystem.config['preop.cert.subsystem.profile'] = 'caECInternalAuthSubsystemCert'

        if external or standalone:

            # This is needed by IPA to detect step 1 completion.
            # See is_step_one_done() in ipaserver/install/cainstance.py.

            subsystem.config['preop.ca.type'] = 'otherca'

        elif subsystem.type != 'CA' or subordinate:

            subsystem.config['preop.ca.type'] = 'sdca'

        # configure CA
        if subsystem.type == 'CA':

            if subordinate:
                subsystem.config['preop.cert.signing.type'] = 'remote'
                subsystem.config['preop.cert.signing.profile'] = 'caInstallCACert'

            if config.str2bool(self.mdict['pki_profiles_in_ldap']):
                index = subsystem.get_subsystem_index('profile')
                subsystem.config['subsystem.%d.class' % index] = \
                    'com.netscape.cmscore.profile.LDAPProfileSubsystem'

        # configure OCSP
        if subsystem.type == 'OCSP':
            if clone:
                subsystem.config['ocsp.store.defStore.refreshInSec'] = '14400'

        # configure TPS
        if subsystem.type == 'TPS':
            subsystem.config['auths.instance.ldap1.ldap.basedn'] = \
                self.mdict['pki_authdb_basedn']
            subsystem.config['auths.instance.ldap1.ldap.ldapconn.host'] = \
                self.mdict['pki_authdb_hostname']
            subsystem.config['auths.instance.ldap1.ldap.ldapconn.port'] = \
                self.mdict['pki_authdb_port']
            subsystem.config['auths.instance.ldap1.ldap.ldapconn.secureConn'] = \
                self.mdict['pki_authdb_secure_conn']

    def configure_ca(self, subsystem):

        if config.str2bool(self.mdict['pki_use_oaep_rsa_keywrap']):
            subsystem.config['keyWrap.useOAEP'] = 'true'

        request_id_generator = self.mdict['pki_request_id_generator']

        if request_id_generator == 'random':
            subsystem.config['dbs.request.id.generator'] = request_id_generator
            subsystem.config['dbs.request.id.length'] = self.mdict['pki_request_id_length']

        else:  # legacy
            subsystem.config['dbs.beginRequestNumber'] = '1'
            subsystem.config['dbs.endRequestNumber'] = '10000000'
            subsystem.config['dbs.requestIncrement'] = '10000000'
            subsystem.config['dbs.requestLowWaterMark'] = '2000000'
            subsystem.config['dbs.requestCloneTransferNumber'] = '10000'
            subsystem.config['dbs.requestRangeDN'] = 'ou=requests,ou=ranges'

            request_number_range_start = self.mdict.get('pki_request_number_range_start')
            if request_number_range_start:
                subsystem.config['dbs.beginRequestNumber'] = request_number_range_start

            request_number_range_end = self.mdict.get('pki_request_number_range_end')
            if request_number_range_end:
                subsystem.config['dbs.endRequestNumber'] = request_number_range_end

        cert_id_generator = self.mdict['pki_cert_id_generator']

        if cert_id_generator == 'random':
            subsystem.config['dbs.cert.id.generator'] = cert_id_generator
            subsystem.config['dbs.cert.id.length'] = self.mdict['pki_cert_id_length']

        else:  # legacy
            subsystem.config['dbs.beginSerialNumber'] = '1'
            subsystem.config['dbs.endSerialNumber'] = '10000000'
            subsystem.config['dbs.serialIncrement'] = '10000000'
            subsystem.config['dbs.serialLowWaterMark'] = '2000000'
            subsystem.config['dbs.serialCloneTransferNumber'] = '10000'
            subsystem.config['dbs.serialRangeDN'] = 'ou=certificateRepository,ou=ranges'
            if config.str2bool(self.mdict['pki_random_serial_numbers_enable']):
                subsystem.config['dbs.enableRandomSerialNumbers'] = 'true'
            subsystem.config['dbs.randomSerialNumberCounter'] = '0'

            serial_number_range_start = self.mdict.get('pki_serial_number_range_start')
            if serial_number_range_start:
                subsystem.config['dbs.beginSerialNumber'] = serial_number_range_start

            serial_number_range_end = self.mdict.get('pki_serial_number_range_end')
            if serial_number_range_end:
                subsystem.config['dbs.endSerialNumber'] = serial_number_range_end

        replica_number_range_start = self.mdict.get('pki_replica_number_range_start')
        if replica_number_range_start:
            subsystem.config['dbs.beginReplicaNumber'] = replica_number_range_start

        replica_number_range_end = self.mdict.get('pki_replica_number_range_end')
        if replica_number_range_end:
            subsystem.config['dbs.endReplicaNumber'] = replica_number_range_end

        ocsp_uri = self.mdict.get('pki_default_ocsp_uri')
        if ocsp_uri:
            subsystem.config['ca.defaultOcspUri'] = ocsp_uri

    def configure_kra(self, subsystem):

        if config.str2bool(self.mdict['pki_use_oaep_rsa_keywrap']):
            subsystem.config['keyWrap.useOAEP'] = 'true'

        request_id_generator = self.mdict['pki_request_id_generator']

        if request_id_generator == 'random':
            subsystem.config['dbs.request.id.generator'] = request_id_generator
            subsystem.config['dbs.request.id.length'] = self.mdict['pki_request_id_length']

        else:  # legacy
            subsystem.config['dbs.beginRequestNumber'] = '1'
            subsystem.config['dbs.endRequestNumber'] = '10000000'
            subsystem.config['dbs.requestIncrement'] = '10000000'
            subsystem.config['dbs.requestLowWaterMark'] = '2000000'
            subsystem.config['dbs.requestCloneTransferNumber'] = '10000'
            subsystem.config['dbs.requestRangeDN'] = 'ou=requests,ou=ranges'

        key_id_generator = self.mdict['pki_key_id_generator']

        if key_id_generator == 'random':
            subsystem.config['dbs.key.id.generator'] = key_id_generator
            subsystem.config['dbs.key.id.length'] = self.mdict['pki_key_id_length']

        else:  # legacy
            subsystem.config['dbs.beginSerialNumber'] = '1'
            subsystem.config['dbs.endSerialNumber'] = '10000000'
            subsystem.config['dbs.serialIncrement'] = '10000000'
            subsystem.config['dbs.serialLowWaterMark'] = '2000000'
            subsystem.config['dbs.serialCloneTransferNumber'] = '10000'
            subsystem.config['dbs.serialRangeDN'] = 'ou=keyRepository,ou=ranges'

        if config.str2bool(self.mdict['pki_kra_ephemeral_requests']):
            logger.debug('Setting ephemeral requests to true')
            subsystem.config['kra.ephemeralRequests'] = 'true'

    def configure_tps(self, subsystem):

        baseDN = subsystem.config['internaldb.basedn']

        subsystem.config['tokendb.activityBaseDN'] = 'ou=Activities,' + baseDN
        subsystem.config['tokendb.baseDN'] = 'ou=Tokens,' + baseDN
        subsystem.config['tokendb.certBaseDN'] = 'ou=Certificates,' + baseDN
        subsystem.config['tokendb.userBaseDN'] = baseDN

        nickname = subsystem.config['tps.subsystem.nickname']
        token = subsystem.config['tps.subsystem.tokenname']

        if pki.nssdb.internal_token(token):
            fullname = nickname
        else:
            fullname = token + ':' + nickname

        timestamp = round(time.time() * 1000 * 1000)

        logger.info('Configuring CA connector')

        ca_url = urllib.parse.urlparse(self.mdict['pki_ca_uri'])
        subsystem.config['tps.connector.ca1.enable'] = 'true'
        subsystem.config['tps.connector.ca1.host'] = ca_url.hostname
        subsystem.config['tps.connector.ca1.port'] = str(ca_url.port)
        subsystem.config['tps.connector.ca1.minHttpConns'] = '1'
        subsystem.config['tps.connector.ca1.maxHttpConns'] = '15'
        subsystem.config['tps.connector.ca1.nickName'] = fullname
        subsystem.config['tps.connector.ca1.timeout'] = '30'
        subsystem.config['tps.connector.ca1.uri.enrollment'] = \
            '/ca/ee/ca/profileSubmitSSLClient'
        subsystem.config['tps.connector.ca1.uri.getcert'] = \
            '/ca/ee/ca/displayBySerial'
        subsystem.config['tps.connector.ca1.uri.renewal'] = \
            '/ca/ee/ca/profileSubmitSSLClient'
        subsystem.config['tps.connector.ca1.uri.revoke'] = \
            '/ca/ee/subsystem/ca/doRevoke'
        subsystem.config['tps.connector.ca1.uri.unrevoke'] = \
            '/ca/ee/subsystem/ca/doUnrevoke'

        subsystem.config['config.Subsystem_Connections.ca1.state'] = 'Enabled'
        subsystem.config['config.Subsystem_Connections.ca1.timestamp'] = timestamp

        logger.info('Configuring TKS connector')

        tks_url = urllib.parse.urlparse(self.mdict['pki_tks_uri'])
        subsystem.config['tps.connector.tks1.enable'] = 'true'
        subsystem.config['tps.connector.tks1.host'] = tks_url.hostname
        subsystem.config['tps.connector.tks1.port'] = str(tks_url.port)
        subsystem.config['tps.connector.tks1.minHttpConns'] = '1'
        subsystem.config['tps.connector.tks1.maxHttpConns'] = '15'
        subsystem.config['tps.connector.tks1.nickName'] = fullname
        subsystem.config['tps.connector.tks1.timeout'] = '30'
        subsystem.config['tps.connector.tks1.generateHostChallenge'] = 'true'
        subsystem.config['tps.connector.tks1.serverKeygen'] = 'false'
        subsystem.config['tps.connector.tks1.keySet'] = 'defKeySet'
        subsystem.config['tps.connector.tks1.tksSharedSymKeyName'] = 'sharedSecret'
        subsystem.config['tps.connector.tks1.uri.computeRandomData'] = \
            '/tks/agent/tks/computeRandomData'
        subsystem.config['tps.connector.tks1.uri.computeSessionKey'] = \
            '/tks/agent/tks/computeSessionKey'
        subsystem.config['tps.connector.tks1.uri.createKeySetData'] = \
            '/tks/agent/tks/createKeySetData'
        subsystem.config['tps.connector.tks1.uri.encryptData'] = \
            '/tks/agent/tks/encryptData'

        subsystem.config['config.Subsystem_Connections.tks1.state'] = 'Enabled'
        subsystem.config['config.Subsystem_Connections.tks1.timestamp'] = timestamp

        subsystem.config['target.Subsystem_Connections.list'] = 'ca1,tks1'

        keygen = config.str2bool(self.mdict['pki_enable_server_side_keygen'])

        if keygen:
            logger.info('Configuring KRA connector')

            kra_url = urllib.parse.urlparse(self.mdict['pki_kra_uri'])
            subsystem.config['tps.connector.kra1.enable'] = 'true'
            subsystem.config['tps.connector.kra1.host'] = kra_url.hostname
            subsystem.config['tps.connector.kra1.port'] = str(kra_url.port)
            subsystem.config['tps.connector.kra1.minHttpConns'] = '1'
            subsystem.config['tps.connector.kra1.maxHttpConns'] = '15'
            subsystem.config['tps.connector.kra1.nickName'] = fullname
            subsystem.config['tps.connector.kra1.timeout'] = '30'
            subsystem.config['tps.connector.kra1.uri.GenerateKeyPair'] = \
                '/kra/agent/kra/GenerateKeyPair'
            subsystem.config['tps.connector.kra1.uri.TokenKeyRecovery'] = \
                '/kra/agent/kra/TokenKeyRecovery'

            subsystem.config['config.Subsystem_Connections.kra1.state'] = 'Enabled'
            subsystem.config['config.Subsystem_Connections.kra1.timestamp'] = timestamp

            subsystem.config['target.Subsystem_Connections.list'] = 'ca1,tks1,kra1'

            subsystem.config['tps.connector.tks1.serverKeygen'] = 'true'

            # TODO: see if there are other profiles need to be configured
            subsystem.config[
                'op.enroll.userKey.keyGen.encryption.serverKeygen.enable'] = 'true'
            subsystem.config[
                'op.enroll.userKeyTemporary.keyGen.encryption.serverKeygen.enable'] = 'true'
            subsystem.config[
                'op.enroll.soKey.keyGen.encryption.serverKeygen.enable'] = 'true'
            subsystem.config[
                'op.enroll.soKeyTemporary.keyGen.encryption.serverKeygen.enable'] = 'true'

        else:
            # TODO: see if there are other profiles need to be configured
            subsystem.config[
                'op.enroll.userKey.keyGen.encryption.serverKeygen.enable'] = 'false'
            subsystem.config[
                'op.enroll.userKeyTemporary.keyGen.encryption.serverKeygen.enable'] = 'false'
            subsystem.config[
                'op.enroll.userKey.keyGen.encryption.recovery.destroyed.scheme'
            ] = 'GenerateNewKey'
            subsystem.config[
                'op.enroll.userKeyTemporary.keyGen.encryption.recovery.onHold.scheme'
            ] = 'GenerateNewKey'
            subsystem.config[
                'op.enroll.soKey.keyGen.encryption.serverKeygen.enable'] = 'false'
            subsystem.config[
                'op.enroll.soKeyTemporary.keyGen.encryption.serverKeygen.enable'] = 'false'
            subsystem.config[
                'op.enroll.soKey.keyGen.encryption.recovery.destroyed.scheme'
            ] = 'GenerateNewKey'
            subsystem.config[
                'op.enroll.soKeyTemporary.keyGen.encryption.recovery.onHold.scheme'
            ] = 'GenerateNewKey'

    def configure_subsystem(self, subsystem):

        # configure internal database
        if self.ds_url.scheme == 'ldaps':
            subsystem.config['internaldb.ldapconn.secureConn'] = 'true'

        elif self.ds_url.scheme == 'ldap':
            subsystem.config['internaldb.ldapconn.secureConn'] = 'false'

        else:
            raise Exception('Unsupported protocol: %s' % self.ds_url.scheme)

        subsystem.config['internaldb.ldapconn.host'] = self.ds_url.hostname
        subsystem.config['internaldb.ldapconn.port'] = self.ds_url.port

        subsystem.config['internaldb.ldapauth.bindDN'] = self.mdict['pki_ds_bind_dn']
        subsystem.config['internaldb.basedn'] = self.mdict['pki_ds_base_dn']
        subsystem.config['internaldb.database'] = self.mdict['pki_ds_database']

        if subsystem.type == 'CA':
            self.configure_ca(subsystem)

        if subsystem.type == 'KRA':
            self.configure_kra(subsystem)

        if subsystem.type == 'TPS':
            self.configure_tps(subsystem)

    def request_ranges(self, subsystem):

        if subsystem.type not in ['CA', 'KRA']:
            return

        master_url = self.mdict['pki_clone_uri']

        logger.info('Requesting ranges from %s master', subsystem.type)
        subsystem.request_ranges(master_url, session_id=self.install_token.token)

    def import_master_config(self, subsystem):

        master_url = self.mdict['pki_clone_uri']

        logger.info('Retrieving config params from %s master', subsystem.type)

        names = []
        substores = []

        if config.str2bool(self.mdict['pki_ds_setup']):

            names.extend([
                'internaldb.ldapauth.password',
                'internaldb.replication.password'
            ])

            substores.extend([
                'internaldb',
                'internaldb.ldapauth',
                'internaldb.ldapconn'
            ])

        tags = subsystem.config['preop.cert.list'].split(',')
        for tag in tags:
            if tag == 'sslserver':
                continue

            # check CSR in CS.cfg
            cert_id = self.get_cert_id(subsystem, tag)
            param = 'pki_%s_csr_path' % cert_id

            if self.mdict.get(param):
                # CSR already exists
                continue

            # CSR doesn't provided, import from master
            names.append('%s.%s.certreq' % (subsystem.name, tag))

        if subsystem.name == 'ca':
            substores.append('ca.connector.KRA')
        else:
            names.append('cloning.ca.type')

        master_config = subsystem.retrieve_config(
            master_url,
            names,
            substores,
            session_id=self.install_token.token)

        master_properties = master_config['Properties']

        if config.str2bool(self.mdict['pki_ds_setup']):

            logger.info('Validating %s database config params', subsystem.type)

            master_hostname = master_properties['internaldb.ldapconn.host']
            master_port = master_properties['internaldb.ldapconn.port']

            replica_hostname = subsystem.config['internaldb.ldapconn.host']
            replica_port = subsystem.config['internaldb.ldapconn.port']

            if master_hostname == replica_hostname and master_port == replica_port:
                raise Exception('%s database already set up' % subsystem.type)

        logger.info('Importing %s master config params', subsystem.type)

        requests = {key: val for key, val in master_properties.items() if key.endswith('.certreq')}
        for key, value in requests.items():
            self.store_master_cert_request(subsystem, key, value)
            master_properties.pop(key)

        subsystem.import_master_config(master_properties)
        return master_config

    def store_master_cert_request(self, subsystem, key, csr):

        csr_pem = pki.nssdb.convert_csr(csr, 'base64', 'pem')
        tag = key.split('.')[1]
        csr_path = subsystem.csr_file(tag)

        self.file.create(csr_path)
        with open(csr_path, 'w', encoding='utf-8') as f:
            f.write(csr_pem)

    def setup_database(self, subsystem, master_config):

        if config.str2bool(self.mdict['pki_ds_remove_data']):

            if config.str2bool(self.mdict['pki_ds_create_new_db']):
                logger.info('Removing existing database')
                subsystem.remove_database(force=True)

            elif not config.str2bool(self.mdict['pki_clone']) or \
                    config.str2bool(self.mdict['pki_clone_setup_replication']):
                logger.info('Emptying existing database')
                subsystem.empty_database(force=True)

            else:
                logger.info('Reusing replicated database')

        if config.str2bool(self.mdict['pki_ds_create_new_db']):
            logger.info('Creating database')
            subsystem.create_database()

        logger.info('Initializing database')

        # In most cases, we want to replicate the schema and therefore not add it here.
        # We provide this option though in case the clone already has schema
        # and we want to replicate back to the master.

        # On the other hand, if we are not setting up replication,
        # then we are assuming that replication is already taken care of,
        # and schema has already been replicated.

        skip_schema = config.str2bool(self.mdict['pki_clone']) and \
            config.str2bool(self.mdict['pki_clone_setup_replication']) and \
            config.str2bool(self.mdict['pki_clone_replicate_schema'])

        # When cloning a subsystem without setting up the replication agreements,
        # the database is a subtree of an existing tree and is already replicated,
        # so there is no need to set up the base entry.

        skip_base = not config.str2bool(self.mdict['pki_ds_create_new_db']) and \
            config.str2bool(self.mdict['pki_clone']) and \
            not config.str2bool(self.mdict['pki_clone_setup_replication'])

        skip_containers = config.str2bool(self.mdict['pki_clone'])

        subsystem.init_database(
            skip_schema=skip_schema,
            skip_base=skip_base,
            skip_containers=skip_containers)

        if config.str2bool(self.mdict['pki_clone']) and \
                config.str2bool(self.mdict['pki_clone_setup_replication']):
            self.setup_replication(subsystem, master_config)

        # For security a PKI subsystem can be configured to use a database user
        # that only has a limited access to the database (instead of cn=Directory
        # Manager that has a full access to the database).
        #
        # The default database user is uid=pkidbuser,ou=people,<subsystem base DN>.
        # However, if the subsystem is configured to share the database with another
        # subsystem (pki_share_db=True), it can also be configured to use the same
        # database user (pki_share_dbuser_dn).

        if config.str2bool(self.mdict['pki_share_db']):
            dbuser = self.mdict['pki_share_dbuser_dn']
        else:
            dbuser = 'uid=pkidbuser,ou=people,' + self.mdict['pki_ds_base_dn']

        subsystem.grant_database_access(dbuser)

        # Always create search and VLV indexes since they will not be replicated
        subsystem.add_indexes()

        # If the database is already replicated but not yet indexed, rebuild the indexes
        if config.str2bool(self.mdict['pki_clone']) and \
                not config.str2bool(self.mdict['pki_clone_setup_replication']) and \
                config.str2bool(self.mdict['pki_clone_reindex_data']):
            subsystem.rebuild_indexes()

        subsystem.add_vlv()
        subsystem.reindex_vlv()

    def setup_replication(self, subsystem, master_config):

        logger.info('Setting up replication')

        master_replication_port = self.mdict['pki_clone_replication_master_port']
        logger.info('- master replication port: %s', master_replication_port)

        replica_replication_port = self.mdict['pki_clone_replication_clone_port']
        logger.info('- replica replication port: %s', replica_replication_port)

        ds_port = subsystem.config['internaldb.ldapconn.port']
        logger.info('- internaldb.ldapconn.port: %s', ds_port)

        secure_conn = subsystem.config['internaldb.ldapconn.secureConn']
        logger.info('- internaldb.ldapconn.secureConn: %s', secure_conn)

        if replica_replication_port == ds_port and secure_conn == 'true':
            replication_security = 'SSL'

        else:
            replication_security = self.mdict['pki_clone_replication_security']
            if not replication_security:
                replication_security = 'None'

        logger.info('- replication security: %s', replication_security)

        # get master database config

        master_ldap_config = {}
        for name in master_config['Properties']:

            match = re.match(r'internaldb\.(.*)$', name)

            if not match:
                continue

            new_name = match.group(1)  # strip internaldb prefix

            if new_name == 'replication.password':  # unused
                continue

            elif new_name == 'ldapauth.bindPWPrompt':  # unused
                continue

            elif new_name.startswith('_'):  # ignore comments
                continue

            elif new_name == 'ldapauth.password':  # rename
                new_name = 'ldapauth.bindPassword'

            value = master_config['Properties'][name]

            master_ldap_config[new_name] = value

        # get replica database config

        replica_ldap_config = {}
        for name in subsystem.config:

            match = re.match(r'internaldb\.(.*)$', name)

            if not match:
                continue

            new_name = match.group(1)  # strip internaldb prefix

            if new_name.startswith('_'):  # ignore comments
                continue

            elif new_name == 'ldapauth.bindPWPrompt':  # replace
                new_name = 'ldapauth.bindPassword'
                value = self.instance.get_password('internaldb')

            else:
                value = subsystem.config[name]

            replica_ldap_config[new_name] = value

        hostname = self.mdict['pki_hostname']
        master_agreement_name = 'masterAgreement1-%s-%s' % (hostname, self.instance.name)
        replica_agreement_name = 'cloneAgreement1-%s-%s' % (hostname, self.instance.name)

        master_hostname = master_ldap_config['ldapconn.host']
        if not master_replication_port:
            master_replication_port = master_ldap_config['ldapconn.port']
        master_url = 'ldap://%s:%s' % (master_hostname, master_replication_port)

        master_bind_dn = 'cn=Replication Manager %s,ou=csusers,cn=config' % \
            master_agreement_name
        master_bind_password = master_config['Properties']['internaldb.replication.password']

        replica_hostname = replica_ldap_config['ldapconn.host']
        if not replica_replication_port:
            replica_replication_port = ds_port
        replica_url = 'ldap://%s:%s' % (replica_hostname, replica_replication_port)

        replica_bind_dn = 'cn=Replication Manager %s,ou=csusers,cn=config' % \
            replica_agreement_name
        replica_bind_password = self.instance.get_password('replicationdb')

        logger.info('Enable replication on master')

        # TODO: provide param to specify the replica ID for the master
        subsystem.enable_replication(
            master_ldap_config,
            master_bind_dn,
            master_bind_password,
            None)

        logger.info('Enable replication on replica')

        # TODO: provide param to specify the replica ID for the replica
        subsystem.enable_replication(
            replica_ldap_config,
            replica_bind_dn,
            replica_bind_password,
            None)

        logger.info('Adding master replication agreement')
        logger.info('- replica URL: %s', replica_url)

        subsystem.add_replication_agreement(
            master_agreement_name,
            master_ldap_config,
            replica_url,
            replica_bind_dn,
            replica_bind_password,
            replication_security)

        logger.info('Adding replica replication agreement')
        logger.info('- master URL: %s', master_url)

        subsystem.add_replication_agreement(
            replica_agreement_name,
            replica_ldap_config,
            master_url,
            master_bind_dn,
            master_bind_password,
            replication_security)

        logger.info('Initializing replication agreement')

        subsystem.init_replication_agreement(
            master_agreement_name,
            master_ldap_config)

    def is_using_legacy_id_generator(self, subsystem):

        if subsystem.type in ['CA', 'KRA']:

            request_id_generator = subsystem.config.get('dbs.request.id.generator', 'legacy')
            logger.info('Request ID generator: %s', request_id_generator)

            if request_id_generator == 'legacy':
                return True

        if subsystem.type == 'CA':

            cert_id_generator = subsystem.config.get('dbs.cert.id.generator', 'legacy')
            logger.info('Certificate ID generator: %s', cert_id_generator)

            if cert_id_generator == 'legacy':
                return True

        elif subsystem.type == 'KRA':

            key_id_generator = subsystem.config.get('dbs.key.id.generator', 'legacy')
            logger.info('Key ID generator: %s', key_id_generator)

            if key_id_generator == 'legacy':
                return True

        return False

    def get_cert_id(self, subsystem, tag):

        if tag == 'signing':
            return '%s_%s' % (subsystem.name, tag)
        else:
            return tag

    def generate_ca_signing_request(self, subsystem):

        csr_path = self.mdict.get('pki_ca_signing_csr_path')
        if not csr_path:
            return

        basic_constraints_ext = {
            'ca': True,
            'path_length': None,
            'critical': True
        }

        key_usage_ext = {
            'digitalSignature': True,
            'nonRepudiation': True,
            'certSigning': True,
            'crlSigning': True,
            'critical': True
        }

        # if specified, add generic CSR extension
        generic_exts = None

        if 'preop.cert.signing.ext.oid' in subsystem.config and \
           'preop.cert.signing.ext.data' in subsystem.config:

            data = subsystem.config['preop.cert.signing.ext.data']
            critical = subsystem.config['preop.cert.signing.ext.critical']

            generic_ext = {
                'oid': subsystem.config['preop.cert.signing.ext.oid'],
                'data': binascii.unhexlify(data),
                'critical': config.str2bool(critical)
            }

            generic_exts = [generic_ext]

        tag = 'signing'
        cert = subsystem.get_subsystem_cert(tag)
        token = pki.nssdb.normalize_token(cert['token'])

        if not token:
            token = self.mdict['pki_token_name']

        nssdb = self.instance.open_nssdb(token)

        try:
            self.generate_csr(
                nssdb,
                subsystem,
                tag,
                csr_path,
                basic_constraints_ext=basic_constraints_ext,
                key_usage_ext=key_usage_ext,
                generic_exts=generic_exts,
                subject_key_id=self.configuration_file.req_ski,
            )

        finally:
            nssdb.close()

    def generate_kra_storage_request(self, subsystem):

        csr_path = self.mdict.get('pki_storage_csr_path')
        if not csr_path:
            return

        key_usage_ext = {
            'digitalSignature': True,
            'nonRepudiation': True,
            'keyEncipherment': True,
            'dataEncipherment': True,
            'critical': True
        }

        extended_key_usage_ext = {
            'clientAuth': True
        }

        tag = 'storage'
        cert = subsystem.get_subsystem_cert(tag)
        token = pki.nssdb.normalize_token(cert['token'])

        if not token:
            token = self.mdict['pki_token_name']

        nssdb = self.instance.open_nssdb(token)

        try:
            self.generate_csr(
                nssdb,
                subsystem,
                tag,
                csr_path,
                key_usage_ext=key_usage_ext,
                extended_key_usage_ext=extended_key_usage_ext
            )

        finally:
            nssdb.close()

    def generate_kra_transport_request(self, subsystem):

        csr_path = self.mdict.get('pki_transport_csr_path')
        if not csr_path:
            return

        key_usage_ext = {
            'digitalSignature': True,
            'nonRepudiation': True,
            'keyEncipherment': True,
            'dataEncipherment': True,
            'critical': True
        }

        extended_key_usage_ext = {
            'clientAuth': True
        }

        tag = 'transport'
        cert = subsystem.get_subsystem_cert(tag)
        token = pki.nssdb.normalize_token(cert['token'])

        if not token:
            token = self.mdict['pki_token_name']

        nssdb = self.instance.open_nssdb(token)

        try:
            self.generate_csr(
                nssdb,
                subsystem,
                tag,
                csr_path,
                key_usage_ext=key_usage_ext,
                extended_key_usage_ext=extended_key_usage_ext
            )

        finally:
            nssdb.close()

    def generate_ocsp_signing_request(self, subsystem):

        csr_path = self.mdict.get('pki_ocsp_signing_csr_path')
        if not csr_path:
            return

        tag = 'signing'
        cert = subsystem.get_subsystem_cert(tag)
        token = pki.nssdb.normalize_token(cert['token'])

        if not token:
            token = self.mdict['pki_token_name']

        nssdb = self.instance.open_nssdb(token)

        try:
            self.generate_csr(
                nssdb,
                subsystem,
                tag,
                csr_path
            )

        finally:
            nssdb.close()

    def generate_sslserver_request(self, subsystem):

        csr_path = self.mdict.get('pki_sslserver_csr_path')
        if not csr_path:
            return

        key_usage_ext = {
            'digitalSignature': True,
            'nonRepudiation': True,
            'keyEncipherment': True,
            'dataEncipherment': True,
            'critical': True
        }

        extended_key_usage_ext = {
            'serverAuth': True
        }

        tag = 'sslserver'
        cert = subsystem.get_subsystem_cert(tag)
        token = pki.nssdb.normalize_token(cert['token'])

        if not token:
            token = self.mdict['pki_token_name']

        nssdb = self.instance.open_nssdb(token)

        try:
            self.generate_csr(
                nssdb,
                subsystem,
                tag,
                csr_path,
                key_usage_ext=key_usage_ext,
                extended_key_usage_ext=extended_key_usage_ext
            )

        finally:
            nssdb.close()

    def generate_subsystem_request(self, subsystem):

        csr_path = self.mdict.get('pki_subsystem_csr_path')
        if not csr_path:
            return

        key_usage_ext = {
            'digitalSignature': True,
            'nonRepudiation': True,
            'keyEncipherment': True,
            'dataEncipherment': True,
            'critical': True
        }

        extended_key_usage_ext = {
            'serverAuth': True,
            'clientAuth': True
        }

        tag = 'subsystem'
        cert = subsystem.get_subsystem_cert(tag)
        token = pki.nssdb.normalize_token(cert['token'])

        if not token:
            token = self.mdict['pki_token_name']

        nssdb = self.instance.open_nssdb(token)

        try:
            self.generate_csr(
                nssdb,
                subsystem,
                tag,
                csr_path,
                key_usage_ext=key_usage_ext,
                extended_key_usage_ext=extended_key_usage_ext
            )

        finally:
            nssdb.close()

    def generate_audit_signing_request(self, subsystem):

        csr_path = self.mdict.get('pki_audit_signing_csr_path')
        if not csr_path:
            return

        key_usage_ext = {
            'digitalSignature': True,
            'nonRepudiation': True,
            'critical': True
        }

        tag = 'audit_signing'
        cert = subsystem.get_subsystem_cert(tag)
        token = pki.nssdb.normalize_token(cert['token'])

        if not token:
            token = self.mdict['pki_token_name']

        nssdb = self.instance.open_nssdb(token)

        try:
            self.generate_csr(
                nssdb,
                subsystem,
                tag,
                csr_path,
                key_usage_ext=key_usage_ext
            )

        finally:
            nssdb.close()

    def generate_admin_request(self, subsystem):

        csr_path = self.mdict.get('pki_admin_csr_path')
        if not csr_path:
            return

        client_nssdb = pki.nssdb.NSSDatabase(
            directory=self.mdict['pki_client_database_dir'],
            password=self.mdict['pki_client_database_password'])

        try:
            self.generate_csr(
                client_nssdb,
                subsystem,
                'admin',
                csr_path
            )

        finally:
            client_nssdb.close()

    def generate_system_cert_requests(self, subsystem):

        if subsystem.name == 'ca':
            self.generate_ca_signing_request(subsystem)

        if subsystem.name == 'kra':
            self.generate_kra_storage_request(subsystem)
            self.generate_kra_transport_request(subsystem)

        if subsystem.name == 'ocsp':
            self.generate_ocsp_signing_request(subsystem)

        if subsystem.name in ['kra', 'ocsp', 'tks', 'tps']:
            self.generate_sslserver_request(subsystem)
            self.generate_subsystem_request(subsystem)
            self.generate_audit_signing_request(subsystem)
            self.generate_admin_request(subsystem)

    def import_system_cert_request(self, subsystem, tag):

        cert_id = self.get_cert_id(subsystem, tag)
        param = 'pki_%s_csr_path' % cert_id
        source_path = self.mdict.get(param)

        if not source_path:
            # no CSR file to import
            return

        logger.info('Importing CSR for %s from %s', tag, source_path)

        if not os.path.exists(source_path):
            raise Exception('Invalid path in %s: %s' % (param, source_path))

        dest_path = subsystem.csr_file(tag)

        if os.path.realpath(source_path) == os.path.realpath(dest_path):
            # CSR already imported
            return

        self.file.copy(
            old_name=source_path,
            new_name=dest_path,
            overwrite_flag=True)

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
            # no CA signing cert file to import
            return

        logger.info('Importing CA signing cert from %s', cert_file)

        if not os.path.exists(cert_file):
            raise Exception('Invalid path in %s: %s' % (param, cert_file))

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

        if not cert_file:
            # no system cert to import
            return

        logger.info('Importing %s cert from %s', cert_id, cert_file)

        if not os.path.exists(cert_file):
            raise Exception('Invalid path in %s: %s' % (param, cert_file))

        cert = subsystem.get_subsystem_cert(tag)
        nickname = cert['nickname']
        token = pki.nssdb.normalize_token(cert['token'])

        if not token:
            token = self.mdict.get('pki_sslserver_token')
            if not token:
                token = self.mdict['pki_token_name']

        nssdb.import_cert_chain(
            nickname=nickname,
            cert_chain_file=cert_file,
            token=token,
            trust_attributes=trust_attributes)

    def import_admin_cert(self):

        param = 'pki_admin_cert_path'
        cert_file = self.mdict.get(param)

        if not cert_file:
            # no admin cert to import
            return

        logger.info('Importing admin cert from %s', cert_file)

        if not os.path.exists(cert_file):
            raise Exception('Invalid path in %s: %s' % (param, cert_file))

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

    def store_admin_cert(self, pem_cert):

        cert_file = self.mdict['pki_client_admin_cert']
        logger.info('Storing admin cert into %s', cert_file)

        with open(cert_file, "w", encoding='utf-8') as f:
            f.write(pem_cert)

        os.chmod(cert_file, pki.server.DEFAULT_FILE_MODE)

        client_nssdb_dir = self.mdict['pki_client_database_dir']
        logger.info('Importing admin cert into %s', client_nssdb_dir)

        client_nssdb = pki.nssdb.NSSDatabase(
            directory=client_nssdb_dir,
            password_file=self.mdict['pki_client_password_conf'])

        try:
            client_nssdb.add_cert(
                re.sub("&#39;", "'", self.mdict['pki_admin_nickname']),
                cert_file)

        finally:
            client_nssdb.close()

    def export_admin_pkcs12(self):

        pkcs12_file = self.mdict['pki_client_admin_cert_p12']
        logger.info('Exporting admin cert into %s', pkcs12_file)

        pkcs12_path = os.path.abspath(pkcs12_file)
        pkcs12_dir = os.path.dirname(pkcs12_path)

        # Create directory for PKCS #12 file
        self.directory.create(pkcs12_dir)

        # Export admin cert into PKCS #12 file
        self.pk12util.create_file(
            pkcs12_file,
            re.sub("&#39;", "'", self.mdict['pki_admin_nickname']),
            self.mdict['pki_client_pkcs12_password_conf'],
            self.mdict['pki_client_password_conf'],
            self.mdict['pki_client_database_dir'])

        os.chmod(
            pkcs12_file,
            config.PKI_DEPLOYMENT_DEFAULT_SECURITY_DATABASE_PERMISSIONS)

    def import_certs_and_keys(self, nssdb):

        param = 'pki_external_pkcs12_path'
        pkcs12_file = self.mdict.get(param)

        if not pkcs12_file:
            # no PKCS #12 file to import
            return

        logger.info('Importing certs and keys from %s', pkcs12_file)

        if not os.path.exists(pkcs12_file):
            raise Exception('Invalid path in %s: %s' % (param, pkcs12_file))

        pkcs12_password = self.mdict['pki_external_pkcs12_password']
        nssdb.import_pkcs12(pkcs12_file, pkcs12_password)

    def import_cert_chain(self, nssdb):

        logger.debug('PKIDeployer.import_cert_chain()')

        param = 'pki_cert_chain_path'
        cert_chain_path = self.mdict.get(param)

        if not cert_chain_path:
            # no cert chain to import
            return

        if not os.path.exists(cert_chain_path):
            raise Exception('Certificate chain not found: %s' % cert_chain_path)

        logger.info('Importing cert chain from %s', cert_chain_path)

        nickname = self.mdict['pki_cert_chain_nickname']

        nssdb.import_cert_chain(
            nickname=nickname,
            cert_chain_file=cert_chain_path,
            trust_attributes='CT,C,C')

    def retrieve_cert_chain(self, url):

        logger.info('Retrieving cert chain from %s', url)
        cert_chain = self.get_ca_signing_cert(url)

        logger.info('Importing cert chain from %s', url)
        nssdb = self.instance.open_nssdb()
        try:
            nssdb.import_pkcs7(
                pkcs7_data=cert_chain,
                trust_attributes='CT,C,C')
        finally:
            nssdb.close()

        return cert_chain

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

    def update_system_certs(self, subsystem):

        logger.info('Updating system certs')

        if subsystem.name == 'ca':
            nickname = self.mdict['pki_ca_signing_nickname']
            subsystem.config['ca.signing.cacertnickname'] = nickname

            subsystem.config['ca.signing.defaultSigningAlgorithm'] = \
                self.mdict['pki_ca_signing_signing_algorithm']

            subsystem.config['ca.ocsp_signing.defaultSigningAlgorithm'] = \
                self.mdict['pki_ocsp_signing_signing_algorithm']

        if subsystem.name == 'ocsp':
            subsystem.config['ocsp.signing.defaultSigningAlgorithm'] = \
                self.mdict['pki_ocsp_signing_signing_algorithm']

        subsystem.config['%s.audit_signing.defaultSigningAlgorithm' % subsystem.name] = \
            self.mdict['pki_audit_signing_signing_algorithm']

    def validate_system_certs(self, subsystem):

        logger.info('Validate system certs')

        if subsystem.name == 'ca':
            subsystem.validate_system_cert('signing')
            subsystem.validate_system_cert('ocsp_signing')

        if subsystem.name == 'kra':
            subsystem.validate_system_cert('storage')
            subsystem.validate_system_cert('transport')

        if subsystem.name == 'ocsp':
            subsystem.validate_system_cert('signing')

        subsystem.validate_system_cert('sslserver')
        subsystem.validate_system_cert('subsystem')
        subsystem.validate_system_cert('audit_signing')

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

        ds_url = self.ds_url.geturl()
        logger.info('Connecting to LDAP server at %s', ds_url)

        self.ds_connection = ldap.initialize(ds_url)

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

        conf_dir = os.path.join(pki.server.PKIServer.CONFIG_DIR,
                                self.mdict['pki_instance_name'])
        nssdb_dir = os.path.join(conf_dir, 'alias')
        ca_cert = os.path.join(nssdb_dir, 'ca.crt')

        if not os.path.exists(ca_cert):

            # if ca.crt doesn't exist, use provided cert chain
            cert_chain_path = self.mdict['pki_cert_chain_path']
            logger.info('Certificate chain: %s', cert_chain_path)

            if cert_chain_path:

                if not os.path.exists(cert_chain_path):
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

        logger.info('Getting security domain info')

        self.sd_connect()

        sd_client = pki.system.SecurityDomainClient(self.sd_connection)
        domain_info = sd_client.get_domain_info()

        return domain_info

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

        logger.info('Getting install token')

        hostname = self.mdict['pki_hostname']
        subsystem = self.subsystem_type

        sd_client = pki.system.SecurityDomainClient(self.sd_connection)
        install_token = sd_client.get_install_token(hostname, subsystem)

        # Sleep for a bit to allow the install token to replicate to other clones.
        # In the future this can be replaced with signed tokens.
        # https://github.com/dogtagpki/pki/issues/2951
        #
        # The default sleep time is 5s.

        sd_delay = self.mdict.get('pki_security_domain_post_login_sleep_seconds', '5')
        time.sleep(int(sd_delay))

        return install_token

    def join_security_domain(self):

        sd_url = self.mdict['pki_security_domain_uri']

        url = urllib.parse.urlparse(sd_url)
        sd_hostname = url.hostname
        sd_port = str(url.port)

        sd_subsystem = self.domain_info.subsystems['CA']
        self.sd_host = sd_subsystem.get_host(sd_hostname, sd_port)

        self.install_token = self.get_install_token()

    def leave_security_domain(self, subsystem):

        sd_host = subsystem.config.get('securitydomain.host')

        if not sd_host:
            return

        sd_port = subsystem.config['securitydomain.httpsadminport']
        sd_url = 'https://%s:%s' % (sd_host, sd_port)

        hostname = subsystem.config['machineName']

        server_config = self.instance.get_server_config()
        secure_port = server_config.get_secure_port()

        proxy_secure_port = subsystem.config.get('proxy.securePort')
        if proxy_secure_port:
            secure_port = proxy_secure_port

        host_id = '%s %s %s' % (subsystem.type, hostname, secure_port)

        logger.info(
            'Removing %s from security domain at %s',
            host_id,
            sd_url)

        try:
            subsystem.leave_security_domain(
                sd_url,
                host_id,
                hostname,
                secure_port)

        except subprocess.CalledProcessError:
            logger.error(
                'Unable to remove %s from security domain', subsystem.type)
            logger.error('To remove manually:')
            logger.error(
                '$ pki -U %s -n <admin> securitydomain-host-del "%s"',
                sd_url,
                host_id)
            raise

    def setup_security_domain(self, subsystem):

        server_config = self.instance.get_server_config()
        unsecurePort = server_config.get_unsecure_port()
        securePort = server_config.get_secure_port()

        if self.mdict['pki_security_domain_type'] == 'existing':

            sd_url = self.mdict['pki_security_domain_uri']
            logger.info('Joining security domain at %s', sd_url)

            self.join_security_domain()

            subsystem.config['securitydomain.host'] = self.sd_host.Hostname
            subsystem.config['securitydomain.httpport'] = self.sd_host.Port
            subsystem.config['securitydomain.httpsadminport'] = self.sd_host.SecurePort

        else:  # self.mdict['pki_security_domain_type'] == 'new'

            if config.str2bool(self.mdict['pki_subordinate']) and \
                    config.str2bool(self.mdict['pki_subordinate_create_new_security_domain']):

                logger.info('Creating new subordinate security domain')
                self.join_security_domain()

            else:
                logger.info('Creating new security domain')

            subsystem.config['securitydomain.host'] = self.mdict['pki_hostname']
            subsystem.config['securitydomain.httpport'] = unsecurePort
            subsystem.config['securitydomain.httpsadminport'] = securePort

    def setup_security_domain_manager(self, subsystem):

        clone = self.configuration_file.clone

        server_config = self.instance.get_server_config()
        unsecurePort = server_config.get_unsecure_port()
        securePort = server_config.get_secure_port()

        proxyUnsecurePort = subsystem.config.get('proxy.unsecurePort')
        if not proxyUnsecurePort:
            proxyUnsecurePort = unsecurePort

        proxySecurePort = subsystem.config.get('proxy.securePort')
        if not proxySecurePort:
            proxySecurePort = securePort

        if self.mdict['pki_security_domain_type'] == 'existing':

            sd_url = self.mdict['pki_security_domain_uri']
            logger.info('Joining security domain at %s', sd_url)

            subsystem.config['securitydomain.select'] = 'existing'
            subsystem.config['securitydomain.name'] = self.domain_info.id

            domain_manager = False

            if subsystem.type == 'CA' and clone:

                # check whether the primary CA is a security domain manager

                sd_hostname = subsystem.config['securitydomain.host']
                sd_port = subsystem.config['securitydomain.httpsadminport']

                sd_subsystem = self.domain_info.subsystems['CA']
                sd_host = sd_subsystem.get_host(sd_hostname, sd_port)

                if sd_host.DomainManager and sd_host.DomainManager.lower() == 'true':
                    domain_manager = True

            logger.info('Domain manager: %s', domain_manager)

            if domain_manager:

                logger.info('Cloning security domain manager')

                subsystem.config['securitydomain.select'] = 'new'
                subsystem.config['securitydomain.host'] = self.mdict['pki_hostname']
                subsystem.config['securitydomain.httpport'] = unsecurePort
                subsystem.config['securitydomain.httpsadminport'] = securePort

            subsystem.join_security_domain(
                sd_url,
                self.mdict['pki_subsystem_name'],
                self.mdict['pki_hostname'],
                unsecure_port=proxyUnsecurePort,
                secure_port=proxySecurePort,
                domain_manager=domain_manager,
                clone=clone,
                session_id=self.install_token.token)

        else:  # self.mdict['pki_security_domain_type'] == 'new'

            if config.str2bool(self.mdict['pki_subordinate']) and \
                    config.str2bool(self.mdict['pki_subordinate_create_new_security_domain']):

                logger.info('Creating new subordinate security domain')
                sd_name = self.mdict['pki_subordinate_security_domain_name']

            else:
                logger.info('Creating new security domain')
                sd_name = self.mdict['pki_security_domain_name']

            subsystem.config['securitydomain.select'] = 'new'
            subsystem.config['securitydomain.name'] = sd_name

            subsystem.create_security_domain(name=sd_name)

            domain_manager = True

            logger.info('Adding security domain manager')
            subsystem.add_security_domain_subsystem(
                self.mdict['pki_subsystem_name'],
                subsystem.type,
                self.mdict['pki_hostname'],
                unsecure_port=proxyUnsecurePort,
                secure_port=proxySecurePort,
                domain_manager=True)

        if domain_manager:
            logger.info('Adding security domain sessions')
            subsystem.config['securitydomain.checkIP'] = 'false'
            subsystem.config['securitydomain.checkinterval'] = '300000'
            subsystem.config['securitydomain.flushinterval'] = '86400000'
            subsystem.config['securitydomain.source'] = 'ldap'

    def pki_connect(self):

        ca_cert = os.path.join(self.instance.nssdb_dir, "ca.crt")

        connection = pki.client.PKIConnection(
            protocol='https',
            hostname=self.mdict['pki_hostname'],
            port=self.mdict['pki_https_port'],
            trust_env=False,
            cert_paths=ca_cert)

        self.client = pki.system.SystemConfigClient(
            connection,
            subsystem=self.mdict['pki_subsystem_type'])

    def import_cert_request(self, subsystem, tag, request):

        request_id_generator = subsystem.config.get('dbs.request.id.generator', 'legacy')

        if request_id_generator == 'legacy':
            # call the server to generate legacy request ID
            logger.info('Creating request ID for %s cert', tag)
            request.systemCert.requestID = self.client.createRequestID(request)
            logger.info('- request ID: %s', request.systemCert.requestID)
        else:
            # let pki-server ca-cert-request-import generate the request ID
            request.systemCert.requestID = None

        logger.info('Importing %s cert request into CA database', tag)
        request_pem = pki.nssdb.convert_csr(request.systemCert.request, 'base64', 'pem')
        result = subsystem.import_cert_request(
            request_id=request.systemCert.requestID,
            request_data=request_pem,
            request_type=request.systemCert.requestType,
            profile_path=request.systemCert.profile,
            dns_names=request.systemCert.dnsNames,
            adjust_validity=request.systemCert.adjustValidity)

        if request_id_generator != 'legacy':
            # get the request ID generated by pki-server ca-cert-request-import
            request.systemCert.requestID = result['requestID']
            logger.info('- request ID: %s', request.systemCert.requestID)

    def create_system_cert_info(self, subsystem, tag):

        if subsystem.type == 'CA' and tag == 'signing':
            cert_id = 'ca_signing'

        elif subsystem.type == 'CA' and tag == 'ocsp_signing':
            cert_id = 'ocsp_signing'

        elif subsystem.type == 'KRA' and tag == 'storage':
            cert_id = 'storage'

        elif subsystem.type == 'KRA' and tag == 'transport':
            cert_id = 'transport'

        elif subsystem.type == 'OCSP' and tag == 'signing':
            cert_id = 'ocsp_signing'

        elif tag == 'sslserver':
            cert_id = 'sslserver'

        elif tag == 'subsystem':
            cert_id = 'subsystem'

        elif tag == 'audit_signing':
            cert_id = 'audit_signing'

        else:
            raise Exception('Invalid tag for %s: %s' % (subsystem.type, tag))

        system_cert = pki.system.SystemCertData()
        system_cert.keySize = self.mdict['pki_%s_key_size' % cert_id]
        system_cert.nickname = self.mdict['pki_%s_nickname' % cert_id]
        system_cert.subjectDN = self.mdict['pki_%s_subject_dn' % cert_id]
        system_cert.token = self.mdict['pki_%s_token' % cert_id]
        system_cert.op_flags = self.mdict['pki_%s_opFlags' % cert_id]
        system_cert.op_flags_mask = self.mdict['pki_%s_opFlagsMask' % cert_id]

        if not system_cert.token:
            if config.str2bool(self.mdict['pki_hsm_enable']):
                system_cert.token = self.mdict['pki_token_name']
            else:
                system_cert.token = subsystem.config['preop.module.token']

        if pki.nssdb.internal_token(system_cert.token):
            system_cert.token = pki.nssdb.INTERNAL_TOKEN_NAME

        return system_cert

    def create_cert_setup_request(self, subsystem, tag, cert):

        request = pki.system.CertificateSetupRequest()
        request.tag = tag
        request.pin = self.mdict['pki_one_time_pin']

        request.systemCert = self.create_system_cert_info(subsystem, tag)

        # cert type: selfsign, local, or remote
        request.systemCert.type = subsystem.config['preop.cert.%s.type' % tag]

        if request.systemCert.type == 'selfsign':
            request.systemCert.signingAlgorithm = \
                subsystem.config.get('preop.cert.signing.keyalgorithm', 'SHA256withRSA')

        elif request.systemCert.type == 'local':
            request.systemCert.signingAlgorithm = \
                subsystem.config.get('preop.cert.signing.signingalgorithm', 'SHA256withRSA')

        # key type: rsa or ecc
        key_type = subsystem.config['preop.cert.%s.keytype' % tag]
        request.systemCert.keyType = key_type

        if key_type == 'RSA':

            if not request.systemCert.keySize:
                request.systemCert.keySize = subsystem.config['keys.rsa.keysize.default']

            if tag == 'transport' or tag == 'storage':
                request.systemCert.keyWrap = True
            else:
                request.systemCert.keyWrap = False

        elif key_type == 'EC':

            request.systemCert.keyCurveName = request.systemCert.keySize

            if not request.systemCert.keyCurveName:
                request.systemCert.keyCurveName = subsystem.config['keys.ecc.curve.default']

            # Default SSL server cert to ECDHE unless stated otherwise.
            # Note: IE only supports ECDHE, but ECDH is more efficient.
            ec_type = subsystem.config.get('preop.cert.%s.ec.type' % tag, 'ECDHE')

            # For ECDH SSL server cert server.xml should have the following ciphers:
            # -TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            # +TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
            #
            # For ECDHE SSL server cert server.xml should have the following ciphers:
            # +TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            # -TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
            if tag == 'sslserver' and ec_type.upper() == 'ECDH':
                request.systemCert.sslECDH = True
            else:
                request.systemCert.sslECDH = False

        request.systemCert.keyAlgorithm = subsystem.config['preop.cert.%s.keyalgorithm' % tag]

        csr_path = subsystem.csr_file(tag)

        # load existing CSR if exists
        if os.path.exists(csr_path):
            with open(csr_path, 'r', encoding='utf-8') as f:
                csr_data = f.read()
            request.systemCert.request = pki.nssdb.convert_csr(csr_data, 'pem', 'base64')

        request.systemCert.requestType = 'pkcs10'

        request.systemCert.cert = cert.get('data')
        request.systemCert.profile = subsystem.config['preop.cert.%s.profile' % tag]
        request.systemCert.req_ext_oid = subsystem.config.get('preop.cert.%s.ext.oid' % tag)
        request.systemCert.req_ext_data = subsystem.config.get('preop.cert.%s.ext.data' % tag)
        request.systemCert.req_ext_critical = subsystem.config.get(
            'preop.cert.%s.ext.critical' % tag)

        inject_san = subsystem.config.get('service.injectSAN')
        if tag == 'sslserver' and inject_san == 'true':
            logger.info('SAN extension:')
            dns_names = subsystem.config['service.sslserver.san'].split(',')
            for dns_name in dns_names:
                logger.info('- %s', dns_name)
            request.systemCert.dnsNames = dns_names
        else:
            request.systemCert.dnsNames = None

        request.systemCert.adjustValidity = tag != 'signing'

        return request

    def find_cert_key(self, tag, request):

        logger.info('Searching for %s key', tag)

        nssdb = self.instance.open_nssdb()
        try:
            result = nssdb.find_keys(
                nickname=request.systemCert.nickname,
                token=request.systemCert.token)
        finally:
            nssdb.close()

        keys = result['entries']

        if not keys:
            return None

        # get the first key
        return keys[0]['keyId']

    def create_cert_key(self, tag, request):

        logger.info('Creating %s key', tag)

        token = request.systemCert.token
        key_type = request.systemCert.keyType
        op_flags = request.systemCert.op_flags
        op_flags_mask = request.systemCert.op_flags_mask
        key_size = None
        key_wrap = False
        curve = None
        ssl_ecdh = False

        if request.systemCert.keyType == 'RSA':
            key_size = request.systemCert.keySize
            key_wrap = request.systemCert.keyWrap

        elif request.systemCert.keyType == 'EC':
            curve = request.systemCert.keyCurveName
            ssl_ecdh = request.systemCert.sslECDH

        else:
            raise Exception('Unsupported key type: %s' % key_type)

        nssdb = self.instance.open_nssdb()
        try:
            result = nssdb.create_key(
                token=token,
                key_type=key_type,
                key_size=key_size,
                key_wrap=key_wrap,
                curve=curve,
                ssl_ecdh=ssl_ecdh,
                op_flags=op_flags,
                op_flags_mask=op_flags_mask)
        finally:
            nssdb.close()

        return result['keyId']

    def generate_csr(self,
                     nssdb,
                     subsystem,
                     tag,
                     csr_path,
                     basic_constraints_ext=None,
                     key_usage_ext=None,
                     extended_key_usage_ext=None,
                     subject_key_id=None,
                     generic_exts=None):

        cert_id = self.get_cert_id(subsystem, tag)
        logger.info('Generating %s CSR in %s', cert_id, csr_path)
        csr_pathname = os.path.join(nssdb.tmpdir, os.path.basename(csr_path))

        subject_dn = self.mdict['pki_%s_subject_dn' % cert_id]

        (key_type, key_size, curve, hash_alg) = self.get_key_params(cert_id)

        """
        For newer HSM in FIPS mode:
        for KRA, storage cert and transport cert need to use the new -w
        option of PKCS10Client
        e.g. PKCS10Client -d /var/lib/pki/<ca instance>/alias -h hsm-module
          -a rsa -l 2048 -n "CN= KRA storage cert" -w -v -o kra-storage.csr.b64

        Here we use the pkispawn config param to determine if it's HSM to trigger:
            pki_hsm_enable = True

        """

        logger.debug('generate_csr: pki_hsm_enable: %s', self.mdict['pki_hsm_enable'])
        logger.debug('generate_csr: subsystem type: %s', subsystem.type)

        if (subsystem.type == 'KRA' and
                config.str2bool(self.mdict['pki_hsm_enable']) and
                (cert_id in ['storage', 'transport'])):

            logger.debug('generate_csr: calling PKCS10Client for %s', cert_id)

            nssdb.create_request_with_wrapping_key(
                subject_dn=subject_dn,
                request_file=csr_path,
                key_size=key_size)

        else:

            logger.debug('generate_csr: calling certutil for %s', cert_id)

            nssdb.create_request(
                subject_dn=subject_dn,
                request_file=csr_pathname,
                key_type=key_type,
                key_size=key_size,
                curve=curve,
                hash_alg=hash_alg,
                basic_constraints_ext=basic_constraints_ext,
                key_usage_ext=key_usage_ext,
                extended_key_usage_ext=extended_key_usage_ext,
                subject_key_id=subject_key_id,
                generic_exts=generic_exts,
                use_jss=True)

            shutil.move(csr_pathname, csr_path)

        self.file.copy(
            old_name=csr_path,
            new_name=subsystem.csr_file(tag),
            overwrite_flag=True)

    def create_cert_request(self, nssdb, tag, request):

        logger.info('Creating %s cert request', tag)

        if request.systemCert.requestType != 'pkcs10':
            raise Exception(
                'Certificate request type not supported: %s' % request.systemCert.requestType)

        # match <digest>with<encryption>
        match = re.fullmatch(r'(\S+)with(\S+)', request.systemCert.keyAlgorithm)
        hash_alg = None
        if match:
            hash_alg = match.group(1)

        basic_constraints_ext = None
        key_usage_ext = None
        generic_exts = None

        if tag == 'signing':

            basic_constraints_ext = {
                'ca': True,
                'path_length': None,
                'critical': True
            }

            key_usage_ext = {
                'digitalSignature': True,
                'nonRepudiation': True,
                'certSigning': True,
                'crlSigning': True,
                'critical': True
            }

            # NSCertTypeExtension (unsupported)
            # ns_cert_type_ext = {
            #     'nsCertType': True,
            #     'ssl_ca': True
            # }

        if request.systemCert.req_ext_oid and request.systemCert.req_ext_data:

            generic_ext = {
                'oid': request.systemCert.req_ext_oid,
                'data': binascii.unhexlify(request.systemCert.req_ext_data),
                'critical': config.str2bool(request.systemCert.req_ext_critical)
            }

            generic_exts = [generic_ext]

        tmpdir = tempfile.mkdtemp()
        try:
            csr_file = os.path.join(tmpdir, 'request.csr')

            nssdb.create_request(
                subject_dn=request.systemCert.subjectDN,
                request_file=csr_file,
                token=request.systemCert.token,
                key_id=request.systemCert.keyID,
                hash_alg=hash_alg,
                basic_constraints_ext=basic_constraints_ext,
                key_usage_ext=key_usage_ext,
                generic_exts=generic_exts,
                use_jss=True)

            with open(csr_file, encoding='utf-8') as f:
                pem_csr = f.read()

            return pki.nssdb.convert_csr(pem_csr, 'pem', 'base64')

        finally:
            shutil.rmtree(tmpdir)

    def create_temp_sslserver_cert(self):

        hostname = self.mdict['pki_hostname']

        (key_type, key_size, curve, hash_alg) = self.get_key_params('sslserver')

        nickname = self.mdict['pki_self_signed_nickname']
        token = self.mdict['pki_self_signed_token']

        subject_dn = \
            'cn=' + self.mdict['pki_hostname'] + ',' + \
            'o=' + self.mdict['pki_certificate_timestamp']

        serial = self.mdict.get('pki_self_signed_serial_number')
        validity = self.mdict.get('pki_self_signed_validity_period')
        trust_attributes = self.mdict.get('pki_self_signed_trustargs')

        self.instance.set_sslserver_cert_nickname(nickname)

        tmpdir = tempfile.mkdtemp()
        nssdb = self.instance.open_nssdb()

        try:
            logger.info('Checking existing temp SSL server cert: %s', nickname)
            pem_cert = nssdb.get_cert(nickname=nickname)

            if pem_cert:
                cert = x509.load_pem_x509_certificate(pem_cert, default_backend())
                cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
                cert_hostname = cn.value

                logger.info('Existing temp SSL server cert is for %s', cert_hostname)

                # if cert hostname is correct, don't create new temp cert
                if cert_hostname == hostname:
                    return

                logger.info('Removing existing temp SSL server cert for %s', cert_hostname)

                nssdb.remove_cert(nickname=nickname, remove_key=True)

            logger.info('Creating new temp SSL server cert for %s', hostname)

            # TODO: replace with pki-server create-cert --temp sslserver

            # NOTE:  ALWAYS create the temporary sslserver certificate
            #        in the software DB regardless of whether the
            #        instance will utilize 'softokn' or an HSM

            csr_file = os.path.join(tmpdir, 'sslserver.csr')
            cert_file = os.path.join(tmpdir, 'sslserver.crt')

            nssdb.create_request(
                subject_dn=subject_dn,
                request_file=csr_file,
                token=token,
                key_type=key_type,
                key_size=key_size,
                curve=curve,
                hash_alg=hash_alg,
                use_jss=True
            )

            nssdb.create_cert(
                request_file=csr_file,
                cert_file=cert_file,
                serial=serial,
                validity=validity,
                use_jss=True
            )

            nssdb.add_cert(
                nickname=nickname,
                cert_file=cert_file,
                token=token,
                trust_attributes=trust_attributes)

        finally:
            nssdb.close()
            shutil.rmtree(tmpdir)

    def remove_temp_sslserver_cert(self):

        nickname = self.mdict['pki_self_signed_nickname']
        logger.info('Removing temp SSL server cert: %s', nickname)

        nssdb = self.instance.open_nssdb()

        try:
            # remove temp SSL server cert and key
            nssdb.remove_cert(nickname=nickname, remove_key=True)

        finally:
            nssdb.close()

    def update_sslserver_cert_nickname(self, subsystem):

        sslserver = subsystem.get_subsystem_cert('sslserver')
        nickname = sslserver['nickname']
        token = sslserver['token']
        self.instance.set_sslserver_cert_nickname(nickname, token)

    def create_cert(self, subsystem, tag, request):

        cert_id_generator = subsystem.config.get('dbs.cert.id.generator', 'legacy')

        if cert_id_generator == 'legacy':
            # call the server to generate legacy cert ID
            logger.info('Creating cert ID for %s cert', tag)
            request.systemCert.certID = self.client.createCertID(request)
            logger.info('- cert ID: %s', request.systemCert.certID)
        else:
            # let pki-server ca-cert-create generate the cert ID
            request.systemCert.certID = None

        logger.info('Creating %s cert', tag)
        cert_data = subsystem.create_cert(
            request_id=request.systemCert.requestID,
            profile_id=request.systemCert.profile,
            cert_type=request.systemCert.type,
            key_id=request.systemCert.keyID,
            key_token=request.systemCert.token,
            key_algorithm=request.systemCert.keyAlgorithm,
            signing_algorithm=request.systemCert.signingAlgorithm,
            serial=request.systemCert.certID,
            cert_format='DER')

        return base64.b64encode(cert_data).decode('ascii')

    def import_cert(self, subsystem, tag, request, cert_data):

        logger.info('Importing %s cert into CA database', tag)
        logger.debug('- cert: %s', cert_data)

        pem_cert = pki.nssdb.convert_cert(cert_data, 'base64', 'pem')

        subsystem.import_cert(
            cert_data=pem_cert,
            cert_format='PEM',
            profile_path=request.systemCert.profile,
            request_id=request.systemCert.requestID)

    def setup_system_cert(self, nssdb, subsystem, tag, system_cert, request):

        logger.debug('PKIDeployer.setup_system_cert()')

        # Check whether the cert already exists in NSS database

        cert_info = nssdb.get_cert_info(
            nickname=request.systemCert.nickname,
            token=request.systemCert.token)

        if cert_info:
            logger.info('%s cert already exists in NSS database', tag)
            logger.info('- serial: %s', hex(cert_info['serial_number']))
            logger.info('- subject: %s', cert_info['subject'])
            logger.info('- issuer: %s', cert_info['issuer'])
            logger.info('- trust flags: %s', cert_info['trust_flags'])

        else:
            logger.info('%s cert does not exist in NSS database', tag)

        # For external/existing CA case, the requests and certs might be provided
        # (i.e. already exists in NSS database), but they still need to be imported
        # into CA database.
        #
        # A new SSL server cert will always be created separately later.

        external = config.str2bool(self.mdict['pki_external'])

        if subsystem.type == 'CA' and external and cert_info:

            signing_cert_info = nssdb.get_cert_info(
                nickname=subsystem.config["ca.signing.nickname"])
            logger.info('CA subject: %s', signing_cert_info['subject'])

            if cert_info['object'].issuer != signing_cert_info['object'].subject:
                logger.info('Do not import external cert and request into database: %s', tag)
                return

            # When importing existing self-signed CA certificate, create a
            # certificate record to reserve the serial number. Otherwise it
            # might conflict with system certificates to be created later.
            # Also create the certificate request record for renewals.

            if config.str2bool(self.mdict['pki_import_system_certs']) and \
                    config.str2bool(self.mdict['pki_ds_setup']):
                self.import_cert_request(subsystem, tag, request)
                self.import_cert(subsystem, tag, request, system_cert['data'])

            return

        csr_file = subsystem.csr_file(tag)
        if os.path.exists(csr_file):
            logger.info('Reusing %s cert request in %s', tag, csr_file)

        else:
            if cert_info:
                request.systemCert.keyID = self.find_cert_key(tag, request)

            if request.systemCert.keyID:
                logger.info('Reusing %s key in NSS database', tag)
            else:
                logger.info('Creating new %s key in NSS database', tag)
                request.systemCert.keyID = self.create_cert_key(tag, request)

            logger.info('- key ID: %s', request.systemCert.keyID)

            request.systemCert.request = self.create_cert_request(nssdb, tag, request)
            logger.debug('- request: %s', request.systemCert.request)

            system_cert['request'] = request.systemCert.request

            logger.info('Storing cert request for %s', tag)
            subsystem.store_system_cert_request(system_cert)

        if request.systemCert.type == 'remote':

            if cert_info:
                logger.info('Reusing %s cert in NSS database', tag)
                return

            # Issue subordinate CA signing cert using remote CA signing cert.

            if subsystem.type == 'CA' and \
                    config.str2bool(self.mdict['pki_clone']) \
                    and tag == 'sslserver':

                # For CA clone always use the master CA to generate the SSL
                # server certificate to avoid any changes which may have
                # been made to the X500Name directory string encoding order.
                ca_url = self.mdict['pki_clone_uri']

            elif tag == 'subsystem':

                sd_hostname = subsystem.config['securitydomain.host']
                sd_port = subsystem.config['securitydomain.httpsadminport']
                ca_url = 'https://%s:%s' % (sd_hostname, sd_port)

            else:

                ca_url = self.mdict['pki_issuing_ca']

            hostname = self.mdict['pki_hostname']

            server_config = self.instance.get_server_config()
            secure_port = server_config.get_secure_port()

            requestor = '%s-%s-%s' % (subsystem.type, hostname, secure_port)

            logger.info('Requesting %s cert from %s', tag, ca_url)

            cert_pem = self.request_cert(
                ca_url,
                request.systemCert.requestType,
                request.systemCert.request,
                request.systemCert.profile,
                request.systemCert.subjectDN,
                dns_names=request.systemCert.dnsNames,
                requestor=requestor)

            system_cert['data'] = pki.nssdb.convert_cert(cert_pem, 'pem', 'base64')

            cert_obj = x509.load_pem_x509_certificate(
                bytes(cert_pem, 'utf-8'),
                backend=default_backend())
            logger.info('- serial: %s', hex(cert_obj.serial_number))

            logger.info('Importing %s cert into NSS database', tag)
            nssdb.add_cert(
                nickname=request.systemCert.nickname,
                cert_data=system_cert['data'],
                cert_format='base64',
                token=request.systemCert.token)

            return

        # selfsign or local

        if config.str2bool(self.mdict['pki_ds_setup']):
            # import request into CA database and get a request ID
            self.import_cert_request(subsystem, tag, request)

        if cert_info:
            logger.info('Reusing %s cert in NSS database', tag)

        else:
            system_cert['data'] = self.create_cert(subsystem, tag, request)

            cert_pem = pki.nssdb.convert_cert(system_cert['data'], 'base64', 'pem').encode()
            cert_obj = x509.load_pem_x509_certificate(cert_pem, backend=default_backend())
            logger.info('- serial: %s', hex(cert_obj.serial_number))

            logger.info('Importing %s cert into NSS database', tag)
            nssdb.add_cert(
                nickname=request.systemCert.nickname,
                cert_data=system_cert['data'],
                cert_format='base64',
                token=request.systemCert.token)

        if config.str2bool(self.mdict['pki_ds_setup']):
            # import cert into CA database
            self.import_cert(subsystem, tag, request, system_cert['data'])

    def setup_system_certs(self, nssdb, subsystem):

        logger.debug('PKIDeployer.setup_system_certs()')
        system_certs = {}

        clone = self.configuration_file.clone
        num_subsystems = len(self.instance.get_subsystems())

        external = config.str2bool(self.mdict['pki_external']) or \
            config.str2bool(self.mdict['pki_standalone'])

        tags = subsystem.config['%s.cert.list' % subsystem.name].split(',')

        for tag in tags:

            logger.info('Setting up %s cert', tag)

            system_cert = subsystem.get_subsystem_cert(tag)
            system_certs[tag] = system_cert

            if tag != 'sslserver' and clone:
                logger.info('%s cert is already set up', tag)
                continue

            if tag == 'sslserver' and num_subsystems > 1:
                logger.info('sslserver cert is already set up')
                continue

            if tag == 'subsystem' and num_subsystems > 1:
                logger.info('subsystem cert is already set up')
                continue

            # For external/standalone KRA/OCSP/TKS/TPS case, all system certs will be provided.
            # No system certs will be generated including the SSL server cert.

            if subsystem.type in ['KRA', 'OCSP', 'TKS', 'TPS'] and external:
                continue

            request = self.create_cert_setup_request(subsystem, tag, system_cert)

            self.setup_system_cert(nssdb, subsystem, tag, system_cert, request)

        logger.info('Setting up trust flags')

        if pki.nssdb.internal_token(self.mdict.get('pki_token_name')):
            token = ''
        else:
            token = self.mdict['pki_token_name'] + ':'

        if subsystem.type == 'CA':
            nssdb.modify_cert(
                nickname=token + self.mdict['pki_ca_signing_nickname'],
                trust_attributes='CTu,Cu,Cu')

        nssdb.modify_cert(
            nickname=token + self.mdict['pki_audit_signing_nickname'],
            trust_attributes='u,u,Pu')

        # Reset the NSS database ownership and permissions

        pki.util.chown(
            self.instance.nssdb_dir,
            self.mdict['pki_uid'],
            self.mdict['pki_gid'])

        pki.util.chmod(
            self.instance.nssdb_dir,
            config.PKI_DEPLOYMENT_DEFAULT_SECURITY_DATABASE_PERMISSIONS)

        os.chmod(
            self.instance.nssdb_dir,
            pki.server.DEFAULT_DIR_MODE)

        return system_certs

    def load_admin_cert(self):

        logger.debug('PKIDeployer.load_admin_cert()')

        cert_file = self.mdict.get('pki_admin_cert_file')
        if cert_file and os.path.exists(cert_file):

            # admin cert was in 'pki_admin_cert_file' but not yet in client
            # nssdb

            logger.info('Loading admin cert from %s', cert_file)
            with open(cert_file, 'r', encoding='utf-8') as f:
                pem_cert = f.read()

            return pem_cert

        return None

    def request_cert(
            self,
            url,
            request_type,
            csr,
            profile,
            subject,
            dns_names=None,
            requestor=None):

        tmpdir = tempfile.mkdtemp()
        try:
            pem_csr = pki.nssdb.convert_csr(csr, 'base64', 'pem')
            csr_file = os.path.join(tmpdir, 'request.csr')
            with open(csr_file, 'w', encoding='utf-8') as f:
                f.write(pem_csr)

            install_token = os.path.join(tmpdir, 'install-token')
            with open(install_token, 'w', encoding='utf-8') as f:
                f.write(self.install_token.token)

            cmd = [
                'pki',
                '-d', self.instance.nssdb_dir,
                '-f', self.instance.password_conf,
                '-U', url,
                '--ignore-banner',
                'ca-cert-request-submit',
                '--request-type', request_type,
                '--csr-file', csr_file,
                '--profile', profile,
                '--subject', subject
            ]

            if dns_names:
                cmd.extend(['--dns-names', ','.join(dns_names)])

            if requestor:
                cmd.extend(['--requestor', requestor])

            cmd.extend([
                '--install-token', install_token,
                '--output-format', 'PEM'
            ])

            if logger.isEnabledFor(logging.DEBUG):
                cmd.append('--debug')

            elif logger.isEnabledFor(logging.INFO):
                cmd.append('--verbose')

            logger.debug('Command: %s', ' '.join(cmd))
            result = subprocess.run(cmd, stdout=subprocess.PIPE, check=True)

            return result.stdout.decode()

        finally:
            shutil.rmtree(tmpdir)

    def create_admin_csr(self, subsystem):

        if self.mdict['pki_admin_cert_request_type'] != 'pkcs10':
            raise Exception(log.PKI_CONFIG_PKCS10_SUPPORT_ONLY)

        csr_path = os.path.join(self.mdict['pki_client_database_dir'], 'admin.csr')

        client_nssdb = pki.nssdb.NSSDatabase(
            directory=self.mdict['pki_client_database_dir'],
            password_file=self.mdict['pki_client_password_conf'])

        try:
            self.generate_csr(
                client_nssdb,
                subsystem,
                'admin',
                csr_path
            )

        finally:
            client_nssdb.close()

        with open(csr_path, encoding='utf-8') as f:
            pem_csr = f.read()

        return pki.nssdb.convert_csr(pem_csr, 'pem', 'base64')

    def valid_algorithm(self, key_type, algorithm):

        if key_type == 'RSA' and 'RSA' in algorithm:
            return True

        if key_type == 'EC' and 'EC' in algorithm:
            return True

        if key_type == 'DSA' and 'DSA' in algorithm:
            return True

        return False

    def get_signing_algorithm(self, subsystem, profile):
        '''
        Get the signing algorithm from a profile.

        First, get the allowed algorithms from the profile (constraint.params.signingAlgsAllowed).
        If the property does not exist, get the ca.profiles.defaultSigningAlgsAllowed from CS.cfg.
        If the property does not exist, use the default: SHA256withRSA, SHA256withEC.

        Next, get the default signing algorithm from the profile (default.params.signingAlg).
        If the property exists and matches the signing CA key type, return the algorithm.
        If the property does not exist or equals '-', get the first allowed algorithm
        that matches the CA signing key type.
        '''

        key_type = subsystem.config['preop.cert.signing.keytype']
        logger.info('Key type: %s', key_type)

        algorithm = None
        allowed_algorithms = None

        # get default algorithm and allowed algorithms from profile
        for name in profile:
            value = profile[name]

            if name.endswith('default.params.signingAlg'):
                algorithm = value.strip()

            if name.endswith('constraint.params.signingAlgsAllowed'):
                allowed_algorithms = value.split(',')

        # if profile does not define allowed algorithms, use the one from CS.cfg
        if not allowed_algorithms:
            default_allowed_algorithms = subsystem.config.get(
                'ca.profiles.defaultSigningAlgsAllowed',
                'SHA256withRSA,SHA256withEC')
            allowed_algorithms = default_allowed_algorithms.split(',')

        logger.info('Allowed signing algorithms: %s', ','.join(allowed_algorithms))

        if not allowed_algorithms:
            raise Exception('Unable to get allowed signing algorithms')

        # check algorithm
        if algorithm and algorithm != '-':

            if not self.valid_algorithm(key_type, algorithm):
                raise Exception('Invalid signing algorithm: %s' % algorithm)

            if algorithm not in allowed_algorithms:
                raise Exception('Signing algorithm not allowed: %s' % algorithm)

            return algorithm

        # get the first allowed algorithm
        for algorithm in allowed_algorithms:

            if not self.valid_algorithm(key_type, algorithm):
                continue

            return algorithm

        raise Exception('Unable to get signing algorithm')

    def create_admin_cert(self, subsystem, csr):

        request = pki.system.CertificateSetupRequest()
        request.tag = 'admin'
        request.pin = self.mdict['pki_one_time_pin']

        request.systemCert = pki.system.SystemCertData()

        request.systemCert.type = subsystem.config.get('preop.cert.admin.type', 'local')

        if request.systemCert.type == 'selfsign':
            request.systemCert.signingAlgorithm = \
                subsystem.config.get('preop.cert.signing.keyalgorithm', 'SHA256withRSA')

        elif request.systemCert.type == 'local':
            request.systemCert.signingAlgorithm = \
                subsystem.config.get('preop.cert.signing.signingalgorithm', 'SHA256withRSA')

        request.systemCert.keyType = self.mdict['pki_admin_key_type']
        request.systemCert.profile = subsystem.config['preop.cert.admin.profile']
        request.systemCert.subjectDN = self.mdict['pki_admin_subject_dn']

        request.systemCert.requestType = self.mdict['pki_admin_cert_request_type']
        request.systemCert.request = csr

        request.systemCert.dnsNames = None
        request.systemCert.adjustValidity = False

        profile_filename = os.path.join(
            subsystem.conf_dir,
            'profiles/ca/%s.cfg' % self.mdict['pki_admin_profile_id'])
        logger.info('Loading %s', profile_filename)

        profile = {}
        pki.util.load_properties(profile_filename, profile)

        request.systemCert.keyAlgorithm = self.get_signing_algorithm(subsystem, profile)
        logger.info('Signing algorithm: %s', request.systemCert.keyAlgorithm)

        if config.str2bool(self.mdict['pki_ds_setup']):
            self.import_cert_request(subsystem, 'admin', request)

        cert_data = self.create_cert(subsystem, 'admin', request)

        if config.str2bool(self.mdict['pki_ds_setup']):
            self.import_cert(subsystem, 'admin', request, cert_data)

        cert_pem = pki.nssdb.convert_cert(cert_data, 'base64', 'pem')
        cert_obj = x509.load_pem_x509_certificate(cert_pem.encode(), backend=default_backend())
        logger.info('- serial: %s', hex(cert_obj.serial_number))

        return cert_pem

    def setup_admin_cert(self, subsystem, base64_csr=None):

        logger.debug('PKIDeployer.setup_admin_cert()')

        external = config.str2bool(self.mdict['pki_external'])
        standalone = config.str2bool(self.mdict['pki_standalone'])

        nickname = self.mdict['pki_admin_nickname']

        client_nssdb = pki.nssdb.NSSDatabase(
            directory=self.mdict['pki_client_database_dir'],
            password=self.mdict['pki_client_database_password'])

        try:
            logger.info('Checking admin cert: %s', nickname)
            cert_info = client_nssdb.get_cert_info(nickname)

            if cert_info:
                logger.info('admin cert already exists in NSS database')
                logger.info('- serial: %s', hex(cert_info['serial_number']))
                logger.info('- subject: %s', cert_info['subject'])
                logger.info('- issuer: %s', cert_info['issuer'])
                logger.info('- trust flags: %s', cert_info['trust_flags'])

                pem_cert = pki.nssdb.convert_cert(cert_info['data'], 'base64', 'pem')

            else:
                logger.info('admin cert does not exist in NSS database')
                pem_cert = None

        finally:
            client_nssdb.close()

        if pem_cert:
            logger.debug('Admin cert:\n%s', pem_cert)

            if external and subsystem.type != 'CA' or standalone:
                self.store_admin_cert(pem_cert)
                self.export_admin_pkcs12()

            return pem_cert

        cert_path = self.mdict.get('pki_admin_cert_path')
        if cert_path:

            logger.info('Loading admin cert from %s', cert_path)
            with open(cert_path, 'r', encoding='utf-8') as f:
                pem_cert = f.read()

            logger.debug('Admin cert:\n%s', pem_cert)

            if external and subsystem.type != 'CA' or standalone:
                self.store_admin_cert(pem_cert)
                self.export_admin_pkcs12()

            return pem_cert

        if config.str2bool(self.mdict['pki_import_admin_cert']) \
                or external and subsystem.type != 'CA' \
                or standalone:
            logger.info('Importing admin cert')
            pem_cert = self.load_admin_cert()
            logger.debug('Admin cert:\n%s', pem_cert)

            if external and subsystem.type != 'CA' or standalone:
                self.store_admin_cert(pem_cert)
                self.export_admin_pkcs12()

            return pem_cert

        if subsystem.type == 'CA':
            logger.info('Creating admin cert')
            pem_cert = self.create_admin_cert(subsystem, base64_csr)
            logger.debug('Admin cert:\n%s', pem_cert)

            self.store_admin_cert(pem_cert)
            self.export_admin_pkcs12()

            return pem_cert

        ca_type = subsystem.config['preop.ca.type']

        if ca_type == 'sdca':
            ca_url = self.mdict['pki_issuing_ca']

        else:
            ca_hostname = subsystem.config['securitydomain.host']
            ca_port = subsystem.config['securitydomain.httpsadminport']
            ca_url = 'https://%s:%s' % (ca_hostname, ca_port)

        logger.info('Requesting admin cert from %s', ca_url)

        request_type = self.mdict['pki_admin_cert_request_type']

        key_type = self.mdict['pki_admin_key_type']

        if key_type.lower() == 'ecc':
            profile = 'caECAdminCert'
        else:
            profile = self.mdict['pki_admin_profile_id']

        subject = self.mdict['pki_admin_subject_dn']

        pem_cert = self.request_cert(
            ca_url,
            request_type,
            base64_csr,
            profile,
            subject)

        logger.debug('Admin cert:\n%s', pem_cert)

        self.store_admin_cert(pem_cert)
        self.export_admin_pkcs12()

        return pem_cert

    def setup_admin_user(self, subsystem, cert_data):

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

        groups = ['Administrators']

        if subsystem.type == 'CA':
            groups.append('Certificate Manager Agents')

        elif subsystem.type == 'KRA':
            groups.append('Data Recovery Manager Agents')

        elif subsystem.type == 'OCSP':
            groups.append('Online Certificate Status Manager Agents')

        elif subsystem.type == 'TKS':
            groups.append('Token Key Service Manager Agents')

        elif subsystem.type == 'TPS':
            groups.append('TPS Agents')
            groups.append('TPS Operators')

        if subsystem.config.get('securitydomain.select') == 'new':

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
        subsystem.add_user_cert(uid, cert_data=cert_data.encode(), cert_format='PEM')

    def setup_subsystem_user(self, subsystem, cert):

        server_config = self.instance.get_server_config()
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
            # TODO: ignore failure only if user already exists in the group

    def backup_keys(self, subsystem):

        tmpdir = tempfile.mkdtemp()
        try:
            password_file = os.path.join(tmpdir, 'password.txt')
            with open(password_file, 'w', encoding='utf-8') as f:
                f.write(self.mdict['pki_backup_password'])

            cmd = [
                'pki-server',
                'subsystem-cert-export',
                subsystem.name,
                '-i', self.instance.name,
                '--pkcs12-file', self.mdict['pki_backup_file'],
                '--pkcs12-password-file', password_file
            ]

            logger.debug('Command: %s', ' '.join(cmd))
            subprocess.run(cmd, check=True)

        finally:
            shutil.rmtree(tmpdir)

    def setup_database_user(self, subsystem):

        logger.info('Adding pkidbuser')
        subsystem.add_user(
            'pkidbuser',
            full_name='pkidbuser',
            user_type='agentType',
            state='1',
            attributes={
                'nsPagedSizeLimit': '20000'
            })
        subsystem_cert = subsystem.get_subsystem_cert('subsystem')
        subject = subsystem_cert['subject']

        nssdb = self.instance.open_nssdb()
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
                with open(install_token, 'w', encoding='utf-8') as f:
                    f.write(session)

            cmd = [
                'pki',
                '-d', self.instance.nssdb_dir,
                '-f', self.instance.password_conf,
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
                with open(cert_file, 'w', encoding='utf-8') as f:
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

    def get_ca_signing_cert(self, ca_url):

        cmd = [
            'pki',
            '-d', self.instance.nssdb_dir,
            '-f', self.instance.password_conf,
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

    def get_ca_subsystem_cert(self, ca_url):

        cmd = [
            'pki',
            '-d', self.instance.nssdb_dir,
            '-f', self.instance.password_conf,
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

    def add_kra_connector(self, subsystem, ca_url):

        server_config = self.instance.get_server_config()
        hostname = self.mdict['pki_hostname']
        securePort = server_config.get_secure_port()

        kra_url = 'https://%s:%s/kra/agent/kra/connector' % (hostname, securePort)

        subsystem_cert = subsystem.get_subsystem_cert('subsystem').get('data')
        transport_cert_info = subsystem.get_subsystem_cert('transport')
        transport_cert = transport_cert_info.get('data')
        transport_nickname = transport_cert_info.get('nickname')

        tmpdir = tempfile.mkdtemp()
        try:
            subsystem_cert_file = os.path.join(tmpdir, 'subsystem.crt')
            with open(subsystem_cert_file, 'w', encoding='utf-8') as f:
                f.write(subsystem_cert)

            transport_cert_file = os.path.join(tmpdir, 'transport.crt')
            with open(transport_cert_file, 'w', encoding='utf-8') as f:
                f.write(transport_cert)

            install_token = os.path.join(tmpdir, 'install-token')
            with open(install_token, 'w', encoding='utf-8') as f:
                f.write(self.install_token.token)

            cmd = [
                'pki',
                '-d', self.instance.nssdb_dir,
                '-f', self.instance.password_conf,
                '-U', ca_url,
                '--ignore-banner',
                'ca-kraconnector-add',
                '--url', kra_url,
                '--subsystem-cert', subsystem_cert_file,
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

    def add_ocsp_publisher(self, subsystem, ca_url):

        server_config = self.instance.get_server_config()
        hostname = self.mdict['pki_hostname']
        securePort = server_config.get_secure_port()

        ocsp_url = 'https://%s:%s' % (hostname, securePort)

        subsystem_cert = subsystem.get_subsystem_cert('subsystem').get('data')

        tmpdir = tempfile.mkdtemp()
        try:
            subsystem_cert_file = os.path.join(tmpdir, 'subsystem.crt')
            with open(subsystem_cert_file, 'w', encoding='utf-8') as f:
                f.write(subsystem_cert)

            install_token = os.path.join(tmpdir, 'install-token')
            with open(install_token, 'w', encoding='utf-8') as f:
                f.write(self.install_token.token)

            cmd = [
                'pki',
                '-d', self.instance.nssdb_dir,
                '-f', self.instance.password_conf,
                '-U', ca_url,
                '--ignore-banner',
                'ca-publisher-ocsp-add',
                '--url', ocsp_url,
                '--subsystem-cert', subsystem_cert_file,
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

    def get_kra_transport_cert(self):

        kra_url = self.mdict['pki_kra_uri']

        cmd = [
            'pki',
            '-d', self.instance.nssdb_dir,
            '-f', self.instance.password_conf,
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

    def set_tks_transport_cert(self, cert, session=None, install_token=None):

        tks_url = self.mdict['pki_tks_uri']
        sd_url = self.mdict['pki_security_domain_uri']

        hostname = self.mdict['pki_hostname']

        server_config = self.instance.get_server_config()
        secure_port = server_config.get_secure_port()

        nickname = 'transportCert-%s-%s' % (hostname, secure_port)

        tmpdir = tempfile.mkdtemp()
        try:
            if not install_token:
                install_token = os.path.join(tmpdir, 'install-token')
                with open(install_token, 'w', encoding='utf-8') as f:
                    f.write(session)

            cmd = [
                'pki',
                '-d', self.instance.nssdb_dir,
                '-f', self.instance.password_conf,
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

            # don't use text param to support Python 3.6
            # https://stackoverflow.com/questions/52663518/python-subprocess-popen-doesnt-take-text-argument

            subprocess.run(
                cmd,
                input=cert,
                universal_newlines=True,
                check=True)

        finally:
            shutil.rmtree(tmpdir)

    def get_tps_connector(self, subsystem):

        tks_uri = self.mdict['pki_tks_uri']
        subsystem_cert = subsystem.get_subsystem_cert('subsystem')

        nickname = subsystem_cert['nickname']
        token = subsystem_cert['token']

        if not pki.nssdb.internal_token(token):
            nickname = token + ':' + nickname

        server_config = self.instance.get_server_config()
        securePort = server_config.get_secure_port()

        cmd = [
            'pki',
            '-U', tks_uri,
            '-d', self.instance.nssdb_dir,
            '-f', self.instance.password_conf,
            '-n', nickname,
            '--ignore-banner',
            'tks-tpsconnector-show',
            '--host', self.mdict['pki_hostname'],
            '--port', securePort
        ]

        logger.debug('Command: %s', ' '.join(cmd))
        result = subprocess.run(cmd, stdout=subprocess.PIPE, check=False)

        if result.returncode == 0:
            return json.loads(result.stdout.decode())
        else:
            return None

    def create_tps_connector(self, subsystem):

        tks_uri = self.mdict['pki_tks_uri']
        subsystem_cert = subsystem.get_subsystem_cert('subsystem')

        nickname = subsystem_cert['nickname']
        token = subsystem_cert['token']

        if not pki.nssdb.internal_token(token):
            nickname = token + ':' + nickname

        server_config = self.instance.get_server_config()
        securePort = server_config.get_secure_port()

        cmd = [
            'pki',
            '-U', tks_uri,
            '-d', self.instance.nssdb_dir,
            '-f', self.instance.password_conf,
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

    def get_shared_secret(self, subsystem, tps_connector_id):

        tks_uri = self.mdict['pki_tks_uri']
        subsystem_cert = subsystem.get_subsystem_cert('subsystem')

        nickname = subsystem_cert['nickname']
        token = subsystem_cert['token']

        if not pki.nssdb.internal_token(token):
            nickname = token + ':' + nickname

        cmd = [
            'pki',
            '-U', tks_uri,
            '-d', self.instance.nssdb_dir,
            '-f', self.instance.password_conf,
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

    def create_shared_secret(self, subsystem, tps_connector_id):

        tks_uri = self.mdict['pki_tks_uri']
        subsystem_cert = subsystem.get_subsystem_cert('subsystem')

        nickname = subsystem_cert['nickname']
        token = subsystem_cert['token']

        if not pki.nssdb.internal_token(token):
            nickname = token + ':' + nickname

        cmd = [
            'pki',
            '-U', tks_uri,
            '-d', self.instance.nssdb_dir,
            '-f', self.instance.password_conf,
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

    def replace_shared_secret(self, subsystem, tps_connector_id):

        tks_uri = self.mdict['pki_tks_uri']
        subsystem_cert = subsystem.get_subsystem_cert('subsystem')

        nickname = subsystem_cert['nickname']
        token = subsystem_cert['token']

        if not pki.nssdb.internal_token(token):
            nickname = token + ':' + nickname

        cmd = [
            'pki',
            '-U', tks_uri,
            '-d', self.instance.nssdb_dir,
            '-f', self.instance.password_conf,
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

    def import_shared_secret(self, subsystem, secret_nickname, shared_secret):

        subsystem_cert = subsystem.get_subsystem_cert('subsystem')

        nickname = subsystem_cert['nickname']
        token = subsystem_cert['token']

        if not pki.nssdb.internal_token(token):
            nickname = token + ':' + nickname

        cmd = [
            'pki',
            '-d', self.instance.nssdb_dir,
            '-f', self.instance.password_conf,
            'nss-key-import', secret_nickname,
            '--wrapper', nickname
        ]

        logger.debug('Command: %s', ' '.join(cmd))

        # don't use text param to support Python 3.6
        # https://stackoverflow.com/questions/52663518/python-subprocess-popen-doesnt-take-text-argument

        subprocess.run(
            cmd,
            input=json.dumps(shared_secret),
            universal_newlines=True,
            check=True)

    def setup_shared_secret(self, subsystem):

        # This method configures the shared secret between TKS and TPS. The shared secret
        # is initially generated in TKS, then exported from TKS, and reimported into TPS.
        # However, if TKS and TPS are running on the same instance, it is not necessary
        # to export and reimport since they are sharing the same NSS database.

        # TODO: Clean up the code and determine whether TKS and TPS are in the same
        # instance automatically.

        hostname = self.mdict['pki_hostname']

        server_config = self.instance.get_server_config()
        securePort = server_config.get_secure_port()

        secret_nickname = 'TPS-%s-%s sharedSecret' % (hostname, securePort)

        logger.info('Searching for TPS connector in TKS')
        tps_connector = self.get_tps_connector(subsystem)

        if tps_connector:
            logger.info('Getting shared secret')
            tps_connector_id = tps_connector['id']
            shared_secret = self.get_shared_secret(subsystem, tps_connector_id)

            if shared_secret:
                logger.info('Replacing shared secret')
                shared_secret = self.replace_shared_secret(subsystem, tps_connector_id)

            else:
                logger.info('Creating shared secret')
                shared_secret = self.create_shared_secret(subsystem, tps_connector_id)

        else:
            logger.info('Creating a new TPS connector')
            tps_connector = self.create_tps_connector(subsystem)
            tps_connector_id = tps_connector['id']

            logger.info('Creating shared secret')
            shared_secret = self.create_shared_secret(subsystem, tps_connector_id)

        if config.str2bool(self.mdict['pki_import_shared_secret']):
            logger.info('Importing shared secret')
            self.import_shared_secret(subsystem, secret_nickname, shared_secret)

        subsystem.config['conn.tks1.tksSharedSymKeyName'] = secret_nickname
        subsystem.save()

    def finalize_ca(self, subsystem):

        if config.str2bool(self.mdict['pki_master_crl_enable']):
            logger.info('Enabling CRL')
            subsystem.config['ca.crl.MasterCRL.enable'] = 'true'
        else:
            logger.info('Disabling CRL')
            subsystem.config['ca.crl.MasterCRL.enable'] = 'false'

        clone = self.configuration_file.clone

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

    def finalize_kra(self, subsystem):

        ca_type = subsystem.config.get('preop.ca.type')

        if ca_type:
            subsystem.config['cloning.ca.type'] = ca_type

        clone = self.configuration_file.clone
        standalone = self.configuration_file.standalone

        if not clone:
            logger.info('Updating KRA ranges')
            subsystem.update_ranges()

        if standalone:
            ca_url = None
        else:
            ca_url = self.mdict['pki_issuing_ca']

        if ca_url and not clone:

            url = urllib.parse.urlparse(ca_url)
            ca_host = url.hostname
            ca_port = str(url.port)

            ca_uid = 'CA-%s-%s' % (ca_host, ca_port)

            logger.info('Adding %s user into KRA', ca_uid)
            subsystem.add_user(
                ca_uid,
                full_name=ca_uid,
                user_type='agentType',
                state='1')

            logger.info('Getting CA subsystem certificate from %s', ca_url)
            subsystem_cert_data = self.get_ca_subsystem_cert(ca_url)

            logger.info('Adding CA subsystem certificate into %s', ca_uid)
            subsystem.add_user_cert(ca_uid, cert_data=subsystem_cert_data, cert_format='PEM')

            logger.info('Adding %s into Trusted Managers', ca_uid)
            subsystem.add_group_member('Trusted Managers', ca_uid)

        if ca_url:

            logger.info('Adding KRA connector in CA')
            self.add_kra_connector(subsystem, ca_url)

    def finalize_ocsp(self, subsystem):

        ca_type = subsystem.config.get('preop.ca.type')

        if ca_type:
            subsystem.config['cloning.ca.type'] = ca_type

        clone = self.configuration_file.clone
        standalone = self.configuration_file.standalone

        if standalone:
            ca_url = None
        else:
            ca_url = self.mdict['pki_issuing_ca']

        if ca_url and not clone:

            logger.info('Adding CRL issuing point')
            base64_chain = subsystem.config['preop.ca.pkcs7']
            cert_chain = base64.b64decode(base64_chain)
            subsystem.add_crl_issuing_point(cert_chain=cert_chain, cert_format='DER')

            url = urllib.parse.urlparse(ca_url)
            ca_host = url.hostname
            ca_port = str(url.port)

            ca_uid = 'CA-%s-%s' % (ca_host, ca_port)

            logger.info('Adding %s user into OCSP', ca_uid)
            subsystem.add_user(
                ca_uid,
                full_name=ca_uid,
                user_type='agentType',
                state='1')

            logger.info('Getting CA subsystem certificate from %s', ca_url)
            subsystem_cert_data = self.get_ca_subsystem_cert(ca_url)

            logger.info('Adding CA subsystem certificate into %s', ca_uid)
            subsystem.add_user_cert(ca_uid, cert_data=subsystem_cert_data, cert_format='PEM')

            logger.info('Adding %s into Trusted Managers', ca_uid)
            subsystem.add_group_member('Trusted Managers', ca_uid)

            logger.info('Adding OCSP publisher in CA')
            # For now don't register publishing with the CA for a clone,
            # preserving existing functionality.
            # Next we need to treat the publishing of clones as a group,
            # and fail over amongst them.
            self.add_ocsp_publisher(subsystem, ca_url)

    def finalize_tks(self, subsystem):

        ca_type = subsystem.config.get('preop.ca.type')

        if ca_type:
            subsystem.config['cloning.ca.type'] = ca_type

    def finalize_tps(self, subsystem):

        ca_type = subsystem.config.get('preop.ca.type')

        if ca_type:
            subsystem.config['cloning.ca.type'] = ca_type

        tps_uid = 'TPS-%s-%s' % (self.mdict['pki_hostname'], self.mdict['pki_https_port'])
        full_name = self.mdict['pki_subsystem_name']
        subsystem_cert = subsystem.get_subsystem_cert('subsystem').get('data')

        logger.info('Registering TPS in CA')
        self.add_subsystem_user(
            'ca',
            self.mdict['pki_ca_uri'],
            tps_uid,
            full_name,
            cert=subsystem_cert,
            session=self.install_token.token)

        logger.info('Registering TPS in TKS')
        self.add_subsystem_user(
            'tks',
            self.mdict['pki_tks_uri'],
            tps_uid,
            full_name,
            cert=subsystem_cert,
            session=self.install_token.token)

        keygen = config.str2bool(self.mdict['pki_enable_server_side_keygen'])

        if keygen:
            logger.info('Registering TPS in KRA')
            self.add_subsystem_user(
                'kra',
                self.mdict['pki_kra_uri'],
                tps_uid,
                full_name,
                cert=subsystem_cert,
                session=self.install_token.token)

            logger.info('Exporting transport cert from KRA')
            transport_cert = self.get_kra_transport_cert()

            logger.info('Importing transport cert into TKS')
            self.set_tks_transport_cert(
                transport_cert,
                session=self.install_token.token)

        logger.info('Setting up shared secret')
        self.setup_shared_secret(subsystem)

    def finalize_subsystem(self, subsystem):

        if subsystem.type == 'CA':
            self.finalize_ca(subsystem)

        if subsystem.type == 'KRA':
            self.finalize_kra(subsystem)

        if subsystem.type == 'OCSP':
            self.finalize_ocsp(subsystem)

        if subsystem.type == 'TKS':
            self.finalize_tks(subsystem)

        if subsystem.type == 'TPS':
            self.finalize_tps(subsystem)

        # save EC type for sslserver cert (if present)
        ec_type = subsystem.config.get('preop.cert.sslserver.ec.type', 'ECDHE')
        subsystem.config['jss.ssl.sslserver.ectype'] = ec_type

        for key in list(subsystem.config.keys()):
            if key.startswith('preop.'):
                del subsystem.config[key]

        subsystem.config['cs.state'] = '1'

        subsystem.save()

    def store_config(self):

        subsystem = self.instance.get_subsystem(self.subsystem_type.lower())

        # Store user's deployment.cfg into
        # /etc/sysconfig/pki/tomcat/<instance>/<subsystem>/deployment.cfg

        deployment_cfg = os.path.join(subsystem.registry_dir, 'deployment.cfg')
        logger.info('Creating %s', deployment_cfg)

        self.file.create(deployment_cfg)

        with open(deployment_cfg, 'w', encoding='utf-8') as f:
            self.user_config.write(f)

        # For debugging/auditing purposes, store user's deployment.cfg into
        # /var/log/pki/<instance>/<subsystem>/archive/spawn_deployment.cfg.<timestamp>

        deployment_cfg_archive = os.path.join(
            subsystem.log_archive_dir,
            'spawn_deployment.cfg.' + self.mdict['pki_timestamp'])
        logger.info('Creating %s', deployment_cfg_archive)

        self.file.copy(deployment_cfg, deployment_cfg_archive)

    def store_manifest(self):

        subsystem = self.instance.get_subsystem(self.subsystem_type.lower())

        # Store installation manifest into
        # /etc/sysconfig/pki/tomcat/<instance>/<subsystem>/manifest

        manifest_file = os.path.join(subsystem.registry_dir, 'manifest')
        logger.info('Creating %s', manifest_file)

        file = manifest.File(self.manifest_db)
        file.register(manifest_file)
        file.write()

        self.file.modify(manifest_file, silent=True)

        # For debugging/auditing purposes, store installation manifest into
        # /var/log/pki/<instance>/<subsystem>/archive/spawn_manifest.<timestamp>

        manifest_archive = os.path.join(
            subsystem.log_archive_dir,
            'spawn_manifest.' + self.mdict['pki_timestamp'])
        logger.info('Creating %s', manifest_archive)

        self.file.copy(manifest_file, manifest_archive)

    def restore_selinux_contexts(self):
        selinux.restorecon(self.instance.base_dir, True)
        selinux.restorecon(config.PKI_DEPLOYMENT_LOG_ROOT, True)
        selinux.restorecon(self.instance.log_dir, True)
        selinux.restorecon(self.instance.conf_dir, True)

    def selinux_context_exists(self, records, context_value):
        '''
        Check if a given `context_value` exists in the given set of `records`.
        This method can process both port contexts and file contexts.
        '''
        for keys in records.keys():
            for key in keys:
                if str(key) == context_value:
                    return True
        return False

    def create_selinux_contexts(self):

        suffix = '(/.*)?'

        trans = seobject.semanageRecords('targeted')
        trans.start()

        fcon = seobject.fcontextRecords(trans)

        logger.info('Adding SELinux fcontext "%s"', self.instance.conf_dir + suffix)
        fcon.add(
            self.instance.conf_dir + suffix,
            config.PKI_CFG_SELINUX_CONTEXT, '', 's0', '')

        logger.info('Adding SELinux fcontext "%s"', self.instance.nssdb_dir + suffix)
        fcon.add(
            self.instance.nssdb_dir + suffix,
            config.PKI_CERTDB_SELINUX_CONTEXT, '', 's0', '')

        logger.info('Adding SELinux fcontext "%s"', self.instance.base_dir + suffix)
        fcon.add(
            self.instance.base_dir + suffix,
            config.PKI_INSTANCE_SELINUX_CONTEXT, '', 's0', '')

        logger.info('Adding SELinux fcontext "%s"', self.instance.log_dir + suffix)
        fcon.add(
            self.instance.log_dir + suffix,
            config.PKI_LOG_SELINUX_CONTEXT, '', 's0', '')

        port_records = seobject.portRecords(trans)

        for port in config.pki_selinux_config_ports:
            logger.info('Adding SELinux port %s', port)
            port_records.add(
                port, 'tcp', 's0',
                config.PKI_PORT_SELINUX_CONTEXT)

        trans.finish()

    def remove_selinux_contexts(self):

        suffix = '(/.*)?'

        trans = seobject.semanageRecords('targeted')
        trans.start()

        port_records = seobject.portRecords(trans)
        port_record_values = port_records.get_all()

        for port in config.pki_selinux_config_ports:
            if self.selinux_context_exists(port_record_values, port):
                logger.info('Removing SELinux port %s', port)
                port_records.delete(port, 'tcp')

        fcon = seobject.fcontextRecords(trans)
        file_records = fcon.get_all()

        if self.selinux_context_exists(file_records, self.instance.log_dir + suffix):
            logger.info('Removing SELinux fcontext "%s"', self.instance.log_dir + suffix)
            fcon.delete(self.instance.log_dir + suffix, '')

        if self.selinux_context_exists(file_records, self.instance.base_dir + suffix):
            logger.info('Removing SELinux fcontext "%s"', self.instance.base_dir + suffix)
            fcon.delete(self.instance.base_dir + suffix, '')

        if self.selinux_context_exists(file_records, self.instance.nssdb_dir + suffix):
            logger.info('Removing SELinux fcontext "%s"', self.instance.nssdb_dir + suffix)
            fcon.delete(self.instance.nssdb_dir + suffix, '')

        if self.selinux_context_exists(file_records, self.instance.conf_dir + suffix):
            logger.info('Removing SELinux fcontext "%s"', self.instance.conf_dir + suffix)
            fcon.delete(self.instance.conf_dir + suffix, '')

        trans.finish()

    def spawn(self):

        print('Installing ' + self.subsystem_type + ' into ' + self.instance.base_dir + '.')

        scriptlet = pki.server.deployment.scriptlets.initialization.PkiScriptlet()
        scriptlet.deployer = self
        scriptlet.instance = self.instance
        scriptlet.spawn(self)

        scriptlet = pki.server.deployment.scriptlets.infrastructure_layout.PkiScriptlet()
        scriptlet.deployer = self
        scriptlet.instance = self.instance
        scriptlet.spawn(self)

        scriptlet = pki.server.deployment.scriptlets.instance_layout.PkiScriptlet()
        scriptlet.deployer = self
        scriptlet.instance = self.instance
        scriptlet.spawn(self)

        scriptlet = pki.server.deployment.scriptlets.subsystem_layout.PkiScriptlet()
        scriptlet.deployer = self
        scriptlet.instance = self.instance
        scriptlet.spawn(self)

        scriptlet = pki.server.deployment.scriptlets.security_databases.PkiScriptlet()
        scriptlet.deployer = self
        scriptlet.instance = self.instance
        scriptlet.spawn(self)

        scriptlet = pki.server.deployment.scriptlets.selinux_setup.PkiScriptlet()
        scriptlet.deployer = self
        scriptlet.instance = self.instance
        scriptlet.spawn(self)

        scriptlet = pki.server.deployment.scriptlets.keygen.PkiScriptlet()
        scriptlet.deployer = self
        scriptlet.instance = self.instance
        scriptlet.spawn(self)

        scriptlet = pki.server.deployment.scriptlets.fapolicy_setup.PkiScriptlet()
        scriptlet.deployer = self
        scriptlet.instance = self.instance
        scriptlet.spawn(self)

        scriptlet = pki.server.deployment.scriptlets.configuration.PkiScriptlet()
        scriptlet.deployer = self
        scriptlet.instance = self.instance
        scriptlet.spawn(self)

        scriptlet = pki.server.deployment.scriptlets.finalization.PkiScriptlet()
        scriptlet.deployer = self
        scriptlet.instance = self.instance
        scriptlet.spawn(self)

    def destroy(self):

        print('Uninstalling ' + self.subsystem_type + ' from ' + self.instance.base_dir + '.')

        scriptlet = pki.server.deployment.scriptlets.initialization.PkiScriptlet()
        scriptlet.deployer = self
        scriptlet.instance = self.instance
        scriptlet.destroy(self)

        scriptlet = pki.server.deployment.scriptlets.configuration.PkiScriptlet()
        scriptlet.deployer = self
        scriptlet.instance = self.instance
        scriptlet.destroy(self)

        scriptlet = pki.server.deployment.scriptlets.keygen.PkiScriptlet()
        scriptlet.deployer = self
        scriptlet.instance = self.instance
        scriptlet.destroy(self)

        scriptlet = pki.server.deployment.scriptlets.subsystem_layout.PkiScriptlet()
        scriptlet.deployer = self
        scriptlet.instance = self.instance
        scriptlet.destroy(self)

        scriptlet = pki.server.deployment.scriptlets.security_databases.PkiScriptlet()
        scriptlet.deployer = self
        scriptlet.instance = self.instance
        scriptlet.destroy(self)

        scriptlet = pki.server.deployment.scriptlets.instance_layout.PkiScriptlet()
        scriptlet.deployer = self
        scriptlet.instance = self.instance
        scriptlet.destroy(self)

        scriptlet = pki.server.deployment.scriptlets.selinux_setup.PkiScriptlet()
        scriptlet.deployer = self
        scriptlet.instance = self.instance
        scriptlet.destroy(self)

        scriptlet = pki.server.deployment.scriptlets.infrastructure_layout.PkiScriptlet()
        scriptlet.deployer = self
        scriptlet.instance = self.instance
        scriptlet.destroy(self)

        scriptlet = pki.server.deployment.scriptlets.finalization.PkiScriptlet()
        scriptlet.deployer = self
        scriptlet.instance = self.instance
        scriptlet.destroy(self)

        scriptlet = pki.server.deployment.scriptlets.fapolicy_setup.PkiScriptlet()
        scriptlet.deployer = self
        scriptlet.instance = self.instance
        scriptlet.destroy(self)
