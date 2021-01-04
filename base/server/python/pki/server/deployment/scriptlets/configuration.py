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
# Copyright (C) 2012 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import logging
import os
import shutil
import subprocess
import tempfile
import urllib.parse

# PKI Deployment Imports
from .. import pkiconfig as config
from .. import pkiscriptlet

import pki.encoder
import pki.nssdb
import pki.server
import pki.server.instance
import pki.system
import pki.util

logger = logging.getLogger('configuration')


# PKI Deployment Configuration Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):

    def get_cert_id(self, subsystem, tag):

        if tag == 'signing':
            return '%s_%s' % (subsystem.name, tag)
        else:
            return tag

    def import_system_cert_request(self, deployer, subsystem, tag):

        cert_id = self.get_cert_id(subsystem, tag)

        csr_path = deployer.mdict.get('pki_%s_csr_path' % cert_id)
        if not csr_path or not os.path.exists(csr_path):
            return

        logger.info('Importing %s CSR from %s', tag, csr_path)

        with open(csr_path) as f:
            csr_data = f.read()

        b64_csr = pki.nssdb.convert_csr(csr_data, 'pem', 'base64')
        subsystem.config['%s.%s.certreq' % (subsystem.name, tag)] = b64_csr

    def import_ca_signing_csr(self, deployer, subsystem):

        csr_path = deployer.mdict.get('pki_ca_signing_csr_path')
        if not csr_path or not os.path.exists(csr_path):
            return

        logger.info('Importing ca_signing CSR from %s', csr_path)

        with open(csr_path) as f:
            csr_data = f.read()

        b64_csr = pki.nssdb.convert_csr(csr_data, 'pem', 'base64')
        subsystem.config['ca.signing.certreq'] = b64_csr

    def import_system_cert_requests(self, deployer, subsystem):

        if subsystem.name == 'ca':
            self.import_ca_signing_csr(deployer, subsystem)
            self.import_system_cert_request(deployer, subsystem, 'ocsp_signing')

        if subsystem.name == 'kra':
            self.import_system_cert_request(deployer, subsystem, 'storage')
            self.import_system_cert_request(deployer, subsystem, 'transport')

        if subsystem.name == 'ocsp':
            self.import_system_cert_request(deployer, subsystem, 'signing')

        self.import_system_cert_request(deployer, subsystem, 'audit_signing')
        self.import_system_cert_request(deployer, subsystem, 'subsystem')
        self.import_system_cert_request(deployer, subsystem, 'sslserver')

    def import_ca_signing_cert(self, deployer, nssdb):

        param = 'pki_ca_signing_cert_path'
        cert_file = deployer.mdict.get(param)

        if not cert_file:
            return

        if not os.path.exists(cert_file):
            raise Exception('Invalid certificate path: %s=%s' % (param, cert_file))

        nickname = deployer.mdict['pki_ca_signing_nickname']

        logger.info('Importing ca_signing certificate from %s', cert_file)

        nssdb.import_cert_chain(
            nickname=nickname,
            cert_chain_file=cert_file,
            trust_attributes='CT,C,C')

    def import_system_cert(
            self, deployer, nssdb, subsystem, tag,
            trust_attributes=None):

        cert_id = self.get_cert_id(subsystem, tag)
        param = 'pki_%s_cert_path' % cert_id
        cert_file = deployer.mdict.get(param)

        if not cert_file or not os.path.exists(cert_file):
            return

        logger.info('Importing %s certificate from %s', cert_id, cert_file)

        cert = subsystem.get_subsystem_cert(tag)
        nickname = cert['nickname']
        token = pki.nssdb.normalize_token(cert['token'])

        if not token:
            token = deployer.mdict['pki_token_name']

        nssdb.import_cert_chain(
            nickname=nickname,
            cert_chain_file=cert_file,
            token=token,
            trust_attributes=trust_attributes)

    def import_admin_cert(self, deployer):

        cert_file = deployer.mdict.get('pki_admin_cert_path')
        if not cert_file or not os.path.exists(cert_file):
            return

        nickname = deployer.mdict['pki_admin_nickname']

        client_nssdb = pki.nssdb.NSSDatabase(
            directory=deployer.mdict['pki_client_database_dir'],
            password=deployer.mdict['pki_client_database_password'])

        try:
            logger.info('Importing admin certificate from %s', cert_file)

            client_nssdb.import_cert_chain(
                nickname=nickname,
                cert_chain_file=cert_file,
                trust_attributes=',,')

        finally:
            client_nssdb.close()

    def import_certs_and_keys(self, deployer, nssdb):

        pkcs12_file = deployer.mdict.get('pki_external_pkcs12_path')
        if not pkcs12_file or not os.path.exists(pkcs12_file):
            return

        logger.info('Importing certificates and keys from %s', pkcs12_file)

        pkcs12_password = deployer.mdict['pki_external_pkcs12_password']
        nssdb.import_pkcs12(pkcs12_file, pkcs12_password)

    def import_cert_chain(self, deployer, nssdb):

        chain_file = deployer.mdict.get('pki_cert_chain_path')

        if not chain_file or not os.path.exists(chain_file):
            return

        nickname = deployer.mdict['pki_cert_chain_nickname']

        logger.info('Importing certificate chain from %s', chain_file)

        nssdb.import_cert_chain(
            nickname=nickname,
            cert_chain_file=chain_file,
            trust_attributes='CT,C,C')

    def import_system_certs(self, deployer, nssdb, subsystem):

        if subsystem.name == 'ca':
            self.import_system_cert(deployer, nssdb, subsystem, 'signing', 'CT,C,C')
            self.import_system_cert(deployer, nssdb, subsystem, 'ocsp_signing')

        if subsystem.name == 'kra':
            self.import_ca_signing_cert(deployer, nssdb)

            self.import_system_cert(deployer, nssdb, subsystem, 'storage')
            self.import_system_cert(deployer, nssdb, subsystem, 'transport')
            self.import_admin_cert(deployer)

        if subsystem.name == 'ocsp':
            self.import_ca_signing_cert(deployer, nssdb)

            self.import_system_cert(deployer, nssdb, subsystem, 'signing')
            self.import_admin_cert(deployer)

        sslserver = subsystem.get_subsystem_cert('sslserver')
        nickname = sslserver['nickname']
        token = sslserver['token']
        subsystem.instance.set_sslserver_cert_nickname(nickname, token)

        self.import_system_cert(deployer, nssdb, subsystem, 'sslserver')
        self.import_system_cert(deployer, nssdb, subsystem, 'subsystem')
        self.import_system_cert(deployer, nssdb, subsystem, 'audit_signing', ',,P')

        # If provided, import certs and keys from PKCS #12 file
        # into NSS database.

        self.import_certs_and_keys(deployer, nssdb)

        # If provided, import cert chain into NSS database.
        # Note: Cert chain must be imported after the system certs
        # to ensure that the system certs are imported with
        # the correct nicknames.

        self.import_cert_chain(deployer, nssdb)

    def configure_system_cert(self, deployer, subsystem, tag):

        cert_id = self.get_cert_id(subsystem, tag)
        nickname = deployer.mdict['pki_%s_nickname' % cert_id]

        subsystem.config['%s.%s.nickname' % (subsystem.name, tag)] = nickname
        subsystem.config['%s.%s.tokenname' % (subsystem.name, tag)] = \
            deployer.mdict['pki_%s_token' % cert_id]
        subsystem.config['%s.%s.defaultSigningAlgorithm' % (subsystem.name, tag)] = \
            deployer.mdict['pki_%s_key_algorithm' % cert_id]

    def update_system_cert(self, deployer, nssdb, subsystem, tag):

        cert_id = self.get_cert_id(subsystem, tag)
        nickname = deployer.mdict['pki_%s_nickname' % cert_id]

        cert_data = nssdb.get_cert(
            nickname=nickname,
            output_format='base64',
            output_text=True,
        )

        subsystem.config['%s.%s.cert' % (subsystem.name, tag)] = cert_data

    def configure_ca_signing_cert(self, deployer, subsystem):

        logger.info('Configuring ca_signing certificate')

        self.configure_system_cert(deployer, subsystem, 'signing')

        nickname = deployer.mdict['pki_ca_signing_nickname']
        subsystem.config['ca.signing.cacertnickname'] = nickname

    def configure_ca_ocsp_signing_cert(self, deployer, subsystem):

        logger.info('Configuring ca_ocsp_signing certificate')

        self.configure_system_cert(deployer, subsystem, 'ocsp_signing')

    def configure_sslserver_cert(self, deployer, subsystem):

        logger.info('Configuring sslserver certificate')

        self.configure_system_cert(deployer, subsystem, 'sslserver')

    def configure_subsystem_cert(self, deployer, subsystem):

        logger.info('Configuring subsystem certificate')

        self.configure_system_cert(deployer, subsystem, 'subsystem')

    def configure_audit_signing_cert(self, deployer, subsystem):

        logger.info('Configuring audit_signing certificate')

        self.configure_system_cert(deployer, subsystem, 'audit_signing')

    def update_admin_cert(self, deployer, subsystem):

        logger.info('Updating admin certificate')

        client_nssdb = pki.nssdb.NSSDatabase(
            directory=deployer.mdict['pki_client_database_dir'],
            password=deployer.mdict['pki_client_database_password'])

        try:
            nickname = deployer.mdict['pki_admin_nickname']
            cert_data = client_nssdb.get_cert(
                nickname=nickname,
                output_format='base64',
                output_text=True,
            )

            subsystem.config['%s.admin.cert' % subsystem.name] = cert_data

        finally:
            client_nssdb.close()

    def configure_kra_storage_cert(self, deployer, subsystem):

        logger.info('Configuring kra_storage certificate')

        self.configure_system_cert(deployer, subsystem, 'storage')

    def configure_kra_transport_cert(self, deployer, subsystem):

        logger.info('Configuring kra_transport certificate')

        self.configure_system_cert(deployer, subsystem, 'transport')

    def configure_ocsp_signing_cert(self, deployer, subsystem):

        logger.info('Configuring ocsp_signing certificate')

        self.configure_system_cert(deployer, subsystem, 'signing')

    def configure_system_certs(self, deployer, subsystem):

        if subsystem.name == 'ca':
            self.configure_ca_signing_cert(deployer, subsystem)
            self.configure_ca_ocsp_signing_cert(deployer, subsystem)

        if subsystem.name == 'kra':
            self.configure_kra_storage_cert(deployer, subsystem)
            self.configure_kra_transport_cert(deployer, subsystem)

        if subsystem.name == 'ocsp':
            self.configure_ocsp_signing_cert(deployer, subsystem)

        self.configure_sslserver_cert(deployer, subsystem)
        self.configure_subsystem_cert(deployer, subsystem)
        self.configure_audit_signing_cert(deployer, subsystem)

    def update_system_certs(self, deployer, nssdb, subsystem):

        if subsystem.name == 'ca':
            self.update_system_cert(deployer, nssdb, subsystem, 'signing')
            self.update_system_cert(deployer, nssdb, subsystem, 'ocsp_signing')

        if subsystem.name == 'kra':
            self.update_system_cert(deployer, nssdb, subsystem, 'storage')
            self.update_system_cert(deployer, nssdb, subsystem, 'transport')
            self.update_admin_cert(deployer, subsystem)

        if subsystem.name == 'ocsp':
            self.update_system_cert(deployer, nssdb, subsystem, 'signing')
            self.update_admin_cert(deployer, subsystem)

        self.update_system_cert(deployer, nssdb, subsystem, 'sslserver')
        self.update_system_cert(deployer, nssdb, subsystem, 'subsystem')
        self.update_system_cert(deployer, nssdb, subsystem, 'audit_signing')

    def validate_system_cert(self, deployer, nssdb, subsystem, tag):

        cert_id = self.get_cert_id(subsystem, tag)
        nickname = deployer.mdict['pki_%s_nickname' % cert_id]
        cert_data = nssdb.get_cert(
            nickname=nickname)

        if not cert_data:
            return

        logger.info('Validating %s certificate', tag)

        subsystem.validate_system_cert(tag)

    def validate_system_certs(self, deployer, nssdb, subsystem):

        if subsystem.name == 'ca':
            self.validate_system_cert(deployer, nssdb, subsystem, 'signing')
            self.validate_system_cert(deployer, nssdb, subsystem, 'ocsp_signing')

        if subsystem.name == 'kra':
            self.validate_system_cert(deployer, nssdb, subsystem, 'storage')
            self.validate_system_cert(deployer, nssdb, subsystem, 'transport')

        if subsystem.name == 'ocsp':
            self.validate_system_cert(deployer, nssdb, subsystem, 'signing')

        self.validate_system_cert(deployer, nssdb, subsystem, 'sslserver')
        self.validate_system_cert(deployer, nssdb, subsystem, 'subsystem')
        self.validate_system_cert(deployer, nssdb, subsystem, 'audit_signing')

    def create_temp_sslserver_cert(self, deployer, instance):

        if len(deployer.instance.tomcat_instance_subsystems()) > 1:
            return False

        nickname = deployer.mdict['pki_sslserver_nickname']
        instance.set_sslserver_cert_nickname(nickname)

        tmpdir = tempfile.mkdtemp()
        nssdb = instance.open_nssdb()

        try:
            logger.info('Checking existing SSL server cert: %s', nickname)
            pem_cert = nssdb.get_cert(nickname=nickname)

            if pem_cert:
                cert = x509.load_pem_x509_certificate(pem_cert, default_backend())
                cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]
                hostname = cn.value

                logger.info('Existing SSL server cert is for %s', hostname)

                # if hostname is correct, don't create temp cert
                if hostname == deployer.mdict['pki_hostname']:
                    return False

                logger.info('Removing SSL server cert for %s', hostname)

                nssdb.remove_cert(
                    nickname=nickname,
                    remove_key=True)

            logger.info('Creating temp SSL server cert for %s', deployer.mdict['pki_hostname'])

            # TODO: replace with pki-server create-cert --temp sslserver

            # NOTE:  ALWAYS create the temporary sslserver certificate
            #        in the software DB regardless of whether the
            #        instance will utilize 'softokn' or an HSM

            csr_file = os.path.join(tmpdir, 'sslserver.csr')
            cert_file = os.path.join(tmpdir, 'sslserver.crt')

            nssdb.create_request(
                subject_dn=deployer.mdict['pki_self_signed_subject'],
                request_file=csr_file,
                token=deployer.mdict['pki_self_signed_token'],
                key_type=deployer.mdict['pki_sslserver_key_type'],
                key_size=deployer.mdict['pki_sslserver_key_size']
            )

            nssdb.create_cert(
                request_file=csr_file,
                cert_file=cert_file,
                serial=deployer.mdict['pki_self_signed_serial_number'],
                validity=deployer.mdict['pki_self_signed_validity_period']
            )

            nssdb.add_cert(
                nickname=nickname,
                cert_file=cert_file,
                token=deployer.mdict['pki_self_signed_token'],
                trust_attributes=deployer.mdict['pki_self_signed_trustargs']
            )

            return True

        finally:
            nssdb.close()
            shutil.rmtree(tmpdir)

    def remove_temp_sslserver_cert(self, instance, sslserver):

        # TODO: replace with pki-server cert-import sslserver

        nickname = sslserver['nickname']
        token = sslserver['token']

        logger.info(
            'Removing temp SSL server cert from internal token: %s',
            nickname)

        nssdb = instance.open_nssdb()

        try:
            # Remove temp SSL server cert from internal token.
            # Remove temp key too if the perm cert uses HSM.
            if pki.nssdb.normalize_token(token):
                remove_key = True
            else:
                remove_key = False
            nssdb.remove_cert(
                nickname=nickname,
                remove_key=remove_key)

        finally:
            nssdb.close()

    def import_perm_sslserver_cert(self, deployer, instance, cert):

        nickname = cert['nickname']
        token = pki.nssdb.normalize_token(cert['token'])

        if not token:
            token = deployer.mdict['pki_token_name']

        logger.info(
            'Importing permanent SSL server cert into %s token: %s',
            token, nickname)

        tmpdir = tempfile.mkdtemp()
        nssdb = instance.open_nssdb(token)

        try:
            pem_cert = pki.nssdb.convert_cert(cert['data'], 'base64', 'pem')

            cert_file = os.path.join(tmpdir, 'sslserver.crt')
            with open(cert_file, 'w') as f:
                f.write(pem_cert)

            nssdb.add_cert(
                nickname=nickname,
                cert_file=cert_file)

        finally:
            nssdb.close()
            shutil.rmtree(tmpdir)

    def get_cert_chain(self, instance, url):

        cmd = [
            'pki',
            '-d', instance.nssdb_dir,
            '-f', instance.password_conf,
            '-U', url,
            '--ignore-cert-status', 'UNTRUSTED_ISSUER',
            'ca-cert-signing-export',
            '--pkcs7'
        ]

        logger.debug('Command: %s', ' '.join(cmd))
        output = subprocess.check_output(cmd)

        return output.decode()

    def spawn(self, deployer):

        external = deployer.configuration_file.external
        standalone = deployer.configuration_file.standalone
        step_one = deployer.configuration_file.external_step_one
        skip_configuration = deployer.configuration_file.skip_configuration

        if (external or standalone) and step_one or skip_configuration:
            logger.info('Skipping configuration')
            return

        logger.info('Configuring subsystem')

        try:
            startup_timeout = int(os.environ['PKISPAWN_STARTUP_TIMEOUT_SECONDS'])
        except (KeyError, ValueError):
            startup_timeout = 60

        if startup_timeout <= 0:
            startup_timeout = 60

        # Configure status request timeout. This is used for each
        # status request in wait_for_startup().
        value = deployer.mdict['pki_status_request_timeout']
        if len(value) == 0:
            request_timeout = None
        else:
            request_timeout = int(value)
            if request_timeout <= 0:
                raise ValueError("timeout must be greater than zero")

        instance = self.instance
        instance.load()

        subsystems = instance.get_subsystems()
        subsystem = instance.get_subsystem(deployer.mdict['pki_subsystem'].lower())

        # configure internal database
        subsystem.config['internaldb.ldapconn.host'] = deployer.mdict['pki_ds_hostname']

        if config.str2bool(deployer.mdict['pki_ds_secure_connection']):
            subsystem.config['internaldb.ldapconn.secureConn'] = 'true'
            subsystem.config['internaldb.ldapconn.port'] = deployer.mdict['pki_ds_ldaps_port']
        else:
            subsystem.config['internaldb.ldapconn.secureConn'] = 'false'
            subsystem.config['internaldb.ldapconn.port'] = deployer.mdict['pki_ds_ldap_port']

        subsystem.config['internaldb.ldapauth.bindDN'] = deployer.mdict['pki_ds_bind_dn']
        subsystem.config['internaldb.basedn'] = deployer.mdict['pki_ds_base_dn']
        subsystem.config['internaldb.database'] = deployer.mdict['pki_ds_database']

        if config.str2bool(deployer.mdict['pki_share_db']):
            subsystem.config['preop.internaldb.dbuser'] = deployer.mdict['pki_share_dbuser_dn']

        ocsp_uri = deployer.mdict.get('pki_default_ocsp_uri')
        if ocsp_uri:
            subsystem.config['ca.defaultOcspUri'] = ocsp_uri

        if subsystem.name == 'ca':
            serial_number_range_start = deployer.mdict.get('pki_serial_number_range_start')
            if serial_number_range_start:
                subsystem.config['dbs.beginSerialNumber'] = serial_number_range_start

            serial_number_range_end = deployer.mdict.get('pki_serial_number_range_end')
            if serial_number_range_end:
                subsystem.config['dbs.endSerialNumber'] = serial_number_range_end

            request_number_range_start = deployer.mdict.get('pki_request_number_range_start')
            if request_number_range_start:
                subsystem.config['dbs.beginRequestNumber'] = request_number_range_start

            request_number_range_end = deployer.mdict.get('pki_request_number_range_end')
            if request_number_range_end:
                subsystem.config['dbs.endRequestNumber'] = request_number_range_end

            replica_number_range_start = deployer.mdict.get('pki_replica_number_range_start')
            if replica_number_range_start:
                subsystem.config['dbs.beginReplicaNumber'] = replica_number_range_start

            replica_number_range_end = deployer.mdict.get('pki_replica_number_range_end')
            if replica_number_range_end:
                subsystem.config['dbs.endReplicaNumber'] = replica_number_range_end

        if subsystem.name == 'kra':
            if config.str2bool(deployer.mdict['pki_kra_ephemeral_requests']):
                logger.debug('Setting ephemeral requests to true')
                subsystem.config['kra.ephemeralRequests'] = 'true'

        if subsystem.name == 'tps':
            baseDN = subsystem.config['internaldb.basedn']
            dsHost = subsystem.config['internaldb.ldapconn.host']
            dsPort = subsystem.config['internaldb.ldapconn.port']

            subsystem.config['tokendb.activityBaseDN'] = 'ou=Activities,' + baseDN
            subsystem.config['tokendb.baseDN'] = 'ou=Tokens,' + baseDN
            subsystem.config['tokendb.certBaseDN'] = 'ou=Certificates,' + baseDN
            subsystem.config['tokendb.userBaseDN'] = baseDN
            subsystem.config['tokendb.hostport'] = dsHost + ':' + dsPort

        subsystem.save()

        token = pki.nssdb.normalize_token(deployer.mdict['pki_token_name'])
        nssdb = instance.open_nssdb()

        existing = deployer.configuration_file.existing
        step_two = deployer.configuration_file.external_step_two
        clone = deployer.configuration_file.clone
        master_url = deployer.mdict['pki_clone_uri']

        try:
            if existing or (external or standalone) and step_two:

                self.import_system_cert_requests(deployer, subsystem)
                self.import_system_certs(deployer, nssdb, subsystem)

                self.configure_system_certs(deployer, subsystem)
                self.update_system_certs(deployer, nssdb, subsystem)
                subsystem.save()

                self.validate_system_certs(deployer, nssdb, subsystem)

            elif len(subsystems) > 1:

                for s in subsystems:

                    # find a subsystem that is already installed
                    if s.name == subsystem.name:
                        continue

                    # import cert/request data from the existing subsystem
                    # into the new subsystem being installed

                    logger.info('Importing sslserver cert data from %s', s.type)
                    subsystem.config['%s.sslserver.cert' % subsystem.name] = \
                        s.config['%s.sslserver.cert' % s.name]

                    logger.info('Importing subsystem cert data from %s', s.type)
                    subsystem.config['%s.subsystem.cert' % subsystem.name] = \
                        s.config['%s.subsystem.cert' % s.name]

                    logger.info('Importing sslserver request data from %s', s.type)
                    subsystem.config['%s.sslserver.certreq' % subsystem.name] = \
                        s.config['%s.sslserver.certreq' % s.name]

                    logger.info('Importing subsystem request data from %s', s.type)
                    subsystem.config['%s.subsystem.certreq' % subsystem.name] = \
                        s.config['%s.subsystem.certreq' % s.name]

                    break

            else:  # self-signed CA

                # To be implemented in ticket #1692.

                # Generate CA cert request.
                # Self sign CA cert.
                # Import self-signed CA cert into NSS database.

                pass

        finally:
            nssdb.close()

        create_temp_sslserver_cert = self.create_temp_sslserver_cert(deployer, instance)

        server_config = instance.get_server_config()
        unsecurePort = server_config.get_unsecure_port()
        securePort = server_config.get_secure_port()

        proxyUnsecurePort = subsystem.config.get('proxy.unsecurePort')
        if not proxyUnsecurePort:
            proxyUnsecurePort = unsecurePort

        proxySecurePort = subsystem.config.get('proxy.securePort')
        if not proxySecurePort:
            proxySecurePort = securePort

        if deployer.mdict['pki_security_domain_type'] == 'existing':

            logger.info('Joining existing domain')

            deployer.join_domain()

            subsystem.configure_security_domain(
                'existing',
                deployer.domain_info.id,
                deployer.sd_host.Hostname,
                deployer.sd_host.Port,
                deployer.sd_host.SecurePort)

        elif config.str2bool(deployer.mdict['pki_subordinate']) and \
                config.str2bool(deployer.mdict['pki_subordinate_create_new_security_domain']):

            logger.info('Creating new subordinate security domain')

            deployer.join_domain()

            subsystem.configure_security_domain(
                'new',
                deployer.mdict['pki_subordinate_security_domain_name'],
                deployer.mdict['pki_hostname'],
                unsecurePort,
                securePort)

        else:

            logger.info('Creating new security domain')

            subsystem.configure_security_domain(
                'new',
                deployer.mdict['pki_security_domain_name'],
                deployer.mdict['pki_hostname'],
                unsecurePort,
                securePort)

        subsystem.config['service.securityDomainPort'] = securePort

        hierarchy = subsystem.config.get('hierarchy.select')
        issuing_ca = deployer.mdict['pki_issuing_ca']

        if not (subsystem.type == 'CA' and hierarchy == 'Root'):

            if not external and not standalone:

                logger.info('Using CA at %s', issuing_ca)

                url = urllib.parse.urlparse(issuing_ca)

                subsystem.config['preop.ca.url'] = issuing_ca
                subsystem.config['preop.ca.hostname'] = url.hostname
                subsystem.config['preop.ca.httpsport'] = str(url.port)
                subsystem.config['preop.ca.httpsadminport'] = str(url.port)

        system_certs_imported = \
            deployer.mdict['pki_server_pkcs12_path'] != '' or \
            deployer.mdict['pki_clone_pkcs12_path'] != ''

        if not (subsystem.type == 'CA' and hierarchy == 'Root'):

            if external or standalone:
                subsystem.config['preop.ca.pkcs7'] = ''

            elif not clone and not system_certs_imported:

                logger.info('Retrieving CA certificate chain from %s', issuing_ca)

                pem_chain = self.get_cert_chain(instance, issuing_ca)
                base64_chain = pki.nssdb.convert_pkcs7(pem_chain, 'pem', 'base64')
                subsystem.config['preop.ca.pkcs7'] = base64_chain

                logger.info('Importing CA certificate chain')

                nssdb = instance.open_nssdb()
                try:
                    nssdb.import_pkcs7(pkcs7_data=pem_chain, trust_attributes='CT,C,C')
                finally:
                    nssdb.close()

        if subsystem.type == 'CA' and clone and not system_certs_imported:

            logger.info('Retrieving CA certificate chain from %s', master_url)

            pem_chain = self.get_cert_chain(instance, master_url)
            base64_chain = pki.nssdb.convert_pkcs7(pem_chain, 'pem', 'base64')
            subsystem.config['preop.clone.pkcs7'] = base64_chain

            logger.info('Importing CA certificate chain')

            nssdb = instance.open_nssdb()
            try:
                nssdb.import_pkcs7(pkcs7_data=pem_chain, trust_attributes='CT,C,C')
            finally:
                nssdb.close()

        subsystem.save()

        if clone:

            if subsystem.type in ['CA', 'KRA']:

                logger.info('Requesting ranges from %s master', subsystem.type)
                subsystem.request_ranges(master_url, deployer.install_token)

            logger.info('Updating configuration for %s clone', subsystem.type)
            subsystem.update_config(master_url, deployer.install_token)

        if config.str2bool(deployer.mdict['pki_ds_remove_data']):

            if config.str2bool(deployer.mdict['pki_ds_create_new_db']):
                logger.info('Removing existing database')
                subsystem.remove_database(force=True)

            elif not config.str2bool(deployer.mdict['pki_clone']) or \
                    config.str2bool(deployer.mdict['pki_clone_setup_replication']):
                logger.info('Emptying existing database')
                subsystem.empty_database(force=True)

            else:
                logger.info('Reusing replicated database')

        logger.info('Initializing database')

        # In most cases, we want to replicate the schema and therefore not add it here.
        # We provide this option though in case the clone already has schema
        # and we want to replicate back to the master.

        # On the other hand, if we are not setting up replication,
        # then we are assuming that replication is already taken care of,
        # and schema has already been replicated.

        setup_schema = not config.str2bool(deployer.mdict['pki_clone']) or \
            not config.str2bool(deployer.mdict['pki_clone_setup_replication']) or \
            not config.str2bool(deployer.mdict['pki_clone_replicate_schema'])

        create_database = config.str2bool(deployer.mdict['pki_ds_create_new_db'])

        # When cloning a subsystem without setting up the replication agreements,
        # the database is a subtree of an existing tree and is already replicated,
        # so there is no need to set up the base entry.

        create_base = config.str2bool(deployer.mdict['pki_ds_create_new_db']) or \
            not config.str2bool(deployer.mdict['pki_clone']) or \
            config.str2bool(deployer.mdict['pki_clone_setup_replication'])

        create_containers = not config.str2bool(deployer.mdict['pki_clone'])

        # Set up replication if required for cloning.

        setup_replication = clone and \
            config.str2bool(deployer.mdict['pki_clone_setup_replication'])

        ds_port = subsystem.config['internaldb.ldapconn.port']
        secure_conn = subsystem.config['internaldb.ldapconn.secureConn']
        replication_security = deployer.mdict['pki_clone_replication_security']
        replication_port = deployer.mdict['pki_clone_replication_clone_port']
        master_replication_port = deployer.mdict['pki_clone_replication_master_port']

        if replication_port == ds_port and secure_conn == 'true':
            replication_security = 'SSL'

        elif not replication_security:
            replication_security = 'None'

        # If the database is already replicated but not yet indexed, rebuild the indexes.

        rebuild_indexes = config.str2bool(deployer.mdict['pki_clone']) and \
            not config.str2bool(deployer.mdict['pki_clone_setup_replication']) and \
            config.str2bool(deployer.mdict['pki_clone_reindex_data'])

        subsystem.init_database(
            setup_schema=setup_schema,
            create_database=create_database,
            create_base=create_base,
            create_containers=create_containers,
            rebuild_indexes=rebuild_indexes,
            setup_replication=setup_replication,
            replication_security=replication_security,
            replication_port=replication_port,
            master_replication_port=master_replication_port)

        subsystem.add_vlv()
        subsystem.reindex_vlv()

        subsystem.load()

        if not clone and subsystem.type == 'CA':
            subsystem.import_profiles(
                input_folder='/usr/share/pki/ca/profiles/ca')

        # Start/Restart this Tomcat PKI Process
        # Optionally prepare to enable a java debugger
        # (e. g. - 'eclipse'):
        if config.str2bool(deployer.mdict['pki_enable_java_debugger']):
            config.prepare_for_an_external_java_debugger(
                deployer.mdict['pki_target_tomcat_conf_instance_id'])
        tomcat_instance_subsystems = \
            len(deployer.instance.tomcat_instance_subsystems())

        if tomcat_instance_subsystems == 1:
            logger.info('Starting server')
            instance.start()

        elif tomcat_instance_subsystems > 1:
            logger.info('Restarting server')
            instance.restart()

        deployer.instance.wait_for_startup(
            subsystem,
            startup_timeout,
            request_timeout,
        )

        # Optionally wait for debugger to attach (e. g. - 'eclipse'):
        if config.str2bool(deployer.mdict['pki_enable_java_debugger']):
            config.wait_to_attach_an_external_java_debugger()

        ca_cert = os.path.join(instance.nssdb_dir, "ca.crt")

        connection = pki.client.PKIConnection(
            protocol='https',
            hostname=deployer.mdict['pki_hostname'],
            port=deployer.mdict['pki_https_port'],
            trust_env=False,
            cert_paths=ca_cert)

        client = pki.system.SystemConfigClient(
            connection,
            subsystem=deployer.mdict['pki_subsystem_type'])

        # If pki_one_time_pin is not already defined, load from CS.cfg
        if 'pki_one_time_pin' not in deployer.mdict:
            deployer.mdict['pki_one_time_pin'] = subsystem.config['preop.pin']

        system_certs = {}
        for system_cert in subsystem.find_system_certs():
            cert_id = system_cert['id']
            system_certs[cert_id] = system_cert

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

            logger.info('Setting up %s certificate', tag)
            cert = deployer.setup_cert(client, tag)

            if not cert:
                continue

            logger.debug('- cert: %s', cert['cert'])
            logger.debug('- request: %s', cert['request'])

            system_certs[tag]['data'] = cert['cert']
            system_certs[tag]['request'] = cert['request']
            system_certs[tag]['token'] = cert['token']

        if not clone:
            logger.info('Setting up admin user')
            deployer.setup_admin(subsystem, client)

        if config.str2bool(deployer.mdict['pki_backup_keys']):

            # by default store the backup file in the NSS databases directory
            if not deployer.mdict['pki_backup_file']:
                deployer.mdict['pki_backup_file'] = \
                    deployer.mdict['pki_server_database_path'] + '/' + \
                    deployer.mdict['pki_subsystem'].lower() + '_backup_keys.p12'

            logger.info('Backing up keys into %s', deployer.mdict['pki_backup_file'])
            deployer.backup_keys(instance, subsystem)

        domain_manager = False

        if subsystem.type == 'CA':
            if clone:
                sd_hostname = subsystem.config['securitydomain.host']
                sd_port = subsystem.config['securitydomain.httpsadminport']

                sd_subsystem = deployer.domain_info.subsystems['CA']
                sd_host = sd_subsystem.get_host(sd_hostname, sd_port)

                if sd_host.DomainManager and sd_host.DomainManager.lower() == 'true':
                    domain_manager = True

        if deployer.mdict['pki_security_domain_type'] == 'existing':
            logger.info('Joining security domain')
            subsystem.join_security_domain(
                deployer.install_token,
                deployer.mdict['pki_subsystem_name'],
                deployer.mdict['pki_hostname'],
                unsecure_port=proxyUnsecurePort,
                secure_port=proxySecurePort,
                domain_manager=domain_manager,
                clone=clone)

        else:
            logger.info('Creating security domain')
            subsystem.create_security_domain()

            logger.info('Adding security domain manager')
            subsystem.add_security_domain_host(
                deployer.mdict['pki_subsystem_name'],
                deployer.mdict['pki_hostname'],
                unsecure_port=proxyUnsecurePort,
                secure_port=proxySecurePort,
                domain_manager=True)

        if not config.str2bool(deployer.mdict['pki_share_db']) and not clone:
            logger.info('Setting up database user')
            deployer.setup_database_user(instance, subsystem)

        logger.info('Finalizing %s configuration', subsystem.type)
        finalize_config_request = deployer.config_client.create_finalize_config_request()
        finalize_config_request.domainInfo = deployer.domain_info
        finalize_config_request.installToken = deployer.install_token
        client.finalizeConfiguration(finalize_config_request)

        subsystem.load()

        if subsystem.type == 'CA':

            if not clone:
                logger.info('Updating CA ranges')
                subsystem.update_ranges()

            if clone:
                if sd_host.DomainManager and sd_host.DomainManager.lower() == 'true':

                    logger.info('Cloning security domain master')

                    subsystem.config['securitydomain.select'] = 'new'
                    subsystem.config['securitydomain.host'] = deployer.mdict['pki_hostname']
                    subsystem.config['securitydomain.httpport'] = unsecurePort
                    subsystem.config['securitydomain.httpsadminport'] = securePort
                    subsystem.config['securitydomain.httpsagentport'] = securePort
                    subsystem.config['securitydomain.httpseeport'] = securePort

                logger.info('Disabling CRL caching and generation on clone')

                subsystem.config['ca.certStatusUpdateInterval'] = '0'
                subsystem.config['ca.listenToCloneModifications'] = 'false'
                subsystem.config['ca.crl.MasterCRL.enableCRLCache'] = 'false'
                subsystem.config['ca.crl.MasterCRL.enableCRLUpdates'] = 'false'

                url = urllib.parse.urlparse(master_url)

                subsystem.config['master.ca.agent.host'] = url.hostname
                subsystem.config['master.ca.agent.port'] = str(url.port)

            crl_number = deployer.mdict['pki_ca_starting_crl_number']
            logger.info('Starting CRL number: %s', crl_number)
            subsystem.config['ca.crl.MasterCRL.startingCrlNumber'] = crl_number

            logger.info('Enabling profile subsystem')
            subsystem.enable_subsystem('profile')

            # Delete CA signing cert record to avoid migration conflict
            if not config.str2bool(deployer.mdict['pki_ca_signing_record_create']):
                logger.info('Deleting CA signing cert record')
                serial_number = deployer.mdict['pki_ca_signing_serial_number']
                subsystem.remove_cert(serial_number)

        if subsystem.type == 'KRA':

            if not clone:
                logger.info('Updating KRA ranges')
                subsystem.update_ranges()

        if subsystem.type == 'TPS':
            logger.info('Setting up shared secret')
            deployer.setup_shared_secret(instance, subsystem)

        deployer.finalize_subsystem(subsystem)

        logger.info('%s configuration complete', subsystem.type)

        # Create an empty file that designates the fact that although
        # this server instance has been configured, it has NOT yet
        # been restarted!

        restart_server = os.path.join(instance.conf_dir, 'restart_server_after_configuration')
        logger.debug('Creating %s', restart_server)

        open(restart_server, 'a').close()
        os.chown(restart_server, instance.uid, instance.gid)
        os.chmod(restart_server, 0o660)

        # If temp SSL server cert was created and there's a new perm cert,
        # replace it with the perm cert.
        if create_temp_sslserver_cert and system_certs['sslserver']['data']:
            logger.info('Stopping server')
            instance.stop()

            # Remove temp SSL server cert.
            self.remove_temp_sslserver_cert(instance, system_certs['sslserver'])

            # Import perm SSL server cert unless it's already imported
            # earlier in external/standalone installation.

            if not (standalone or external and subsystem.name in ['kra', 'ocsp']):

                nickname = system_certs['sslserver']['nickname']
                token = pki.nssdb.normalize_token(system_certs['sslserver']['token'])

                if not token:
                    token = deployer.mdict['pki_token_name']

                instance.set_sslserver_cert_nickname(nickname, token)

                self.import_perm_sslserver_cert(deployer, instance, system_certs['sslserver'])

            logger.info('Starting server')
            instance.start()

        elif config.str2bool(deployer.mdict['pki_restart_configured_instance']):
            logger.info('Restarting server')
            instance.restart()

        deployer.instance.wait_for_startup(
            subsystem,
            startup_timeout,
            request_timeout,
        )

    def destroy(self, deployer):
        pass
