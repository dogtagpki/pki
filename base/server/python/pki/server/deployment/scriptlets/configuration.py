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
import time
import logging
import os
import shutil
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

logger = logging.getLogger(__name__)


# PKI Deployment Configuration Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):

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

        # Reset the NSS database ownership and permissions
        # after importing the permanent SSL server cert
        # since it might create new files.
        pki.util.chown(
            deployer.mdict['pki_server_database_path'],
            deployer.mdict['pki_uid'],
            deployer.mdict['pki_gid'])
        pki.util.chmod(
            deployer.mdict['pki_server_database_path'],
            config.PKI_DEPLOYMENT_DEFAULT_SECURITY_DATABASE_PERMISSIONS)
        os.chmod(
            deployer.mdict['pki_server_database_path'],
            pki.server.DEFAULT_DIR_MODE)

    def spawn(self, deployer):

        external = deployer.configuration_file.external
        standalone = deployer.configuration_file.standalone
        step_one = deployer.configuration_file.external_step_one
        skip_configuration = deployer.configuration_file.skip_configuration

        if (external or standalone) and step_one or skip_configuration:
            logger.info('Skipping configuration')
            return

        logger.info('Configuring subsystem')

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
            cert_id_generator = deployer.mdict.get('pki_cert_id_generator')
            if cert_id_generator:
                subsystem.config['dbs.cert.id.generator'] = cert_id_generator

            serial_number_range_start = deployer.mdict.get('pki_serial_number_range_start')
            if serial_number_range_start:
                subsystem.config['dbs.beginSerialNumber'] = serial_number_range_start

            serial_number_range_end = deployer.mdict.get('pki_serial_number_range_end')
            if serial_number_range_end:
                subsystem.config['dbs.endSerialNumber'] = serial_number_range_end

            if cert_id_generator == 'legacy2':
                if not serial_number_range_start.startswith('0x'):
                    raise Exception('pki_serial_number_range_start format not valid, expecting 0x...')
                if not serial_number_range_end.startswith('0x'):
                    raise Exception('pki_serial_number_range_end format not valid, expecting 0x...')
                subsystem.config['dbs.serialIncrement'] = '0x10000000'
                subsystem.config['dbs.serialLowWaterMark'] = '0x2000000'
                subsystem.config['dbs.serialCloneTransferNumber'] = '0x10000'
                subsystem.config['dbs.requestRangeDN'] = 'ou=requests,ou=ranges_v2'
                subsystem.config['dbs.serialRangeDN'] = 'ou=certificateRepository,ou=ranges_v2'

            request_id_generator = deployer.mdict.get('pki_request_id_generator')
            if request_id_generator:
                subsystem.config['dbs.request.id.generator'] = request_id_generator

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

            nickname = subsystem.config['tps.subsystem.nickname']
            token = subsystem.config['tps.subsystem.tokenname']

            if pki.nssdb.normalize_token(token):
                fullname = token + ':' + nickname
            else:
                fullname = nickname

            timestamp = round(time.time() * 1000 * 1000)

            logger.info('Configuring CA connector')

            ca_url = urllib.parse.urlparse(deployer.mdict['pki_ca_uri'])
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

            tks_url = urllib.parse.urlparse(deployer.mdict['pki_tks_uri'])
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

            keygen = config.str2bool(deployer.mdict['pki_enable_server_side_keygen'])

            if keygen:
                logger.info('Configuring KRA connector')

                kra_url = urllib.parse.urlparse(deployer.mdict['pki_kra_uri'])
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

        subsystem.save()

        token = pki.nssdb.normalize_token(deployer.mdict['pki_token_name'])
        nssdb = instance.open_nssdb()

        existing = deployer.configuration_file.existing
        step_two = deployer.configuration_file.external_step_two
        clone = deployer.configuration_file.clone
        master_url = deployer.mdict['pki_clone_uri']

        try:
            if existing or (external or standalone) and step_two:

                deployer.import_system_cert_requests(subsystem)
                deployer.import_system_certs(nssdb, subsystem)

                # If provided, import cert chain into NSS database.
                # Note: Cert chain must be imported after the system certs
                # to ensure that the system certs are imported with
                # the correct nicknames.
                deployer.import_cert_chain(nssdb)

                deployer.configure_system_certs(subsystem)

                deployer.update_system_certs(nssdb, subsystem)
                subsystem.save()

                deployer.validate_system_certs(nssdb, subsystem)

            elif len(subsystems) > 1:

                # If provided, import cert chain into NSS database.
                deployer.import_cert_chain(nssdb)

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

                # If provided, import cert chain into NSS database.
                deployer.import_cert_chain(nssdb)

                # To be implemented in ticket #1692.

                # Generate CA cert request.
                # Self sign CA cert.
                # Import self-signed CA cert into NSS database.

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

            deployer.join_security_domain()

            subsystem.configure_security_domain(
                'existing',
                deployer.domain_info.id,
                deployer.sd_host.Hostname,
                deployer.sd_host.Port,
                deployer.sd_host.SecurePort)

        elif config.str2bool(deployer.mdict['pki_subordinate']) and \
                config.str2bool(deployer.mdict['pki_subordinate_create_new_security_domain']):

            logger.info('Creating new subordinate security domain')

            deployer.join_security_domain()

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

        if external and subsystem.type == 'CA':
            # No need to use issuing CA during CA installation
            # with external certs since the certs will be provided.
            pass

        elif standalone and subsystem.type in ['KRA', 'OCSP']:
            # No need to use issuing CA during standalone KRA/OCSP
            # installation since the certs will be provided.
            pass

        else:
            # For other cases, use issuing CA to issue certs during installation.
            # KRA will also configure a connector in the issuing CA, and OCSP will
            # configure a publisher in the issuing CA.

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

            if external and subsystem.type == 'CA' or \
                    standalone and subsystem.type in ['KRA', 'OCSP']:
                subsystem.config['preop.ca.pkcs7'] = ''

            elif not clone and not system_certs_imported:

                logger.info('Retrieving CA certificate chain from %s', issuing_ca)

                pem_chain = deployer.get_ca_signing_cert(instance, issuing_ca)
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

            pem_chain = deployer.get_ca_signing_cert(instance, master_url)
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
                subsystem.request_ranges(master_url, session_id=deployer.install_token.token)

            logger.info('Updating configuration for %s clone', subsystem.type)
            subsystem.update_config(master_url, session_id=deployer.install_token.token)

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
        logger.info('- internaldb.ldapconn.port: %s', ds_port)

        secure_conn = subsystem.config['internaldb.ldapconn.secureConn']
        logger.info('- internaldb.ldapconn.secureConn: %s', secure_conn)

        replication_security = deployer.mdict['pki_clone_replication_security']
        logger.info('- pki_clone_replication_security: %s', replication_security)

        replication_port = deployer.mdict['pki_clone_replication_clone_port']
        logger.info('- pki_clone_replication_clone_port: %s', replication_port)

        master_replication_port = deployer.mdict['pki_clone_replication_master_port']
        logger.info('- pki_clone_replication_master_port: %s', master_replication_port)

        if replication_port == ds_port and secure_conn == 'true':
            replication_security = 'SSL'

        elif not replication_security:
            replication_security = 'None'

        logger.info('- replication_security: %s', replication_security)

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

            logger.info('Enabling %s subsystem', subsystem.type)
            subsystem.enable()

            logger.info('Starting PKI server')
            instance.start(
                wait=True,
                max_wait=deployer.startup_timeout,
                timeout=deployer.request_timeout)

        elif tomcat_instance_subsystems > 1:

            logger.info('Enabling %s subsystem', subsystem.type)
            subsystem.enable(
                wait=True,
                max_wait=deployer.startup_timeout,
                timeout=deployer.request_timeout)

        logger.info('Waiting for %s subsystem', subsystem.type)
        subsystem.wait_for_startup(deployer.startup_timeout, deployer.request_timeout)

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

        system_certs = deployer.setup_system_certs(subsystem, client)

        if subsystem.type == 'CA':
            logger.info('Setting up subsystem user')
            deployer.setup_subsystem_user(instance, subsystem, system_certs['subsystem'])

        if not clone:
            logger.info('Getting admin certificate')
            admin_cert = deployer.get_admin_cert(subsystem, client)

            logger.info('Setting up admin user')
            deployer.setup_admin_user(subsystem, admin_cert)

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

            sd_url = deployer.mdict['pki_security_domain_uri']
            logger.info('Joining security domain at %s', sd_url)
            subsystem.join_security_domain(
                sd_url,
                deployer.mdict['pki_subsystem_name'],
                deployer.mdict['pki_hostname'],
                unsecure_port=proxyUnsecurePort,
                secure_port=proxySecurePort,
                domain_manager=domain_manager,
                clone=clone,
                session_id=deployer.install_token.token)

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

        if subsystem.type == 'CA':

            if clone:
                if sd_host.DomainManager and sd_host.DomainManager.lower() == 'true':

                    logger.info('Cloning security domain master')

                    subsystem.config['securitydomain.select'] = 'new'
                    subsystem.config['securitydomain.host'] = deployer.mdict['pki_hostname']
                    subsystem.config['securitydomain.httpport'] = unsecurePort
                    subsystem.config['securitydomain.httpsadminport'] = securePort
                    subsystem.config['securitydomain.httpsagentport'] = securePort
                    subsystem.config['securitydomain.httpseeport'] = securePort

        deployer.finalize_subsystem(instance, subsystem)

        logger.info('%s configuration complete', subsystem.type)

        # If temp SSL server cert was created and there's a new perm cert,
        # replace it with the perm cert.
        if create_temp_sslserver_cert and system_certs['sslserver']['data']:

            logger.info('Stopping PKI server')
            instance.stop(
                wait=True,
                max_wait=deployer.startup_timeout,
                timeout=deployer.request_timeout)

            # Remove temp SSL server cert.
            self.remove_temp_sslserver_cert(instance, system_certs['sslserver'])

            # Import perm SSL server cert unless it's already imported
            # earlier in external/standalone installation.

            if not (standalone or external and subsystem.name in ['kra', 'ocsp']):
                self.import_perm_sslserver_cert(deployer, instance, system_certs['sslserver'])

            # Store perm SSL server cert nickname and token
            nickname = system_certs['sslserver']['nickname']
            token = pki.nssdb.normalize_token(system_certs['sslserver']['token'])

            if not token:
                token = deployer.mdict['pki_token_name']

            instance.set_sslserver_cert_nickname(nickname, token)

            logger.info('Starting PKI server')
            instance.start(
                wait=True,
                max_wait=deployer.startup_timeout,
                timeout=deployer.request_timeout)

        elif config.str2bool(deployer.mdict['pki_restart_configured_instance']):

            logger.info('Restarting %s subsystem', subsystem.type)
            subsystem.restart(
                wait=True,
                max_wait=deployer.startup_timeout,
                timeout=deployer.request_timeout)

        logger.info('Waiting for %s subsystem', subsystem.type)
        subsystem.wait_for_startup(deployer.startup_timeout, deployer.request_timeout)

    def destroy(self, deployer):
        pass
