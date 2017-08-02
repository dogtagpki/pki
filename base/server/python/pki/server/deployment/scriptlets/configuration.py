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
import binascii
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import json
import os
import re
import shutil
import tempfile

# PKI Deployment Imports
from .. import pkiconfig as config
from .. import pkimessages as log
from .. import pkiscriptlet

import pki.encoder
import pki.nssdb
import pki.server
import pki.system
import pki.util


# PKI Deployment Configuration Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):

    def get_cert_id(self, subsystem, tag):

        if tag == 'signing':
            return '%s_%s' % (subsystem.name, tag)
        else:
            return tag

    def get_key_params(self, deployer, cert_id):

        key_type = deployer.mdict['pki_%s_key_type' % cert_id]
        key_alg = deployer.mdict['pki_%s_key_algorithm' % cert_id]
        key_size = deployer.mdict['pki_%s_key_size' % cert_id]

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

            m = re.match(r'(.*)withEC', key_alg)
            if not m:
                raise Exception('Invalid key algorithm: %s' % key_alg)

            hash_alg = m.group(1)

        else:
            raise Exception('Invalid key type: %s' % key_type)

        return (key_type, key_size, curve, hash_alg)

    def generate_csr(self, deployer, nssdb, subsystem, tag, csr_path,
                     basic_constraints_ext=None,
                     key_usage_ext=None,
                     generic_exts=None):

        cert_id = self.get_cert_id(subsystem, tag)

        config.pki_log.info(
            "generating %s CSR in %s" % (cert_id, csr_path),
            extra=config.PKI_INDENTATION_LEVEL_2)

        subject_dn = deployer.mdict['pki_%s_subject_dn' % cert_id]

        (key_type, key_size, curve, hash_alg) = self.get_key_params(
            deployer, cert_id)

        nssdb.create_request(
            subject_dn=subject_dn,
            request_file=csr_path,
            key_type=key_type,
            key_size=key_size,
            curve=curve,
            hash_alg=hash_alg,
            basic_constraints_ext=basic_constraints_ext,
            key_usage_ext=key_usage_ext,
            generic_exts=generic_exts)

        with open(csr_path) as f:
            csr = f.read()

        b64_csr = pki.nssdb.convert_csr(csr, 'pem', 'base64')
        subsystem.config['%s.%s.certreq' % (subsystem.name, tag)] = b64_csr

    def generate_ca_signing_csr(self, deployer, nssdb, subsystem):

        csr_path = deployer.mdict.get('pki_external_csr_path')
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

        self.generate_csr(
            deployer, nssdb, subsystem, 'signing', csr_path,
            basic_constraints_ext, key_usage_ext, generic_exts
        )

    def generate_system_cert_requests(self, deployer, nssdb, subsystem):

        if subsystem.name == 'ca':
            self.generate_ca_signing_csr(deployer, nssdb, subsystem)

    def import_ca_signing_csr(self, deployer, subsystem):

        csr_path = deployer.mdict.get('pki_external_csr_path')
        if not csr_path or not os.path.exists(csr_path):
            return

        config.pki_log.info(
            "importing ca_signing CSR from %s" % csr_path,
            extra=config.PKI_INDENTATION_LEVEL_2)

        with open(csr_path) as f:
            csr_data = f.read()

        b64_csr = pki.nssdb.convert_csr(csr_data, 'pem', 'base64')
        subsystem.config['ca.signing.certreq'] = b64_csr

    def import_system_cert_requests(self, deployer, subsystem):

        if subsystem.name == 'ca':
            self.import_ca_signing_csr(deployer, subsystem)

    def create_temp_sslserver_cert(self, deployer, instance, token):

        if len(deployer.instance.tomcat_instance_subsystems()) > 1:
            return False

        nssdb = instance.open_nssdb(token)

        try:
            nickname = deployer.mdict['pki_self_signed_nickname']

            config.pki_log.info(
                "checking existing SSL server cert: %s" % nickname,
                extra=config.PKI_INDENTATION_LEVEL_2)

            pem_cert = nssdb.get_cert(nickname)

            if pem_cert:
                cert = x509.load_pem_x509_certificate(pem_cert, default_backend())
                cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]
                hostname = cn.value

                config.pki_log.info(
                    "existing SSL server cert is for %s" % hostname,
                    extra=config.PKI_INDENTATION_LEVEL_2)

                # if hostname is correct, don't create temp cert
                if hostname == deployer.mdict['pki_hostname']:
                    return False

                config.pki_log.info(
                    "removing SSL server cert for %s" % hostname,
                    extra=config.PKI_INDENTATION_LEVEL_2)

                nssdb.remove_cert(nickname, remove_key=True)

            config.pki_log.info(
                "creating temp SSL server cert for %s" % deployer.mdict['pki_hostname'],
                extra=config.PKI_INDENTATION_LEVEL_2)

            # TODO: replace with pki-server create-cert sslserver --temp

            deployer.password.create_password_conf(
                deployer.mdict['pki_shared_pfile'],
                deployer.mdict['pki_pin'], pin_sans_token=True)

            # only create a self signed cert for a new instance
            #
            # NOTE:  ALWAYS create the temporary sslserver certificate
            #        in the software DB regardless of whether the
            #        instance will utilize 'softokn' or an HSM
            #
            # note: in the function below, certutil is used to generate
            # the request for the self signed cert.  The keys are generated
            # by NSS, which does not actually use the data in the noise
            # file, so it does not matter what is in this file.  Certutil
            # still requires it though, otherwise it waits for keyboard
            # input

            with open(deployer.mdict['pki_self_signed_noise_file'], 'w') as f:
                f.write("not_so_random_data")

            deployer.certutil.generate_self_signed_certificate(
                deployer.mdict['pki_database_path'],
                deployer.mdict['pki_cert_database'],
                deployer.mdict['pki_key_database'],
                deployer.mdict['pki_secmod_database'],
                deployer.mdict['pki_self_signed_token'],
                deployer.mdict['pki_self_signed_nickname'],
                deployer.mdict['pki_self_signed_subject'],
                deployer.mdict['pki_self_signed_serial_number'],
                deployer.mdict['pki_self_signed_validity_period'],
                deployer.mdict['pki_self_signed_issuer_name'],
                deployer.mdict['pki_self_signed_trustargs'],
                deployer.mdict['pki_self_signed_noise_file'],
                password_file=deployer.mdict['pki_shared_pfile'])

            # Delete the temporary 'noise' file
            deployer.file.delete(
                deployer.mdict['pki_self_signed_noise_file'])

            # Always delete the temporary 'pfile'
            deployer.file.delete(deployer.mdict['pki_shared_pfile'])

            return True

        finally:
            nssdb.close()

    def replace_sslserver_cert(self, deployer, instance, sslserver):

        if len(deployer.instance.tomcat_instance_subsystems()) == 1:
            # Modify contents of 'serverCertNick.conf' (if necessary)
            deployer.servercertnick_conf.modify()

        # TODO: replace with pki-server cert-import sslserver

        nickname = sslserver['nickname']

        config.pki_log.info(
            "removing temp SSL server cert from internal token: %s" % nickname,
            extra=config.PKI_INDENTATION_LEVEL_2)

        nssdb = instance.open_nssdb()

        try:
            nssdb.remove_cert(nickname, remove_key=True)

        finally:
            nssdb.close()

        token = deployer.mdict['pki_token_name']

        config.pki_log.info(
            "importing permanent SSL server cert into %s token: %s" % (token, nickname),
            extra=config.PKI_INDENTATION_LEVEL_2)

        tmpdir = tempfile.mkdtemp()
        nssdb = instance.open_nssdb(token)

        try:
            pem_cert = pki.nssdb.convert_cert(sslserver['cert'], 'base64', 'pem')

            cert_file = os.path.join(tmpdir, 'sslserver.crt')
            with open(cert_file, 'w') as f:
                f.write(pem_cert)

            nssdb.add_cert(nickname, cert_file)

        finally:
            nssdb.close()
            shutil.rmtree(tmpdir)

    def spawn(self, deployer):

        if config.str2bool(deployer.mdict['pki_skip_configuration']):
            config.pki_log.info(log.SKIP_CONFIGURATION_SPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            return

        config.pki_log.info(log.CONFIGURATION_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)

        # Place "slightly" less restrictive permissions on
        # the top-level client directory ONLY
        deployer.directory.create(
            deployer.mdict['pki_client_subsystem_dir'],
            uid=0, gid=0,
            perms=config.PKI_DEPLOYMENT_DEFAULT_CLIENT_DIR_PERMISSIONS)
        # Since 'certutil' does NOT strip the 'token=' portion of
        # the 'token=password' entries, create a client password file
        # which ONLY contains the 'password' for the purposes of
        # allowing 'certutil' to generate the security databases
        deployer.password.create_password_conf(
            deployer.mdict['pki_client_password_conf'],
            deployer.mdict['pki_client_database_password'], pin_sans_token=True)
        deployer.file.modify(
            deployer.mdict['pki_client_password_conf'],
            uid=0, gid=0)
        # Similarly, create a simple password file containing the
        # PKCS #12 password used when exporting the "Admin Certificate"
        # into a PKCS #12 file
        deployer.password.create_client_pkcs12_password_conf(
            deployer.mdict['pki_client_pkcs12_password_conf'])
        deployer.file.modify(deployer.mdict['pki_client_pkcs12_password_conf'])
        deployer.directory.create(
            deployer.mdict['pki_client_database_dir'],
            uid=0, gid=0)
        deployer.certutil.create_security_databases(
            deployer.mdict['pki_client_database_dir'],
            deployer.mdict['pki_client_cert_database'],
            deployer.mdict['pki_client_key_database'],
            deployer.mdict['pki_client_secmod_database'],
            password_file=deployer.mdict['pki_client_password_conf'])

        instance = pki.server.PKIInstance(deployer.mdict['pki_instance_name'])
        instance.load()

        subsystem = instance.get_subsystem(
            deployer.mdict['pki_subsystem'].lower())

        ocsp_uri = deployer.mdict.get('pki_default_ocsp_uri')
        if ocsp_uri:
            subsystem.config['ca.defaultOcspUri'] = ocsp_uri
            subsystem.save()

        token = deployer.mdict['pki_token_name']
        nssdb = instance.open_nssdb(token)

        existing = deployer.configuration_file.existing
        external = deployer.configuration_file.external
        standalone = deployer.configuration_file.standalone
        step_one = deployer.configuration_file.external_step_one
        step_two = deployer.configuration_file.external_step_two
        clone = deployer.configuration_file.clone

        try:
            if external and step_one:  # external CA step 1 only

                self.generate_system_cert_requests(deployer, nssdb, subsystem)

                # This is needed by IPA to detect step 1 completion.
                # See is_step_one_done() in ipaserver/install/cainstance.py.

                subsystem.config['preop.ca.type'] = 'otherca'

                subsystem.save()

            if existing or external and step_two:
                # existing CA or external CA step 2

                self.import_system_cert_requests(deployer, subsystem)

                # If specified, import CA signing cert into NSS database.
                signing_nickname = deployer.mdict['pki_ca_signing_nickname']
                signing_cert_file = deployer.mdict['pki_external_ca_cert_path']
                if signing_cert_file:
                    config.pki_log.info(
                        "importing %s from %s",
                        signing_nickname, signing_cert_file,
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    nssdb.add_cert(
                        nickname=signing_nickname,
                        cert_file=signing_cert_file,
                        trust_attributes='CT,C,C')

                # If specified, import certs and keys from PKCS #12 file
                # into NSS database.
                pkcs12_file = deployer.mdict['pki_external_pkcs12_path']
                if pkcs12_file:
                    config.pki_log.info(
                        "importing certificates and keys from %s", pkcs12_file,
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    pkcs12_password = deployer.mdict[
                        'pki_external_pkcs12_password']
                    nssdb.import_pkcs12(pkcs12_file, pkcs12_password)

                # If specified, import cert chain into NSS database.
                # Note: Cert chain must be imported after the system certs
                # to ensure that the system certs are imported with
                # the correct nicknames.
                external_ca_cert_chain_nickname = \
                    deployer.mdict['pki_external_ca_cert_chain_nickname']
                external_ca_cert_chain_file = deployer.mdict[
                    'pki_external_ca_cert_chain_path']
                if external_ca_cert_chain_file:
                    config.pki_log.info(
                        "importing certificate chain %s from %s",
                        external_ca_cert_chain_nickname,
                        external_ca_cert_chain_file,
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    cert_chain, _nicks = nssdb.import_cert_chain(
                        nickname=external_ca_cert_chain_nickname,
                        cert_chain_file=external_ca_cert_chain_file,
                        trust_attributes='CT,C,C')
                    subsystem.config['ca.external_ca_chain.cert'] = cert_chain

                # Export CA signing cert from NSS database and import
                # it into CS.cfg.
                signing_cert_data = nssdb.get_cert(
                    nickname=signing_nickname,
                    output_format='base64')
                subsystem.config['ca.signing.nickname'] = signing_nickname
                subsystem.config['ca.signing.tokenname'] = (
                    deployer.mdict['pki_ca_signing_token'])
                subsystem.config['ca.signing.cert'] = signing_cert_data
                subsystem.config['ca.signing.cacertnickname'] = signing_nickname
                subsystem.config['ca.signing.defaultSigningAlgorithm'] = (
                    deployer.mdict['pki_ca_signing_signing_algorithm'])

                subsystem.save()

                # verify the signing certificate
                # raises exception on  failure
                config.pki_log.info("validating the signing certificate",
                                    extra=config.PKI_INDENTATION_LEVEL_2)
                verifier = pki.server.deployment.PKIDeployer.create_system_cert_verifier(
                    instance, 'ca')
                verifier.verify_certificate('signing')

            else:  # self-signed CA

                # To be implemented in ticket #1692.

                # Generate CA cert request.
                # Self sign CA cert.
                # Import self-signed CA cert into NSS database.

                pass

        finally:
            nssdb.close()

        if external and step_one:
            return

        self.create_temp_sslserver_cert(deployer, instance, token)

        # Start/Restart this Tomcat PKI Process
        # Optionally prepare to enable a java debugger
        # (e. g. - 'eclipse'):
        if config.str2bool(deployer.mdict['pki_enable_java_debugger']):
            config.prepare_for_an_external_java_debugger(
                deployer.mdict['pki_target_tomcat_conf_instance_id'])
        tomcat_instance_subsystems = \
            len(deployer.instance.tomcat_instance_subsystems())
        if tomcat_instance_subsystems == 1:
            deployer.systemd.start()
        elif tomcat_instance_subsystems > 1:
            deployer.systemd.restart()

        # wait for startup
        status = deployer.instance.wait_for_startup(60)
        if status is None:
            config.pki_log.error(
                "server failed to restart",
                extra=config.PKI_INDENTATION_LEVEL_2)
            raise Exception("server failed to restart")

        # Optionally wait for debugger to attach (e. g. - 'eclipse'):
        if config.str2bool(deployer.mdict['pki_enable_java_debugger']):
            config.wait_to_attach_an_external_java_debugger()

        # Construct PKI Subsystem Configuration Data
        data = None
        if deployer.mdict['pki_instance_type'] == "Tomcat":
            # CA, KRA, OCSP, TKS, or TPS
            data = deployer.config_client.construct_pki_configuration_data()

        # Configure the subsystem
        response = deployer.config_client.configure_pki_data(
            json.dumps(data, cls=pki.encoder.CustomTypeEncoder))

        config.pki_log.debug(
            log.PKI_CONFIG_RESPONSE_STATUS + " " + str(response['status']),
            extra=config.PKI_INDENTATION_LEVEL_2)

        try:
            certs = response['systemCerts']
        except KeyError:
            # no system certs created
            config.pki_log.debug(
                "No new system certificates generated.",
                extra=config.PKI_INDENTATION_LEVEL_2)
            certs = []

        if not isinstance(certs, list):
            certs = [certs]

        sslserver = None

        for cdata in certs:

            if cdata['tag'] == 'sslserver':
                sslserver = cdata

            if standalone and not step_two:

                # Stand-alone PKI (Step 1)

                if cdata['tag'].lower() == "audit_signing":
                    # Save Stand-alone PKI 'Audit Signing Certificate' CSR
                    # (Step 1)
                    deployer.config_client.save_system_csr(
                        cdata['request'],
                        log.PKI_CONFIG_EXTERNAL_CSR_SAVE_PKI_AUDIT_SIGNING_1,
                        deployer.mdict['pki_external_audit_signing_csr_path'],
                        subsystem.name)

                elif cdata['tag'].lower() == "signing":
                    # Save Stand-alone PKI OCSP 'OCSP Signing Certificate'
                    # CSR (Step 1)
                    deployer.config_client.save_system_csr(
                        cdata['request'],
                        log.PKI_CONFIG_EXTERNAL_CSR_SAVE_OCSP_SIGNING,
                        deployer.mdict['pki_external_signing_csr_path'])

                elif cdata['tag'].lower() == "sslserver":
                    # Save Stand-alone PKI 'SSL Server Certificate' CSR
                    # (Step 1)
                    deployer.config_client.save_system_csr(
                        cdata['request'],
                        log.PKI_CONFIG_EXTERNAL_CSR_SAVE_PKI_SSLSERVER_1,
                        deployer.mdict['pki_external_sslserver_csr_path'],
                        subsystem.name)

                elif cdata['tag'].lower() == "storage":
                    # Save Stand-alone PKI KRA 'Storage Certificate' CSR
                    # (Step 1)
                    deployer.config_client.save_system_csr(
                        cdata['request'],
                        log.PKI_CONFIG_EXTERNAL_CSR_SAVE_KRA_STORAGE,
                        deployer.mdict['pki_external_storage_csr_path'])

                elif cdata['tag'].lower() == "subsystem":
                    # Save Stand-alone PKI 'Subsystem Certificate' CSR
                    # (Step 1)
                    deployer.config_client.save_system_csr(
                        cdata['request'],
                        log.PKI_CONFIG_EXTERNAL_CSR_SAVE_PKI_SUBSYSTEM_1,
                        deployer.mdict['pki_external_subsystem_csr_path'],
                        subsystem.name)

                elif cdata['tag'].lower() == "transport":
                    # Save Stand-alone PKI KRA 'Transport Certificate' CSR
                    # (Step 1)
                    deployer.config_client.save_system_csr(
                        cdata['request'],
                        log.PKI_CONFIG_EXTERNAL_CSR_SAVE_KRA_TRANSPORT,
                        deployer.mdict['pki_external_transport_csr_path'])

            else:
                config.pki_log.debug(
                    log.PKI_CONFIG_CDATA_TAG + " " + cdata['tag'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                config.pki_log.debug(
                    log.PKI_CONFIG_CDATA_CERT + "\n" + cdata['cert'],
                    extra=config.PKI_INDENTATION_LEVEL_2)
                config.pki_log.debug(
                    log.PKI_CONFIG_CDATA_REQUEST + "\n" + cdata['request'],
                    extra=config.PKI_INDENTATION_LEVEL_2)

        # Cloned PKI subsystems do not return an Admin Certificate
        if not clone:

            if standalone:
                if not step_two:
                    # NOTE:  Do nothing for Stand-alone PKI (Step 1)
                    #        as this has already been addressed
                    #        in 'set_admin_parameters()'
                    pass
                else:
                    admin_cert = response['adminCert']['cert']
                    deployer.config_client.process_admin_cert(admin_cert)

            elif not config.str2bool(deployer.mdict['pki_import_admin_cert']):
                admin_cert = response['adminCert']['cert']
                deployer.config_client.process_admin_cert(admin_cert)

        if sslserver and sslserver['cert']:
            deployer.systemd.stop()
            self.replace_sslserver_cert(deployer, instance, sslserver)
            deployer.systemd.start()

        elif config.str2bool(deployer.mdict['pki_restart_configured_instance']):
            # Optionally, programmatically 'restart' the configured PKI instance
            deployer.systemd.restart()

        # wait for startup
        status = None

        if deployer.fips.is_fips_enabled():
            # must use 'http' protocol when FIPS mode is enabled
            status = deployer.instance.wait_for_startup(
                60, secure_connection=False)

        else:
            status = deployer.instance.wait_for_startup(
                60, secure_connection=True)

        if not status:
            config.pki_log.error(
                "server failed to restart",
                extra=config.PKI_INDENTATION_LEVEL_1)
            raise RuntimeError("server failed to restart")

    def destroy(self, deployer):

        config.pki_log.info(log.CONFIGURATION_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        if len(deployer.instance.tomcat_instance_subsystems()) == 1:
            if deployer.directory.exists(deployer.mdict['pki_client_dir']):
                deployer.directory.delete(deployer.mdict['pki_client_dir'])
