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
                     extended_key_usage_ext=None,
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
            extended_key_usage_ext=extended_key_usage_ext,
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

    def generate_sslserver_csr(self, deployer, nssdb, subsystem):

        csr_path = deployer.mdict.get('pki_external_sslserver_csr_path')
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

        self.generate_csr(
            deployer,
            nssdb,
            subsystem,
            'sslserver',
            csr_path,
            key_usage_ext=key_usage_ext,
            extended_key_usage_ext=extended_key_usage_ext
        )

    def generate_subsystem_csr(self, deployer, nssdb, subsystem):

        csr_path = deployer.mdict.get('pki_external_subsystem_csr_path')
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

        self.generate_csr(
            deployer,
            nssdb,
            subsystem,
            'subsystem',
            csr_path,
            key_usage_ext=key_usage_ext,
            extended_key_usage_ext=extended_key_usage_ext
        )

    def generate_audit_signing_csr(self, deployer, nssdb, subsystem):

        csr_path = deployer.mdict.get('pki_external_audit_signing_csr_path')
        if not csr_path:
            return

        key_usage_ext = {
            'digitalSignature': True,
            'nonRepudiation': True,
            'critical': True
        }

        self.generate_csr(
            deployer,
            nssdb,
            subsystem,
            'audit_signing',
            csr_path,
            key_usage_ext=key_usage_ext
        )

    def generate_admin_csr(self, deployer, subsystem):

        csr_path = deployer.mdict.get('pki_external_admin_csr_path')
        if not csr_path:
            return

        client_nssdb = pki.nssdb.NSSDatabase(
            directory=deployer.mdict['pki_client_database_dir'],
            password=deployer.mdict['pki_client_database_password'])

        try:
            self.generate_csr(
                deployer,
                client_nssdb,
                subsystem,
                'admin',
                csr_path
            )

        finally:
            client_nssdb.close()

    def generate_kra_storage_csr(self, deployer, nssdb, subsystem):

        csr_path = deployer.mdict.get('pki_external_storage_csr_path')
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

        self.generate_csr(
            deployer,
            nssdb,
            subsystem,
            'storage',
            csr_path,
            key_usage_ext=key_usage_ext,
            extended_key_usage_ext=extended_key_usage_ext
        )

    def generate_kra_transport_csr(self, deployer, nssdb, subsystem):

        csr_path = deployer.mdict.get('pki_external_transport_csr_path')
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

        self.generate_csr(
            deployer,
            nssdb,
            subsystem,
            'transport',
            csr_path,
            key_usage_ext=key_usage_ext,
            extended_key_usage_ext=extended_key_usage_ext
        )

    def generate_ocsp_signing_csr(self, deployer, nssdb, subsystem):

        csr_path = deployer.mdict.get('pki_external_signing_csr_path')
        if not csr_path:
            return

        self.generate_csr(
            deployer,
            nssdb,
            subsystem,
            'signing',
            csr_path
        )

    def generate_system_cert_requests(self, deployer, nssdb, subsystem):

        if subsystem.name == 'ca':
            self.generate_ca_signing_csr(deployer, nssdb, subsystem)

        if subsystem.name in ['kra', 'ocsp']:
            self.generate_sslserver_csr(deployer, nssdb, subsystem)
            self.generate_subsystem_csr(deployer, nssdb, subsystem)
            self.generate_audit_signing_csr(deployer, nssdb, subsystem)
            self.generate_admin_csr(deployer, subsystem)

        if subsystem.name == 'kra':
            self.generate_kra_storage_csr(deployer, nssdb, subsystem)
            self.generate_kra_transport_csr(deployer, nssdb, subsystem)

        if subsystem.name == 'ocsp':
            self.generate_ocsp_signing_csr(deployer, nssdb, subsystem)

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

    def import_ca_signing_cert(self, deployer, nssdb):

        cert_file = deployer.mdict.get('pki_external_ca_cert_path')
        if not cert_file or not os.path.exists(cert_file):
            return

        nickname = deployer.mdict['pki_ca_signing_nickname']

        config.pki_log.info(
            "importing ca_signing certificate from %s" % cert_file,
            extra=config.PKI_INDENTATION_LEVEL_2)

        nssdb.import_cert_chain(
            nickname=nickname,
            cert_chain_file=cert_file,
            trust_attributes='CT,C,C')

    def import_external_ca_signing_cert(self, deployer, nssdb):

        cert_file = deployer.mdict.get('pki_external_ca_cert_path')
        if not cert_file or not os.path.exists(cert_file):
            return

        nickname = deployer.mdict['pki_cert_chain_nickname']

        config.pki_log.info(
            "importing external certificate from %s" % cert_file,
            extra=config.PKI_INDENTATION_LEVEL_2)

        nssdb.import_cert_chain(
            nickname=nickname,
            cert_chain_file=cert_file,
            trust_attributes='CT,C,C')

    def import_sslserver_cert(self, deployer, nssdb):

        cert_file = deployer.mdict.get('pki_external_sslserver_cert_path')
        if not cert_file or not os.path.exists(cert_file):
            return

        nickname = deployer.mdict['pki_sslserver_nickname']

        config.pki_log.info(
            "importing sslserver certificate from %s" % cert_file,
            extra=config.PKI_INDENTATION_LEVEL_2)

        nssdb.import_cert_chain(
            nickname=nickname,
            cert_chain_file=cert_file,
            trust_attributes=',,')

    def import_subsystem_cert(self, deployer, nssdb):

        cert_file = deployer.mdict.get('pki_external_subsystem_cert_path')
        if not cert_file or not os.path.exists(cert_file):
            return

        nickname = deployer.mdict['pki_subsystem_nickname']

        config.pki_log.info(
            "importing subsystem certificate from %s" % cert_file,
            extra=config.PKI_INDENTATION_LEVEL_2)

        nssdb.import_cert_chain(
            nickname=nickname,
            cert_chain_file=cert_file,
            trust_attributes=',,')

    def import_audit_signing_cert(self, deployer, nssdb):

        cert_file = deployer.mdict.get('pki_external_audit_signing_cert_path')
        if not cert_file or not os.path.exists(cert_file):
            return

        nickname = deployer.mdict['pki_audit_signing_nickname']

        config.pki_log.info(
            "importing audit_signing certificate from %s" % cert_file,
            extra=config.PKI_INDENTATION_LEVEL_2)

        nssdb.import_cert_chain(
            nickname=nickname,
            cert_chain_file=cert_file,
            trust_attributes=',,P')

    def import_admin_cert(self, deployer):

        cert_file = deployer.mdict.get('pki_external_admin_cert_path')
        if not cert_file or not os.path.exists(cert_file):
            return

        nickname = deployer.mdict['pki_admin_nickname']

        client_nssdb = pki.nssdb.NSSDatabase(
            directory=deployer.mdict['pki_client_database_dir'],
            password=deployer.mdict['pki_client_database_password'])

        try:
            config.pki_log.info(
                "importing admin certificate from %s" % cert_file,
                extra=config.PKI_INDENTATION_LEVEL_2)

            client_nssdb.import_cert_chain(
                nickname=nickname,
                cert_chain_file=cert_file,
                trust_attributes=',,')

        finally:
            client_nssdb.close()

    def import_kra_storage_cert(self, deployer, nssdb):

        cert_file = deployer.mdict.get('pki_external_storage_cert_path')
        if not cert_file or not os.path.exists(cert_file):
            return

        nickname = deployer.mdict['pki_storage_nickname']

        config.pki_log.info(
            "importing kra_storage certificate from %s" % cert_file,
            extra=config.PKI_INDENTATION_LEVEL_2)

        nssdb.import_cert_chain(
            nickname=nickname,
            cert_chain_file=cert_file,
            trust_attributes=',,')

    def import_kra_transport_cert(self, deployer, nssdb):

        cert_file = deployer.mdict.get('pki_external_transport_cert_path')
        if not cert_file or not os.path.exists(cert_file):
            return

        nickname = deployer.mdict['pki_transport_nickname']

        config.pki_log.info(
            "importing kra_transport certificate from %s" % cert_file,
            extra=config.PKI_INDENTATION_LEVEL_2)

        nssdb.import_cert_chain(
            nickname=nickname,
            cert_chain_file=cert_file,
            trust_attributes=',,')

    def import_ocsp_signing_cert(self, deployer, nssdb):

        cert_file = deployer.mdict.get('pki_external_signing_cert_path')
        if not cert_file or not os.path.exists(cert_file):
            return

        nickname = deployer.mdict['pki_ocsp_signing_nickname']

        config.pki_log.info(
            "importing ocsp_signing certificate from %s" % cert_file,
            extra=config.PKI_INDENTATION_LEVEL_2)

        nssdb.import_cert_chain(
            nickname=nickname,
            cert_chain_file=cert_file,
            trust_attributes=',,')

    def import_certs_and_keys(self, deployer, nssdb):

        pkcs12_file = deployer.mdict.get('pki_external_pkcs12_path')
        if not pkcs12_file or not os.path.exists(pkcs12_file):
            return

        config.pki_log.info(
            "importing certificates and keys from %s" % pkcs12_file,
            extra=config.PKI_INDENTATION_LEVEL_2)

        pkcs12_password = deployer.mdict['pki_external_pkcs12_password']
        nssdb.import_pkcs12(pkcs12_file, pkcs12_password)

    def import_cert_chain(self, deployer, nssdb):

        chain_file = deployer.mdict.get('pki_external_ca_cert_chain_path')
        if not chain_file or not os.path.exists(chain_file):
            return

        nickname = deployer.mdict['pki_external_ca_cert_chain_nickname']

        config.pki_log.info(
            "importing certificate chain from %s" % chain_file,
            extra=config.PKI_INDENTATION_LEVEL_2)

        nssdb.import_cert_chain(
            nickname=nickname,
            cert_chain_file=chain_file,
            trust_attributes='CT,C,C')

    def import_system_certs(self, deployer, nssdb, subsystem):

        if subsystem.name == 'ca':
            self.import_ca_signing_cert(deployer, nssdb)

        if subsystem.name in ['kra', 'ocsp']:
            self.import_external_ca_signing_cert(deployer, nssdb)
            self.import_sslserver_cert(deployer, nssdb)
            self.import_subsystem_cert(deployer, nssdb)
            self.import_audit_signing_cert(deployer, nssdb)
            self.import_admin_cert(deployer)

        if subsystem.name == 'kra':
            self.import_kra_storage_cert(deployer, nssdb)
            self.import_kra_transport_cert(deployer, nssdb)

        if subsystem.name == 'ocsp':
            self.import_ocsp_signing_cert(deployer, nssdb)

        # If provided, import certs and keys from PKCS #12 file
        # into NSS database.

        self.import_certs_and_keys(deployer, nssdb)

        # If provided, import cert chain into NSS database.
        # Note: Cert chain must be imported after the system certs
        # to ensure that the system certs are imported with
        # the correct nicknames.

        self.import_cert_chain(deployer, nssdb)

    def configure_system_cert(self, deployer, nssdb, subsystem, tag):

        cert_id = self.get_cert_id(subsystem, tag)

        nickname = deployer.mdict['pki_%s_nickname' % cert_id]
        cert_data = nssdb.get_cert(
            nickname=nickname,
            output_format='base64')

        subsystem.config['%s.%s.nickname' % (subsystem.name, tag)] = nickname
        subsystem.config['%s.%s.tokenname' % (subsystem.name, tag)] = \
            deployer.mdict['pki_%s_token' % cert_id]
        subsystem.config['%s.%s.cert' % (subsystem.name, tag)] = cert_data
        subsystem.config['%s.%s.defaultSigningAlgorithm' % (subsystem.name, tag)] = \
            deployer.mdict['pki_%s_key_algorithm' % cert_id]

    def configure_ca_signing_cert(self, deployer, nssdb, subsystem):

        self.configure_system_cert(deployer, nssdb, subsystem, 'signing')

        nickname = deployer.mdict['pki_ca_signing_nickname']
        subsystem.config['ca.signing.cacertnickname'] = nickname

    def configure_sslserver_cert(self, deployer, nssdb, subsystem):

        config.pki_log.info(
            "configuring sslserver certificate",
            extra=config.PKI_INDENTATION_LEVEL_2)

        self.configure_system_cert(deployer, nssdb, subsystem, 'sslserver')

    def configure_subsystem_cert(self, deployer, nssdb, subsystem):

        config.pki_log.info(
            "configuring subsystem certificate",
            extra=config.PKI_INDENTATION_LEVEL_2)

        self.configure_system_cert(deployer, nssdb, subsystem, 'subsystem')

    def configure_audit_signing_cert(self, deployer, nssdb, subsystem):

        config.pki_log.info(
            "configuring audit_signing certificate",
            extra=config.PKI_INDENTATION_LEVEL_2)

        self.configure_system_cert(deployer, nssdb, subsystem, 'audit_signing')

    def configure_admin_cert(self, deployer, subsystem):

        config.pki_log.info(
            "configuring admin certificate",
            extra=config.PKI_INDENTATION_LEVEL_2)

        client_nssdb = pki.nssdb.NSSDatabase(
            directory=deployer.mdict['pki_client_database_dir'],
            password=deployer.mdict['pki_client_database_password'])

        try:
            nickname = deployer.mdict['pki_admin_nickname']
            cert_data = client_nssdb.get_cert(
                nickname=nickname,
                output_format='base64')

            subsystem.config['%s.admin.cert' % subsystem.name] = cert_data

        finally:
            client_nssdb.close()

    def configure_kra_storage_cert(self, deployer, nssdb, subsystem):

        config.pki_log.info(
            "configuring kra_storage certificate",
            extra=config.PKI_INDENTATION_LEVEL_2)

        self.configure_system_cert(deployer, nssdb, subsystem, 'storage')

    def configure_kra_transport_cert(self, deployer, nssdb, subsystem):

        config.pki_log.info(
            "configuring kra_transport certificate",
            extra=config.PKI_INDENTATION_LEVEL_2)

        self.configure_system_cert(deployer, nssdb, subsystem, 'transport')

    def configure_ocsp_signing_cert(self, deployer, nssdb, subsystem):

        config.pki_log.info(
            "configuring ocsp_signing certificate",
            extra=config.PKI_INDENTATION_LEVEL_2)

        self.configure_system_cert(deployer, nssdb, subsystem, 'signing')

    def configure_system_certs(self, deployer, nssdb, subsystem):

        if subsystem.name == 'ca':
            self.configure_ca_signing_cert(deployer, nssdb, subsystem)

        if subsystem.name in ['kra', 'ocsp']:
            self.configure_sslserver_cert(deployer, nssdb, subsystem)
            self.configure_subsystem_cert(deployer, nssdb, subsystem)
            self.configure_audit_signing_cert(deployer, nssdb, subsystem)
            self.configure_admin_cert(deployer, subsystem)

        if subsystem.name == 'kra':
            self.configure_kra_storage_cert(deployer, nssdb, subsystem)
            self.configure_kra_transport_cert(deployer, nssdb, subsystem)

        if subsystem.name == 'ocsp':
            self.configure_ocsp_signing_cert(deployer, nssdb, subsystem)

    def validate_system_cert(self, deployer, nssdb, subsystem, tag):

        cert_id = self.get_cert_id(subsystem, tag)
        nickname = deployer.mdict['pki_%s_nickname' % cert_id]
        cert_data = nssdb.get_cert(nickname)

        if not cert_data:
            return

        config.pki_log.info(
            "validating %s certificate" % tag,
            extra=config.PKI_INDENTATION_LEVEL_2)

        subsystem.validate_system_cert(tag)

    def validate_system_certs(self, deployer, nssdb, subsystem):

        if subsystem.name == 'ca':
            self.validate_system_cert(deployer, nssdb, subsystem, 'signing')

        if subsystem.name in ['kra', 'ocsp']:
            self.validate_system_cert(deployer, nssdb, subsystem, 'sslserver')
            self.validate_system_cert(deployer, nssdb, subsystem, 'subsystem')
            self.validate_system_cert(deployer, nssdb, subsystem, 'audit_signing')

        if subsystem.name == 'kra':
            self.validate_system_cert(deployer, nssdb, subsystem, 'storage')
            self.validate_system_cert(deployer, nssdb, subsystem, 'transport')

        if subsystem.name == 'ocsp':
            self.validate_system_cert(deployer, nssdb, subsystem, 'signing')

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
            # remove temp SSL server cert but keep the key
            nssdb.remove_cert(nickname)

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

        try:
            PKISPAWN_STARTUP_TIMEOUT_SECONDS = \
                int(os.environ['PKISPAWN_STARTUP_TIMEOUT_SECONDS'])
        except (KeyError, ValueError):
            PKISPAWN_STARTUP_TIMEOUT_SECONDS = 60
        if PKISPAWN_STARTUP_TIMEOUT_SECONDS <= 0:
            PKISPAWN_STARTUP_TIMEOUT_SECONDS = 60

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
            if (external or standalone) and step_one:

                self.generate_system_cert_requests(deployer, nssdb, subsystem)

                # This is needed by IPA to detect step 1 completion.
                # See is_step_one_done() in ipaserver/install/cainstance.py.

                subsystem.config['preop.ca.type'] = 'otherca'

                subsystem.save()

                # End of step 1.
                return

            if existing or (external or standalone) and step_two:

                self.import_system_cert_requests(deployer, subsystem)
                self.import_system_certs(deployer, nssdb, subsystem)

                self.configure_system_certs(deployer, nssdb, subsystem)
                subsystem.save()

                self.validate_system_certs(deployer, nssdb, subsystem)

            else:  # self-signed CA

                # To be implemented in ticket #1692.

                # Generate CA cert request.
                # Self sign CA cert.
                # Import self-signed CA cert into NSS database.

                pass

        finally:
            nssdb.close()

        create_temp_sslserver_cert = self.create_temp_sslserver_cert(deployer, instance, token)

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
        status = deployer.instance.wait_for_startup(PKISPAWN_STARTUP_TIMEOUT_SECONDS)
        if status is None:
            config.pki_log.error(
                "server failed to restart",
                extra=config.PKI_INDENTATION_LEVEL_2)
            raise Exception("server failed to restart")

        # Optionally wait for debugger to attach (e. g. - 'eclipse'):
        if config.str2bool(deployer.mdict['pki_enable_java_debugger']):
            config.wait_to_attach_an_external_java_debugger()

        # Construct PKI Subsystem Configuration Data
        nssdb = instance.open_nssdb(token)
        try:
            data = deployer.config_client.construct_pki_configuration_data(nssdb)

        finally:
            nssdb.close()

        # Configure the subsystem
        response = deployer.config_client.configure_pki_data(
            json.dumps(data, cls=pki.encoder.CustomTypeEncoder))

        config.pki_log.debug(
            log.PKI_CONFIG_RESPONSE_STATUS + " " + str(response['status']),
            extra=config.PKI_INDENTATION_LEVEL_2)

        # Create an empty file that designates the fact that although
        # this server instance has been configured, it has NOT yet
        # been restarted!

        restart_server = os.path.join(instance.conf_dir, 'restart_server_after_configuration')
        config.pki_log.debug(
            'creating %s' % restart_server,
            extra=config.PKI_INDENTATION_LEVEL_2)

        open(restart_server, 'a').close()
        os.chown(restart_server, instance.uid, instance.gid)
        os.chmod(restart_server, 0o660)

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

        # If temp SSL server cert was created and there's a new perm cert,
        # replace it with the perm cert.
        if create_temp_sslserver_cert and sslserver and sslserver['cert']:
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
                PKISPAWN_STARTUP_TIMEOUT_SECONDS, secure_connection=False)

        else:
            status = deployer.instance.wait_for_startup(
                PKISPAWN_STARTUP_TIMEOUT_SECONDS, secure_connection=True)

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
