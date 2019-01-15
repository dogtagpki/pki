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
# Copyright (C) 2018 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
import binascii
import logging
import re

import pki.encoder
import pki.nssdb
import pki.server
import pki.system
import pki.util

from .. import pkiconfig as config
from .. import pkiscriptlet

logger = logging.getLogger('keygen')


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

    def generate_csr(self,
                     deployer,
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
            subject_key_id=subject_key_id,
            generic_exts=generic_exts)

        with open(csr_path) as f:
            csr = f.read()

        b64_csr = pki.nssdb.convert_csr(csr, 'pem', 'base64')
        subsystem.config['%s.%s.certreq' % (subsystem.name, tag)] = b64_csr

    def generate_ca_signing_csr(self, deployer, subsystem):

        csr_path = deployer.mdict.get('pki_ca_signing_csr_path')
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
            token = deployer.mdict['pki_token_name']

        nssdb = subsystem.instance.open_nssdb(token)

        try:
            self.generate_csr(
                deployer,
                nssdb,
                subsystem,
                tag,
                csr_path,
                basic_constraints_ext=basic_constraints_ext,
                key_usage_ext=key_usage_ext,
                generic_exts=generic_exts,
                subject_key_id=subsystem.config.get(
                    'preop.cert.signing.subject_key_id'),
            )

        finally:
            nssdb.close()

    def generate_sslserver_csr(self, deployer, subsystem):

        csr_path = deployer.mdict.get('pki_sslserver_csr_path')
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
            token = deployer.mdict['pki_token_name']

        nssdb = subsystem.instance.open_nssdb(token)

        try:
            self.generate_csr(
                deployer,
                nssdb,
                subsystem,
                tag,
                csr_path,
                key_usage_ext=key_usage_ext,
                extended_key_usage_ext=extended_key_usage_ext
            )

        finally:
            nssdb.close()

    def generate_subsystem_csr(self, deployer, subsystem):

        csr_path = deployer.mdict.get('pki_subsystem_csr_path')
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
            token = deployer.mdict['pki_token_name']

        nssdb = subsystem.instance.open_nssdb(token)

        try:
            self.generate_csr(
                deployer,
                nssdb,
                subsystem,
                tag,
                csr_path,
                key_usage_ext=key_usage_ext,
                extended_key_usage_ext=extended_key_usage_ext
            )

        finally:
            nssdb.close()

    def generate_audit_signing_csr(self, deployer, subsystem):

        csr_path = deployer.mdict.get('pki_audit_signing_csr_path')
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
            token = deployer.mdict['pki_token_name']

        nssdb = subsystem.instance.open_nssdb(token)

        try:
            self.generate_csr(
                deployer,
                nssdb,
                subsystem,
                tag,
                csr_path,
                key_usage_ext=key_usage_ext
            )

        finally:
            nssdb.close()

    def generate_admin_csr(self, deployer, subsystem):

        csr_path = deployer.mdict.get('pki_admin_csr_path')
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

    def generate_kra_storage_csr(self, deployer, subsystem):

        csr_path = deployer.mdict.get('pki_storage_csr_path')
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
            token = deployer.mdict['pki_token_name']

        nssdb = subsystem.instance.open_nssdb(token)

        try:
            self.generate_csr(
                deployer,
                nssdb,
                subsystem,
                tag,
                csr_path,
                key_usage_ext=key_usage_ext,
                extended_key_usage_ext=extended_key_usage_ext
            )

        finally:
            nssdb.close()

    def generate_kra_transport_csr(self, deployer, subsystem):

        csr_path = deployer.mdict.get('pki_transport_csr_path')
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
            token = deployer.mdict['pki_token_name']

        nssdb = subsystem.instance.open_nssdb(token)

        try:
            self.generate_csr(
                deployer,
                nssdb,
                subsystem,
                tag,
                csr_path,
                key_usage_ext=key_usage_ext,
                extended_key_usage_ext=extended_key_usage_ext
            )

        finally:
            nssdb.close()

    def generate_ocsp_signing_csr(self, deployer, subsystem):

        csr_path = deployer.mdict.get('pki_ocsp_signing_csr_path')
        if not csr_path:
            return

        tag = 'signing'
        cert = subsystem.get_subsystem_cert(tag)
        token = pki.nssdb.normalize_token(cert['token'])

        if not token:
            token = deployer.mdict['pki_token_name']

        nssdb = subsystem.instance.open_nssdb(token)

        try:
            self.generate_csr(
                deployer,
                nssdb,
                subsystem,
                tag,
                csr_path
            )

        finally:
            nssdb.close()

    def generate_system_cert_requests(self, deployer, subsystem):

        if subsystem.name == 'ca':
            self.generate_ca_signing_csr(deployer, subsystem)

        if subsystem.name in ['kra', 'ocsp']:
            self.generate_sslserver_csr(deployer, subsystem)
            self.generate_subsystem_csr(deployer, subsystem)
            self.generate_audit_signing_csr(deployer, subsystem)
            self.generate_admin_csr(deployer, subsystem)

        if subsystem.name == 'kra':
            self.generate_kra_storage_csr(deployer, subsystem)
            self.generate_kra_transport_csr(deployer, subsystem)

        if subsystem.name == 'ocsp':
            self.generate_ocsp_signing_csr(deployer, subsystem)

    def spawn(self, deployer):

        if config.str2bool(deployer.mdict['pki_skip_installation']):
            logger.info('Skipping key generation')
            return

        logger.info('Generating keys')

        instance = pki.server.PKIInstance(deployer.mdict['pki_instance_name'])
        instance.load()

        subsystem = instance.get_subsystem(
            deployer.mdict['pki_subsystem'].lower())

        external = deployer.configuration_file.external
        standalone = deployer.configuration_file.standalone
        step_one = deployer.configuration_file.external_step_one

        if (external or standalone) and step_one:

            self.generate_system_cert_requests(deployer, subsystem)

            # This is needed by IPA to detect step 1 completion.
            # See is_step_one_done() in ipaserver/install/cainstance.py.

            subsystem.config['preop.ca.type'] = 'otherca'

            subsystem.save()

    def destroy(self, deployer):
        pass
