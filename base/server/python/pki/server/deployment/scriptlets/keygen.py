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

import pki.nssdb

from .. import pkiconfig as config
from .. import pkiscriptlet

logger = logging.getLogger(__name__)


class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):

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
            deployer.generate_csr(
                nssdb,
                subsystem,
                tag,
                csr_path,
                basic_constraints_ext=basic_constraints_ext,
                key_usage_ext=key_usage_ext,
                generic_exts=generic_exts,
                subject_key_id=deployer.configuration_file.req_ski,
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
            deployer.generate_csr(
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
            deployer.generate_csr(
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
            deployer.generate_csr(
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
            deployer.generate_csr(
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
            deployer.generate_csr(
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
            deployer.generate_csr(
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
            deployer.generate_csr(
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

        if subsystem.name in ['kra', 'ocsp', 'tks', 'tps']:
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

        logger.info('Generating system keys')

        instance = self.instance
        instance.load()

        subsystem = instance.get_subsystem(
            deployer.mdict['pki_subsystem'].lower())

        external = deployer.configuration_file.external
        standalone = deployer.configuration_file.standalone
        step_one = deployer.configuration_file.external_step_one

        if (external or standalone) and step_one:

            self.generate_system_cert_requests(deployer, subsystem)

            subsystem.save()

    def destroy(self, deployer):
        pass
