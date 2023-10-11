# Authors:
#     Marco Fargetta <mfargett@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import os

import pki

logger = logging.getLogger(__name__)


class RemoveCertCSRfromConfig(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super().__init__()
        self.message = 'Removes certs data and CSR from CS.cfg'

    def upgrade_subsystem(self, instance, subsystem):

        self.backup(subsystem.cs_conf)
        certs_path = os.path.join(instance.conf_dir, 'certs')
        instance.makedirs(certs_path, exist_ok=True)
        logger.info('Removing certs data')
        if subsystem.name == 'ca':
            self.clean_cert_csr('signing', subsystem, certs_path)
            self.clean_cert_csr('ocsp_signing', subsystem, certs_path)
        if subsystem.name == 'kra':
            self.clean_cert_csr('storage', subsystem, certs_path)
            self.clean_cert_csr('transport', subsystem, certs_path)
        if subsystem.name == 'ocsp':
            self.clean_cert_csr('signing', subsystem, certs_path)

        self.clean_cert_csr('sslserver', subsystem, certs_path)
        self.clean_cert_csr('subsystem', subsystem, certs_path)
        self.clean_cert_csr('audit_signing', subsystem, certs_path)

        subsystem.save()

    def clean_cert_csr(self, tag, subsystem, dest_path):
        subsystem.config.pop('%s.%s.cert' % (subsystem.name, tag), None)
        cert_req = subsystem.config.pop('%s.%s.certreq' % (subsystem.name, tag), None)
        nickname = subsystem.config.get('%s.%s.nickname' % (subsystem.name, tag))
        if cert_req:
            csr_data = pki.nssdb.convert_csr(cert_req, 'base64', 'pem')
            csr_file = os.path.join(dest_path, nickname + '.csr')
            with open(csr_file, 'w', encoding='utf-8') as f:
                f.write(csr_data)
            os.chown(csr_file, subsystem.instance.uid, subsystem.instance.gid)
