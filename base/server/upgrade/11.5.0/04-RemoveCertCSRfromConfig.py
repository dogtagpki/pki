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
        instance.makedirs(instance.certs_dir, exist_ok=True)

        logger.info('Removing certs data')
        certs = subsystem.find_system_certs()
        for cert in certs:
            self.clean_cert_csr(cert['id'], subsystem)

        subsystem.save()

    def clean_cert_csr(self, tag, subsystem):
        subsystem.config.pop('%s.%s.cert' % (subsystem.name, tag), None)
        cert_req = subsystem.config.pop('%s.%s.certreq' % (subsystem.name, tag), None)
        if tag != 'sslserver' and tag != 'subsystem':
            tag = subsystem.name + '_' + tag
        if cert_req:
            csr_data = pki.nssdb.convert_csr(cert_req, 'base64', 'pem')
            csr_file = subsystem.instance.csr_file(tag)
            with open(csr_file, 'w', encoding='utf-8') as f:
                f.write(csr_data)
            os.chown(csr_file, subsystem.instance.uid, subsystem.instance.gid)
