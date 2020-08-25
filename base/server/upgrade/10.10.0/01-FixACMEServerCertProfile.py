# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import absolute_import
import logging
import os

import pki

logger = logging.getLogger(__name__)


class FixACMEServerCertProfile(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(FixACMEServerCertProfile, self).__init__()
        self.message = 'Fix acmeServerCert profile'

    def upgrade_subsystem(self, instance, subsystem):

        if subsystem.name != 'ca':
            return

        path = os.path.join(subsystem.base_dir, 'profiles', 'ca', 'acmeServerCert.cfg')
        self.backup(path)

        config = {}

        logger.info('Loading %s', path)
        pki.util.load_properties(path, config)

        prefix = 'policyset.serverCertSet.5.default.params.'
        ocsp_url = config.get(prefix + 'authInfoAccessADLocation_0')

        logger.info('Checking OCSP URL: %s', ocsp_url)

        if ocsp_url != 'http://ocsp.example.com':
            logger.info('Profile has been customized, do not fix it')
            return

        logger.info('Profile has not been customized, fix it')

        # remove the hard-coded OCSP URL so CA will auto-generate it
        config[prefix + 'authInfoAccessADLocation_0'] = ''

        # remove the CA issuer access method (1.3.6.1.5.5.7.48.2)
        config.pop(prefix + 'authInfoAccessADEnable_1', None)
        config.pop(prefix + 'authInfoAccessADLocationType_1', None)
        config.pop(prefix + 'authInfoAccessADLocation_1', None)
        config.pop(prefix + 'authInfoAccessADMethod_1', None)

        # just keep the OCSP access method (1.3.6.1.5.5.7.48.1)
        config[prefix + 'authInfoAccessNumADs'] = '1'

        # remove Let's Encrypt cert policy (1.3.6.1.4.1.44947.1.1.1)
        prefix = 'policyset.serverCertSet.11.default.params.PoliciesExt.'
        config.pop(prefix + 'certPolicy1.enable', None)
        config.pop(prefix + 'certPolicy1.policyId', None)
        config.pop(prefix + 'certPolicy1.PolicyQualifiers.num', None)
        config.pop(prefix + 'certPolicy1.PolicyQualifiers0.CPSURI.enable', None)
        config.pop(prefix + 'certPolicy1.PolicyQualifiers0.CPSURI.value', None)

        # just keep the domain-validated cert policy (2.23.140.1.2.1)
        config[prefix + 'num'] = '1'

        logger.info('Storing %s', path)
        pki.util.store_properties(path, config)
