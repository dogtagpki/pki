#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
import logging
import subprocess

import pki

logger = logging.getLogger(__name__)


class AddCRLVLVIndex(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super().__init__()
        self.message = 'Add VLV index for CRL generation by issuer'

    def upgrade_subsystem(self, instance, subsystem):
        # Only apply to CA subsystem
        if subsystem.name != 'ca':
            return

        # Check if VLV indexes are being used in Directory Server
        # Note: If a CA was created with pki_ds_setup_vlv = True, ca-db-vlv-find
        # returns all VLV entries with exit code 0 (success). Otherwise, it returns
        # nothing but still with exit code 0 (success).
        logger.info('Checking for existing VLV indexes')

        try:
            result = subprocess.run(
                [
                    'pki-server',
                    '-i', instance.name,
                    'ca-db-vlv-find'
                ],
                capture_output=True,
                text=True,
                check=True
            )

            # If output is empty or very short, no VLV indexes exist
            if not result.stdout or len(result.stdout.strip()) < 10:
                logger.info('No VLV indexes found. Skipping CRL VLV index addition.')
                return

            # Check if allRevokedCertsByIssuer VLV index already exists
            if 'allRevokedCertsByIssuer-' + instance.name in result.stdout:
                logger.info('allRevokedCertsByIssuer VLV index already exists. Skipping.')
                return

            logger.info('Existing VLV indexes found. Adding allRevokedCertsByIssuer VLV index.')

        except subprocess.CalledProcessError as e:
            raise Exception('Failed to query VLV indexes: %s' % e) from e

        # Add VLV index. This reads the CA issuer DN from the CA signing cert
        # and creates the VLV entries. Duplicates are ignored. Reindexing is
        # skipped to avoid performance impact since this runs on every restart.
        try:
            subsystem.add_vlv()
            logger.info('VLV index added successfully')

        except subprocess.CalledProcessError as e:
            raise Exception('Failed to add VLV index: %s' % e) from e
