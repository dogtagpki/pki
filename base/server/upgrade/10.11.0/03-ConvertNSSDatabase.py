#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
from __future__ import absolute_import
import logging
import os

import pki

logger = logging.getLogger(__name__)


class ConvertNSSDatabase(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(ConvertNSSDatabase, self).__init__()
        self.message = 'Convert NSS database into SQL database'

    def upgrade_instance(self, instance):

        logger.info('Converting %s into SQL database', instance.nssdb_dir)
        self.backup(instance.nssdb_dir)

        if not os.path.exists(instance.nssdb_dir):
            return

        nssdb = instance.open_nssdb()

        try:
            # Only attempt to convert if target format is sql and DB is dbm
            if nssdb.needs_conversion():
                nssdb.convert_db()
        finally:
            nssdb.close()
